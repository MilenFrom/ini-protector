<?php
/**
 * INI WP platform integration: security posture state + event buffer.
 *
 * Mirrors SeoWP's platform model. INI Protector does NOT talk to the control plane
 * directly; it exposes a read-only, HMAC-signed REST endpoint that the INI WP
 * control plane pulls. Auth reuses the connector's IniWP_Token + IniWP_Signature
 * so there is one signing contract, not two.
 *
 * Public contract: the global function secwp_platform_state().
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Platform {

	const REST_NAMESPACE = SECWP_NAMESPACE; // 'secwp/v1'
	const REST_ROUTE     = '/state';

	const EVENTS_OPTION = 'secwp_platform_events';
	const EVENTS_MAX    = 50;
	const SCHEMA        = 1;

	public function __construct() {
		add_action( 'secwp_platform_event', array( __CLASS__, 'record' ), 10, 3 );
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/* --------------------------------------------------------------------- */
	/* REST endpoint                                                          */
	/* --------------------------------------------------------------------- */

	public function register_routes(): void {
		if ( ! $this->connector_available() ) {
			return;
		}
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE,
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'rest_state' ),
				'permission_callback' => array( $this, 'authorize' ),
			)
		);
	}

	private function connector_available(): bool {
		return class_exists( 'IniWP_Token' )
			&& class_exists( 'IniWP_Signature' )
			&& IniWP_Token::is_configured();
	}

	/**
	 * Verify the inbound request with the connector's HMAC scheme. Mirrors
	 * IniWP_REST::authorize(): parse token → match site-id → verify signature.
	 *
	 * @param WP_REST_Request $request
	 * @return true|WP_Error
	 */
	public function authorize( WP_REST_Request $request ) {
		if ( ! $this->connector_available() ) {
			return new WP_Error( 'secwp_not_configured', 'INI WP connector is not configured.', array( 'status' => 503 ) );
		}
		$parsed = IniWP_Token::parse();
		if ( null === $parsed ) {
			return new WP_Error( 'secwp_not_configured', 'INI WP connector has no connection token.', array( 'status' => 503 ) );
		}
		$site_id = (string) $request->get_header( IniWP_Signature::HEADER_SITE_ID );
		if ( '' === $site_id || ! hash_equals( $parsed['site_id'], $site_id ) ) {
			return new WP_Error( 'secwp_site_mismatch', 'Site id mismatch.', array( 'status' => 401 ) );
		}
		return IniWP_Signature::verify_request( $request, $parsed['secret'] );
	}

	public function rest_state( WP_REST_Request $request ): WP_REST_Response {
		$params = array(
			'kinds' => array( 'audit', 'integrity' ),
		);
		// Optional look-back window hint for the traffic summary (panel passes ?hours=).
		$hours = (int) $request->get_param( 'hours' );
		if ( $hours > 0 ) {
			$params['traffic_hours'] = $hours;
		}
		// Optional single-IP drill-down: ?detail_ip=1.2.3.4 adds traffic.detail (profile_ip).
		// Validated here so a malformed value never reaches the query layer.
		$detail_ip = (string) $request->get_param( 'detail_ip' );
		if ( '' !== $detail_ip && filter_var( $detail_ip, FILTER_VALIDATE_IP ) ) {
			$params['traffic_detail_ip'] = $detail_ip;
		}
		return new WP_REST_Response( self::state( $params ), 200 );
	}

	/* --------------------------------------------------------------------- */
	/* State                                                                  */
	/* --------------------------------------------------------------------- */

	/** Default traffic look-back window (hours) and row cap for the summary. */
	const TRAFFIC_HOURS = 24;
	const TRAFFIC_LIMIT = 25;

	/** Timeline rows returned in a single-IP detail pull. Tighter than the admin UI's 200 to keep the pulled payload lean. */
	const TRAFFIC_DETAIL_TIMELINE = 100;

	/**
	 * Full security-posture payload for the platform.
	 *
	 * @param array $params Optional: { kinds: [audit, integrity], traffic_hours: int }.
	 * @return array
	 */
	public static function state( array $params = array() ): array {
		return array(
			'schema_version' => self::SCHEMA,
			'plugin'         => 'securitywp',
			'version'        => defined( 'SECWP_VERSION' ) ? SECWP_VERSION : '',
			'generated_at'   => gmdate( 'c' ),
			'hardening'      => self::hardening(),
			'scan'           => self::scan( $params ),
			'events'         => self::get_events(),
			'traffic'        => self::traffic( $params ),
			'vulnerabilities' => self::vulnerabilities(),
			'autoblock'      => self::autoblock(),
			'file_integrity' => self::file_integrity(),
			'two_factor'     => self::two_factor(),
		);
	}

	/**
	 * Two-factor coverage for the panel: which roles must use it, and who actually
	 * has. Counts only — no secret, no recovery code, nothing that could weaken an
	 * account, ever leaves the site. Additive key; schema_version stays 1.
	 *
	 * `required_without` is the number that matters operationally: accounts whose
	 * role requires 2FA but that have not enrolled yet.
	 *
	 * @return array
	 */
	private static function two_factor(): array {
		if ( ! class_exists( 'SecurityWP_2FA' ) || ! class_exists( 'SecurityWP_TOTP' ) ) {
			return array( 'enabled' => false );
		}
		if ( class_exists( 'SecurityWP_Features' ) && ! SecurityWP_Features::is_on( SecurityWP_2FA::FEATURE ) ) {
			return array( 'enabled' => false );
		}

		$enrolled = get_users(
			array(
				'meta_key'   => SecurityWP_TOTP::META_ENABLED,
				'meta_value' => 1,
				'fields'     => 'ID',
			)
		);

		$required_roles   = SecurityWP_2FA::required_roles();
		$required_total   = 0;
		$required_missing = 0;

		if ( $required_roles ) {
			foreach ( get_users( array( 'role__in' => $required_roles, 'fields' => array( 'ID' ) ) ) as $u ) {
				++$required_total;
				if ( ! SecurityWP_TOTP::is_enabled( (int) $u->ID ) ) {
					++$required_missing;
				}
			}
		}

		return array(
			'enabled'         => true,
			'required_roles'  => $required_roles,
			'enrolled'        => count( $enrolled ),
			'required_users'  => $required_total,
			'required_without' => $required_missing,
		);
	}

	/**
	 * File integrity monitoring state for the panel. Read-only projection of the
	 * stored snapshot — it never triggers a scan (cron/WP-CLI own that), so the
	 * pull stays cheap and side-effect-free, like the rest of state().
	 *
	 * Named `file_integrity`, NOT `integrity`: `scan.integrity` already carries the
	 * on-demand WordPress.org core-checksum check, which is a different thing —
	 * core files only, on demand, no baseline, no off-server alert. This block is
	 * the scheduled whole-tree baseline monitor.
	 *
	 * `alert.delivered` matters to the panel as much as the counts do: a change set
	 * nobody was told about is the failure mode this feature exists to prevent.
	 * Changes also flow through events[] (`integrity_change`). Additive key —
	 * schema_version stays 1.
	 *
	 * @return array
	 */
	private static function file_integrity(): array {
		if ( ! class_exists( 'SecurityWP_Integrity' ) ) {
			return array( 'enabled' => false );
		}
		if ( class_exists( 'SecurityWP_Features' ) && ! SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			return array( 'enabled' => false );
		}

		$r = SecurityWP_Integrity::get_results();
		return array(
			'enabled'           => true,
			'status'            => (string) $r['status'],
			'seq'               => (int) $r['seq'],
			'scanned_at'        => $r['scanned_at'] ? gmdate( 'c', (int) $r['scanned_at'] ) : null,
			'schedule'          => SecurityWP_Integrity::frequency(),
			'next_run'          => wp_next_scheduled( SecurityWP_Integrity::HOOK ) ? gmdate( 'c', (int) wp_next_scheduled( SecurityWP_Integrity::HOOK ) ) : null,
			'counts'            => (array) $r['counts'],
			'baseline_files'    => SecurityWP_Integrity::baseline_count(),
			'state_digest'      => (string) $r['state_digest'],
			'prev_state_digest' => (string) $r['prev_state_digest'],
			'files_truncated'   => (bool) $r['files_truncated'],
			'alert'             => (array) $r['alert'],
			'changes'           => array_values( (array) $r['changes'] ),
		);
	}

	/**
	 * Auto-block escalation state for the panel. Read-only projection — the cron
	 * owns evaluation, so the pull is side-effect-free. Additive key,
	 * schema_version stays 1; auto-block events also flow through events[]
	 * (`autoblock_temp`). No write surface: a panel "rescan / clear level" would
	 * be a connector command, same boundary as Traffic's "Block this IP".
	 *
	 * Reports `mode` so the panel can distinguish suggest-only (Block Suggestion
	 * System) from enforce (Auto-Block), and the active escalation entries.
	 *
	 * @return array
	 */
	private static function autoblock(): array {
		if ( ! class_exists( 'SecurityWP_Autoblock' ) || ! SecurityWP_Autoblock::is_enabled() ) {
			return array( 'enabled' => false );
		}
		$state   = SecurityWP_Autoblock::state();
		$entries = array();
		foreach ( $state as $ip => $rec ) {
			$entries[] = array(
				'ip'            => (string) $ip,
				'level'         => (int) ( $rec['level'] ?? 0 ),
				'last_block_at' => ! empty( $rec['last_block_at'] ) ? gmdate( 'c', (int) $rec['last_block_at'] ) : null,
			);
		}
		return array(
			'enabled'   => true,
			'mode'      => SecurityWP_Autoblock::is_enforcing() ? 'enforce' : 'suggest',
			'max_level' => SecurityWP_Autoblock::MAX_LEVEL,
			'tracked'   => count( $entries ),
			'entries'   => $entries,
		);
	}

	/**
	 * Vulnerability-scan results for the panel. Read-only projection of the stored
	 * snapshot — it never triggers a live scan (the daily cron owns scanning), so
	 * the pull stays cheap and side-effect-free, like the rest of state().
	 *
	 * Returns { enabled: false } when the scan tweak is off or its class is missing,
	 * mirroring traffic(). Additive key — schema_version stays 1.
	 *
	 * @return array
	 */
	private static function vulnerabilities(): array {
		if ( ! class_exists( 'SecurityWP_Vuln_Scan' ) ) {
			return array( 'enabled' => false );
		}
		if ( class_exists( 'SecurityWP_Features' ) && ! SecurityWP_Features::is_on( 'vulnerability_scan' ) ) {
			return array( 'enabled' => false );
		}
		$results = SecurityWP_Vuln_Scan::get_results();
		return array(
			'enabled'     => true,
			'scanned_at'  => $results['scanned_at'] ? gmdate( 'c', (int) $results['scanned_at'] ) : null,
			'scan_status' => (string) $results['scan_status'],
			'counts'      => SecurityWP_Vuln_Scan::summary(),
			'findings'    => array_values( $results['findings'] ),
		);
	}

	/**
	 * Aggregated traffic / threat summary for the panel's Traffic tab. Reuses
	 * SecurityWP_Traffic_Log::summary(), which already produces the exact shape
	 * (totals / top_ips / top_paths / recent / suggested) the panel renders, and
	 * is bounded + computed off the request critical path.
	 *
	 * Returns { enabled: false } when the traffic-monitor tweak is off or its
	 * table doesn't exist yet, so the panel can prompt to enable it rather than
	 * show "no traffic".
	 *
	 * When the caller passes a valid `traffic_detail_ip`, a `detail` key is added
	 * with the single-IP profile (SecurityWP_Traffic_Log::profile_ip) — the same
	 * shape the admin drill-down renders (verdict, status/reason histograms, top
	 * paths, user-agents, capped timeline). Each top_ips row already carries a
	 * `verdict` level (clean/watch/suspicious/hostile) from summary(), so the
	 * panel's list badges match the per-IP verdict without a second request.
	 *
	 * @param array $params Optional: { traffic_hours: int, traffic_detail_ip: string }.
	 * @return array
	 */
	private static function traffic( array $params = array() ): array {
		if ( ! class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return array( 'enabled' => false );
		}
		// Tweak off → report disabled (don't leak a stale summary from an old table).
		if ( class_exists( 'SecurityWP_Features' ) && ! SecurityWP_Features::is_on( 'traffic_log' ) ) {
			return array( 'enabled' => false );
		}
		$hours = isset( $params['traffic_hours'] ) ? (int) $params['traffic_hours'] : self::TRAFFIC_HOURS;
		$hours = $hours > 0 ? $hours : self::TRAFFIC_HOURS;

		$summary = SecurityWP_Traffic_Log::summary( $hours, self::TRAFFIC_LIMIT );
		if ( ! is_array( $summary ) ) {
			return array( 'enabled' => false );
		}

		// Retention/size, so the panel can show how far back this site's history goes and flag a log
		// growing without a bound. Additive — schema_version stays 1.
		$stats = SecurityWP_Traffic_Log::stats();
		if ( ! empty( $stats['enabled'] ) ) {
			$summary['storage'] = array(
				'rows'           => (int) $stats['rows'],
				'bytes'          => (int) $stats['bytes'],
				'rows_per_day'   => (int) $stats['rows_per_day'],
				'oldest'         => (string) $stats['oldest'],
				'retention_days' => (int) $stats['retention_days'], // 0 = kept forever
				'max_rows'       => (int) $stats['max_rows'],       // 0 = no cap
			);
		}

		// Single-IP drill-down, only when explicitly requested with a valid IP.
		if ( ! empty( $params['traffic_detail_ip'] ) ) {
			$ip = (string) $params['traffic_detail_ip'];
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$summary['detail'] = SecurityWP_Traffic_Log::profile_ip( $ip, $hours, self::TRAFFIC_DETAIL_TIMELINE );
			}
		}

		return $summary;
	}

	/**
	 * Which hardening tweaks are enabled, grouped by category. Lets the panel
	 * show a posture matrix without re-deriving the catalog.
	 *
	 * @return array
	 */
	private static function hardening(): array {
		$state      = class_exists( 'SecurityWP_Features' ) ? SecurityWP_Features::state() : array();
		$catalog    = class_exists( 'SecurityWP_Features' ) ? SecurityWP_Features::catalog() : array();
		$categories = class_exists( 'SecurityWP_Features' ) ? SecurityWP_Features::categories() : array();

		$by_cat = array();
		foreach ( $catalog as $key => $def ) {
			$cat = isset( $def['cat'] ) ? $def['cat'] : 'other';
			$by_cat[ $cat ][ $key ] = ! empty( $state[ $key ] );
		}

		$enabled = count( array_filter( $state ) );
		return array(
			'categories'    => $categories,
			'by_category'   => $by_cat,
			'enabled_count' => $enabled,
			'total_count'   => count( $catalog ),
		);
	}

	/**
	 * Read-only security scan (audit + core-integrity). Reuses the ported
	 * SecurityWP_Security_Scan, which is side-effect free.
	 *
	 * @param array $params
	 * @return array
	 */
	private static function scan( array $params ): array {
		if ( ! class_exists( 'SecurityWP_Security_Scan' ) ) {
			return array();
		}
		$result = SecurityWP_Security_Scan::run( $params );
		return is_array( $result ) ? $result : array();
	}

	/* --------------------------------------------------------------------- */
	/* Event buffer                                                           */
	/* --------------------------------------------------------------------- */

	/**
	 * Record a structured security event. Fire via:
	 *   do_action( 'secwp_platform_event', 'login_lockout', 'IP locked', array( 'ip' => '…' ) );
	 *
	 * @param string $type
	 * @param string $message
	 * @param array  $context
	 */
	public static function record( string $type, string $message = '', array $context = array() ): void {
		$events = get_option( self::EVENTS_OPTION, array() );
		if ( ! is_array( $events ) ) {
			$events = array();
		}
		array_unshift(
			$events,
			array(
				'time'    => time(),
				'type'    => sanitize_key( $type ),
				'message' => wp_strip_all_tags( (string) $message ),
				'context' => self::scalarize( $context ),
			)
		);
		$events = array_slice( $events, 0, self::EVENTS_MAX );
		update_option( self::EVENTS_OPTION, $events, false );
	}

	public static function get_events(): array {
		$events = get_option( self::EVENTS_OPTION, array() );
		return is_array( $events ) ? array_slice( $events, 0, 20 ) : array();
	}

	private static function scalarize( array $context ): array {
		$out = array();
		foreach ( $context as $k => $v ) {
			if ( is_scalar( $v ) || null === $v ) {
				$out[ sanitize_key( (string) $k ) ] = is_string( $v ) ? wp_strip_all_tags( $v ) : $v;
			}
		}
		return $out;
	}
}

/**
 * Public contract for the INI WP connector / platform. Stable function name —
 * guard with function_exists() before calling.
 *
 * @return array
 */
if ( ! function_exists( 'secwp_platform_state' ) ) {
	function secwp_platform_state(): array {
		return SecurityWP_Platform::state( array( 'kinds' => array( 'audit', 'integrity' ) ) );
	}
}
