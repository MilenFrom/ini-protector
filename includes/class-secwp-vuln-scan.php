<?php
/**
 * Vulnerability scanner — model + scan engine.
 *
 * Once a day (and on demand) checks every installed plugin, theme, and the WP
 * core version against the free WPVulnerability database (CC0, no API key) and
 * records any component whose INSTALLED version is affected by a known CVE.
 *
 * Storage model mirrors SecurityWP_IP_Block (a bounded wp_option snapshot), NOT
 * SecurityWP_Traffic_Log's table — findings are few, structured, and rewritten
 * whole each scan. The previous fingerprint set is kept alongside so the mailer
 * can fire on genuinely-new findings only.
 *
 * WPVulnerability contract (verified live against the API + the official plugin):
 *   GET {base}/{plugin|theme|core}/{slug-or-version}/   (plain slug, NOT hashed)
 *   { error, message, data:{ name, link, vulnerability:[ {uuid,name,operator,source[],impact} ]|null }, updated }
 *   operator: { min_version, min_operator(ge|gt|null), max_version, max_operator(le|lt|null), unfixed, closed }
 *   source[]: { id, name, link, description, date }   impact.cvss3.{ severity(word), score }
 *
 * No data about the site is sent — only the public component slug is looked up.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Vuln_Scan {

	const FEATURE = 'vulnerability_scan';
	const HOOK    = 'secwp_vuln_scan';

	/** Snapshot of the last scan: schema, scanned_at, scan_status, errors, findings. */
	const OPT_RESULTS = 'secwp_vuln_results';
	/** Flat array of finding fingerprints present at the end of the previous scan (for diffing). */
	const OPT_KNOWN = 'secwp_vuln_known';
	/** Digest of the finding set the admin dismissed from the banner. */
	const OPT_DISMISS = 'secwp_vuln_dismissed';

	const DATA_SCHEMA  = 1;
	const CACHE_TTL    = 12 * HOUR_IN_SECONDS;
	const HTTP_TIMEOUT = 8;
	/** Soft wall-clock budget for a single run; on overrun we stop and mark "partial". */
	const TIME_BUDGET = 50;

	/* --------------------------------------------------------------------- */
	/* Lifecycle                                                              */
	/* --------------------------------------------------------------------- */

	/** Hook the cron callback and lazily heal the schedule to the toggle. */
	public function register(): void {
		add_action( self::HOOK, array( __CLASS__, 'run_scan_cron' ) );
		self::sync_schedule();
	}

	/**
	 * Reconcile the daily cron event with the feature toggle. Called from
	 * register() (lazy self-heal) and from SecurityWP_Admin::after_change() the
	 * moment the toggle flips. Idempotent.
	 */
	public static function sync_schedule(): void {
		$on        = SecurityWP_Features::is_on( self::FEATURE );
		$scheduled = (bool) wp_next_scheduled( self::HOOK );

		if ( $on && ! $scheduled ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
		} elseif ( ! $on && $scheduled ) {
			wp_clear_scheduled_hook( self::HOOK );
		}
	}

	/** Cron entry point. */
	public static function run_scan_cron(): void {
		if ( ! SecurityWP_Features::is_on( self::FEATURE ) ) {
			return;
		}
		( new self() )->run_scan();
	}

	/* --------------------------------------------------------------------- */
	/* Scan                                                                   */
	/* --------------------------------------------------------------------- */

	/**
	 * Run a full scan: enumerate components, query the API (cached), match the
	 * installed version, persist the snapshot, diff against the last run and
	 * notify on new findings.
	 *
	 * On total API failure the previous snapshot is preserved untouched (we never
	 * overwrite good findings with an empty set).
	 *
	 * @param array $args { force?: bool — bypass the per-component transient cache }.
	 * @return array The new (or preserved) results snapshot.
	 */
	public function run_scan( array $args = array() ): array {
		$force     = ! empty( $args['force'] );
		$deadline  = time() + self::TIME_BUDGET;
		$findings  = array();
		$errors    = array();
		$checked   = 0;
		$truncated = false;

		foreach ( $this->components() as $c ) {
			if ( time() > $deadline ) {
				$truncated = true;
				break;
			}
			$resp = $this->fetch( $c['type'], $c['slug'], $c['version'], $force );

			if ( is_wp_error( $resp ) ) {
				$errors[ $c['type'] . ':' . $c['slug'] ] = $resp->get_error_code();
				continue;
			}
			++$checked;

			$vulns = ( is_array( $resp ) && isset( $resp['data']['vulnerability'] ) && is_array( $resp['data']['vulnerability'] ) )
				? $resp['data']['vulnerability']
				: array();

			foreach ( $vulns as $v ) {
				if ( ! is_array( $v ) || empty( $v['operator'] ) || ! is_array( $v['operator'] ) ) {
					continue;
				}
				if ( ! $this->is_affected( $c['version'], $v['operator'] ) ) {
					continue;
				}
				$findings[] = $this->build_finding( $c, $v );
			}
		}

		// Guard: a run where every lookup failed must NOT wipe a good snapshot.
		if ( 0 === $checked && ( $errors || $truncated ) ) {
			$prev                = self::get_results();
			$prev['scan_status'] = 'error';
			$prev['errors']      = $errors;
			$prev['last_error']  = time();
			update_option( self::OPT_RESULTS, $prev, false );
			return $prev;
		}

		$status = ( $errors || $truncated ) ? 'partial' : 'ok';
		return $this->persist( $findings, $errors, $status );
	}

	/**
	 * Write the snapshot, diff against the previous known fingerprints, and fire
	 * the new-finding email + platform event.
	 */
	private function persist( array $findings, array $errors, string $status ): array {
		// De-duplicate by fingerprint (a component can carry the same CVE twice).
		$by_fp = array();
		foreach ( $findings as $f ) {
			$by_fp[ $f['fingerprint'] ] = $f;
		}
		$findings = array_values( $by_fp );

		$results = array(
			'schema'      => self::DATA_SCHEMA,
			'scanned_at'  => time(),
			'scan_status' => $status,
			'errors'      => $errors,
			'findings'    => $findings,
		);
		update_option( self::OPT_RESULTS, $results, false );

		// Diff: which fingerprints are new since the previous scan?
		$current = array_keys( $by_fp );
		$known   = (array) get_option( self::OPT_KNOWN, array() );
		$new_fps = array_diff( $current, $known );
		update_option( self::OPT_KNOWN, $current, false );

		if ( $new_fps ) {
			$new = array_values(
				array_filter(
					$findings,
					static function ( $f ) use ( $new_fps ) {
						return in_array( $f['fingerprint'], $new_fps, true );
					}
				)
			);
			if ( class_exists( 'SecurityWP_Vuln_Mailer' ) ) {
				SecurityWP_Vuln_Mailer::notify_new( $new );
			}
			do_action(
				'secwp_platform_event',
				'vuln_new',
				sprintf( '%d new vulnerability finding(s)', count( $new ) ),
				array( 'count' => count( $new ) )
			);
		}

		return $results;
	}

	/* --------------------------------------------------------------------- */
	/* Component enumeration                                                  */
	/* --------------------------------------------------------------------- */

	/**
	 * Every installed component as { type, slug, version, name, key }.
	 * 'key' is the lookup into the update transients (plugin file / theme slug).
	 */
	private function components(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out = array();

		foreach ( get_plugins() as $file => $data ) {
			$slug = ( false !== strpos( $file, '/' ) ) ? dirname( $file ) : preg_replace( '/\.php$/', '', $file );
			$out[] = array(
				'type'    => 'plugin',
				'slug'    => $slug,
				'version' => (string) ( $data['Version'] ?? '' ),
				'name'    => (string) ( $data['Name'] ?? $slug ),
				'key'     => $file,
			);
		}

		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$out[] = array(
				'type'    => 'theme',
				'slug'    => (string) $stylesheet,
				'version' => (string) $theme->get( 'Version' ),
				'name'    => (string) $theme->get( 'Name' ),
				'key'     => (string) $stylesheet,
			);
		}

		$core = get_bloginfo( 'version' );
		$out[] = array(
			'type'    => 'core',
			'slug'    => $core,        // core uses the raw version as the slug
			'version' => $core,
			'name'    => 'WordPress',
			'key'     => 'core',
		);

		return $out;
	}

	/* --------------------------------------------------------------------- */
	/* API client                                                            */
	/* --------------------------------------------------------------------- */

	/** Build the WPVulnerability endpoint for a component (plain slug, not hashed). */
	public static function endpoint_for( string $type, string $slug ): string {
		$slug = ( 'core' === $type ) ? $slug : sanitize_title( $slug );
		return trailingslashit( SECWP_VULN_API_BASE ) . $type . '/' . rawurlencode( $slug ) . '/';
	}

	/**
	 * Fetch + decode the API response for one component, cached per type+slug+version.
	 *
	 * @return array|WP_Error Decoded JSON, or WP_Error on a real network/server/parse failure.
	 *                        A valid "no known vulnerabilities" body decodes to an array with
	 *                        data.vulnerability === null and is NOT an error.
	 */
	private function fetch( string $type, string $slug, string $version, bool $force = false ) {
		if ( '' === $slug ) {
			return new WP_Error( 'empty_slug' );
		}
		$cache_key = 'secwp_vuln_' . md5( $type . '|' . $slug . '|' . $version );

		if ( ! $force ) {
			$cached = get_transient( $cache_key );
			if ( false !== $cached ) {
				return is_array( $cached ) ? $cached : new WP_Error( (string) $cached );
			}
		}

		$resp = wp_remote_get(
			self::endpoint_for( $type, $slug ),
			array(
				'timeout'    => self::HTTP_TIMEOUT,
				'sslverify'  => true,
				'user-agent' => 'INI-Protector/' . SECWP_VERSION,
				'headers'    => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $resp ) ) {
			set_transient( $cache_key, 'http_error', HOUR_IN_SECONDS );
			return new WP_Error( 'http_error', $resp->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( $code >= 500 ) {
			set_transient( $cache_key, 'http_' . $code, HOUR_IN_SECONDS );
			return new WP_Error( 'http_' . $code );
		}
		// A 404 here means "component unknown to the DB" → treat as no vulns, cache it.
		$body = wp_remote_retrieve_body( $resp );
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			if ( 404 === $code ) {
				$empty = array( 'data' => array( 'vulnerability' => null ) );
				set_transient( $cache_key, $empty, self::CACHE_TTL );
				return $empty;
			}
			set_transient( $cache_key, 'bad_json', HOUR_IN_SECONDS );
			return new WP_Error( 'bad_json' );
		}

		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
	}

	/* --------------------------------------------------------------------- */
	/* Matching                                                              */
	/* --------------------------------------------------------------------- */

	/**
	 * Is $installed within the affected range described by the API's operator block?
	 *
	 * operator: { min_version, min_operator(ge|gt), max_version, max_operator(le|lt) }.
	 * A null bound means "open-ended" on that side. A missing/empty installed version
	 * can't be assessed → not vulnerable (the caller records it as an error instead).
	 */
	public function is_affected( string $installed, array $operator ): bool {
		$installed = trim( $installed );
		if ( '' === $installed ) {
			return false;
		}

		$min = isset( $operator['min_version'] ) ? (string) $operator['min_version'] : '';
		$max = isset( $operator['max_version'] ) ? (string) $operator['max_version'] : '';

		// No bounds at all → the whole product is flagged (rare, but treat as affected).
		if ( '' === $min && '' === $max ) {
			return true;
		}

		if ( '' !== $min ) {
			$op = ( 'gt' === ( $operator['min_operator'] ?? 'ge' ) ) ? '>' : '>=';
			if ( ! version_compare( $installed, $min, $op ) ) {
				return false;
			}
		}
		if ( '' !== $max ) {
			$op = ( 'lt' === ( $operator['max_operator'] ?? 'le' ) ) ? '<' : '<=';
			if ( ! version_compare( $installed, $max, $op ) ) {
				return false;
			}
		}
		return true;
	}

	/** The version a component should be upgraded to, derived from the operator block. */
	private function fixed_in( array $operator ): string {
		// When the upper bound is exclusive ("< 6.6.0"), 6.6.0 is the first safe version.
		if ( ! empty( $operator['max_version'] ) && 'lt' === ( $operator['max_operator'] ?? '' ) ) {
			return (string) $operator['max_version'];
		}
		return '';
	}

	/** Build a normalized finding row from a component + a matched vuln item. */
	private function build_finding( array $c, array $v ): array {
		$source     = ( isset( $v['source'][0] ) && is_array( $v['source'][0] ) ) ? $v['source'][0] : array();
		$source_id  = (string) ( $source['id'] ?? $source['name'] ?? ( $v['uuid'] ?? '' ) );
		$source_url = esc_url_raw( (string) ( $source['link'] ?? '' ) );

		$cvss     = ( isset( $v['impact']['cvss3'] ) && is_array( $v['impact']['cvss3'] ) ) ? $v['impact']['cvss3'] : array();
		$severity = $this->normalize_severity( $cvss );
		$score    = isset( $cvss['score'] ) ? (float) $cvss['score'] : null;

		return array(
			'fingerprint' => sha1( $c['type'] . '|' . $c['slug'] . '|' . $c['version'] . '|' . $source_id ),
			'type'        => $c['type'],
			'slug'        => $c['slug'],
			'name'        => $c['name'],
			'installed'   => $c['version'],
			'severity'    => $severity,
			'cvss'        => $score,
			'source'      => $source_id,
			'source_url'  => $source_url,
			'fixed_in'    => $this->fixed_in( $v['operator'] ),
			'update_avail' => $this->update_available( $c ),
			'title'       => wp_strip_all_tags( (string) ( $v['name'] ?? $source_id ) ),
		);
	}

	/** Normalize the API severity to one of: critical|high|medium|low|unknown. */
	private function normalize_severity( array $cvss ): string {
		$word = strtolower( trim( (string) ( $cvss['severity'] ?? '' ) ) );
		if ( in_array( $word, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
			return $word;
		}
		// Fall back to bucketing the numeric score (CVSS v3 bands).
		if ( isset( $cvss['score'] ) && '' !== (string) $cvss['score'] ) {
			$s = (float) $cvss['score'];
			if ( $s >= 9.0 ) {
				return 'critical';
			}
			if ( $s >= 7.0 ) {
				return 'high';
			}
			if ( $s >= 4.0 ) {
				return 'medium';
			}
			if ( $s > 0 ) {
				return 'low';
			}
		}
		return 'unknown';
	}

	/** Is a WP.org update already available for this component? (a hint, not a gate). */
	private function update_available( array $c ): bool {
		if ( 'plugin' === $c['type'] ) {
			$t = get_site_transient( 'update_plugins' );
			return ! empty( $t->response[ $c['key'] ] );
		}
		if ( 'theme' === $c['type'] ) {
			$t = get_site_transient( 'update_themes' );
			return ! empty( $t->response[ $c['key'] ] );
		}
		if ( 'core' === $c['type'] ) {
			$t = get_site_transient( 'update_core' );
			if ( empty( $t->updates ) || ! is_array( $t->updates ) ) {
				return false;
			}
			foreach ( $t->updates as $u ) {
				if ( isset( $u->response ) && 'upgrade' === $u->response ) {
					return true;
				}
			}
		}
		return false;
	}

	/* --------------------------------------------------------------------- */
	/* Read API (consumed by the admin page, notice, and platform)           */
	/* --------------------------------------------------------------------- */

	/** The stored snapshot, with a safe empty default. */
	public static function get_results(): array {
		$r = get_option( self::OPT_RESULTS, array() );
		if ( ! is_array( $r ) ) {
			$r = array();
		}
		return wp_parse_args(
			$r,
			array(
				'schema'      => self::DATA_SCHEMA,
				'scanned_at'  => 0,
				'scan_status' => 'never',
				'errors'      => array(),
				'findings'    => array(),
			)
		);
	}

	/** Severity counts + total for the current findings. */
	public static function summary(): array {
		$counts = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'unknown'  => 0,
			'total'    => 0,
		);
		foreach ( self::get_results()['findings'] as $f ) {
			$sev = $f['severity'] ?? 'unknown';
			if ( isset( $counts[ $sev ] ) ) {
				++$counts[ $sev ];
			}
			++$counts['total'];
		}
		return $counts;
	}

	/** Unix ts of the last completed scan (0 if never run). */
	public static function last_scan(): int {
		return (int) self::get_results()['scanned_at'];
	}

	/** Stable digest of the current finding set — changes whenever the set changes. */
	public static function findings_digest(): string {
		$fps = array();
		foreach ( self::get_results()['findings'] as $f ) {
			$fps[] = $f['fingerprint'] ?? '';
		}
		sort( $fps );
		return $fps ? sha1( implode( ',', $fps ) ) : '';
	}

	/**
	 * Dismiss token for the current snapshot.
	 *
	 * Keyed to the finding-set digest ALONE — so "Dismiss until something changes"
	 * means exactly that: the alert stays hidden across daily re-scans as long as
	 * they keep finding the SAME vulnerabilities, and reappears only when the
	 * finding set actually changes (a new vuln, or a fixed one drops off).
	 *
	 * NOTE: deliberately NOT combined with last_scan() — doing so made every daily
	 * re-scan mint a fresh token, so the banner came back even though nothing had
	 * changed, contradicting the button's promise.
	 */
	public static function dismiss_token(): string {
		return self::findings_digest();
	}

	/**
	 * Is the current finding set dismissed?
	 *
	 * Tolerates the pre-1.4.2 stored token format ("<scanned_at>:<digest>") so a
	 * site upgrading from 1.4.1 keeps its dismissal instead of having the banner
	 * pop back once: any stored value whose digest part equals the current digest
	 * counts as dismissed. The first time the user clicks Dismiss again, the value
	 * is rewritten to the new digest-only form.
	 */
	public static function is_dismissed(): bool {
		$digest = self::findings_digest();
		if ( '' === $digest ) {
			return false;
		}
		$stored = (string) get_option( self::OPT_DISMISS, '' );
		if ( '' === $stored ) {
			return false;
		}
		// Legacy "<ts>:<digest>" → compare the digest part only.
		if ( false !== strpos( $stored, ':' ) ) {
			$stored = substr( $stored, strpos( $stored, ':' ) + 1 );
		}
		return $stored === $digest;
	}
}
