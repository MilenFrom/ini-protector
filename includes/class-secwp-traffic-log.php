<?php
/**
 * Traffic / request monitor. Records requests that reach WordPress (application layer) into a
 * capped, auto-pruned table so the control panel can surface suspicious activity (brute-force,
 * vulnerability probing, bad bots, enumeration) and SUGGEST firewall/block rules.
 *
 * This is an APPLICATION-layer monitor, not a packet sniffer: it only sees requests that hit PHP
 * (index.php). Static files and anything blocked upstream (nginx/Apache/Cloudflare) are invisible
 * here — those can be added later by ingesting server access logs over SSH (the `source` column is
 * already there so server-log rows merge into the same table without a schema change).
 *
 * Performance: capture runs on `shutdown` (after the response is sent), skips logged-in admins and
 * the INI WP signed channel, and prunes probabilistically — so it adds at most one buffered INSERT
 * to a request, off the critical path. Retention is configurable and **defaults to keeping
 * everything**: neither the age window nor the row cap is applied unless the site sets one. That
 * costs disk and backup size, never request time — with both off the pruner does no work at all.
 *
 * Privacy: client IP and user-agent are personal data, recorded for the security purpose of threat
 * detection and auto-pruned. Admins-only to read.
 *
 * Config tweak key: 'traffic_log' (on/off).
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Traffic_Log {

	// Defaults: keep 90 days, and at most 250,000 rows (~90 MB at a measured 372 bytes/row).
	// These are only the fallback for the (impossible) case where the feature catalog isn't
	// loaded — the values a site actually gets come from the 'retention_days' / 'max_rows'
	// config fields, which declare the same defaults. Keep the two in step.
	//
	// The row cap is deliberately NOT 0. Age alone does not bound this table: at 5,000 requests
	// a day, 90 days is roughly 450,000 rows, and a busy site can reach tens of millions before
	// anything deletes. "No limit" remains available, but as something an administrator chooses
	// rather than something they inherit by not looking.
	const MAX_ROWS       = 250000; // DEFAULT row cap    (config 'max_rows',       0 = no cap)
	const RETENTION_DAYS = 90;     // DEFAULT age limit  (config 'retention_days', 0 = keep forever)
	const SCHEMA_VERSION = 1;
	const OPT_SCHEMA     = 'secwp_traffic_schema';

	/**
	 * Ceiling on how far back a READER may look, in days. Nothing is pruned at this age — it only
	 * stops an "all time" request turning into an unbounded GROUP BY over the whole table, which is
	 * where a long retention window would actually be felt (a slow admin page, not a slow site).
	 */
	const MAX_WINDOW_DAYS = 365;

	/**
	 * A `created_at` cutoff for a window ending now and starting $seconds ago.
	 *
	 * Rows are written with `current_time( 'mysql' )` — the site's LOCAL wall clock — so every
	 * comparison against that column has to be a local wall-clock string too. This class used
	 * `gmdate()` until 1.8.1, which compared local timestamps against a UTC cutoff and shifted
	 * pruning and every read window by the site's UTC offset (3 hours on Europe/Sofia).
	 *
	 * `wp_date()` renders the moment in the site's timezone and is DST-aware **for that moment**,
	 * so a window is correct on both sides of a clock change rather than off by an hour.
	 */
	private static function cutoff( int $seconds ): string {
		$stamp = wp_date( 'Y-m-d H:i:s', time() - $seconds );
		// wp_date() returns false if the timezone is unusable. Falling back to UTC reproduces the
		// old skew, which is wrong but harmless — better than a cutoff of '' matching every row.
		return false !== $stamp ? $stamp : gmdate( 'Y-m-d H:i:s', time() - $seconds );
	}

	/** Effective age limit in days. 0 = keep forever. */
	public static function retention_days(): int {
		if ( ! class_exists( 'SecurityWP_Features' ) ) {
			return self::RETENTION_DAYS;
		}
		return max( 0, (int) SecurityWP_Features::get( 'traffic_log', 'retention_days', self::RETENTION_DAYS ) );
	}

	/** Effective row cap. 0 = no cap. */
	public static function max_rows(): int {
		if ( ! class_exists( 'SecurityWP_Features' ) ) {
			return self::MAX_ROWS;
		}
		return max( 0, (int) SecurityWP_Features::get( 'traffic_log', 'max_rows', self::MAX_ROWS ) );
	}

	/** True when no row is ever dropped for being old. */
	public static function keeps_forever(): bool {
		return self::retention_days() < 1;
	}

	/**
	 * Longest look-back a caller may request, in hours. Normally the retention horizon, so a reader
	 * can never ask for history the table doesn't keep; capped at MAX_WINDOW_DAYS when retention is
	 * unlimited.
	 */
	public static function max_window_hours(): int {
		$days = self::retention_days();
		if ( $days < 1 ) {
			$days = self::MAX_WINDOW_DAYS;
		}
		return 24 * min( $days, self::MAX_WINDOW_DAYS );
	}

	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . 'secwp_traffic_log';
	}

	/** Create/upgrade the table (dbDelta-idempotent). */
	public static function install_table(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table           = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		// VARCHAR(45) holds an IPv6 address. `reason` is empty for normal traffic, set for suspicious.
		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			method VARCHAR(10) NOT NULL DEFAULT '',
			path VARCHAR(512) NOT NULL DEFAULT '',
			status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
			user_agent VARCHAR(255) NOT NULL DEFAULT '',
			referer VARCHAR(255) NOT NULL DEFAULT '',
			source VARCHAR(10) NOT NULL DEFAULT 'php',
			suspicious TINYINT(1) NOT NULL DEFAULT 0,
			reason VARCHAR(40) NOT NULL DEFAULT '',
			PRIMARY KEY (id),
			KEY created_at (created_at),
			KEY ip (ip),
			KEY suspicious (suspicious),
			KEY status (status)
		) {$charset_collate};";

		dbDelta( $sql );
		update_option( self::OPT_SCHEMA, self::SCHEMA_VERSION, false );
	}

	public static function drop_table(): void {
		global $wpdb;
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		delete_option( self::OPT_SCHEMA );
	}

	private static function table_exists(): bool {
		global $wpdb;
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
	}

	public function register(): void {
		if ( ! self::table_exists() || (int) get_option( self::OPT_SCHEMA ) < self::SCHEMA_VERSION ) {
			self::install_table();
		}
		// Capture after the response is generated so we have the final status code and add no
		// latency to the user's request. Late priority so other shutdown work runs first.
		add_action( 'shutdown', array( $this, 'capture' ), 999 );
	}

	/** Should this request be skipped (not logged)? Keeps the firehose down and protects the channel. */
	private function should_skip(): bool {
		// Never log our own signed channel, admin-ajax/cron, CLI, or logged-in admins browsing.
		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST && $this->is_secwp_channel() )
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return true;
		}
		if ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return true;
		}
		return false;
	}

	private function is_secwp_channel(): bool {
		$route = SecurityWP_Input::rest_route();
		foreach ( array( SECWP_NAMESPACE, SECWP_CONNECTOR_NAMESPACE ) as $ns ) {
			if ( $route === $ns || 0 === strpos( $route, $ns . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Record the just-finished request. Cheap: one buffered insert + occasional prune. */
	public function capture(): void {
		if ( $this->should_skip() ) {
			return;
		}
		global $wpdb;

		$ip = self::client_ip();
		if ( '' === $ip ) {
			return; // nothing useful to record / rate-limit on
		}

		$method  = SecurityWP_Input::request_method();
		$uri     = SecurityWP_Input::request_uri();
		$path    = substr( esc_url_raw( (string) wp_parse_url( $uri, PHP_URL_PATH ) ), 0, 512 );
		$status  = (int) http_response_code();
		$ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '';
		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? substr( esc_url_raw( (string) wp_unslash( $_SERVER['HTTP_REFERER'] ) ), 0, 255 ) : '';

		list( $suspicious, $reason ) = self::assess( $method, $path, $status, $ua );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->insert(
			self::table_name(),
			array(
				'created_at' => current_time( 'mysql' ),
				'ip'         => $ip,
				'method'     => $method,
				'path'       => $path,
				'status'     => $status > 0 ? $status : 0,
				'user_agent' => $ua,
				'referer'    => $referer,
				'source'     => 'php',
				'suspicious' => $suspicious ? 1 : 0,
				'reason'     => $reason,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s' )
		);

		$this->maybe_prune();
	}

	/**
	 * Decide whether a request looks suspicious and why. Conservative — these are the signals a
	 * firewall would care about, and the panel turns them into suggested block rules.
	 *
	 * @return array{0:bool,1:string} [ suspicious, reason ]
	 */
	private static function assess( string $method, string $path, int $status, string $ua ): array {
		$p = strtolower( $path );

		// Probing for well-known sensitive files / common vuln paths.
		$bad_paths = array( '/.env', '/.git', 'wp-config.php', '/phpinfo', '/xmlrpc.php', '/.aws',
			'/vendor/', '/composer.json', '/wp-content/debug.log', '/.htpasswd', '/backup', '/.ssh' );
		foreach ( $bad_paths as $needle ) {
			if ( false !== strpos( $p, $needle ) ) {
				return array( true, 'probe:' . ltrim( $needle, '/' ) );
			}
		}

		// XML-RPC is a classic brute-force / pingback-DDoS vector.
		if ( false !== strpos( $p, 'xmlrpc.php' ) ) {
			return array( true, 'xmlrpc' );
		}

		// User/author enumeration probes.
		if ( false !== strpos( $p, '/wp-json/wp/v2/users' ) || preg_match( '/[?&]author=\d+/', $path ) ) {
			return array( true, 'user_enum' );
		}

		// A POST to wp-login.php is a login attempt (brute-force when repeated from one IP).
		if ( 'POST' === $method && false !== strpos( $p, 'wp-login.php' ) ) {
			return array( true, 'login_post' );
		}

		// 404s are how scanners walk a site; flag them so bursts are visible.
		if ( 404 === $status ) {
			return array( true, '404' );
		}

		// Empty/very short user agents are typical of crude bots.
		if ( '' === $ua ) {
			return array( true, 'empty_ua' );
		}

		return array( false, '' );
	}

	/**
	 * The client IP, validated. Every IP-based decision in the plugin comes through here so the
	 * log, the login limiter and the block list cannot disagree about who a visitor is.
	 *
	 * REMOTE_ADDR (the socket peer) is the default, because X-Forwarded-For / CF-Connecting-IP are
	 * CLIENT-SUPPLIED and trivially spoofable — trusting them in a *security* log would let an
	 * attacker forge their IP, evade a block, or get someone else's IP blocked instead.
	 *
	 * Sites behind a reverse proxy / CDN (where REMOTE_ADDR is the proxy) should declare the proxy
	 * in wp-config.php:
	 *
	 *     define( 'SECWP_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );
	 *
	 * A forwarded header is then read ONLY when the socket peer is one of those addresses, which is
	 * the part that makes it trustworthy: a visitor connecting directly to the origin cannot claim
	 * to be someone else, because their peer address is not on the list.
	 *
	 * SECWP_TRUST_PROXY = true is the older, blunter opt-in and is still honoured, but it cannot
	 * check who sent the header. It is treated as legacy: public addresses only (a real CDN never
	 * forwards a private client IP), and the security scan flags it with the upgrade to make.
	 */
	public static function client_ip(): string {
		$peer      = SecurityWP_Input::remote_ip();
		$forwarded = self::forwarded_ip( $peer );
		if ( '' !== $forwarded ) {
			return $forwarded;
		}
		return filter_var( $peer, FILTER_VALIDATE_IP ) ? $peer : '';
	}

	/** Trusted proxy addresses/ranges from wp-config, or an empty list. */
	public static function trusted_proxies(): array {
		if ( ! defined( 'SECWP_TRUSTED_PROXIES' ) ) {
			return array();
		}
		$raw   = SECWP_TRUSTED_PROXIES;
		$raw   = is_array( $raw ) ? implode( ',', $raw ) : (string) $raw;
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		return is_array( $parts ) ? $parts : array();
	}

	/** Is this address one of the declared proxies? Reuses the allowlist CIDR matcher. */
	private static function is_trusted_proxy( string $ip, array $trusted ): bool {
		if ( '' === $ip ) {
			return false;
		}
		foreach ( $trusted as $entry ) {
			if ( class_exists( 'SecurityWP_Autoblock' ) ) {
				if ( SecurityWP_Autoblock::ip_matches( $ip, (string) $entry ) ) {
					return true;
				}
			} elseif ( $ip === trim( (string) $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/** Header value as a list of trimmed candidates, left to right. */
	private static function header_ips( string $key ): array {
		if ( empty( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) {
			return array();
		}
		$raw = wp_unslash( $_SERVER[ $key ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each candidate is validated as an IP below before use.
		$out = array();
		foreach ( explode( ',', $raw ) as $part ) {
			$part = trim( $part );
			if ( '' !== $part ) {
				$out[] = $part;
			}
		}
		return $out;
	}

	/**
	 * The forwarded client address, or '' when none may be trusted.
	 *
	 * With SECWP_TRUSTED_PROXIES the peer must itself be a declared proxy, and X-Forwarded-For is
	 * walked from the RIGHT — the end nearest us, which our own proxies wrote — stopping at the
	 * first address that is not a known hop. Anything the client prepended sits to the left of
	 * that and is never reached, which is exactly the forgery this closes.
	 */
	private static function forwarded_ip( string $peer ): string {
		$trusted = self::trusted_proxies();

		if ( $trusted ) {
			if ( ! self::is_trusted_proxy( $peer, $trusted ) ) {
				return ''; // Direct connection, or an undeclared proxy: headers mean nothing.
			}
			foreach ( self::header_ips( 'HTTP_CF_CONNECTING_IP' ) as $candidate ) {
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					return sanitize_text_field( $candidate ); // Single-valued and written by the edge.
				}
			}
			foreach ( array_reverse( self::header_ips( 'HTTP_X_FORWARDED_FOR' ) ) as $candidate ) {
				if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					return ''; // Garbage in the chain: stop rather than guess past it.
				}
				if ( ! self::is_trusted_proxy( $candidate, $trusted ) ) {
					return sanitize_text_field( $candidate );
				}
			}
			return '';
		}

		if ( defined( 'SECWP_TRUST_PROXY' ) && SECWP_TRUST_PROXY ) {
			// Legacy mode: we cannot tell who sent the header, so at least refuse values a real
			// CDN would never forward. A private or reserved address here is either a
			// misconfiguration or someone trying to look like localhost to dodge a block.
			foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ) as $key ) {
				foreach ( self::header_ips( $key ) as $candidate ) {
					if ( filter_var( $candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return sanitize_text_field( $candidate );
					}
					break; // Left-most only, as before.
				}
			}
		}

		return '';
	}

	/**
	 * Keep the table bounded. Runs ~2% of requests (cheap; the caps are generous).
	 *
	 * Both limits are configurable and either can be switched off: retention 0 keeps rows forever,
	 * row cap 0 removes the ceiling. Each limit's query is skipped when its limit is off — with both
	 * off this returns before touching the database, so "keep everything" is cheaper per request
	 * than the default, not more expensive. The OFFSET lookup in particular scans as many index
	 * entries as the cap allows, so raising the cap is the one setting here with a per-request cost.
	 */
	private function maybe_prune(): void {
		if ( wp_rand( 1, 50 ) !== 1 ) {
			return;
		}
		$retention = self::retention_days();
		$max_rows  = self::max_rows();
		if ( $retention < 1 && $max_rows < 1 ) {
			return; // Keep everything: nothing to delete, and no reason to ask.
		}

		global $wpdb;
		$table = self::table_name();

		if ( $retention > 0 ) {
			$cutoff = self::cutoff( $retention * DAY_IN_SECONDS );
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) );
		}

		if ( $max_rows > 0 ) {
			$min_keep = $wpdb->get_var(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", $max_rows )
			);
			if ( $min_keep ) {
				// The cap is a STORAGE bound, not a licence to starve the feature that reads this
				// table. Auto-block scores a fixed look-back window, so if the cap were allowed to
				// cut into it, a busy site would silently hand the blocker a partial picture — and
				// the busier the site, the less it would see, which is precisely backwards. Rows
				// inside that window survive the cap; it catches up as soon as they age out.
				$keep_since = self::cutoff( self::blocker_window_seconds() );
				$wpdb->query(
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d AND created_at < %s", (int) $min_keep, $keep_since )
				);
			}
		}
	}

	/**
	 * How far back the auto-block engine scores, in seconds.
	 *
	 * Read from the blocker itself rather than restated here, so the two cannot drift: if the
	 * evaluation window is ever widened, the pruner protects the wider window automatically.
	 */
	private static function blocker_window_seconds(): int {
		$hours = defined( 'SecurityWP_Autoblock::EVAL_HOURS' ) ? (int) SecurityWP_Autoblock::EVAL_HOURS : 24;
		return max( 1, $hours ) * HOUR_IN_SECONDS;
	}

	/**
	 * Storage footprint of the log: rows, bytes on disk (data + indexes), the span it covers, and
	 * the recent rows/day rate. Surfaced in the admin so the cost of a long retention window is
	 * visible on the page that offers it, rather than discovered in a backup.
	 *
	 * `bytes` is 0 when information_schema isn't readable (some managed hosts) — treat that as
	 * "unknown", not "empty".
	 */
	public static function stats(): array {
		if ( ! self::table_exists() ) {
			return array( 'enabled' => false );
		}
		global $wpdb;
		$table = self::table_name();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$row = $wpdb->get_row(
			"SELECT COUNT(*) AS rows_total, MIN(created_at) AS oldest, MAX(created_at) AS newest FROM {$table}",
			ARRAY_A
		);
		$since  = self::cutoff( 7 * DAY_IN_SECONDS );
		$recent = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s", $since )
		);
		$bytes = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT data_length + index_length FROM information_schema.tables
			 WHERE table_schema = DATABASE() AND table_name = %s",
			$table
		) );
		// phpcs:enable

		$rows_total = (int) ( $row['rows_total'] ?? 0 );

		return array(
			'enabled'        => true,
			'rows'           => $rows_total,
			'bytes'          => $bytes,
			'bytes_per_row'  => $rows_total > 0 && $bytes > 0 ? (int) round( $bytes / $rows_total ) : 0,
			'rows_per_day'   => (int) round( $recent / 7 ),
			'oldest'         => (string) ( $row['oldest'] ?? '' ),
			'newest'         => (string) ( $row['newest'] ?? '' ),
			'retention_days' => self::retention_days(),
			'max_rows'       => self::max_rows(),
		);
	}

	// ── read / aggregate API (for the traffic_log command) ───────────────────────

	/**
	 * Build a threat summary over the last $hours: totals, top IPs by request and by suspicious
	 * activity, top probed/404 paths, login-failure sources, a recent suspicious-event sample, and
	 * suggested block rules. All read-only aggregation.
	 */
	public static function summary( int $hours = 24, int $limit = 20 ): array {
		if ( ! self::table_exists() ) {
			return array( 'enabled' => false );
		}
		global $wpdb;
		$table  = self::table_name();
		$hours  = max( 1, min( self::max_window_hours(), $hours ) );
		$since  = self::cutoff( $hours * HOUR_IN_SECONDS );
		$limit  = max( 1, min( 100, $limit ) );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$totals = $wpdb->get_row( $wpdb->prepare(
			"SELECT COUNT(*) AS requests, COUNT(DISTINCT ip) AS ips,
			        SUM(suspicious) AS suspicious,
			        SUM(status = 404) AS not_found,
			        SUM(reason = 'login_post') AS login_attempts
			 FROM {$table} WHERE created_at >= %s",
			$since
		), ARRAY_A );

		$top_ips = $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, COUNT(*) AS requests, SUM(suspicious) AS suspicious,
			        SUM(status = 404) AS not_found, SUM(reason = 'login_post') AS login_attempts,
			        COUNT(DISTINCT user_agent) AS distinct_uas,
			        MAX(created_at) AS last_seen
			 FROM {$table} WHERE created_at >= %s AND ip <> ''
			 GROUP BY ip ORDER BY suspicious DESC, requests DESC LIMIT %d",
			$since, $limit
		), ARRAY_A );

		$top_paths = $wpdb->get_results( $wpdb->prepare(
			"SELECT path, reason, COUNT(*) AS hits, COUNT(DISTINCT ip) AS ips
			 FROM {$table} WHERE created_at >= %s AND suspicious = 1
			 GROUP BY path, reason ORDER BY hits DESC LIMIT %d",
			$since, $limit
		), ARRAY_A );

		$recent = $wpdb->get_results( $wpdb->prepare(
			"SELECT created_at, ip, method, path, status, reason, LEFT(user_agent, 120) AS user_agent
			 FROM {$table} WHERE created_at >= %s AND suspicious = 1
			 ORDER BY id DESC LIMIT %d",
			$since, $limit
		), ARRAY_A );
		// phpcs:enable

		return array(
			'enabled'      => true,
			'window_hours' => $hours,
			'generated_at' => gmdate( 'c' ),
			'totals'       => array(
				'requests'       => (int) ( $totals['requests'] ?? 0 ),
				'unique_ips'     => (int) ( $totals['ips'] ?? 0 ),
				'suspicious'     => (int) ( $totals['suspicious'] ?? 0 ),
				'not_found'      => (int) ( $totals['not_found'] ?? 0 ),
				'login_attempts' => (int) ( $totals['login_attempts'] ?? 0 ),
			),
			'top_ips'      => array_map( array( __CLASS__, 'with_verdict' ), (array) $top_ips ),
			'top_paths'    => array_map( array( __CLASS__, 'int_counts' ), (array) $top_paths ),
			'recent'       => (array) $recent,
			'suggested'    => self::suggest_rules( (array) $top_ips ),
		);
	}

	/**
	 * Single-IP activity profile over the last $hours: header counts, status-code mix, top paths,
	 * distinct user-agents, request rate, the suspicious-reason breakdown, and a capped timeline of
	 * the most recent requests. Drives the Traffic → IP drill-down. All read-only aggregation against
	 * the indexed `ip` column, so it stays cheap. The window is clamped to the retention horizon (or to
	 * MAX_WINDOW_DAYS when retention is unlimited), so a caller can never ask for history the table
	 * doesn't keep.
	 *
	 * @return array{enabled:bool} on miss, or the full profile shape on hit.
	 */
	public static function profile_ip( string $ip, int $hours = 168, int $timeline = 200 ): array {
		if ( ! self::table_exists() || '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return array( 'enabled' => false );
		}
		global $wpdb;
		$table    = self::table_name();
		$hours    = max( 1, min( self::max_window_hours(), $hours ) );
		$since    = self::cutoff( $hours * HOUR_IN_SECONDS );
		$timeline = max( 1, min( 500, $timeline ) );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$totals = $wpdb->get_row( $wpdb->prepare(
			"SELECT COUNT(*) AS requests, SUM(suspicious) AS suspicious,
			        SUM(status = 404) AS not_found,
			        SUM(reason = 'login_post') AS login_attempts,
			        COUNT(DISTINCT path) AS distinct_paths,
			        COUNT(DISTINCT user_agent) AS distinct_uas,
			        MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
			 FROM {$table} WHERE ip = %s AND created_at >= %s",
			$ip, $since
		), ARRAY_A );

		$statuses = $wpdb->get_results( $wpdb->prepare(
			"SELECT status, COUNT(*) AS hits FROM {$table}
			 WHERE ip = %s AND created_at >= %s
			 GROUP BY status ORDER BY hits DESC",
			$ip, $since
		), ARRAY_A );

		$reasons = $wpdb->get_results( $wpdb->prepare(
			"SELECT reason, COUNT(*) AS hits FROM {$table}
			 WHERE ip = %s AND created_at >= %s AND reason <> ''
			 GROUP BY reason ORDER BY hits DESC",
			$ip, $since
		), ARRAY_A );

		$paths = $wpdb->get_results( $wpdb->prepare(
			"SELECT path, COUNT(*) AS hits, SUM(suspicious) AS suspicious FROM {$table}
			 WHERE ip = %s AND created_at >= %s
			 GROUP BY path ORDER BY hits DESC LIMIT 15",
			$ip, $since
		), ARRAY_A );

		$user_agents = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent, COUNT(*) AS hits FROM {$table}
			 WHERE ip = %s AND created_at >= %s
			 GROUP BY user_agent ORDER BY hits DESC LIMIT 10",
			$ip, $since
		), ARRAY_A );

		$recent = $wpdb->get_results( $wpdb->prepare(
			"SELECT created_at, method, path, status, suspicious, reason, LEFT(user_agent, 160) AS user_agent
			 FROM {$table} WHERE ip = %s AND created_at >= %s
			 ORDER BY id DESC LIMIT %d",
			$ip, $since, $timeline
		), ARRAY_A );
		// phpcs:enable

		$requests   = (int) ( $totals['requests'] ?? 0 );
		$suspicious = (int) ( $totals['suspicious'] ?? 0 );

		return array(
			'enabled'      => true,
			'ip'           => $ip,
			'window_hours' => $hours,
			'generated_at' => gmdate( 'c' ),
			'totals'       => array(
				'requests'       => $requests,
				'suspicious'     => $suspicious,
				'not_found'      => (int) ( $totals['not_found'] ?? 0 ),
				'login_attempts' => (int) ( $totals['login_attempts'] ?? 0 ),
				'distinct_paths' => (int) ( $totals['distinct_paths'] ?? 0 ),
				'distinct_uas'   => (int) ( $totals['distinct_uas'] ?? 0 ),
				'first_seen'     => (string) ( $totals['first_seen'] ?? '' ),
				'last_seen'      => (string) ( $totals['last_seen'] ?? '' ),
			),
			'verdict'      => self::ip_verdict( $totals, $hours ),
			'statuses'     => array_map( array( __CLASS__, 'int_counts' ), (array) $statuses ),
			'reasons'      => array_map( array( __CLASS__, 'int_counts' ), (array) $reasons ),
			'paths'        => array_map( array( __CLASS__, 'int_counts' ), (array) $paths ),
			'user_agents'  => array_map( array( __CLASS__, 'int_counts' ), (array) $user_agents ),
			'timeline'     => (array) $recent,
		);
	}

	/**
	 * A plain-language read on whether a single IP looks like an intruder, so a non-expert admin or
	 * agent can decide "block or not" without reading raw rows. Returns a level (clean / watch /
	 * suspicious / hostile) plus the human-readable signals that drove it. Thresholds mirror the
	 * suggest_rules() heuristics so the per-IP verdict and the top-IP "suggested block" badge agree.
	 *
	 * @return array{level:string,signals:string[]}
	 */
	private static function ip_verdict( ?array $t, int $hours ): array {
		$requests   = (int) ( $t['requests'] ?? 0 );
		$suspicious = (int) ( $t['suspicious'] ?? 0 );
		$logins     = (int) ( $t['login_attempts'] ?? 0 );
		$not_found  = (int) ( $t['not_found'] ?? 0 );
		$ua_count   = (int) ( $t['distinct_uas'] ?? 0 );

		$signals = array();
		$score   = 0;

		if ( $logins >= 20 ) {
			/* translators: %d: number of login attempts from this IP */
			$signals[] = sprintf( _n( '%d login attempt (brute-force)', '%d login attempts (brute-force)', $logins, 'ini-protector' ), $logins );
			$score    += ( $logins >= 50 ) ? 3 : 2;
		}
		if ( $not_found >= 50 ) {
			/* translators: %d: number of 404 responses this IP received */
			$signals[] = sprintf( _n( '%d 404 (scanning)', '%d 404s (scanning)', $not_found, 'ini-protector' ), $not_found );
			$score    += 2;
		}
		if ( $suspicious >= 50 ) {
			/* translators: %d: number of suspicious requests from this IP */
			$signals[] = sprintf( _n( '%d suspicious request', '%d suspicious requests', $suspicious, 'ini-protector' ), $suspicious );
			$score    += ( $suspicious >= 200 ) ? 3 : 1;
		}
		if ( $requests >= 1000 ) {
			/* translators: %d: total number of requests from this IP */
			$signals[] = sprintf( _n( '%d request (flooding)', '%d requests (flooding)', $requests, 'ini-protector' ), $requests );
			$score    += 2;
		}
		// A single client rotating many user-agents is a classic bot tell.
		if ( $ua_count >= 8 ) {
			/* translators: %d: number of distinct user-agents seen from this IP */
			$signals[] = sprintf( _n( '%d distinct user-agent (rotating)', '%d distinct user-agents (rotating)', $ua_count, 'ini-protector' ), $ua_count );
			$score    += 1;
		}

		if ( $score >= 4 ) {
			$level = 'hostile';
		} elseif ( $score >= 2 ) {
			$level = 'suspicious';
		} elseif ( $suspicious > 0 ) {
			$level = 'watch';
		} else {
			$level = 'clean';
		}

		return array( 'level' => $level, 'signals' => $signals );
	}

	/** Cast count-ish fields to int (wpdb returns strings). */
	private static function int_counts( array $row ): array {
		foreach ( array( 'requests', 'suspicious', 'not_found', 'login_attempts', 'distinct_uas', 'hits', 'ips' ) as $k ) {
			if ( isset( $row[ $k ] ) ) {
				$row[ $k ] = (int) $row[ $k ];
			}
		}
		return $row;
	}

	/**
	 * int_counts() + the shared verdict level, for top_ips rows. Both the overview list badge and the
	 * single-IP detail page read this same `verdict` level, so they can never disagree. The window
	 * isn't needed for the level itself (thresholds are absolute counts), so 0 is passed.
	 */
	private static function with_verdict( array $row ): array {
		$row              = self::int_counts( $row );
		$verdict          = self::ip_verdict( $row, 0 );
		$row['verdict']   = $verdict['level'];
		return $row;
	}

	/**
	 * Turn the worst offenders into suggested block rules. Suggestion-only — the connector does NOT
	 * apply these in v1. A rule is suggested when an IP crosses an obvious-abuse threshold.
	 */
	private static function suggest_rules( array $top_ips ): array {
		$out = array();
		foreach ( $top_ips as $row ) {
			$ip          = (string) ( $row['ip'] ?? '' );
			$suspicious  = (int) ( $row['suspicious'] ?? 0 );
			$logins      = (int) ( $row['login_attempts'] ?? 0 );
			$not_found   = (int) ( $row['not_found'] ?? 0 );
			$requests    = (int) ( $row['requests'] ?? 0 );
			if ( '' === $ip ) {
				continue;
			}
			$why = '';
			if ( $logins >= 20 ) {
				$why = sprintf( '%d login attempts', $logins );
			} elseif ( $not_found >= 50 ) {
				$why = sprintf( '%d 404s (scanning)', $not_found );
			} elseif ( $suspicious >= 50 ) {
				$why = sprintf( '%d suspicious requests', $suspicious );
			} elseif ( $requests >= 1000 ) {
				$why = sprintf( '%d requests (flooding)', $requests );
			}
			if ( '' !== $why ) {
				$out[] = array(
					'ip'       => $ip,
					'reason'   => $why,
					'severity' => ( $logins >= 50 || $suspicious >= 200 ) ? 'high' : 'medium',
				);
			}
		}
		return $out;
	}

	/** Empty the log (admin action). */
	public static function clear(): bool {
		if ( ! self::table_exists() ) {
			return true;
		}
		global $wpdb;
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return false !== $wpdb->query( "TRUNCATE TABLE {$table}" );
	}
}
