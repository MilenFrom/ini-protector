<?php
/**
 * Security scan: a read-only audit + core-integrity check, run on demand via the signed
 * `security_scan` command. Returns structured findings for the control panel to store, display,
 * and alert on. Nothing here changes site state.
 *
 *  - audit: a hardening checklist (file editor, XML-RPC, default admin user, table prefix,
 *    debug-in-production, directory listing, PHP/WordPress versions, SSL, registration, and which
 *    of our own hardening tweaks are enabled). Each finding: id, label, status (pass|warn|fail),
 *    detail, and a short fix.
 *  - integrity: compares WordPress core files against the official WordPress.org checksums and
 *    flags modified core files, missing core files, and unexpected PHP files in core directories,
 *    plus PHP files in uploads/. This is a core-integrity check, NOT a signature-based AV.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Security_Scan {

	/** @param array $params Optional { kinds: string[] } subset of [audit, integrity]. */
	public static function run( array $params ) {
		$kinds = isset( $params['kinds'] ) && is_array( $params['kinds'] ) ? $params['kinds'] : array( 'audit', 'integrity' );

		$out = array( 'scanned_at' => gmdate( 'c' ) );
		if ( in_array( 'audit', $kinds, true ) ) {
			$out['audit'] = self::audit();
		}
		if ( in_array( 'integrity', $kinds, true ) ) {
			$out['integrity'] = self::integrity();
		}
		// Roll up a single worst-status for convenience.
		$out['summary'] = self::summarize( $out );
		return $out;
	}

	// ── hardening audit ─────────────────────────────────────────────────────────

	private static function audit(): array {
		$f = array();

		// File editor.
		$editor_off = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		$f[] = self::finding( 'file_editor', 'Theme/plugin file editor disabled', $editor_off ? 'pass' : 'warn',
			$editor_off ? 'DISALLOW_FILE_EDIT is set.' : 'The built-in code editor is enabled.',
			'Enable the “Disable theme/plugin file editor” tweak.' );

		// XML-RPC.
		$xmlrpc_on = (bool) apply_filters( 'xmlrpc_enabled', true );
		$f[] = self::finding( 'xmlrpc', 'XML-RPC disabled', $xmlrpc_on ? 'warn' : 'pass',
			$xmlrpc_on ? 'xmlrpc.php is reachable (brute-force/pingback vector).' : 'XML-RPC is disabled.',
			'Enable the “Disable XML-RPC” tweak unless a service needs it.' );

		// Default 'admin' username.
		$has_admin = (bool) get_user_by( 'login', 'admin' );
		$f[] = self::finding( 'admin_user', 'No default “admin” username', $has_admin ? 'fail' : 'pass',
			$has_admin ? 'A user named “admin” exists — a prime brute-force target.' : 'No “admin” account.',
			'Create a new admin user with a unique name and delete “admin”.' );

		// Table prefix.
		global $wpdb;
		$default_prefix = ( 'wp_' === $wpdb->prefix );
		$f[] = self::finding( 'table_prefix', 'Non-default DB table prefix', $default_prefix ? 'warn' : 'pass',
			$default_prefix ? 'The database uses the default wp_ prefix.' : 'Custom table prefix in use.',
			'A non-default prefix slightly raises the bar for some automated SQLi tools.' );

		// Debug display in production.
		$debug_display = ( defined( 'WP_DEBUG' ) && WP_DEBUG ) && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$f[] = self::finding( 'debug_display', 'Debug output not shown to visitors', $debug_display ? 'fail' : 'pass',
			$debug_display ? 'WP_DEBUG_DISPLAY is on — errors may leak paths to visitors.' : 'Debug display is off.',
			'Set WP_DEBUG_DISPLAY to false in wp-config.php for production.' );

		// How the client IP is decided (it drives blocking, so forgery matters).
		$trusted    = class_exists( 'SecurityWP_Traffic_Log' ) ? SecurityWP_Traffic_Log::trusted_proxies() : array();
		$legacy     = defined( 'SECWP_TRUST_PROXY' ) && SECWP_TRUST_PROXY;
		$proxy_warn = $legacy && ! $trusted;
		$f[] = self::finding( 'forwarded_ip', 'Client IP cannot be forged', $proxy_warn ? 'warn' : 'pass',
			$proxy_warn
				? 'SECWP_TRUST_PROXY accepts X-Forwarded-For / CF-Connecting-IP without checking who sent it. A visitor reaching the origin directly can hide behind another IP, or get that IP blocked.'
				: ( $trusted
					? 'Forwarded headers are accepted only from the declared proxy addresses.'
					: 'Client IPs come from the socket peer, which a visitor cannot forge.' ),
			'Replace SECWP_TRUST_PROXY with SECWP_TRUSTED_PROXIES in wp-config.php, listing your proxy/CDN ranges — e.g. define( \'SECWP_TRUSTED_PROXIES\', \'173.245.48.0/20, 2400:cb00::/32\' );' );

		// PHP version (EOL check, rough).
		$php_ok = version_compare( PHP_VERSION, '8.1', '>=' );
		$f[] = self::finding( 'php_version', 'Supported PHP version', $php_ok ? 'pass' : 'warn',
			'PHP ' . PHP_VERSION . ( $php_ok ? '' : ' is old; upgrade for security fixes.' ),
			'Ask the host to move to PHP 8.1+.' );

		// WordPress up to date.
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$core      = get_preferred_from_update_core();
		$wp_latest = ( is_object( $core ) && isset( $core->response ) ) ? ( 'latest' === $core->response || 'development' === $core->response ) : true;
		$f[] = self::finding( 'wp_version', 'WordPress up to date', $wp_latest ? 'pass' : 'warn',
			$wp_latest ? 'Running the latest core.' : 'A WordPress core update is available.',
			'Update WordPress core.' );

		// SSL on the site URL.
		$ssl = ( 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ) );
		$f[] = self::finding( 'ssl', 'Site served over HTTPS', $ssl ? 'pass' : 'fail',
			$ssl ? 'Home URL uses https.' : 'The site URL is not https.',
			'Install a TLS certificate and set the site/home URL to https.' );

		// Open registration.
		$open_reg = (bool) get_option( 'users_can_register' );
		$role     = (string) get_option( 'default_role' );
		$risky    = $open_reg && in_array( $role, array( 'administrator', 'editor', 'author' ), true );
		$f[] = self::finding( 'registration', 'Registration role is safe', $risky ? 'fail' : 'pass',
			$open_reg ? ( 'Open registration; default role: ' . $role . '.' ) : 'Registration is closed.',
			$risky ? 'Set the default role to Subscriber, or close registration.' : 'No action needed.' );

		// Directory listing on the uploads dir (best-effort fetch).
		$f[] = self::dir_listing_finding();

		// Our own hardening tweaks.
		foreach ( array(
			'limit_login'             => 'Limit login attempts',
			'altcha'                  => 'Login captcha',
			'prevent_user_enum'       => 'Prevent user enumeration',
			'prevent_info_disclosure' => 'Prevent information disclosure',
		) as $key => $label ) {
			$on  = SecurityWP_Features::is_on( $key );
			$f[] = self::finding( 'tweak_' . $key, $label . ' enabled', $on ? 'pass' : 'warn',
				$on ? 'Enabled.' : 'Not enabled.', 'Enable the “' . $label . '” tweak.' );
		}

		return $f;
	}

	private static function dir_listing_finding(): array {
		$upload = wp_get_upload_dir();
		$url    = isset( $upload['baseurl'] ) ? trailingslashit( $upload['baseurl'] ) : '';
		$listing = false;
		if ( '' !== $url ) {
			$resp = wp_remote_get( $url, array( 'timeout' => 5, 'sslverify' => true ) );
			if ( ! is_wp_error( $resp ) && 200 === (int) wp_remote_retrieve_response_code( $resp ) ) {
				$body    = (string) wp_remote_retrieve_body( $resp );
				$listing = ( false !== stripos( $body, 'Index of' ) );
			}
		}
		return self::finding( 'dir_listing', 'Directory listing disabled', $listing ? 'fail' : 'pass',
			$listing ? 'The uploads directory shows a file index.' : 'No directory listing detected.',
			'Enable the “Prevent information disclosure” tweak (adds Options -Indexes).' );
	}

	// ── core integrity ──────────────────────────────────────────────────────────

	private static function integrity(): array {
		require_once ABSPATH . 'wp-admin/includes/update.php';

		$version    = get_bloginfo( 'version' );
		$locale     = get_locale();
		$checksums  = function_exists( 'get_core_checksums' ) ? get_core_checksums( $version, $locale ) : false;
		if ( empty( $checksums ) && 'en_US' !== $locale ) {
			$checksums = get_core_checksums( $version, 'en_US' );
		}
		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			return array(
				'ok'      => false,
				'message' => 'Could not fetch core checksums from WordPress.org for ' . $version . '.',
			);
		}

		$modified = array();
		$missing  = array();
		foreach ( $checksums as $file => $hash ) {
			// Skip user-content files that legitimately vary.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				$missing[] = $file;
				continue;
			}
			// An unreadable core file would make md5_file() return false → a false "modified"
			// flag; skip it rather than report a phantom change.
			if ( is_readable( $path ) && md5_file( $path ) !== $hash ) {
				$modified[] = $file;
			}
		}

		// Unexpected PHP files in core dirs + PHP in uploads (common backdoor locations).
		$unexpected = array_merge(
			self::unexpected_php( ABSPATH . 'wp-includes', $checksums, 'wp-includes/' ),
			self::unexpected_php( ABSPATH . 'wp-admin', $checksums, 'wp-admin/' )
		);
		$upload  = wp_get_upload_dir();
		$up_php  = isset( $upload['basedir'] ) ? self::php_in_dir( $upload['basedir'], 200 ) : array();

		$status = ( $modified || $missing || $unexpected || $up_php ) ? 'fail' : 'pass';

		return array(
			'ok'              => true,
			'wp_version'      => $version,
			'status'          => $status,
			'modified_core'   => array_slice( $modified, 0, 100 ),
			'missing_core'    => array_slice( $missing, 0, 100 ),
			'unexpected_core' => array_slice( $unexpected, 0, 100 ),
			'php_in_uploads'  => array_slice( $up_php, 0, 100 ),
		);
	}

	/** PHP files present in a core dir that aren't in the official checksum manifest. */
	private static function unexpected_php( string $dir, array $checksums, string $prefix ): array {
		$found = array();
		if ( ! is_dir( $dir ) ) {
			return $found;
		}
		// CATCH_GET_CHILD: skip (don't fatal on) subdirectories we can't open on shared hosts.
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $file ) {
			if ( ! $file->isFile() || ! self::is_executable( $file->getFilename() ) ) {
				continue;
			}
			$rel = $prefix . str_replace( '\\', '/', substr( $file->getPathname(), strlen( $dir ) + 1 ) );
			if ( ! isset( $checksums[ $rel ] ) ) {
				$found[] = $rel;
				if ( count( $found ) >= 100 ) {
					break;
				}
			}
		}
		return $found;
	}

	/** Any PHP files under a directory (uploads shouldn't contain executable PHP). */
	private static function php_in_dir( string $dir, int $limit ): array {
		$found = array();
		if ( ! is_dir( $dir ) ) {
			return $found;
		}
		// CATCH_GET_CHILD: skip (don't fatal on) subdirectories we can't open on shared hosts.
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $file ) {
			if ( $file->isFile() && self::is_executable( $file->getFilename() ) ) {
				$found[] = 'uploads/' . str_replace( '\\', '/', substr( $file->getPathname(), strlen( $dir ) + 1 ) );
				if ( count( $found ) >= $limit ) {
					break;
				}
			}
		}
		return $found;
	}

	// ── helpers ─────────────────────────────────────────────────────────────────

	/**
	 * Shared with the integrity monitor, deliberately.
	 *
	 * These two subsystems used to carry three different ideas of what a PHP file is
	 * ('php' exactly, /php\d?/, and a configurable extension list), so a shell named
	 * .php5 was caught by whichever scanner you happened to run and missed by the
	 * others. One definition now, in one place.
	 */
	private static function is_executable( string $filename ): bool {
		if ( class_exists( 'SecurityWP_Integrity' ) ) {
			return SecurityWP_Integrity::is_executable_name( $filename );
		}
		return (bool) preg_match( '/\.(php|phtml|phps|pht|phar|php[3-8])$/i', $filename );
	}

	private static function finding( string $id, string $label, string $status, string $detail, string $fix ): array {
		return array( 'id' => $id, 'label' => $label, 'status' => $status, 'detail' => $detail, 'fix' => $fix );
	}

	private static function summarize( array $out ): array {
		$counts = array( 'pass' => 0, 'warn' => 0, 'fail' => 0 );
		foreach ( ( $out['audit'] ?? array() ) as $finding ) {
			$s = $finding['status'] ?? 'pass';
			if ( isset( $counts[ $s ] ) ) {
				$counts[ $s ]++;
			}
		}
		$integrity_fail = isset( $out['integrity']['status'] ) && 'fail' === $out['integrity']['status'];
		if ( $integrity_fail ) {
			$counts['fail']++;
		}
		$worst = $counts['fail'] > 0 ? 'fail' : ( $counts['warn'] > 0 ? 'warn' : 'pass' );
		return array( 'status' => $worst, 'pass' => $counts['pass'], 'warn' => $counts['warn'], 'fail' => $counts['fail'] );
	}
}
