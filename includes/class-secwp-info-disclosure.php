<?php
/**
 * Prevent information disclosure. Blocks directory browsing and direct HTTP access to sensitive
 * files (wp-config, .htaccess, backups, logs) and the readme/license files that leak the WP
 * version.
 *
 * On Apache it writes a guarded block into the site's .htaccess via WP's insert_with_markers()
 * (added when the tweak turns on, removed when it turns off — see maybe_sync_htaccess()). On any
 * server it also enforces the readme/license/file-type blocks at the PHP level, so protection
 * doesn't depend on the web server. Nginx users are shown the equivalent config in the admin.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Info_Disclosure {

	const MARKER = 'SecurityWP — Information Disclosure';

	public function register(): void {
		// PHP-level guards (server-agnostic): 403 the readme/license + obvious sensitive requests.
		add_action( 'init', array( $this, 'block_sensitive_requests' ), 0 );
		// Keep the .htaccess block in sync with the toggle state (Apache only).
		add_action( 'admin_init', array( $this, 'maybe_sync_htaccess' ) );
	}

	/** True on Apache/LiteSpeed where .htaccess is honored. */
	private function is_apache(): bool {
		if ( function_exists( 'apache_get_modules' ) ) {
			return true;
		}
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		return false !== strpos( $server, 'apache' ) || false !== strpos( $server, 'litespeed' );
	}

	/** Block direct access to readme/license and clearly-sensitive file requests at the PHP layer. */
	public function block_sensitive_requests(): void {
		if ( is_admin() ) {
			return;
		}
		$uri = strtolower( SecurityWP_Input::request_uri() );
		if ( '' === $uri ) {
			return;
		}
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		// Version-leaking files at the web root.
		if ( preg_match( '#/(readme\.html|license\.txt|wp-config-sample\.php)$#', $path ) ) {
			$this->forbid();
		}
		// Sensitive file types / names anywhere in the path.
		if ( preg_match( '#\.(bak|backup|old|orig|save|swp|sql|log|sh|ini|conf)$#', $path )
			|| preg_match( '#/(wp-config\.php|\.htaccess|\.htpasswd|\.env|wp-config\.bak)$#', $path ) ) {
			$this->forbid();
		}
	}

	private function forbid(): void {
		status_header( 403 );
		nocache_headers();
		wp_die( 'Forbidden', 'Forbidden', array( 'response' => 403 ) );
	}

	// ── .htaccess management (Apache) ───────────────────────────────────────────

	/** The protective rules we insert between the markers. */
	public static function htaccess_rules(): array {
		return array(
			'<IfModule mod_autoindex.c>',
			'Options -Indexes',
			'</IfModule>',
			'<FilesMatch "(?i)(^\.ht|wp-config\.php|\.(bak|backup|old|orig|save|swp|sql|log|sh|ini|conf|env)$|readme\.html|license\.txt|wp-config-sample\.php)">',
			'Require all denied',
			'</FilesMatch>',
		);
	}

	/** Add or remove the .htaccess block to match the current on/off state (Apache only). */
	public function maybe_sync_htaccess(): void {
		if ( ! $this->is_apache() ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$htaccess = get_home_path() . '.htaccess';

		// Only write if we can (don't fatal on a read-only filesystem).
		if ( file_exists( $htaccess ) && ! wp_is_writable( $htaccess ) ) {
			return;
		}
		if ( ! file_exists( $htaccess ) && ! wp_is_writable( dirname( $htaccess ) ) ) {
			return;
		}

		$on    = SecurityWP_Features::is_on( 'prevent_info_disclosure' );
		$rules = $on ? self::htaccess_rules() : array();
		insert_with_markers( $htaccess, self::MARKER, $rules );
	}

	/** Remove our .htaccess block (called on uninstall/disable cleanup). */
	public static function remove_htaccess(): void {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$htaccess = get_home_path() . '.htaccess';
		if ( file_exists( $htaccess ) && wp_is_writable( $htaccess ) ) {
			insert_with_markers( $htaccess, self::MARKER, array() );
		}
	}

	/** Nginx equivalent, shown in the admin for non-Apache servers. */
	public static function nginx_snippet(): string {
		return "location ~* /(readme\\.html|license\\.txt|wp-config-sample\\.php)$ { deny all; }\n"
			. "location ~* \\.(bak|backup|old|orig|save|swp|sql|log|sh|ini|conf|env)$ { deny all; }\n"
			. "location ~ /\\.(ht|env) { deny all; }\n"
			. "location = /wp-config.php { deny all; }\n"
			. "autoindex off;";
	}
}
