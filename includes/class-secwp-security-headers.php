<?php
/**
 * Security response headers. Sends a configurable set of hardening HTTP headers on front-end
 * responses: X-Frame-Options (clickjacking), X-Content-Type-Options (MIME sniffing),
 * Referrer-Policy, Permissions-Policy, and (opt-in) X-XSS-Protection: 0.
 *
 * Design notes:
 *  - FRONT-END ONLY: we don't touch wp-admin, the REST API (incl. the INI WP channel), AJAX,
 *    cron, CLI, or feeds — only normal visitor page responses. Hardening headers on the admin
 *    can break embeds/previews and aren't where the risk is.
 *  - NEVER DUPLICATE: if a header is already present (set by Caddy/Nginx/Cloudflare or another
 *    plugin) we leave it alone, so you don't get two conflicting values on the wire.
 *  - PER-HEADER: each header is an independent checkbox; X-Frame-Options and Referrer-Policy /
 *    Permissions-Policy carry a value chosen in the config.
 *  - X-XSS-Protection is DEPRECATED. The only correct modern value is "0" (disable the legacy
 *    auditor, per OWASP), so when enabled we send exactly that — never "1; mode=block".
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Security_Headers {

	public function register(): void {
		// send_headers fires on every front-end request (via wp) before output — the right place
		// to add response headers. Late priority so we can see headers other code already set.
		add_action( 'send_headers', array( $this, 'send' ), 100 );
	}

	/** Only emit on real front-end visitor responses — never admin/REST/AJAX/cron/CLI/feeds. */
	private function is_frontend_request(): bool {
		if ( is_admin()
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'DOING_AJAX' ) && DOING_AJAX )
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| is_feed() ) {
			return false;
		}
		return true;
	}

	/** True if a header of this name was already emitted (case-insensitive) — don't duplicate it. */
	private function already_set( string $name ): bool {
		if ( ! function_exists( 'headers_list' ) ) {
			return false;
		}
		$needle = strtolower( $name ) . ':';
		foreach ( headers_list() as $h ) {
			if ( 0 === strpos( strtolower( $h ), $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/** Send a header only if it isn't already present (replace=false to be extra safe). */
	private function maybe_header( string $name, string $value ): void {
		if ( headers_sent() || $this->already_set( $name ) ) {
			return;
		}
		header( $name . ': ' . $value, false );
	}

	public function send(): void {
		if ( ! $this->is_frontend_request() ) {
			return;
		}

		if ( SecurityWP_Features::get( 'security_headers', 'x_frame_options', true ) ) {
			// Compare case-insensitively: the select value is stored via sanitize_key(), which
			// lowercases it (SAMEORIGIN → sameorigin), so never compare against the raw casing.
			$v = strtolower( trim( (string) SecurityWP_Features::get( 'security_headers', 'x_frame_value', 'SAMEORIGIN' ) ) );
			$this->maybe_header( 'X-Frame-Options', 'deny' === $v ? 'DENY' : 'SAMEORIGIN' );
		}

		if ( SecurityWP_Features::get( 'security_headers', 'x_content_type_options', true ) ) {
			$this->maybe_header( 'X-Content-Type-Options', 'nosniff' );
		}

		if ( SecurityWP_Features::get( 'security_headers', 'referrer_policy', true ) ) {
			$allowed = array( 'strict-origin-when-cross-origin', 'no-referrer', 'same-origin', 'strict-origin', 'no-referrer-when-downgrade' );
			$v       = strtolower( trim( (string) SecurityWP_Features::get( 'security_headers', 'referrer_value', 'strict-origin-when-cross-origin' ) ) );
			$this->maybe_header( 'Referrer-Policy', in_array( $v, $allowed, true ) ? $v : 'strict-origin-when-cross-origin' );
		}

		if ( SecurityWP_Features::get( 'security_headers', 'permissions_policy', true ) ) {
			$this->maybe_header( 'Permissions-Policy', $this->permissions_value() );
		}

		// Opt-in, off by default. The only modern-correct value is "0" (disable the legacy auditor).
		if ( SecurityWP_Features::get( 'security_headers', 'x_xss_protection', false ) ) {
			$this->maybe_header( 'X-XSS-Protection', '0' );
		}
	}

	/** Build the Permissions-Policy header value from the chosen preset. */
	private function permissions_value(): string {
		$preset = (string) SecurityWP_Features::get( 'security_headers', 'permissions_value', 'lockdown' );
		// Each feature set to "()" means: allowed for no origin (fully disabled).
		if ( 'no_sensors' === $preset ) {
			$features = array( 'camera', 'microphone', 'geolocation' );
		} else {
			$features = array( 'camera', 'microphone', 'geolocation', 'usb', 'payment', 'magnetometer', 'accelerometer', 'gyroscope' );
		}
		return implode( ', ', array_map( static fn( $f ) => $f . '=()', $features ) );
	}
}
