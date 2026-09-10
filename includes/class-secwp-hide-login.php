<?php
/**
 * Mask the login URL. Moves wp-login.php to a secret slug so brute-force bots hitting the default
 * login URLs find nothing, and redirects those defaults away. Pairs with the login captcha and
 * limit-login tweaks (they hook the login flow, which is slug-agnostic).
 *
 * Safety (this feature is the classic way to lock yourself out, so it's defensive):
 *  - INERT WITHOUT A SLUG: with no configured slug the tweak does nothing — login stays at
 *    wp-login.php — so enabling it can't instantly 404 your own login.
 *  - RESERVED-SLUG GUARD: a slug that collides with wp-admin/wp-content/an existing page is
 *    rejected (is_active() returns false), so the tweak stays inert rather than shadowing a real
 *    URL.
 *  - LOGGED-IN ADMINS ARE NEVER BLOCKED: the redirect only affects logged-OUT visitors, so an
 *    admin can't trap themselves mid-session.
 *  - The INI WP signed channel (REST iniwp/v1), admin-ajax, cron and the REST API are untouched —
 *    only the human wp-login.php / wp-admin entry points move.
 *
 * Config: 'hide_login' → slug, redirect_to. The connector also reports the active login URL in
 * its /status snapshot so the control panel can always show it (no lockout for the operator).
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Hide_Login {

	/** Reserved tokens a login slug may never be (would break the site or shadow core paths). */
	const RESERVED = array( 'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'admin', 'login', 'wp-login.php', 'index.php' );

	public function register(): void {
		if ( ! self::is_active() ) {
			return;
		}
		// Gate on wp_loaded (NOT plugins_loaded): by then pluggable.php and the current user are
		// set up, so is_user_logged_in()/wp_safe_redirect() exist and are correct — calling them on
		// plugins_loaded would fatal or mis-read every visitor as logged-out (locking admins out).
		add_action( 'wp_loaded', array( $this, 'handle' ), 1 );

		// Rewrite every login URL WordPress generates so links/redirects use the secret slug.
		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 2 );
		add_filter( 'wp_redirect', array( $this, 'filter_redirect' ), 10, 1 );
		add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 1 );
		add_filter( 'logout_url', array( $this, 'filter_login_url' ), 10, 1 );
		add_filter( 'lostpassword_url', array( $this, 'filter_login_url' ), 10, 1 );
		add_filter( 'register_url', array( $this, 'filter_login_url' ), 10, 1 );
	}

	/** Never touch non-browser entry points — REST (incl. our channel), AJAX, cron, CLI, XML-RPC. */
	private function is_exempt_request(): bool {
		return ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'DOING_AJAX' ) && DOING_AJAX )
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST );
	}

	/** The configured, sanitized slug (empty string if unset). */
	public static function slug(): string {
		$raw = (string) SecurityWP_Features::get( 'hide_login', 'slug', '' );
		return sanitize_title( $raw );
	}

	/** True only when a valid, non-reserved slug is set — otherwise the tweak stays inert. */
	public static function is_active(): bool {
		$slug = self::slug();
		if ( '' === $slug || in_array( $slug, self::RESERVED, true ) ) {
			return false;
		}
		// Don't let the slug shadow an existing page/post.
		if ( function_exists( 'get_page_by_path' ) && get_page_by_path( $slug ) ) {
			return false;
		}
		return true;
	}

	/** The full secret login URL (for the panel/status). Falls back to wp-login when inactive. */
	public static function login_url(): string {
		if ( ! self::is_active() ) {
			return site_url( 'wp-login.php', 'login' );
		}
		return home_url( '/' . self::slug() . '/', 'login' );
	}

	private function redirect_target(): string {
		$to = trim( (string) SecurityWP_Features::get( 'hide_login', 'redirect_to', '' ) );
		if ( '' === $to ) {
			return home_url( '/' );
		}
		// Allow a path ("/contact") or a full URL.
		if ( preg_match( '#^https?://#i', $to ) ) {
			return esc_url_raw( $to );
		}
		return home_url( '/' . ltrim( $to, '/' ) );
	}

	/** The request path (no query), normalized without leading/trailing slashes. */
	private function request_path(): string {
		$uri  = SecurityWP_Input::request_uri();
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH ); // subdirectory installs
		if ( '' !== $home && '/' !== $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		return trim( $path, '/' );
	}

	/**
	 * The single gate (on wp_loaded): serve the login page when the request comes in on the secret
	 * slug; bounce logged-OUT visitors who hit the default login/admin URLs to the redirect target.
	 *
	 * Whitelisting matters: wp-login.php's logout, password-reset, registration and POST flows all
	 * arrive as ?action=… on the slug (our URL filters rewrite the links), so once we match the
	 * slug we hand the WHOLE request — query string and all — to wp-login.php, which dispatches the
	 * action normally. We never bounce those; we only bounce a BARE hit to the real wp-login.php.
	 */
	public function handle(): void {
		if ( $this->is_exempt_request() ) {
			return;
		}
		$path = $this->request_path();
		$slug = self::slug();

		// 1) Secret slug → serve wp-login.php (handles sign-in, logout, lostpassword, rp, register,
		//    and the login POST — all via the preserved ?action / $_POST).
		if ( $path === $slug ) {
			// Core normally runs in global scope. Share the login state with
			// login_header(), login_footer() and authentication hooks when it is
			// included from this method instead.
			global $pagenow, $user_login, $error, $action, $interim_login, $errors;
			$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			require_once ABSPATH . 'wp-login.php';
			exit;
		}

		// 2) Logged-IN users are never affected from here on (can reach wp-admin normally).
		if ( is_user_logged_in() ) {
			return;
		}

		// 3) Logged-out hit to the default login page → bounce to the redirect target.
		if ( 'wp-login.php' === $path ) {
			wp_safe_redirect( $this->redirect_target() );
			exit;
		}

		// 4) Logged-out hit to wp-admin (but NOT admin-ajax/admin-post, which are exempt above for
		//    AJAX and handled by core for legit public posts) → bounce instead of revealing login.
		if ( 0 === strpos( $path, 'wp-admin/' ) || 'wp-admin' === $path ) {
			if ( false === strpos( $path, 'admin-ajax.php' ) && false === strpos( $path, 'admin-post.php' ) ) {
				wp_safe_redirect( $this->redirect_target() );
				exit;
			}
		}
	}

	// ── URL rewriting ─────────────────────────────────────────────────────────

	private function swap( string $url ): string {
		// Replace the wp-login.php path with our slug, preserving any query string.
		return str_replace( 'wp-login.php', self::slug(), $url );
	}

	public function filter_site_url( $url, $path ) {
		if ( is_string( $path ) && 0 === strpos( ltrim( $path, '/' ), 'wp-login.php' ) ) {
			return $this->swap( $url );
		}
		return $url;
	}

	public function filter_redirect( $location ) {
		if ( is_string( $location ) && false !== strpos( $location, 'wp-login.php' ) ) {
			return $this->swap( $location );
		}
		return $location;
	}

	public function filter_login_url( $url ) {
		return is_string( $url ) ? $this->swap( $url ) : $url;
	}
}
