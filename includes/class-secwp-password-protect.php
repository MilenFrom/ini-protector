<?php
/**
 * Site-wide password protection. Hides the entire front-end behind a single password until the
 * visitor enters it (stored as a signed cookie). Logged-in users who can edit posts bypass it,
 * so admins browse normally. Search engines can't pass the gate, so the protected site stays out
 * of indexes (we also send X-Robots-Tag: noindex while locked).
 *
 * Config: 'password_protect' → password, message.
 *
 * The gate is intentionally NOT applied to: wp-admin, wp-login.php, the REST API (so the INI WP
 * channel and the admin keep working), cron, and the password POST itself.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Password_Protect {

	const COOKIE = 'secwp_site_access';
	const FIELD  = 'secwp_site_password';

	public function register(): void {
		// Nothing to enforce until a password is actually set.
		if ( '' === $this->password() ) {
			return;
		}
		// Handle the password submission early, before headers are sent.
		add_action( 'init', array( $this, 'maybe_handle_submit' ) );
		// Gate normal front-end requests just before the template loads.
		add_action( 'template_redirect', array( $this, 'maybe_gate' ), 0 );

		// The HTML front-end isn't the only way to read the site. While locked, also close the
		// JSON/RPC mirrors so a crawler or scraper can't bypass the gate:
		//  - XML-RPC (xmlrpc.php never reaches template_redirect) — disable entirely.
		//  - Core REST (wp/v2/*) — require login; the connector's own namespaces stay exempt so
		//    the INI WP channel and the admin keep working.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'rest_authentication_errors', array( $this, 'gate_rest' ), 99 );
	}

	/** Require login for public REST routes while the gate is on (except the connector's own). */
	public function gate_rest( $result ) {
		if ( ! empty( $result ) || is_user_logged_in() ) {
			return $result; // Already decided, or an authenticated user — leave as-is.
		}
		$route = SecurityWP_Input::rest_route();
		// Never block our own platform endpoint or the INI WP connector channel
		// (both HMAC-authed; used by the control panel).
		foreach ( array( SECWP_NAMESPACE, SECWP_CONNECTOR_NAMESPACE, 'iniwp/admin' ) as $namespace ) {
			if ( $route === $namespace || 0 === strpos( $route, $namespace . '/' ) ) {
				return $result;
			}
		}
		return new WP_Error( 'secwp_site_locked', 'This site is private.', array( 'status' => 401 ) );
	}

	private function password(): string {
		return (string) SecurityWP_Features::get( 'password_protect', 'password', '' );
	}

	/** A cookie value tied to the current password, so changing the password invalidates old cookies. */
	private function expected_cookie(): string {
		return hash_hmac( 'sha256', 'secwp-site-access', wp_salt( 'auth' ) . '|' . $this->password() );
	}

	/** Anyone who can edit posts (editors/admins) bypasses the gate. */
	private function is_exempt_user(): bool {
		return is_user_logged_in() && current_user_can( 'edit_posts' );
	}

	/** Requests that must never be gated (admin, login, REST, cron, ajax). */
	private function is_exempt_request(): bool {
		if ( is_admin() || wp_doing_cron() || wp_doing_ajax() ) {
			return true;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		global $pagenow;
		if ( 'wp-login.php' === $pagenow ) {
			return true;
		}
		return false;
	}

	private function has_valid_cookie(): bool {
		return isset( $_COOKIE[ self::COOKIE ] ) && is_string( $_COOKIE[ self::COOKIE ] )
			&& hash_equals( $this->expected_cookie(), (string) wp_unslash( $_COOKIE[ self::COOKIE ] ) );
	}

	/** Process a submitted password (sets the access cookie on success). */
	public function maybe_handle_submit(): void {
		if ( ! isset( $_POST[ self::FIELD ] ) || ! is_string( $_POST[ self::FIELD ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return;
		}
		check_admin_referer( 'secwp_site_access', 'secwp_nonce' );
		$password = $this->password();
		if ( '' === $password ) {
			return;
		}
		$submitted = (string) wp_unslash( $_POST[ self::FIELD ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- exact password comparison requires preserving all characters; shape and nonce checked above.
		if ( hash_equals( $password, $submitted ) ) {
			// Session cookie (expires when the browser closes); httponly; secure when on HTTPS.
			setcookie( self::COOKIE, $this->expected_cookie(), array(
				'expires'  => 0,
				'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			) );
			// Redirect back to the same URL (PRG) so a refresh doesn't re-post.
			$target = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : home_url( '/' );
			wp_safe_redirect( $target );
			exit;
		}
		// Wrong password: fall through to the gate, which re-renders with an error.
		$this->wrong = true;
	}

	private $wrong = false;

	/** Show the password screen for unauthorized front-end visitors. */
	public function maybe_gate(): void {
		if ( '' === $this->password() ) {
			return; // Not configured yet — don't lock anyone out.
		}
		if ( $this->is_exempt_request() || $this->is_exempt_user() || $this->has_valid_cookie() ) {
			return;
		}
		$this->render_gate();
		exit;
	}

	private function render_gate(): void {
		wp_enqueue_style( 'secwp-password-gate', SECWP_PLUGIN_URL . 'assets/password-gate.css', array(), SECWP_VERSION );
		nocache_headers();
		header( 'X-Robots-Tag: noindex, nofollow', true );
		status_header( 401 );

		$message = (string) SecurityWP_Features::get( 'password_protect', 'message', '' );
		$title   = get_bloginfo( 'name' );
		$wrong   = $this->wrong;
		?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<title><?php echo esc_html( $title ); ?></title>
	<?php wp_print_styles( array( 'secwp-password-gate' ) ); ?>
</head>
<body>
	<div class="box">
		<h1><?php echo esc_html( $title ); ?></h1>
		<p><?php echo esc_html( '' !== $message ? $message : 'This site is private. Please enter the password to continue.' ); ?></p>
		<form method="post" action="">
			<?php wp_nonce_field( 'secwp_site_access', 'secwp_nonce' ); ?>
			<input type="password" name="<?php echo esc_attr( self::FIELD ); ?>" placeholder="Password" autofocus autocomplete="current-password" />
			<?php if ( $wrong ) : ?><p class="err">Incorrect password. Please try again.</p><?php endif; ?>
			<button type="submit">Enter</button>
		</form>
	</div>
</body>
</html>
		<?php
	}
}
