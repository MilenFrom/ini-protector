<?php
/**
 * Two-factor authentication: login interception, second-step form, enrolment UI,
 * and per-role enforcement.
 *
 * WHERE THE INTERRUPTION HAPPENS, AND WHY THERE
 *
 * On the `authenticate` filter at priority 100 — after core's
 * wp_authenticate_username_password (20) and wp_authenticate_spam_check (99),
 * and before wp_signon() issues a cookie. At that point $user is a WP_User only
 * if the password already verified, which is exactly the required order: check
 * the password, then interrupt before the session exists.
 *
 * NOT on `wp_authenticate_user`, the filter that looks like the right one: core
 * applies it BEFORE wp_check_password() (wp-includes/user.php), so hooking there
 * would prompt for a second factor on an unverified password — turning the 2FA
 * form into an oracle for "this username exists" and accepting a valid code with
 * the wrong password.
 *
 * NOT on `wp_login` either (the approach of clearing a cookie that was already
 * set): there the cookie has been issued and we would be taking it back, which
 * leaves a window and depends on nothing else having read it.
 *
 * NON-INTERACTIVE LOGINS
 *
 * A second factor cannot be prompted for over XML-RPC or a REST basic-auth
 * request, so for a user with 2FA on, password authentication there is REFUSED
 * rather than waved through — otherwise 2FA would be trivially bypassable by
 * pointing the same stolen password at xmlrpc.php. Application passwords are the
 * supported path for automation: they are per-application, individually
 * revocable, and can only be created from inside an already-2FA-protected
 * session, so they are honoured as-is.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_2FA {

	const FEATURE = 'two_factor';

	/** wp-login.php action for the second step. */
	const ACTION = 'secwp_2fa';

	/** How long the half-finished login stays valid. */
	const TOKEN_TTL = 300;

	/** Wrong codes allowed per user before the attempt window is shut. */
	const MAX_ATTEMPTS  = 10;
	const ATTEMPT_WINDOW = 900;

	/** Set when core authenticated this request with an application password. */
	private static $via_app_password = false;

	public function register(): void {
		// Must be registered even when the feature is off, so it can never be the
		// reason a request is misread as an application-password login.
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'flag_app_password' ) );

		if ( ! SecurityWP_Features::is_on( self::FEATURE ) ) {
			return;
		}

		add_filter( 'authenticate', array( __CLASS__, 'intercept' ), 100, 3 );
		add_action( 'login_form_' . self::ACTION, array( __CLASS__, 'handle_second_step' ) );

		// Enrolment UI on the user's own profile and on user-edit screens.
		add_action( 'show_user_profile', array( __CLASS__, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile_section' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile' ) );

		// Per-role enforcement: an account that must use 2FA but has not set it up
		// is sent to its profile until it does.
		add_action( 'admin_init', array( __CLASS__, 'enforce_enrolment' ) );
		add_action( 'admin_notices', array( __CLASS__, 'enrolment_notice' ) );

		// Column on Users so an admin can see who is covered at a glance.
		add_filter( 'manage_users_columns', array( __CLASS__, 'users_column' ) );
		add_filter( 'manage_users_custom_column', array( __CLASS__, 'users_column_value' ), 10, 3 );
	}

	public static function flag_app_password(): void {
		self::$via_app_password = true;
	}

	/* --------------------------------------------------------------------- */
	/* Configuration                                                          */
	/* --------------------------------------------------------------------- */

	/** Roles required to use 2FA. */
	public static function required_roles(): array {
		$roles = SecurityWP_Features::get( self::FEATURE, 'roles', array( 'administrator' ) );
		if ( ! is_array( $roles ) ) {
			$roles = array( 'administrator' );
		}
		return array_values( array_filter( array_map( 'strval', $roles ) ) );
	}

	/** Is this user in a role that must use 2FA? */
	public static function is_required_for( WP_User $user ): bool {
		$required = self::required_roles();
		if ( ! $required ) {
			return false;
		}
		return (bool) array_intersect( $required, (array) $user->roles );
	}

	/* --------------------------------------------------------------------- */
	/* Login interception                                                     */
	/* --------------------------------------------------------------------- */

	/**
	 * @param WP_User|WP_Error|null $user Result of the preceding authenticate filters.
	 * @return WP_User|WP_Error|null
	 */
	public static function intercept( $user, $username = '', $password = '' ) {
		// Only act on a login that has already succeeded on the password.
		if ( ! $user instanceof WP_User ) {
			return $user;
		}
		if ( ! SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			// Not enrolled: enforcement (if any) happens after login, on admin_init,
			// so an account in a required role is never locked out by the rollout.
			return $user;
		}
		// Application passwords are their own revocable credential — see the class docblock.
		if ( self::$via_app_password ) {
			return $user;
		}
		// WP-CLI and cron have no browser to prompt in; WP-CLI is also the documented
		// break-glass path, so it must never be gated by the thing it recovers from.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return $user;
		}

		if ( ! self::is_interactive() ) {
			return new WP_Error(
				'secwp_2fa_required',
				__( '<strong>Error:</strong> This account uses two-factor authentication, which cannot be completed over this connection. Use an application password instead.', 'ini-protector' )
			);
		}

		$remember    = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- reading the login form's own field; the password was already verified above.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- login form redirect; URL is sanitized and validated again by wp_safe_redirect().

		self::show_challenge( $user, (string) $redirect_to, (bool) $remember );
		// show_challenge() exits. Nothing below runs, and no cookie was ever issued.
	}

	/**
	 * Is this a browser login we can render a form into?
	 *
	 * Anything else (XML-RPC, REST with a real password, a programmatic wp_signon
	 * during a background request) is refused above rather than allowed through.
	 */
	private static function is_interactive(): bool {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}
		if ( 'cli' === PHP_SAPI ) {
			return false;
		}
		return ! empty( $_SERVER['REQUEST_METHOD'] );
	}

	/* --------------------------------------------------------------------- */
	/* Second step                                                            */
	/* --------------------------------------------------------------------- */

	/** Handles the POST from the second-step form (wp-login.php?action=secwp_2fa). */
	public static function handle_second_step(): void {
		check_admin_referer( 'secwp_second_step', 'secwp_nonce' );
		$token = isset( $_POST['secwp_token'] ) ? sanitize_text_field( wp_unslash( $_POST['secwp_token'] ) ) : '';
		$code  = isset( $_POST['secwp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['secwp_code'] ) ) : '';

		$parsed = self::verify_token( $token );
		if ( ! $parsed ) {
			// Expired or forged: send them back to the start rather than explaining.
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user        = $parsed['user'];
		$remember    = $parsed['remember'];
		$redirect_to = isset( $_POST['redirect_to'] ) && is_string( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : '';

		if ( self::attempts( $user->ID ) >= self::MAX_ATTEMPTS ) {
			self::show_challenge(
				$user,
				(string) $redirect_to,
				$remember,
				__( 'Too many incorrect codes. Wait a few minutes and sign in again.', 'ini-protector' ),
				true
			);
		}

		$ok = SecurityWP_TOTP::verify_for_user( $user->ID, $code );
		if ( ! $ok ) {
			$ok = SecurityWP_TOTP::verify_recovery( $user->ID, $code );
			if ( $ok ) {
				do_action(
					'secwp_platform_event',
					'2fa_recovery_used',
					sprintf( 'Recovery code used to sign in as %s', $user->user_login ),
					array( 'user' => $user->user_login, 'remaining' => SecurityWP_TOTP::recovery_remaining( $user->ID ) )
				);
			}
		}

		if ( ! $ok ) {
			self::bump_attempts( $user->ID );
			self::show_challenge( $user, (string) $redirect_to, $remember, __( 'That code was not correct. Codes change every 30 seconds — check your device clock if this keeps happening.', 'ini-protector' ) );
		}

		self::clear_attempts( $user->ID );

		// Second factor satisfied: complete the login exactly as wp_signon would.
		wp_set_auth_cookie( $user->ID, $remember );
		do_action( 'wp_login', $user->user_login, $user );

		$redirect_to = '' !== (string) $redirect_to ? (string) $redirect_to : admin_url();
		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Render the code form on the login screen and stop the request.
	 *
	 * @param bool $locked Render without an input (attempt limit reached).
	 */
	private static function show_challenge( WP_User $user, string $redirect_to, bool $remember, string $error = '', bool $locked = false ): void {
		$token = self::make_token( $user, $remember );

		// login_header()/login_footer() live in wp-login.php, so they exist for a
		// real login request (masked slug included) and not otherwise.
		$have_login_chrome = function_exists( 'login_header' ) && function_exists( 'login_footer' );

		wp_enqueue_style( 'secwp-two-factor', SECWP_PLUGIN_URL . 'assets/two-factor.css', array(), SECWP_VERSION );
		if ( $have_login_chrome ) {
			login_header( __( 'Two-factor authentication', 'ini-protector' ), '' );
		} else {
			self::minimal_header();
		}

		if ( '' !== $error ) {
			echo '<div id="login_error" class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
		}
		?>
		<form name="secwp_2fa_form" id="secwp_2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
			<?php wp_nonce_field( 'secwp_second_step', 'secwp_nonce' ); ?>
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>" />
			<input type="hidden" name="secwp_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<p class="secwp-2fa-intro">
				<?php
				printf(
					/* translators: %s: user login name. */
					esc_html__( 'Signing in as %s. Enter the current code from your authenticator app.', 'ini-protector' ),
					'<strong>' . esc_html( $user->user_login ) . '</strong>'
				);
				?>
			</p>
			<?php if ( ! SecurityWP_TOTP::secret_readable( $user->ID ) ) : ?>
				<p class="secwp-2fa-hint"><?php esc_html_e( 'Your authenticator setup is no longer readable. This can happen after the site’s security salts change. Enter an unused recovery code to sign in, then reset and set up two-factor authentication again from your profile. If you have no recovery codes, contact the site administrator.', 'ini-protector' ); ?></p>
			<?php endif; ?>
			<?php if ( ! $locked ) : ?>
				<p>
					<label for="secwp_code"><?php esc_html_e( 'Authentication code', 'ini-protector' ); ?></label>
					<input type="text" name="secwp_code" id="secwp_code" class="input" value="" size="20"
						inputmode="numeric" autocomplete="one-time-code" pattern="[0-9A-Za-z\-]*"
						autocapitalize="off" autocorrect="off" spellcheck="false" required autofocus />
				</p>
				<p class="submit">
					<input type="submit" name="submit" id="submit" class="button button-primary button-large"
						value="<?php esc_attr_e( 'Verify', 'ini-protector' ); ?>" />
				</p>
				<p class="secwp-2fa-hint">
					<?php esc_html_e( 'Lost your device? Enter one of your recovery codes in the same box.', 'ini-protector' ); ?>
				</p>
			<?php endif; ?>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Start over', 'ini-protector' ); ?></a></p>

		<?php
		if ( $have_login_chrome ) {
			login_footer();
		} else {
			echo '</body></html>';
		}
		exit;
	}

	/** Minimal standalone page, for the rare login that does not come through wp-login.php. */
	private static function minimal_header(): void {
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
		echo '<title>' . esc_html__( 'Two-factor authentication', 'ini-protector' ) . '</title>';
		wp_enqueue_style( 'secwp-two-factor-standalone', SECWP_PLUGIN_URL . 'assets/two-factor-standalone.css', array( 'secwp-two-factor' ), SECWP_VERSION );
		wp_print_styles( array( 'secwp-two-factor-standalone' ) );
		echo '</head><body>';
	}

	/* --------------------------------------------------------------------- */
	/* Pending-login token                                                    */
	/* --------------------------------------------------------------------- */

	/**
	 * Signed, short-lived, stateless token standing in for "password accepted".
	 *
	 * It authorises nothing on its own: a current authenticator code is still
	 * required to finish, a code cannot be replayed, and the token dies after
	 * TOKEN_TTL seconds.
	 *
	 * Deliberately NOT bound to $user->user_pass, which is the obvious choice and
	 * is wrong: WordPress rehashes the stored password during the very request
	 * that authenticates it whenever the hashing scheme has moved on (the 6.8
	 * bcrypt migration rehashes every account on its next login). The token would
	 * then be signed with the old hash and verified against the new one, and the
	 * user would be bounced back to the login form with no explanation — on their
	 * first sign-in after a WordPress upgrade, which is the worst possible moment.
	 * Bound instead to user_registered, which never changes.
	 */
	private static function make_token( WP_User $user, bool $remember ): string {
		$expires = time() + self::TOKEN_TTL;
		$payload = $user->ID . '|' . $expires . '|' . ( $remember ? '1' : '0' );
		return $payload . '|' . self::sign( $payload, $user );
	}

	/**
	 * @return array{user:WP_User,remember:bool}|null
	 */
	private static function verify_token( string $token ): ?array {
		$parts = explode( '|', $token );
		if ( 4 !== count( $parts ) ) {
			return null;
		}
		list( $user_id, $expires, $remember, $sig ) = $parts;

		if ( (int) $expires < time() ) {
			return null;
		}
		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return null;
		}
		$payload = (int) $user_id . '|' . (int) $expires . '|' . ( '1' === $remember ? '1' : '0' );
		if ( ! hash_equals( self::sign( $payload, $user ), (string) $sig ) ) {
			return null;
		}
		if ( ! SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			return null;
		}
		return array(
			'user'     => $user,
			'remember' => ( '1' === $remember ),
		);
	}

	private static function sign( string $payload, WP_User $user ): string {
		return hash_hmac( 'sha256', $payload . '|' . $user->user_registered, wp_salt( 'secure_auth' ) );
	}

	/* --------------------------------------------------------------------- */
	/* Attempt limiting                                                       */
	/* --------------------------------------------------------------------- */

	private static function attempt_key( int $user_id ): string {
		return 'secwp_2fa_fail_' . $user_id;
	}

	private static function attempts( int $user_id ): int {
		return (int) get_transient( self::attempt_key( $user_id ) );
	}

	private static function bump_attempts( int $user_id ): void {
		$n = self::attempts( $user_id ) + 1;
		set_transient( self::attempt_key( $user_id ), $n, self::ATTEMPT_WINDOW );
		if ( $n >= self::MAX_ATTEMPTS ) {
			do_action(
				'secwp_platform_event',
				'2fa_attempts_exceeded',
				sprintf( 'Two-factor attempt limit reached for user %d', $user_id ),
				array( 'user_id' => $user_id )
			);
		}
	}

	private static function clear_attempts( int $user_id ): void {
		delete_transient( self::attempt_key( $user_id ) );
	}

	/* --------------------------------------------------------------------- */
	/* Enforcement                                                            */
	/* --------------------------------------------------------------------- */

	/** Send an account that must use 2FA to its profile until it has set it up. */
	public static function enforce_enrolment(): void {
		if ( ! is_user_logged_in() || wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! self::is_required_for( $user ) || SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			return;
		}

		// Screens the user must keep reaching: the enrolment form itself and the
		// handlers behind it. user-edit.php is deliberately NOT here — WordPress
		// already redirects an admin editing themselves to profile.php, so allowing
		// it would only hand an unenrolled admin a way to keep working around the
		// requirement.
		$allowed = array( 'profile.php', 'admin-post.php', 'admin-ajax.php' );
		$pagenow = isset( $GLOBALS['pagenow'] ) ? (string) $GLOBALS['pagenow'] : '';
		if ( in_array( $pagenow, $allowed, true ) ) {
			return;
		}

		wp_safe_redirect( add_query_arg( 'secwp_2fa_setup', '1', admin_url( 'profile.php' ) ) . '#secwp-2fa' );
		exit;
	}

	public static function enrolment_notice(): void {
		$screen = get_current_screen();
		if ( ! $screen || 'profile' !== $screen->base ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! self::is_required_for( $user ) || SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Two-factor authentication is required for your account.', 'ini-protector' ) . '</strong> ';
		esc_html_e( 'Set it up below to continue using the site.', 'ini-protector' );
		echo '</p></div>';
	}

	/* --------------------------------------------------------------------- */
	/* Users list column                                                      */
	/* --------------------------------------------------------------------- */

	public static function users_column( array $columns ): array {
		$columns['secwp_2fa'] = __( '2FA', 'ini-protector' );
		return $columns;
	}

	public static function users_column_value( $value, string $column, int $user_id ) {
		if ( 'secwp_2fa' !== $column ) {
			return $value;
		}
		if ( SecurityWP_TOTP::is_enabled( $user_id ) ) {
			$remaining = SecurityWP_TOTP::recovery_remaining( $user_id );
			$label     = sprintf(
				/* translators: %d: number of unused recovery codes. */
				_n( 'On · %d recovery code left', 'On · %d recovery codes left', $remaining, 'ini-protector' ),
				$remaining
			);
			return '<span style="color:#1a7a30;font-weight:600;">' . esc_html( $label ) . '</span>';
		}
		$user = get_user_by( 'id', $user_id );
		if ( $user && self::is_required_for( $user ) ) {
			return '<span style="color:#b32d2e;font-weight:600;">' . esc_html__( 'Required — not set up', 'ini-protector' ) . '</span>';
		}
		return '<span style="color:#646970;">' . esc_html__( 'Off', 'ini-protector' ) . '</span>';
	}

	/* --------------------------------------------------------------------- */
	/* Profile UI                                                             */
	/* --------------------------------------------------------------------- */

	public static function render_profile_section( WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$is_self  = ( get_current_user_id() === $user->ID );
		$enabled  = SecurityWP_TOTP::is_enabled( $user->ID );
		$required = self::is_required_for( $user );

		echo '<h2 id="secwp-2fa">' . esc_html__( 'Two-factor authentication', 'ini-protector' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tbody>';

		// A wrong code on the last save: say so here, where the form is.
		if ( get_transient( 'secwp_2fa_error_' . $user->ID ) ) {
			delete_transient( 'secwp_2fa_error_' . $user->ID );
			echo '<tr><th></th><td><div class="notice notice-error inline"><p>'
				. esc_html__( 'That code was not correct, so two-factor authentication was not turned on. Your key below is unchanged — just enter the next code your app shows.', 'ini-protector' )
				. '</p></div></td></tr>';
		}

		// Freshly issued recovery codes are shown exactly once, right after enrolment.
		$fresh = get_transient( 'secwp_2fa_codes_' . $user->ID );
		if ( is_array( $fresh ) && $fresh ) {
			delete_transient( 'secwp_2fa_codes_' . $user->ID );
			self::render_recovery_codes( $fresh );
		}

		if ( $enabled ) {
			self::render_enabled_state( $user, $is_self );
		} elseif ( $is_self ) {
			self::render_enrolment( $user, $required );
		} else {
			echo '<tr><th>' . esc_html__( 'Status', 'ini-protector' ) . '</th><td><p class="description">'
				. esc_html__( 'Not set up. Only the account holder can turn two-factor authentication on, because it needs their authenticator app.', 'ini-protector' )
				. '</p></td></tr>';
		}

		echo '</tbody></table>';
	}

	private static function render_enabled_state( WP_User $user, bool $is_self ): void {
		$remaining = SecurityWP_TOTP::recovery_remaining( $user->ID );
		$readable  = SecurityWP_TOTP::secret_readable( $user->ID );

		echo '<tr><th>' . esc_html__( 'Status', 'ini-protector' ) . '</th><td>';
		echo '<p><strong style="color:#1a7a30;">' . esc_html__( 'On', 'ini-protector' ) . '</strong>';
		$since = (int) get_user_meta( $user->ID, SecurityWP_TOTP::META_ENABLED_AT, true );
		if ( $since ) {
			echo ' — ' . esc_html( sprintf( /* translators: %s: date. */ __( 'since %s', 'ini-protector' ), wp_date( get_option( 'date_format' ), $since ) ) );
		}
		echo '</p>';

		if ( ! $readable ) {
			echo '<p class="description" style="color:#b32d2e;"><strong>'
				. esc_html__( 'This account’s secret can no longer be read.', 'ini-protector' ) . '</strong> '
				. esc_html__( 'That happens when the site’s security salts in wp-config.php are changed. Sign in with a recovery code (or have an administrator reset 2FA from WP-CLI), then set it up again.', 'ini-protector' )
				. '</p>';
		}

		printf(
			'<p class="description">%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: unused recovery codes. */
					_n( '%d unused recovery code remaining.', '%d unused recovery codes remaining.', $remaining, 'ini-protector' ),
					$remaining
				)
			)
		);
		if ( $remaining <= 2 ) {
			echo '<p class="description" style="color:#b35900;">' . esc_html__( 'Running low — generate a new set and store them somewhere other than the device holding your codes.', 'ini-protector' ) . '</p>';
		}
		echo '</td></tr>';

		if ( $is_self ) {
			echo '<tr><th>' . esc_html__( 'Recovery codes', 'ini-protector' ) . '</th><td>';
			echo '<label><input type="checkbox" name="secwp_2fa_regenerate" value="1" /> '
				. esc_html__( 'Generate a new set of recovery codes when I save this page', 'ini-protector' ) . '</label>';
			echo '<p class="description">' . esc_html__( 'The previous set stops working immediately.', 'ini-protector' ) . '</p>';
			echo '</td></tr>';
		}

		echo '<tr><th>' . esc_html__( 'Turn off', 'ini-protector' ) . '</th><td>';
		echo '<label><input type="checkbox" name="secwp_2fa_disable" value="1" /> '
			. esc_html__( 'Turn off two-factor authentication for this account', 'ini-protector' ) . '</label>';
		if ( self::is_required_for( $user ) ) {
			echo '<p class="description" style="color:#b35900;">'
				. esc_html__( 'This account’s role requires two-factor authentication — turning it off will send it straight back to this page to set it up again.', 'ini-protector' )
				. '</p>';
		}
		echo '</td></tr>';
	}

	private static function render_enrolment( WP_User $user, bool $required ): void {
		// One pending secret per enrolment, kept until it is confirmed — regenerating
		// on every page view would invalidate a code the user is mid-way through typing.
		$secret = SecurityWP_TOTP::get_secret( $user->ID );
		if ( '' === $secret ) {
			$secret = SecurityWP_TOTP::generate_secret();
			SecurityWP_TOTP::set_secret( $user->ID, $secret );
		}

		$uri = SecurityWP_TOTP::provisioning_uri( $user, $secret );
		$svg = function_exists( 'secwp_qr_svg' ) ? secwp_qr_svg( $uri, 4, array( 'level' => 'L', 'label' => __( 'Two-factor setup code', 'ini-protector' ) ) ) : '';

		echo '<tr><th>' . esc_html__( 'Set up', 'ini-protector' ) . '</th><td>';

		if ( $required ) {
			echo '<p style="color:#b32d2e;"><strong>' . esc_html__( 'Required for your role.', 'ini-protector' ) . '</strong></p>';
		}

		echo '<p>' . esc_html__( '1. Scan this with an authenticator app (Google Authenticator, 1Password, Aegis, Bitwarden — any of them).', 'ini-protector' ) . '</p>';

		if ( '' !== $svg ) {
			echo '<div style="margin:10px 0;">';
			// Printed as-is, not through wp_kses(): the markup is generated by
			// SecurityWP_QR from our own otpauth URI, with no external input in it,
			// and wp_kses() lowercases attribute names — which would turn the
			// case-sensitive SVG viewBox into a viewbox the browser ignores.
			echo $svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- self-generated SVG, see above.
			echo '</div>';
		}

		echo '<p>' . esc_html__( 'Or type this key in by hand:', 'ini-protector' ) . '<br />';
		echo '<code style="font-size:15px;letter-spacing:1px;user-select:all;">' . esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ) . '</code></p>';

		if ( '' === $svg ) {
			echo '<p class="description">' . esc_html__( 'The QR code could not be drawn small enough for this site name, so enter the key by hand — it works exactly the same.', 'ini-protector' ) . '</p>';
		}

		echo '<p>' . esc_html__( '2. Enter the 6-digit code the app shows, then save this page.', 'ini-protector' ) . '</p>';
		echo '<input type="text" name="secwp_2fa_code" value="" class="regular-text" size="10" inputmode="numeric" '
			. 'autocomplete="one-time-code" autocapitalize="off" spellcheck="false" placeholder="' . esc_attr__( '000000', 'ini-protector' ) . '" />';
		echo '<p class="description">' . esc_html__( 'Two-factor authentication only switches on once a correct code proves the app is set up — a half-finished setup can never lock you out. You will be given recovery codes at that point; keep them somewhere other than your phone.', 'ini-protector' ) . '</p>';
		echo '</td></tr>';
	}

	private static function render_recovery_codes( array $codes ): void {
		echo '<tr><th>' . esc_html__( 'Your recovery codes', 'ini-protector' ) . '</th><td>';
		echo '<div style="border:1px solid #c3c4c7;border-left:4px solid #2271b1;background:#fff;padding:12px 16px;max-width:420px;">';
		echo '<p style="margin-top:0;"><strong>' . esc_html__( 'Save these now — they are shown once and never again.', 'ini-protector' ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Each code signs you in once if you lose your authenticator. Store them somewhere other than the device that holds the app.', 'ini-protector' ) . '</p>';
		echo '<pre style="font-size:15px;line-height:1.8;letter-spacing:1px;margin:8px 0 0;user-select:all;">';
		foreach ( $codes as $code ) {
			echo esc_html( $code ) . "\n";
		}
		echo '</pre></div></td></tr>';
	}

	/* --------------------------------------------------------------------- */
	/* Profile save                                                           */
	/* --------------------------------------------------------------------- */

	/**
	 * Handle the profile form. Core has already verified the update-user nonce and
	 * the capability before these hooks fire; we re-check the capability anyway.
	 */
	public static function save_profile( int $user_id ): void {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		check_admin_referer( 'update-user_' . $user_id );
		$is_self = ( get_current_user_id() === $user_id );

		// Turning it off: allowed for the account holder and for an administrator
		// who can already edit this user (the in-admin counterpart of the CLI reset).
		if ( ! empty( $_POST['secwp_2fa_disable'] ) ) {
			SecurityWP_TOTP::disable( $user_id );
			do_action(
				'secwp_platform_event',
				'2fa_disabled',
				sprintf( 'Two-factor authentication turned off for user %d', $user_id ),
				array( 'user_id' => $user_id, 'by' => get_current_user_id() )
			);
			return;
		}

		if ( ! $is_self ) {
			// Enabling needs the authenticator app, so only the account holder can.
			return;
		}

		if ( ! empty( $_POST['secwp_2fa_regenerate'] ) && SecurityWP_TOTP::is_enabled( $user_id ) ) {
			$codes = SecurityWP_TOTP::generate_recovery_codes( $user_id );
			set_transient( 'secwp_2fa_codes_' . $user_id, $codes, 5 * MINUTE_IN_SECONDS );
			return;
		}

		$code = isset( $_POST['secwp_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['secwp_2fa_code'] ) ) : '';
		if ( '' === $code || SecurityWP_TOTP::is_enabled( $user_id ) ) {
			return;
		}

		$codes = SecurityWP_TOTP::confirm( $user_id, $code );
		if ( false === $codes ) {
			// Surfaced on the next page load; the pending secret is kept so the user
			// can simply try the next code rather than re-scanning.
			set_transient( 'secwp_2fa_error_' . $user_id, 1, MINUTE_IN_SECONDS );
			return;
		}

		set_transient( 'secwp_2fa_codes_' . $user_id, $codes, 5 * MINUTE_IN_SECONDS );
		do_action(
			'secwp_platform_event',
			'2fa_enabled',
			sprintf( 'Two-factor authentication turned on for user %d', $user_id ),
			array( 'user_id' => $user_id )
		);
	}
}
