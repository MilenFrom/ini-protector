<?php
/**
 * Limit Login Attempts. Tracks failed logins per IP in transients; locks out an IP after the
 * configured threshold for the configured duration. Config: max attempts, lockout minutes
 * (SecurityWP_Features 'limit_login').
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Limit_Login {

	public function register(): void {
		// Fires from wp-login.php long before the credentials are dispatched, so a
		// locked-out IP never reaches the password hash at all. See block_early().
		add_action( 'login_form_login', array( $this, 'block_early' ) );

		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 1 );
		add_action( 'wp_login_failed', array( $this, 'on_failed' ) );
		add_action( 'wp_login', array( $this, 'on_success' ) );
	}

	private function max(): int {
		return max( 1, (int) SecurityWP_Features::get( 'limit_login', 'max', 5 ) );
	}

	private function lockout_seconds(): int {
		return max( 1, (int) SecurityWP_Features::get( 'limit_login', 'lockout', 15 ) ) * 60;
	}

	/**
	 * The canonical client IP, same resolver the traffic log and block list use.
	 *
	 * Behind a declared proxy this is the visitor, not the CDN edge — without it every
	 * visitor shares the edge's address and one attacker's failures lock out the whole
	 * site. With no proxy declared it is still REMOTE_ADDR, exactly as before.
	 */
	private function ip(): string {
		if ( class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return SecurityWP_Traffic_Log::client_ip();
		}
		return SecurityWP_Input::remote_ip();
	}

	private function key( string $suffix ): string {
		return 'secwp_ll_' . $suffix . '_' . md5( $this->ip() );
	}

	private function lockout_message(): string {
		return sprintf( 'Too many failed login attempts. Try again in about %d minutes.', (int) ceil( $this->lockout_seconds() / 60 ) );
	}

	/**
	 * Refuse a locked-out sign-in attempt before WordPress verifies the password.
	 *
	 * check_lockout() below already blocks the login, but it cannot run until priority
	 * 30 — and core's wp_authenticate_username_password() sits at 20, so by then the
	 * password has already been hashed and compared. That is the expensive part: a
	 * locked-out attacker still costs a full bcrypt per request, which turns the
	 * lockout into a CPU amplifier instead of a brake.
	 *
	 * The obvious fix — moving the filter below 20 — would BREAK the lockout: core's
	 * callback only returns early for a WP_User or for empty credentials, so with both
	 * fields filled it would overwrite our WP_Error with its own verdict and let the
	 * attempt through. The ordering has to be fixed here, before dispatch, not there.
	 */
	public function block_early(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'POST' !== $method ) {
			return; // Viewing the form is fine; only submissions are throttled.
		}
		if ( ! get_transient( $this->key( 'lock' ) ) ) {
			return;
		}

		$error = new WP_Error( 'secwp_locked', $this->lockout_message() );
		if ( function_exists( 'login_header' ) && function_exists( 'login_footer' ) ) {
			login_header( __( 'Log In' ), '', $error );
			login_footer();
		} else {
			wp_die( esc_html( $this->lockout_message() ), '', array( 'response' => 403 ) );
		}
		exit;
	}

	/** Backstop: blocks the login even if the early bail was bypassed or not reached. */
	public function check_lockout( $user ) {
		if ( get_transient( $this->key( 'lock' ) ) ) {
			return new WP_Error(
				'secwp_locked',
				sprintf( 'Too many failed login attempts. Try again in about %d minutes.', (int) ceil( $this->lockout_seconds() / 60 ) )
			);
		}
		return $user;
	}

	public function on_failed(): void {
		$attempts = (int) get_transient( $this->key( 'count' ) ) + 1;
		set_transient( $this->key( 'count' ), $attempts, $this->lockout_seconds() );
		if ( $attempts >= $this->max() ) {
			set_transient( $this->key( 'lock' ), 1, $this->lockout_seconds() );
		}
	}

	public function on_success(): void {
		delete_transient( $this->key( 'count' ) );
		delete_transient( $this->key( 'lock' ) );
	}
}
