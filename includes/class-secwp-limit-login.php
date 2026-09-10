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

	private function ip(): string {
		$ip = SecurityWP_Input::remote_ip();
		return $ip;
	}

	private function key( string $suffix ): string {
		return 'secwp_ll_' . $suffix . '_' . md5( $this->ip() );
	}

	/** Block authentication while the IP is locked out. */
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
