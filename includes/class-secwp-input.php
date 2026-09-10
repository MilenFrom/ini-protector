<?php
/**
 * Validation for request metadata used by security gates and traffic logging.
 *
 * @package INI_Protector
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Input {
	/** Keep URL encoding intact; reject non-string input before URL sanitization. */
	public static function request_uri(): string {
		return isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] )
			? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
	}

	/** HTTP methods are tokens, not arbitrary text. Reject instead of truncating. */
	public static function request_method(): string {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] )
			? filter_var( wp_unslash( $_SERVER['REQUEST_METHOD'] ), FILTER_VALIDATE_REGEXP, array( 'options' => array( 'regexp' => '/^[A-Za-z]{1,10}$/D' ) ) ) : false;
		return false !== $method ? strtoupper( sanitize_text_field( $method ) ) : '';
	}

	/** Validate the complete socket address; never turn malformed text into another IP. */
	public static function remote_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] )
			? filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP ) : false;
		return false !== $ip ? sanitize_text_field( $ip ) : '';
	}

	/** Use WordPress's canonical REST route, never an arbitrary URI query substring. */
	public static function rest_route(): string {
		$route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
		return is_string( $route ) ? ltrim( esc_url_raw( '/' . ltrim( $route, '/' ) ), '/' ) : '';
	}
}
