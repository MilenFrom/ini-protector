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
		return false !== $ip ? self::normalize_ip( $ip ) : '';
	}

	/**
	 * One canonical spelling per address, so string comparison and array keys agree:
	 * '2001:DB8:0::1' and '2001:db8::1' are the same host, and an IPv4-mapped IPv6 address
	 * ('::ffff:192.0.2.1', as dual-stack servers report IPv4 clients) is the IPv4 address.
	 *
	 * @return string The canonical form, or '' if $ip is not an IP address.
	 */
	public static function normalize_ip( string $ip ): string {
		$ip = trim( $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strncmp( $bin, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			$bin = substr( $bin, 12 ); // IPv4-mapped.
		}
		$out = inet_ntop( $bin );
		return false !== $out ? $out : '';
	}

	/** Use WordPress's canonical REST route, never an arbitrary URI query substring. */
	public static function rest_route(): string {
		$route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
		return is_string( $route ) ? ltrim( esc_url_raw( '/' . ltrim( $route, '/' ) ), '/' ) : '';
	}
}
