<?php
/**
 * IP blocklist + early request gate.
 *
 * Manual deny-list of IPs (added from the Traffic view). A blocked IP gets a
 * 403 very early in the request, before WordPress does meaningful work. The
 * client IP is resolved with the SAME spoof-resistant logic the traffic log
 * uses (SecurityWP_Traffic_Log::client_ip()) — blocking on a forgeable header
 * would be worse than not blocking at all.
 *
 * This runs independently of the traffic-monitor tweak: a block you set must
 * stay enforced even if the monitor is later switched off.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_IP_Block {

	/**
	 * Option holding the blocklist:
	 *   [ ip => [ 'reason' => string, 'time' => int, 'expires' => int, 'source' => string ] ]
	 *
	 * 'expires' is a unix timestamp; 0 or absent = permanent (back-compat: pre-1.4
	 * entries had no 'expires' key and were permanent — that meaning is preserved).
	 * 'source' is one of self::SOURCE_* (absent = manual, for old entries).
	 */
	const OPTION = 'secwp_blocked_ips';

	/** Safety cap so the option can't grow unbounded. */
	const MAX = 500;

	/* Where a block came from. */
	const SOURCE_MANUAL     = 'manual';     // typed/clicked by an admin
	const SOURCE_SUGGESTION = 'suggestion'; // admin clicked "Apply" on a suggestion
	const SOURCE_AUTO       = 'auto';       // the escalation engine, in Auto-Block mode

	public function register(): void {
		// As early as practical, but after plugins are loaded so client_ip()
		// (and SECWP_TRUST_PROXY) are available. 'init' at priority 0 is early
		// enough to short-circuit before queries/templates run.
		add_action( 'init', array( $this, 'maybe_block' ), 0 );
	}

	/**
	 * 403 the current request if its IP is on the blocklist. Never blocks a
	 * logged-in admin (belt-and-suspenders against self-lockout).
	 */
	public function maybe_block(): void {
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}
		$list = self::all();
		if ( empty( $list ) ) {
			return;
		}
		$ip = self::current_ip();
		if ( '' === $ip || ! isset( $list[ $ip ] ) ) {
			return;
		}

		// Temp blocks: an entry whose 'expires' has passed is no longer enforced.
		// Prune it lazily (cheap, only on a hit) so the list doesn't accrete dead
		// entries. A missing/0 'expires' means permanent — never expires.
		$expires = (int) ( $list[ $ip ]['expires'] ?? 0 );
		if ( $expires > 0 && time() >= $expires ) {
			unset( $list[ $ip ] );
			update_option( self::OPTION, $list, false );
			return;
		}

		// Don't cache a blocked response at the edge.
		nocache_headers();
		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Connection: close' );
		echo 'Forbidden';
		exit;
	}

	/* --------------------------------------------------------------------- */
	/* Storage                                                                */
	/* --------------------------------------------------------------------- */

	/** The full blocklist. @return array<string,array{reason:string,time:int}> */
	public static function all(): array {
		$list = get_option( self::OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	/** Is the IP on the list AND not expired? */
	public static function is_blocked( string $ip ): bool {
		$entry = self::all()[ $ip ] ?? null;
		if ( null === $entry ) {
			return false;
		}
		$expires = (int) ( $entry['expires'] ?? 0 );
		return ! ( $expires > 0 && time() >= $expires );
	}

	/**
	 * Add an IP to the blocklist. Refuses to block an invalid IP or the
	 * current admin's own IP (lockout protection).
	 *
	 * @param string $ip      The IP to block.
	 * @param string $reason  Human-readable why.
	 * @param int    $expires Unix timestamp the block lifts at; 0 = permanent.
	 * @param string $source  One of self::SOURCE_* (manual by default).
	 * @return true|WP_Error
	 */
	public static function block( string $ip, string $reason = '', int $expires = 0, string $source = self::SOURCE_MANUAL ) {
		$ip = trim( $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new WP_Error( 'secwp_bad_ip', __( 'That is not a valid IP address.', 'ini-protector' ) );
		}
		if ( $ip === self::current_ip() ) {
			return new WP_Error( 'secwp_self_block', __( 'You can’t block your own current IP address.', 'ini-protector' ) );
		}
		$list = self::all();
		if ( ! isset( $list[ $ip ] ) && count( $list ) >= self::MAX ) {
			return new WP_Error( 'secwp_block_full', __( 'The blocklist is full.', 'ini-protector' ) );
		}
		$valid_sources = array( self::SOURCE_MANUAL, self::SOURCE_SUGGESTION, self::SOURCE_AUTO );
		$list[ $ip ]   = array(
			'reason'  => sanitize_text_field( $reason ),
			'time'    => time(),
			'expires' => max( 0, $expires ),
			'source'  => in_array( $source, $valid_sources, true ) ? $source : self::SOURCE_MANUAL,
		);
		update_option( self::OPTION, $list, false );

		do_action(
			'secwp_platform_event',
			'ip_blocked',
			sprintf( 'Blocked %s', $ip ),
			array( 'ip' => $ip, 'reason' => $reason, 'expires' => max( 0, $expires ), 'source' => $list[ $ip ]['source'] )
		);
		return true;
	}

	/**
	 * Convenience: block for a number of seconds from now. The escalation engine
	 * uses this for its ladder (1h … 2w). A non-positive TTL falls back to a
	 * permanent block rather than an instantly-expired no-op.
	 *
	 * @return true|WP_Error
	 */
	public static function block_temp( string $ip, string $reason, int $ttl_seconds, string $source = self::SOURCE_AUTO ) {
		$expires = $ttl_seconds > 0 ? time() + $ttl_seconds : 0;
		return self::block( $ip, $reason, $expires, $source );
	}

	/** Remove an IP from the blocklist. */
	public static function unblock( string $ip ): bool {
		$ip   = trim( $ip );
		$list = self::all();
		if ( isset( $list[ $ip ] ) ) {
			unset( $list[ $ip ] );
			update_option( self::OPTION, $list, false );
			return true;
		}
		return false;
	}

	/**
	 * The current request's client IP, spoof-resistant. Reuses the traffic
	 * log's resolver so block + log agree on what an IP is.
	 */
	public static function current_ip(): string {
		if ( class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return SecurityWP_Traffic_Log::client_ip();
		}
		$ip = SecurityWP_Input::remote_ip();
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
