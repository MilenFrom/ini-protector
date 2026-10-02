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

	/** SecurityWP_Atomic lock serialising writes to the blocklist option. */
	const LOCK = 'blocklist';

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
			// Under the blocklist lock and on a fresh read, or a visitor's tidy-up could write
			// back a list that predates a block the cron or an admin just added. Busy: skip;
			// the entry is already not enforced, and the next hit will prune it.
			SecurityWP_Atomic::with_lock(
				self::LOCK,
				static function () use ( $ip ) {
					$fresh = self::fresh_all();
					$exp   = (int) ( $fresh[ $ip ]['expires'] ?? 0 );
					if ( $exp > 0 && time() >= $exp ) {
						unset( $fresh[ $ip ] );
						update_option( self::OPTION, $fresh, false );
					}
				},
				0.0,
				false
			);
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

	/** The list straight from the database, past this request's option cache (for writers). */
	private static function fresh_all(): array {
		wp_cache_delete( self::OPTION, 'options' );
		return self::all();
	}

	/** Entries still being enforced (expired temp blocks left out). */
	public static function active(): array {
		return self::without_expired( self::all() );
	}

	/** The list minus temp blocks whose 'expires' has passed. */
	private static function without_expired( array $list ): array {
		$now = time();
		return array_filter(
			$list,
			static function ( $entry ) use ( $now ) {
				$expires = (int) ( $entry['expires'] ?? 0 );
				return ! ( $expires > 0 && $now >= $expires );
			}
		);
	}

	/** Is the IP on the list AND not expired? */
	public static function is_blocked( string $ip ): bool {
		$entry = self::all()[ SecurityWP_Input::normalize_ip( $ip ) ] ?? null;
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
		// Stored under the canonical spelling, the same one current_ip() produces, so a block
		// typed as '2001:DB8::1' or '::ffff:192.0.2.1' still matches the visitor.
		$ip = SecurityWP_Input::normalize_ip( $ip );
		if ( '' === $ip ) {
			return new WP_Error( 'secwp_bad_ip', __( 'That is not a valid IP address.', 'ini-protector' ) );
		}
		if ( $ip === self::current_ip() ) {
			return new WP_Error( 'secwp_self_block', __( 'You can’t block your own current IP address.', 'ini-protector' ) );
		}
		$valid_sources = array( self::SOURCE_MANUAL, self::SOURCE_SUGGESTION, self::SOURCE_AUTO );
		$entry         = array(
			'reason'  => sanitize_text_field( $reason ),
			'time'    => time(),
			'expires' => max( 0, $expires ),
			'source'  => in_array( $source, $valid_sources, true ) ? $source : self::SOURCE_MANUAL,
		);
		// Read-modify-write of one option: serialised, so a concurrent block, unblock or
		// lazy prune can't overwrite this one with an older copy of the list.
		$full = SecurityWP_Atomic::with_lock(
			self::LOCK,
			static function () use ( $ip, $entry ) {
				// Expired temp blocks are otherwise only pruned when that IP comes back, so
				// one-off scanners would fill the list and make every new block fail.
				$list = self::without_expired( self::fresh_all() );
				if ( ! isset( $list[ $ip ] ) && count( $list ) >= self::MAX ) {
					return true;
				}
				$list[ $ip ] = $entry;
				update_option( self::OPTION, $list, false );
				return false;
			}
		);
		if ( $full ) {
			return new WP_Error( 'secwp_block_full', __( 'The blocklist is full.', 'ini-protector' ) );
		}

		do_action(
			'secwp_platform_event',
			'ip_blocked',
			sprintf( 'Blocked %s', $ip ),
			array( 'ip' => $ip, 'reason' => $reason, 'expires' => max( 0, $expires ), 'source' => $entry['source'] )
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
		$ip = trim( $ip );
		// The exact key too, so an entry saved in another spelling by an older version can go.
		$keys = array_unique( array_filter( array( $ip, SecurityWP_Input::normalize_ip( $ip ) ) ) );
		return (bool) SecurityWP_Atomic::with_lock(
			self::LOCK,
			static function () use ( $keys ) {
				$list = self::fresh_all();
				$hit  = false;
				foreach ( $keys as $key ) {
					if ( isset( $list[ $key ] ) ) {
						unset( $list[ $key ] );
						$hit = true;
					}
				}
				if ( $hit ) {
					update_option( self::OPTION, $list, false );
				}
				return $hit;
			}
		);
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
