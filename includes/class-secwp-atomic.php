<?php
/**
 * Race-free counters, single-use claims and short locks.
 *
 * Attempt limits and one-time codes were read-then-write over transients and meta, so
 * concurrent requests could each read the same value: more guesses than the limit got
 * through, and a TOTP step, recovery code or ALTCHA solution could be accepted twice.
 * Each operation here is one atomic step: an atomic object-cache call when a persistent
 * cache is in use (the only place transients live then), otherwise a single SQL
 * statement on the options table, whose unique option_name index does the arbitration.
 *
 * Rows are named secwp_atom_* (so uninstall removes them) and carry their own expiry;
 * expired rows are swept occasionally.
 *
 * @package INI_Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Atomic {

	const PREFIX = 'secwp_atom_';
	const GROUP  = 'secwp_atomic';

	private static function name( string $key ): string {
		return self::PREFIX . substr( md5( $key ), 0, 32 );
	}

	/**
	 * Add one and return the new count. The window restarts at 1 once it has expired. In the
	 * database each increment also pushes the expiry out to now + $ttl (a sliding window, as
	 * before); in an object cache the window is fixed from the first increment.
	 */
	public static function incr( string $key, int $ttl ): int {
		$ttl  = max( 1, $ttl );
		$name = self::name( $key );

		if ( wp_using_ext_object_cache() ) {
			wp_cache_add( $name, 0, self::GROUP, $ttl );
			$n = wp_cache_incr( $name, 1, self::GROUP );
			if ( false === $n ) { // Evicted between the two calls.
				wp_cache_set( $name, 1, self::GROUP, $ttl );
				return 1;
			}
			// The window here is fixed from the first increment: re-setting the value to slide
			// it could overwrite a concurrent increment, which is the race this class removes.
			return (int) $n;
		}

		global $wpdb;
		$now     = time();
		$expires = $now + $ttl;
		self::maybe_sweep();
		// Stored as "count|expires". One statement: insert, or bump, or restart if expired.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')
				 ON DUPLICATE KEY UPDATE option_value = IF(
					CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) <= %d,
					%s,
					CONCAT(CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) + 1, '|', %d)
				 )",
				$name,
				'1|' . $expires,
				$now,
				'1|' . $expires,
				$expires
			)
		);
		// Read back separately: under concurrency this can already include later callers'
		// increments, so the result is >= this call's own position, never below it. Limits
		// therefore only ever err towards refusing, which is the safe side.
		$value = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) );
		// phpcs:enable
		wp_cache_delete( $name, 'options' );
		return max( 1, (int) strtok( $value, '|' ) );
	}

	/** Current count, 0 if absent or expired. */
	public static function get( string $key ): int {
		$name = self::name( $key );
		if ( wp_using_ext_object_cache() ) {
			return (int) wp_cache_get( $name, self::GROUP );
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		// Read back separately: under concurrency this can already include later callers'
		// increments, so the result is >= this call's own position, never below it. Limits
		// therefore only ever err towards refusing, which is the safe side.
		$value = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) );
		if ( '' === $value ) {
			return 0;
		}
		list( $count, $expires ) = array_pad( explode( '|', $value, 2 ), 2, 0 );
		return (int) $expires > time() ? (int) $count : 0;
	}

	public static function delete( string $key ): void {
		$name = self::name( $key );
		if ( wp_using_ext_object_cache() ) {
			wp_cache_delete( $name, self::GROUP );
			return;
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->delete( $wpdb->options, array( 'option_name' => $name ) );
		wp_cache_delete( $name, 'options' );
	}

	/**
	 * Claim $key for $ttl seconds. True for exactly one caller; false while someone else
	 * holds it. Single-use tokens claim and never release; locks release() when done.
	 */
	public static function claim( string $key, int $ttl ): bool {
		$ttl  = max( 1, $ttl );
		$name = self::name( 'claim|' . $key );

		if ( wp_using_ext_object_cache() ) {
			return (bool) wp_cache_add( $name, 1, self::GROUP, $ttl );
		}

		global $wpdb;
		$now = time();
		self::maybe_sweep();
		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$name,
				'1|' . ( $now + $ttl )
			)
		);
		if ( 1 === (int) $inserted ) {
			return true;
		}
		// Taken, unless the holder's claim has expired: take it over in one UPDATE.
		$taken = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s
				 WHERE option_name = %s AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) <= %d",
				'1|' . ( $now + $ttl ),
				$name,
				$now
			)
		);
		// phpcs:enable
		return 1 === (int) $taken;
	}

	public static function release( string $key ): void {
		self::delete( 'claim|' . $key );
	}

	/**
	 * Run $fn while holding a short lock. Waits up to $wait seconds; if the lock is still
	 * held after that, runs $fn anyway when $run_anyway (better a rare lost update than a
	 * refused admin action), otherwise returns null without running it.
	 *
	 * @return mixed $fn's return value, or null if skipped.
	 */
	public static function with_lock( string $key, callable $fn, float $wait = 2.0, bool $run_anyway = true ) {
		$deadline = microtime( true ) + $wait;
		$held     = self::claim( 'lock|' . $key, 30 );
		while ( ! $held && microtime( true ) < $deadline ) {
			usleep( 50000 );
			$held = self::claim( 'lock|' . $key, 30 );
		}
		if ( ! $held && ! $run_anyway ) {
			return null;
		}
		try {
			return $fn();
		} finally {
			if ( $held ) {
				self::release( 'lock|' . $key );
			}
		}
	}

	/** Delete expired rows now and then (cheap: only rows under our prefix). */
	private static function maybe_sweep(): void {
		if ( 1 !== wp_rand( 1, 100 ) ) {
			return;
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) <= %d",
				$wpdb->esc_like( self::PREFIX ) . '%',
				time()
			)
		);
	}
}
