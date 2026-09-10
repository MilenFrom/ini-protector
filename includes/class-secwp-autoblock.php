<?php
/**
 * Auto-block escalation engine (Block Suggestion System / Auto-Block).
 *
 * Every 5 minutes (cron `secwp_autoblock_eval`) this reads the traffic monitor's
 * own suggestion list — SecurityWP_Traffic_Log::summary()['suggested'], the same
 * abuse-threshold candidates the IP Block page shows — and, for each candidate
 * that survives the exemption gate, computes the next temp-block on a per-IP
 * escalation ladder:
 *
 *     L1 = 1h   L2 = 4h   L3 = 8h   L4 = 5d   L5 = 2w   (L5+ repeats 2w)
 *
 * Two modes (a SecurityWP_Features toggle, off by default):
 *   • Block Suggestion System (default) — decide only; the IP Block page surfaces
 *     suggestions for one-click Apply. This engine writes nothing in this mode.
 *   • Auto-Block (opt-in) — apply the temp block via SecurityWP_IP_Block, bump
 *     the IP's level, emit a platform event.
 *
 * NEVER issues an automatic permanent block: the ladder caps at level 5 (2 weeks,
 * repeating). True perma stays a manual admin action.
 *
 * Escalation state lives in a bounded wp_option (secwp_autoblock_state), rewritten
 * whole — same pattern as SecurityWP_IP_Block / the vuln snapshot. No DB table.
 *
 * Decay: an IP with no fresh offense for DECAY_DAYS drops one level (floor 0).
 * The clock is state.last_block_at (the option), NOT absence from the traffic log
 * — the log only retains 14 days, shorter than the 30-day decay window.
 *
 * The cron *decides*; SecurityWP_IP_Block::maybe_block() *enforces* per request.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Autoblock {

	/** The escalation-state option: [ ip => [ level:int, last_block_at:int ] ]. */
	const OPTION = 'secwp_autoblock_state';

	/** Cron hook + interval slug (custom 5-minute schedule). */
	const CRON_HOOK     = 'secwp_autoblock_eval';
	const CRON_SCHEDULE = 'secwp_5min';

	/** Feature toggle key (SecurityWP_Features catalog) + its config fields. */
	const FEATURE_AUTOBLOCK = 'autoblock'; // master toggle: engine runs at all
	const FIELD_ENFORCE     = 'enforce';   // config field: Auto-Block vs suggest-only

	/** Look-back window for each evaluation (hours). */
	const EVAL_HOURS = 24;

	/** Cap on tracked IPs in the state option. */
	const MAX_STATE = 2000;

	/** Days with no fresh offense before an IP's level decays by one. */
	const DECAY_DAYS = 30;

	/**
	 * The escalation ladder: level (1-based) => seconds. Level 5 is the ceiling;
	 * any further offense re-applies the level-5 duration (no auto-perma).
	 */
	const LADDER = array(
		1 => HOUR_IN_SECONDS,          // 1 hour
		2 => 4 * HOUR_IN_SECONDS,      // 4 hours
		3 => 8 * HOUR_IN_SECONDS,      // 8 hours
		4 => 5 * DAY_IN_SECONDS,       // 5 days
		5 => 14 * DAY_IN_SECONDS,      // 2 weeks
	);

	const MAX_LEVEL = 5;

	/* --------------------------------------------------------------------- */
	/* Registration / cron lifecycle                                          */
	/* --------------------------------------------------------------------- */

	public function register(): void {
		add_filter( 'cron_schedules', array( $this, 'add_schedule' ) );
		add_action( self::CRON_HOOK, array( $this, 'run' ) );
		// Lazy self-heal: keep the schedule in step with the toggle on every load.
		add_action( 'init', array( $this, 'sync_schedule' ), 11 );
	}

	public function add_schedule( array $schedules ): array {
		if ( ! isset( $schedules[ self::CRON_SCHEDULE ] ) ) {
			$schedules[ self::CRON_SCHEDULE ] = array(
				'interval' => 5 * MINUTE_IN_SECONDS,
				'display'  => __( 'Every 5 minutes (INI Protector auto-block)', 'ini-protector' ),
			);
		}
		return $schedules;
	}

	/** Schedule the cron when the engine is on, clear it when off. */
	public function sync_schedule(): void {
		$on        = self::is_enabled();
		$scheduled = (bool) wp_next_scheduled( self::CRON_HOOK );
		if ( $on && ! $scheduled ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, self::CRON_SCHEDULE, self::CRON_HOOK );
		} elseif ( ! $on && $scheduled ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/* --------------------------------------------------------------------- */
	/* Mode                                                                   */
	/* --------------------------------------------------------------------- */

	/** Master on/off: is the escalation engine active at all? */
	public static function is_enabled(): bool {
		return class_exists( 'SecurityWP_Features' ) && SecurityWP_Features::is_on( self::FEATURE_AUTOBLOCK );
	}

	/** Auto-Block (enforce) vs Block Suggestion System (suggest only). */
	public static function is_enforcing(): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		return (bool) SecurityWP_Features::get( self::FEATURE_AUTOBLOCK, self::FIELD_ENFORCE, false );
	}

	/* --------------------------------------------------------------------- */
	/* Evaluation                                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * One evaluation pass. Decay always runs (so levels relax even while paused
	 * in suggest-only mode). Enforcement only applies blocks when in Auto-Block
	 * mode. Returns a small summary (handy for WP-CLI / tests).
	 *
	 * @return array{evaluated:int,exempt:int,applied:int,enforcing:bool}
	 */
	public function run(): array {
		$out = array( 'evaluated' => 0, 'exempt' => 0, 'applied' => 0, 'enforcing' => self::is_enforcing() );

		if ( ! self::is_enabled() || ! class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return $out;
		}

		$this->decay();

		$summary    = SecurityWP_Traffic_Log::summary( self::EVAL_HOURS, 100 );
		$candidates = $summary['suggested'] ?? array();
		if ( empty( $candidates ) ) {
			return $out;
		}

		$state    = self::state();
		$enforce  = self::is_enforcing();
		$changed  = false;

		foreach ( $candidates as $row ) {
			$ip  = (string) ( $row['ip'] ?? '' );
			$why = (string) ( $row['reason'] ?? '' );
			if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			$out['evaluated']++;

			if ( self::is_exempt( $ip ) ) {
				$out['exempt']++;
				continue;
			}

			// If already actively blocked, don't re-escalate on the same offense window.
			if ( SecurityWP_IP_Block::is_blocked( $ip ) ) {
				continue;
			}

			if ( ! $enforce ) {
				// Suggest-only: decide nothing persistent. The IP Block page already
				// shows this candidate (same suggested[] source); leave it for Apply.
				continue;
			}

			$res = self::escalate( $ip, $why, SecurityWP_IP_Block::SOURCE_AUTO, $state );
			if ( is_wp_error( $res ) ) {
				continue; // e.g. own IP / list full — skip, never fatal.
			}
			$changed = true;
			$out['applied']++;
		}

		if ( $changed ) {
			self::save_state( $state );
		}
		return $out;
	}

	/**
	 * Block an IP at its NEXT escalation level and bump its state — the single
	 * code path shared by the cron (Auto-Block mode) and the admin "Apply block"
	 * action on a suggestion. Both are temporary blocks on the same ladder; the
	 * only difference is who triggered it (recorded via $source). A human Apply
	 * therefore continues the same escalation an auto-block would, and decay
	 * applies to it too — no permanent suggestion-applied blocks.
	 *
	 * @param string     $ip     The IP to block (assumed already validated/exempt-checked by caller for the cron path; revalidated here for the admin path).
	 * @param string     $why    Human-readable reason (e.g. "62 404s (scanning)").
	 * @param string     $source SecurityWP_IP_Block::SOURCE_* — AUTO (cron) or SUGGESTION (Apply).
	 * @param array|null $state  Optional in-flight state array (the cron passes its own to batch the save); when null this loads + saves state itself.
	 * @return true|WP_Error
	 */
	public static function escalate( string $ip, string $why, string $source, array &$state = null ) {
		$own_state = ( null === $state );
		if ( $own_state ) {
			$state = self::state();
		}

		$level     = (int) ( $state[ $ip ]['level'] ?? 0 );
		$new_level = min( $level + 1, self::MAX_LEVEL );
		$ttl       = self::LADDER[ $new_level ];

		$reason = sprintf(
			/* translators: 1: level, 2: why */
			__( 'Auto-block L%1$d: %2$s', 'ini-protector' ),
			$new_level,
			$why
		);
		$res = SecurityWP_IP_Block::block_temp( $ip, $reason, $ttl, $source );
		if ( is_wp_error( $res ) ) {
			return $res;
		}

		$state[ $ip ] = array( 'level' => $new_level, 'last_block_at' => time() );
		if ( $own_state ) {
			self::save_state( $state );
		}

		do_action(
			'secwp_platform_event',
			'autoblock_temp',
			sprintf( 'Auto-blocked %s (level %d)', $ip, $new_level ),
			array( 'ip' => $ip, 'level' => $new_level, 'ttl' => $ttl, 'reason' => $why, 'source' => $source )
		);
		return true;
	}

	/**
	 * Drop one level off any IP that hasn't offended in DECAY_DAYS. Runs every
	 * pass; cheap (iterates the bounded option). Levels at 0 are pruned.
	 */
	private function decay(): void {
		$state = self::state();
		if ( empty( $state ) ) {
			return;
		}
		$cutoff  = time() - ( self::DECAY_DAYS * DAY_IN_SECONDS );
		$changed = false;
		foreach ( $state as $ip => $rec ) {
			$last = (int) ( $rec['last_block_at'] ?? 0 );
			if ( $last > $cutoff ) {
				continue;
			}
			$level = (int) ( $rec['level'] ?? 0 ) - 1;
			if ( $level <= 0 ) {
				unset( $state[ $ip ] );
			} else {
				// Advance last_block_at by one decay window so it keeps stepping down.
				$state[ $ip ] = array( 'level' => $level, 'last_block_at' => $last + ( self::DECAY_DAYS * DAY_IN_SECONDS ) );
			}
			$changed = true;
		}
		if ( $changed ) {
			self::save_state( $state );
		}
	}

	/* --------------------------------------------------------------------- */
	/* Exemption gate                                                         */
	/* --------------------------------------------------------------------- */

	/**
	 * An IP that must never be auto-blocked. Checked BEFORE any block, in both
	 * modes. Order: never auto-block the current admin's own IP, the allowlist
	 * (single IP + CIDR), the connector/family channel IP, then verified search
	 * bots by reverse-DNS. Filterable so a family plugin can extend it.
	 */
	public static function is_exempt( string $ip ): bool {
		// Never the current request's own IP (belt-and-suspenders; block() also guards this).
		if ( $ip === SecurityWP_IP_Block::current_ip() && '' !== $ip ) {
			return true;
		}
		// Admin-configured allowlist (single IPs + CIDR ranges).
		foreach ( self::allowlist() as $entry ) {
			if ( self::ip_matches( $ip, $entry ) ) {
				return true;
			}
		}
		// Verified search-engine bots (reverse + forward DNS). Auto-blocking these
		// deindexes the site, so they are always exempt.
		if ( self::is_verified_bot( $ip ) ) {
			return true;
		}
		/**
		 * Let other code (e.g. the connector, a family plugin) exempt an IP.
		 * Return true to exempt.
		 */
		return (bool) apply_filters( 'secwp_autoblock_is_exempt', false, $ip );
	}

	/** Admin allowlist of IPs/CIDRs, from feature config (newline/comma separated). */
	public static function allowlist(): array {
		$raw = '';
		if ( class_exists( 'SecurityWP_Features' ) ) {
			$raw = (string) SecurityWP_Features::get( self::FEATURE_AUTOBLOCK, 'allowlist', '' );
		}
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		return is_array( $parts ) ? $parts : array();
	}

	/** Validate IP/CIDR before any integer conversion; invalid masks must never become /0. */
	public static function valid_allowlist_entry( string $entry ): bool {
		$parts = explode( '/', trim( $entry ) );
		if ( count( $parts ) > 2 || ! filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( 1 === count( $parts ) ) {
			return true;
		}
		$max = false === strpos( $parts[0], ':' ) ? 32 : 128;
		return 1 === preg_match( '/^(0|[1-9][0-9]{0,2})$/D', $parts[1] ) && (int) $parts[1] <= $max;
	}

	/** Does $ip match a single-IP or CIDR allowlist entry? IPv4 + IPv6. */
	public static function ip_matches( string $ip, string $entry ): bool {
		$entry = trim( $entry );
		if ( ! self::valid_allowlist_entry( $entry ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( false === strpos( $entry, '/' ) ) {
			return $ip === $entry;
		}
		list( $subnet, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
		$bits = (int) $bits;
		$ipb  = @inet_pton( $ip );
		$snb  = @inet_pton( $subnet );
		if ( false === $ipb || false === $snb || strlen( $ipb ) !== strlen( $snb ) ) {
			return false;
		}
		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( $bytes > 0 && 0 !== substr_compare( $ipb, $snb, 0, $bytes ) ) {
			return false;
		}
		if ( $rem > 0 ) {
			$mask = chr( 0xff << ( 8 - $rem ) & 0xff );
			if ( ( $ipb[ $bytes ] & $mask ) !== ( $snb[ $bytes ] & $mask ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Verified search-engine bot: reverse-DNS the IP, confirm the hostname ends
	 * in a known bot domain, then forward-resolve that hostname back to the IP.
	 * The forward check defeats spoofed PTR records. Result cached 12h.
	 */
	public static function is_verified_bot( string $ip ): bool {
		$key    = 'secwp_vbot_' . md5( $ip );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return '1' === $cached;
		}
		$verified = self::verify_bot_uncached( $ip );
		set_transient( $key, $verified ? '1' : '0', 12 * HOUR_IN_SECONDS );
		return $verified;
	}

	private static function verify_bot_uncached( string $ip ): bool {
		$host = @gethostbyaddr( $ip );
		if ( ! $host || $host === $ip ) {
			return false;
		}
		$host    = strtolower( rtrim( $host, '.' ) );
		$domains = apply_filters(
			'secwp_autoblock_bot_domains',
			array( '.googlebot.com', '.google.com', '.search.msn.com', '.crawl.yahoo.net', '.applebot.apple.com', '.duckduckgo.com' )
		);
		$match = false;
		foreach ( $domains as $d ) {
			if ( substr( $host, -strlen( $d ) ) === $d ) {
				$match = true;
				break;
			}
		}
		if ( ! $match ) {
			return false;
		}
		// Forward-confirm: the hostname must resolve back to this IP.
		$forward = @gethostbynamel( $host );
		if ( is_array( $forward ) && in_array( $ip, $forward, true ) ) {
			return true;
		}
		// IPv6 forward check (gethostbynamel is IPv4-only).
		$recs = @dns_get_record( $host, DNS_AAAA );
		if ( is_array( $recs ) ) {
			foreach ( $recs as $r ) {
				if ( isset( $r['ipv6'] ) && @inet_pton( $r['ipv6'] ) === @inet_pton( $ip ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/* --------------------------------------------------------------------- */
	/* State storage                                                          */
	/* --------------------------------------------------------------------- */

	/** @return array<string,array{level:int,last_block_at:int}> */
	public static function state(): array {
		$s = get_option( self::OPTION, array() );
		return is_array( $s ) ? $s : array();
	}

	private static function save_state( array $state ): void {
		// Bound the option: if oversized, keep the highest-level / most-recent IPs.
		if ( count( $state ) > self::MAX_STATE ) {
			uasort(
				$state,
				static function ( $a, $b ) {
					$la = (int) ( $a['level'] ?? 0 );
					$lb = (int) ( $b['level'] ?? 0 );
					if ( $la !== $lb ) {
						return $lb <=> $la;
					}
					return (int) ( $b['last_block_at'] ?? 0 ) <=> (int) ( $a['last_block_at'] ?? 0 );
				}
			);
			$state = array_slice( $state, 0, self::MAX_STATE, true );
		}
		update_option( self::OPTION, $state, false );
	}

	/** Current escalation level for an IP (0 if untracked). For UI/platform. */
	public static function level_for( string $ip ): int {
		return (int) ( self::state()[ $ip ]['level'] ?? 0 );
	}
}
