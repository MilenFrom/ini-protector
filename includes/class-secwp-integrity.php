<?php
/**
 * File integrity monitoring — baseline, scan engine, and off-server alerting.
 *
 * Hashes every code file (SHA-256), stores a baseline, re-hashes on a schedule
 * and reports the diff: NEW, MODIFIED and DELETED files. Media is never hashed
 * (wp-content/uploads is excluded by default), so a large library costs nothing.
 *
 * THE DESIGN POINT — the alert leaves the server BEFORE the baseline is updated.
 * An attacker with filesystem AND database write access can rewrite any baseline
 * we keep here to match the state they planted. They cannot un-send an email or
 * a webhook that already left the box. So:
 *
 *   1. walk + hash          → observed state
 *   2. diff against baseline → changes
 *   3. DISPATCH the report  → email / webhook  (off-server, timestamped)
 *   4. only then persist the new baseline
 *
 * If every configured channel fails, the baseline is deliberately NOT updated:
 * the change is re-detected and re-reported on the next run rather than being
 * silently adopted. Fail-safe direction is "keep alerting", never "assume seen".
 *
 * Each report also carries a sequence number and a chain of state digests
 * (prev_state_digest → state_digest). A gap in the sequence, or a report whose
 * prev_state_digest does not match the digest in the message before it, means
 * the on-server record was tampered with (or mail was suppressed) — detectable
 * from the mailbox alone, without trusting anything on the server.
 *
 * Storage: a dedicated table (a 6-figure file count does not belong in an option).
 * The scan snapshot and rolling history are bounded options, mirroring
 * SecurityWP_Vuln_Scan.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Integrity {

	const FEATURE = 'file_integrity';
	const HOOK    = 'secwp_integrity_scan';

	/** Snapshot of the last scan: seq, scanned_at, status, counts, changes (capped). */
	const OPT_RESULTS = 'secwp_integrity_results';
	/** Rolling recent-change log (bounded), so the admin page shows history, not just the last run. */
	const OPT_HISTORY = 'secwp_integrity_history';
	/** Monotonic report sequence — a gap in the mailbox means a report was suppressed. */
	const OPT_SEQ = 'secwp_integrity_seq';
	/** Digest of the state the stored baseline represents (chain anchor). */
	const OPT_DIGEST = 'secwp_integrity_digest';
	/** Table schema version + the cron recurrence the schedule was built with. */
	const OPT_SCHEMA = 'secwp_integrity_schema';
	const OPT_SCHED  = 'secwp_integrity_sched';
	/** Digest of the change set the admin dismissed from the banner. */
	const OPT_DISMISS = 'secwp_integrity_dismissed';

	const SCHEMA_VERSION = 1;

	/** Changes kept in the snapshot / history / listed in the email body. */
	const REPORT_MAX    = 500;
	const HISTORY_MAX   = 300;
	const MAIL_LIST_MAX = 200;

	/** Rows per bulk write. */
	const WRITE_CHUNK = 200;

	/** Field separator for the packed in-memory maps (keeps peak memory ~halved). */
	const SEP = "\x1f";

	/**
	 * Everything PHP will execute, not just ".php".
	 *
	 * Hosts routinely map .php5/.php7/.phtml to the interpreter, .phar is executable
	 * outright, and .pht/.phps slip past naive filters — which is exactly why droppers
	 * use them. One list, shared by the integrity monitor and the security scan, so the
	 * two can never disagree about what counts as code again.
	 */
	const EXECUTABLE_EXTENSIONS = 'php,phtml,phps,pht,phar,php3,php4,php5,php6,php7,php8';

	/**
	 * Watched by exact filename, because pathinfo() cannot see them.
	 *
	 * pathinfo( '.user.ini' ) reports the extension as "ini", NOT "user.ini" — so an
	 * extension list can never match it, however it is written. Both of these turn PHP
	 * execution ON in a directory, so they matter most in precisely the places that
	 * hold no code: a .htaccess or .user.ini appearing under uploads is the enabler
	 * half of a webshell.
	 */
	const ALWAYS_WATCH_FILENAMES = '.htaccess,.user.ini';

	const DEFAULT_EXTENSIONS = 'php,phtml,phps,pht,phar,php3,php4,php5,php6,php7,php8,js,htaccess';
	const DEFAULT_MAX_FILES  = 200000;

	/* --------------------------------------------------------------------- */
	/* Table                                                                  */
	/* --------------------------------------------------------------------- */

	public static function table_name(): string {
		global $wpdb;
		return $wpdb->prefix . 'secwp_integrity';
	}

	/**
	 * Create/upgrade the baseline table (dbDelta-idempotent).
	 *
	 * Keyed on a hash of the path, not the path itself: a VARCHAR(512) utf8mb4
	 * column is 2048 bytes and cannot be a reliable primary key across MySQL
	 * versions, while CHAR(40) always can.
	 */
	public static function install_table(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table           = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			path_hash CHAR(40) NOT NULL,
			path VARCHAR(512) NOT NULL DEFAULT '',
			hash CHAR(64) NOT NULL DEFAULT '',
			size BIGINT UNSIGNED NOT NULL DEFAULT 0,
			mtime BIGINT UNSIGNED NOT NULL DEFAULT 0,
			first_seen BIGINT UNSIGNED NOT NULL DEFAULT 0,
			updated_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY  (path_hash),
			KEY path (path(191))
		) {$charset_collate};";

		dbDelta( $sql );
		update_option( self::OPT_SCHEMA, self::SCHEMA_VERSION, false );
	}

	public static function drop_table(): void {
		global $wpdb;
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		delete_option( self::OPT_SCHEMA );
	}

	public static function table_exists(): bool {
		global $wpdb;
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
	}

	/** Number of files in the stored baseline (0 when there is none). */
	public static function baseline_count(): int {
		global $wpdb;
		if ( (int) get_option( self::OPT_SCHEMA ) < self::SCHEMA_VERSION && ! self::table_exists() ) {
			return 0;
		}
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	/* --------------------------------------------------------------------- */
	/* Lifecycle                                                              */
	/* --------------------------------------------------------------------- */

	/** Hook the cron callback; heal table + schedule on init. */
	public function register(): void {
		add_action( self::HOOK, array( __CLASS__, 'run_scan_cron' ) );
		// Lazy self-heal, deliberately on init and not on plugins_loaded: scheduling
		// runs the cron_schedules filter, which other code translates — doing that
		// before init trips WP 6.7+'s "textdomain loaded too early" notice. Matches
		// how SecurityWP_Autoblock defers its own sync.
		add_action( 'init', array( __CLASS__, 'boot' ), 11 );
	}

	/** Table + schedule reconciliation, safe to run on every load. */
	public static function boot(): void {
		if ( SecurityWP_Features::is_on( self::FEATURE )
			&& (int) get_option( self::OPT_SCHEMA ) < self::SCHEMA_VERSION ) {
			self::install_table();
		}
		self::sync_schedule();
	}

	/**
	 * Reconcile the cron event with the toggle AND the configured recurrence.
	 * Idempotent; called on load and from SecurityWP_Admin::after_change().
	 */
	public static function sync_schedule(): void {
		$on   = SecurityWP_Features::is_on( self::FEATURE );
		$freq = self::frequency();
		$next = wp_next_scheduled( self::HOOK );

		if ( ! $on || 'off' === $freq ) {
			if ( $next ) {
				wp_clear_scheduled_hook( self::HOOK );
			}
			delete_option( self::OPT_SCHED );
			return;
		}

		$stored = (string) get_option( self::OPT_SCHED, '' );
		if ( ! $next || $stored !== $freq ) {
			wp_clear_scheduled_hook( self::HOOK );
			wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, $freq, self::HOOK );
			update_option( self::OPT_SCHED, $freq, false );
		}
	}

	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::HOOK );
		delete_option( self::OPT_SCHED );
	}

	/** Cron entry point. */
	public static function run_scan_cron(): void {
		if ( ! SecurityWP_Features::is_on( self::FEATURE ) ) {
			return;
		}
		( new self() )->run_scan();
	}

	/* --------------------------------------------------------------------- */
	/* Config                                                                 */
	/* --------------------------------------------------------------------- */

	public static function frequency(): string {
		$f     = (string) SecurityWP_Features::get( self::FEATURE, 'frequency', 'hourly' );
		$valid = array( 'hourly', 'twicedaily', 'daily', 'off' );
		return in_array( $f, $valid, true ) ? $f : 'hourly';
	}

	/** @return string[] Lowercase executable extensions, no leading dot. */
	public static function executable_extensions(): array {
		return explode( ',', self::EXECUTABLE_EXTENSIONS );
	}

	/**
	 * Would this filename be executed, or make its directory executable?
	 *
	 * The single test every scanner in the plugin uses. Takes a bare filename, not a
	 * path, so callers cannot accidentally match on a directory component.
	 */
	public static function is_executable_name( string $filename ): bool {
		$name = strtolower( $filename );
		if ( in_array( $name, explode( ',', self::ALWAYS_WATCH_FILENAMES ), true ) ) {
			return true;
		}
		$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		return '' !== $ext && in_array( $ext, self::executable_extensions(), true );
	}

	/**
	 * Extensions that count as "code" for the ordinary (non-media) roots.
	 *
	 * NOTE: an extension list cannot express ".user.ini" — pathinfo() calls that "ini".
	 * Filename-matched watches live in ALWAYS_WATCH_FILENAMES instead.
	 *
	 * @return string[] lowercase, no leading dot
	 */
	public function extensions(): array {
		$raw = (string) SecurityWP_Features::get( self::FEATURE, 'extensions', self::DEFAULT_EXTENSIONS );
		if ( '' === trim( $raw ) ) {
			$raw = self::DEFAULT_EXTENSIONS;
		}
		$out = array();
		foreach ( preg_split( '/[\s,]+/', strtolower( $raw ) ) as $ext ) {
			$ext = ltrim( trim( (string) $ext ), '.' );
			if ( '' !== $ext ) {
				$out[ $ext ] = true;
			}
		}
		return array_keys( $out );
	}

	/**
	 * Paths never walked, relative to ABSPATH. Defaults cover media, caches and
	 * backup/update working directories — the places that churn without being code.
	 *
	 * @return string[]
	 */
	/**
	 * Built-in prefixes that hold data, not code.
	 *
	 * These are NOT skipped outright any more. They are descended into and checked for
	 * executables only — hashing the media is what was expensive, never the walking, and
	 * uploads is the single most common place a shell is dropped. Ordinary files there
	 * are still ignored, so a churning uploads folder still costs nothing to monitor.
	 *
	 * @return string[]
	 */
	public function media_prefixes(): array {
		return array(
			'wp-content/uploads',
			'wp-content/cache',
			'wp-content/upgrade',
			'wp-content/upgrade-temp-backup',
			'wp-content/backup',
			'wp-content/backups',
			'wp-content/backup-db',
			'wp-content/ai1wm-backups',
			'wp-content/updraft',
			'wp-content/wflogs',
			'wp-content/et-cache',
			'wp-content/w3tc-cache',
		);
	}

	public function excluded_prefixes(): array {
		$defaults = array(
			'wp-content/uploads',
			'wp-content/cache',
			'wp-content/upgrade',
			'wp-content/upgrade-temp-backup',
			'wp-content/backup',
			'wp-content/backups',
			'wp-content/backup-db',
			'wp-content/ai1wm-backups',
			'wp-content/updraft',
			'wp-content/wflogs',
			'wp-content/et-cache',
			'wp-content/w3tc-cache',
		);

		$extra = (string) SecurityWP_Features::get( self::FEATURE, 'exclude', '' );
		foreach ( preg_split( '/[\r\n]+/', $extra ) as $line ) {
			$line = trim( (string) $line );
			$line = ltrim( str_replace( '\\', '/', $line ), '/' );
			$line = untrailingslashit( $line );
			if ( '' !== $line ) {
				$defaults[] = $line;
			}
		}

		/**
		 * Filter the path prefixes (relative to ABSPATH) that are never hashed.
		 *
		 * @param string[] $prefixes
		 */
		return array_values( array_unique( (array) apply_filters( 'secwp_integrity_exclude_paths', $defaults ) ) );
	}

	/** Directory names skipped wherever they appear. */
	public function excluded_dirnames(): array {
		/**
		 * Filter directory basenames skipped anywhere in the tree.
		 *
		 * @param string[] $names
		 */
		return (array) apply_filters( 'secwp_integrity_exclude_dirnames', array( 'node_modules', '.git', '.svn', '.hg', 'bower_components' ) );
	}

	/**
	 * Directory roots to walk: ABSPATH, plus wp-content when it lives outside it.
	 *
	 * @return string[]
	 */
	public function roots(): array {
		$abspath = untrailingslashit( str_replace( '\\', '/', ABSPATH ) );
		$roots   = array( $abspath );

		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$content = untrailingslashit( str_replace( '\\', '/', WP_CONTENT_DIR ) );
			if ( '' !== $content && 0 !== strpos( $content . '/', $abspath . '/' ) ) {
				$roots[] = $content;
			}
		}

		/**
		 * Filter the directory roots walked by the integrity scan.
		 *
		 * @param string[] $roots Absolute paths, no trailing slash.
		 */
		return array_values( array_unique( (array) apply_filters( 'secwp_integrity_roots', $roots ) ) );
	}

	/**
	 * Individual files outside the roots that must still be watched.
	 *
	 * WordPress falls back to ../wp-config.php when ABSPATH/wp-config.php is
	 * absent — a very common layout, and exactly the file attackers inject into.
	 * Mirroring core's own resolution keeps us from watching a stranger's file
	 * on a shared parent directory.
	 *
	 * @return string[]
	 */
	public function extra_files(): array {
		$out     = array();
		$abspath = untrailingslashit( str_replace( '\\', '/', ABSPATH ) );

		if ( ! file_exists( $abspath . '/wp-config.php' ) ) {
			$parent = dirname( $abspath ) . '/wp-config.php';
			if ( file_exists( $parent ) && ! file_exists( dirname( $abspath ) . '/wp-settings.php' ) ) {
				$out[] = $parent;
			}
		}

		/**
		 * Filter individual absolute file paths watched outside the roots.
		 *
		 * @param string[] $files
		 */
		return (array) apply_filters( 'secwp_integrity_extra_files', $out );
	}

	/** Path stored in the baseline: relative to ABSPATH when inside it, absolute otherwise. */
	public function relative_path( string $abs ): string {
		$abs  = str_replace( '\\', '/', $abs );
		$base = untrailingslashit( str_replace( '\\', '/', ABSPATH ) ) . '/';
		return ( 0 === strpos( $abs, $base ) ) ? substr( $abs, strlen( $base ) ) : $abs;
	}

	/**
	 * Is this a path where a change is very likely to matter? Drives the "critical"
	 * flag that sorts the report and leads the email. Derived from where real
	 * WordPress compromises land: core directories, wp-config, mu-plugins,
	 * .htaccess, theme function files, and anything at the web root.
	 */
	public function is_critical( string $rel ): bool {
		$base = strtolower( basename( $rel ) );

		if ( 'wp-config.php' === $base || '.htaccess' === $base || '.user.ini' === $base ) {
			return true;
		}
		// Executable code where only media lives. There is no innocent reason for a
		// .php in wp-content/uploads, so when one appears it leads the report.
		foreach ( $this->media_prefixes() as $p ) {
			if ( 0 === strpos( $rel, $p . '/' ) && self::is_executable_name( $base ) ) {
				return true;
			}
		}
		if ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) {
			return true;
		}
		if ( 0 === strpos( $rel, 'wp-content/mu-plugins/' ) ) {
			return true;
		}
		if ( preg_match( '#^wp-content/themes/[^/]+/functions\.php$#', $rel ) ) {
			return true;
		}
		// A file sitting at the web root (no directory component) — index.php, wp-load.php, a dropped webshell.
		if ( false === strpos( $rel, '/' ) ) {
			return true;
		}
		return false;
	}

	/* --------------------------------------------------------------------- */
	/* Walk + hash                                                            */
	/* --------------------------------------------------------------------- */

	/**
	 * Hash every in-scope file.
	 *
	 * @return array{files:array<string,string>,unreadable:string[],truncated:bool,bytes:int}
	 *         files: path_hash => "sha256<SEP>size<SEP>mtime<SEP>relative path"
	 */
	public function collect(): array {
		$exts       = array_flip( $this->extensions() );
		$prefixes   = $this->excluded_prefixes();
		$media      = $this->media_prefixes();
		// A user-configured exclusion still means "do not look here at all"; only the
		// built-in media/cache defaults are downgraded to an executables-only sweep, so
		// nobody's deliberate exclusion starts producing noise after an update.
		$blind      = array_values( array_diff( $prefixes, $media ) );
		$dirnames   = array_flip( $this->excluded_dirnames() );
		$max_files  = (int) SecurityWP_Features::get( self::FEATURE, 'max_files', self::DEFAULT_MAX_FILES );
		$max_files  = $max_files > 0 ? $max_files : self::DEFAULT_MAX_FILES;

		$files      = array();
		$unreadable = array();
		$bytes      = 0;
		$truncated  = false;

		foreach ( $this->roots() as $root ) {
			if ( $truncated || ! is_dir( $root ) ) {
				continue;
			}

			try {
				$dir = new RecursiveDirectoryIterator(
					$root,
					FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS
				);
			} catch ( Exception $e ) {
				continue;
			}

			// Prune excluded directories during descent — far cheaper than filtering leaves.
			$filtered = new RecursiveCallbackFilterIterator(
				$dir,
				function ( $current ) use ( $blind, $dirnames ) {
					try {
						if ( ! $current->isDir() ) {
							return true;
						}
					} catch ( Exception $e ) {
						return false;
					}
					if ( isset( $dirnames[ $current->getFilename() ] ) ) {
						return false;
					}
					$rel = $this->relative_path( $current->getPathname() );
					foreach ( $blind as $p ) {
						if ( $rel === $p || 0 === strpos( $rel . '/', $p . '/' ) ) {
							return false;
						}
					}
					return true;
				}
			);

			$it = new RecursiveIteratorIterator(
				$filtered,
				RecursiveIteratorIterator::LEAVES_ONLY,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);

			foreach ( $it as $file ) {
				if ( count( $files ) >= $max_files ) {
					$truncated = true;
					break;
				}
				$path       = $file->getPathname();
				$name       = $file->getFilename();
				$ext        = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
				$executable = self::is_executable_name( $name );

				// Cheap test first: most files are neither code nor executable, and
				// skipping them here avoids computing a relative path per leaf.
				if ( ! $executable && ! isset( $exts[ $ext ] ) ) {
					continue;
				}
				// Inside uploads/cache/backups we hash executables and nothing else.
				// A .js or .htaccess-shaped asset there is ordinary; a .php or a
				// .user.ini is not, and that asymmetry is the whole point.
				if ( ! $executable && $this->under_prefix( $path, $media ) ) {
					continue;
				}
				// Symlinks are not followed into (no FOLLOW_SYMLINKS) and a symlinked
				// FILE is hashed by target content, which is what we want.
				$this->hash_into( $path, $files, $unreadable, $bytes );
			}
		}

		foreach ( $this->extra_files() as $path ) {
			if ( count( $files ) >= $max_files ) {
				$truncated = true;
				break;
			}
			$this->hash_into( $path, $files, $unreadable, $bytes );
		}

		return array(
			'files'      => $files,
			'unreadable' => $unreadable,
			'truncated'  => $truncated,
			'bytes'      => $bytes,
		);
	}

	/** Is this absolute path inside one of the given ABSPATH-relative prefixes? */
	private function under_prefix( string $abs, array $prefixes ): bool {
		$rel = $this->relative_path( $abs );
		foreach ( $prefixes as $p ) {
			if ( $rel === $p || 0 === strpos( $rel, $p . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Hash one file into the collection, recording it as unreadable on failure. */
	private function hash_into( string $path, array &$files, array &$unreadable, int &$bytes ): void {
		$rel = $this->relative_path( $path );

		if ( ! is_readable( $path ) ) {
			$unreadable[] = $rel;
			return;
		}
		// hash_file() streams, so a large bundle costs no extra memory.
		$hash = @hash_file( 'sha256', $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $hash || '' === $hash ) {
			$unreadable[] = $rel;
			return;
		}
		$size   = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$mtime  = (int) @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$bytes += $size;

		$files[ sha1( $rel ) ] = $hash . self::SEP . $size . self::SEP . $mtime . self::SEP . $rel;
	}

	/** Read the stored baseline as path_hash => "hash<SEP>size<SEP>mtime<SEP>path". */
	public function load_baseline(): array {
		global $wpdb;
		$table = self::table_name();
		$out   = array();

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( "SELECT path_hash, hash, size, mtime, path FROM {$table}", ARRAY_N );
		foreach ( (array) $rows as $r ) {
			$out[ $r[0] ] = $r[1] . self::SEP . $r[2] . self::SEP . $r[3] . self::SEP . $r[4];
		}
		return $out;
	}

	/** Stable digest of an observed state — the anchor of the report chain. */
	public function state_digest( array $files ): string {
		if ( ! $files ) {
			return '';
		}
		ksort( $files );
		$ctx = hash_init( 'sha256' );
		foreach ( $files as $ph => $packed ) {
			$parts = explode( self::SEP, $packed );
			hash_update( $ctx, $ph . ':' . ( $parts[0] ?? '' ) . "\n" );
		}
		return hash_final( $ctx );
	}

	/* --------------------------------------------------------------------- */
	/* Scan                                                                   */
	/* --------------------------------------------------------------------- */

	/**
	 * Run a scan: hash everything, diff against the baseline, alert, then persist.
	 *
	 * @param array $args {
	 *   @type bool $baseline Rebuild the baseline from the current state, no alert.
	 *   @type bool $notify   Dispatch alerts (default true).
	 * }
	 * @return array The report.
	 */
	public function run_scan( array $args = array() ): array {
		$started       = microtime( true );
		$force_baseline = ! empty( $args['baseline'] );
		$notify         = ! isset( $args['notify'] ) || (bool) $args['notify'];

		if ( ! self::table_exists() ) {
			self::install_table();
		}

		$scan     = $this->collect();
		$current  = $scan['files'];
		$baseline = $this->load_baseline();

		// An unreadable file must not masquerade as a deletion: carry its old
		// baseline row forward untouched so it is neither reported nor dropped.
		foreach ( $scan['unreadable'] as $rel ) {
			$ph = sha1( $rel );
			if ( isset( $baseline[ $ph ] ) && ! isset( $current[ $ph ] ) ) {
				$current[ $ph ] = $baseline[ $ph ];
			}
		}

		// A truncated scan never reached the whole tree, so "absent from $current" means
		// "not looked at", not "deleted". Carrying every unseen baseline row forward keeps
		// the run honest twice over: no storm of false deletions in the report, and
		// persist() cannot drop rows for files it never opened — which would silently
		// shrink the monitored set to the truncated head and leave the rest unwatched
		// from then on. Files we DID reach are still compared normally.
		if ( $scan['truncated'] ) {
			$current += $baseline;
		}

		$first_run = empty( $baseline );
		$changes   = ( $first_run || $force_baseline ) ? array() : $this->diff( $baseline, $current );

		$prev_digest = (string) get_option( self::OPT_DIGEST, '' );
		$digest      = $this->state_digest( $current );
		$seq         = (int) get_option( self::OPT_SEQ, 0 ) + 1;

		$report = array(
			'seq'                 => $seq,
			'scanned_at'          => time(),
			'status'              => $first_run ? 'baseline' : ( $force_baseline ? 'rebaselined' : 'ok' ),
			'counts'              => $this->counts( $changes ) + array(
				'files'      => count( $current ),
				'unreadable' => count( $scan['unreadable'] ),
			),
			'changes'             => array_slice( $changes, 0, self::REPORT_MAX ),
			'changes_truncated'   => count( $changes ) > self::REPORT_MAX,
			'files_truncated'     => (bool) $scan['truncated'],
			'unreadable'          => array_slice( $scan['unreadable'], 0, 50 ),
			'bytes'               => (int) $scan['bytes'],
			'prev_state_digest'   => $prev_digest,
			'state_digest'        => $digest,
			'duration'            => round( microtime( true ) - $started, 2 ),
			'alert'               => array( 'attempted' => false, 'delivered' => false, 'channels' => array() ),
		);

		if ( $scan['truncated'] ) {
			$report['status'] = 'truncated';
		}

		/* ---- Off-server alert FIRST, baseline SECOND. ---------------------- */
		$deliver = ( $changes && $notify && ! $force_baseline && ! $first_run );
		if ( $deliver ) {
			$report['alert'] = SecurityWP_Integrity_Alert::dispatch( $report, $changes );
		}

		// If every CONFIGURED channel failed, keep the old baseline so the change is
		// reported again next run instead of being silently adopted. With no channel
		// configured at all there is nothing to fail, so we adopt and let the admin
		// page carry the warning instead of looping forever on the same change.
		$adopt = ! $deliver
			|| empty( $report['alert']['configured'] )
			|| ! empty( $report['alert']['delivered'] );
		if ( $adopt ) {
			$this->persist( $baseline, $current );
			update_option( self::OPT_DIGEST, $digest, false );
		} else {
			$report['status'] = 'alert_failed';
		}

		update_option( self::OPT_SEQ, $seq, false );
		update_option( self::OPT_RESULTS, $report, false );

		if ( $changes ) {
			$this->push_history( $changes, $seq );
			do_action(
				'secwp_platform_event',
				'integrity_change',
				sprintf(
					'%d new, %d modified, %d deleted code file(s)',
					$report['counts']['new'],
					$report['counts']['modified'],
					$report['counts']['deleted']
				),
				$report['counts']
			);
		}

		/**
		 * Fires after every integrity scan, with the full report.
		 *
		 * @param array $report
		 */
		do_action( 'secwp_integrity_scanned', $report );

		return $report;
	}

	/**
	 * Diff two packed state maps into a flat change list.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function diff( array $baseline, array $current ): array {
		$changes = array();

		foreach ( $current as $ph => $packed ) {
			list( $hash, $size, $mtime, $path ) = array_pad( explode( self::SEP, $packed, 4 ), 4, '' );

			if ( ! isset( $baseline[ $ph ] ) ) {
				$changes[] = array(
					'state'    => 'new',
					'path'     => $path,
					'hash'     => $hash,
					'old_hash' => '',
					'size'     => (int) $size,
					'mtime'    => (int) $mtime,
					'critical' => $this->is_critical( $path ),
				);
				continue;
			}

			list( $old_hash, $old_size, $old_mtime ) = array_pad( explode( self::SEP, $baseline[ $ph ], 4 ), 4, '' );
			if ( $old_hash === $hash ) {
				continue;
			}

			$changes[] = array(
				'state'    => 'modified',
				'path'     => $path,
				'hash'     => $hash,
				'old_hash' => (string) $old_hash,
				'size'     => (int) $size,
				'mtime'    => (int) $mtime,
				'critical' => $this->is_critical( $path ),
				// Content changed but the modification time did not move forward:
				// the hallmark of a self-rewriting payload or a timestomped file.
				'timestomp' => ( (int) $mtime <= (int) $old_mtime ),
			);
		}

		foreach ( $baseline as $ph => $packed ) {
			if ( isset( $current[ $ph ] ) ) {
				continue;
			}
			list( $old_hash, $old_size, $old_mtime, $path ) = array_pad( explode( self::SEP, $packed, 4 ), 4, '' );
			$changes[] = array(
				'state'    => 'deleted',
				'path'     => $path,
				'hash'     => '',
				'old_hash' => (string) $old_hash,
				'size'     => (int) $old_size,
				'mtime'    => (int) $old_mtime,
				'critical' => $this->is_critical( $path ),
			);
		}

		// Critical first, then new/modified/deleted, then path — the order a human reads.
		$rank = array( 'new' => 0, 'modified' => 1, 'deleted' => 2 );
		usort(
			$changes,
			static function ( $a, $b ) use ( $rank ) {
				if ( $a['critical'] !== $b['critical'] ) {
					return $a['critical'] ? -1 : 1;
				}
				$ra = $rank[ $a['state'] ] ?? 9;
				$rb = $rank[ $b['state'] ] ?? 9;
				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}
				return strcmp( $a['path'], $b['path'] );
			}
		);

		return $changes;
	}

	private function counts( array $changes ): array {
		$c = array( 'new' => 0, 'modified' => 0, 'deleted' => 0, 'critical' => 0, 'total' => 0 );
		foreach ( $changes as $ch ) {
			if ( isset( $c[ $ch['state'] ] ) ) {
				++$c[ $ch['state'] ];
			}
			if ( ! empty( $ch['critical'] ) ) {
				++$c['critical'];
			}
			++$c['total'];
		}
		return $c;
	}

	/**
	 * Write the observed state to the baseline table: upsert everything present,
	 * delete rows for files that are gone.
	 */
	private function persist( array $baseline, array $current ): void {
		global $wpdb;
		$table = self::table_name();
		$now   = time();

		$write = array();
		foreach ( $current as $ph => $packed ) {
			if ( isset( $baseline[ $ph ] ) && $baseline[ $ph ] === $packed ) {
				continue; // Unchanged, including size/mtime — nothing to write.
			}
			$write[ $ph ] = $packed;
		}

		foreach ( array_chunk( $write, self::WRITE_CHUNK, true ) as $chunk ) {
			$values = array();
			$params = array();
			foreach ( $chunk as $ph => $packed ) {
				list( $hash, $size, $mtime, $path ) = array_pad( explode( self::SEP, $packed, 4 ), 4, '' );
				// The path column is capped, but the row is keyed on a hash of the FULL
				// path, so a very long path is still diffed correctly — only its
				// display is shortened.
				$values[] = '(%s,%s,%s,%d,%d,%d,%d)';
				array_push( $params, $ph, substr( $path, 0, 512 ), $hash, (int) $size, (int) $mtime, $now, $now );
			}
			$sql = "INSERT INTO {$table} (path_hash, path, hash, size, mtime, first_seen, updated_at) VALUES "
				. implode( ',', $values )
				. ' ON DUPLICATE KEY UPDATE path=VALUES(path), hash=VALUES(hash), size=VALUES(size), mtime=VALUES(mtime), updated_at=VALUES(updated_at)';
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
			$wpdb->query( $wpdb->prepare( $sql, $params ) );
		}

		$gone = array_keys( array_diff_key( $baseline, $current ) );
		foreach ( array_chunk( $gone, self::WRITE_CHUNK ) as $chunk ) {
			$in  = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );
			$sql = "DELETE FROM {$table} WHERE path_hash IN ({$in})";
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
			$wpdb->query( $wpdb->prepare( $sql, $chunk ) );
		}
	}

	/** Append to the bounded rolling history (newest first). */
	private function push_history( array $changes, int $seq ): void {
		$history = (array) get_option( self::OPT_HISTORY, array() );
		$now     = time();
		$add     = array();

		foreach ( array_slice( $changes, 0, self::HISTORY_MAX ) as $ch ) {
			$add[] = array(
				'seq'       => $seq,
				'at'        => $now,
				'state'     => $ch['state'],
				'path'      => $ch['path'],
				'critical'  => ! empty( $ch['critical'] ),
				'timestomp' => ! empty( $ch['timestomp'] ),
			);
		}

		$history = array_slice( array_merge( $add, $history ), 0, self::HISTORY_MAX );
		update_option( self::OPT_HISTORY, $history, false );
	}

	/* --------------------------------------------------------------------- */
	/* Read API                                                               */
	/* --------------------------------------------------------------------- */

	/** The stored snapshot with a safe empty default. */
	public static function get_results(): array {
		$r = get_option( self::OPT_RESULTS, array() );
		if ( ! is_array( $r ) ) {
			$r = array();
		}
		return wp_parse_args(
			$r,
			array(
				'seq'               => 0,
				'scanned_at'        => 0,
				'status'            => 'never',
				'counts'            => array( 'new' => 0, 'modified' => 0, 'deleted' => 0, 'critical' => 0, 'total' => 0, 'files' => 0, 'unreadable' => 0 ),
				'changes'           => array(),
				'changes_truncated' => false,
				'files_truncated'   => false,
				'unreadable'        => array(),
				'bytes'             => 0,
				'prev_state_digest' => '',
				'state_digest'      => '',
				'duration'          => 0,
				'alert'             => array( 'attempted' => false, 'delivered' => false, 'channels' => array() ),
			)
		);
	}

	public static function history(): array {
		$h = get_option( self::OPT_HISTORY, array() );
		return is_array( $h ) ? $h : array();
	}

	public static function last_scan(): int {
		return (int) self::get_results()['scanned_at'];
	}

	/** Stable digest of the current change set — changes when the change set changes. */
	public static function changes_digest(): string {
		$r    = self::get_results();
		$keys = array();
		foreach ( $r['changes'] as $c ) {
			$keys[] = ( $c['state'] ?? '' ) . '|' . ( $c['path'] ?? '' ) . '|' . ( $c['hash'] ?? '' );
		}
		sort( $keys );
		return $keys ? sha1( implode( ',', $keys ) ) : '';
	}

	/** Is the current change set dismissed from the dashboard banner? */
	public static function is_dismissed(): bool {
		$digest = self::changes_digest();
		if ( '' === $digest ) {
			return false;
		}
		return (string) get_option( self::OPT_DISMISS, '' ) === $digest;
	}

	/** Clear the stored baseline entirely (the next scan re-establishes it). */
	public static function reset_baseline(): void {
		global $wpdb;
		if ( ! self::table_exists() ) {
			return;
		}
		$table = self::table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "TRUNCATE TABLE {$table}" );
		delete_option( self::OPT_DIGEST );
	}
}
