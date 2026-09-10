<?php
/**
 * WP-CLI commands.
 *
 * The integrity scan exists partly BECAUSE WP-Cron cannot be trusted: on a site
 * with DISABLE_WP_CRON set it never fires, and on any site it depends on traffic.
 * `wp secwp integrity scan` is the supported way to drive it from system cron,
 * and it exits 1 when changes are found so a monitoring system can act on the
 * status code alone.
 *
 * `wp secwp asset-salt rotate` exists for the same reason in reverse: it belongs
 * at the end of a deploy script, where no admin is sitting in front of a button.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * Hash code files, compare against the baseline, and report new/modified/deleted files.
 */
class SecurityWP_CLI_Integrity {

	/**
	 * Scan the site and report any change since the baseline.
	 *
	 * The first run on a site with no baseline records one and reports nothing.
	 * Alerts (email/webhook) are dispatched before the baseline is updated, so a
	 * change is never adopted without leaving the server first.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * [--no-notify]
	 * : Do not send email/webhook alerts for this run. The baseline is still updated.
	 *
	 * [--quiet]
	 * : Print nothing on a clean run (for cron). Changes are still printed.
	 *
	 * ## EXAMPLES
	 *
	 *     # From system cron, hourly at :17
	 *     17 * * * * cd /var/www/site && wp secwp integrity scan --quiet
	 *
	 *     wp secwp integrity scan --format=json
	 *
	 * @when after_wp_load
	 */
	public function scan( $args, $assoc ) {
		$this->require_feature();

		$quiet  = (bool) WP_CLI\Utils\get_flag_value( $assoc, 'quiet', false );
		$format = (string) WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );
		$notify = ! (bool) WP_CLI\Utils\get_flag_value( $assoc, 'no-notify', false );

		$report = ( new SecurityWP_Integrity() )->run_scan( array( 'notify' => $notify ) );
		$counts = $report['counts'];

		if ( 'json' === $format ) {
			WP_CLI::line( (string) wp_json_encode( $report ) );
			$this->halt_on_changes( $report );
			return;
		}

		if ( 'baseline' === $report['status'] ) {
			WP_CLI::success(
				sprintf(
					'Baseline recorded: %s files hashed in %ss. Nothing is reported on the first run.',
					number_format_i18n( (int) $counts['files'] ),
					$report['duration']
				)
			);
			return;
		}

		if ( 0 === (int) $counts['total'] ) {
			if ( ! $quiet ) {
				WP_CLI::success(
					sprintf(
						'No changes. %s files hashed in %ss.',
						number_format_i18n( (int) $counts['files'] ),
						$report['duration']
					)
				);
			}
			return;
		}

		WP_CLI::warning(
			sprintf(
				'%d change(s): %d new, %d modified, %d deleted (%d in critical locations).',
				(int) $counts['total'],
				(int) $counts['new'],
				(int) $counts['modified'],
				(int) $counts['deleted'],
				(int) $counts['critical']
			)
		);

		$rows = array();
		foreach ( $report['changes'] as $c ) {
			$rows[] = array(
				'state'    => $c['state'],
				'critical' => ! empty( $c['critical'] ) ? 'yes' : '',
				'path'     => $c['path'],
				'size'     => 'deleted' === $c['state'] ? '' : (string) $c['size'],
				'mtime'    => 'deleted' === $c['state'] ? '' : gmdate( 'Y-m-d H:i', (int) $c['mtime'] ),
				'note'     => ! empty( $c['timestomp'] ) ? 'mtime did not move' : '',
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'state', 'critical', 'path', 'size', 'mtime', 'note' ) );

		$this->report_alert_status( $report );
		$this->halt_on_changes( $report );
	}

	/**
	 * Accept the current state of the site as the baseline. Reports nothing and sends no alert.
	 *
	 * Use after a legitimate update, deploy, or once you have reviewed and cleaned
	 * up a set of reported changes.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * @when after_wp_load
	 */
	public function baseline( $args, $assoc ) {
		$this->require_feature();
		WP_CLI::confirm( 'Mark every code file currently on disk as known-good?', $assoc );

		$report = ( new SecurityWP_Integrity() )->run_scan( array( 'baseline' => true ) );
		WP_CLI::success(
			sprintf(
				'Baseline updated: %s files hashed in %ss. State digest %s',
				number_format_i18n( (int) $report['counts']['files'] ),
				$report['duration'],
				(string) $report['state_digest']
			)
		);
	}

	/**
	 * Show the state of the last scan without running one.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @when after_wp_load
	 */
	public function status( $args, $assoc ) {
		$r      = SecurityWP_Integrity::get_results();
		$format = (string) WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );

		$data = array(
			'enabled'        => SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ? 'yes' : 'no',
			'status'         => (string) $r['status'],
			'report'         => (int) $r['seq'],
			'last_scan'      => $r['scanned_at'] ? gmdate( 'Y-m-d H:i:s', (int) $r['scanned_at'] ) . ' UTC' : 'never',
			'baseline_files' => SecurityWP_Integrity::baseline_count(),
			'files_hashed'   => (int) ( $r['counts']['files'] ?? 0 ),
			'new'            => (int) ( $r['counts']['new'] ?? 0 ),
			'modified'       => (int) ( $r['counts']['modified'] ?? 0 ),
			'deleted'        => (int) ( $r['counts']['deleted'] ?? 0 ),
			'critical'       => (int) ( $r['counts']['critical'] ?? 0 ),
			'schedule'       => SecurityWP_Integrity::frequency(),
			'next_run'       => wp_next_scheduled( SecurityWP_Integrity::HOOK ) ? gmdate( 'Y-m-d H:i:s', (int) wp_next_scheduled( SecurityWP_Integrity::HOOK ) ) . ' UTC' : 'not scheduled',
			'state_digest'   => (string) $r['state_digest'],
		);

		if ( 'json' === $format ) {
			WP_CLI::line( (string) wp_json_encode( $data ) );
			return;
		}

		$rows = array();
		foreach ( $data as $k => $v ) {
			$rows[] = array( 'field' => $k, 'value' => (string) $v );
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'field', 'value' ) );
	}

	/**
	 * List the changes recorded by the last scan.
	 *
	 * ## OPTIONS
	 *
	 * [--state=<state>]
	 * : Only show one kind of change.
	 * ---
	 * options:
	 *   - new
	 *   - modified
	 *   - deleted
	 * ---
	 *
	 * [--critical]
	 * : Only show changes in critical locations.
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * @subcommand list
	 * @when after_wp_load
	 */
	public function list_( $args, $assoc ) {
		$r        = SecurityWP_Integrity::get_results();
		$state    = (string) WP_CLI\Utils\get_flag_value( $assoc, 'state', '' );
		$critical = (bool) WP_CLI\Utils\get_flag_value( $assoc, 'critical', false );
		$format   = (string) WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );

		$rows = array();
		foreach ( (array) $r['changes'] as $c ) {
			if ( '' !== $state && $state !== $c['state'] ) {
				continue;
			}
			if ( $critical && empty( $c['critical'] ) ) {
				continue;
			}
			$rows[] = array(
				'state'    => (string) $c['state'],
				'critical' => ! empty( $c['critical'] ) ? 'yes' : '',
				'path'     => (string) $c['path'],
				'sha256'   => (string) ( $c['hash'] ?? '' ),
			);
		}

		if ( ! $rows ) {
			WP_CLI::success( 'No matching changes in the last scan.' );
			return;
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'state', 'critical', 'path', 'sha256' ) );
	}

	/* --------------------------------------------------------------------- */

	private function require_feature(): void {
		if ( ! SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			WP_CLI::error( 'File integrity monitoring is off. Enable it in INI Protector settings first.' );
		}
	}

	/** Tell the operator when an alert could not be delivered — silence is the failure mode that matters. */
	private function report_alert_status( array $report ): void {
		$alert = (array) $report['alert'];
		if ( empty( $alert['attempted'] ) ) {
			if ( empty( $alert['configured'] ) ) {
				WP_CLI::warning( 'No alert channel is configured — this change was recorded on the server only.' );
			}
			return;
		}
		foreach ( (array) $alert['channels'] as $channel => $status ) {
			if ( 'sent' === $status ) {
				WP_CLI::log( sprintf( 'Alert delivered via %s.', $channel ) );
			} else {
				WP_CLI::warning( sprintf( 'Alert via %s FAILED.', $channel ) );
			}
		}
		if ( empty( $alert['delivered'] ) ) {
			WP_CLI::warning( 'No channel delivered — the baseline was left unchanged so this is reported again next run.' );
		}
	}

	/** Exit 1 on changes so cron/monitoring can branch on the status code. */
	private function halt_on_changes( array $report ): void {
		if ( (int) ( $report['counts']['total'] ?? 0 ) > 0 ) {
			WP_CLI::halt( 1 );
		}
	}
}

WP_CLI::add_command( 'secwp integrity', 'SecurityWP_CLI_Integrity' );

/**
 * Inspect and reset two-factor authentication. The break-glass path when a phone is lost.
 */
class SecurityWP_CLI_2FA {

	/**
	 * Show two-factor status for one user, or for everyone who has it on.
	 *
	 * ## OPTIONS
	 *
	 * [<user>]
	 * : User ID, login, or email. Omit to list every enrolled account.
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * @when after_wp_load
	 */
	public function status( $args, $assoc ) {
		$format = (string) WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );

		$users = isset( $args[0] )
			? array( $this->get_user( $args[0] ) )
			: get_users( array( 'meta_key' => SecurityWP_TOTP::META_ENABLED, 'meta_value' => 1 ) );

		if ( ! $users ) {
			WP_CLI::success( 'No account has two-factor authentication enabled.' );
			return;
		}

		$rows = array();
		foreach ( $users as $u ) {
			$enabled = SecurityWP_TOTP::is_enabled( $u->ID );
			$rows[]  = array(
				'ID'             => $u->ID,
				'user_login'     => $u->user_login,
				'roles'          => implode( ',', (array) $u->roles ),
				'2fa'            => $enabled ? 'on' : 'off',
				'required'       => SecurityWP_2FA::is_required_for( $u ) ? 'yes' : '',
				'recovery_left'  => $enabled ? SecurityWP_TOTP::recovery_remaining( $u->ID ) : '',
				// "no" means the secret was encrypted under salts this site no longer
				// has — the account can only get back in with a recovery code or a reset.
				'secret_readable' => $enabled ? ( SecurityWP_TOTP::secret_readable( $u->ID ) ? 'yes' : 'NO' ) : '',
			);
		}
		WP_CLI\Utils\format_items( $format, $rows, array( 'ID', 'user_login', 'roles', '2fa', 'required', 'recovery_left', 'secret_readable' ) );
	}

	/**
	 * Turn two-factor authentication off for a user — the break-glass for a lost device.
	 *
	 * Removes the secret, the enrolment flag, and the recovery codes, so the account
	 * signs in with its password alone again. If the user's role requires 2FA they are
	 * sent back to their profile to enrol on the next admin page they open.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp secwp 2fa reset admin --yes
	 *
	 * @when after_wp_load
	 */
	public function reset( $args, $assoc ) {
		$user = $this->get_user( $args[0] );
		if ( ! SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			WP_CLI::success( sprintf( '%s does not have two-factor authentication enabled — nothing to do.', $user->user_login ) );
			return;
		}
		WP_CLI::confirm( sprintf( 'Turn two-factor authentication OFF for %s (ID %d)?', $user->user_login, $user->ID ), $assoc );

		SecurityWP_TOTP::disable( $user->ID );
		do_action(
			'secwp_platform_event',
			'2fa_disabled',
			sprintf( 'Two-factor authentication reset from WP-CLI for user %d', $user->ID ),
			array( 'user_id' => $user->ID, 'via' => 'wp-cli' )
		);
		WP_CLI::success( sprintf( 'Two-factor authentication removed for %s. They can sign in with their password alone.', $user->user_login ) );
	}

	/**
	 * Issue a fresh set of recovery codes for a user and print them once.
	 *
	 * The previous set stops working immediately. Hand these over on a channel the
	 * user actually controls — they are equivalent to the second factor.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * @when after_wp_load
	 */
	public function codes( $args, $assoc ) {
		$user = $this->get_user( $args[0] );
		if ( ! SecurityWP_TOTP::is_enabled( $user->ID ) ) {
			WP_CLI::error( sprintf( '%s does not have two-factor authentication enabled.', $user->user_login ) );
		}
		WP_CLI::confirm( sprintf( 'Replace the recovery codes for %s? The current set stops working.', $user->user_login ), $assoc );

		$codes = SecurityWP_TOTP::generate_recovery_codes( $user->ID );
		WP_CLI::log( '' );
		foreach ( $codes as $c ) {
			WP_CLI::log( '  ' . $c );
		}
		WP_CLI::log( '' );
		WP_CLI::success( sprintf( '%d recovery codes issued for %s. They are not stored in readable form and cannot be shown again.', count( $codes ), $user->user_login ) );
	}

	/** Resolve an ID / login / email to a user, or stop. */
	private function get_user( $ref ): WP_User {
		$user = get_user_by( 'id', (int) $ref );
		if ( ! $user ) {
			$user = get_user_by( 'login', (string) $ref );
		}
		if ( ! $user ) {
			$user = get_user_by( 'email', (string) $ref );
		}
		if ( ! $user ) {
			WP_CLI::error( sprintf( 'No such user: %s', $ref ) );
		}
		return $user;
	}
}

WP_CLI::add_command( 'secwp 2fa', 'SecurityWP_CLI_2FA' );

/**
 * Rotate and inspect the salt behind the masked ?ver= on CSS and JS URLs.
 *
 * The masked token is derived from the version an asset *declares*, so an
 * enqueue with a hard-coded version string keeps the same URL after the file
 * behind it changes and returning visitors keep the copy in their browser
 * cache. Rotating changes every masked URL at once and forces a clean
 * re-fetch — the reason this is a command and not just a button is that it
 * belongs at the end of a deploy script, after the step that syncs files.
 */
class SecurityWP_CLI_Asset_Salt {

	/**
	 * Rotate the salt, changing the version token on every CSS and JS URL.
	 *
	 * Every visitor re-downloads all CSS and JS once after this. Fine after a
	 * deploy, wasteful on a schedule.
	 *
	 * Runs without a confirmation prompt so it can sit unattended in a deploy
	 * script — it is a cache cost, not a destructive change, and a prompt in the
	 * one place this command is meant to live would just be an obstacle.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print only the new token.
	 *
	 * ## EXAMPLES
	 *
	 *     # At the end of a deploy, after files are synced
	 *     wp secwp asset-salt rotate
	 *
	 * @when after_wp_load
	 */
	public function rotate( $args, $assoc ) {
		$porcelain = (bool) WP_CLI\Utils\get_flag_value( $assoc, 'porcelain', false );
		$entry     = SecurityWP_Tweaks::rotate_asset_version_salt( 'wp-cli' );

		if ( $porcelain ) {
			WP_CLI::line( (string) $entry['fingerprint'] );
			return;
		}

		$active = SecurityWP_Tweaks::asset_version_mask_active();

		WP_CLI::success(
			sprintf(
				'Asset cache token rotated: %s → %s.%s',
				(string) $entry['previous'],
				(string) $entry['fingerprint'],
				$active ? ' Every CSS and JS URL has changed.' : ''
			)
		);

		// Silence here would be the worst outcome: the command reports success
		// while nothing about what visitors receive has actually changed.
		if ( ! $active ) {
			WP_CLI::warning( $this->inactive_reason() );
			return;
		}

		WP_CLI::log( 'Visitors will re-download all CSS and JS once. Use this after a deploy, not on a schedule.' );
		WP_CLI::log( 'If the site is behind a page cache, purge it too — cached HTML still carries the old asset URLs.' );
	}

	/**
	 * Show the current token and when it was last rotated.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. json also includes the rotation history.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * @when after_wp_load
	 */
	public function show( $args, $assoc ) {
		$format = (string) WP_CLI\Utils\get_flag_value( $assoc, 'format', 'table' );
		$active = SecurityWP_Tweaks::asset_version_mask_active();
		$last   = SecurityWP_Tweaks::asset_version_last_rotation();

		$data = array(
			'token'            => SecurityWP_Tweaks::asset_version_fingerprint(),
			'masking_active'   => $active ? 'yes' : 'no',
			'last_rotated'     => $last ? gmdate( 'Y-m-d H:i:s', (int) $last['time'] ) . ' UTC' : 'never',
			'last_rotated_by'  => $last ? ( '' !== (string) $last['user_login'] ? (string) $last['user_login'] : 'no logged-in user' ) : '',
			'last_rotated_via' => $last ? (string) $last['via'] : '',
			'rotations'        => count( SecurityWP_Tweaks::asset_version_rotations() ),
		);

		if ( 'json' === $format ) {
			$data['history'] = SecurityWP_Tweaks::asset_version_rotations();
			WP_CLI::line( (string) wp_json_encode( $data ) );
			return;
		}

		$rows = array();
		foreach ( $data as $k => $v ) {
			$rows[] = array( 'field' => $k, 'value' => (string) $v );
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'field', 'value' ) );

		if ( ! $active ) {
			WP_CLI::warning( $this->inactive_reason() );
		}
	}

	/** Why a rotation would not reach visitors right now. */
	private function inactive_reason(): string {
		if ( SecurityWP_Features::is_on( 'remove_asset_version' ) ) {
			return '"Remove version on static assets" is on, so asset URLs carry no version at all — there is no token for visitors to see.';
		}
		return '"Mask version on static assets" is off, so the real ?ver= is being sent — rotating has no visible effect until masking is on.';
	}
}

WP_CLI::add_command( 'secwp asset-salt', 'SecurityWP_CLI_Asset_Salt' );
