<?php
/**
 * INI Protector → File integrity admin page + dashboard notice.
 *
 * Renders SecurityWP_Integrity::get_results() — the same snapshot the platform
 * pulls — so there is one source of truth. Mirrors SecurityWP_Vuln_Admin and
 * reuses the shared .secwp-* card/badge CSS.
 *
 * The page is also where the two things that quietly defeat this feature get
 * surfaced: no alert channel configured (a monitor nobody hears), and WP-Cron
 * disabled (a schedule that never fires). Both print the exact fix.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Integrity_Admin {

	const SLUG = 'ini-protector-integrity';
	const CAP  = 'manage_options';

	private $page_hook = '';

	public function __construct() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_menu', array( $this, 'menu' ), 20 );
		add_action( 'admin_post_secwp_integrity_action', array( $this, 'handle_action' ) );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== $this->page_hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-integrity-admin-css', SECWP_PLUGIN_URL . 'assets/integrity-admin.css', array(), SECWP_VERSION );
	}

	public function menu(): void {
		$title      = __( 'File integrity', 'ini-protector' );
		$menu_title = $title;

		if ( SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			$total = (int) ( SecurityWP_Integrity::get_results()['counts']['total'] ?? 0 );
			if ( $total > 0 ) {
				$menu_title .= ' <span class="awaiting-mod count-' . $total . '"><span class="pending-count">' . $total . '</span></span>';
			}
		}

		$this->page_hook = add_submenu_page( 'ini-protector', $title, $menu_title, self::CAP, self::SLUG, array( $this, 'render' ) );
	}

	/* --------------------------------------------------------------------- */
	/* Actions                                                                */
	/* --------------------------------------------------------------------- */

	public function handle_action(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'ini-protector' ) );
		}
		check_admin_referer( 'secwp_integrity_action' );

		// "Scan"/"Baseline" are POST forms; "Dismiss" is a nonce'd GET link — accept either.
		$do  = isset( $_REQUEST['do'] ) ? sanitize_key( wp_unslash( $_REQUEST['do'] ) ) : '';
		$msg = 'invalid';

		if ( in_array( $do, array( 'scan', 'baseline', 'reset' ), true ) && ! SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			$this->redirect( 'disabled' );
		}

		switch ( $do ) {
			case 'scan':
				$this->raise_limits();
				$report = ( new SecurityWP_Integrity() )->run_scan();
				$msg    = ( ( $report['counts']['total'] ?? 0 ) > 0 ) ? 'changes' : 'clean';
				break;

			case 'baseline':
				$this->raise_limits();
				( new SecurityWP_Integrity() )->run_scan( array( 'baseline' => true ) );
				$msg = 'rebaselined';
				break;

			case 'reset':
				SecurityWP_Integrity::reset_baseline();
				$msg = 'reset';
				break;

			case 'dismiss':
				update_option( SecurityWP_Integrity::OPT_DISMISS, SecurityWP_Integrity::changes_digest(), false );
				$msg = 'dismissed';
				break;
		}

		$this->redirect( $msg );
	}

	private function redirect( string $msg ): void {
		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'secwp_msg' => $msg ), admin_url( 'admin.php' ) ) );
		exit;
	}

	/** A full-tree hash can outlive the default web limits; ask for more where allowed. */
	private function raise_limits(): void {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		wp_raise_memory_limit( 'admin' );
	}

	/* --------------------------------------------------------------------- */
	/* Dashboard notice                                                       */
	/* --------------------------------------------------------------------- */

	public function notice(): void {
		if ( ! current_user_can( self::CAP ) || ! SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ( 'dashboard' !== $screen->id && false === strpos( $screen->id, 'ini-protector' ) ) ) {
			return;
		}
		if ( $screen && false !== strpos( (string) $screen->id, self::SLUG ) ) {
			return;
		}

		$r     = SecurityWP_Integrity::get_results();
		$total = (int) ( $r['counts']['total'] ?? 0 );
		if ( $total < 1 || SecurityWP_Integrity::is_dismissed() ) {
			return;
		}

		$critical = (int) ( $r['counts']['critical'] ?? 0 );
		$text     = sprintf(
			/* translators: 1: new, 2: modified, 3: deleted. */
			__( 'File integrity monitoring found %1$d new, %2$d modified and %3$d deleted code file(s) since the last check.', 'ini-protector' ),
			(int) $r['counts']['new'],
			(int) $r['counts']['modified'],
			(int) $r['counts']['deleted']
		);
		if ( $critical > 0 ) {
			$text .= ' ' . sprintf(
				/* translators: %d: number of changes in critical locations. */
				_n( '%d of them is in a critical location (core, wp-config, mu-plugins, .htaccess).', '%d of them are in critical locations (core, wp-config, mu-plugins, .htaccess).', $critical, 'ini-protector' ),
				$critical
			);
		}

		echo '<div class="notice notice-error">';
		echo '<p><strong>' . esc_html__( 'INI Protector', 'ini-protector' ) . '</strong> — ' . esc_html( $text ) . '</p>';
		echo '<p>';
		printf(
			'<a class="button button-primary" href="%s">%s</a> ',
			esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ),
			esc_html__( 'Review changed files', 'ini-protector' )
		);
		printf(
			'<a class="button" href="%s">%s</a>',
			esc_url(
				wp_nonce_url(
					add_query_arg( array( 'action' => 'secwp_integrity_action', 'do' => 'dismiss' ), admin_url( 'admin-post.php' ) ),
					'secwp_integrity_action'
				)
			),
			esc_html__( 'Dismiss until something changes', 'ini-protector' )
		);
		echo '</p></div>';
	}

	/* --------------------------------------------------------------------- */
	/* Render                                                                 */
	/* --------------------------------------------------------------------- */

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-media-code"></span> ' . esc_html__( 'File integrity', 'ini-protector' ) . '</h1>';
		$this->page_notice();

		if ( ! SecurityWP_Features::is_on( SecurityWP_Integrity::FEATURE ) ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body">';
			printf(
				'<p>%s</p><p><a class="button button-primary" href="%s">%s</a></p>',
				esc_html__( 'File integrity monitoring is off. Turn on “File integrity monitoring” to hash every code file, store a baseline, and be told by email the moment a file is added, changed, or deleted.', 'ini-protector' ),
				esc_url( admin_url( 'admin.php?page=ini-protector' ) ),
				esc_html__( 'Go to settings', 'ini-protector' )
			);
			echo '</div></div></div>';
			return;
		}

		$results = SecurityWP_Integrity::get_results();

		$this->render_header( $results );
		$this->render_warnings( $results );
		$this->render_changes( $results );
		$this->render_history();
		$this->render_scheduling();

		echo '</div>';
	}

	private function render_header( array $r ): void {
		$counts   = $r['counts'];
		$baseline = SecurityWP_Integrity::baseline_count();

		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body secwp-ip-head">';

		echo '<div class="secwp-ip-id">';
		if ( (int) $counts['total'] > 0 ) {
			foreach ( array( 'new' => 'secwp-badge-high', 'modified' => 'secwp-badge-susp', 'deleted' => 'secwp-badge-medium' ) as $state => $class ) {
				if ( (int) $counts[ $state ] > 0 ) {
					printf(
						'<span class="secwp-badge %s">%s %d</span> ',
						esc_attr( $class ),
						esc_html( ucfirst( $state ) ),
						(int) $counts[ $state ]
					);
				}
			}
		} elseif ( 'never' === $r['status'] ) {
			echo '<span class="secwp-badge secwp-badge-medium">' . esc_html__( 'No baseline yet', 'ini-protector' ) . '</span>';
		} else {
			echo '<span class="secwp-badge secwp-badge-clean">' . esc_html__( 'No changes', 'ini-protector' ) . '</span>';
		}
		echo '</div>';

		$when = $r['scanned_at']
			? sprintf(
				/* translators: 1: human time diff, 2: files hashed, 3: seconds, 4: baseline size. */
				__( 'Last check %1$s ago · %2$s files hashed in %3$ss · baseline holds %4$s files', 'ini-protector' ),
				human_time_diff( (int) $r['scanned_at'], time() ),
				number_format_i18n( (int) ( $counts['files'] ?? 0 ) ),
				(float) $r['duration'],
				number_format_i18n( $baseline )
			)
			: __( 'Never checked. Run the first scan to establish the baseline.', 'ini-protector' );
		echo '<div class="secwp-ip-sub">' . esc_html( $when ) . '</div>';

		echo '<div class="secwp-ip-action">';
		$this->action_button( 'scan', __( 'Scan now', 'ini-protector' ), 'button-primary' );
		echo '</div>';

		echo '</div></div>';
	}

	/** The things that silently defeat this feature, stated plainly with the fix. */
	private function render_warnings( array $r ): void {
		$email   = (bool) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'email_alert', true );
		$webhook = trim( (string) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'webhook_url', '' ) );

		if ( ! $email && '' === $webhook ) {
			$this->warn(
				'dashicons-warning',
				__( 'No alert channel is configured', 'ini-protector' ),
				__( 'Changes are recorded on this server and nowhere else. An attacker who can write to the filesystem and the database can rewrite that record. Turn on the email alert (or set a webhook) in the INI Protector settings so every change leaves the server the moment it is found.', 'ini-protector' )
			);
		}

		if ( 'alert_failed' === ( $r['status'] ?? '' ) ) {
			$this->warn(
				'dashicons-email-alt',
				__( 'The last alert could not be delivered', 'ini-protector' ),
				__( 'Every configured channel failed, so the baseline was deliberately NOT updated — the same changes will be reported again on the next run rather than being silently accepted. Check that this site can send mail (or that the webhook URL is reachable).', 'ini-protector' )
			);
		}

		if ( ! empty( $r['files_truncated'] ) ) {
			$this->warn(
				'dashicons-warning',
				__( 'The file limit was reached', 'ini-protector' ),
				__( 'Part of the tree was not hashed, so changes there would not be seen. Raise “Maximum files” or exclude a directory that does not hold code.', 'ini-protector' )
			);
		}

		if ( ! empty( $r['unreadable'] ) ) {
			$this->warn(
				'dashicons-lock',
				sprintf(
					/* translators: %d: number of unreadable files. */
					_n( '%d file could not be read', '%d files could not be read', count( (array) $r['unreadable'] ), 'ini-protector' ),
					count( (array) $r['unreadable'] )
				),
				esc_html__( 'These are left in the baseline unchanged (they are not reported as deleted). Usually a permissions issue: ', 'ini-protector' ) . esc_html( implode( ', ', array_slice( (array) $r['unreadable'], 0, 10 ) ) )
			);
		}
	}

	private function warn( string $icon, string $title, string $body ): void {
		echo '<div class="secwp-card secwp-card-wide secwp-warn">';
		echo '<div class="secwp-card-body">';
		printf(
			'<p class="secwp-warn-title"><span class="dashicons %s"></span> <strong>%s</strong></p><p class="secwp-warn-body">%s</p>',
			esc_attr( $icon ),
			esc_html( $title ),
			wp_kses_post( $body )
		);
		echo '</div></div>';
	}

	private function render_changes( array $r ): void {
		$changes = (array) $r['changes'];

		echo '<div class="secwp-card secwp-card-wide">';
		echo '<div class="secwp-card-head"><span class="dashicons dashicons-media-text"></span><h2>' . esc_html__( 'Changes found in the last check', 'ini-protector' ) . '</h2></div>';
		echo '<div class="secwp-card-body">';

		if ( ! $changes ) {
			echo '<p class="secwp-empty">';
			if ( 'never' === $r['status'] ) {
				esc_html_e( 'No scan has run yet. The first scan records a baseline — it does not report anything.', 'ini-protector' );
			} elseif ( 'baseline' === $r['status'] || 'rebaselined' === $r['status'] ) {
				esc_html_e( 'Baseline recorded. From the next check onwards, any new, modified, or deleted code file is reported.', 'ini-protector' );
			} else {
				esc_html_e( 'No code file has been added, changed, or deleted since the last check.', 'ini-protector' );
			}
			echo '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'State', 'ini-protector' ), __( 'File', 'ini-protector' ), __( 'Size', 'ini-protector' ), __( 'Modified', 'ini-protector' ), __( 'SHA-256', 'ini-protector' ) ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';

			foreach ( $changes as $c ) {
				$state = (string) ( $c['state'] ?? '' );
				echo '<tr>';
				printf(
					'<td><span class="secwp-badge %s">%s</span></td>',
					esc_attr( $this->state_class( $state ) ),
					esc_html( ucfirst( $state ) )
				);

				echo '<td><code>' . esc_html( (string) ( $c['path'] ?? '' ) ) . '</code>';
				if ( ! empty( $c['critical'] ) ) {
					echo ' <span class="secwp-badge secwp-badge-high">' . esc_html__( 'critical location', 'ini-protector' ) . '</span>';
				}
				if ( ! empty( $c['timestomp'] ) ) {
					echo '<div class="secwp-ua">' . esc_html__( 'Content changed without the timestamp moving — self-rewriting file or a forged mtime.', 'ini-protector' ) . '</div>';
				}
				echo '</td>';

				printf( '<td>%s</td>', 'deleted' === $state ? '&mdash;' : esc_html( number_format_i18n( (int) ( $c['size'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', 'deleted' === $state ? '&mdash;' : esc_html( wp_date( 'Y-m-d H:i', (int) ( $c['mtime'] ?? 0 ) ) ) );

				$hash = (string) ( $c['hash'] ?? '' );
				printf( '<td><code>%s</code></td>', esc_html( '' === $hash ? '—' : substr( $hash, 0, 16 ) . '…' ) );
				echo '</tr>';
			}
			echo '</tbody></table>';

			if ( ! empty( $r['changes_truncated'] ) ) {
				echo '<p class="secwp-seen">' . esc_html__( 'Only the first 500 changes are stored. A change set this large is usually an update or a restore — re-baseline once you have confirmed it.', 'ini-protector' ) . '</p>';
			}
		}

		echo '<p class="secwp-actions">';
		$this->action_button( 'baseline', __( 'Accept current state as the baseline', 'ini-protector' ), '', __( 'This marks every file on disk right now as known-good. Only do this once you have confirmed the changes are yours.', 'ini-protector' ) );
		echo ' ';
		$this->action_button( 'reset', __( 'Clear the baseline', 'ini-protector' ), '', __( 'Deletes the stored baseline. The next scan records a fresh one and reports nothing.', 'ini-protector' ) );
		echo '</p>';

		if ( ! empty( $r['state_digest'] ) ) {
			printf(
				'<p class="secwp-seen">%s <code>%s</code>%s</p>',
				esc_html__( 'State digest of this baseline:', 'ini-protector' ),
				esc_html( (string) $r['state_digest'] ),
				esc_html( sprintf( /* translators: %d: report number. */ __( ' (report #%d)', 'ini-protector' ), (int) $r['seq'] ) )
			);
		}

		echo '</div></div>';
	}

	private function render_history(): void {
		$history = SecurityWP_Integrity::history();
		if ( ! $history ) {
			return;
		}

		echo '<div class="secwp-card secwp-card-wide">';
		echo '<div class="secwp-card-head"><span class="dashicons dashicons-backup"></span><h2>' . esc_html__( 'Recent change history', 'ini-protector' ) . '</h2></div>';
		echo '<div class="secwp-card-body">';
		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'When', 'ini-protector' ), __( 'Report', 'ini-protector' ), __( 'State', 'ini-protector' ), __( 'File', 'ini-protector' ) ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( array_slice( $history, 0, 100 ) as $h ) {
			$state = (string) ( $h['state'] ?? '' );
			echo '<tr>';
			printf( '<td>%s</td>', esc_html( wp_date( 'Y-m-d H:i', (int) ( $h['at'] ?? 0 ) ) ) );
			printf( '<td>#%d</td>', (int) ( $h['seq'] ?? 0 ) );
			printf( '<td><span class="secwp-badge %s">%s</span></td>', esc_attr( $this->state_class( $state ) ), esc_html( ucfirst( $state ) ) );
			printf(
				'<td><code>%s</code>%s</td>',
				esc_html( (string) ( $h['path'] ?? '' ) ),
				! empty( $h['critical'] ) ? ' <span class="secwp-badge secwp-badge-high">' . esc_html__( 'critical', 'ini-protector' ) . '</span>' : ''
			);
			echo '</tr>';
		}
		echo '</tbody></table></div></div>';
	}

	/** Scheduling status + the exact system-cron line for sites with WP-Cron disabled. */
	private function render_scheduling(): void {
		$freq     = SecurityWP_Integrity::frequency();
		$next     = wp_next_scheduled( SecurityWP_Integrity::HOOK );
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		echo '<div class="secwp-card secwp-card-wide">';
		echo '<div class="secwp-card-head"><span class="dashicons dashicons-clock"></span><h2>' . esc_html__( 'Scheduling', 'ini-protector' ) . '</h2></div>';
		echo '<div class="secwp-card-body">';

		if ( 'off' === $freq ) {
			echo '<p>' . esc_html__( 'Automatic checks are off — the scan only runs when you start it here or from WP-CLI.', 'ini-protector' ) . '</p>';
		} else {
			printf(
				'<p>%s</p>',
				esc_html(
					$next
						? sprintf(
							/* translators: 1: recurrence, 2: next run time. */
							__( 'Scheduled %1$s. Next run: %2$s.', 'ini-protector' ),
							$freq,
							wp_date( 'Y-m-d H:i', (int) $next )
						)
						: sprintf( /* translators: %s: recurrence. */ __( 'Scheduled %s — no event is queued yet.', 'ini-protector' ), $freq )
				)
			);
		}

		if ( $disabled ) {
			echo '<p class="secwp-warn-body"><strong>' . esc_html__( 'WP-Cron is disabled on this site (DISABLE_WP_CRON).', 'ini-protector' ) . '</strong> ';
			esc_html_e( 'The schedule above will not fire on its own. Run the scan from system cron instead — the recommended setup anyway, because it does not depend on a visitor hitting the site:', 'ini-protector' );
			echo '</p>';
		} else {
			echo '<p>' . esc_html__( 'You can also run the scan from system cron, which does not depend on site traffic:', 'ini-protector' ) . '</p>';
		}

		$path = defined( 'ABSPATH' ) ? untrailingslashit( ABSPATH ) : '';
		printf(
			'<pre class="secwp-pre">%s</pre>',
			esc_html( sprintf( '17 * * * * cd %s && wp secwp integrity scan --quiet', $path ) )
		);
		echo '<p class="secwp-seen">' . esc_html__( 'The command exits with status 1 when changes are found and 0 when clean, so a monitoring system can act on it directly. Add --format=json for machine-readable output.', 'ini-protector' ) . '</p>';

		echo '</div></div>';
	}

	/* --------------------------------------------------------------------- */
	/* Helpers                                                                */
	/* --------------------------------------------------------------------- */

	private function action_button( string $do, string $label, string $class = '', string $confirm = '' ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin:0;"<?php echo '' !== $confirm ? ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ');"' : ''; ?>>
			<input type="hidden" name="action" value="secwp_integrity_action" />
			<input type="hidden" name="do" value="<?php echo esc_attr( $do ); ?>" />
			<?php wp_nonce_field( 'secwp_integrity_action' ); ?>
			<button type="submit" class="button <?php echo esc_attr( $class ); ?>"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	private function state_class( string $state ): string {
		switch ( $state ) {
			case 'new':
				return 'secwp-badge-high';
			case 'modified':
				return 'secwp-badge-susp';
			case 'deleted':
				return 'secwp-badge-medium';
			default:
				return 'secwp-badge-clean';
		}
	}

	private function page_notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'clean'       => array( 'success', __( 'Scan complete — no changes.', 'ini-protector' ) ),
			'changes'     => array( 'warning', __( 'Scan complete — changes were found. Review them below.', 'ini-protector' ) ),
			'rebaselined' => array( 'success', __( 'Baseline updated to the current state of the site.', 'ini-protector' ) ),
			'reset'       => array( 'success', __( 'Baseline cleared. The next scan records a fresh one.', 'ini-protector' ) ),
			'dismissed'   => array( 'success', __( 'Alert dismissed until the change set changes.', 'ini-protector' ) ),
			'disabled'    => array( 'error', __( 'Turn on file integrity monitoring first.', 'ini-protector' ) ),
			'invalid'     => array( 'error', __( 'Unknown action.', 'ini-protector' ) ),
		);
		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
	}

	/** Shared .secwp-* look, defined here so the page stands alone. */

}
