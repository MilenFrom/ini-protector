<?php
/**
 * INI Protector → Utilities admin page.
 *
 * Maintenance actions that are not themselves hardening — they exist because a
 * hardening feature has an operational cost somewhere else. Deliberately its own
 * page rather than a card on the settings screen: nothing here protects the site,
 * and filing it under a security heading would misrepresent what it does.
 *
 * Includes traffic-history cleanup and rotating the salt behind "Mask version on static
 * assets". The masked ?ver= token is derived from the version an asset
 * *declares*, so code that hard-codes a version string ('1.3' forever) keeps the
 * same URL after the file behind it changes, and returning visitors keep serving
 * the old copy out of their browser cache. Rotating changes every masked URL at
 * once and forces a clean re-fetch.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Utilities_Admin {

	const SLUG = 'ini-protector-utilities';
	const CAP  = 'manage_options';

	private $page_hook = '';

	public function __construct() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_menu', array( $this, 'menu' ), 30 );
		add_action( 'admin_post_secwp_utilities_action', array( $this, 'handle_action' ) );
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== $this->page_hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-utilities-admin-css', SECWP_PLUGIN_URL . 'assets/utilities-admin.css', array(), SECWP_VERSION );
	}

	public function menu(): void {
		$this->page_hook = add_submenu_page(
			'ini-protector',
			__( 'Utilities', 'ini-protector' ),
			__( 'Utilities', 'ini-protector' ),
			self::CAP,
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/* --------------------------------------------------------------------- */
	/* Actions                                                                */
	/* --------------------------------------------------------------------- */

	public function handle_action(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'ini-protector' ) );
		}
		check_admin_referer( 'secwp_utilities_action' );

		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$msg = 'invalid';

		if ( 'rotate_asset_salt' === $do ) {
			SecurityWP_Tweaks::rotate_asset_version_salt( 'admin' );
			// Say plainly when the rotation cannot be seen yet, rather than
			// reporting success for something the visitor will never receive.
			$msg = SecurityWP_Tweaks::asset_version_mask_active() ? 'rotated' : 'rotated_inactive';
		}

		if ( 'clear_traffic' === $do ) {
			$msg = SecurityWP_Traffic_Log::clear() ? 'traffic_cleared' : 'traffic_clear_failed';
		}

		$args = array();
		if ( 'settings_export' === $do ) {
			$this->send_export( ! empty( $_POST['include_secrets'] ) ); // Exits.
		}
		if ( 'settings_preview' === $do ) {
			$msg = $this->receive_upload();
		}
		if ( 'settings_apply' === $do ) {
			$parsed = SecurityWP_Settings_Transfer::stashed();
			SecurityWP_Settings_Transfer::forget();
			if ( $parsed ) {
				$args['secwp_count'] = count( SecurityWP_Settings_Transfer::apply( $parsed, 'admin' ) );
				$msg                 = 'settings_imported';
			} else {
				$msg = 'settings_expired';
			}
		}
		if ( 'settings_cancel' === $do ) {
			SecurityWP_Settings_Transfer::forget();
			$msg = 'settings_cancelled';
		}
		if ( 'settings_undo' === $do ) {
			$msg = SecurityWP_Settings_Transfer::undo( 'admin' ) ? 'settings_undone' : 'settings_no_undo';
		}

		$args = array_merge( array( 'page' => self::SLUG, 'secwp_msg' => $msg ), $args );
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) . ( 0 === strpos( $do, 'settings_' ) ? '#secwp-settings-transfer' : '' ) );
		exit;
	}

	/** Stream the settings file as a download. */
	private function send_export( bool $include_secrets ): void {
		do_action(
			'secwp_platform_event',
			'settings_exported',
			$include_secrets ? 'Settings exported, including secrets' : 'Settings exported (secrets left out)',
			array( 'user_id' => get_current_user_id(), 'secrets' => $include_secrets )
		);
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . SecurityWP_Settings_Transfer::filename() . '"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo SecurityWP_Settings_Transfer::export_json( $include_secrets ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A JSON download, not HTML.
		exit;
	}

	/** Read and check an uploaded settings file; park it for the preview. Returns a message key. */
	private function receive_upload(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Only tmp_name/size/error are read; the contents are validated by parse().
		$file = isset( $_FILES['settings_file'] ) && is_array( $_FILES['settings_file'] ) ? $_FILES['settings_file'] : array();
		if ( empty( $file['tmp_name'] ) || UPLOAD_ERR_OK !== (int) ( $file['error'] ?? UPLOAD_ERR_NO_FILE ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
			return 'settings_no_file';
		}
		if ( (int) $file['size'] > SecurityWP_Settings_Transfer::MAX_BYTES ) {
			return 'settings_bad_file';
		}
		$json   = (string) file_get_contents( $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- PHP's own upload temp file.
		$parsed = SecurityWP_Settings_Transfer::parse( $json );
		if ( is_wp_error( $parsed ) ) {
			return 'newer_schema' === $parsed->get_error_code() ? 'settings_newer' : 'settings_bad_file';
		}
		SecurityWP_Settings_Transfer::stash( $parsed );
		return 'settings_preview';
	}

	/* --------------------------------------------------------------------- */
	/* Render                                                                 */
	/* --------------------------------------------------------------------- */

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-admin-tools"></span> ' . esc_html__( 'Utilities', 'ini-protector' ) . '</h1>';
		printf(
			'<p class="secwp-muted">%s</p>',
			esc_html__( 'Maintenance actions for asset caching, traffic history and settings.', 'ini-protector' )
		);
		$this->page_notice();
		$this->render_asset_salt();
		$this->render_traffic_cleanup();
		$this->render_settings_transfer();
		echo '</div>';
	}

	private function render_settings_transfer(): void {
		$pending = SecurityWP_Settings_Transfer::stashed();
		$action  = esc_url( admin_url( 'admin-post.php' ) );
		echo '<div class="secwp-card secwp-card-wide" id="secwp-settings-transfer">';
		echo '<div class="secwp-card-head"><span class="dashicons dashicons-migrate"></span><h2>' . esc_html__( 'Export / import settings', 'ini-protector' ) . '</h2></div>';
		echo '<div class="secwp-card-body">';

		if ( $pending ) {
			$this->render_import_preview( $pending, $action );
			echo '</div></div>';
			return;
		}

		printf( '<p class="secwp-lead">%s</p>', esc_html__( 'Copy this site’s INI Protector configuration to another site, or keep it as a backup.', 'ini-protector' ) );
		printf( '<p class="secwp-why">%s</p>', esc_html__( 'The file holds which protections are on and how each is configured. It never holds traffic history, the file-integrity baseline, scan results, IP blocks, or anyone’s two-factor secrets — those belong to one site.', 'ini-protector' ) );

		// Export.
		echo '<h3 class="secwp-subhead">' . esc_html__( 'Export', 'ini-protector' ) . '</h3>';
		printf( '<form method="post" action="%s" class="secwp-actions">', $action ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		echo '<input type="hidden" name="action" value="secwp_utilities_action" /><input type="hidden" name="do" value="settings_export" />';
		wp_nonce_field( 'secwp_utilities_action' );
		printf(
			'<p><label><input type="checkbox" name="include_secrets" value="1" /> %s</label><br /><span class="secwp-hint-inline">%s</span></p>',
			esc_html__( 'Include secrets (site password, webhook secret)', 'ini-protector' ),
			esc_html__( 'They are stored in the file in plain text. Leave this off unless the file goes straight to another site you control.', 'ini-protector' )
		);
		printf( '<button type="submit" class="button">%s</button>', esc_html__( 'Download settings file', 'ini-protector' ) );
		echo '</form>';

		// Import.
		echo '<h3 class="secwp-subhead">' . esc_html__( 'Import', 'ini-protector' ) . '</h3>';
		printf( '<p class="secwp-why">%s</p>', esc_html__( 'You will see every change before anything is applied, and the current settings are kept so the import can be undone. Settings the file does not contain are left as they are; secrets are never cleared.', 'ini-protector' ) );
		printf( '<form method="post" action="%s" enctype="multipart/form-data" class="secwp-actions">', $action ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		echo '<input type="hidden" name="action" value="secwp_utilities_action" /><input type="hidden" name="do" value="settings_preview" />';
		wp_nonce_field( 'secwp_utilities_action' );
		echo '<p><input type="file" name="settings_file" accept=".json,application/json" required /></p>';
		printf( '<button type="submit" class="button">%s</button>', esc_html__( 'Preview import', 'ini-protector' ) );
		echo '</form>';

		$undo = SecurityWP_Settings_Transfer::undo_point();
		if ( $undo ) {
			echo '<h3 class="secwp-subhead">' . esc_html__( 'Undo', 'ini-protector' ) . '</h3>';
			$user = get_userdata( (int) $undo['user'] );
			printf(
				'<p class="secwp-why">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: date and time, 2: user name, 3: where the import came from. */
						__( 'Last import: %1$s by %2$s (%3$s). Undo puts every setting back as it was just before it.', 'ini-protector' ),
						$this->local_time( (int) $undo['time'] ),
						$user ? $user->user_login : __( 'no logged-in user', 'ini-protector' ),
						$this->source( (string) ( $undo['via'] ?? '' ) )
					)
				)
			);
			printf( '<form method="post" action="%s" class="secwp-actions">', $action ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
			echo '<input type="hidden" name="action" value="secwp_utilities_action" /><input type="hidden" name="do" value="settings_undo" />';
			wp_nonce_field( 'secwp_utilities_action' );
			printf(
				'<button type="submit" class="button" onclick="return confirm(%s);">%s</button>',
				esc_attr( (string) wp_json_encode( __( 'Put all INI Protector settings back as they were before the last import?', 'ini-protector' ) ) ),
				esc_html__( 'Undo last import', 'ini-protector' )
			);
			echo '</form>';
		}

		printf(
			'<p class="secwp-hint">%s <code>wp inipr settings export</code> · <code>wp inipr settings import &lt;file&gt;</code> · <code>wp inipr settings undo</code></p>',
			esc_html__( 'From the command line:', 'ini-protector' )
		);
		echo '</div></div>';
	}

	private function render_import_preview( array $parsed, string $action ): void {
		$rows = SecurityWP_Settings_Transfer::diff( $parsed );
		printf( '<p class="secwp-lead">%s</p>', esc_html__( 'Review the import. Nothing has changed yet.', 'ini-protector' ) );

		echo '<table class="secwp-kv"><tbody>';
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Exported from', 'ini-protector' ), esc_html( '' !== $parsed['site'] ? $parsed['site'] : __( 'unknown', 'ini-protector' ) ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Plugin version', 'ini-protector' ), esc_html( '' !== $parsed['plugin_version'] ? $parsed['plugin_version'] : __( 'unknown', 'ini-protector' ) ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Exported at', 'ini-protector' ), esc_html( '' !== $parsed['exported_at'] ? $parsed['exported_at'] : __( 'unknown', 'ini-protector' ) ) );
		printf(
			'<tr><th>%s</th><td>%s</td></tr>',
			esc_html__( 'Secrets', 'ini-protector' ),
			esc_html( $parsed['secrets_included'] ? __( 'Included — this site’s secrets will be replaced where the file has one.', 'ini-protector' ) : __( 'Not included — this site keeps its own.', 'ini-protector' ) )
		);
		echo '</tbody></table>';

		if ( $parsed['ignored'] ) {
			printf(
				'<div class="secwp-warn-box"><span class="dashicons dashicons-warning"></span> %s <code>%s</code></div>',
				esc_html__( 'Not known to this version, so they will be skipped:', 'ini-protector' ),
				esc_html( implode( ', ', $parsed['ignored'] ) )
			);
		}

		if ( ! $rows ) {
			printf( '<p class="secwp-why">%s</p>', esc_html__( 'This file matches the current settings — there is nothing to change.', 'ini-protector' ) );
		} else {
			if ( array_filter( wp_list_pluck( $rows, 'sensitive' ) ) ) {
				printf(
					'<div class="secwp-cost"><span class="dashicons dashicons-info-outline"></span> <strong>%s</strong> %s</div>',
					esc_html__( 'Check the highlighted rows.', 'ini-protector' ),
					esc_html__( 'They change how people sign in or who is let in or blocked. If the login address changes, the new one is shown after the import — note it before you sign out.', 'ini-protector' )
				);
			}
			echo '<table class="widefat striped secwp-import-diff"><thead><tr>';
			printf( '<th>%s</th><th>%s</th><th>%s</th><th>%s</th>', esc_html__( 'Protection', 'ini-protector' ), esc_html__( 'Setting', 'ini-protector' ), esc_html__( 'Now', 'ini-protector' ), esc_html__( 'After import', 'ini-protector' ) );
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				printf(
					'<tr%s><td>%s</td><td>%s</td><td>%s</td><td><strong>%s</strong></td></tr>',
					$row['sensitive'] ? ' class="secwp-sensitive"' : '',
					esc_html( $row['label'] ),
					esc_html( '' !== $row['field'] ? $row['field'] : __( 'Enabled', 'ini-protector' ) ),
					esc_html( $row['from'] ),
					esc_html( $row['to'] )
				);
			}
			echo '</tbody></table>';
		}

		printf( '<form method="post" action="%s" class="secwp-actions secwp-import-actions">', $action ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by the caller.
		echo '<input type="hidden" name="action" value="secwp_utilities_action" />';
		wp_nonce_field( 'secwp_utilities_action' );
		if ( $rows ) {
			printf(
				'<button type="submit" name="do" value="settings_apply" class="button button-primary">%s</button> ',
				esc_html( sprintf( /* translators: %d: number of settings. */ _n( 'Apply %d change', 'Apply %d changes', count( $rows ), 'ini-protector' ), count( $rows ) ) )
			);
		}
		printf( '<button type="submit" name="do" value="settings_cancel" class="button">%s</button>', esc_html__( 'Cancel', 'ini-protector' ) );
		echo '</form>';
	}

	private function render_traffic_cleanup(): void {
		?>
		<div class="secwp-card secwp-card-wide" id="secwp-clean-traffic">
			<div class="secwp-card-head"><span class="dashicons dashicons-trash"></span><h2><?php esc_html_e( 'Clean traffic table contents', 'ini-protector' ); ?></h2></div>
			<div class="secwp-card-body">
				<p class="secwp-lead"><?php esc_html_e( 'Permanently delete all recorded traffic history to free database space.', 'ini-protector' ); ?></p>
				<p class="secwp-why"><?php esc_html_e( 'This cannot be undone. Traffic reports and new automatic-block suggestions will start from fresh history. Existing IP blocks and settings are kept. New requests will continue to be recorded while the traffic monitor is enabled.', 'ini-protector' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secwp-actions">
					<input type="hidden" name="action" value="secwp_utilities_action" />
					<input type="hidden" name="do" value="clear_traffic" />
					<?php wp_nonce_field( 'secwp_utilities_action' ); ?>
					<button type="submit" class="button" onclick="return confirm(<?php echo esc_attr( (string) wp_json_encode( __( 'Permanently delete all traffic history? This cannot be undone. Existing IP blocks and settings will be kept.', 'ini-protector' ) ) ); ?>);"><?php esc_html_e( 'Clean traffic table', 'ini-protector' ); ?></button>
				</form>
			</div>
		</div>
		<?php
	}

	private function render_asset_salt(): void {
		$active = SecurityWP_Tweaks::asset_version_mask_active();
		$last   = SecurityWP_Tweaks::asset_version_last_rotation();

		echo '<div class="secwp-card secwp-card-wide">';
		echo '<div class="secwp-card-head"><span class="dashicons dashicons-update"></span><h2>' . esc_html__( 'Rotate asset cache token', 'ini-protector' ) . '</h2></div>';
		echo '<div class="secwp-card-body">';

		printf(
			'<p class="secwp-lead">%s</p>',
			esc_html__( 'Changes the version token on every CSS and JS URL. Use after a deploy if visitors are still seeing old styles or scripts.', 'ini-protector' )
		);

		printf(
			'<p class="secwp-why">%s</p>',
			esc_html__( 'Why this is needed: the masked token is derived from the version an asset declares, so a plugin that hard-codes a version string keeps the same URL even after its file changes — and a browser that has been here before keeps using its cached copy.', 'ini-protector' )
		);

		// The cost, stated before the button. Rotating occasionally is fine;
		// wiring it into a cron is not, and one line of copy is what stops that.
		echo '<div class="secwp-cost">';
		printf(
			'<span class="dashicons dashicons-info-outline"></span> <strong>%s</strong> %s',
			esc_html__( 'This has a cost.', 'ini-protector' ),
			esc_html__( 'Rotating invalidates every asset URL at once, so the next visit re-downloads all CSS and JS. That is fine occasionally and wasteful as a habit — reach for it after a deploy, not on a schedule.', 'ini-protector' )
		);
		echo '</div>';

		if ( ! $active ) {
			echo '<div class="secwp-warn-box">';
			printf(
				'<span class="dashicons dashicons-warning"></span> %s ',
				esc_html(
					SecurityWP_Features::is_on( 'remove_asset_version' )
						? __( '“Remove version on static assets” is on, so asset URLs carry no version at all and there is no token to rotate. Rotating now will have no visible effect.', 'ini-protector' )
						: __( '“Mask version on static assets” is off, so the real ?ver= is being sent and there is no token to rotate. Rotating now will have no visible effect.', 'ini-protector' )
				)
			);
			printf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'admin.php?page=ini-protector' ) ),
				esc_html__( 'Head cleanup settings', 'ini-protector' )
			);
			echo '</div>';
		}

		// Current identity + last rotation, so a deploy can be confirmed at a glance.
		echo '<table class="secwp-kv"><tbody>';
		printf(
			'<tr><th>%s</th><td><code>%s</code> <span class="secwp-hint-inline">%s</span></td></tr>',
			esc_html__( 'Current token', 'ini-protector' ),
			esc_html( SecurityWP_Tweaks::asset_version_fingerprint() ),
			esc_html__( '(identifies the salt in use — not the salt itself)', 'ini-protector' )
		);
		printf(
			'<tr><th>%s</th><td>%s</td></tr>',
			esc_html__( 'Last rotated', 'ini-protector' ),
			esc_html( $this->describe_rotation( $last ) )
		);
		echo '</tbody></table>';

		printf(
			'<form method="post" action="%s" class="secwp-actions">',
			esc_url( admin_url( 'admin-post.php' ) )
		);
		echo '<input type="hidden" name="action" value="secwp_utilities_action" />';
		echo '<input type="hidden" name="do" value="rotate_asset_salt" />';
		wp_nonce_field( 'secwp_utilities_action' );
		printf(
			'<button type="submit" class="button button-primary" onclick="return confirm(%s);">%s</button>',
			// Escaped for a JS string inside an HTML attribute.
			esc_attr( (string) wp_json_encode( __( 'Rotate the asset cache token? Every visitor will re-download all CSS and JS once.', 'ini-protector' ) ) ),
			esc_html__( 'Rotate asset cache token', 'ini-protector' )
		);
		echo '</form>';

		printf(
			'<p class="secwp-hint">%s <code>wp inipr asset-salt rotate</code> — %s</p>',
			esc_html__( 'From a deploy script:', 'ini-protector' ),
			esc_html__( 'run it after the step that syncs changed files. If the site is behind a page cache, purge that too: cached HTML still contains the old asset URLs.', 'ini-protector' )
		);

		$this->render_history();

		echo '</div></div>';
	}

	/** The audit trail — who rotated and when, so a cache-miss spike can be explained. */
	private function render_history(): void {
		$log = SecurityWP_Tweaks::asset_version_rotations();
		if ( count( $log ) < 2 ) {
			return; // The latest rotation is already stated above.
		}

		echo '<details class="secwp-history"><summary>' . esc_html__( 'Rotation history', 'ini-protector' ) . '</summary>';
		echo '<table class="widefat striped"><thead><tr>';
		printf( '<th>%s</th>', esc_html__( 'When', 'ini-protector' ) );
		printf( '<th>%s</th>', esc_html__( 'By', 'ini-protector' ) );
		printf( '<th>%s</th>', esc_html__( 'From', 'ini-protector' ) );
		printf( '<th>%s</th>', esc_html__( 'Token', 'ini-protector' ) );
		echo '</tr></thead><tbody>';
		foreach ( $log as $entry ) {
			printf(
				'<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code> → <code>%s</code></td></tr>',
				esc_html( $this->local_time( (int) $entry['time'] ) ),
				esc_html( $this->actor( $entry ) ),
				esc_html( $this->source( (string) ( $entry['via'] ?? '' ) ) ),
				esc_html( (string) ( $entry['previous'] ?? '' ) ),
				esc_html( (string) ( $entry['fingerprint'] ?? '' ) )
			);
		}
		echo '</tbody></table></details>';
	}

	/**
	 * "2 March 2026 at 14:05 by admin (from the admin)" — or a plain statement
	 * that this site has never rotated, which is the normal state.
	 *
	 * @param array<string,mixed>|null $entry
	 */
	private function describe_rotation( ?array $entry ): string {
		if ( ! $entry ) {
			return __( 'Never — the token has not been rotated since it was first generated.', 'ini-protector' );
		}
		return sprintf(
			/* translators: 1: date and time, 2: user name or "unknown", 3: where the rotation came from. */
			__( '%1$s by %2$s (%3$s)', 'ini-protector' ),
			$this->local_time( (int) $entry['time'] ),
			$this->actor( $entry ),
			$this->source( (string) ( $entry['via'] ?? '' ) )
		);
	}

	private function local_time( int $ts ): string {
		if ( $ts < 1 ) {
			return __( 'unknown', 'ini-protector' );
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
	}

	/** @param array<string,mixed> $entry */
	private function actor( array $entry ): string {
		$login = trim( (string) ( $entry['user_login'] ?? '' ) );
		if ( '' !== $login ) {
			return $login;
		}
		// WP-CLI and cron have no logged-in user; say so rather than inventing one.
		return __( 'no logged-in user', 'ini-protector' );
	}

	private function source( string $via ): string {
		$map = array(
			'admin'  => __( 'from the admin', 'ini-protector' ),
			'wp-cli' => __( 'from WP-CLI', 'ini-protector' ),
			'wpcli'  => __( 'from WP-CLI', 'ini-protector' ),
			'wp_cli' => __( 'from WP-CLI', 'ini-protector' ),
		);
		return $map[ $via ] ?? sprintf(
			/* translators: %s: the source label recorded with the rotation. */
			__( 'from %s', 'ini-protector' ),
			$via ? $via : __( 'an unknown source', 'ini-protector' )
		);
	}

	private function page_notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'rotated'          => array( 'notice-success', __( 'Asset cache token rotated. Every CSS and JS URL has changed; visitors will re-download them once.', 'ini-protector' ) ),
			'rotated_inactive' => array( 'notice-warning', __( 'Asset cache token rotated, but version masking is off — asset URLs are unchanged for visitors until you turn “Mask version on static assets” on.', 'ini-protector' ) ),
			'traffic_cleared' => array( 'notice-success', __( 'Traffic history cleared. Existing IP blocks and settings were kept.', 'ini-protector' ) ),
			'traffic_clear_failed' => array( 'notice-error', __( 'Traffic history could not be cleared. Please try again or check database permissions.', 'ini-protector' ) ),
			'invalid'          => array( 'notice-error', __( 'Unknown action.', 'ini-protector' ) ),
			'settings_preview'   => array( 'notice-info', __( 'Settings file read. Review the changes below, then apply or cancel.', 'ini-protector' ) ),
			'settings_no_file'   => array( 'notice-error', __( 'Choose a settings file to import.', 'ini-protector' ) ),
			'settings_bad_file'  => array( 'notice-error', __( 'That file is not an INI Protector settings export.', 'ini-protector' ) ),
			'settings_newer'     => array( 'notice-error', __( 'That file was exported by a newer version of INI Protector. Update this site first, then import it.', 'ini-protector' ) ),
			'settings_expired'   => array( 'notice-warning', __( 'The import preview expired before it was applied. Nothing was changed; upload the file again.', 'ini-protector' ) ),
			'settings_cancelled' => array( 'notice-info', __( 'Import cancelled. Nothing was changed.', 'ini-protector' ) ),
			'settings_undone'    => array( 'notice-success', __( 'Settings restored to how they were before the last import.', 'ini-protector' ) ),
			'settings_no_undo'   => array( 'notice-warning', __( 'There is no import to undo.', 'ini-protector' ) ),
		);
		if ( 'settings_imported' === $msg ) {
			$count = isset( $_GET['secwp_count'] ) ? absint( $_GET['secwp_count'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$map[ $msg ] = array(
				'notice-success',
				/* translators: %d: number of settings changed. */
				sprintf( _n( 'Settings imported: %d change applied. You can undo it below.', 'Settings imported: %d changes applied. You can undo it below.', $count, 'ini-protector' ), $count ),
			);
		}
		if ( in_array( $msg, array( 'settings_imported', 'settings_undone' ), true ) && '' !== SecurityWP_Settings_Transfer::login_notice() ) {
			printf(
				'<div class="notice notice-warning"><p><strong>%s</strong> <a href="%s"><code>%s</code></a></p></div>',
				esc_html__( 'Your login address is now:', 'ini-protector' ),
				esc_url( SecurityWP_Settings_Transfer::login_notice() ),
				esc_html( SecurityWP_Settings_Transfer::login_notice() )
			);
		}
		if ( ! isset( $map[ $msg ] ) ) {
			return;
		}
		printf(
			'<div class="notice %s is-dismissible"><p>%s</p></div>',
			esc_attr( $map[ $msg ][0] ),
			esc_html( $map[ $msg ][1] )
		);
	}


}
