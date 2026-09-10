<?php
/**
 * INI Protector admin. One page, the tweak catalog grouped into category cards.
 *
 * Each tweak is a toggle switch that posts immediately (no per-row Save button);
 * tweaks with config fields reveal an inline panel with its own Save when on.
 * Styling mirrors the WP-native flat look used across the INI WP family.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Admin {

	const MENU_SLUG = 'ini-protector';
	const CAP       = 'manage_options';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_secwp_toggle', array( $this, 'handle_toggle' ) );
		add_action( 'admin_post_secwp_save_config', array( $this, 'handle_save_config' ) );
		add_action( 'wp_ajax_secwp_toggle', array( $this, 'ajax_toggle' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_filter( 'plugin_action_links_' . SECWP_BASENAME, array( $this, 'action_links' ) );
		add_filter( 'plugin_row_meta', array( $this, 'row_meta' ), 10, 2 );
		add_action( 'admin_post_secwp_check_updates', array( $this, 'check_updates' ) );
		add_action( 'admin_action_secwp_install_update', array( 'SecurityWP_Manual_Update', 'install' ) );
		add_action( 'admin_notices', array( $this, 'update_notice' ) );
		add_action( 'network_admin_notices', array( $this, 'update_notice' ) );
	}

	/** Enqueue the toggle script on our settings page only. */
	public function enqueue( string $hook ): void {
		if ( 'toplevel_page_' . self::MENU_SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-admin-css', SECWP_PLUGIN_URL . 'assets/admin.css', array(), SECWP_VERSION );
		wp_enqueue_script( 'secwp-admin-config-js', SECWP_PLUGIN_URL . 'assets/admin-config.js', array(), SECWP_VERSION, true );
		wp_enqueue_script(
			'secwp-admin',
			SECWP_PLUGIN_URL . 'assets/admin.js',
			array(),
			SECWP_VERSION,
			true
		);
		wp_localize_script(
			'secwp-admin',
			'secwpAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'secwp_toggle_ajax' ),
				'flash'   => $this->flash_message(),
				'i18n'    => array(
					'enabled'  => __( 'Protection enabled.', 'ini-protector' ),
					'disabled' => __( 'Protection disabled.', 'ini-protector' ),
					'error'    => __( 'Could not save the change. Please try again.', 'ini-protector' ),
				),
			)
		);
	}

	/**
	 * A message queued by a redirect (config save / no-JS toggle), to be shown
	 * as a toast on load. Returns an array{type,message} or null.
	 *
	 * @return array<string,string>|null
	 */
	private function flash_message(): ?array {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return null;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'enabled'  => array( 'success', __( 'Protection enabled.', 'ini-protector' ) ),
			'disabled' => array( 'success', __( 'Protection disabled.', 'ini-protector' ) ),
			'saved'    => array( 'success', __( 'Settings saved.', 'ini-protector' ) ),
			'invalid'  => array( 'error', __( 'Unknown setting.', 'ini-protector' ) ),
		);
		if ( ! isset( $map[ $msg ] ) ) {
			return null;
		}
		return array(
			'type'    => $map[ $msg ][0],
			'message' => $map[ $msg ][1],
		);
	}

	public function menu(): void {
		add_menu_page(
			__( 'INI Protector', 'ini-protector' ),
			__( 'INI Protector', 'ini-protector' ),
			self::CAP,
			self::MENU_SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			81
		);
	}

	public function action_links( array $links ): array {
		$links[] = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG ) ),
			esc_html__( 'Settings', 'ini-protector' )
		);
		return $links;
	}

	/** Add a manual WordPress.org update check beside the plugin version. */
	public function row_meta( array $links, string $file ): array {
		if ( SECWP_BASENAME !== $file || ! current_user_can( 'update_plugins' ) ) {
			return $links;
		}
		$links[] = sprintf(
			'<a href="%s">%s</a>',
			esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secwp_check_updates' ), 'secwp_check_updates' ) ),
			esc_html__( 'Check for updates', 'ini-protector' )
		);
		return $links;
	}

	/** Refresh official update metadata; installation remains a separate WP action. */
	public function check_updates(): void {
		if ( ! current_user_can( 'update_plugins' ) ) {
			wp_die( esc_html__( 'You do not have permission to update plugins.', 'ini-protector' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'secwp_check_updates' );
		$result = SecurityWP_Manual_Update::check();
		wp_safe_redirect( add_query_arg( 'secwp_update_check', $result, network_admin_url( 'plugins.php' ) ) );
		exit;
	}

	/** Display only fixed status messages on the plugins screen. */
	public function update_notice(): void {
		$screen = get_current_screen();
		if ( ! $screen || 'plugins' !== $screen->base || ! current_user_can( 'update_plugins' ) ) {
			return;
		}
		// This read-only status does not trigger an update or other state change.
		$result = isset( $_GET['secwp_update_check'] ) && is_string( $_GET['secwp_update_check'] ) ? sanitize_key( wp_unslash( $_GET['secwp_update_check'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$messages = array(
			'available' => __( 'A new INI Protector release is available from WordPress.org.', 'ini-protector' ),
			'current'   => __( 'INI Protector is up to date with the latest release available from WordPress.org.', 'ini-protector' ),
			'incompatible' => __( 'The latest INI Protector release requires a newer WordPress or PHP version. Update your environment before installing it.', 'ini-protector' ),
			'failed'    => __( 'Could not confirm the latest INI Protector version from WordPress.org. Please try again later.', 'ini-protector' ),
		);
		if ( 'available' === $result ) {
			SecurityWP_Manual_Update::offer_notice();
			return;
		}
		if ( isset( $messages[ $result ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', in_array( $result, array( 'failed', 'incompatible' ), true ) ? 'warning' : 'success', esc_html( $messages[ $result ] ) );
		}
	}

	/* --------------------------------------------------------------------- */
	/* Save handlers                                                          */
	/* --------------------------------------------------------------------- */

	/** Toggle a single tweak on/off (posted by the switch). */
	public function handle_toggle(): void {
		$this->guard();
		check_admin_referer( 'secwp_toggle' );

		$key     = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';
		$catalog = SecurityWP_Features::catalog();
		if ( '' === $key || ! isset( $catalog[ $key ] ) ) {
			$this->redirect( 'invalid' );
		}

		$on = ! empty( $_POST['on'] );
		SecurityWP_Features::set( $key, $on );
		$this->after_change( $key, $on );
		$this->redirect( $on ? 'enabled' : 'disabled' );
	}

	/** Toggle a single tweak on/off via AJAX (no page reload). */
	public function ajax_toggle(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'ini-protector' ) ), 403 );
		}
		check_ajax_referer( 'secwp_toggle_ajax' );

		$key     = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';
		$catalog = SecurityWP_Features::catalog();
		if ( '' === $key || ! isset( $catalog[ $key ] ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown setting.', 'ini-protector' ) ), 400 );
		}

		$on = ! empty( $_POST['on'] );
		SecurityWP_Features::set( $key, $on );
		$this->after_change( $key, $on );

		wp_send_json_success(
			array(
				'key' => $key,
				'on'  => $on,
			)
		);
	}

	/** Save a tweak's config fields (posted by its inline panel). */
	public function handle_save_config(): void {
		$this->guard();
		check_admin_referer( 'secwp_save_config' );

		$key     = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';
		$catalog = SecurityWP_Features::catalog();
		if ( '' === $key || ! isset( $catalog[ $key ]['fields'] ) ) {
			$this->redirect( 'invalid' );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- per-field sanitize happens in set_config().
		$cfg = isset( $_POST['cfg'] ) && is_array( $_POST['cfg'] ) ? wp_unslash( $_POST['cfg'] ) : array();
		$cfg['__submitted'] = 1;
		SecurityWP_Features::set_config( $key, $cfg );
		$this->after_change( $key, SecurityWP_Features::is_on( $key ) );
		$this->redirect( 'saved', $this->return_page() );
	}

	/** Side effects that some tweaks need on change. */
	private function after_change( string $key, bool $on ): void {
		if ( 'hide_login' === $key ) {
			flush_rewrite_rules();
		}
		if ( 'prevent_info_disclosure' === $key && class_exists( 'SecurityWP_Info_Disclosure' ) ) {
			if ( ! $on && method_exists( 'SecurityWP_Info_Disclosure', 'remove_htaccess' ) ) {
				SecurityWP_Info_Disclosure::remove_htaccess();
			}
		}
		// Schedule/clear the daily scan the moment the toggle flips.
		if ( 'vulnerability_scan' === $key && class_exists( 'SecurityWP_Vuln_Scan' ) ) {
			SecurityWP_Vuln_Scan::sync_schedule();
		}
		// Schedule/clear the 5-minute auto-block evaluation the moment it flips.
		if ( SecurityWP_Autoblock::FEATURE_AUTOBLOCK === $key && class_exists( 'SecurityWP_Autoblock' ) ) {
			( new SecurityWP_Autoblock() )->sync_schedule();
		}
		// Schedule/clear the integrity scan, and pick up a changed frequency, the
		// moment the toggle or its config is saved.
		if ( SecurityWP_Integrity::FEATURE === $key && class_exists( 'SecurityWP_Integrity' ) ) {
			if ( $on ) {
				SecurityWP_Integrity::install_table();
			}
			SecurityWP_Integrity::sync_schedule();
		}
	}

	private function guard(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'ini-protector' ) );
		}
	}

	/**
	 * INI Protector screens a save is allowed to return to. An allowlist, not a caller-supplied URL:
	 * a settings form that redirects wherever it is told is an open redirect.
	 */
	private const RETURN_PAGES = array( 'ini-protector-traffic', 'ini-protector-ip-block' );

	/**
	 * Where a save came from, when it was posted by a panel living on another INI Protector screen
	 * (the Traffic page's retention window). Anything unrecognised falls back to the settings page.
	 */
	private function return_page(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the caller has already run guard().
		$page = isset( $_POST['return_page'] ) ? sanitize_key( wp_unslash( $_POST['return_page'] ) ) : '';
		return in_array( $page, self::RETURN_PAGES, true ) ? $page : self::MENU_SLUG;
	}

	private function redirect( string $status, string $page = '' ): void {
		$page = '' !== $page ? $page : self::MENU_SLUG;
		wp_safe_redirect( add_query_arg( array( 'page' => $page, 'secwp_msg' => $status ), admin_url( 'admin.php' ) ) );
		exit;
	}

	/* --------------------------------------------------------------------- */
	/* Render                                                                 */
	/* --------------------------------------------------------------------- */

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$categories = SecurityWP_Features::categories();
		$catalog    = SecurityWP_Features::catalog();
		$state      = SecurityWP_Features::state();
		$enabled    = count( array_filter( $state ) );

		$by_cat = array();
		foreach ( $catalog as $key => $def ) {
			$by_cat[ $def['cat'] ?? 'other' ][ $key ] = $def;
		}

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-shield"></span> ' . esc_html__( 'INI Protector', 'ini-protector' ) . '</h1>';
		echo '<noscript>';
		$this->notice(); // JS users get a toast instead (see flash_message()).
		echo '</noscript>';

		printf(
			'<p class="secwp-muted">%s</p>',
			esc_html( sprintf( /* translators: 1: enabled count, 2: total. */ __( '%1$d of %2$d protections enabled.', 'ini-protector' ), $enabled, count( $catalog ) ) )
		);

		foreach ( $categories as $cat_key => $cat_label ) {
			if ( empty( $by_cat[ $cat_key ] ) ) {
				continue;
			}
			echo '<div class="secwp-card secwp-card-wide">';
			echo '<div class="secwp-card-head"><span class="dashicons ' . esc_attr( $this->cat_icon( $cat_key ) ) . '"></span><h2>' . esc_html( $cat_label ) . '</h2></div>';
			echo '<div class="secwp-card-body"><div class="secwp-features">';

			foreach ( $by_cat[ $cat_key ] as $key => $def ) {
				$on        = ! empty( $state[ $key ] );
				$hasFields = ! empty( $def['fields'] );
				?>
				<div class="secwp-feature">
					<div class="secwp-feature-info">
						<div class="secwp-feature-label"><?php echo esc_html( $def['label'] ); ?></div>
						<div class="secwp-feature-desc"><?php echo esc_html( $def['desc'] ?? '' ); ?></div>
						<?php if ( $hasFields ) : ?>
							<a href="#" class="secwp-config-toggle" data-target="cfg-<?php echo esc_attr( $key ); ?>"<?php echo $on ? '' : ' style="display:none;"'; ?>><?php esc_html_e( 'Configure ▾', 'ini-protector' ); ?></a>
						<?php endif; ?>
						<?php if ( 'traffic_log' === $key && 0 === SecurityWP_Traffic_Log::retention_days() ) : ?>
							<span class="secwp-retention-warning">
								<?php esc_html_e( 'History set to "Unlimited". The database may become large.', 'ini-protector' ); ?>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=ini-protector-utilities#secwp-clean-traffic' ) ); ?>"><?php esc_html_e( 'Clean traffic history in Utilities', 'ini-protector' ); ?></a>
							</span>
						<?php endif; ?>
					</div>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secwp-toggle-form" data-key="<?php echo esc_attr( $key ); ?>">
						<input type="hidden" name="action" value="secwp_toggle" />
						<input type="hidden" name="key" value="<?php echo esc_attr( $key ); ?>" />
						<input type="hidden" name="on" value="<?php echo $on ? '0' : '1'; ?>" />
						<?php wp_nonce_field( 'secwp_toggle' ); ?>
						<button type="submit" class="secwp-switch <?php echo $on ? 'on' : ''; ?>" aria-pressed="<?php echo $on ? 'true' : 'false'; ?>" aria-label="<?php echo esc_attr( $def['label'] ); ?>">
							<span class="secwp-switch-knob"></span>
						</button>
					</form>
				</div>
				<?php if ( $hasFields ) : ?>
					<div class="secwp-config" id="cfg-<?php echo esc_attr( $key ); ?>">
						<?php $this->render_config_form( $key, $def['fields'] ); ?>
					</div>
				<?php endif; ?>
				<?php
			}

			echo '</div></div></div>';
		}

		echo '</div>';
	}

	/** The inline config form for a tweak with fields. */
	private function render_config_form( string $key, array $fields ): void {
		$config = SecurityWP_Features::config( $key );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secwp-config-form">
			<input type="hidden" name="action" value="secwp_save_config" />
			<input type="hidden" name="key" value="<?php echo esc_attr( $key ); ?>" />
			<?php wp_nonce_field( 'secwp_save_config' ); ?>
			<div class="secwp-config-grid">
				<?php foreach ( $fields as $fkey => $fdef ) : ?>
					<?php $this->render_field( $key, $fkey, $fdef, $config[ $fkey ] ?? ( $fdef['default'] ?? '' ) ); ?>
				<?php endforeach; ?>
			</div>
			<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Save settings', 'ini-protector' ); ?></button></p>
		</form>
		<?php
	}

	private function render_field( string $tweak, string $fkey, array $fdef, $value ): void {
		$name  = 'cfg[' . $fkey . ']';
		$id    = 'secwp_' . $tweak . '_' . $fkey;
		$type  = $fdef['type'] ?? 'text';
		$label = $fdef['label'] ?? $fkey;
		$desc  = $fdef['desc'] ?? '';
		$ph    = $fdef['placeholder'] ?? '';
		echo '<div class="secwp-field">';
		switch ( $type ) {
			case 'checkbox':
				printf(
					'<label class="secwp-checkbox"><input type="checkbox" name="%s" value="1" %s /> %s</label>',
					esc_attr( $name ),
					checked( ! empty( $value ), true, false ),
					esc_html( $label )
				);
				break;
			case 'select':
				printf( '<label class="secwp-field-label" for="%s">%s</label>', esc_attr( $id ), esc_html( $label ) );
				printf( '<select id="%s" name="%s" class="secwp-input">', esc_attr( $id ), esc_attr( $name ) );
				foreach ( (array) ( $fdef['options'] ?? array() ) as $oval => $olabel ) {
					printf( '<option value="%s" %s>%s</option>', esc_attr( $oval ), selected( (string) $value, (string) $oval, false ), esc_html( $olabel ) );
				}
				echo '</select>';
				break;
			case 'number':
				printf( '<label class="secwp-field-label" for="%s">%s</label>', esc_attr( $id ), esc_html( $label ) );
				printf( '<input type="number" id="%s" name="%s" value="%s" class="secwp-input small" />', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ) );
				break;
			case 'password':
				printf( '<label class="secwp-field-label" for="%s">%s</label>', esc_attr( $id ), esc_html( $label ) );
				printf( '<input type="password" id="%s" name="%s" value="" placeholder="%s" class="secwp-input" autocomplete="new-password" />', esc_attr( $id ), esc_attr( $name ), esc_attr__( '••••• (unchanged)', 'ini-protector' ) );
				break;
			case 'roles':
				printf( '<span class="secwp-field-label">%s</span>', esc_html( $label ) );
				$selected = is_array( $value ) ? array_map( 'strval', $value ) : array();
				// Default to administrator when nothing has ever been saved, so the
				// feature is meaningful the moment it is switched on.
				if ( ! $selected && ! SecurityWP_Features::is_on( $tweak ) ) {
					$selected = array( 'administrator' );
				}
				echo '<div class="secwp-ns-list">';
				foreach ( wp_roles()->get_names() as $role_key => $role_label ) {
					printf(
						'<label class="secwp-checkbox"><input type="checkbox" name="%s[]" value="%s" %s /> %s</label>',
						esc_attr( $name ),
						esc_attr( $role_key ),
						checked( in_array( (string) $role_key, $selected, true ), true, false ),
						esc_html( translate_user_role( $role_label ) )
					);
				}
				echo '</div>';
				break;
			case 'rest_namespaces':
				printf( '<span class="secwp-field-label">%s</span>', esc_html( $label ) );
				$selected   = is_array( $value ) ? array_map( 'strval', $value ) : array();
				$namespaces = $this->rest_namespaces();
				if ( empty( $namespaces ) ) {
					printf( '<p class="secwp-hint">%s</p>', esc_html__( 'No public REST namespaces registered.', 'ini-protector' ) );
					break;
				}
				echo '<div class="secwp-ns-list">';
				foreach ( $namespaces as $ns ) {
					printf(
						'<label class="secwp-checkbox"><input type="checkbox" name="%s[]" value="%s" %s /> <code>%s</code></label>',
						esc_attr( $name ),
						esc_attr( $ns ),
						checked( in_array( $ns, $selected, true ), true, false ),
						esc_html( $ns )
					);
				}
				echo '</div>';

				/* Read-only note: the INI WP family namespaces stay public no
				   matter what, so the control panel can never be locked out. */
				$always = SecurityWP_Tweaks::always_exempt();
				if ( ! empty( $always ) ) {
					echo '<div class="secwp-ns-always">';
					printf( '<span class="dashicons dashicons-lock"></span> %s ', esc_html__( 'Always public (cannot be blocked):', 'ini-protector' ) );
					$codes = array_map( static function ( $ns ) {
						return '<code>' . esc_html( $ns ) . '</code>';
					}, $always );
					echo wp_kses( implode( ' ', $codes ), array( 'code' => array() ) );
					printf( '<p class="secwp-hint">%s</p>', esc_html__( 'These keep the INI WP control panel and its plugins working; each has its own authentication.', 'ini-protector' ) );
					echo '</div>';
				}
				break;
			default:
				printf( '<label class="secwp-field-label" for="%s">%s</label>', esc_attr( $id ), esc_html( $label ) );
				printf( '<input type="text" id="%s" name="%s" value="%s" placeholder="%s" class="secwp-input" />', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ), esc_attr( $ph ) );
		}
		if ( '' !== $desc ) {
			printf( '<p class="secwp-hint">%s</p>', esc_html( $desc ) );
		}
		echo '</div>';
	}

	/**
	 * Registered REST namespaces an admin may choose to keep public, excluding
	 * the always-exempt INI WP namespaces (those can't be toggled — they're
	 * needed for the control panel and are exempt regardless).
	 *
	 * @return string[]
	 */
	private function rest_namespaces(): array {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return array();
		}
		$all     = rest_get_server()->get_namespaces();
		$exclude = SecurityWP_Tweaks::always_exempt(); // family namespaces are always public, not tickable.
		$out     = array();
		foreach ( $all as $ns ) {
			if ( ! in_array( strtolower( $ns ), $exclude, true ) ) {
				$out[] = $ns;
			}
		}
		sort( $out );
		return $out;
	}

	private function cat_icon( string $cat ): string {
		$icons = array(
			'security' => 'dashicons-shield',
			'head'     => 'dashicons-editor-removeformatting',
			'seo'      => 'dashicons-privacy',
		);
		return $icons[ $cat ] ?? 'dashicons-admin-generic';
	}

	private function notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'enabled'  => __( 'Protection enabled.', 'ini-protector' ),
			'disabled' => __( 'Protection disabled.', 'ini-protector' ),
			'saved'    => __( 'Settings saved.', 'ini-protector' ),
			'invalid'  => __( 'Unknown setting.', 'ini-protector' ),
		);
		if ( isset( $map[ $msg ] ) ) {
			$class = 'invalid' === $msg ? 'notice-error' : 'notice-success';
			printf( '<div class="notice %s is-dismissible"><p>%s</p></div>', esc_attr( $class ), esc_html( $map[ $msg ] ) );
		}
	}




}
