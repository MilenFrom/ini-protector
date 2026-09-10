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

		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'secwp_msg' => $msg ), admin_url( 'admin.php' ) ) );
		exit;
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
			esc_html__( 'Maintenance actions for asset caching and traffic history.', 'ini-protector' )
		);
		$this->page_notice();
		$this->render_asset_salt();
		$this->render_traffic_cleanup();
		echo '</div>';
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
			'<p class="secwp-hint">%s <code>wp secwp asset-salt rotate</code> — %s</p>',
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
		);
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
