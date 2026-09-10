<?php
/**
 * INI Protector → IP Block admin page.
 *
 * The home for blocking decisions, separate from the Traffic monitor (which is a
 * read-only forensics view). Three sections:
 *
 *   1. Suggested by the system — IPs the traffic monitor flags as abuse
 *      candidates (SecurityWP_Traffic_Log::summary()['suggested']), with a
 *      one-click Apply. This finally renders data that was previously computed
 *      and only exposed to the platform pull.
 *   2. Currently blocked — the active blocklist, with Unblock.
 *   3. Manual add — block an IP by hand.
 *
 * Phase 1: Apply creates a permanent block (same as a manual block) — the
 * temp-block escalation engine (1h→2w ladder) lands in Phase 2, after which the
 * proposed-duration column and the Auto-Block mode toggle become meaningful. See
 * ini-protector-block-suggestion-system.md.
 *
 * Blocking uses SecurityWP_IP_Block. Verdict badges reuse the same level→label
 * mapping as the Traffic page so the two views agree.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_IP_Block_Admin {

	const SLUG = 'ini-protector-ipblock';
	const CAP  = 'manage_options';

	/** Look-back window (hours) used to compute suggestions on this page. */
	const SUGGEST_HOURS = 168;

	/** How many suggested rules to show. */
	const SUGGEST_LIMIT = 25;

	private $page_hook = '';

	public function __construct() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_menu', array( $this, 'menu' ), 21 );
		add_action( 'admin_post_secwp_ipblock_action', array( $this, 'handle_action' ) );
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== $this->page_hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-ip-block-admin-css', SECWP_PLUGIN_URL . 'assets/ip-block-admin.css', array(), SECWP_VERSION );
	}

	public function menu(): void {
		$this->page_hook = add_submenu_page(
			'ini-protector',
			__( 'IP Block', 'ini-protector' ),
			__( 'IP Block', 'ini-protector' ),
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
		check_admin_referer( 'secwp_ipblock_action' );

		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$ip  = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$msg = 'invalid';

		switch ( $do ) {
			case 'apply':
				// Applying a suggestion = a TEMPORARY block on the escalation ladder
				// (1h → 2w), identical to an auto-block but human-triggered. It bumps
				// the IP's escalation level, so a repeat offender keeps climbing and
				// decay applies — no permanent suggestion-applied blocks.
				$why = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
				if ( class_exists( 'SecurityWP_Autoblock' ) ) {
					$res = SecurityWP_Autoblock::escalate( $ip, $why, SecurityWP_IP_Block::SOURCE_SUGGESTION );
				} else {
					// Defensive fallback (engine class somehow absent): a fixed 24h temp block.
					$reason = '' !== $why
						? sprintf( /* translators: %s: why the IP was suggested */ __( 'Suggested: %s', 'ini-protector' ), $why )
						: __( 'Applied from suggestions', 'ini-protector' );
					$res = SecurityWP_IP_Block::block_temp( $ip, $reason, DAY_IN_SECONDS, SecurityWP_IP_Block::SOURCE_SUGGESTION );
				}
				$msg = is_wp_error( $res ) ? $res->get_error_code() : 'blocked';
				break;
			case 'block':
				$res = SecurityWP_IP_Block::block( $ip, __( 'Blocked from IP Block page', 'ini-protector' ), 0, SecurityWP_IP_Block::SOURCE_MANUAL );
				$msg = is_wp_error( $res ) ? $res->get_error_code() : 'blocked';
				break;
			case 'unblock':
				SecurityWP_IP_Block::unblock( $ip );
				$msg = 'unblocked';
				break;
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

		$monitor_on = class_exists( 'SecurityWP_Features' ) && SecurityWP_Features::is_on( 'traffic_log' );
		$summary    = ( $monitor_on && class_exists( 'SecurityWP_Traffic_Log' ) )
			? SecurityWP_Traffic_Log::summary( self::SUGGEST_HOURS, self::SUGGEST_LIMIT )
			: array();
		$suggested  = $summary['suggested'] ?? array();
		$blocked    = SecurityWP_IP_Block::all();

		// Don't suggest an IP that is already blocked.
		$suggested = array_values( array_filter(
			$suggested,
			static function ( $row ) use ( $blocked ) {
				return ! isset( $blocked[ (string) ( $row['ip'] ?? '' ) ] );
			}
		) );

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-shield"></span> ' . esc_html__( 'IP Block', 'ini-protector' ) . '</h1>';
		$this->notice();

		$this->render_mode_banner();
		$this->render_suggested( $suggested, $monitor_on );
		$this->render_blocklist( $blocked );

		echo '</div>';
	}

	/**
	 * A one-line status of the escalation engine: off, suggest-only (Block
	 * Suggestion System), or enforcing (Auto-Block). Links to the settings toggle.
	 */
	private function render_mode_banner(): void {
		if ( ! class_exists( 'SecurityWP_Autoblock' ) ) {
			return;
		}
		// Escaped once here and reused in the three printf()s below; the escaping sniff cannot
		// follow it through the variable, hence the per-line ignores there.
		$settings = esc_url( admin_url( 'admin.php?page=ini-protector' ) );
		if ( ! SecurityWP_Autoblock::is_enabled() ) {
			printf(
				'<div class="secwp-mode secwp-mode-off"><span class="dashicons dashicons-marker"></span> %s <a href="%s">%s</a></div>',
				esc_html__( 'Auto-block escalation is off — these are manual blocks and one-off suggestions only.', 'ini-protector' ),
				$settings, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url()'d above.
				esc_html__( 'Turn it on', 'ini-protector' )
			);
			return;
		}
		if ( SecurityWP_Autoblock::is_enforcing() ) {
			printf(
				'<div class="secwp-mode secwp-mode-enforce"><span class="dashicons dashicons-shield-alt"></span> %s <a href="%s">%s</a></div>',
				esc_html__( 'Auto-Block is ON — offending IPs are blocked automatically on an escalating schedule (1h → 2w).', 'ini-protector' ),
				$settings, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url()'d above.
				esc_html__( 'Settings', 'ini-protector' )
			);
			return;
		}
		printf(
			'<div class="secwp-mode secwp-mode-suggest"><span class="dashicons dashicons-lightbulb"></span> %s <a href="%s">%s</a></div>',
			esc_html__( 'Block Suggestion System — the engine suggests blocks for you to review and Apply; it does not block automatically. Enable “Enforce” to switch to Auto-Block.', 'ini-protector' ),
			$settings, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url()'d above.
			esc_html__( 'Settings', 'ini-protector' )
		);
	}

	private function render_suggested( array $suggested, bool $monitor_on ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-lightbulb"></span><h2>' . esc_html__( 'Suggested by the system', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';

		if ( ! $monitor_on ) {
			printf(
				'<p class="secwp-empty">%s <a href="%s">%s</a></p>',
				esc_html__( 'The traffic monitor is off, so there are no suggestions yet. Turn on “Traffic monitor” to start flagging abusive IPs.', 'ini-protector' ),
				esc_url( admin_url( 'admin.php?page=ini-protector' ) ),
				esc_html__( 'Go to settings', 'ini-protector' )
			);
			echo '</div></div>';
			return;
		}

		if ( empty( $suggested ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'No IPs are over the abuse threshold right now. Nothing to suggest.', 'ini-protector' ) . '</p>';
			echo '</div></div>';
			return;
		}

		printf(
			'<p class="secwp-hint">%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: look-back window in hours */
					__( 'IPs that crossed an abuse threshold in the last %d hours. Apply a block, or open the IP to investigate first.', 'ini-protector' ),
					self::SUGGEST_HOURS
				)
			)
		);

		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'IP', 'ini-protector' ), __( 'Severity', 'ini-protector' ), __( 'Why', 'ini-protector' ), '' ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $suggested as $row ) {
			$ip       = (string) ( $row['ip'] ?? '' );
			$why      = (string) ( $row['reason'] ?? '' );
			$severity = (string) ( $row['severity'] ?? 'medium' );
			if ( '' === $ip ) {
				continue;
			}
			echo '<tr>';
			printf( '<td><a class="secwp-ip-link" href="%s"><code>%s</code></a></td>', esc_url( $this->ip_detail_url( $ip ) ), esc_html( $ip ) );
			echo '<td>' . $this->severity_badge( $severity ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
			printf( '<td>%s</td>', esc_html( $why ) );
			echo '<td>' . $this->apply_button( $ip, $why ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div></div>';
	}

	private function render_blocklist( array $blocked ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-dismiss"></span><h2>' . esc_html__( 'Currently blocked', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';

		// Manual add form.
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secwp-block-add">
			<input type="hidden" name="action" value="secwp_ipblock_action" />
			<input type="hidden" name="do" value="block" />
			<?php wp_nonce_field( 'secwp_ipblock_action' ); ?>
			<input type="text" name="ip" class="secwp-input" placeholder="<?php esc_attr_e( 'IP address to block', 'ini-protector' ); ?>" style="max-width:240px;" />
			<button type="submit" class="button"><?php esc_html_e( 'Block IP', 'ini-protector' ); ?></button>
		</form>
		<?php

		if ( empty( $blocked ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'No IPs are blocked.', 'ini-protector' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'IP', 'ini-protector' ), __( 'Reason', 'ini-protector' ), __( 'Source', 'ini-protector' ), __( 'Blocked', 'ini-protector' ), __( 'Expires', 'ini-protector' ), '' ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $blocked as $ip => $meta ) {
				echo '<tr>';
				printf( '<td><a class="secwp-ip-link" href="%s"><code>%s</code></a></td>', esc_url( $this->ip_detail_url( (string) $ip ) ), esc_html( (string) $ip ) );
				printf( '<td>%s</td>', esc_html( (string) ( $meta['reason'] ?? '' ) ) );
				echo '<td>' . $this->source_label( (string) ( $meta['source'] ?? SecurityWP_IP_Block::SOURCE_MANUAL ) ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
				printf( '<td>%s</td>', esc_html( ! empty( $meta['time'] ) ? date_i18n( 'Y-m-d H:i', (int) $meta['time'] ) : '' ) );
				printf( '<td>%s</td>', esc_html( $this->expires_label( (int) ( $meta['expires'] ?? 0 ) ) ) );
				echo '<td>' . $this->unblock_button( (string) $ip ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	/* --------------------------------------------------------------------- */
	/* Helpers                                                                */
	/* --------------------------------------------------------------------- */

	/** Link to the Traffic single-IP drill-down so the admin can investigate before blocking. */
	private function ip_detail_url( string $ip ): string {
		return add_query_arg(
			array( 'page' => SecurityWP_Traffic_Admin::SLUG, 'ip' => $ip, 'hours' => 168 ),
			admin_url( 'admin.php' )
		);
	}

	private function source_label( string $source ): string {
		$map = array(
			SecurityWP_IP_Block::SOURCE_MANUAL     => array( 'medium', __( 'Manual', 'ini-protector' ) ),
			SecurityWP_IP_Block::SOURCE_SUGGESTION => array( 'medium', __( 'Suggested', 'ini-protector' ) ),
			SecurityWP_IP_Block::SOURCE_AUTO       => array( 'high', __( 'Auto', 'ini-protector' ) ),
		);
		$m = $map[ $source ] ?? $map[ SecurityWP_IP_Block::SOURCE_MANUAL ];
		return sprintf( '<span class="secwp-badge secwp-badge-%s">%s</span>', esc_attr( $m[0] ), esc_html( $m[1] ) );
	}

	/** "Permanent" for a 0/absent expiry, otherwise a human date. */
	private function expires_label( int $expires ): string {
		if ( $expires <= 0 ) {
			return __( 'Permanent', 'ini-protector' );
		}
		if ( time() >= $expires ) {
			return __( 'Expired', 'ini-protector' );
		}
		return date_i18n( 'Y-m-d H:i', $expires );
	}

	private function severity_badge( string $severity ): string {
		$map = array(
			'high'   => array( 'high', __( 'High', 'ini-protector' ) ),
			'medium' => array( 'medium', __( 'Medium', 'ini-protector' ) ),
		);
		$m = $map[ $severity ] ?? $map['medium'];
		return sprintf( '<span class="secwp-badge secwp-badge-%s">%s</span>', esc_attr( $m[0] ), esc_html( $m[1] ) );
	}

	private function apply_button( string $ip, string $why ): string {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
			<input type="hidden" name="action" value="secwp_ipblock_action" />
			<input type="hidden" name="do" value="apply" />
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>" />
			<input type="hidden" name="reason" value="<?php echo esc_attr( $why ); ?>" />
			<?php wp_nonce_field( 'secwp_ipblock_action' ); ?>
			<button type="submit" class="button button-small button-primary"><?php esc_html_e( 'Apply block', 'ini-protector' ); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	private function unblock_button( string $ip ): string {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
			<input type="hidden" name="action" value="secwp_ipblock_action" />
			<input type="hidden" name="do" value="unblock" />
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>" />
			<?php wp_nonce_field( 'secwp_ipblock_action' ); ?>
			<button type="submit" class="button button-small"><?php esc_html_e( 'Unblock', 'ini-protector' ); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	private function notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'blocked'          => array( 'success', __( 'IP blocked.', 'ini-protector' ) ),
			'unblocked'        => array( 'success', __( 'IP unblocked.', 'ini-protector' ) ),
			'secwp_self_block' => array( 'error', __( 'You can’t block your own current IP address.', 'ini-protector' ) ),
			'secwp_bad_ip'     => array( 'error', __( 'That is not a valid IP address.', 'ini-protector' ) ),
			'secwp_block_full' => array( 'error', __( 'The blocklist is full.', 'ini-protector' ) ),
		);
		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
	}


}
