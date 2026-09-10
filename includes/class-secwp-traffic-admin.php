<?php
/**
 * INI Protector → Traffic admin page.
 *
 * A read-out of the traffic monitor for site owners who are NOT on the INI WP
 * platform — totals, top offender IPs, suspicious paths, recent events, and
 * suggested blocks — plus working Block / Unblock IP actions and Clear log.
 *
 * Renders SecurityWP_Traffic_Log::summary() (the same data the platform pulls),
 * so there is one source of truth. Blocking uses SecurityWP_IP_Block.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Traffic_Admin {

	const SLUG = 'ini-protector-traffic';
	const CAP  = 'manage_options';

	/** Look-back windows offered (hours), before the retention filter in windows(). */
	const WINDOWS = array( 1, 24, 168, 720, 2160, 8760 );

	/**
	 * The windows this site can actually answer: never wider than what the log keeps, so the bar
	 * can't offer a month of history to a site that prunes at 14 days. Always keeps the two short
	 * windows so the bar is never empty.
	 */
	private static function windows(): array {
		$max = class_exists( 'SecurityWP_Traffic_Log' ) ? SecurityWP_Traffic_Log::max_window_hours() : 24 * 14;
		$out = array();
		foreach ( self::WINDOWS as $w ) {
			if ( $w <= $max || $w <= 24 ) {
				$out[] = $w;
			}
		}
		return $out;
	}

	/** Labels for the window bar. */
	private static function window_labels(): array {
		return array(
			1    => __( 'Last hour', 'ini-protector' ),
			24   => __( '24 hours', 'ini-protector' ),
			168  => __( '7 days', 'ini-protector' ),
			720  => __( '30 days', 'ini-protector' ),
			2160 => __( '90 days', 'ini-protector' ),
			8760 => __( '1 year', 'ini-protector' ),
		);
	}

	private $page_hook = '';

	public function __construct() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_menu', array( $this, 'menu' ), 20 );
		add_action( 'admin_post_secwp_traffic_action', array( $this, 'handle_action' ) );
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== $this->page_hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-traffic-admin-css', SECWP_PLUGIN_URL . 'assets/traffic-admin.css', array(), SECWP_VERSION );
		wp_enqueue_script( 'secwp-traffic-admin-modal-js', SECWP_PLUGIN_URL . 'assets/traffic-admin-modal.js', array(), SECWP_VERSION, true );
	}

	public function menu(): void {
		$this->page_hook = add_submenu_page(
			'ini-protector',
			__( 'Traffic', 'ini-protector' ),
			__( 'Traffic', 'ini-protector' ),
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
		check_admin_referer( 'secwp_traffic_action' );

		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$ip  = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$msg = 'invalid';

		switch ( $do ) {
			case 'block':
				$res = SecurityWP_IP_Block::block( $ip, __( 'Blocked from Traffic view', 'ini-protector' ) );
				$msg = is_wp_error( $res ) ? $res->get_error_code() : 'blocked';
				break;
			case 'unblock':
				SecurityWP_IP_Block::unblock( $ip );
				$msg = 'unblocked';
				break;
			case 'clear':
				$msg = class_exists( 'SecurityWP_Traffic_Log' ) && SecurityWP_Traffic_Log::clear() ? 'cleared' : 'clear_failed';
				break;
		}

		$args = array( 'page' => self::SLUG, 'secwp_msg' => $msg );
		if ( isset( $_POST['hours'] ) ) {
			$args['hours'] = (int) $_POST['hours'];
		}
		// If the action came from the single-IP drill-down, return there instead of the overview.
		$return_ip = isset( $_POST['return_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['return_ip'] ) ) : '';
		if ( '' !== $return_ip && filter_var( $return_ip, FILTER_VALIDATE_IP ) ) {
			$args['ip'] = $return_ip;
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/* --------------------------------------------------------------------- */
	/* Render                                                                 */
	/* --------------------------------------------------------------------- */

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$hours = isset( $_GET['hours'] ) ? (int) $_GET['hours'] : 24; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $hours, self::windows(), true ) ) {
			$hours = 24;
		}

		// Drill-down: ?ip=… renders the single-IP activity view instead of the overview.
		$detail_ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $detail_ip && filter_var( $detail_ip, FILTER_VALIDATE_IP ) ) {
			$this->render_ip_detail( $detail_ip, $hours );
			return;
		}

		$enabled = class_exists( 'SecurityWP_Features' ) && SecurityWP_Features::is_on( 'traffic_log' );
		$summary = class_exists( 'SecurityWP_Traffic_Log' ) ? SecurityWP_Traffic_Log::summary( $hours, 25 ) : array( 'enabled' => false );
		$blocked = SecurityWP_IP_Block::all();

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-visibility"></span> ' . esc_html__( 'Traffic & threats', 'ini-protector' ) . '</h1>';
		$this->notice();

		if ( ! $enabled ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body">';
			printf(
				'<p>%s</p><p><a class="button button-primary" href="%s">%s</a></p>',
				esc_html__( 'The traffic monitor is off, so there is nothing to show yet. Turn on “Traffic monitor” to start recording suspicious requests.', 'ini-protector' ),
				esc_url( admin_url( 'admin.php?page=ini-protector' ) ),
				esc_html__( 'Go to settings', 'ini-protector' )
			);
			echo '</div></div>';
			echo '</div>';
			return;
		}

		$this->render_window_bar( $hours );
		$this->render_storage();
		$this->render_retention_window();
		$this->verdict_legend();
		$this->render_totals( $summary['totals'] ?? array() );
		$this->render_top_ips( $summary['top_ips'] ?? array(), $summary['suggested'] ?? array(), $blocked, $hours );
		$this->render_top_paths( $summary['top_paths'] ?? array() );
		$this->render_recent( $summary['recent'] ?? array() );
		$this->render_blocklist_link();
		$this->render_clear( $hours );

		echo '</div>';
	}

	private function render_window_bar( int $hours ): void {
		$labels = self::window_labels();
		echo '<p class="secwp-window">';
		foreach ( self::windows() as $w ) {
			$url = add_query_arg( array( 'page' => self::SLUG, 'hours' => $w ), admin_url( 'admin.php' ) );
			printf(
				'<a class="button %s" href="%s">%s</a> ',
				$w === $hours ? 'button-primary' : '',
				esc_url( $url ),
				esc_html( $labels[ $w ] )
			);
		}
		echo '</p>';
	}

	/**
	 * What the log is costing, on the page that offers to make it cost more. The growth projection is
	 * only shown when retention is unlimited — that is the setting where the number is a forecast
	 * rather than a bounded steady state.
	 */
	private function render_storage(): void {
		if ( ! class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return;
		}
		$st = SecurityWP_Traffic_Log::stats();
		if ( empty( $st['enabled'] ) ) {
			return;
		}

		$parts = array();

		/* translators: %s: number of stored requests */
		$parts[] = sprintf( __( '%s requests stored', 'ini-protector' ), number_format_i18n( (int) $st['rows'] ) );

		if ( $st['bytes'] > 0 ) {
			/* translators: %s: formatted size, e.g. "5 MB" */
			$parts[] = sprintf( __( '%s on disk', 'ini-protector' ), size_format( (int) $st['bytes'] ) );
		}

		if ( '' !== $st['oldest'] ) {
			/* translators: %s: date of the oldest stored request */
			$parts[] = sprintf( __( 'oldest %s', 'ini-protector' ), mysql2date( get_option( 'date_format' ), $st['oldest'] ) );
		}

		if ( (int) $st['retention_days'] < 1 ) {
			$parts[] = __( 'kept indefinitely', 'ini-protector' );
		} else {
			/* translators: %d: retention window in days */
			$parts[] = sprintf( _n( 'kept %d day', 'kept %d days', (int) $st['retention_days'], 'ini-protector' ), (int) $st['retention_days'] );
		}

		$parts[] = (int) $st['max_rows'] > 0
			/* translators: %s: maximum number of rows kept */
			? sprintf( __( 'max %s rows', 'ini-protector' ), number_format_i18n( (int) $st['max_rows'] ) )
			: __( 'no row limit', 'ini-protector' );

		$note = '';
		// Only forecast when nothing prunes by age; with a retention window the size settles instead.
		if ( (int) $st['retention_days'] < 1 && $st['rows_per_day'] > 0 && $st['bytes_per_row'] > 0 ) {
			$per_year = $st['rows_per_day'] * 365 * $st['bytes_per_row'];
			$note     = sprintf(
				/* translators: 1: requests per day, 2: projected size per year, e.g. "1.2 GB" */
				__( 'At the recent rate of %1$s requests/day that is roughly %2$s per year — it lands in your database backups too.', 'ini-protector' ),
				number_format_i18n( (int) $st['rows_per_day'] ),
				size_format( $per_year )
			);
		}

		printf(
			'<p class="secwp-storage"><span class="dashicons dashicons-database"></span> <span>%s%s</span><button type="button" class="button button-small secwp-retention-open">%s</button></p>',
			esc_html( implode( __( ' · ', 'ini-protector' ), $parts ) ),
			'' !== $note ? ' <em>' . esc_html( $note ) . '</em>' : '',
			esc_html__( 'Retention settings', 'ini-protector' )
		);
	}

	/**
	 * The retention window: how long traffic history is kept, edited where its cost is visible
	 * rather than three clicks away under the settings list.
	 *
	 * Labels, defaults and bounds come from the feature catalog, so this window and the inline panel
	 * on the settings page can't drift apart — only the presentation is duplicated. The form posts to
	 * the same admin-post handler as that panel and returns here via `return_page`.
	 *
	 * Rendered with a native <dialog> for the free backdrop, Esc handling and focus trapping. With JS
	 * off the dialog can't be opened, so the fallback link to the settings page is always present.
	 */
	private function render_retention_window(): void {
		if ( ! class_exists( 'SecurityWP_Features' ) || ! class_exists( 'SecurityWP_Traffic_Log' ) ) {
			return;
		}
		$catalog = SecurityWP_Features::catalog();
		$fields  = $catalog['traffic_log']['fields'] ?? array();
		if ( empty( $fields ) ) {
			return;
		}
		$config = SecurityWP_Features::config( 'traffic_log' );
		$stats  = SecurityWP_Traffic_Log::stats();
		?>
		<dialog class="secwp-modal" id="secwp-retention-modal" aria-labelledby="secwp-retention-title">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="secwp-modal-form">
				<input type="hidden" name="action" value="secwp_save_config" />
				<input type="hidden" name="key" value="traffic_log" />
				<input type="hidden" name="return_page" value="<?php echo esc_attr( self::SLUG ); ?>" />
				<input type="hidden" name="cfg[__submitted]" value="1" />
				<?php wp_nonce_field( 'secwp_save_config' ); ?>

				<div class="secwp-modal-head">
					<h2 id="secwp-retention-title"><?php esc_html_e( 'Traffic retention', 'ini-protector' ); ?></h2>
					<button type="button" class="secwp-modal-x secwp-retention-close" aria-label="<?php esc_attr_e( 'Close', 'ini-protector' ); ?>">&times;</button>
				</div>

				<div class="secwp-modal-body">
					<?php foreach ( $fields as $fkey => $fdef ) : ?>
						<?php
						$id  = 'secwp-retention-' . $fkey;
						$val = $config[ $fkey ] ?? ( $fdef['default'] ?? 0 );
						?>
						<div class="secwp-modal-field">
							<label for="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $fdef['label'] ?? $fkey ); ?></label>
							<?php if ( 'select' === ( $fdef['type'] ?? '' ) ) : ?>
								<select id="<?php echo esc_attr( $id ); ?>" name="cfg[<?php echo esc_attr( $fkey ); ?>]">
									<?php foreach ( (array) ( $fdef['options'] ?? array() ) as $oval => $olabel ) : ?>
										<option value="<?php echo esc_attr( (string) $oval ); ?>" <?php selected( (string) $val, (string) $oval ); ?>>
											<?php echo esc_html( $olabel ); ?>
										</option>
									<?php endforeach; ?>
								</select>
							<?php else : ?>
								<input
									type="number"
									id="<?php echo esc_attr( $id ); ?>"
									name="cfg[<?php echo esc_attr( $fkey ); ?>]"
									value="<?php echo esc_attr( (string) $val ); ?>"
									step="1"
									<?php echo isset( $fdef['min'] ) ? ' min="' . esc_attr( (string) $fdef['min'] ) . '"' : ''; ?>
									<?php echo isset( $fdef['max'] ) ? ' max="' . esc_attr( (string) $fdef['max'] ) . '"' : ''; ?>
								/>
							<?php endif; ?>
							<p class="secwp-modal-hint"><?php echo esc_html( $fdef['desc'] ?? '' ); ?></p>
						</div>
					<?php endforeach; ?>

					<?php if ( ! empty( $stats['enabled'] ) && $stats['bytes_per_row'] > 0 && $stats['rows_per_day'] > 0 ) : ?>
						<p class="secwp-modal-cost">
							<?php
							printf(
								/* translators: 1: requests per day, 2: size per row, 3: size added per month */
								esc_html__( 'This site records about %1$s requests a day at roughly %2$s each — around %3$s of database (and backup) growth per month at the current rate. Keeping history costs disk, not page speed: the log is written after the response is sent.', 'ini-protector' ),
								esc_html( number_format_i18n( (int) $stats['rows_per_day'] ) ),
								esc_html( size_format( (int) $stats['bytes_per_row'] ) ),
								esc_html( size_format( (int) $stats['rows_per_day'] * 30 * (int) $stats['bytes_per_row'] ) )
							);
							?>
						</p>
					<?php endif; ?>

					<p class="secwp-modal-hint">
						<?php esc_html_e( 'Visitor IPs and user-agents are personal data. Keeping them indefinitely is a deliberate choice, not a default.', 'ini-protector' ); ?>
					</p>
				</div>

				<div class="secwp-modal-foot">
					<a class="secwp-modal-alt" href="<?php echo esc_url( admin_url( 'admin.php?page=ini-protector' ) ); ?>"><?php esc_html_e( 'All INI Protector settings', 'ini-protector' ); ?></a>
					<span>
						<button type="button" class="button secwp-retention-close"><?php esc_html_e( 'Cancel', 'ini-protector' ); ?></button>
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Save retention', 'ini-protector' ); ?></button>
					</span>
				</div>
			</form>
		</dialog>
		<?php
	}

	/** Open/close wiring for the retention window. Vanilla JS — the traffic screen loads no jQuery of its own. */


	private function render_totals( array $t ): void {
		$cards = array(
			'requests'       => __( 'Requests', 'ini-protector' ),
			'unique_ips'     => __( 'Unique IPs', 'ini-protector' ),
			'suspicious'     => __( 'Suspicious', 'ini-protector' ),
			'not_found'      => __( '404s', 'ini-protector' ),
			'login_attempts' => __( 'Login attempts', 'ini-protector' ),
		);
		echo '<div class="secwp-totals">';
		foreach ( $cards as $k => $label ) {
			printf(
				'<div class="secwp-stat"><div class="secwp-stat-n">%s</div><div class="secwp-stat-l">%s</div></div>',
				esc_html( number_format_i18n( (int) ( $t[ $k ] ?? 0 ) ) ),
				esc_html( $label )
			);
		}
		echo '</div>';
	}

	private function render_top_ips( array $ips, array $suggested, array $blocked, int $hours ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-admin-users"></span><h2>' . esc_html__( 'Top offender IPs', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		if ( empty( $ips ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'No traffic recorded in this window.', 'ini-protector' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'IP', 'ini-protector' ), __( 'Requests', 'ini-protector' ), __( 'Suspicious', 'ini-protector' ), __( '404s', 'ini-protector' ), __( 'Logins', 'ini-protector' ), __( 'Last seen', 'ini-protector' ), '' ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $ips as $row ) {
				$ip          = (string) ( $row['ip'] ?? '' );
				$is_blocked  = isset( $blocked[ $ip ] );
				$verdict     = (string) ( $row['verdict'] ?? 'clean' );
				echo '<tr>';
				printf( '<td><a class="secwp-ip-link" href="%s"><code>%s</code></a>', esc_url( $this->ip_url( $ip, $hours ) ), esc_html( $ip ) );
				// Same verdict the detail page shows; skip the badge for 'clean' to keep the list calm.
				if ( 'clean' !== $verdict ) {
					echo ' ' . $this->verdict_badge( $verdict ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
				}
				echo '</td>';
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['requests'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['suspicious'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['not_found'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['login_attempts'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', esc_html( (string) ( $row['last_seen'] ?? '' ) ) );
				echo '<td>' . $this->ip_action_button( $ip, $is_blocked, $hours ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* below.
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	private function render_top_paths( array $paths ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-warning"></span><h2>' . esc_html__( 'Suspicious paths', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		if ( empty( $paths ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'Nothing suspicious in this window.', 'ini-protector' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'Path', 'ini-protector' ), __( 'Reason', 'ini-protector' ), __( 'Hits', 'ini-protector' ), __( 'IPs', 'ini-protector' ) ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $paths as $row ) {
				echo '<tr>';
				printf( '<td><code>%s</code></td>', esc_html( $this->trim_str( (string) ( $row['path'] ?? '' ), 80 ) ) );
				printf( '<td><code>%s</code></td>', esc_html( (string) ( $row['reason'] ?? '' ) ) );
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['hits'] ?? 0 ) ) ) );
				printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['ips'] ?? 0 ) ) ) );
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	private function render_recent( array $recent ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-list-view"></span><h2>' . esc_html__( 'Recent suspicious requests', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		if ( empty( $recent ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'None recorded.', 'ini-protector' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'Time', 'ini-protector' ), __( 'IP', 'ini-protector' ), __( 'Method', 'ini-protector' ), __( 'Path', 'ini-protector' ), __( 'Status', 'ini-protector' ), __( 'Reason', 'ini-protector' ), __( 'User agent', 'ini-protector' ) ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $recent as $row ) {
				echo '<tr>';
				printf( '<td>%s</td>', esc_html( (string) ( $row['created_at'] ?? '' ) ) );
				printf( '<td><code>%s</code></td>', esc_html( (string) ( $row['ip'] ?? '' ) ) );
				printf( '<td>%s</td>', esc_html( (string) ( $row['method'] ?? '' ) ) );
				printf( '<td><code>%s</code></td>', esc_html( $this->trim_str( (string) ( $row['path'] ?? '' ), 60 ) ) );
				printf( '<td>%s</td>', esc_html( (string) ( $row['status'] ?? '' ) ) );
				printf( '<td><code>%s</code></td>', esc_html( (string) ( $row['reason'] ?? '' ) ) );
				printf( '<td class="secwp-ua">%s</td>', esc_html( $this->trim_str( (string) ( $row['user_agent'] ?? '' ), 60 ) ) );
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	/**
	 * The full blocklist + manual-add now live on the dedicated INI Protector → IP
	 * Block page (alongside system suggestions). The Traffic page keeps only the
	 * per-row Block buttons (block-in-place while investigating) and a pointer.
	 */
	private function render_blocklist_link(): void {
		printf(
			'<p class="secwp-blocklist-link"><a class="button" href="%s"><span class="dashicons dashicons-shield" style="vertical-align:text-bottom;"></span> %s</a></p>',
			esc_url( add_query_arg( array( 'page' => SecurityWP_IP_Block_Admin::SLUG ), admin_url( 'admin.php' ) ) ),
			esc_html__( 'Manage blocked IPs & suggestions', 'ini-protector' )
		);
	}

	private function render_clear( int $hours ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Clear the entire traffic log?', 'ini-protector' ) ); ?>');" style="margin-top:8px;">
			<input type="hidden" name="action" value="secwp_traffic_action" />
			<input type="hidden" name="do" value="clear" />
			<input type="hidden" name="hours" value="<?php echo esc_attr( (string) $hours ); ?>" />
			<?php wp_nonce_field( 'secwp_traffic_action' ); ?>
			<button type="submit" class="button"><?php esc_html_e( 'Clear traffic log', 'ini-protector' ); ?></button>
		</form>
		<?php
	}

	/* --------------------------------------------------------------------- */
	/* Single-IP drill-down                                                   */
	/* --------------------------------------------------------------------- */

	private function render_ip_detail( string $ip, int $hours ): void {
		$enabled = class_exists( 'SecurityWP_Features' ) && SecurityWP_Features::is_on( 'traffic_log' );
		$profile = class_exists( 'SecurityWP_Traffic_Log' ) ? SecurityWP_Traffic_Log::profile_ip( $ip, $hours ) : array( 'enabled' => false );
		$blocked = SecurityWP_IP_Block::all();
		$is_blocked = isset( $blocked[ $ip ] );

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-visibility"></span> ' . esc_html__( 'IP activity', 'ini-protector' ) . '</h1>';
		$this->notice();

		// Back link + the live window (window labels reflect the actual clamp to 14-day retention).
		printf(
			'<p class="secwp-window"><a class="button" href="%s">%s</a></p>',
			esc_url( add_query_arg( array( 'page' => self::SLUG, 'hours' => $hours ), admin_url( 'admin.php' ) ) ),
			esc_html__( '← Back to traffic overview', 'ini-protector' )
		);

		// Header: the IP, its verdict, the window, and the primary Block/Unblock action.
		$totals  = $profile['totals'] ?? array();
		$verdict = $profile['verdict'] ?? array( 'level' => 'clean', 'signals' => array() );
		$win_h   = (int) ( $profile['window_hours'] ?? $hours );

		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body secwp-ip-head">';
		echo '<div class="secwp-ip-id"><code class="secwp-ip-big">' . esc_html( $ip ) . '</code> ' . $this->verdict_badge( (string) $verdict['level'] ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- badge built from esc_* below.
		$keeps_forever = class_exists( 'SecurityWP_Traffic_Log' ) && SecurityWP_Traffic_Log::keeps_forever();
		$retention     = class_exists( 'SecurityWP_Traffic_Log' ) ? SecurityWP_Traffic_Log::retention_days() : 14;
		printf(
			'<div class="secwp-ip-sub">%s</div>',
			esc_html( $keeps_forever
				? sprintf(
					/* translators: 1: request count, 2: window in hours. Nothing is pruned by age. */
					__( '%1$s requests · last %2$d h (history kept indefinitely)', 'ini-protector' ),
					number_format_i18n( (int) ( $totals['requests'] ?? 0 ) ),
					$win_h
				)
				: sprintf(
					/* translators: 1: request count, 2: window in hours, 3: retention in days */
					__( '%1$s requests · last %2$d h (max %3$d-day history)', 'ini-protector' ),
					number_format_i18n( (int) ( $totals['requests'] ?? 0 ) ),
					$win_h,
					$retention
				)
			)
		);
		echo '<div class="secwp-ip-action">';
		echo $is_blocked ? $this->unblock_button( $ip, $ip ) : $this->ip_action_button( $ip, false, $hours, $ip ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helpers.
		echo '</div>';
		echo '</div></div>';

		if ( empty( $profile['enabled'] ) || (int) ( $totals['requests'] ?? 0 ) === 0 ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body"><p class="secwp-empty">';
			echo $enabled
				? esc_html__( 'No activity recorded for this IP in this window.', 'ini-protector' )
				: esc_html__( 'The traffic monitor is off, so no activity is recorded.', 'ini-protector' );
			echo '</p></div></div></div>';
			return;
		}

		// Window switcher scoped to this IP.
		$labels = self::window_labels();
		echo '<p class="secwp-window">';
		foreach ( self::windows() as $w ) {
			printf(
				'<a class="button %s" href="%s">%s</a> ',
				$w === $hours ? 'button-primary' : '',
				esc_url( $this->ip_url( $ip, $w ) ),
				esc_html( $labels[ $w ] )
			);
		}
		echo '</p>';

		$this->verdict_legend();

		// Why-this-verdict signals.
		if ( ! empty( $verdict['signals'] ) ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-flag"></span><h2>' . esc_html__( 'Why this looks suspicious', 'ini-protector' ) . '</h2></div><div class="secwp-card-body"><ul class="secwp-signals">';
			foreach ( $verdict['signals'] as $sig ) {
				echo '<li>' . esc_html( (string) $sig ) . '</li>';
			}
			echo '</ul></div></div>';
		}

		$this->render_ip_facts( $totals );
		$this->render_ip_breakdown( __( 'Status codes', 'ini-protector' ), 'dashicons-chart-bar', $profile['statuses'] ?? array(), 'status' );
		$this->render_ip_breakdown( __( 'Suspicious reasons', 'ini-protector' ), 'dashicons-warning', $profile['reasons'] ?? array(), 'reason' );
		$this->render_ip_paths( $profile['paths'] ?? array() );
		$this->render_ip_uas( $profile['user_agents'] ?? array() );
		$this->render_ip_timeline( $profile['timeline'] ?? array() );

		echo '</div>';
	}

	private function render_ip_facts( array $t ): void {
		$cards = array(
			'requests'       => __( 'Requests', 'ini-protector' ),
			'suspicious'     => __( 'Suspicious', 'ini-protector' ),
			'not_found'      => __( '404s', 'ini-protector' ),
			'login_attempts' => __( 'Login attempts', 'ini-protector' ),
			'distinct_paths' => __( 'Paths', 'ini-protector' ),
			'distinct_uas'   => __( 'User agents', 'ini-protector' ),
		);
		echo '<div class="secwp-totals secwp-totals-6">';
		foreach ( $cards as $k => $label ) {
			printf(
				'<div class="secwp-stat"><div class="secwp-stat-n">%s</div><div class="secwp-stat-l">%s</div></div>',
				esc_html( number_format_i18n( (int) ( $t[ $k ] ?? 0 ) ) ),
				esc_html( $label )
			);
		}
		echo '</div>';
		printf(
			'<p class="secwp-seen">%s</p>',
			esc_html( sprintf(
				/* translators: 1: first-seen datetime, 2: last-seen datetime */
				__( 'First seen %1$s · last seen %2$s', 'ini-protector' ),
				(string) ( $t['first_seen'] ?? '—' ),
				(string) ( $t['last_seen'] ?? '—' )
			) )
		);
	}

	/** A small two-column "value → hits" table for status-code and reason histograms. */
	private function render_ip_breakdown( string $title, string $icon, array $rows, string $key ): void {
		if ( empty( $rows ) ) {
			return;
		}
		printf( '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons %s"></span><h2>%s</h2></div><div class="secwp-card-body">', esc_attr( $icon ), esc_html( $title ) );
		echo '<table class="widefat striped"><thead><tr>';
		printf( '<th>%s</th><th>%s</th>', esc_html( ucfirst( $key ) ), esc_html__( 'Hits', 'ini-protector' ) );
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$val = (string) ( $row[ $key ] ?? '' );
			printf(
				'<tr><td><code>%s</code></td><td>%s</td></tr>',
				esc_html( '' === $val ? '—' : $val ),
				esc_html( number_format_i18n( (int) ( $row['hits'] ?? 0 ) ) )
			);
		}
		echo '</tbody></table></div></div>';
	}

	private function render_ip_paths( array $paths ): void {
		if ( empty( $paths ) ) {
			return;
		}
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-admin-links"></span><h2>' . esc_html__( 'Top paths', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Path', 'ini-protector' ), __( 'Hits', 'ini-protector' ), __( 'Suspicious', 'ini-protector' ) ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $paths as $row ) {
			echo '<tr>';
			printf( '<td><code>%s</code></td>', esc_html( $this->trim_str( (string) ( $row['path'] ?? '' ), 90 ) ) );
			printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['hits'] ?? 0 ) ) ) );
			printf( '<td>%s</td>', esc_html( number_format_i18n( (int) ( $row['suspicious'] ?? 0 ) ) ) );
			echo '</tr>';
		}
		echo '</tbody></table></div></div>';
	}

	private function render_ip_uas( array $uas ): void {
		if ( empty( $uas ) ) {
			return;
		}
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-id"></span><h2>' . esc_html__( 'User agents', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		echo '<table class="widefat striped"><thead><tr>';
		printf( '<th>%s</th><th>%s</th>', esc_html__( 'User agent', 'ini-protector' ), esc_html__( 'Hits', 'ini-protector' ) );
		echo '</tr></thead><tbody>';
		foreach ( $uas as $row ) {
			$ua = (string) ( $row['user_agent'] ?? '' );
			printf(
				'<tr><td class="secwp-ua">%s</td><td>%s</td></tr>',
				esc_html( '' === $ua ? __( '(empty)', 'ini-protector' ) : $this->trim_str( $ua, 110 ) ),
				esc_html( number_format_i18n( (int) ( $row['hits'] ?? 0 ) ) )
			);
		}
		echo '</tbody></table></div></div>';
	}

	private function render_ip_timeline( array $rows ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-clock"></span><h2>' . esc_html__( 'Request timeline', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		if ( empty( $rows ) ) {
			echo '<p class="secwp-empty">' . esc_html__( 'No requests in this window.', 'ini-protector' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'Time', 'ini-protector' ), __( 'Method', 'ini-protector' ), __( 'Path', 'ini-protector' ), __( 'Status', 'ini-protector' ), __( 'Reason', 'ini-protector' ), __( 'User agent', 'ini-protector' ) ) as $h ) {
				echo '<th>' . esc_html( $h ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				$susp = ! empty( $row['suspicious'] );
				printf( '<tr class="%s">', $susp ? 'secwp-row-susp' : '' );
				printf( '<td>%s</td>', esc_html( (string) ( $row['created_at'] ?? '' ) ) );
				printf( '<td>%s</td>', esc_html( (string) ( $row['method'] ?? '' ) ) );
				printf( '<td><code>%s</code></td>', esc_html( $this->trim_str( (string) ( $row['path'] ?? '' ), 70 ) ) );
				printf( '<td>%s</td>', esc_html( (string) ( $row['status'] ?? '' ) ) );
				printf( '<td><code>%s</code></td>', esc_html( (string) ( $row['reason'] ?? '' ) ) );
				printf( '<td class="secwp-ua">%s</td>', esc_html( $this->trim_str( (string) ( $row['user_agent'] ?? '' ), 60 ) ) );
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';
	}

	/** URL of the single-IP drill-down for a given window. */
	private function ip_url( string $ip, int $hours ): string {
		return add_query_arg(
			array( 'page' => self::SLUG, 'ip' => $ip, 'hours' => $hours ),
			admin_url( 'admin.php' )
		);
	}

	/** Verdict level → [ css-suffix, label ]. Single source for both the badge and the legend. */
	private function verdict_levels(): array {
		return array(
			'hostile'    => array( 'high', __( 'Hostile', 'ini-protector' ) ),
			'suspicious' => array( 'susp', __( 'Suspicious', 'ini-protector' ) ),
			'watch'      => array( 'medium', __( 'Watch', 'ini-protector' ) ),
			'clean'      => array( 'clean', __( 'Looks clean', 'ini-protector' ) ),
		);
	}

	private function verdict_badge( string $level ): string {
		$map = $this->verdict_levels();
		$m   = $map[ $level ] ?? $map['clean'];
		return sprintf( '<span class="secwp-badge secwp-badge-%s">%s</span>', esc_attr( $m[0] ), esc_html( $m[1] ) );
	}

	/**
	 * Expandable verdict legend for placement under the window bar. Collapsed = the four chips;
	 * expanded (<details>, no JS) = what each level means and what triggers it. The trigger copy
	 * mirrors SecurityWP_Traffic_Log::ip_verdict() thresholds — keep the two in sync if those change.
	 */
	private function verdict_legend(): void {
		$levels = $this->verdict_levels();
		// Order worst → safest so the legend reads as a severity ladder.
		$explain = array(
			'hostile'    => __( 'Multiple abuse signals at once, or a severe one on its own — e.g. 50+ login attempts, 200+ suspicious requests. Strong block candidate.', 'ini-protector' ),
			'suspicious' => __( 'A clear abuse pattern: 50+ “not found” responses (scanning), 20+ login attempts (brute-force), 1,000+ requests (flooding), or many rotating user-agents. Worth investigating.', 'ini-protector' ),
			'watch'      => __( 'Some requests were flagged (a 404, an empty user-agent, a probe) but below any abuse threshold. Usually a stray bot — keep an eye on it.', 'ini-protector' ),
			'clean'      => __( 'Nothing flagged in this window — normal traffic.', 'ini-protector' ),
		);

		echo '<details class="secwp-legend">';
		echo '<summary class="secwp-legend-sum">';
		echo '<span class="secwp-legend-label">' . esc_html__( 'Verdict levels', 'ini-protector' ) . '</span> ';
		foreach ( $levels as $level => $m ) {
			echo $this->verdict_badge( $level ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput -- built from esc_* in helper.
		}
		echo '</summary>';
		echo '<ul class="secwp-legend-list">';
		foreach ( $explain as $level => $text ) {
			echo '<li>' . $this->verdict_badge( $level ) . ' <span class="secwp-legend-text">' . esc_html( $text ) . '</span></li>'; // phpcs:ignore WordPress.Security.EscapeOutput -- badge built from esc_* in helper; text escaped here.
		}
		echo '</ul>';
		echo '</details>';
	}

	private function ip_action_button( string $ip, bool $is_blocked, int $hours, string $return_ip = '' ): string {
		if ( $is_blocked ) {
			return '<span class="secwp-blocked-tag">' . esc_html__( 'Blocked', 'ini-protector' ) . '</span>';
		}
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
			<input type="hidden" name="action" value="secwp_traffic_action" />
			<input type="hidden" name="do" value="block" />
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>" />
			<input type="hidden" name="hours" value="<?php echo esc_attr( (string) $hours ); ?>" />
			<?php if ( '' !== $return_ip ) : ?>
				<input type="hidden" name="return_ip" value="<?php echo esc_attr( $return_ip ); ?>" />
			<?php endif; ?>
			<?php wp_nonce_field( 'secwp_traffic_action' ); ?>
			<button type="submit" class="button button-small"><?php esc_html_e( 'Block', 'ini-protector' ); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	private function unblock_button( string $ip, string $return_ip = '' ): string {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
			<input type="hidden" name="action" value="secwp_traffic_action" />
			<input type="hidden" name="do" value="unblock" />
			<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>" />
			<?php if ( '' !== $return_ip ) : ?>
				<input type="hidden" name="return_ip" value="<?php echo esc_attr( $return_ip ); ?>" />
			<?php endif; ?>
			<?php wp_nonce_field( 'secwp_traffic_action' ); ?>
			<button type="submit" class="button button-small"><?php esc_html_e( 'Unblock', 'ini-protector' ); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	private function trim_str( string $s, int $len ): string {
		$s = trim( $s );
		return strlen( $s ) > $len ? substr( $s, 0, $len - 1 ) . '…' : $s;
	}

	private function notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'blocked'         => array( 'success', __( 'IP blocked.', 'ini-protector' ) ),
			'unblocked'       => array( 'success', __( 'IP unblocked.', 'ini-protector' ) ),
			'clear_failed'    => array( 'error', __( 'Traffic history could not be cleared. Please try again or check database permissions.', 'ini-protector' ) ),
			'cleared'         => array( 'success', __( 'Traffic log cleared.', 'ini-protector' ) ),
			'saved'           => array( 'success', __( 'Retention settings saved.', 'ini-protector' ) ),
			'secwp_self_block'=> array( 'error', __( 'You can’t block your own current IP address.', 'ini-protector' ) ),
			'secwp_bad_ip'    => array( 'error', __( 'That is not a valid IP address.', 'ini-protector' ) ),
			'secwp_block_full'=> array( 'error', __( 'The blocklist is full.', 'ini-protector' ) ),
		);
		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
	}


}
