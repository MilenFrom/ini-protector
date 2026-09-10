<?php
/**
 * INI Protector → Vulnerabilities admin page + dashboard notice.
 *
 * Surfaces the Vulnerability Scan findings for site owners who are NOT on the
 * INI WP platform: a findings table (component, type, installed, severity, CVE,
 * fixed-in, update-available), a "Scan now" button, a dismissible admin notice,
 * and a count bubble on the submenu item.
 *
 * Renders SecurityWP_Vuln_Scan::get_results() (the same snapshot the platform
 * pulls), so there is one source of truth. Mirrors SecurityWP_Traffic_Admin and
 * reuses its shared .secwp-* CSS / .secwp-badge-* severity colours.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Vuln_Admin {

	const SLUG = 'ini-protector-vulnerabilities';
	const CAP  = 'manage_options';

	private $page_hook = '';

	public function __construct() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_menu', array( $this, 'menu' ), 20 );
		add_action( 'admin_post_secwp_vuln_action', array( $this, 'handle_action' ) );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	public function enqueue( string $hook ): void {
		if ( $hook !== $this->page_hook ) {
			return;
		}
		wp_enqueue_style( 'secwp-vuln-admin-css', SECWP_PLUGIN_URL . 'assets/vuln-admin.css', array(), SECWP_VERSION );
	}

	public function menu(): void {
		$title = __( 'Vulnerabilities', 'ini-protector' );
		// Count bubble (WP-native), like Plugins/Updates, when there are findings.
		$total = SecurityWP_Features::is_on( 'vulnerability_scan' ) ? SecurityWP_Vuln_Scan::summary()['total'] : 0;
		$menu_title = $title;
		if ( $total > 0 ) {
			$menu_title .= ' <span class="awaiting-mod count-' . (int) $total . '"><span class="pending-count">' . (int) $total . '</span></span>';
		}

		$this->page_hook = add_submenu_page(
			'ini-protector',
			$title,
			$menu_title,
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
		check_admin_referer( 'secwp_vuln_action' );

		// "Scan now" is a POST form; "Dismiss" is a nonce'd GET link — accept either.
		$do  = isset( $_REQUEST['do'] ) ? sanitize_key( wp_unslash( $_REQUEST['do'] ) ) : '';
		$msg = 'invalid';

		switch ( $do ) {
			case 'scan':
				if ( SecurityWP_Features::is_on( 'vulnerability_scan' ) ) {
					( new SecurityWP_Vuln_Scan() )->run_scan( array( 'force' => true ) );
					$msg = 'scanned';
				} else {
					$msg = 'disabled';
				}
				break;
			case 'dismiss':
				// Persist the current finding-set digest; the banner stays hidden across
				// re-scans and reappears only when the finding set actually changes.
				update_option( SecurityWP_Vuln_Scan::OPT_DISMISS, SecurityWP_Vuln_Scan::dismiss_token(), false );
				$msg = 'dismissed';
				break;
		}

		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'secwp_msg' => $msg ), admin_url( 'admin.php' ) ) );
		exit;
	}

	/* --------------------------------------------------------------------- */
	/* Dashboard notice (shown on every admin screen)                         */
	/* --------------------------------------------------------------------- */

	public function notice(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		// Don't double up on our own page (the table already states the findings).
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ( 'dashboard' !== $screen->id && false === strpos( $screen->id, 'ini-protector' ) ) ) {
			return;
		}
		if ( $screen && false !== strpos( (string) $screen->id, self::SLUG ) ) {
			return;
		}
		if ( ! SecurityWP_Features::is_on( 'vulnerability_scan' ) ) {
			return;
		}

		$summary = SecurityWP_Vuln_Scan::summary();
		if ( $summary['total'] < 1 ) {
			return;
		}
		// Suppressed until the finding set changes (digest-keyed; survives re-scans).
		if ( SecurityWP_Vuln_Scan::is_dismissed() ) {
			return;
		}

		$urgent = $summary['critical'] + $summary['high'];
		$text   = $urgent > 0
			? sprintf(
				/* translators: 1: urgent count, 2: total count. */
				_n( 'INI Protector found %2$d known vulnerability on this site (%1$d high or critical).', 'INI Protector found %2$d known vulnerabilities on this site (%1$d high or critical).', $summary['total'], 'ini-protector' ),
				$urgent,
				$summary['total']
			)
			: sprintf(
				/* translators: %d: total count. */
				_n( 'INI Protector found %d known vulnerability on this site.', 'INI Protector found %d known vulnerabilities on this site.', $summary['total'], 'ini-protector' ),
				$summary['total']
			);

		echo '<div class="notice notice-error">';
		echo '<p><strong>' . esc_html__( 'INI Protector', 'ini-protector' ) . '</strong> — ' . esc_html( $text ) . '</p>';
		echo '<p>';
		printf(
			'<a class="button button-primary" href="%s">%s</a> ',
			esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ),
			esc_html__( 'Review vulnerabilities', 'ini-protector' )
		);
		// Persistent dismissal (our own, not the per-view X) so it stays gone until the set changes.
		printf(
			'<a class="button" href="%s">%s</a>',
			esc_url(
				wp_nonce_url(
					add_query_arg(
						array( 'action' => 'secwp_vuln_action', 'do' => 'dismiss' ),
						admin_url( 'admin-post.php' )
					),
					'secwp_vuln_action'
				)
			),
			esc_html__( 'Dismiss until something changes', 'ini-protector' )
		);
		echo '</p></div>';
	}

	/* --------------------------------------------------------------------- */
	/* Page render                                                            */
	/* --------------------------------------------------------------------- */

	public function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		$enabled = SecurityWP_Features::is_on( 'vulnerability_scan' );

		echo '<div class="wrap secwp-wrap">';
		echo '<h1 class="secwp-h1"><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'Vulnerabilities', 'ini-protector' ) . '</h1>';
		$this->page_notice();

		if ( ! $enabled ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body">';
			printf(
				'<p>%s</p><p><a class="button button-primary" href="%s">%s</a></p>',
				esc_html__( 'The vulnerability scan is off. Turn on “Vulnerability scan” to check your installed plugins, themes, and WordPress core against the free WPVulnerability database once a day.', 'ini-protector' ),
				esc_url( admin_url( 'admin.php?page=ini-protector' ) ),
				esc_html__( 'Go to settings', 'ini-protector' )
			);
			echo '</div></div></div>';
			return;
		}

		$results  = SecurityWP_Vuln_Scan::get_results();
		$summary  = SecurityWP_Vuln_Scan::summary();
		$findings = $results['findings'];

		$this->render_header( $results, $summary );

		// Surface a degraded scan so an empty table never silently reads as "all clear".
		if ( in_array( $results['scan_status'], array( 'partial', 'error' ), true ) && ! empty( $results['errors'] ) ) {
			$this->render_errors( $results['errors'] );
		}

		if ( empty( $findings ) ) {
			echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body"><p class="secwp-empty">';
			echo ( 'never' === $results['scan_status'] )
				? esc_html__( 'No scan has run yet. Click “Scan now” to check your components.', 'ini-protector' )
				: esc_html__( 'No known vulnerabilities found in your installed plugins, themes, or WordPress core. 🎉', 'ini-protector' );
			echo '</p></div></div></div>';
			return;
		}

		$this->render_table( $findings );
		echo '</div>';
	}

	private function render_header( array $results, array $summary ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-body secwp-ip-head">';

		echo '<div class="secwp-ip-id">';
		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $sev ) {
			if ( $summary[ $sev ] > 0 ) {
				printf(
					'<span class="secwp-badge %s">%s %d</span> ',
					esc_attr( $this->sev_class( $sev ) ),
					esc_html( ucfirst( $sev ) ),
					(int) $summary[ $sev ]
				);
			}
		}
		if ( 0 === $summary['total'] ) {
			echo '<span class="secwp-badge secwp-badge-clean">' . esc_html__( 'No findings', 'ini-protector' ) . '</span>';
		}
		echo '</div>';

		$when = $results['scanned_at']
			? sprintf(
				/* translators: %s: human time diff. */
				__( 'Last scan: %s ago', 'ini-protector' ),
				human_time_diff( (int) $results['scanned_at'], time() )
			)
			: __( 'Never scanned', 'ini-protector' );
		echo '<div class="secwp-ip-sub">' . esc_html( $when ) . '</div>';

		echo '<div class="secwp-ip-action">';
		$this->scan_button();
		echo '</div>';

		echo '</div></div>';
	}

	private function render_errors( array $errors ): void {
		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-info"></span><h2>' . esc_html__( 'Components that could not be checked', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		echo '<p class="secwp-empty">' . esc_html__( 'The database could not be reached for these components in the last scan, so they are neither confirmed safe nor flagged. They will be retried on the next scan.', 'ini-protector' ) . '</p>';
		echo '<ul class="secwp-signals">';
		foreach ( $errors as $component => $reason ) {
			printf( '<li><code>%s</code> — %s</li>', esc_html( (string) $component ), esc_html( (string) $reason ) );
		}
		echo '</ul></div></div>';
	}

	private function render_table( array $findings ): void {
		// Sort worst-first so the most urgent rows are at the top.
		usort(
			$findings,
			function ( $a, $b ) {
				return $this->sev_rank( $b['severity'] ?? 'unknown' ) <=> $this->sev_rank( $a['severity'] ?? 'unknown' );
			}
		);

		echo '<div class="secwp-card secwp-card-wide"><div class="secwp-card-head"><span class="dashicons dashicons-warning"></span><h2>' . esc_html__( 'Known vulnerabilities', 'ini-protector' ) . '</h2></div><div class="secwp-card-body">';
		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Component', 'ini-protector' ), __( 'Type', 'ini-protector' ), __( 'Installed', 'ini-protector' ), __( 'Severity', 'ini-protector' ), __( 'Reference', 'ini-protector' ), __( 'Fixed in', 'ini-protector' ), __( 'Update', 'ini-protector' ) ) as $h ) {
			echo '<th>' . esc_html( $h ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $findings as $f ) {
			$sev = (string) ( $f['severity'] ?? 'unknown' );
			echo '<tr>';
			printf(
				'<td><strong>%s</strong><div class="secwp-ua">%s</div></td>',
				esc_html( (string) ( $f['name'] ?? $f['slug'] ?? '' ) ),
				esc_html( $this->trim_str( (string) ( $f['title'] ?? '' ), 90 ) )
			);
			printf( '<td>%s</td>', esc_html( ucfirst( (string) ( $f['type'] ?? '' ) ) ) );
			printf( '<td><code>%s</code></td>', esc_html( (string) ( $f['installed'] ?? '' ) ) );
			printf( '<td><span class="secwp-badge %s">%s</span></td>', esc_attr( $this->sev_class( $sev ) ), esc_html( ucfirst( $sev ) ) );

			// Reference (CVE) — linked when we have a URL.
			$ref = (string) ( $f['source'] ?? '' );
			if ( '' !== $ref && ! empty( $f['source_url'] ) ) {
				printf( '<td><a href="%s" target="_blank" rel="noopener noreferrer"><code>%s</code></a></td>', esc_url( (string) $f['source_url'] ), esc_html( $ref ) );
			} else {
				printf( '<td><code>%s</code></td>', esc_html( '' === $ref ? '—' : $ref ) );
			}

			printf( '<td>%s</td>', esc_html( '' !== (string) ( $f['fixed_in'] ?? '' ) ? (string) $f['fixed_in'] : '—' ) );

			if ( ! empty( $f['update_avail'] ) ) {
				printf( '<td><a class="button button-small button-primary" href="%s">%s</a></td>', esc_url( admin_url( 'update-core.php' ) ), esc_html__( 'Available', 'ini-protector' ) );
			} else {
				echo '<td><span class="secwp-empty">' . esc_html__( 'none', 'ini-protector' ) . '</span></td>';
			}
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '<p class="secwp-seen">' . esc_html__( 'Data from the WPVulnerability database (CC0). A finding means your installed version is within a known-affected range — update to the “Fixed in” version (or later) to clear it.', 'ini-protector' ) . '</p>';
		echo '</div></div>';
	}

	private function scan_button(): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
			<input type="hidden" name="action" value="secwp_vuln_action" />
			<input type="hidden" name="do" value="scan" />
			<?php wp_nonce_field( 'secwp_vuln_action' ); ?>
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Scan now', 'ini-protector' ); ?></button>
		</form>
		<?php
	}

	/* --------------------------------------------------------------------- */
	/* Helpers                                                                */
	/* --------------------------------------------------------------------- */

	/** Severity → shared badge CSS class. critical reuses the strongest (red) badge. */
	private function sev_class( string $sev ): string {
		switch ( $sev ) {
			case 'critical':
			case 'high':
				return 'secwp-badge-high';
			case 'medium':
				return 'secwp-badge-susp';
			case 'low':
				return 'secwp-badge-medium';
			default:
				return 'secwp-badge-clean';
		}
	}

	private function sev_rank( string $sev ): int {
		$map = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'unknown' => 0 );
		return $map[ $sev ] ?? 0;
	}

	private function trim_str( string $s, int $len ): string {
		$s = trim( $s );
		return strlen( $s ) > $len ? substr( $s, 0, $len - 1 ) . '…' : $s;
	}

	private function page_notice(): void {
		if ( empty( $_GET['secwp_msg'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$msg = sanitize_key( wp_unslash( $_GET['secwp_msg'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map = array(
			'scanned'   => array( 'success', __( 'Scan complete.', 'ini-protector' ) ),
			'dismissed' => array( 'success', __( 'Alert dismissed until the findings change.', 'ini-protector' ) ),
			'disabled'  => array( 'error', __( 'Turn on the vulnerability scan first.', 'ini-protector' ) ),
		);
		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
	}

	/**
	 * Page styles. Reuses the Traffic page's shared .secwp-* design (cards, badges,
	 * header). Defined here too so the page is self-contained whether or not the
	 * Traffic page rendered its block on the same request.
	 */

}
