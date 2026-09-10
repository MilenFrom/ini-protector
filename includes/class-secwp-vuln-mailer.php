<?php
/**
 * New-finding email alert for the Vulnerability Scan.
 *
 * Opt-in (the feature's `email_alert` config field). Fires only for findings
 * that are genuinely NEW since the previous scan and that meet the configured
 * minimum severity — never on a repeat scan of the same vulnerabilities. Kept
 * separate from the scanner so run_scan() stays a pure data routine.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Vuln_Mailer {

	/** Severity → rank, for the minimum-severity gate. */
	private static function rank( string $severity ): int {
		$map = array(
			'critical' => 4,
			'high'     => 3,
			'medium'   => 2,
			'low'      => 1,
			'unknown'  => 0,
		);
		return $map[ $severity ] ?? 0;
	}

	/**
	 * Email the admin about new findings (opt-in, severity-filtered).
	 *
	 * @param array $new New finding rows (as built by SecurityWP_Vuln_Scan).
	 */
	public static function notify_new( array $new ): void {
		if ( ! SecurityWP_Features::is_on( 'vulnerability_scan' ) ) {
			return;
		}
		$cfg = (bool) SecurityWP_Features::get( 'vulnerability_scan', 'email_alert', false );
		if ( ! $cfg ) {
			return;
		}

		$threshold = self::rank( (string) SecurityWP_Features::get( 'vulnerability_scan', 'min_severity', 'high' ) );
		$relevant  = array_values(
			array_filter(
				$new,
				static function ( $f ) use ( $threshold ) {
					return self::rank( (string) ( $f['severity'] ?? 'unknown' ) ) >= $threshold;
				}
			)
		);
		if ( ! $relevant ) {
			return;
		}

		$to = sanitize_email( (string) SecurityWP_Features::get( 'vulnerability_scan', 'email_to', '' ) );
		if ( '' === $to || ! is_email( $to ) ) {
			$to = (string) get_option( 'admin_email' );
		}
		if ( '' === $to ) {
			return;
		}

		$site    = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$subject = sprintf(
			/* translators: 1: site name, 2: count of new findings. */
			_n( '[%1$s] %2$d new security vulnerability found', '[%1$s] %2$d new security vulnerabilities found', count( $relevant ), 'ini-protector' ),
			$site,
			count( $relevant )
		);

		$headers = array(
			'Content-Type: text/plain; charset=UTF-8',
			'Reply-To: ' . get_option( 'admin_email' ),
		);

		wp_mail( $to, $subject, self::body( $relevant ), $headers );
	}

	/** Plain-text email body. */
	private static function body( array $findings ): string {
		$lines = array();
		$lines[] = sprintf(
			/* translators: %s: site name. */
			__( 'INI Protector found new known vulnerabilities affecting components installed on %s:', 'ini-protector' ),
			wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES )
		);
		$lines[] = '';

		foreach ( $findings as $f ) {
			$lines[] = sprintf(
				'• [%s] %s %s (installed %s)',
				strtoupper( (string) ( $f['severity'] ?? 'unknown' ) ),
				ucfirst( (string) ( $f['type'] ?? '' ) ),
				(string) ( $f['name'] ?? $f['slug'] ?? '' ),
				(string) ( $f['installed'] ?? '?' )
			);
			if ( ! empty( $f['fixed_in'] ) ) {
				$lines[] = sprintf( '    %s %s', __( 'Fixed in:', 'ini-protector' ), $f['fixed_in'] );
			}
			if ( ! empty( $f['source'] ) ) {
				$lines[] = '    ' . trim( $f['source'] . ' ' . (string) ( $f['source_url'] ?? '' ) );
			}
			$lines[] = '';
		}

		$lines[] = __( 'Review and update these components:', 'ini-protector' );
		$lines[] = admin_url( 'admin.php?page=ini-protector-vulnerabilities' );
		$lines[] = '';
		$lines[] = __( '— INI Protector', 'ini-protector' );

		return implode( "\n", $lines );
	}
}
