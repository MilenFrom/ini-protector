<?php
/**
 * Off-server alerting for file integrity monitoring.
 *
 * This is the part of the feature that actually catches an attacker. Everything
 * the scanner stores — baseline table, snapshot option, history — sits on a box
 * the attacker may own; a report that has already left it does not.
 *
 * dispatch() is therefore called BEFORE the baseline is updated, and reports
 * precisely which channels delivered, so the scanner can decline to adopt a
 * change set nobody was told about.
 *
 * Every message carries:
 *   • a monotonic report number — a gap means a report was suppressed;
 *   • the previous and current state digests — a mismatch against the digest in
 *     the previous message means the on-server baseline was rewritten.
 * Both are verifiable from the mailbox alone, trusting nothing on the server.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Integrity_Alert {

	const WEBHOOK_TIMEOUT = 10;

	/**
	 * Send the report on every configured channel.
	 *
	 * @param array $report  The scan report (without the alert key filled in).
	 * @param array $changes Full change list (the report's copy may be truncated).
	 * @return array{attempted:bool,configured:bool,delivered:bool,channels:array<string,string>}
	 */
	public static function dispatch( array $report, array $changes ): array {
		$result = array(
			'attempted'  => false,
			'configured' => false,
			'delivered'  => false,
			'channels'   => array(),
		);

		$email_on = (bool) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'email_alert', true );
		$webhook  = trim( (string) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'webhook_url', '' ) );

		if ( $email_on ) {
			$result['configured']        = true;
			$result['attempted']         = true;
			$sent                        = self::send_email( $report, $changes );
			$result['channels']['email'] = $sent ? 'sent' : 'failed';
			$result['delivered']         = $result['delivered'] || $sent;
		}

		// Note: deliberately NOT gated on wp_http_validate_url(). That helper refuses
		// any host that does not resolve publicly and any private-range address, so
		// an internal collector (10.x, a .local box) would be skipped in silence —
		// and a channel that is configured but silently never used is exactly the
		// failure this feature exists to prevent. The URL is set by an admin, not by
		// a visitor, so the SSRF reasoning behind that helper does not apply. A bad
		// URL surfaces as a FAILED channel, which is visible everywhere.
		if ( '' !== $webhook ) {
			$result['configured']          = true;
			$result['attempted']           = true;
			$sent                          = self::send_webhook( $webhook, $report, $changes );
			$result['channels']['webhook'] = $sent ? 'sent' : 'failed';
			$result['delivered']           = $result['delivered'] || $sent;
		}

		/**
		 * Fires when an integrity change set is dispatched off-server.
		 *
		 * Use this to add a channel of your own (SMS, Slack, syslog). Anything
		 * hooked here runs before the baseline is updated.
		 *
		 * @param array $report
		 * @param array $changes
		 * @param array $result
		 */
		do_action( 'secwp_integrity_alert', $report, $changes, $result );

		return $result;
	}

	/* --------------------------------------------------------------------- */
	/* Email                                                                  */
	/* --------------------------------------------------------------------- */

	private static function recipient(): string {
		$to = sanitize_email( (string) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'email_to', '' ) );
		if ( '' === $to || ! is_email( $to ) ) {
			$to = (string) get_option( 'admin_email' );
		}
		return $to;
	}

	private static function send_email( array $report, array $changes ): bool {
		$to = self::recipient();
		if ( '' === $to || ! is_email( $to ) ) {
			return false;
		}

		$site   = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$counts = $report['counts'];

		$subject = sprintf(
			/* translators: 1: site name, 2: new count, 3: modified count, 4: deleted count. */
			__( '[%1$s] File integrity alert: %2$d new, %3$d modified, %4$d deleted', 'ini-protector' ),
			$site,
			(int) $counts['new'],
			(int) $counts['modified'],
			(int) $counts['deleted']
		);
		if ( ! empty( $counts['critical'] ) ) {
			$subject = sprintf(
				/* translators: 1: subject, 2: count of changes in critical locations. */
				__( '%1$s (%2$d in critical locations)', 'ini-protector' ),
				$subject,
				(int) $counts['critical']
			);
		}

		$headers = array(
			'Content-Type: text/plain; charset=UTF-8',
			'Auto-Submitted: auto-generated',
		);

		return (bool) wp_mail( $to, $subject, self::body( $report, $changes ), $headers );
	}

	/** Plain-text report body. Deliberately readable without any rendering. */
	public static function body( array $report, array $changes ): string {
		$counts = $report['counts'];
		$lines  = array();

		$lines[] = sprintf(
			/* translators: %s: site name. */
			__( 'INI Protector detected changes to code files on %s.', 'ini-protector' ),
			wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES )
		);
		$lines[] = home_url( '/' );
		$lines[] = '';
		/* translators: %d: sequential report number, used to spot a suppressed report */
		$lines[] = sprintf( __( 'Report number: %d', 'ini-protector' ), (int) $report['seq'] );
		$lines[] = sprintf(
			/* translators: 1: site-local time, 2: UTC time. */
			__( 'Detected at:   %1$s (site) / %2$s UTC', 'ini-protector' ),
			wp_date( 'Y-m-d H:i:s', (int) $report['scanned_at'] ),
			gmdate( 'Y-m-d H:i:s', (int) $report['scanned_at'] )
		);
		$lines[] = sprintf(
			/* translators: 1: new, 2: modified, 3: deleted, 4: total files hashed. */
			__( 'Changes:       %1$d new, %2$d modified, %3$d deleted (of %4$d files hashed)', 'ini-protector' ),
			(int) $counts['new'],
			(int) $counts['modified'],
			(int) $counts['deleted'],
			(int) ( $counts['files'] ?? 0 )
		);
		$lines[] = '';

		$critical = array_values(
			array_filter(
				$changes,
				static function ( $c ) {
					return ! empty( $c['critical'] );
				}
			)
		);
		if ( $critical ) {
			$lines[] = str_repeat( '=', 68 );
			$lines[] = __( 'CHANGES IN CRITICAL LOCATIONS', 'ini-protector' );
			$lines[] = __( '(WordPress core, wp-config.php, mu-plugins, .htaccess, theme functions, web root)', 'ini-protector' );
			$lines[] = str_repeat( '=', 68 );
			foreach ( array_slice( $critical, 0, SecurityWP_Integrity::MAIL_LIST_MAX ) as $c ) {
				$lines[] = self::format_change( $c );
			}
			if ( count( $critical ) > SecurityWP_Integrity::MAIL_LIST_MAX ) {
				/* translators: %d: number of further changed files not listed */
				$lines[] = sprintf( __( '  … and %d more.', 'ini-protector' ), count( $critical ) - SecurityWP_Integrity::MAIL_LIST_MAX );
			}
			$lines[] = '';
		}

		$other = array_values(
			array_filter(
				$changes,
				static function ( $c ) {
					return empty( $c['critical'] );
				}
			)
		);
		if ( $other ) {
			$budget  = max( 20, SecurityWP_Integrity::MAIL_LIST_MAX - count( $critical ) );
			$lines[] = str_repeat( '-', 68 );
			$lines[] = __( 'OTHER CHANGES', 'ini-protector' );
			$lines[] = str_repeat( '-', 68 );
			foreach ( array_slice( $other, 0, $budget ) as $c ) {
				$lines[] = self::format_change( $c );
			}
			if ( count( $other ) > $budget ) {
				/* translators: %d: number of further changed files not listed */
				$lines[] = sprintf( __( '  … and %d more (see the admin page).', 'ini-protector' ), count( $other ) - $budget );
			}
			$lines[] = '';
		}

		if ( ! empty( $report['unreadable'] ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of unreadable files. */
				__( 'Note: %d file(s) could not be read and were left in the baseline unchanged.', 'ini-protector' ),
				count( (array) $report['unreadable'] )
			);
			$lines[] = '';
		}
		if ( ! empty( $report['files_truncated'] ) ) {
			$lines[] = __( 'WARNING: the file limit was reached — part of the tree was NOT hashed. Raise the limit or narrow the scope.', 'ini-protector' );
			$lines[] = '';
		}

		$lines[] = str_repeat( '-', 68 );
		$lines[] = __( 'VERIFY THIS REPORT', 'ini-protector' );
		$lines[] = str_repeat( '-', 68 );
		$lines[] = __( 'These two lines let you check the reports against each other without', 'ini-protector' );
		$lines[] = __( 'trusting anything still on the server:', 'ini-protector' );
		$lines[] = '';
		$lines[] = '  ' . __( 'Previous state digest:', 'ini-protector' ) . ' ' . ( $report['prev_state_digest'] ? $report['prev_state_digest'] : '(none)' );
		$lines[] = '  ' . __( 'Current state digest: ', 'ini-protector' ) . ' ' . $report['state_digest'];
		$lines[] = '';
		$lines[] = __( '• The previous digest above must match the current digest printed in the', 'ini-protector' );
		$lines[] = __( '  last report you received. If it does not, the stored baseline was', 'ini-protector' );
		$lines[] = __( '  changed by something other than this scanner.', 'ini-protector' );
		$lines[] = __( '• Report numbers must not skip. A missing number means a report was', 'ini-protector' );
		$lines[] = __( '  suppressed before it left the server.', 'ini-protector' );
		$lines[] = '';
		$lines[] = __( 'Review the changes:', 'ini-protector' );
		$lines[] = admin_url( 'admin.php?page=' . SecurityWP_Integrity_Admin::SLUG );
		$lines[] = '';
		$lines[] = __( '— INI Protector', 'ini-protector' );

		return implode( "\n", $lines );
	}

	/** One change as a readable line (plus a detail line where it earns one). */
	private static function format_change( array $c ): string {
		$state = strtoupper( (string) ( $c['state'] ?? '' ) );
		$line  = sprintf( '  [%-8s] %s', $state, (string) ( $c['path'] ?? '' ) );

		$detail = array();
		if ( 'deleted' !== ( $c['state'] ?? '' ) ) {
			$detail[] = sprintf(
				/* translators: 1: byte size, 2: modification time. */
				__( '%1$s bytes, mtime %2$s', 'ini-protector' ),
				number_format_i18n( (int) ( $c['size'] ?? 0 ) ),
				gmdate( 'Y-m-d H:i:s', (int) ( $c['mtime'] ?? 0 ) )
			);
		}
		if ( ! empty( $c['timestomp'] ) ) {
			$detail[] = __( 'CONTENT CHANGED WITHOUT THE TIMESTAMP MOVING — the file rewrote itself or the mtime was forged', 'ini-protector' );
		}
		if ( ! empty( $c['hash'] ) ) {
			$detail[] = 'sha256 ' . substr( (string) $c['hash'], 0, 16 ) . '…';
		}

		if ( $detail ) {
			$line .= "\n" . '             ' . implode( ' · ', $detail );
		}
		return $line;
	}

	/* --------------------------------------------------------------------- */
	/* Webhook                                                                */
	/* --------------------------------------------------------------------- */

	/**
	 * The one destination a collector never legitimately lives at.
	 *
	 * Private ranges stay allowed on purpose — an internal collector on 10.x or a box on the LAN
	 * is a real deployment, and refusing it would silently disable the channel (see the note on
	 * wp_http_validate_url above). Link-local is different: 169.254.0.0/16 is the cloud metadata
	 * endpoint on every major host, it has no collector use, and it is the single address that
	 * turns "an admin picked a bad URL" into "an admin picked a URL that talks to the instance
	 * credentials". Nothing is lost by refusing it.
	 *
	 * This is defence in depth, not a boundary: the request is already POST-only, non-redirecting,
	 * and returns nothing but a 2xx/not-2xx boolean, and the URL can only be set by an
	 * administrator. It closes the one case where that boolean would be worth having.
	 */
	private static function is_link_local( string $host ): bool {
		$host = trim( $host, '[]' );
		if ( ! filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return false; // A name, not a literal. Resolution is the host's business, not ours.
		}
		if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return 0 === strpos( $host, '169.254.' );
		}
		$packed = @inet_pton( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return false;
		}
		// fe80::/10 — the first ten bits are 1111111010.
		$first  = ord( $packed[0] );
		$second = ord( $packed[1] );
		return 0xfe === $first && 0x80 === ( $second & 0xc0 );
	}

	private static function send_webhook( string $url, array $report, array $changes ): bool {
		$parts = wp_parse_url( $url );
		if ( empty( $parts['host'] ) || ! in_array( strtolower( (string) ( $parts['scheme'] ?? '' ) ), array( 'http', 'https' ), true ) ) {
			return false;
		}
		if ( self::is_link_local( (string) $parts['host'] ) ) {
			return false;
		}

		$payload = wp_json_encode(
			array(
				'source'            => 'ini-protector',
				'event'             => 'file_integrity_change',
				'site'              => home_url( '/' ),
				'seq'               => (int) $report['seq'],
				'detected_at'       => gmdate( 'c', (int) $report['scanned_at'] ),
				'counts'            => $report['counts'],
				'prev_state_digest' => (string) $report['prev_state_digest'],
				'state_digest'      => (string) $report['state_digest'],
				'files_truncated'   => (bool) $report['files_truncated'],
				'changes'           => array_slice( $changes, 0, SecurityWP_Integrity::REPORT_MAX ),
			)
		);
		if ( ! is_string( $payload ) ) {
			return false;
		}

		$headers = array(
			'Content-Type' => 'application/json; charset=utf-8',
			'User-Agent'   => 'INI Protector/' . SECWP_VERSION . '; ' . home_url(),
		);

		$secret = (string) SecurityWP_Features::get( SecurityWP_Integrity::FEATURE, 'webhook_secret', '' );
		if ( '' !== $secret ) {
			// Lets the receiver prove the report came from this site and was not edited.
			$headers['X-SecurityWP-Signature'] = 'sha256=' . hash_hmac( 'sha256', $payload, $secret );
		}

		$resp = wp_remote_post(
			$url,
			array(
				'timeout'     => self::WEBHOOK_TIMEOUT,
				'redirection' => 0,
				'blocking'    => true,
				'headers'     => $headers,
				'body'        => $payload,
			)
		);

		if ( is_wp_error( $resp ) ) {
			return false;
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		return $code >= 200 && $code < 300;
	}
}
