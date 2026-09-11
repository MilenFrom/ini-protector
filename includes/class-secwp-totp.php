<?php
/**
 * TOTP (RFC 6238) engine and per-user 2FA storage.
 *
 * HMAC-SHA1 over a 30-second counter, 6 digits — the algorithm every standard
 * authenticator app implements. No external dependency: PHP's hash_hmac plus a
 * small base32 codec is the whole of it.
 *
 * Storage decisions worth knowing:
 *
 *  • The shared secret is ENCRYPTED at rest with a key derived from wp-config's
 *    salts, not stored in the clear. An attacker who can only read the database
 *    (SQL injection, a leaked dump, a stolen backup) then holds a ciphertext they
 *    cannot use, and cannot mint codes even after rewriting a password hash.
 *    Trade-off: rotating the site's salts makes existing secrets unreadable —
 *    users then sign in with a recovery code (or the WP-CLI break-glass) and
 *    re-enrol. secret_readable() detects that state so the UI can say so plainly
 *    instead of failing mysteriously. Encryption is mandatory: if it is not
 *    available, enrolment is refused rather than silently storing the seed in
 *    the clear, and any unencrypted seed left by an earlier version is
 *    re-encrypted the next time it is read.
 *
 *  • Recovery codes are stored as plain SHA-256 hashes, deliberately NOT with a
 *    slow password hash. They are 50-bit random tokens we generate, not
 *    human-chosen passwords, so there is nothing to brute-force offline; slow
 *    hashing would only make the login path slow.
 *
 *  • A used time step is remembered per user, so a code that was observed
 *    (shoulder-surfed, phished, read from a proxy log) cannot be replayed inside
 *    its own 30-second window.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_TOTP {

	const META_SECRET     = 'secwp_totp_secret';
	const META_ENABLED    = 'secwp_totp_enabled';
	const META_LAST_SLOT  = 'secwp_totp_last_slot';
	const META_RECOVERY   = 'secwp_2fa_recovery';
	const META_ENABLED_AT = 'secwp_2fa_enabled_at';

	/** RFC 6238 defaults — what every authenticator app assumes when the URI omits them. */
	const PERIOD = 30;
	const DIGITS = 6;
	/** Steps of clock skew accepted either side (±1 = ±30s). */
	const WINDOW = 1;
	/** 160-bit secret, the size RFC 4226 recommends for HMAC-SHA1. */
	const SECRET_BYTES = 20;

	const RECOVERY_COUNT  = 10;
	const RECOVERY_GROUP  = 5;
	const ENCRYPTED_PREFIX = 'secwp1:';

	/* --------------------------------------------------------------------- */
	/* Base32 (RFC 4648)                                                      */
	/* --------------------------------------------------------------------- */

	const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function base32_encode( string $bytes ): string {
		if ( '' === $bytes ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $bytes ) as $b ) {
			$bits .= str_pad( decbin( ord( $b ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32_ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	public static function base32_decode( string $b32 ): string {
		$b32 = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $b32 ) );
		if ( '' === $b32 ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( self::B32_ALPHABET, $b32[ $i ] );
			if ( false === $pos ) {
				return '';
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/* --------------------------------------------------------------------- */
	/* Codes                                                                  */
	/* --------------------------------------------------------------------- */

	/** A fresh random secret, base32 encoded (what the user scans or types). */
	public static function generate_secret(): string {
		return self::base32_encode( random_bytes( self::SECRET_BYTES ) );
	}

	/** The current time step. */
	public static function slot( ?int $timestamp = null ): int {
		$timestamp = null === $timestamp ? time() : $timestamp;
		return (int) floor( $timestamp / self::PERIOD );
	}

	/**
	 * The code for a given secret and time step (RFC 6238 / RFC 4226 truncation).
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $slot   Time step.
	 */
	public static function code_at( string $secret, int $slot ): string {
		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}
		// 64-bit big-endian counter.
		$counter = pack( 'J', $slot );
		$hash    = hash_hmac( 'sha1', $counter, $key, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$value  = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );

		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Check a code against a secret, allowing ±WINDOW steps of clock drift.
	 *
	 * @return int|false The matched time step, or false.
	 */
	public static function check_code( string $secret, string $code, ?int $now = null ) {
		$code = preg_replace( '/\D/', '', $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$current = self::slot( $now );
		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			$slot     = $current + $i;
			$expected = self::code_at( $secret, $slot );
			if ( '' !== $expected && hash_equals( $expected, $code ) ) {
				return $slot;
			}
		}
		return false;
	}

	/**
	 * Verify a code for an enrolled user, refusing replay of an already-used step.
	 *
	 * @return bool
	 */
	public static function verify_for_user( int $user_id, string $code ): bool {
		$secret = self::get_secret( $user_id );
		if ( '' === $secret ) {
			return false;
		}
		$slot = self::check_code( $secret, $code );
		if ( false === $slot ) {
			return false;
		}
		// A step is good exactly once: an observed code cannot be reused.
		$last = (int) get_user_meta( $user_id, self::META_LAST_SLOT, true );
		if ( $slot <= $last ) {
			return false;
		}
		update_user_meta( $user_id, self::META_LAST_SLOT, $slot );
		return true;
	}

	/**
	 * The otpauth:// URI an authenticator app consumes.
	 *
	 * Kept short on purpose: it has to fit in a QR the bundled encoder can
	 * actually produce, so the issuer is trimmed rather than the URI being built
	 * blindly and failing to render.
	 */
	public static function provisioning_uri( WP_User $user, string $secret, int $max_label = 40 ): string {
		$issuer = self::issuer();
		if ( strlen( $issuer ) > $max_label ) {
			$issuer = substr( $issuer, 0, $max_label );
		}
		$account = $user->user_login;
		if ( strlen( $account ) > $max_label ) {
			$account = substr( $account, 0, $max_label );
		}

		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			$secret,
			rawurlencode( $issuer )
		);
	}

	/** Label shown in the authenticator app. The site host, which is short and unambiguous. */
	public static function issuer(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! $host ) {
			$host = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		}
		/**
		 * Filter the issuer shown in the authenticator app.
		 *
		 * @param string $issuer
		 */
		return (string) apply_filters( 'secwp_2fa_issuer', (string) $host );
	}

	/* --------------------------------------------------------------------- */
	/* Per-user state                                                         */
	/* --------------------------------------------------------------------- */

	public static function is_enabled( int $user_id ): bool {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Store a pending secret (enrolment is only completed by confirm()).
	 *
	 * @return bool False when the secret could not be encrypted — nothing is
	 *              written, and the caller must abandon the enrolment rather
	 *              than leave an unusable or unprotected row behind.
	 */
	public static function set_secret( int $user_id, string $secret ): bool {
		$stored = self::encrypt( $secret );
		if ( null === $stored ) {
			return false;
		}
		update_user_meta( $user_id, self::META_SECRET, $stored );
		return true;
	}

	public static function get_secret( int $user_id ): string {
		$stored = (string) get_user_meta( $user_id, self::META_SECRET, true );
		if ( '' === $stored ) {
			return '';
		}
		// A row from a build that stored the seed unencrypted. Upgrade it in place
		// now that we can, so the at-rest guarantee becomes true for this user too.
		// Best effort: if it still cannot be encrypted the login must keep working.
		if ( 0 !== strpos( $stored, self::ENCRYPTED_PREFIX ) ) {
			self::set_secret( $user_id, $stored );
			return $stored;
		}
		return self::decrypt( $stored );
	}

	/**
	 * Is this user's stored secret still readable?
	 *
	 * False means it was encrypted under salts this site no longer has — the user
	 * must use a recovery code (or the CLI break-glass) and re-enrol.
	 */
	public static function secret_readable( int $user_id ): bool {
		$stored = (string) get_user_meta( $user_id, self::META_SECRET, true );
		if ( '' === $stored ) {
			return false;
		}
		return '' !== self::decrypt( $stored );
	}

	/**
	 * Complete enrolment: the user proved they hold the secret by entering a code.
	 *
	 * @return string[]|false Fresh recovery codes (plaintext, shown once), or false.
	 */
	public static function confirm( int $user_id, string $code ) {
		$secret = self::get_secret( $user_id );
		if ( '' === $secret ) {
			return false;
		}
		$slot = self::check_code( $secret, $code );
		if ( false === $slot ) {
			return false;
		}
		update_user_meta( $user_id, self::META_ENABLED, 1 );
		update_user_meta( $user_id, self::META_LAST_SLOT, $slot );
		update_user_meta( $user_id, self::META_ENABLED_AT, time() );

		do_action( 'secwp_2fa_enabled', $user_id );

		return self::generate_recovery_codes( $user_id );
	}

	/** Turn 2FA off and erase every trace of it for this user. */
	public static function disable( int $user_id ): void {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_LAST_SLOT );
		delete_user_meta( $user_id, self::META_RECOVERY );
		delete_user_meta( $user_id, self::META_ENABLED_AT );

		do_action( 'secwp_2fa_disabled', $user_id );
	}

	/* --------------------------------------------------------------------- */
	/* Recovery codes                                                         */
	/* --------------------------------------------------------------------- */

	/**
	 * Issue a fresh set, replacing any existing one.
	 *
	 * @return string[] Plaintext codes — the only time they are ever readable.
	 */
	public static function generate_recovery_codes( int $user_id ): array {
		$plain  = array();
		$hashes = array();

		for ( $i = 0; $i < self::RECOVERY_COUNT; $i++ ) {
			$raw = '';
			for ( $c = 0; $c < self::RECOVERY_GROUP * 2; $c++ ) {
				$raw .= self::B32_ALPHABET[ random_int( 0, 31 ) ];
			}
			$code     = substr( $raw, 0, self::RECOVERY_GROUP ) . '-' . substr( $raw, self::RECOVERY_GROUP );
			$plain[]  = $code;
			$hashes[] = self::hash_recovery( $code );
		}

		update_user_meta( $user_id, self::META_RECOVERY, $hashes );
		return $plain;
	}

	/** Consume a recovery code. Each one works exactly once. */
	public static function verify_recovery( int $user_id, string $code ): bool {
		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( ! is_array( $hashes ) || ! $hashes ) {
			return false;
		}
		$candidate = self::hash_recovery( $code );

		foreach ( $hashes as $i => $stored ) {
			if ( hash_equals( (string) $stored, $candidate ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_RECOVERY, array_values( $hashes ) );
				do_action( 'secwp_2fa_recovery_used', $user_id, count( $hashes ) );
				return true;
			}
		}
		return false;
	}

	public static function recovery_remaining( int $user_id ): int {
		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/** Normalise then hash. Case and dashes are noise the user should not have to get right. */
	private static function hash_recovery( string $code ): string {
		$norm = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', $code ) );
		return hash( 'sha256', $norm );
	}

	/* --------------------------------------------------------------------- */
	/* Secret encryption at rest                                              */
	/* --------------------------------------------------------------------- */

	/** 32-byte key derived from the site's wp-config salts (never stored in the DB). */
	private static function key(): string {
		$material = wp_salt( 'secure_auth' ) . '|secwp-2fa';
		return hash( 'sha256', $material, true );
	}

	/**
	 * Encrypt, or fail — never fall back to storing the seed in the clear.
	 *
	 * Earlier versions returned the plaintext when libsodium was missing or the
	 * call threw. That made the documented guarantee ("a database-only compromise
	 * cannot mint codes") conditional on something the reader could not see, and
	 * the verifier accepted the degraded value forever afterwards. In practice the
	 * branch was unreachable — WordPress has shipped the sodium_compat polyfill
	 * since 5.2 and we require 5.7 — so refusing costs nothing and the promise
	 * becomes true unconditionally.
	 *
	 * @return string|null Ciphertext, or null when it could not be protected.
	 */
	private static function encrypt( string $plain ): ?string {
		if ( '' === $plain ) {
			return '';
		}
		if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
			return null;
		}
		try {
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $plain, $nonce, self::key() );
		} catch ( Throwable $e ) {
			return null;
		}
		return self::ENCRYPTED_PREFIX . base64_encode( $nonce . $cipher );
	}

	/** Decrypt, tolerating a plaintext value written before/without libsodium. */
	private static function decrypt( string $stored ): string {
		if ( 0 !== strpos( $stored, self::ENCRYPTED_PREFIX ) ) {
			return $stored;
		}
		if ( ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
			return '';
		}
		$raw = base64_decode( substr( $stored, strlen( self::ENCRYPTED_PREFIX ) ), true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return '';
		}
		$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		try {
			$plain = sodium_crypto_secretbox_open( $cipher, $nonce, self::key() );
		} catch ( Exception $e ) {
			return '';
		}
		// false here means the salts changed (or the row was tampered with).
		return is_string( $plain ) ? $plain : '';
	}
}
