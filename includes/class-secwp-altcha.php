<?php
/**
 * ALTCHA proof-of-work captcha on the core auth forms (login, register, lost-password).
 *
 * Self-hosted and self-contained: the connector generates a challenge (a random salt and a secret
 * number; the widget must find the number whose SHA-256 of salt+number equals the published
 * challenge hash), and verifies the solution server-side. The challenge carries an HMAC signature
 * keyed by the site's salts, so a forged challenge can't be accepted. No external service, no API
 * keys, no Google — GDPR-friendly. Pairs with Limit Login Attempts.
 *
 * Config tweak key: 'altcha' (on/off; tune difficulty via the 'complexity' field).
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Altcha {

	const FIELD   = 'secwp_altcha';
	const MAX_AGE = 600; // A challenge solution is valid for 10 minutes.

	public function register(): void {
		// Render the widget on the three core forms.
		add_action( 'login_form', array( $this, 'render' ) );          // wp-login (sign in)
		add_action( 'register_form', array( $this, 'render' ) );       // registration
		add_action( 'lostpassword_form', array( $this, 'render' ) );   // lost password
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );

		// Verify on submit. authenticate runs for login; the others have dedicated hooks.
		add_filter( 'authenticate', array( $this, 'verify_login' ), 25, 1 );
		add_filter( 'registration_errors', array( $this, 'verify_register' ), 10, 1 );
		add_action( 'lostpassword_post', array( $this, 'verify_lostpassword' ), 10, 1 );
	}

	/** Difficulty: the secret number is drawn from [0, max). Higher = more bot CPU cost. */
	private function max_number(): int {
		$complexity = (int) SecurityWP_Features::get( 'altcha', 'complexity', 50000 );
		return max( 1000, min( 1000000, $complexity ) );
	}

	private function hmac_key(): string {
		return wp_salt( 'auth' ) . '|secwp-altcha';
	}

	// ── challenge ───────────────────────────────────────────────────────────────

	/** Build a fresh challenge payload (the data attributes the widget consumes). */
	private function make_challenge(): array {
		$ts = time();
		// The salt carries the issue time as an ALTCHA "param" (…?ts=). The widget echoes the salt
		// back verbatim in its solution, and our signature covers challenge+salt — so a solution
		// can't be replayed past MAX_AGE and the timestamp can't be forged.
		$salt   = bin2hex( random_bytes( 12 ) ) . '?ts=' . $ts;
		$secret = random_int( 0, $this->max_number() );
		$hash   = hash( 'sha256', $salt . $secret );
		$sig    = hash_hmac( 'sha256', $hash . '|' . $salt, $this->hmac_key() );
		return array(
			'algorithm' => 'SHA-256',
			'challenge' => $hash,
			'salt'      => $salt,
			'signature' => $sig,
			'maxnumber' => $this->max_number(),
		);
	}

	/** Extract the issue timestamp embedded in the salt (…?ts=NNN); 0 if absent. */
	private function salt_timestamp( string $salt ): int {
		if ( preg_match( '/[?&]ts=(\d+)/', $salt, $m ) ) {
			return (int) $m[1];
		}
		return 0;
	}

	/**
	 * Verify a solved-and-base64'd ALTCHA payload. Returns true if the proof is valid: signature
	 * authentic (we issued it), and SHA-256(salt+number) matches the challenge.
	 */
	private function check( string $solution ): bool {
		if ( '' === $solution ) {
			return false;
		}
		$json = base64_decode( $solution, true );
		if ( false === $json ) {
			return false;
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			return false;
		}
		foreach ( array( 'algorithm', 'challenge', 'salt', 'signature', 'number' ) as $k ) {
			if ( ! isset( $data[ $k ] ) ) {
				return false;
			}
		}
		if ( 'SHA-256' !== $data['algorithm'] ) {
			return false;
		}
		// 1) Signature must be one WE issued (authenticates challenge + salt, so the embedded
		//    timestamp can't be tampered with).
		$expected_sig = hash_hmac( 'sha256', (string) $data['challenge'] . '|' . (string) $data['salt'], $this->hmac_key() );
		if ( ! hash_equals( $expected_sig, (string) $data['signature'] ) ) {
			return false;
		}
		// 2) Reject stale challenges (replay window bound).
		$ts = $this->salt_timestamp( (string) $data['salt'] );
		if ( $ts <= 0 || ( time() - $ts ) > self::MAX_AGE ) {
			return false;
		}
		// 3) The solved number must actually hash to the challenge.
		$expected_hash = hash( 'sha256', $data['salt'] . $data['number'] );
		if ( ! hash_equals( $expected_hash, (string) $data['challenge'] ) ) {
			return false;
		}
		// 4) Single-use: a given solution (challenge hash) can be accepted once, within MAX_AGE.
		$used_key = 'secwp_altcha_' . md5( (string) $data['challenge'] );
		if ( get_transient( $used_key ) ) {
			return false;
		}
		set_transient( $used_key, 1, self::MAX_AGE );
		return true;
	}

	private function solution_from_post(): string {
		return isset( $_POST[ self::FIELD ] ) ? (string) wp_unslash( $_POST[ self::FIELD ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput
	}

	// ── render + assets ─────────────────────────────────────────────────────────

	public function enqueue(): void {
		// Bundled ALTCHA widget (no external CDN). The widget is an ES MODULE (it ends with
		// `export {...}` and uses import) — it MUST be loaded with type="module" or the browser
		// throws on the export/import and never registers the <altcha-widget> custom element (so
		// the widget never appears). We add type="module" via script_loader_tag below.
		wp_enqueue_script( 'secwp-altcha', SECWP_PLUGIN_URL . 'assets/altcha.min.js', array(), SECWP_VERSION, true );
		add_filter( 'script_loader_tag', array( $this, 'module_script_tag' ), 10, 3 );

		wp_enqueue_style( 'secwp-altcha', false, array(), SECWP_VERSION );
		wp_add_inline_style(
			'secwp-altcha',
			'.secwp-altcha{margin:0 0 16px}altcha-widget{--altcha-border-radius:4px;--altcha-max-width:100%;display:block}'
		);
	}

	/** Force type="module" on our ALTCHA script (the widget is an ES module). */
	public function module_script_tag( string $tag, string $handle, string $src ): string {
		if ( 'secwp-altcha' !== $handle ) {
			return $tag;
		}
		return wp_get_script_tag( array( 'type' => 'module', 'src' => $src, 'id' => 'secwp-altcha-js' ) );
	}

	public function render(): void {
		$c = $this->make_challenge();
		// The widget POSTs the solved payload under our field name. challengejson is the
		// self-contained challenge so no callback URL is needed.
		printf(
			'<div class="secwp-altcha"><altcha-widget name="%s" challengejson="%s"></altcha-widget></div>',
			esc_attr( self::FIELD ),
			esc_attr( wp_json_encode( $c ) )
		);
	}

	// ── verification hooks ──────────────────────────────────────────────────────

	/** Login: block authentication if the proof is missing/invalid. */
	public function verify_login( $user ) {
		// Only gate actual login POSTs (not programmatic calls or cookie auth).
		if ( empty( $_POST ) || ! isset( $_POST['log'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return $user;
		}
		if ( ! $this->check( $this->solution_from_post() ) ) {
			return new WP_Error( 'secwp_altcha', __( '<strong>Error:</strong> Please complete the verification challenge.', 'ini-protector' ) );
		}
		return $user;
	}

	/** Registration: append an error if the proof is missing/invalid. */
	public function verify_register( $errors ) {
		if ( ! $this->check( $this->solution_from_post() ) ) {
			if ( is_wp_error( $errors ) ) {
				$errors->add( 'secwp_altcha', __( '<strong>Error:</strong> Please complete the verification challenge.', 'ini-protector' ) );
			}
		}
		return $errors;
	}

	/** Lost password: attach an error so WP halts the reset. */
	public function verify_lostpassword( $errors ): void {
		if ( ! $this->check( $this->solution_from_post() ) && is_wp_error( $errors ) ) {
			$errors->add( 'secwp_altcha', __( '<strong>Error:</strong> Please complete the verification challenge.', 'ini-protector' ) );
		}
	}
}
