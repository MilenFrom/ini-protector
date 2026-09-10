<?php
/** Disposable WP only: wp eval-file bin/salt-regressions.php */
function inipr_salt_assert( $ok, $message ) {
 if ( ! $ok ) { throw new RuntimeException( $message ); }
 echo "PASS: $message\n";
}
function inipr_salt_private( $object, $method, ...$args ) {
 $r = new ReflectionMethod( $object, $method );
 $r->setAccessible( true );
 return $r->invoke( is_object( $object ) ? $object : null, ...$args );
}
require_once ABSPATH . 'wp-admin/includes/user.php';
$id = wp_create_user( 'salt-test-' . bin2hex( random_bytes( 4 ) ), wp_generate_password( 32 ) );
if ( is_wp_error( $id ) ) { throw new RuntimeException( 'Test user creation failed.' ); }
$old_map = get_option( 'secwp_author_tokens', false );
$phase = 'before';
$filter = static function ( $salt, $scheme ) use ( &$phase ) { return hash( 'sha512', $phase . '-test-only-' . $scheme ); };
add_filter( 'salt', $filter, 10, 2 );
$a = new SecurityWP_Author_Slugs();
$token = '';
try {
 $legacy = substr( hash( 'sha256', wp_salt( 'auth' ) . '|author|' . $id ), 0, 16 );
 update_option( 'secwp_author_tokens', array( $legacy => $id ) );
 SecurityWP_Author_Slugs::migrate_legacy_tokens();
 inipr_salt_assert( false === get_option( 'secwp_author_tokens', false ), 'legacy salt-derived state removed' );
 inipr_salt_assert( ! isset( $a->resolve_request( array( 'author_name' => $legacy ) )['author'] ), 'legacy URL rejected' );
 $link = $a->filter_author_link( 'http://example.test/author/test/', $id );
 $token = basename( $link );
 inipr_salt_private( $a, 'claim_option', SecurityWP_Author_Slugs::TOKEN_PREFIX . $id, str_repeat( 'b', 32 ) );
 inipr_salt_assert( get_option( SecurityWP_Author_Slugs::TOKEN_PREFIX . $id ) === $token, 'losing first-request insert cannot replace published token' );
 inipr_salt_assert( 1 === preg_match( '/^[a-f0-9]{32}$/D', $token ), 'independent 128-bit token generated' );
 inipr_salt_assert( $a->resolve_request( array( 'author_name' => $token ) )['author'] === $id, 'new author URL resolves' );
 $user = get_user_by( 'id', $id );
 $secret = SecurityWP_TOTP::generate_secret();
 SecurityWP_TOTP::set_secret( $id, $secret );
 $codes = SecurityWP_TOTP::confirm( $id, SecurityWP_TOTP::code_at( $secret, SecurityWP_TOTP::slot() ) );
 inipr_salt_assert( is_array( $codes ), 'TOTP enrolled before rotation' );
 $login = inipr_salt_private( 'SecurityWP_2FA', 'make_token', $user, false );
 inipr_salt_assert( null !== inipr_salt_private( 'SecurityWP_2FA', 'verify_token', $login ), 'original login challenge valid' );
 $gate = new SecurityWP_Password_Protect();
 $_COOKIE[ SecurityWP_Password_Protect::COOKIE ] = inipr_salt_private( $gate, 'expected_cookie' );
 inipr_salt_assert( inipr_salt_private( $gate, 'has_valid_cookie' ), 'original site-access cookie valid' );
 $altcha = new SecurityWP_Altcha();
 $challenge = inipr_salt_private( $altcha, 'make_challenge' );
 for ( $n = 0; $n <= $challenge['maxnumber']; ++$n ) {
  if ( hash( 'sha256', $challenge['salt'] . $n ) === $challenge['challenge'] ) { break; }
 }
 $challenge['number'] = $n;
 $solution = base64_encode( wp_json_encode( $challenge ) );
 // Do not consume the one-use challenge until testing rotation.
 $phase = 'after';
 inipr_salt_assert( $a->filter_author_link( 'http://example.test/author/test/', $id ) === $link, 'author link stable after salt rotation' );
 inipr_salt_assert( $a->resolve_request( array( 'author_name' => $token ) )['author'] === $id, 'author link still resolves after rotation' );
 $response = $a->filter_rest_user( new WP_REST_Response( array( 'slug' => 'test', 'link' => $link ) ), $user );
 inipr_salt_assert( $response->data['slug'] === $token, 'REST slug agrees with author URL' );
 foreach ( array( $legacy, 'test', array( $token ), $token . '/extra', str_repeat( 'a', 32 ) ) as $bad ) {
  inipr_salt_assert( ! isset( $a->resolve_request( array( 'author_name' => $bad ) )['author'] ), 'old, raw, malformed or unknown author identifier rejected' );
 }
 inipr_salt_assert( null === inipr_salt_private( 'SecurityWP_2FA', 'verify_token', $login ), 'old login challenge invalidated' );
 $fresh = inipr_salt_private( 'SecurityWP_2FA', 'make_token', $user, false );
 inipr_salt_assert( null !== inipr_salt_private( 'SecurityWP_2FA', 'verify_token', $fresh ), 'restarted login challenge valid' );
 inipr_salt_assert( ! inipr_salt_private( $gate, 'has_valid_cookie' ), 'old site-access cookie invalidated' );
 $_COOKIE[ SecurityWP_Password_Protect::COOKIE ] = inipr_salt_private( $gate, 'expected_cookie' );
 inipr_salt_assert( inipr_salt_private( $gate, 'has_valid_cookie' ), 'fresh site-access cookie valid' );
 inipr_salt_assert( ! inipr_salt_private( $altcha, 'check', $solution ), 'old ALTCHA proof rejected after rotation' );
 inipr_salt_assert( ! SecurityWP_TOTP::secret_readable( $id ), 'rotated salt cannot decrypt old TOTP secret' );
 inipr_salt_assert( SecurityWP_TOTP::is_enabled( $id ), 'unreadable TOTP never silently disables authentication' );
 inipr_salt_assert( ! SecurityWP_TOTP::verify_for_user( $id, SecurityWP_TOTP::code_at( $secret, SecurityWP_TOTP::slot() + 1 ) ), 'old authenticator code fails closed' );
 inipr_salt_assert( SecurityWP_TOTP::verify_recovery( $id, $codes[0] ), 'recovery code survives salt rotation' );
 inipr_salt_assert( ! SecurityWP_TOTP::verify_recovery( $id, $codes[0] ), 'recovery code cannot be reused' );
 SecurityWP_TOTP::disable( $id );
 $secret = SecurityWP_TOTP::generate_secret();
 SecurityWP_TOTP::set_secret( $id, $secret );
 inipr_salt_assert( is_array( SecurityWP_TOTP::confirm( $id, SecurityWP_TOTP::code_at( $secret, SecurityWP_TOTP::slot() ) ) ), 'reset and re-enrollment succeeds under new salts' );
 inipr_salt_assert( SecurityWP_TOTP::verify_for_user( $id, SecurityWP_TOTP::code_at( $secret, SecurityWP_TOTP::slot() + 1 ) ), 'new authenticator works after re-enrollment' );
} finally {
 remove_filter( 'salt', $filter, 10 );
 unset( $_COOKIE[ SecurityWP_Password_Protect::COOKIE ] );
 delete_option( SecurityWP_Author_Slugs::TOKEN_PREFIX . $id );
 if ( $token ) { delete_option( SecurityWP_Author_Slugs::OWNER_PREFIX . $token ); }
 delete_option( 'secwp_author_tokens' );
 if ( false !== $old_map ) { update_option( 'secwp_author_tokens', $old_map ); }
 wp_delete_user( $id );
}
echo "Salt regression tests passed.\n";
