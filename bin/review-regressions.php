<?php
/** Run with wp eval-file on a disposable test installation only. */
function inipr_assert( $condition, $message ) {
	if ( ! $condition ) { throw new RuntimeException( $message ); }
	echo "PASS: $message\n";
}
function inipr_private( $class, $method, ...$args ) {
	$m = new ReflectionMethod( $class, $method );
	$m->setAccessible( true );
	return $m->invoke( is_object( $class ) ? $class : null, ...$args );
}
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/template.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
wp_set_current_user( 1 );

// Migrate legacy data without enabling any feature, including stale salts from older wp-config values.
update_option( 'secwp_features', array() );
foreach ( array( str_repeat( 'x', 32 ) . AUTH_SALT, str_repeat( 'y', 32 ) . 'OLD-AUTH-SALT' ) as $legacy ) {
	delete_option( 'secwp_ver_salt_schema' );
	update_option( 'secwp_ver_salt', $legacy );
	SecurityWP_Tweaks::migrate_asset_version_salt();
	$clean = get_option( 'secwp_ver_salt' );
	inipr_assert( 1 === preg_match( '/^[a-f0-9]{64}$/D', $clean ) && $clean !== $legacy && false === strpos( $clean, AUTH_SALT ), 'legacy salt replaced by independent random value' );
	SecurityWP_Tweaks::migrate_asset_version_salt();
	inipr_assert( $clean === get_option( 'secwp_ver_salt' ), 'migration is idempotent' );
}
delete_option( 'secwp_ver_salt' ); delete_option( 'secwp_ver_salt_schema' );
SecurityWP_Tweaks::migrate_asset_version_salt();
inipr_assert( false === get_option( 'secwp_ver_salt', false ), 'unused feature does not create a salt' );
$before = SecurityWP_Tweaks::asset_version_fingerprint();
SecurityWP_Tweaks::rotate_asset_version_salt();
inipr_assert( $before !== SecurityWP_Tweaks::asset_version_fingerprint(), 'manual cache rotation still works' );

// Plain multiline settings remain usable; malformed shapes do not clear configured secrets.
$key = SecurityWP_Integrity::FEATURE;
SecurityWP_Features::set_config( $key, array( 'exclude' => "wp-content/cache\nwp-content/Тест folder\n<script>alert(1)</script>" ) );
$exclude = SecurityWP_Features::get( $key, 'exclude' );
inipr_assert( false === strpos( $exclude, '<script' ) && false !== strpos( $exclude, "wp-content/cache\nwp-content/Тест folder" ), 'textarea removes markup and preserves multiline paths' );
SecurityWP_Features::set_config( 'password_protect', array( 'password' => 'a<>&%secret' ) );
SecurityWP_Features::set_config( 'password_protect', array( 'password' => array( 'bad' ) ) );
inipr_assert( 'a<>&%secret' === SecurityWP_Features::get( 'password_protect', 'password' ), 'password punctuation preserved; malformed scalar rejected' );
foreach ( array( '203.0.113.0/garbage', '203.0.113.0/-1', '203.0.113.0/33', '::/129', '::/1/2', '::/', '203.0.113.0/999999999999' ) as $entry ) {
	inipr_assert( ! SecurityWP_Autoblock::ip_matches( '203.0.113.4', $entry ), 'invalid CIDR fails closed: ' . $entry );
}
inipr_assert( SecurityWP_Autoblock::ip_matches( '203.0.113.4', '203.0.113.0/24' ), 'valid IPv4 CIDR matches' );
inipr_assert( ! SecurityWP_Autoblock::ip_matches( '203.0.114.4', '203.0.113.0/24' ), 'IPv4 outside CIDR rejected' );
inipr_assert( SecurityWP_Autoblock::ip_matches( '2001:db8::1', '2001:db8::/32' ), 'valid IPv6 CIDR matches' );
SecurityWP_Features::set_config( SecurityWP_Autoblock::FEATURE_AUTOBLOCK, array( 'allowlist' => "203.0.113.0/garbage\n203.0.113.0/24\n2001:db8::/32" ) );
inipr_assert( "203.0.113.0/24\n2001:db8::/32" === SecurityWP_Features::get( SecurityWP_Autoblock::FEATURE_AUTOBLOCK, 'allowlist' ), 'only valid allowlist entries stored' );

// Escape at the returned HTML boundary, preserve deliberate inline formatting.
wp_set_current_user( 0 );
$email = new SecurityWP_Email_Protect();
foreach ( array( '<script>alert(1)</script><strong>Contact</strong>', '<img src=x onerror="alert(1)"><em>Mail</em>' ) as $label ) {
	$html = $email->filter_html( '<a href="mailto:team@example.test">' . $label . '</a>' );
	inipr_assert( false === strpos( $html, '<script' ) && false === strpos( $html, 'onerror' ), 'email labels reject active HTML' );
}
$html = $email->filter_html( '<a href="mailto:team@example.test"><strong>Contact us</strong></a>' );
inipr_assert( false !== strpos( $html, '<strong>Contact us</strong>' ), 'formatted email label retained' );
add_shortcode( 'obfuscate', '__return_empty_string' );
$email->register();
inipr_assert( '__return_empty_string' === $GLOBALS['shortcode_tags']['obfuscate'], 'generic shortcode owned by another plugin remains intact' );
inipr_assert( false !== strpos( do_shortcode( '[inipr_obfuscate email="team@example.test"]' ), 'data-eml=' ), 'prefixed shortcode works' );

$_SERVER['REQUEST_URI'] = '/subdirectory/a%20b/%2Fprivate?x=1&y=2';
inipr_assert( $_SERVER['REQUEST_URI'] === SecurityWP_Input::request_uri(), 'URL encoding and query delimiters retained' );
$_SERVER['REQUEST_URI'] = array( 'bad' );
inipr_assert( '' === SecurityWP_Input::request_uri(), 'malformed URI rejected' );
foreach ( array( 'POST<script>', "GET\r\nInjected", 'VERYLONGINVALIDMETHOD' ) as $method ) {
	$_SERVER['REQUEST_METHOD'] = $method;
	inipr_assert( '' === SecurityWP_Input::request_method(), 'invalid method rejected' );
}
$_SERVER['REQUEST_METHOD'] = 'post';
inipr_assert( 'POST' === SecurityWP_Input::request_method(), 'normal method normalized' );
foreach ( array( '127.0.0.1extra', '127.0.0.1<script>', array( '127.0.0.1' ) ) as $ip ) {
	$_SERVER['REMOTE_ADDR'] = $ip;
	inipr_assert( '' === SecurityWP_Input::remote_ip(), 'malformed peer IP rejected' );
}
$_SERVER['REMOTE_ADDR'] = '2001:db8::1';
inipr_assert( '2001:db8::1' === SecurityWP_Input::remote_ip(), 'IPv6 peer preserved' );
$GLOBALS['wp']->query_vars['rest_route'] = '/wp/v2/posts/secwp/v1/fake';
inipr_assert( is_wp_error( ( new SecurityWP_Password_Protect() )->gate_rest( null ) ), 'embedded namespace cannot bypass password REST gate' );
$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/users?x=/secwp/v1/';
$GLOBALS['wp']->query_vars['rest_route'] = '/wp/v2/users';
inipr_assert( ! inipr_private( new SecurityWP_Traffic_Log(), 'is_secwp_channel' ), 'query substring cannot exempt traffic logging' );
$GLOBALS['wp']->query_vars['rest_route'] = '/secwp/v1/state';
inipr_assert( null === ( new SecurityWP_Password_Protect() )->gate_rest( null ), 'authenticated connector namespace remains reachable' );

// Nonce rejection before state mutation, plus legitimate nonce control.
add_filter( 'wp_die_handler', static function () { return static function () { throw new RuntimeException( 'nonce-rejected' ); }; }, PHP_INT_MAX );
add_filter( 'wp_die_ajax_handler', static function () { return static function () { throw new RuntimeException( 'nonce-rejected' ); }; }, PHP_INT_MAX );
wp_set_current_user( 1 );
$_POST = array( 'key' => 'security_headers', 'on' => '1' ); $_REQUEST = $_POST;
try { ( new SecurityWP_Admin() )->handle_toggle(); throw new RuntimeException( 'unprotected admin save' ); }
catch ( RuntimeException $e ) { inipr_assert( 'nonce-rejected' === $e->getMessage(), 'admin save rejects absent nonce' ); }
inipr_assert( ! SecurityWP_Features::is_on( 'security_headers' ), 'rejected save leaves feature unchanged' );
foreach ( array( '', 'invalid' ) as $nonce ) {
	$_POST = array( 'secwp_nonce' => $nonce ); $_REQUEST = $_POST;
	try { SecurityWP_2FA::handle_second_step(); throw new RuntimeException( 'unprotected second step' ); }
	catch ( RuntimeException $e ) { inipr_assert( 'nonce-rejected' === $e->getMessage(), 'second-factor step rejects invalid nonce' ); }
}
$_REQUEST = array( 'secwp_nonce' => wp_create_nonce( 'secwp_second_step' ) );
inipr_assert( false !== check_admin_referer( 'secwp_second_step', 'secwp_nonce' ), 'valid second-factor nonce accepted' );
wp_set_current_user( 0 ); $_REQUEST = array( '_wpnonce' => 'bad' );
try { ( new SecurityWP_Admin() )->handle_toggle(); throw new RuntimeException( 'unprotected admin permission' ); }
catch ( RuntimeException $e ) { inipr_assert( 'nonce-rejected' === $e->getMessage(), 'unauthorized save rejected' ); }

wp_set_current_user( 1 ); $_GET = array(); $_POST = array(); $_REQUEST = array();
set_current_screen( 'edit-post' );
foreach ( array( new SecurityWP_Vuln_Admin(), new SecurityWP_Integrity_Admin(), 'SecurityWP_2FA' ) as $notice ) {
	ob_start(); is_string( $notice ) ? $notice::enrolment_notice() : $notice->notice(); $html = ob_get_clean();
	inipr_assert( '' === $html, 'unrelated editor screen receives no security notice' );
}
update_option( 'secwp_features', array() );
update_option( 'secwp_features_config', array() );
$_SERVER['REQUEST_URI'] = '/';
echo "Review regressions passed.\n";
