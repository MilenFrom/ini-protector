<?php
/** Run on a disposable WordPress installation with wp eval-file --skip-plugins=ini-protector. */
define( 'SECWP_VERSION', '1.9.2' );
require_once __DIR__ . '/../includes/class-secwp-manual-update.php';
define( 'SECWP_BASENAME', 'ini-protector/ini-protector.php' );
require_once __DIR__ . '/../includes/class-secwp-admin.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';

function secwp_update_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
	echo "PASS: $message\n";
}

$admin = new SecurityWP_Admin();
wp_set_current_user( 1 );
$links = $admin->row_meta( array( 'Version' ), SECWP_BASENAME );
secwp_update_assert( 2 === count( $links ) && false !== strpos( $links[1], 'Check for updates' ), 'button added beside metadata' );
secwp_update_assert( array() === $admin->row_meta( array(), 'other/other.php' ), 'other plugins unchanged' );
parse_str( wp_parse_url( html_entity_decode( preg_replace( '/.*href="([^"]+)".*/', '$1', $links[1] ) ), PHP_URL_QUERY ), $query );
secwp_update_assert( wp_verify_nonce( $query['_wpnonce'], 'secwp_check_updates' ), 'button contains valid nonce' );

add_filter( 'wp_die_handler', function () { return function () { throw new RuntimeException( 'denied' ); }; } );
add_filter( 'wp_die_ajax_handler', function () { return function () { throw new RuntimeException( 'denied' ); }; } );
wp_set_current_user( 0 );
secwp_update_assert( array() === $admin->row_meta( array(), SECWP_BASENAME ), 'button hidden without update permission' );
try { $admin->check_updates(); throw new RuntimeException( 'permission bypass' ); }
catch ( RuntimeException $e ) { secwp_update_assert( 'denied' === $e->getMessage(), 'handler rejects unauthorized users' ); }
wp_set_current_user( 1 );
$_REQUEST['_wpnonce'] = 'invalid';
try { $admin->check_updates(); throw new RuntimeException( 'nonce bypass' ); }
catch ( RuntimeException $e ) { secwp_update_assert( 'denied' === $e->getMessage(), 'handler rejects invalid nonce' ); }
// Installation has an independent capability check and a version-bound nonce.
wp_set_current_user( 0 );
try { SecurityWP_Manual_Update::install(); throw new RuntimeException( 'install permission bypass' ); }
catch ( RuntimeException $e ) { secwp_update_assert( 'denied' === $e->getMessage(), 'installation rejects unauthorized users' ); }
wp_set_current_user( 1 );
$_GET['version'] = '1.9.3';
try { SecurityWP_Manual_Update::install(); throw new RuntimeException( 'install nonce bypass' ); }
catch ( RuntimeException $e ) { secwp_update_assert( 'denied' === $e->getMessage(), 'installation rejects invalid nonce' ); }
$_REQUEST['_wpnonce'] = wp_create_nonce( 'secwp_check_updates' );

$scenario = 'available';
$requests = 0;
add_filter( 'pre_http_request', function ( $pre, $args, $url ) use ( &$scenario, &$requests ) {
	if ( false === strpos( $url, 'api.wordpress.org/plugins/info/' ) ) {
		return new WP_Error( 'test', 'Unrelated network request blocked.' );
	}
	++$requests;
	if ( 'failed' === $scenario ) { return new WP_Error( 'test', 'Simulated outage.' ); }
	$version = 'current' === $scenario ? '1.9.2' : ( 'older' === $scenario ? '1.9.1' : '1.9.3' );
	$body = array( 'slug' => 'ini-protector', 'version' => $version, 'download_link' => 'https://downloads.wordpress.org/plugin/ini-protector.' . $version . '.zip', 'requires' => '5.7', 'requires_php' => '7.4' );
	if ( 'incompatible' === $scenario ) { $body['requires_php'] = '99.0'; }
	if ( 'wrong_host' === $scenario ) { $body['download_link'] = 'https://example.com/plugin.zip'; }
	if ( 'wrong_slug' === $scenario ) { $body['slug'] = 'other-plugin'; }
	if ( 'malformed' === $scenario ) { $body['version'] = array( '1.9.3' ); }

	return array( 'response' => array( 'code' => 200 ), 'body' => wp_json_encode( $body ) );
}, 10, 3 );
add_filter( 'wp_redirect', function ( $url ) { throw new RuntimeException( $url ); }, -100 );
$original = get_site_transient( 'update_plugins' );
try {
	foreach ( array( 'available', 'current', 'failed', 'incompatible', 'older', 'wrong_host', 'wrong_slug', 'malformed' ) as $scenario ) {
		$expected = in_array( $scenario, array( 'wrong_host', 'wrong_slug', 'malformed' ), true ) ? 'failed' : ( 'older' === $scenario ? 'current' : $scenario );
		$before = $requests;
		try { $admin->check_updates(); }
		catch ( RuntimeException $e ) {
			secwp_update_assert( false !== strpos( $e->getMessage(), 'secwp_update_check=' . $expected ), "$scenario redirects with correct result" );
		}
		secwp_update_assert( $requests > $before, "$scenario forces a fresh request despite cached data" );
		set_current_screen( 'plugins' );
		$_GET['secwp_update_check'] = $expected;
		ob_start(); $admin->update_notice(); $html = ob_get_clean();
		if ( 'available' === $scenario ) { secwp_update_assert( false !== strpos( $html, '1.9.3' ) && false !== strpos( $html, 'secwp_install_update' ), 'new version has explicit install link' ); }
		secwp_update_assert( false !== strpos( $html, 'INI Protector' ), "$scenario displays feedback" );
	}
	secwp_update_assert( $original == get_site_transient( 'update_plugins' ), 'manual checks do not modify shared update cache' );
} finally {
	set_site_transient( 'update_plugins', $original );
}
