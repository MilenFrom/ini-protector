<?php
/** Run only on disposable WordPress: wp --skip-plugins=ini-protector eval-file this-file.php */
require_once WP_PLUGIN_DIR . '/ini-protector/ini-protector.php';
if ( ! class_exists( 'SecurityWP_Manual_Update' ) ) {
	require_once __DIR__ . '/../includes/class-secwp-manual-update.php';
}
require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
wp_set_current_user( 1 );

function secwp_install_assert( $ok, $label ) {
	if ( ! $ok ) { throw new RuntimeException( $label ); }
	echo "PASS: $label\n";
}

$file = WP_PLUGIN_DIR . '/' . SECWP_BASENAME;
$hash = hash_file( 'sha256', $file );
$active = get_option( 'active_plugins' );
$cache = get_site_transient( 'update_plugins' );
$settings = array( get_option( 'secwp_features' ), get_option( 'secwp_features_config' ) );
// Mark active without executing unrelated feature hooks in this isolated test.
update_option( 'active_plugins', array_values( array_unique( array_merge( $active, array( SECWP_BASENAME ) ) ) ) );
$info = (object) array( 'version' => '99.0', 'download_link' => 'https://downloads.wordpress.org/plugin/ini-protector.99.0.zip' );
$scenario = 'network';
$download = function () use ( &$scenario ) {
	if ( 'network' === $scenario ) { return new WP_Error( 'test_download_failed', 'Simulated download failure.' ); }
	$zip = wp_tempnam( 'secwp-invalid-package.zip' );
	$archive = new ZipArchive();
	$archive->open( $zip, ZipArchive::OVERWRITE );
	$version = 'wrong_version' === $scenario ? '98.0' : '99.0';
	$name = 'wrong_name' === $scenario ? 'Different Plugin' : 'INI Protector';
	$requires = 'incompatible' === $scenario ? '99.0' : '7.4';
	$archive->addFromString( 'ini-protector/ini-protector.php', "<?php\n/*\nPlugin Name: $name\nVersion: $version\nRequires PHP: $requires\n*/\n" );
	$archive->close();
	return $zip;
};
add_filter( 'upgrader_pre_download', $download );
add_filter( 'filesystem_method', static function () { return 'direct'; } );
try {
	foreach ( array( 'network', 'wrong_version', 'wrong_name', 'incompatible' ) as $scenario ) {
		$skin = new Automatic_Upgrader_Skin();
		ob_start();
		$result = SecurityWP_Manual_Update::upgrade( $info, $skin );
		ob_end_clean();
		secwp_install_assert( true !== $result && ( is_wp_error( $result ) || is_wp_error( $skin->result ) || 'network' === $scenario && in_array( 'Simulated download failure.', $skin->get_upgrade_messages(), true ) ), "$scenario aborts installation" );
		secwp_install_assert( $hash === hash_file( 'sha256', $file ), "$scenario leaves original plugin file intact" );
		secwp_install_assert( is_plugin_active( SECWP_BASENAME ), "$scenario preserves activation" );
		secwp_install_assert( $settings === array( get_option( 'secwp_features' ), get_option( 'secwp_features_config' ) ), "$scenario preserves settings" );
		$after = get_site_transient( 'update_plugins' );
		secwp_install_assert( empty( $after->response[ SECWP_BASENAME ] ) || '99.0' !== $after->response[ SECWP_BASENAME ]->new_version, "$scenario does not leak manual offer into shared cache" );
	}
} finally {
	remove_filter( 'upgrader_pre_download', $download );
	update_option( 'active_plugins', $active );
	set_site_transient( 'update_plugins', $cache );
}
