<?php
/** Run with wp eval-file on a disposable test installation only (plugin active). Restores both settings options when done. */

function secwp_st_check( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
	echo "PASS: $message\n";
}

$st_state  = get_option( SecurityWP_Features::OPT_STATE );
$st_config = get_option( SecurityWP_Features::OPT_CONFIG );
$st_undo   = get_option( SecurityWP_Settings_Transfer::OPT_UNDO );
wp_set_current_user( (int) ( get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) )[0] ?? 0 ) );

try {
	// Known starting point.
	SecurityWP_Features::set( 'password_protect', false );
	SecurityWP_Features::set_config( 'password_protect', array( 'password' => 'source-site-pass', 'message' => 'Private' ) );
	SecurityWP_Features::set_config( 'file_integrity', array( 'webhook_secret' => 'hook-secret' ) );
	SecurityWP_Features::set( 'limit_login', true );
	SecurityWP_Features::set_config( 'limit_login', array( 'max' => 5, 'lockout' => 15 ) );

	// --- Export -------------------------------------------------------------
	$doc  = SecurityWP_Settings_Transfer::export();
	$json = SecurityWP_Settings_Transfer::export_json();
	secwp_st_check( 'ini-protector-settings' === $doc['format'] && 1 === $doc['schema'] && false === $doc['secrets_included'], 'export carries format, schema and secrets flag' );
	secwp_st_check( array_keys( $doc['features'] ) === array_keys( SecurityWP_Features::catalog() ), 'export lists every known protection' );
	secwp_st_check( ! isset( $doc['features']['password_protect']['config']['password'] ) && ! isset( $doc['features']['file_integrity']['config']['webhook_secret'] ), 'secrets left out by default' );
	secwp_st_check( false === strpos( $json, 'source-site-pass' ) && false === strpos( $json, 'hook-secret' ), 'secret values absent from the default file' );
	secwp_st_check( 'Private' === $doc['features']['password_protect']['config']['message'], 'non-secret fields of the same protection are exported' );
	$with = SecurityWP_Settings_Transfer::export( true );
	secwp_st_check( 'source-site-pass' === $with['features']['password_protect']['config']['password'] && true === $with['secrets_included'], 'secrets exported only on request' );
	foreach ( array( 'secwp_traffic', 'secwp_integrity_digest', 'secwp_vuln_results', 'secwp_ver_salt', 'secwp_platform_events', '2fa' ) as $needle ) {
		secwp_st_check( false === strpos( $json, $needle ), "export contains no site state ($needle)" );
	}

	// --- Parse --------------------------------------------------------------
	secwp_st_check( is_wp_error( SecurityWP_Settings_Transfer::parse( 'not json' ) ), 'garbage rejected' );
	secwp_st_check( is_wp_error( SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'other', 'features' => array() ) ) ) ), 'other formats rejected' );
	secwp_st_check( 'newer_schema' === SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'ini-protector-settings', 'schema' => 99, 'features' => array() ) ) )->get_error_code(), 'newer schema refused' );
	secwp_st_check( 'too_large' === SecurityWP_Settings_Transfer::parse( str_repeat( ' ', SecurityWP_Settings_Transfer::MAX_BYTES + 1 ) )->get_error_code(), 'oversized file refused' );
	$p = SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'ini-protector-settings', 'schema' => 1, 'features' => array( 'made_up' => array( 'on' => true ), 'limit_login' => array( 'on' => true, 'config' => array( 'max' => 3, 'bogus' => 'x' ) ) ) ) ) );
	secwp_st_check( array( 'made_up' ) === $p['ignored'] && ! isset( $p['features']['made_up'] ), 'unknown protections ignored and reported' );
	secwp_st_check( ! isset( $p['features']['limit_login']['config']['bogus'] ), 'unknown fields dropped' );

	// --- Diff ---------------------------------------------------------------
	$config_before_preview = get_option( SecurityWP_Features::OPT_CONFIG );
	secwp_st_check( array() === SecurityWP_Settings_Transfer::diff( SecurityWP_Settings_Transfer::parse( $json ) ), 'own export shows no changes' );
	$rows = SecurityWP_Settings_Transfer::diff( $p );
	secwp_st_check( 1 === count( $rows ) && 'limit_login' === $rows[0]['key'] && '3' === $rows[0]['to'] && $rows[0]['sensitive'], 'field change listed and flagged sensitive' );
	$loose = SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'ini-protector-settings', 'features' => array( 'limit_login' => array( 'config' => array( 'max' => '5' ) ) ) ) ) );
	secwp_st_check( array() === SecurityWP_Settings_Transfer::diff( $loose ), "'5' vs 5 is not a change" );
	$sec = SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'ini-protector-settings', 'features' => array( 'password_protect' => array( 'config' => array( 'password' => 'other-pass' ) ) ) ) ) );
	$sr  = SecurityWP_Settings_Transfer::diff( $sec );
	secwp_st_check( 1 === count( $sr ) && false === strpos( wp_json_encode( $sr ), 'other-pass' ) && false === strpos( wp_json_encode( $sr ), 'source-site-pass' ), 'secret change listed without revealing either value' );
	secwp_st_check( $config_before_preview === get_option( SecurityWP_Features::OPT_CONFIG ), 'previews wrote nothing' );
	secwp_st_check( 5 === (int) SecurityWP_Features::get( 'limit_login', 'max' ), 'preview left stored values untouched' );

	// --- Apply: sanitizing, merging, secrets, side effects ---------------------
	$vuln_was_on = SecurityWP_Features::is_on( 'vulnerability_scan' );
	SecurityWP_Features::set( 'vulnerability_scan', false );
	SecurityWP_Admin::after_change( 'vulnerability_scan', false );
	$header_before = SecurityWP_Features::get( 'security_headers', 'x_frame_options' );
	$crafted = array(
		'format'   => 'ini-protector-settings',
		'schema'   => 1,
		'features' => array(
			'security_headers'   => array( 'config' => array( 'x_frame_value' => "DENY\r\nSet-Cookie: x=1" ) ),
			'password_protect'   => array( 'on' => false, 'config' => array( 'message' => '<script>alert(1)</script>Hi' ) ),
			'autoblock'          => array( 'config' => array( 'allowlist' => "203.0.113.7\nnot-an-ip\n198.51.100.0/24" ) ),
			'limit_login'        => array( 'config' => array( 'max' => 'abc' ) ),
			'vulnerability_scan' => array( 'on' => true ),
		),
	);
	$parsed  = SecurityWP_Settings_Transfer::parse( wp_json_encode( $crafted ) );
	$before  = array( 'state' => get_option( SecurityWP_Features::OPT_STATE ), 'config' => get_option( SecurityWP_Features::OPT_CONFIG ) );
	$applied = SecurityWP_Settings_Transfer::apply( $parsed, 'test' );
	secwp_st_check( count( $applied ) > 0, 'apply reports what changed' );
	secwp_st_check( 'SAMEORIGIN' === SecurityWP_Features::get( 'security_headers', 'x_frame_value' ) || 'DENY' === SecurityWP_Features::get( 'security_headers', 'x_frame_value' ), 'header-injection value replaced by an allowed option' );
	secwp_st_check( false === strpos( (string) SecurityWP_Features::get( 'password_protect', 'message' ), '<script' ), 'markup stripped from text field' );
	secwp_st_check( "203.0.113.7\n198.51.100.0/24" === SecurityWP_Features::get( 'autoblock', 'allowlist' ), 'invalid allowlist entries dropped' );
	secwp_st_check( 5 === SecurityWP_Features::get( 'limit_login', 'max' ), 'non-numeric number falls back to the field default, as in the form' );
	secwp_st_check( 'source-site-pass' === SecurityWP_Features::get( 'password_protect', 'password' ) && 'hook-secret' === SecurityWP_Features::get( 'file_integrity', 'webhook_secret' ), 'secrets kept when the file has none' );
	secwp_st_check( $header_before === SecurityWP_Features::get( 'security_headers', 'x_frame_options' ), 'checkbox absent from the file keeps its value' );
	secwp_st_check( false !== wp_next_scheduled( 'secwp_vuln_scan' ), 'side effects ran (vulnerability scan scheduled)' );
	$undo = SecurityWP_Settings_Transfer::undo_point();
	secwp_st_check( $undo && $before['state'] === $undo['state'] && $before['config'] === $undo['config'] && 'test' === $undo['via'], 'undo point holds the exact previous options' );

	// --- Undo ---------------------------------------------------------------
	secwp_st_check( SecurityWP_Settings_Transfer::undo( 'test' ), 'undo succeeds' );
	secwp_st_check( $before['state'] === get_option( SecurityWP_Features::OPT_STATE ) && $before['config'] === get_option( SecurityWP_Features::OPT_CONFIG ), 'undo restores both options exactly' );
	secwp_st_check( false === wp_next_scheduled( 'secwp_vuln_scan' ), 'undo re-ran side effects (scan unscheduled)' );
	secwp_st_check( null === SecurityWP_Settings_Transfer::undo_point() && false === SecurityWP_Settings_Transfer::undo( 'test' ), 'undo is single-use' );

	// --- Secrets replaced when included --------------------------------------
	SecurityWP_Settings_Transfer::apply( $sec, 'test' );
	secwp_st_check( 'other-pass' === SecurityWP_Features::get( 'password_protect', 'password' ), 'included secret replaces the stored one' );
	$blank = SecurityWP_Settings_Transfer::parse( wp_json_encode( array( 'format' => 'ini-protector-settings', 'secrets_included' => true, 'features' => array( 'password_protect' => array( 'config' => array( 'password' => '' ) ) ) ) ) );
	SecurityWP_Settings_Transfer::apply( $blank, 'test' );
	secwp_st_check( 'other-pass' === SecurityWP_Features::get( 'password_protect', 'password' ), 'an empty secret in the file never clears one' );

	// --- set_config() split is behaviour-neutral -----------------------------
	$vals = array( 'max' => '7', 'lockout' => 'abc' );
	$pred = SecurityWP_Features::clean_config( 'limit_login', $vals );
	SecurityWP_Features::set_config( 'limit_login', $vals );
	secwp_st_check( $pred === get_option( SecurityWP_Features::OPT_CONFIG )['limit_login'], 'clean_config() predicts exactly what set_config() stores' );
	secwp_st_check( null === SecurityWP_Features::clean_config( 'disable_xmlrpc', array() ) && false === SecurityWP_Features::set_config( 'disable_xmlrpc', array() ), 'fieldless protection still refused' );

	if ( $vuln_was_on ) {
		SecurityWP_Features::set( 'vulnerability_scan', true );
	}
	echo "Settings transfer regressions passed.\n";
} finally {
	update_option( SecurityWP_Features::OPT_STATE, $st_state, false );
	update_option( SecurityWP_Features::OPT_CONFIG, $st_config, false );
	false === $st_undo ? delete_option( SecurityWP_Settings_Transfer::OPT_UNDO ) : update_option( SecurityWP_Settings_Transfer::OPT_UNDO, $st_undo, false );
	SecurityWP_Admin::after_change( 'vulnerability_scan', SecurityWP_Features::is_on( 'vulnerability_scan' ) );
}
