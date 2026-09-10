<?php
function ini_assert($condition, $message) { if (!$condition) { throw new RuntimeException($message); } echo "PASS: $message\n"; }
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/template.php';
wp_set_current_user(1);
$header = get_plugin_data(WP_PLUGIN_DIR . '/ini-protector/ini-protector.php');
ini_assert($header['Name'] === 'INI Protector' && $header['Version'] === SECWP_VERSION, 'plugin identity');
ini_assert($header['TextDomain'] === 'ini-protector', 'translation domain');
ini_assert(!class_exists('SecurityWP_Updater') && !defined('SECWP_UPDATE_ENDPOINT'), 'external updater removed');
ini_assert(SECWP_NAMESPACE === 'secwp/v1', 'REST compatibility');
ini_assert(SecurityWP_Integrity::table_exists(), 'integrity table installed');
update_option('secwp_features', array('security_headers'=>true));
ini_assert(SecurityWP_Features::is_on('security_headers'), 'existing settings retained');
$secret=SecurityWP_TOTP::base32_encode('12345678901234567890');
ini_assert(SecurityWP_TOTP::code_at($secret, 1)==='287082', 'RFC TOTP vector');
$altcha = new SecurityWP_Altcha(); $altcha->enqueue();
$tag = $altcha->module_script_tag('', 'secwp-altcha', 'https://example.test/altcha.js');
ini_assert(strpos($tag,'type="module"')!==false, 'ALTCHA module script');
ini_assert(wp_script_is('secwp-altcha','enqueued'), 'ALTCHA enqueued');
$pages = array('SecurityWP_Admin','SecurityWP_Traffic_Admin','SecurityWP_IP_Block_Admin','SecurityWP_Vuln_Admin','SecurityWP_Integrity_Admin','SecurityWP_Utilities_Admin');
foreach ($pages as $page) {
 ob_start(); (new $page())->render(); $html=ob_get_clean();
 ini_assert(strlen($html)>100, "$page renders");
 ini_assert(strpos($html, 'page=securitywp')===false, "$page uses renamed links");
}
update_option('secwp_features', array());
echo "Smoke tests complete.\n";
