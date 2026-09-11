<?php
/**
 * Plugin Name: INI Protector
 * Description: Lightweight WordPress hardening — file integrity monitoring with off-server alerts, TOTP two-factor authentication, login masking & lockout, security headers, information-disclosure protection, user-enumeration prevention, ALTCHA captcha, head cleanup, feed/author privacy and more. Integrates with the INI WP control panel.
 * Version:     1.9.6
 * Author:      ini software
 * Author URI:  https://iniwp.com
 * License:     GPL v2 or later
 * Text Domain: ini-protector
 * Requires at least: 5.7
 * Requires PHP: 7.4
 * Domain Path: /languages
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SECWP_VERSION', '1.9.6' );
define( 'SECWP_FILE', __FILE__ );
define( 'SECWP_DIR', plugin_dir_path( __FILE__ ) );
define( 'SECWP_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SECWP_BASENAME', plugin_basename( __FILE__ ) );

/* Our own REST namespace (the platform-state endpoint). */
define( 'SECWP_NAMESPACE', 'secwp/v1' );

/* The INI WP connector's signed channel — exempted from REST blocking,
   password-gating and traffic logging so the control panel keeps working. */
if ( ! defined( 'SECWP_CONNECTOR_NAMESPACE' ) ) {
	define( 'SECWP_CONNECTOR_NAMESPACE', 'iniwp/v1' );
}

/* WPVulnerability database host (free, CC0, no API key). The Vulnerability Scan
   queries {base}/{plugin|theme|core}/{slug-or-version}/. Override per-install by
   defining SECWP_VULN_API_BASE in wp-config.php (e.g. to self-host a mirror). */
if ( ! defined( 'SECWP_VULN_API_BASE' ) ) {
	define( 'SECWP_VULN_API_BASE', 'https://www.wpvulnerability.net' );
}

/* --- Includes ------------------------------------------------------------- */
require_once SECWP_DIR . 'includes/class-secwp-input.php';
require_once SECWP_DIR . 'includes/class-secwp-features.php';
require_once SECWP_DIR . 'includes/class-secwp-tweaks.php';
require_once SECWP_DIR . 'includes/class-secwp-security-headers.php';
require_once SECWP_DIR . 'includes/class-secwp-hide-login.php';
require_once SECWP_DIR . 'includes/class-secwp-limit-login.php';
require_once SECWP_DIR . 'includes/class-secwp-password-protect.php';
require_once SECWP_DIR . 'includes/class-secwp-info-disclosure.php';
require_once SECWP_DIR . 'includes/class-secwp-email-protect.php';
require_once SECWP_DIR . 'includes/class-secwp-altcha.php';
require_once SECWP_DIR . 'includes/class-secwp-disable-comments.php';
require_once SECWP_DIR . 'includes/class-secwp-author-slugs.php';
require_once SECWP_DIR . 'includes/class-secwp-traffic-log.php';
require_once SECWP_DIR . 'includes/class-secwp-ip-block.php';
require_once SECWP_DIR . 'includes/class-secwp-autoblock.php';
require_once SECWP_DIR . 'includes/class-secwp-security-scan.php';
require_once SECWP_DIR . 'includes/class-secwp-manual-update.php';
require_once SECWP_DIR . 'includes/class-secwp-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-traffic-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-ip-block-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-platform.php';
require_once SECWP_DIR . 'includes/class-secwp-vuln-scan.php';
require_once SECWP_DIR . 'includes/class-secwp-vuln-mailer.php';
require_once SECWP_DIR . 'includes/class-secwp-vuln-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-integrity.php';
require_once SECWP_DIR . 'includes/class-secwp-integrity-alert.php';
require_once SECWP_DIR . 'includes/class-secwp-integrity-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-utilities-admin.php';
require_once SECWP_DIR . 'includes/class-secwp-qr.php';
require_once SECWP_DIR . 'includes/class-secwp-totp.php';
require_once SECWP_DIR . 'includes/class-secwp-2fa.php';

/* WP-CLI commands — the file returns early when not running under WP-CLI. */
require_once SECWP_DIR . 'includes/class-secwp-cli.php';

/* --- Boot ----------------------------------------------------------------- */
add_action(
	'plugins_loaded',
	static function () {
		// Clean up stored legacy authentication material regardless of feature state.
		SecurityWP_Tweaks::migrate_asset_version_salt();
		SecurityWP_Author_Slugs::migrate_legacy_tokens();

		// Apply every enabled hardening tweak.
		( new SecurityWP_Features() )->apply();

		// IP blocklist gate — always on (independent of the traffic monitor), so
		// a manually blocked IP stays blocked regardless of tweak state.
		( new SecurityWP_IP_Block() )->register();

		// Vulnerability scanner — registers its daily cron callback and lazily
		// (re)syncs the schedule to the feature toggle. Works standalone.
		( new SecurityWP_Vuln_Scan() )->register();

		// Auto-block escalation engine — registers its 5-minute cron callback and
		// lazily (re)syncs the schedule to the feature toggle. Decides only unless
		// Enforce is on; SecurityWP_IP_Block enforces the temp blocks it writes.
		( new SecurityWP_Autoblock() )->register();

		// File integrity monitoring — registers its cron callback, heals the
		// baseline table, and syncs the schedule to the configured frequency.
		// Runs outside is_admin() so cron and WP-CLI reach it.
		( new SecurityWP_Integrity() )->register();

		// Two-factor authentication — hooks the login chain and the profile UI.
		// Registers outside is_admin() because the login screen is not wp-admin.
		( new SecurityWP_2FA() )->register();

		// Admin UI and platform endpoint.
		if ( is_admin() ) {
			new SecurityWP_Admin();
			new SecurityWP_Traffic_Admin();
			new SecurityWP_IP_Block_Admin();
			new SecurityWP_Vuln_Admin();
			new SecurityWP_Integrity_Admin();
			new SecurityWP_Utilities_Admin();
		}
		new SecurityWP_Platform();

	}
);

/*
 * Register our REST namespace into the INI WP connector's family registry, so
 * the connector (the authority on family membership) reports secwp/v1 as
 * always-public for the REST-guest block on every family plugin. Harmless when
 * the connector isn't installed — the filter simply has no listener.
 */
add_filter(
	'iniwp_family_rest_namespaces',
	static function ( $namespaces ) {
		$namespaces   = is_array( $namespaces ) ? $namespaces : array();
		$namespaces[] = defined( 'SECWP_NAMESPACE' ) ? SECWP_NAMESPACE : 'secwp/v1';
		return $namespaces;
	}
);

/* --- Lifecycle ------------------------------------------------------------ */
register_activation_hook(
	__FILE__,
	static function () {
		// Baseline table for file integrity monitoring (harmless when the feature is off).
		if ( class_exists( 'SecurityWP_Integrity' ) ) {
			SecurityWP_Integrity::install_table();
		}
		// Rewrite rules (hide-login slug) need flushing on activate.
		flush_rewrite_rules();
	}
);

register_deactivation_hook(
	__FILE__,
	static function () {
		// Remove any .htaccess rules we wrote, and flush rewrites.
		if ( class_exists( 'SecurityWP_Info_Disclosure' ) && method_exists( 'SecurityWP_Info_Disclosure', 'remove_htaccess' ) ) {
			SecurityWP_Info_Disclosure::remove_htaccess();
		}
		// Leave no orphaned cron behind.
		wp_clear_scheduled_hook( 'secwp_vuln_scan' );
		if ( class_exists( 'SecurityWP_Autoblock' ) ) {
			SecurityWP_Autoblock::unschedule();
		} else {
			wp_clear_scheduled_hook( 'secwp_autoblock_eval' );
		}
		if ( class_exists( 'SecurityWP_Integrity' ) ) {
			SecurityWP_Integrity::unschedule();
		} else {
			wp_clear_scheduled_hook( 'secwp_integrity_scan' );
		}
		flush_rewrite_rules();
	}
);
