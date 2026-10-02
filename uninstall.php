<?php
/**
 * Uninstall: remove everything INI Protector stored.
 *
 * Runs only when the plugin is deleted from Plugins (never on deactivation), after
 * deactivation has already cleared its cron events and .htaccess block. The plugin
 * itself is not loaded here, so this works from the stored names alone.
 *
 * What goes: every `secwp_*` option and transient (settings, including the site
 * password and webhook secret, which are stored in plain text), the traffic log and
 * integrity baseline tables, and the per-user two-factor secrets and recovery codes.
 *
 * @package INI_Protector
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/** Remove one site's data. */
function secwp_uninstall_site(): void {
	global $wpdb;

	// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.SchemaChange
	$like = array(
		$wpdb->esc_like( 'secwp_' ) . '%',
		$wpdb->esc_like( '_transient_secwp_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_secwp_' ) . '%',
	);
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$like[0],
			$like[1],
			$like[2]
		)
	);

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}secwp_traffic_log" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}secwp_integrity" );
	// phpcs:enable

	foreach ( array( 'secwp_vuln_scan', 'secwp_autoblock_eval', 'secwp_integrity_scan' ) as $hook ) {
		wp_clear_scheduled_hook( $hook );
	}
	wp_cache_flush();
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $secwp_site_id ) {
		switch_to_blog( (int) $secwp_site_id );
		secwp_uninstall_site();
		restore_current_blog();
	}
	// Network-wide transients live in sitemeta.
	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( '_site_transient_secwp_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_secwp_' ) . '%'
		)
	);
} else {
	secwp_uninstall_site();
}

// User meta is shared by every site of a network: two-factor secrets, recovery codes, state.
global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s",
		$wpdb->esc_like( 'secwp_' ) . '%'
	)
);
