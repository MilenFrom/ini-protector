<?php
/**
 * Disable comments site-wide. Closes comments (and pingbacks/trackbacks) on every post type,
 * hides existing comments from the front-end, and strips the comment UI out of wp-admin — the
 * Comments menu, the dashboard "Recent Comments" widget, the admin-bar Comments item, the
 * Discussion meta box, and the default Recent Comments widget. Also drops the comment feed.
 *
 * Reverses cleanly when toggled off (all behavior is hook-based; nothing is written to the DB).
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Disable_Comments {

	public function register(): void {
		// Comments and pingbacks/trackbacks are closed everywhere, for every post type.
		add_filter( 'comments_open', '__return_false', 20 );
		add_filter( 'pings_open', '__return_false', 20 );

		// Hide any existing comments from the front-end (themes calling comments_template()).
		add_filter( 'comments_array', '__return_empty_array', 20 );

		// Remove comment support from all post types so the editor metabox/quick-edit drop it.
		add_action( 'init', array( $this, 'remove_post_type_support' ), 100 );

		// Admin cleanup.
		add_action( 'admin_init', array( $this, 'admin_cleanup' ) );
		add_action( 'admin_menu', array( $this, 'remove_menu' ) );
		add_action( 'wp_dashboard_setup', array( $this, 'remove_dashboard_widget' ) );
		add_action( 'wp_before_admin_bar_render', array( $this, 'remove_admin_bar_node' ) );

		// Drop the comment feed link and 404 the comment feed.
		add_filter( 'feed_links_show_comments_feed', '__return_false' );

		// Unregister the core "Recent Comments" widget.
		add_action( 'widgets_init', array( $this, 'unregister_widget' ), 100 );
	}

	public function remove_post_type_support(): void {
		foreach ( get_post_types() as $type ) {
			if ( post_type_supports( $type, 'comments' ) ) {
				remove_post_type_support( $type, 'comments' );
			}
			if ( post_type_supports( $type, 'trackbacks' ) ) {
				remove_post_type_support( $type, 'trackbacks' );
			}
		}
	}

	/** Redirect away from the Comments admin screen and remove the Discussion meta boxes. */
	public function admin_cleanup(): void {
		global $pagenow;
		if ( 'edit-comments.php' === $pagenow ) {
			wp_safe_redirect( admin_url() );
			exit;
		}
		// Remove the per-post Discussion + comments meta boxes for every post type.
		foreach ( get_post_types() as $type ) {
			remove_meta_box( 'commentstatusdiv', $type, 'normal' );
			remove_meta_box( 'commentsdiv', $type, 'normal' );
		}
	}

	public function remove_menu(): void {
		remove_menu_page( 'edit-comments.php' );
		// Also remove Discussion settings under Settings (optional but consistent).
		remove_submenu_page( 'options-general.php', 'options-discussion.php' );
	}

	public function remove_dashboard_widget(): void {
		remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'normal' );
	}

	public function remove_admin_bar_node(): void {
		if ( is_admin_bar_showing() ) {
			global $wp_admin_bar;
			$wp_admin_bar->remove_node( 'comments' );
		}
	}

	public function unregister_widget(): void {
		unregister_widget( 'WP_Widget_Recent_Comments' );
	}
}
