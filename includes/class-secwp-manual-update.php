<?php
/** Explicit, administrator-initiated updates from the WordPress.org directory.
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Manual_Update {
	/** Fetch the directory release afresh, independently of the update-check cache. */
	public static function latest() {
		$url = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=ini-protector';
		$response = wp_remote_get( $url, array( 'timeout' => 20, 'headers' => array( 'Cache-Control' => 'no-cache' ) ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'directory_unavailable', __( 'Could not check WordPress.org. Please try again later.', 'ini-protector' ) );
		}
		$info = json_decode( wp_remote_retrieve_body( $response ) );
		if ( ! is_object( $info ) || ! isset( $info->slug, $info->version, $info->download_link ) ||
			'ini-protector' !== $info->slug || ! is_string( $info->version ) ||
			! preg_match( '/^[0-9]+(?:\.[0-9]+)*(?:[-.]?(?:alpha|beta|rc)[0-9.]*)?$/i', $info->version ) ||
			'https://downloads.wordpress.org/plugin/ini-protector.' . $info->version . '.zip' !== $info->download_link ) {
			return new WP_Error( 'invalid_release', __( 'WordPress.org returned invalid release information. Please try again later.', 'ini-protector' ) );
		}
		foreach ( array( 'requires', 'requires_php' ) as $field ) {
			if ( isset( $info->$field ) && false !== $info->$field && ! is_string( $info->$field ) ) {
				return new WP_Error( 'invalid_release', __( 'WordPress.org returned invalid release requirements.', 'ini-protector' ) );
			}
		}
		return $info;
	}

	private static function offer_key(): string {
		return 'secwp_manual_offer_' . get_current_user_id();
	}

	public static function compatible( $info ): bool {
		return ( empty( $info->requires ) || is_wp_version_compatible( $info->requires ) ) &&
			( empty( $info->requires_php ) || is_php_version_compatible( $info->requires_php ) );
	}

	/** Store an offer only for this administrator; never expose it to auto-updates. */
	public static function check(): string {
		delete_site_transient( self::offer_key() );
		$info = self::latest();
		if ( is_wp_error( $info ) ) {
			return 'failed';
		}
		if ( ! version_compare( $info->version, SECWP_VERSION, '>' ) ) {
			return 'current';
		}
		if ( ! self::compatible( $info ) ) {
			return 'incompatible';
		}
		set_site_transient( self::offer_key(), $info, 15 * MINUTE_IN_SECONDS );
		return 'available';
	}

	public static function offer_notice(): void {
		$info = get_site_transient( self::offer_key() );
		if ( ! is_object( $info ) || empty( $info->version ) || ! version_compare( $info->version, SECWP_VERSION, '>' ) ) {
			echo '<div class="notice notice-info"><p>' . esc_html__( 'Please check for INI Protector updates again to refresh the available release.', 'ini-protector' ) . '</p></div>';
			return;
		}
		$url = wp_nonce_url( add_query_arg( array( 'action' => 'secwp_install_update', 'version' => $info->version ), network_admin_url( 'admin.php' ) ), 'secwp_install_update_' . $info->version );
		printf(
			'<div class="notice notice-success"><p>%s <a href="%s">%s</a></p></div>',
			/* translators: %s: available plugin version. */
			esc_html( sprintf( __( 'INI Protector %s is available from WordPress.org.', 'ini-protector' ), $info->version ) ),
			esc_url( $url ),
			esc_html__( 'Update now', 'ini-protector' )
		);
	}

	/** Use the native upgrader for one explicit update, including filesystem prompts. */
	public static function install(): void {
		if ( ! current_user_can( 'update_plugins' ) ) {
			wp_die( esc_html__( 'You do not have permission to update plugins.', 'ini-protector' ), '', array( 'response' => 403 ) );
		}
		$version = isset( $_GET['version'] ) && is_string( $_GET['version'] ) ? sanitize_text_field( wp_unslash( $_GET['version'] ) ) : '';
		check_admin_referer( 'secwp_install_update_' . $version );
		$info = self::latest();
		if ( is_wp_error( $info ) ) {
			wp_die( esc_html( $info->get_error_message() ) );
		}
		if ( $version !== $info->version || ! version_compare( $version, SECWP_VERSION, '>' ) || ! self::compatible( $info ) ) {
			wp_die( esc_html__( 'This update is no longer available or compatible. Return to Plugins and check for updates again.', 'ini-protector' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		set_current_screen( 'plugins' );
		$GLOBALS['parent_file'] = 'plugins.php';
		$GLOBALS['title'] = __( 'Update INI Protector', 'ini-protector' );
		require_once ABSPATH . 'wp-admin/admin-header.php';
		$url = add_query_arg( array( 'action' => 'secwp_install_update', 'version' => $version ), network_admin_url( 'admin.php' ) );
		$skin = new Plugin_Upgrader_Skin( array( 'url' => $url, 'nonce' => 'secwp_install_update_' . $version, 'plugin' => SECWP_BASENAME, 'title' => $GLOBALS['title'] ) );
		self::upgrade( $info, $skin );
		require_once ABSPATH . 'wp-admin/admin-footer.php';
		exit;
	}

	/** Explicit ZIP replacement through core's upload/install path, without update-cache hooks. */
	public static function upgrade( $info, $skin ) {
		$installer = new Plugin_Upgrader( $skin );
		$options = static function ( $options ) use ( $info ) {
			if ( $options['package'] === $info->download_link && 'plugin' === ( $options['hook_extra']['type'] ?? '' ) ) {
				$options['hook_extra']['plugin'] = SECWP_BASENAME;
				// Core 6.3+ can restore the old directory if copying the replacement fails.
				$options['hook_extra']['temp_backup'] = array( 'slug' => dirname( SECWP_BASENAME ), 'src' => WP_PLUGIN_DIR, 'dir' => 'plugins' );
			}
			return $options;
		};
		$validate = static function ( $source, $remote_source, $upgrader, $extra ) use ( $info, $installer ) {
			if ( is_wp_error( $source ) || $upgrader !== $installer ) {
				return $source;
			}
			global $wp_filesystem;
			$content = $wp_filesystem->get_contents( trailingslashit( $source ) . 'ini-protector.php' );
			if ( basename( untrailingslashit( $source ) ) !== dirname( SECWP_BASENAME ) ||
				! is_string( $content ) || ! preg_match( '/^[ \t\/*#@]*Version:\s*([^\r\n]+)/mi', $content, $match ) || trim( $match[1] ) !== $info->version ||
				! preg_match( '/^[ \t\/*#@]*Plugin Name:\s*INI Protector\s*$/mi', $content ) ) {
				return new WP_Error( 'unexpected_package', __( 'The downloaded package does not match the selected INI Protector release.', 'ini-protector' ) );
			}
			return $source;
		};
		add_filter( 'upgrader_package_options', $options );
		add_filter( 'upgrader_source_selection', $validate, 20, 4 );
		try {
			return $installer->install( $info->download_link, array( 'overwrite_package' => true ) );
		} finally {
			remove_filter( 'upgrader_package_options', $options );
			remove_filter( 'upgrader_source_selection', $validate, 20 );
		}
	}
}
