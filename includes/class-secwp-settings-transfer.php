<?php
/**
 * Export and import INI Protector settings as a JSON file, with one-step undo.
 *
 * Only configuration travels: the on/off state of each protection and its fields
 * (SecurityWP_Features::OPT_STATE / OPT_CONFIG). Everything that describes one site
 * stays behind — traffic history, the integrity baseline, vulnerability results, IP
 * blocks, platform events, asset salts, and every per-user secret (2FA).
 *
 * Secrets (password-type fields: the site password and the webhook secret) are left
 * out unless the exporter opts in. An import never clears a secret, so a file without
 * them leaves the receiving site's secrets as they are.
 *
 * An import is applied through the same path as the settings form: values go through
 * SecurityWP_Features::set() / set_config() and their sanitizers, then through
 * SecurityWP_Admin::after_change() so .htaccess rules, rewrite rules and schedules
 * follow the new settings. A crafted file can store nothing the form would refuse.
 *
 * Used by the Utilities page and by `wp inipr settings`.
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Settings_Transfer {

	const FORMAT     = 'ini-protector-settings';
	const SCHEMA     = 1;
	const MAX_BYTES  = 262144; // A real export is a few KB.
	const OPT_UNDO   = 'secwp_settings_undo';
	const PENDING    = 'secwp_settings_import_'; // + user ID: a parsed file awaiting confirmation.

	/**
	 * Changes worth a second look before they are applied: they decide how people sign in,
	 * who is let in, or who gets blocked. Shown highlighted in the preview.
	 */
	const SENSITIVE = array( 'hide_login', 'password_protect', 'two_factor', 'limit_login', 'autoblock', 'altcha', 'disable_rest_guests' );

	/** The export document. Secrets only when asked for. */
	public static function export( bool $include_secrets = false ): array {
		$state    = SecurityWP_Features::state();
		$features = array();
		foreach ( SecurityWP_Features::catalog() as $key => $def ) {
			$entry = array( 'on' => ! empty( $state[ $key ] ) );
			if ( ! empty( $def['fields'] ) ) {
				$config = SecurityWP_Features::config( $key );
				foreach ( $def['fields'] as $fkey => $fdef ) {
					if ( 'password' === ( $fdef['type'] ?? '' ) && ! $include_secrets ) {
						unset( $config[ $fkey ] );
					}
				}
				$entry['config'] = $config;
			}
			$features[ $key ] = $entry;
		}
		return array(
			'format'           => self::FORMAT,
			'schema'           => self::SCHEMA,
			'plugin_version'   => SECWP_VERSION,
			'exported_at'      => gmdate( 'c' ),
			'site'             => home_url( '/' ),
			'secrets_included' => $include_secrets,
			'features'         => $features,
		);
	}

	public static function export_json( bool $include_secrets = false ): string {
		return (string) wp_json_encode( self::export( $include_secrets ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	public static function filename(): string {
		// Dots become dashes: sanitize_file_name() would otherwise munge "example.com" into "example_.com".
		$host = str_replace( '.', '-', (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return sanitize_file_name( 'ini-protector-settings-' . ( '' !== $host ? $host : 'site' ) . '-' . gmdate( 'Y-m-d' ) . '.json' );
	}

	/**
	 * Decode and check a settings file. Returns the document reduced to features this
	 * version knows (plus the list of ignored keys), or a WP_Error that says what is wrong.
	 *
	 * @return array|WP_Error
	 */
	public static function parse( string $json ) {
		if ( strlen( $json ) > self::MAX_BYTES ) {
			return new WP_Error( 'too_large', __( 'That file is too large to be an INI Protector settings export.', 'ini-protector' ) );
		}
		$doc = json_decode( $json, true );
		if ( ! is_array( $doc ) || self::FORMAT !== ( $doc['format'] ?? '' ) || ! isset( $doc['features'] ) || ! is_array( $doc['features'] ) ) {
			return new WP_Error( 'not_settings', __( 'That file is not an INI Protector settings export.', 'ini-protector' ) );
		}
		if ( (int) ( $doc['schema'] ?? 0 ) > self::SCHEMA ) {
			return new WP_Error( 'newer_schema', __( 'That file was exported by a newer version of INI Protector. Update this site first, then import it.', 'ini-protector' ) );
		}
		$catalog  = SecurityWP_Features::catalog();
		$features = array();
		$ignored  = array();
		foreach ( $doc['features'] as $key => $entry ) {
			$key = (string) $key;
			if ( ! isset( $catalog[ $key ] ) || ! is_array( $entry ) ) {
				$ignored[] = sanitize_key( $key );
				continue;
			}
			$clean = array();
			if ( array_key_exists( 'on', $entry ) ) {
				$clean['on'] = (bool) $entry['on'];
			}
			if ( isset( $entry['config'] ) && is_array( $entry['config'] ) && ! empty( $catalog[ $key ]['fields'] ) ) {
				// Known fields only; set_config() sanitizes the values themselves.
				$clean['config'] = array_intersect_key( $entry['config'], $catalog[ $key ]['fields'] );
			}
			$features[ $key ] = $clean;
		}
		return array(
			'plugin_version'   => is_string( $doc['plugin_version'] ?? null ) ? $doc['plugin_version'] : '',
			'exported_at'      => is_string( $doc['exported_at'] ?? null ) ? $doc['exported_at'] : '',
			'site'             => is_string( $doc['site'] ?? null ) ? esc_url_raw( $doc['site'] ) : '',
			'secrets_included' => ! empty( $doc['secrets_included'] ),
			'features'         => $features,
			'ignored'          => array_values( array_filter( $ignored ) ),
		);
	}

	/**
	 * What applying a parsed document would change, one row per setting. Secrets are
	 * reported as changed or not, never shown.
	 *
	 * @return array<int, array{key:string, label:string, field:string, from:string, to:string, sensitive:bool}>
	 */
	public static function diff( array $parsed ): array {
		$catalog = SecurityWP_Features::catalog();
		$state   = SecurityWP_Features::state();
		$rows    = array();
		foreach ( $parsed['features'] as $key => $entry ) {
			$def       = $catalog[ $key ];
			$label     = (string) $def['label'];
			$sensitive = in_array( $key, self::SENSITIVE, true );
			if ( isset( $entry['on'] ) && $entry['on'] !== ! empty( $state[ $key ] ) ) {
				$rows[] = array(
					'key'       => $key,
					'label'     => $label,
					'field'     => '',
					'from'      => ! empty( $state[ $key ] ) ? __( 'On', 'ini-protector' ) : __( 'Off', 'ini-protector' ),
					'to'        => $entry['on'] ? __( 'On', 'ini-protector' ) : __( 'Off', 'ini-protector' ),
					'sensitive' => $sensitive,
				);
			}
			if ( empty( $entry['config'] ) ) {
				continue;
			}
			// Compare against what set_config() would actually store, not the raw file value.
			$current = SecurityWP_Features::config( $key );
			$after   = self::preview_config( $key, $entry['config'] );
			foreach ( $def['fields'] as $fkey => $fdef ) {
				// Compared as displayed: '5' saved by an older version vs 5, or a never-saved list ('')
				// vs an empty one ([]), are the same setting, not a change.
				if ( ! array_key_exists( $fkey, $entry['config'] ) || self::display( $after[ $fkey ] ) === self::display( $current[ $fkey ] ) ) {
					continue;
				}
				$secret = 'password' === ( $fdef['type'] ?? '' );
				$rows[] = array(
					'key'       => $key,
					'label'     => $label,
					'field'     => (string) ( $fdef['label'] ?? $fkey ),
					'from'      => $secret ? __( '(secret)', 'ini-protector' ) : self::display( $current[ $fkey ] ),
					'to'        => $secret ? __( '(new secret)', 'ini-protector' ) : self::display( $after[ $fkey ] ),
					'sensitive' => $sensitive || $secret,
				);
			}
		}
		return $rows;
	}

	/**
	 * Apply a parsed document. The previous settings are saved first so the import can be
	 * undone. Returns the rows that changed.
	 */
	public static function apply( array $parsed, string $via = 'admin' ): array {
		$rows = self::diff( $parsed );
		update_option(
			self::OPT_UNDO,
			array(
				'state'  => get_option( SecurityWP_Features::OPT_STATE, array() ),
				'config' => get_option( SecurityWP_Features::OPT_CONFIG, array() ),
				'time'   => time(),
				'user'   => get_current_user_id(),
				'via'    => $via,
			),
			false
		);
		$before = SecurityWP_Features::state();
		foreach ( $parsed['features'] as $key => $entry ) {
			if ( isset( $entry['on'] ) ) {
				SecurityWP_Features::set( $key, $entry['on'] );
			}
			if ( ! empty( $entry['config'] ) ) {
				SecurityWP_Features::set_config( $key, self::form_values( $key, $entry['config'] ) );
			}
		}
		self::sync( $before, array_unique( wp_list_pluck( $rows, 'key' ) ) );
		do_action(
			'secwp_platform_event',
			'settings_imported',
			sprintf( '%d setting(s) changed by a settings import', count( $rows ) ),
			array( 'user_id' => get_current_user_id(), 'via' => $via, 'source' => $parsed['site'], 'changes' => count( $rows ) )
		);
		return $rows;
	}

	/** The saved pre-import settings, if an import can be undone. */
	public static function undo_point(): ?array {
		$undo = get_option( self::OPT_UNDO );
		return is_array( $undo ) && isset( $undo['state'], $undo['config'], $undo['time'] ) ? $undo : null;
	}

	/** Put back the settings as they were before the last import. */
	public static function undo( string $via = 'admin' ): bool {
		$undo = self::undo_point();
		if ( ! $undo ) {
			return false;
		}
		$before = SecurityWP_Features::state();
		$config = get_option( SecurityWP_Features::OPT_CONFIG, array() );
		// These were the stored options themselves, already sanitized when first saved.
		update_option( SecurityWP_Features::OPT_STATE, (array) $undo['state'], false );
		update_option( SecurityWP_Features::OPT_CONFIG, (array) $undo['config'], false );
		$changed = array();
		foreach ( array_keys( SecurityWP_Features::catalog() ) as $key ) {
			if ( ( $config[ $key ] ?? null ) !== ( ( (array) $undo['config'] )[ $key ] ?? null ) ) {
				$changed[] = $key;
			}
		}
		self::sync( $before, $changed );
		delete_option( self::OPT_UNDO );
		do_action( 'secwp_platform_event', 'settings_import_undone', 'Settings restored to before the last import', array( 'user_id' => get_current_user_id(), 'via' => $via ) );
		return true;
	}

	/** The hidden login address, if one is in force, to show after an import. */
	public static function login_notice(): string {
		return SecurityWP_Features::is_on( 'hide_login' ) && SecurityWP_Hide_Login::is_active() ? SecurityWP_Hide_Login::login_url() : '';
	}

	/* Pending import for the admin preview (one per user, short-lived). */

	public static function stash( array $parsed ): void {
		set_transient( self::PENDING . get_current_user_id(), $parsed, 15 * MINUTE_IN_SECONDS );
	}

	public static function stashed(): ?array {
		$parsed = get_transient( self::PENDING . get_current_user_id() );
		return is_array( $parsed ) && isset( $parsed['features'] ) ? $parsed : null;
	}

	public static function forget(): void {
		delete_transient( self::PENDING . get_current_user_id() );
	}

	/* Internals */

	/**
	 * Values for set_config(): the current config with the file's fields laid over it, marked
	 * as a full submission. Checkbox fields absent from the file keep their current value
	 * instead of reading as unticked (set_config()'s form semantics).
	 */
	private static function form_values( string $key, array $incoming ): array {
		$values                = array_merge( SecurityWP_Features::config( $key ), $incoming );
		$values['__submitted'] = 1;
		return $values;
	}

	/** What set_config() would store for these values, merged with field defaults like config(). */
	private static function preview_config( string $key, array $incoming ): array {
		$clean = (array) SecurityWP_Features::clean_config( $key, self::form_values( $key, $incoming ) );
		$out   = array();
		foreach ( SecurityWP_Features::catalog()[ $key ]['fields'] as $fkey => $def ) {
			$out[ $fkey ] = $clean[ $fkey ] ?? ( $def['default'] ?? '' );
		}
		return $out;
	}

	/** Run the settings form's side effects for every feature whose state or config moved. */
	private static function sync( array $before, array $config_changed ): void {
		$after = SecurityWP_Features::state();
		foreach ( $after as $key => $on ) {
			if ( $on !== ( $before[ $key ] ?? false ) || in_array( $key, $config_changed, true ) ) {
				SecurityWP_Admin::after_change( $key, $on );
			}
		}
	}

	private static function display( $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? __( 'On', 'ini-protector' ) : __( 'Off', 'ini-protector' );
		}
		if ( is_array( $value ) ) {
			$value = implode( ', ', array_map( 'strval', $value ) );
		}
		$value = trim( (string) $value );
		$value = str_replace( array( "\r\n", "\n" ), ', ', $value );
		return '' === $value ? __( '(empty)', 'ini-protector' ) : $value;
	}
}
