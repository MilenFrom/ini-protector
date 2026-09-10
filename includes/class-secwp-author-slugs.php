<?php
/**
 * Obfuscate author page URLs: replace /author/username/ with /author/<random-token>/, 404 the
 * original username URLs, and mask slugs in the /wp/v2/users REST endpoint.
 *
 * The token and its reverse lookup are stored lazily in per-author options.
 * Tokens are independent random identifiers, reused so links survive WordPress salt rotation.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Author_Slugs {

	const TOKEN_PREFIX = 'inipr_author_token_';
	const OWNER_PREFIX = 'inipr_author_owner_';

	public function register(): void {
		add_filter( 'author_link', array( $this, 'filter_author_link' ), 10, 2 );
		add_filter( 'request', array( $this, 'resolve_request' ) );
		add_filter( 'rest_prepare_user', array( $this, 'filter_rest_user' ), 10, 2 );
	}

	/** Retire every legacy salt-derived identifier, including when this feature is off. */
	public static function migrate_legacy_tokens(): void {
		delete_option( 'secwp_author_tokens' );
	}

	/** Persist one winner without add_option()'s duplicate-key overwrite behavior. */
	private function claim_option( string $key, string $value ): void {
		global $wpdb;
		// The options table has a unique option_name index; values never autoload.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- atomic insert-if-absent is required for stable public URLs.
		$wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, %s)", $key, $value, 'no' ) );
		// Discard negative and per-option caches before reading the persisted winner.
		wp_cache_delete( 'notoptions', 'options' );
		wp_cache_delete( $key, 'options' );
	}

	private function ensure_token( int $user_id ): string {
		$key = self::TOKEN_PREFIX . $user_id;
		$token = get_option( $key, false );
		if ( false === $token ) {
			// The unique option name selects one winner even for concurrent requests.
			$this->claim_option( $key, bin2hex( random_bytes( 16 ) ) );
			$token = get_option( $key );
		}
		if ( ! is_string( $token ) || ! preg_match( '/^[a-f0-9]{32}$/D', $token ) ) {
			throw new RuntimeException( 'Invalid INI Protector author token storage.' );
		}
		$reverse = self::OWNER_PREFIX . $token;
		if ( false === get_option( $reverse, false ) ) {
			$this->claim_option( $reverse, (string) $user_id );
		}
		if ( (int) get_option( $reverse ) !== $user_id ) {
			throw new RuntimeException( 'INI Protector author token could not be persisted.' );
		}
		return $token;
	}

	/** Rewrite generated author links to use the token. */
	public function filter_author_link( string $link, int $author_id ): string {
		$token = $this->ensure_token( $author_id );
		// Replace the trailing /author/<slug>/ segment with the token.
		return preg_replace( '#/author/[^/]+/?$#', '/author/' . $token . '/', $link );
	}

	/** Map an incoming /author/<token>/ back to the real author; 404 raw-username requests. */
	public function resolve_request( array $qv ): array {
		if ( ! isset( $qv['author_name'] ) || '' === $qv['author_name'] ) {
			return $qv;
		}
		$requested = $qv['author_name'];
		if ( is_string( $requested ) && preg_match( '/^[a-f0-9]{32}$/D', $requested ) ) {
			$user_id = (int) get_option( self::OWNER_PREFIX . $requested, 0 );
			// Check both directions so stale or incomplete state never becomes an alias.
			if ( $user_id > 0 && get_option( self::TOKEN_PREFIX . $user_id ) === $requested && get_user_by( 'id', $user_id ) ) {
				unset( $qv['author_name'] );
				$qv['author'] = $user_id;
				return $qv;
			}
		}

		// A raw username (or unknown) was requested → force a 404.
		$qv['author_name'] = '___secwp_block___';
		return $qv;
	}

	/** Hide the real slug in the REST users endpoint. */
	public function filter_rest_user( $response, $user ) {
		if ( is_object( $response ) && isset( $response->data ) && is_array( $response->data ) ) {
			$token = $this->ensure_token( (int) $user->ID );
			if ( isset( $response->data['slug'] ) ) {
				$response->data['slug'] = $token;
			}
			if ( isset( $response->data['link'] ) ) {
				$response->data['link'] = preg_replace( '#/author/[^/]+/?$#', '/author/' . $token . '/', (string) $response->data['link'] );
			}
		}
		return $response;
	}
}
