<?php
/**
 * Tweak implementations. Each enabled tweak wires up its WordPress hooks. Kept separate from
 * the registry (SecurityWP_Features) so the catalog stays readable. All tweaks are pure WordPress
 * (no file edits) and reverse cleanly when toggled off.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Tweaks {

	/** Site-specific secret behind the masked ?ver= token. Autoloaded — read on every front-end request. */
	const OPT_VER_SALT = 'secwp_ver_salt';

	/** Audit trail of salt rotations, newest first. Not autoloaded — read only by the admin page and WP-CLI. */
	const OPT_VER_SALT_LOG = 'secwp_ver_salt_log';

	/** How many rotations to keep. Enough to explain a cache-miss spike; bounded so the option can't grow. */
	const VER_SALT_LOG_MAX = 10;

	/**
	 * REST namespaces that must NEVER be blocked by "Require login for REST API",
	 * regardless of the admin whitelist — otherwise we could lock out the INI WP
	 * control panel (wp.ini.bg) or a family plugin that the panel integrates with.
	 *
	 * "Family" is determined by the INI WP connector, which owns site identity
	 * (the connection token) and is therefore the authority on what integrates
	 * with wp.ini.bg. When the connector is present we read its registry
	 * (iniwp_family_rest_namespaces()); family plugins — including SeoWP and
	 * INI Protector itself — register their namespaces INTO that registry via the
	 * connector's `iniwp_family_rest_namespaces` filter, so the connector
	 * aggregates the whole family without hardcoding sibling names.
	 *
	 * When the connector is absent (INI Protector running standalone) we fall back
	 * to our own namespace plus a built-in default set, and still expose the
	 * local `secwp_rest_always_exempt` filter for one-off additions.
	 *
	 * Every namespace here authenticates itself (HMAC or admin cookie-nonce), so
	 * exempting them from the guest-block doesn't weaken security — it just lets
	 * their own auth decide.
	 *
	 * @return string[] Lower-cased namespace prefixes.
	 */
	public static function always_exempt(): array {
		// Preferred source: the connector's family registry (authoritative).
		if ( function_exists( 'iniwp_family_rest_namespaces' ) ) {
			$list = (array) iniwp_family_rest_namespaces();
			// Always include our own namespace even if we haven't registered yet.
			$list[] = defined( 'SECWP_NAMESPACE' ) ? SECWP_NAMESPACE : 'secwp/v1';
		} else {
			// Standalone fallback: connector not installed.
			$list = array(
				defined( 'SECWP_NAMESPACE' ) ? SECWP_NAMESPACE : 'secwp/v1',
				defined( 'SECWP_CONNECTOR_NAMESPACE' ) ? SECWP_CONNECTOR_NAMESPACE : 'iniwp/v1',
				'iniwp/admin',
				'iniseo/v1',
			);
		}

		/**
		 * Local override for the always-exempt REST namespaces. Prefer the
		 * connector's `iniwp_family_rest_namespaces` filter for family plugins;
		 * this one is for site-level one-offs or when the connector is absent.
		 *
		 * @param string[] $list Always-exempt namespace prefixes.
		 */
		$list = apply_filters( 'secwp_rest_always_exempt', $list );

		$out = array();
		foreach ( (array) $list as $ns ) {
			$ns = strtolower( trim( (string) $ns ) );
			if ( '' !== $ns ) {
				$out[] = $ns;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/** Apply every enabled tweak. $state: key => bool. */
	public static function apply( array $state ): void {
		foreach ( $state as $key => $on ) {
			if ( ! $on ) {
				continue;
			}
			$method = 'tweak_' . $key;
			if ( method_exists( __CLASS__, $method ) ) {
				self::$method();
			}
		}
	}

	// ── Security ──────────────────────────────────────────────────────────────

	private static function tweak_disable_xmlrpc(): void {
		// Defense in depth: neutralise every XML-RPC method (incl. pingback.ping and
		// system.multicall) for any programmatic/internal XML-RPC path.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );

		// Hard-block a direct hit on xmlrpc.php with an early 403, BEFORE WordPress
		// finishes booting (theme/init/REST never run). xmlrpc.php defines
		// XMLRPC_REQUEST before loading WP, and this tweak fires on plugins_loaded,
		// so the request is short-circuited at near-zero cost — no theme, no query.
		// This makes a flood of bogus xmlrpc.php requests cheap to absorb and returns
		// the clean 403 a server-level deny would, without writing any server config.
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			self::block_xmlrpc_request();
		}
	}

	/** Send a 403 and stop, before WordPress finishes loading. */
	private static function block_xmlrpc_request(): void {
		if ( ! headers_sent() ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			nocache_headers();
		}
		// Minimal XML-RPC fault so a well-behaved client gets a parseable refusal
		// rather than an empty body; scanners just see the 403.
		echo "403 Forbidden: XML-RPC is disabled on this site.\n";
		exit;
	}

	private static function tweak_disable_file_editor(): void {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	private static function tweak_hide_login(): void {
		( new SecurityWP_Hide_Login() )->register();
	}

	private static function tweak_password_protect(): void {
		( new SecurityWP_Password_Protect() )->register();
	}

	private static function tweak_disable_comments(): void {
		( new SecurityWP_Disable_Comments() )->register();
	}

	private static function tweak_altcha(): void {
		( new SecurityWP_Altcha() )->register();
	}

	private static function tweak_disable_pingbacks(): void {
		// Close pingbacks/trackbacks on every post (front-end) without touching comments.
		add_filter( 'pings_open', '__return_false', 20 );
		// Remove the X-Pingback header advertised on the front-end.
		add_filter( 'wp_headers', static function ( $headers ) {
			unset( $headers['X-Pingback'] );
			return $headers;
		} );
		// Block the XML-RPC pingback/trackback methods (if XML-RPC is otherwise on).
		add_filter( 'xmlrpc_methods', static function ( $methods ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
			return $methods;
		} );
		// Don't advertise pingback in the RSD/head.
		add_filter( 'bloginfo_url', static function ( $output, $key ) {
			return ( 'pingback_url' === $key ) ? '' : $output;
		}, 10, 2 );
	}

	private static function tweak_prevent_user_enum(): void {
		// 404 the classic ?author=N enumeration probe (front-end, non-logged-in).
		add_action( 'template_redirect', static function () {
			if ( is_admin() || is_user_logged_in() ) {
				return;
			}
			// A nonempty author query is an enumeration probe; its value is never consumed.
			if ( isset( $_GET['author'] ) && '' !== $_GET['author'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only probe detection.
				global $wp_query;
				$wp_query->set_404();
				status_header( 404 );
				nocache_headers();
				exit;
			}
		}, 0 );
		// Require login for the REST users endpoint specifically (narrower than disable_rest_guests).
		add_filter( 'rest_endpoints', static function ( $endpoints ) {
			foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
				if ( isset( $endpoints[ $route ] ) ) {
					foreach ( $endpoints[ $route ] as $i => $handler ) {
						if ( is_array( $handler ) && isset( $handler['permission_callback'] ) ) {
							$prev = $handler['permission_callback'];
							$endpoints[ $route ][ $i ]['permission_callback'] = static function ( $request ) use ( $prev ) {
								if ( ! is_user_logged_in() ) {
									return new WP_Error( 'secwp_no_user_enum', 'Authentication required.', array( 'status' => 401 ) );
								}
								return is_callable( $prev ) ? call_user_func( $prev, $request ) : true;
							};
						}
					}
				}
			}
			return $endpoints;
		} );
		// Strip the author link from oEmbed responses (it exposes the user id/slug).
		add_filter( 'oembed_response_data', static function ( $data ) {
			unset( $data['author_url'], $data['author_name'] );
			return $data;
		} );
		// Drop the users provider from core sitemaps.
		add_filter( 'wp_sitemaps_add_provider', static function ( $provider, $name ) {
			return ( 'users' === $name ) ? false : $provider;
		}, 10, 2 );
	}

	private static function tweak_prevent_info_disclosure(): void {
		( new SecurityWP_Info_Disclosure() )->register();
	}

	private static function tweak_security_headers(): void {
		( new SecurityWP_Security_Headers() )->register();
	}

	private static function tweak_traffic_log(): void {
		( new SecurityWP_Traffic_Log() )->register();
	}

	private static function tweak_disable_rest_guests(): void {
		add_filter( 'rest_authentication_errors', static function ( $result ) {
			if ( ! empty( $result ) ) {
				return $result;
			}
			if ( is_user_logged_in() ) {
				return $result;
			}

			$route = SecurityWP_Input::rest_route();
			$route = ltrim( $route, '/' );

			// Always-exempt INI WP family namespaces (never blockable, so the
			// control panel / family plugins can't be locked out).
			$exempt = self::always_exempt();

			// Admin-chosen public namespaces (e.g. headless front-end, oEmbed).
			$whitelist = SecurityWP_Features::get( 'disable_rest_guests', 'whitelist', array() );
			if ( is_array( $whitelist ) ) {
				$exempt = array_merge( $exempt, $whitelist );
			}

			foreach ( $exempt as $ns ) {
				$ns = trim( (string) $ns );
				if ( '' === $ns ) {
					continue;
				}
				// Match the namespace as a path segment: "wp/v2" matches the route
				// "wp/v2/posts" but not a route that merely contains the substring.
				if ( $route === $ns || 0 === strpos( $route, $ns . '/' ) ) {
					return $result;
				}
			}

			return new WP_Error( 'rest_not_logged_in', 'REST API restricted to logged-in users.', array( 'status' => 401 ) );
		} );
	}

	private static function tweak_limit_login(): void {
		( new SecurityWP_Limit_Login() )->register();
	}

	// ── Head cleanup ──────────────────────────────────────────────────────────

	private static function tweak_remove_version_meta(): void {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
	}

	private static function tweak_remove_feed_generator(): void {
		foreach ( array( 'rss2_head', 'commentsrss2_head', 'rss_head', 'rdf_header', 'atom_head', 'comments_atom_head', 'opml_head', 'app_head' ) as $hook ) {
			add_action( $hook, static function () {
				add_filter( 'the_generator', '__return_empty_string' );
			}, 0 );
		}
	}

	private static function tweak_remove_asset_version(): void {
		$strip = static function ( $src ) {
			if ( $src && is_string( $src ) && ! is_admin() && ! is_user_logged_in() ) {
				$src = remove_query_arg( 'ver', $src );
			}
			return $src;
		};
		add_filter( 'style_loader_src', $strip, 9999 );
		add_filter( 'script_loader_src', $strip, 9999 );
	}

	/**
	 * Replace the real ?ver= value with an opaque, salted hash for guests.
	 * Keeps cache-busting (the hash is unique per real version, so it changes
	 * when WP/a plugin updates) while hiding the actual version number.
	 *
	 * No-op when remove_asset_version is also enabled — that one strips ?ver=
	 * entirely, so masking it would be pointless double work.
	 */
	private static function tweak_mask_asset_version(): void {
		if ( SecurityWP_Features::is_on( 'remove_asset_version' ) ) {
			return;
		}
		$salt = self::asset_version_salt();
		$mask = static function ( $src ) use ( $salt ) {
			if ( ! $src || ! is_string( $src ) || is_admin() || is_user_logged_in() ) {
				return $src;
			}
			$parts = wp_parse_url( $src );
			if ( empty( $parts['query'] ) ) {
				return $src;
			}
			parse_str( $parts['query'], $args );
			if ( ! isset( $args['ver'] ) || '' === $args['ver'] ) {
				return $src;
			}
			// 8 hex chars of a salted hash — opaque, stable, and unique per real version.
			$token       = substr( hash( 'sha1', $salt . '|' . $args['ver'] ), 0, 8 );
			$args['ver'] = $token;
			return add_query_arg( 'ver', $token, remove_query_arg( 'ver', $src ) );
		};
		add_filter( 'style_loader_src', $mask, 9999 );
		add_filter( 'script_loader_src', $mask, 9999 );
	}

	/**
	 * A stable, site-specific secret so masked tokens can't be reversed to a
	 * known WordPress/plugin version via a precomputed table. Generated once,
	 * stored autoloaded, and reused independently of authentication secrets.
	 *
	 * Stays private: the salt is the secret that makes the mask worth having, and
	 * nothing outside this class needs the value itself. Callers that want to
	 * identify the current salt use asset_version_fingerprint().
	 */
	private static function asset_version_salt(): string {
		self::migrate_asset_version_salt();
		$salt = get_option( self::OPT_VER_SALT );
		if ( is_string( $salt ) && '' !== $salt ) {
			return $salt;
		}
		$salt = self::generate_asset_version_salt();
		update_option( self::OPT_VER_SALT, $salt, true );
		return $salt;
	}

	/** Replace legacy values even when masking is disabled; never copy auth salts into options. */
	public static function migrate_asset_version_salt(): void {
		if ( 2 === (int) get_option( 'secwp_ver_salt_schema', 0 ) ) {
			return;
		}
		if ( false !== get_option( self::OPT_VER_SALT, false ) ) {
			update_option( self::OPT_VER_SALT, self::generate_asset_version_salt(), true );
		}
		update_option( 'secwp_ver_salt_schema', 2, false );
	}

	/** A fresh secret, in the same shape whether it is the first one or a rotation. */
	private static function generate_asset_version_salt(): string {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * A short, non-reversible identifier for the salt currently in use.
	 *
	 * Safe to print in wp-admin, in WP-CLI output and in a deploy log: it changes
	 * on every rotation (so you can tell two salts apart, and confirm a rotate
	 * landed) but reveals nothing about the salt, which must stay secret or the
	 * masked tokens become reversible to real version numbers again.
	 */
	public static function asset_version_fingerprint(): string {
		return substr( hash( 'sha1', 'fp|' . self::asset_version_salt() ), 0, 8 );
	}

	/**
	 * Whether masked ?ver= tokens are actually being emitted right now.
	 *
	 * Rotating the salt only changes what visitors see while this is true: with
	 * the mask off the real ?ver= is emitted, and with "Remove version on static
	 * assets" on there is no ?ver= at all (mask_asset_version returns early).
	 */
	public static function asset_version_mask_active(): bool {
		return SecurityWP_Features::is_on( 'mask_asset_version' )
			&& ! SecurityWP_Features::is_on( 'remove_asset_version' );
	}

	/**
	 * Replace the salt, changing every masked asset URL on the site at once.
	 *
	 * The masked token is derived from the version a plugin *declares*, so an
	 * enqueue with a hard-coded version string ('1.3' that never moves) keeps the
	 * same URL after the file behind it changes, and returning visitors keep the
	 * copy in their browser cache. Rotating is the blunt instrument for that: it
	 * invalidates every CSS and JS URL, so the next visit re-downloads all of
	 * them once. Fine after a deploy, wasteful as a habit — hence the cost is
	 * stated at both call sites rather than buried here.
	 *
	 * Records who did it and when, so a spike in cache-miss traffic can be
	 * explained afterwards instead of guessed at.
	 *
	 * @param string   $via     Where the rotation came from: 'admin', 'wp-cli', or a caller's own label.
	 * @param int|null $user_id Acting user; defaults to the current user (0 under WP-CLI / cron).
	 * @return array<string,mixed> The rotation record that was stored.
	 */
	public static function rotate_asset_version_salt( string $via = 'admin', ?int $user_id = null ): array {
		$previous = self::asset_version_fingerprint(); // Also seeds the salt if this site never had one.
		$old      = (string) get_option( self::OPT_VER_SALT, '' );

		// A new salt that is genuinely new: a repeat would leave every URL unchanged
		// and quietly turn "rotate" into a no-op. Collision is vanishingly unlikely,
		// so the loop is a guarantee rather than a real code path.
		$salt = '';
		for ( $i = 0; $i < 5; $i++ ) {
			$salt = self::generate_asset_version_salt();
			if ( '' !== $salt && $salt !== $old ) {
				break;
			}
		}
		if ( '' === $salt || $salt === $old ) {
			$salt = hash( 'sha256', $old . '|' . microtime( true ) . '|' . wp_rand() );
		}
		update_option( self::OPT_VER_SALT, $salt, true );

		if ( null === $user_id ) {
			$user_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		}
		$user  = $user_id ? get_user_by( 'id', $user_id ) : null;
		$entry = array(
			'time'        => time(),
			'via'         => sanitize_key( $via ),
			'user_id'     => (int) $user_id,
			'user_login'  => $user ? (string) $user->user_login : '',
			'previous'    => $previous,
			'fingerprint' => self::asset_version_fingerprint(),
		);

		$log = self::asset_version_rotations();
		array_unshift( $log, $entry );
		update_option( self::OPT_VER_SALT_LOG, array_slice( $log, 0, self::VER_SALT_LOG_MAX ), false );

		/*
		 * Page caches serve stored HTML, which still carries the OLD asset URLs —
		 * so on a cached site the rotation is invisible until that cache is purged.
		 * This hook is where a deploy script or a cache plugin bridge purges it.
		 */
		do_action( 'secwp_asset_salt_rotated', $entry );

		do_action(
			'secwp_platform_event',
			'asset_salt_rotated',
			sprintf( 'Asset cache token rotated (%s → %s) via %s', $previous, $entry['fingerprint'], $entry['via'] ),
			array(
				'via'         => $entry['via'],
				'user_id'     => $entry['user_id'],
				'user_login'  => $entry['user_login'],
				'fingerprint' => $entry['fingerprint'],
			)
		);

		return $entry;
	}

	/**
	 * The rotation audit trail, newest first.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function asset_version_rotations(): array {
		$log = get_option( self::OPT_VER_SALT_LOG, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array();
		foreach ( $log as $entry ) {
			if ( is_array( $entry ) && isset( $entry['time'] ) ) {
				$out[] = $entry;
			}
		}
		return $out;
	}

	/**
	 * The most recent rotation, or null on a site that has never rotated.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function asset_version_last_rotation(): ?array {
		$log = self::asset_version_rotations();
		return $log ? $log[0] : null;
	}

	private static function tweak_remove_wlw(): void {
		remove_action( 'wp_head', 'wlwmanifest_link' );
	}

	private static function tweak_remove_rsd(): void {
		remove_action( 'wp_head', 'rsd_link' );
	}

	private static function tweak_remove_shortlink(): void {
		remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
	}

	/**
	 * Remove auto-discovery hints for the REST API + oEmbed, and the version
	 * leak inside oEmbed responses. The REST API stays fully functional — we
	 * only strip the discovery <link> tags, the wp-json Link: header, and the
	 * WordPress version; we do NOT disable any endpoint.
	 */
	private static function tweak_remove_rest_discovery(): void {
		// REST API discovery: <link rel="https://api.w.org/"> and the Link: header.
		remove_action( 'wp_head', 'rest_output_link_wp_head' );
		remove_action( 'template_redirect', 'rest_output_link_header', 11 );

		// oEmbed discovery: the <link rel="alternate" type="application/json+oembed">
		// tags. Core registers this callback TWICE (default-filters.php) — at
		// priority 4 (the one that actually prints) and at the default 10 — so we
		// must remove both, otherwise the links still render.
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 4 );
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );

		// Blank the WordPress version in the generator tag, which leaks into the
		// oEmbed HTML render (and feeds). NOTE: the JSON oEmbed "version" field is
		// the oEmbed spec version (1.0), NOT the WP version — we must NOT touch it.
		add_filter( 'the_generator', '__return_empty_string' );
	}

	private static function tweak_disable_dashicons(): void {
		add_action( 'wp_enqueue_scripts', static function () {
			if ( ! is_user_logged_in() ) {
				wp_deregister_style( 'dashicons' );
				wp_dequeue_style( 'dashicons' );
			}
		}, 100 );
	}

	// ── SEO & privacy ─────────────────────────────────────────────────────────

	private static function tweak_disable_feeds(): void {
		$kill = static function () {
			wp_die( esc_html__( 'Feeds are disabled on this site.', 'ini-protector' ), '', array( 'response' => 410 ) );
		};
		foreach ( array( 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom', 'do_feed_rss2_comments', 'do_feed_atom_comments' ) as $hook ) {
			add_action( $hook, $kill, 1 );
		}
		remove_action( 'wp_head', 'feed_links', 2 );
		remove_action( 'wp_head', 'feed_links_extra', 3 );
	}

	private static function tweak_disable_author_archives(): void {
		// 404 author archive requests.
		add_action( 'template_redirect', static function () {
			if ( is_author() ) {
				global $wp_query;
				$wp_query->set_404();
				status_header( 404 );
				nocache_headers();
			}
		} );
		// Remove author links output by the_author_posts_link.
		add_filter( 'author_link', static function () {
			return home_url( '/' );
		} );
		// Drop authors from the sitemap.
		add_filter( 'wp_sitemaps_add_provider', static function ( $provider, $name ) {
			return ( 'users' === $name ) ? false : $provider;
		}, 10, 2 );
	}

	private static function tweak_obfuscate_author_slugs(): void {
		( new SecurityWP_Author_Slugs() )->register();
	}

	// ── SEO & privacy (continued) ─────────────────────────────────────────────

	private static function tweak_email_obfuscator(): void {
		( new SecurityWP_Email_Protect() )->register();
	}
}
