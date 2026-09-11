<?php
/**
 * Feature/tweak registry, storage, and config.
 *
 * Each tweak has: a category, label, description, and optional `fields` (config inputs). The
 * on/off state and field values are stored in two options. The actual behavior lives in
 * SecurityWP_Tweaks (registered on load for whatever is enabled) — this class is the model.
 *
 * Field types: 'textarea' (code), 'number', 'text', 'checkbox' (bool), 'select', 'color',
 * 'email', 'password', 'page', 'posttypes' (multi-select of public types), 'roles'
 * (multi-select of editable roles).
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Features {

	const OPT_STATE  = 'secwp_features';        // key => bool
	const OPT_CONFIG = 'secwp_features_config'; // key => [ field => value ]

	/** Category labels, in display order. */
	public static function categories(): array {
		return array(
			'security' => 'Security',
			'head'     => 'Head cleanup',
			'seo'      => 'SEO & privacy',
		);
	}

	/**
	 * The tweak catalog. Each: category, label, desc, optional fields.
	 * fields: key => [ type, label, desc?, placeholder?, default? ].
	 */
	public static function catalog(): array {
		return array(
			// ── Security ──
			'disable_xmlrpc'      => array( 'cat' => 'security', 'label' => 'Disable XML-RPC', 'desc' => 'Block xmlrpc.php — closes a common brute-force/DDoS vector.' ),
			'disable_file_editor' => array( 'cat' => 'security', 'label' => 'Disable theme/plugin file editor', 'desc' => 'Hide the built-in code editor (DISALLOW_FILE_EDIT).' ),
			'disable_rest_guests' => array(
				'cat'    => 'security',
				'label'  => 'Require login for REST API',
				'desc'   => 'Block anonymous REST access. The INI WP channel always stays exempt; tick any namespaces below that must remain public (e.g. a headless front-end, oEmbed, a contact-form endpoint).',
				'fields' => array(
					'whitelist' => array(
						'type'  => 'rest_namespaces',
						'label' => 'Keep these REST namespaces public',
						'desc'  => 'Anonymous requests to the ticked namespaces are allowed; everything else requires login. Leave all unticked for the strictest setting.',
					),
				),
			),
			'limit_login'         => array(
				'cat'    => 'security',
				'label'  => 'Limit login attempts',
				'desc'   => 'Lock out an IP after too many failed logins.',
				'fields' => array(
					'max'      => array( 'type' => 'number', 'label' => 'Max attempts', 'default' => 5 ),
					'lockout'  => array( 'type' => 'number', 'label' => 'Lockout minutes', 'default' => 15 ),
				),
			),
			'password_protect'    => array(
				'cat'    => 'security',
				'label'  => 'Password-protect the site',
				'desc'   => 'Hide the whole front-end behind a single password. Logged-in admins still see the site normally; search engines are blocked.',
				'fields' => array(
					'password' => array( 'type' => 'password', 'label' => 'Site password', 'desc' => 'Visitors must enter this to view the site. Leave blank to disable until set.' ),
					'message'  => array( 'type' => 'text', 'label' => 'Prompt message', 'placeholder' => 'This site is private.', 'desc' => 'Optional text shown above the password box.' ),
				),
			),
			'disable_comments'    => array( 'cat' => 'security', 'label' => 'Disable comments', 'desc' => 'Turn off comments everywhere: close them on all post types, hide existing ones, and remove the comment admin menus, widgets, and toolbar item.' ),
			'disable_pingbacks'   => array( 'cat' => 'security', 'label' => 'Disable pingbacks & trackbacks', 'desc' => 'Close pingbacks/trackbacks on all posts, remove the X-Pingback header, and block the XML-RPC pingback methods — without touching regular comments.' ),
			'prevent_user_enum'   => array( 'cat' => 'security', 'label' => 'Prevent user enumeration', 'desc' => 'Stop bots from discovering usernames: 404 the ?author=N probe, require login for the REST users endpoint, remove the author from oEmbed, and drop the author sitemap.' ),
			'prevent_info_disclosure' => array( 'cat' => 'security', 'label' => 'Prevent information disclosure', 'desc' => 'Block directory listing and direct access to sensitive files (wp-config, .htaccess, backups, logs) and the readme/license files. On Apache this writes protective .htaccess rules; on Nginx the page shows the config to paste.' ),
			'hide_login'          => array(
				'cat'    => 'security',
				'label'  => 'Mask login URL',
				'desc'   => 'Move the login/registration page to a secret slug so bots can’t hammer /wp-login.php. Default login URLs are redirected away. Set a slug first — with no slug the tweak stays off so you can’t lock yourself out. INI WP always shows the real login URL on the site page.',
				'fields' => array(
					'slug'        => array( 'type' => 'text', 'label' => 'Login slug', 'placeholder' => 'secret-portal', 'desc' => 'Your new login path, e.g. “secret-portal” → https://yoursite.com/secret-portal. Letters, numbers and dashes only; can’t collide with an existing page.' ),
					'redirect_to' => array( 'type' => 'text', 'label' => 'Redirect default URLs to', 'placeholder' => '/ (home)', 'desc' => 'Where to send visitors/bots who hit /wp-login.php or /wp-admin while logged out. Leave blank to send them to the home page.' ),
				),
			),
			'security_headers'    => array(
				'cat'    => 'security',
				'label'  => 'Security headers',
				'desc'   => 'Send hardening HTTP response headers on every front-end page: anti-clickjacking, MIME-sniffing protection, referrer and browser-feature policy. Each header is independently toggleable. If a header is already set by your server (Caddy/Nginx/Cloudflare) the connector won’t duplicate it.',
				'fields' => array(
					'x_frame_options'        => array( 'type' => 'checkbox', 'label' => 'X-Frame-Options', 'default' => true, 'desc' => 'Stop other sites from embedding your pages in a frame/iframe (clickjacking protection).' ),
					'x_frame_value'          => array(
						'type'    => 'select',
						'label'   => 'Framing policy',
						'default' => 'SAMEORIGIN',
						'options' => array( 'SAMEORIGIN' => 'SAMEORIGIN — only your own site may frame (recommended)', 'DENY' => 'DENY — no site may frame (strictest)' ),
					),
					'x_content_type_options' => array( 'type' => 'checkbox', 'label' => 'X-Content-Type-Options: nosniff', 'default' => true, 'desc' => 'Stop browsers from MIME-sniffing a response away from its declared content-type.' ),
					'referrer_policy'        => array( 'type' => 'checkbox', 'label' => 'Referrer-Policy', 'default' => true, 'desc' => 'Control how much referrer information is sent when visitors click links to other sites.' ),
					'referrer_value'         => array(
						'type'    => 'select',
						'label'   => 'Referrer policy value',
						'default' => 'strict-origin-when-cross-origin',
						'options' => array(
							'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin (browser default, recommended)',
							'no-referrer'                     => 'no-referrer (send nothing)',
							'same-origin'                     => 'same-origin (only on your own site)',
							'strict-origin'                   => 'strict-origin (origin only, HTTPS→HTTPS)',
							'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade (legacy)',
						),
					),
					'permissions_policy'     => array( 'type' => 'checkbox', 'label' => 'Permissions-Policy', 'default' => true, 'desc' => 'Disable powerful browser features (camera, microphone, geolocation, etc.) that your site doesn’t use.' ),
					'permissions_value'      => array(
						'type'    => 'select',
						'label'   => 'Permissions policy',
						'default' => 'lockdown',
						'options' => array(
							'lockdown'   => 'Lock down — disable camera, microphone, geolocation, USB, payment (recommended)',
							'no_sensors' => 'Disable sensors only — camera, microphone, geolocation',
						),
					),
					'x_xss_protection'       => array( 'type' => 'checkbox', 'label' => 'X-XSS-Protection: 0', 'default' => false, 'desc' => 'Send “0” to switch OFF the legacy browser XSS auditor — which is deprecated and has itself caused vulnerabilities. Only enable this if a scanner specifically flags the missing header.' ),
				),
			),
			'traffic_log'         => array(
				'cat'    => 'security',
				'label'  => 'Traffic monitor',
				'desc'   => 'Record incoming requests (IP, path, status, user-agent) so the INI WP panel can show suspicious activity — brute-force, vulnerability probing, bad bots, enumeration — and suggest IP block rules. Logged-in admins and the INI WP channel are never logged. No automatic blocking — it only reports and suggests. How much history to keep is set below.',
				'fields' => array(
					'retention_days' => array(
						'type'    => 'select',
						'label'   => 'Keep history for',
						'default' => 90,
						'options' => array(
							0    => 'Unlimited — never delete by age',
							7    => '7 days',
							14   => '14 days',
							30   => '30 days',
							90   => '90 days (default)',
							180  => '180 days',
							365  => '1 year',
							730  => '2 years',
						),
						'desc'    => 'How far back the traffic log reaches. “Unlimited” never deletes anything by age. Keeping history costs database and backup size, not page speed — requests are recorded after the page has already been sent. The Traffic page shows what this site is actually using, and projects the growth. Visitor IPs and user-agents are personal data, so a long window is worth choosing deliberately.',
					),
					'max_rows'       => array(
						'type'    => 'select',
						'label'   => 'Maximum requests kept',
						'default' => 250000,
						'options' => array(
							0       => 'No limit — never delete by count',
							10000   => '10,000',
							50000   => '50,000',
							100000  => '100,000',
							250000  => '250,000 (default)',
							500000  => '500,000',
							1000000 => '1,000,000',
						),
						'desc'    => 'An absolute ceiling on top of the window above: once the log passes this many requests the oldest go, whatever the retention says. 250,000 rows is roughly 90 MB. Whichever limit is reached first wins, so on a busy site this is usually the one that applies — at 5,000 requests a day the default holds about 50 days rather than the full 90. Choose “No limit” only if you have looked at the growth projection on the Traffic page and want the retention window to be the only bound. Recent requests are never deleted by this setting, however low you set it, so auto-block always sees its full evaluation window.',
					),
				),
			),
			'autoblock'           => array(
				'cat'    => 'security',
				'label'  => 'Auto-block escalation',
				'desc'   => 'Score offending IPs from the traffic monitor every 5 minutes and escalate temp blocks (1h → 4h → 8h → 5 days → 2 weeks). By default it only SUGGESTS blocks (review them on the IP Block page); tick “Enforce” to apply them automatically. Never issues a permanent block automatically; an IP that behaves drops a level after 30 quiet days. Requires the Traffic monitor.',
				'fields' => array(
					'enforce'   => array( 'type' => 'checkbox', 'label' => 'Enforce (Auto-Block mode)', 'default' => false, 'desc' => 'When OFF, the engine only suggests blocks on the IP Block page (Block Suggestion System). When ON, it applies the escalating temp blocks automatically. Leave OFF first and watch the suggestions for a while.' ),
					'allowlist' => array( 'type' => 'textarea', 'label' => 'Never block these IPs / ranges', 'desc' => 'One IP or CIDR range per line (e.g. 203.0.113.7 or 203.0.113.0/24, IPv6 supported). Your office, monitoring, CDN, or payment-webhook IPs. Verified Googlebot/Bing/etc. are always exempt automatically.' ),
				),
			),
			'vulnerability_scan'  => array(
				'cat'    => 'security',
				'label'  => 'Vulnerability scan',
				'desc'   => 'Check your installed plugins, themes, and WordPress core against the free WPVulnerability database (CC0, no API key) once a day. Any component whose installed version has a known vulnerability is listed on the Vulnerabilities page and flagged on the dashboard. No data about your site is sent — only the public slug of each component is looked up.',
				'fields' => array(
					'email_alert'  => array( 'type' => 'checkbox', 'label' => 'Email me on new findings', 'default' => false, 'desc' => 'Send an email only when a NEW vulnerability appears (never on every scan). Quiet once you’ve seen a finding.' ),
					'email_to'     => array( 'type' => 'email', 'label' => 'Alert recipient', 'desc' => 'Where to send the alert. Leave blank to use the site admin email.' ),
					'min_severity' => array(
						'type'    => 'select',
						'label'   => 'Minimum severity to alert on',
						'default' => 'high',
						'options' => array(
							'critical' => 'Critical only',
							'high'     => 'High and above (recommended)',
							'medium'   => 'Medium and above',
							'low'      => 'Everything, including low',
						),
					),
				),
			),
			'two_factor'          => array(
				'cat'    => 'security',
				'label'  => 'Two-factor authentication',
				'desc'   => 'Add a time-based one-time code (TOTP) to sign-in, using any standard authenticator app — Google Authenticator, 1Password, Aegis, Bitwarden. The password is checked first, then the code is asked for before any session is created. Each user turns it on from their own profile; the roles ticked below must. Recovery codes are issued at setup, and “wp secwp 2fa reset <user>” restores access from the shell if a phone is lost.',
				'fields' => array(
					'roles' => array(
						'type'  => 'roles',
						'label' => 'Roles that must use two-factor authentication',
						'desc'  => 'Users in a ticked role are sent to their profile to set it up and cannot use the rest of wp-admin until they do. Everyone else may still turn it on voluntarily. Administrators at minimum is the sensible setting.',
					),
				),
			),
			'file_integrity'      => array(
				'cat'    => 'security',
				'label'  => 'File integrity monitoring',
				'desc'   => 'Hash every code file (.php, .js, .htaccess …), keep a baseline, and re-check on a schedule. Any file that is added, changed, or deleted is reported by email (and an optional webhook) the moment it is found — off-server evidence that stands even if the site itself is fully compromised. Media is never hashed, so a large uploads folder costs nothing.',
				'fields' => array(
					'frequency'      => array(
						'type'    => 'select',
						'label'   => 'Check how often',
						'default' => 'hourly',
						'options' => array(
							'hourly'     => 'Every hour (recommended)',
							'twicedaily' => 'Twice a day',
							'daily'      => 'Once a day',
							'off'        => 'Manually / from system cron only',
						),
						'desc'    => 'Uses WP-Cron. If WP-Cron is disabled on this site, run “wp secwp integrity scan” from system cron instead — the File integrity page prints the exact line.',
					),
					'email_alert'    => array( 'type' => 'checkbox', 'label' => 'Email me every change', 'default' => true, 'desc' => 'The point of this feature: the report leaves the server before the baseline is updated, so it survives an attacker who owns the site. Turning this off leaves the record on the server only, where it can be rewritten.' ),
					'email_to'       => array( 'type' => 'email', 'label' => 'Alert recipient', 'desc' => 'Where to send the report. Leave blank to use the site admin email. A mailbox off this server is best.' ),
					'webhook_url'    => array( 'type' => 'text', 'label' => 'Webhook URL (optional)', 'placeholder' => 'https://…', 'desc' => 'A second, independent channel. The report is POSTed as JSON.' ),
					'webhook_secret' => array( 'type' => 'password', 'label' => 'Webhook secret (optional)', 'desc' => 'When set, the request carries X-SecurityWP-Signature: sha256=HMAC(secret, body) so the receiver can verify it.' ),
					'extensions'     => array( 'type' => 'text', 'label' => 'File types to hash', 'default' => 'php,phtml,js,htaccess', 'desc' => 'Comma-separated, no dots needed. Code only — adding media types here would hash your whole uploads folder for nothing. “htaccess” also covers .htaccess; add “user.ini” to cover .user.ini.' ),
					'exclude'        => array( 'type' => 'textarea', 'label' => 'Extra paths to skip', 'desc' => 'One path per line, relative to the WordPress root (e.g. wp-content/my-cache). wp-content/uploads, caches, backup and update working directories are already skipped.' ),
					'max_files'      => array( 'type' => 'number', 'label' => 'Maximum files', 'default' => 200000, 'desc' => 'Safety stop for a runaway tree. If it is ever reached the scan says so loudly — a silent partial scan would be worse than none.' ),
				),
			),
			'altcha'              => array(
				'cat'    => 'security',
				'label'  => 'Login captcha (ALTCHA)',
				'desc'   => 'Add a privacy-friendly, self-hosted proof-of-work challenge to the login, registration, and password-reset forms. No Google, no external calls. Pairs with Limit login attempts.',
				'fields' => array(
					'complexity' => array( 'type' => 'number', 'label' => 'Difficulty', 'default' => 50000, 'desc' => 'Higher = more work for bots (and a touch slower for humans). 50000 is a good default.' ),
				),
			),

			// ── Head cleanup ──
			'remove_version_meta'  => array( 'cat' => 'head', 'label' => 'Remove generator meta tag', 'desc' => 'Hide the WordPress version from the <head> generator meta.' ),
			'remove_feed_generator'=> array( 'cat' => 'head', 'label' => 'Remove RSS generator tag', 'desc' => 'Hide the WordPress version from the RSS feed <generator>.' ),
			'remove_asset_version' => array( 'cat' => 'head', 'label' => 'Remove version on static assets', 'desc' => 'Strip ?ver= from CSS/JS URLs for guests entirely. May break caches/CDNs that rely on ?ver= to detect updates — prefer “Mask version on static assets” if unsure.' ),
			'mask_asset_version'   => array( 'cat' => 'head', 'label' => 'Mask version on static assets', 'desc' => 'Replace ?ver=6.4.2 with an opaque token for guests — hides the real WordPress/plugin version while keeping a version so caches still bust on update. Safer than “Remove version on static assets”. (Ignored if Remove is also on.)' ),
			'remove_wlw'           => array( 'cat' => 'head', 'label' => 'Remove Windows Live Writer link', 'desc' => 'WLW was discontinued in 2017; the manifest link is unused.' ),
			'remove_rsd'           => array( 'cat' => 'head', 'label' => 'Remove RSD link', 'desc' => 'Really Simple Discovery — not needed without pingback/XML-RPC clients.' ),
			'remove_shortlink'     => array( 'cat' => 'head', 'label' => 'Remove shortlink tag', 'desc' => 'The default WP shortlink <link> is ignored by search engines.' ),
			'remove_rest_discovery' => array( 'cat' => 'head', 'label' => 'Disable oEmbed & REST discovery', 'desc' => 'Remove the oEmbed and REST API <link> discovery tags, the wp-json HTTP Link header, and the WordPress version from the generator tag (which leaks into oEmbed/feed output). The REST API itself keeps working — only the auto-discovery hints and version leak are removed.' ),
			'disable_dashicons'    => array( 'cat' => 'head', 'label' => 'Disable front-end Dashicons', 'desc' => 'Stop loading Dashicons CSS for visitors (check custom login forms after).' ),

			// ── SEO & privacy ──
			'disable_feeds'        => array( 'cat' => 'seo', 'label' => 'Disable feeds', 'desc' => 'Disable all RSS/Atom/RDF feeds and remove feed links from <head>.' ),
			'disable_author_archives' => array( 'cat' => 'seo', 'label' => 'Disable author archives', 'desc' => '404 author archive pages, remove author links and sitemap entries.' ),
			'obfuscate_author_slugs'  => array( 'cat' => 'seo', 'label' => 'Obfuscate author slugs', 'desc' => 'Replace /author/username/ URLs with random tokens; also masks the users REST endpoint.' ),
			'email_obfuscator'        => array( 'cat' => 'seo', 'label' => 'Email address protection', 'desc' => 'Automatically scramble every email address and mailto link in your content so spam bots can’t harvest them; visitors still see and click them normally (decoded by a tiny script). Also provides the [inipr_obfuscate email="…"] shortcode.' ),
		);
	}

	/** Current on/off state: key => bool. */
	public static function state(): array {
		$saved = (array) get_option( self::OPT_STATE, array() );
		$state = array();
		foreach ( array_keys( self::catalog() ) as $key ) {
			$state[ $key ] = ! empty( $saved[ $key ] );
		}
		return $state;
	}

	public static function is_on( string $key ): bool {
		$saved = (array) get_option( self::OPT_STATE, array() );
		return ! empty( $saved[ $key ] );
	}

	/** Set a tweak on/off (validates the key). */
	public static function set( string $key, bool $on ): bool {
		if ( ! array_key_exists( $key, self::catalog() ) ) {
			return false;
		}
		$saved         = (array) get_option( self::OPT_STATE, array() );
		$saved[ $key ] = $on;
		update_option( self::OPT_STATE, $saved, false );
		return true;
	}

	/** All config for a tweak (merged with field defaults). */
	public static function config( string $key ): array {
		$catalog = self::catalog();
		$fields  = $catalog[ $key ]['fields'] ?? array();
		$saved   = (array) get_option( self::OPT_CONFIG, array() );
		$values  = (array) ( $saved[ $key ] ?? array() );
		$out     = array();
		foreach ( $fields as $fkey => $def ) {
			$out[ $fkey ] = $values[ $fkey ] ?? ( $def['default'] ?? '' );
		}
		return $out;
	}

	/** A single config value. */
	public static function get( string $key, string $field, $default = '' ) {
		$cfg = self::config( $key );
		return $cfg[ $field ] ?? $default;
	}

	/** Save config values for a tweak (only known fields are kept). */
	public static function set_config( string $key, array $values ): bool {
		$catalog = self::catalog();
		if ( ! isset( $catalog[ $key ]['fields'] ) ) {
			return false;
		}
		$fields  = $catalog[ $key ]['fields'];
		$saved   = (array) get_option( self::OPT_CONFIG, array() );
		$current = (array) ( $saved[ $key ] ?? array() );
		$clean   = $current; // Start from existing values; only overwrite submitted fields.

		foreach ( $fields as $fkey => $def ) {
			// An unchecked checkbox submits nothing, so "absent" must mean false — not "unchanged".
			// (Only do this when the form that owns this field was actually submitted: we detect that
			// by a hidden marker field cfg[__submitted] so a partial save can't silently clear boxes.)
			if ( 'checkbox' === $def['type'] ) {
				if ( ! empty( $values['__submitted'] ) ) {
					$clean[ $fkey ] = self::sanitize_field( 'checkbox', $values[ $fkey ] ?? false, $def );
				}
				continue;
			}
			// Checkbox-group types (none ticked = absent key), same submitted-marker rule:
			// an empty submission must clear the list, not leave the old one.
			if ( in_array( $def['type'], array( 'rest_namespaces', 'posttypes', 'roles' ), true ) ) {
				if ( ! empty( $values['__submitted'] ) ) {
					$clean[ $fkey ] = self::sanitize_field( $def['type'], $values[ $fkey ] ?? array(), $def );
				}
				continue;
			}
			if ( ! array_key_exists( $fkey, $values ) ) {
				continue;
			}
			// A blank password submit means "keep the existing value" (the field renders empty for
			// security, so we must not wipe a stored secret just because the box was left blank).
			if ( ! is_scalar( $values[ $fkey ] ) ) {
				continue; // Malformed scalar fields must not overwrite existing configuration.
			}
			if ( 'password' === $def['type'] && '' === (string) $values[ $fkey ] ) {
				continue;
			}
			$clean[ $fkey ] = self::sanitize_field( $def['type'], $values[ $fkey ], $def );
			if ( 'allowlist' === $fkey ) {
				$entries = preg_split( '/[\s,]+/', $clean[ $fkey ], -1, PREG_SPLIT_NO_EMPTY );
				$clean[ $fkey ] = implode( "\n", array_filter( $entries, array( 'SecurityWP_Autoblock', 'valid_allowlist_entry' ) ) );
			}
		}

		$saved[ $key ] = $clean;
		update_option( self::OPT_CONFIG, $saved, false );
		return true;
	}

	private static function sanitize_field( string $type, $value, array $def = array() ) {
		if ( ! in_array( $type, array( 'roles', 'posttypes', 'rest_namespaces' ), true ) && ! is_scalar( $value ) ) {
			return $def['default'] ?? '';
		}
		switch ( $type ) {
			case 'checkbox':
				// HTML checkbox posts '1'/'on' when ticked, nothing when not; store a real bool.
				return ! empty( $value ) && '0' !== (string) $value;
			case 'number':
				// A non-numeric entry must not read as 0: on fields where 0 is meaningful ("no limit")
				// a typo would silently switch the limit off. Fall back to the field's own default,
				// then clamp to a declared minimum so a negative can't mean "unlimited" either.
				$n = is_numeric( $value ) ? (int) $value : (int) ( $def['default'] ?? 0 );
				if ( isset( $def['min'] ) ) {
					$n = max( (int) $def['min'], $n );
				}
				if ( isset( $def['max'] ) ) {
					$n = min( (int) $def['max'], $n );
				}
				return $n;
			case 'page':
				return (int) $value;
			case 'posttypes':
			case 'roles':
				$value = is_array( $value ) ? $value : array();
				return array_values( array_map( 'sanitize_key', array_filter( $value, 'is_string' ) ) );
			case 'rest_namespaces':
				// REST namespaces look like 'wp/v2' or 'oembed/1.0' — sanitize_key()
				// would strip the slash/dot and break route matching. Keep only the
				// characters valid in a namespace and drop anything else.
				$value = is_array( $value ) ? $value : array();
				$clean = array();
				foreach ( $value as $ns ) {
					if ( ! is_string( $ns ) ) {
						continue;
					}
					$ns = strtolower( trim( (string) $ns ) );
					$ns = preg_replace( '#[^a-z0-9/._-]#', '', $ns );
					if ( '' !== $ns ) {
						$clean[] = $ns;
					}
				}
				return array_values( array_unique( $clean ) );
			case 'textarea':
				// Multiline IP allowlists and excluded paths contain plain text only.
				return sanitize_textarea_field( (string) $value );
			case 'password':
				// Don't run sanitize_text_field — it would strip characters valid in passwords.
				// Only manage_options users reach this; stored as-is (must be readable to use).
				return (string) $value;
			case 'email':
				return sanitize_email( (string) $value );
			case 'select':
				// Select values can be option keys like 'SAMEORIGIN' or 'strict-origin-when-cross-origin'
				// — sanitize_key() would lowercase/strip them and break matching, and some are sent
				// verbatim as HTTP header values. Strip CR/LF/control chars (header-injection safe) and
				// cap length.
				$v = preg_replace( '/[\x00-\x1f\x7f]/', '', (string) $value );
				$v = substr( trim( (string) $v ), 0, 128 );
				// When the field declares its own options, anything else is not a choice the user could
				// have made — fall back to the default rather than storing it. Retention is the reason:
				// an unlisted value there decides what gets deleted.
				if ( ! empty( $def['options'] ) && is_array( $def['options'] ) ) {
					$keys = array_map( 'strval', array_keys( $def['options'] ) );
					if ( ! in_array( $v, $keys, true ) ) {
						return (string) ( $def['default'] ?? reset( $keys ) );
					}
				}
				return $v;
			case 'color':
				// sanitize_hex_color() lives in wp-admin; our config save runs via REST, so validate
				// the #RGB / #RRGGBB form ourselves to avoid an undefined-function fatal.
				$c = trim( (string) $value );
				return preg_match( '/^#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})$/', $c ) ? $c : '';
			default:
				return sanitize_text_field( (string) $value );
		}
	}

	/** Apply all enabled tweaks (delegates to SecurityWP_Tweaks). Call on plugins_loaded. */
	public function apply(): void {
		SecurityWP_Tweaks::apply( self::state() );
	}
}
