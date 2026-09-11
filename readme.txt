=== INI Protector ===
Contributors: milenfrom
Tags: security, hardening, file integrity, two-factor, login
Requires at least: 5.7
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.9.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight WordPress hardening — file integrity monitoring, two-factor authentication, login protection, security headers and privacy.

== Description ==

INI Protector is a focused, no-bloat hardening plugin for WordPress. Every feature
is an independent toggle, grouped into three areas:

**Security**

* **File integrity monitoring** — hashes every code file (.php, .php5, .phtml,
  .phar, .js, .htaccess, .user.ini …), keeps a baseline, and re-checks on a
  schedule. Any file that is added, changed, or deleted is emailed to you (and
  optionally POSTed to a webhook) *before* the baseline is updated, so the
  evidence has already left the server even if the site itself is compromised.
  Media is never hashed, but uploads, caches and backup folders are still checked
  for executable files — a .php among your images has no innocent explanation and
  is reported as critical. Runs from WP-Cron or from system cron via
  `wp secwp integrity scan`.
* **Two-factor authentication (TOTP)** — a time-based one-time code from any
  standard authenticator app, required per role. The password is verified first,
  then the code, before any session cookie is issued. Recovery codes are issued
  at setup, and `wp secwp 2fa reset <user>` restores access from the shell.
* Disable XML-RPC, disable the theme/plugin file editor, require login for the
  REST API.
* Limit login attempts (IP lockout), mask the login URL to a secret slug.
* Password-protect the whole front-end.
* Disable comments and pingbacks/trackbacks.
* Prevent user enumeration and information disclosure (directory listing,
  wp-config/.htaccess/backup/log access; Apache .htaccess rules or an Nginx
  snippet).
* Hardening HTTP security headers (X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy).
* ALTCHA proof-of-work login captcha (self-hosted, no third-party calls).
* Traffic monitor — records incoming requests so suspicious activity is visible,
  with a per-IP drill-down. Keeps the full history by default; you can cap it by
  age, by number of requests, or both.
* Auto-block escalation — a dedicated **IP Block** page that surfaces the
  traffic monitor's suggested blocks for one-click review (Block Suggestion
  System), and an optional **Auto-Block** mode that blocks offending IPs
  automatically on an escalating temporary schedule (1h → 4h → 8h → 5 days →
  2 weeks). Never issues a permanent block automatically; an allowlist and
  verified search-engine bots are always exempt; quiet IPs decay back down.
* Vulnerability scan — a daily check of your installed plugins, themes, and
  WordPress core against the free WPVulnerability database (CC0, no API key).
  Findings appear on a dedicated page and on the dashboard, with an optional
  email alert on new findings. No data about your site is sent — only the
  public slug of each component is looked up.

**Head cleanup**

* Remove the generator/RSD/WLW/shortlink tags, strip or mask asset version
  query strings, drop front-end Dashicons.

**Utilities**

* **Rotate asset cache token** — changes the version token on every CSS and JS
  URL at once, so returning visitors re-fetch them. Use it after a deploy when
  a file has changed but the version it declares has not. Available from
  **INI Protector → Utilities** and from `wp secwp asset-salt rotate`, which is
  where it belongs in a deploy script.

**SEO & privacy**

* Disable feeds, disable author archives, obfuscate author slugs, and protect
  email addresses from harvesting.

**INI WP platform**

* Exposes a read-only, HMAC-signed REST endpoint (`secwp/v1/state`) so the
  INI WP control panel can pull this site's security posture and scan results.
  The endpoint only activates when the INI WP connector is installed and
  configured; auth reuses the connector's signed channel.

== Installation ==

1. If replacing SecurityWP, deactivate it first. Existing settings are retained.
   Upload the INI Protector ZIP through Plugins → Add New → Upload Plugin,
   then activate **INI Protector**. Do not activate both versions together.
2. Open **INI Protector** and enable the hardening you want. Each toggle is
   independent and reversible.
3. For "Mask login URL", set a slug before enabling so you can't lock yourself
   out.

== Notes ==

* Head cleanup lives here, not in SeoWP — SeoWP keeps pure SEO concerns
  (titles, meta, schema, noindex directives).
* Behind a reverse proxy or CDN, tell INI Protector which addresses your proxy
  uses so it can read the real visitor IP safely:

      define( 'SECWP_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );

  Forwarded headers (X-Forwarded-For, CF-Connecting-IP) are then read only when
  the connection actually comes from one of those addresses — so a visitor who
  reaches your origin directly cannot claim to be someone else, evade an IP
  block, or get an innocent IP blocked. Without this, client IPs come from the
  socket peer, which cannot be forged. Security → Scan reports which mode you
  are in. The older SECWP_TRUST_PROXY constant still works but cannot check who
  sent the header; replace it when you can.

== External services ==

The optional vulnerability scanner contacts WPVulnerability (https://www.wpvulnerability.com/)
only when you enable Vulnerability Scan. It sends installed plugin/theme slugs
and the WordPress core version to https://www.wpvulnerability.net/ to retrieve
known vulnerabilities. The service also receives the server IP address as part
of the connection. No site URL is included in the plugin's user agent.
Service and privacy information: https://www.wpvulnerability.com/privacy/

File integrity webhooks are optional. When you configure a webhook URL and enable
alerts, reports containing the site URL, changed file paths, hashes and scan
metadata are sent to that URL. Configure only a recipient you trust; its terms
and privacy policy apply. Email alerts use your site's configured mail service.

The optional INI WP connector allows your configured control panel to retrieve
security settings and scan results through an authenticated REST endpoint.
INI Protector does not initiate control-panel requests. Service information:
https://iniwp.com

== Source code ==

The bundled ALTCHA widget is version 2.3.0, licensed under MIT.
Source: https://github.com/altcha-org/altcha/tree/v2.3.0
Build instructions are in that project's README and package.json.
The widget runs locally in the browser; no ALTCHA service account is required.

== Changelog ==

= 1.9.7 =
* Traffic history now keeps at most 250,000 requests by default (about 90 MB) instead of being unlimited. The 90-day window is unchanged, and whichever limit is reached first applies — on a busy site that is usually the row cap. **If your log is already larger than this, the excess is deleted the first time the log prunes after updating.** Choose "No limit" in Configure → Traffic monitor to keep the old behaviour; a limit you set yourself is never overridden.
* The row cap can no longer starve auto-block. Requests inside the auto-block evaluation window are never deleted by the cap, however low it is set, so the blocker always scores a complete window — previously a busy site with a small cap would have handed it a partial picture, and the busier the site the less it would have seen.
* Integrity webhooks now refuse link-local addresses (169.254.0.0/16, fe80::/10), which are the cloud metadata endpoint on every major host and never a collector. Private and loopback addresses still work, because an internal collector is a real setup — but the File integrity page now says plainly when the webhook points inside your network, so an address nobody meant to set is visible rather than silent.
* Fixed a deprecation notice on PHP 8.4 and later in the auto-block escalation routine, which would have become a fatal error on PHP 9.

= 1.9.6 =
* Security: file integrity monitoring now checks **wp-content/uploads, caches and backup folders for executable files**. Media there is still skipped, so scans stay fast (walking 20,000 uploads costs about a tenth of a second), but a .php dropped among the images — the most common way a break-in persists — is now reported, and flagged as critical. Deliberate exclusions you configured yourself are still skipped entirely.
* Security: one definition of "executable file" now covers every scanner. Previously the integrity monitor watched .php/.phtml, the uploads check matched .php plus digits, and the core-file check matched only .php exactly — so a shell named `evil.php5` was caught by whichever scan you happened to run and missed by the others. All of them now cover .php, .phtml, .phps, .pht, .phar and .php3–.php8.
* Security: `.user.ini` is now watched. It was intended to be, but an extension list can never match it — PHP reports the extension of ".user.ini" as "ini" — so it fell through every check. Like .htaccess, it can switch PHP execution on in a folder, so it is treated as critical wherever it appears.
* Security: the site password form is now rate-limited — 10 wrong guesses per visitor, then a 15-minute pause. A single site-wide password that never rotates was previously guessable as fast as requests could be sent, from any URL.
* Security: a locked-out IP is now refused before WordPress verifies the password, rather than after. The lockout always blocked the login, but the password was still hashed on every attempt, so a locked-out attacker could keep burning server CPU.
* Security: the site password now applies to the REST API by the same rule as the front-end. Previously any logged-in account — a subscriber, for example — could read password-protected posts and pages through /wp-json/ even without the site password. Accounts that can edit posts, and anyone who has entered the site password, are unaffected.
* Security: two-factor sign-in no longer extends its own five-minute window. A wrong code used to mint a fresh token, so a pending "password accepted" state could be held open indefinitely by keeping the login screen busy. Retries now keep the original deadline, a successful sign-in consumes the challenge, and changing or resetting the password — or resetting 2FA — revokes any pending sign-in immediately.
* Security: authenticator secrets are now always encrypted before being stored. If encryption is unavailable the setup screen says so and refuses, instead of quietly saving the secret unprotected; an unprotected secret left by an earlier version is re-encrypted the next time it is read.
* Security: added SECWP_TRUSTED_PROXIES for sites behind a proxy or CDN — see Notes. Forwarded IP headers are accepted only from the addresses you declare, and X-Forwarded-For is read from the trusted end, so a visitor cannot forge an identity to dodge a block or get another IP blocked. Security → Scan now reports how client IPs are being decided.
* Fixed: login rate limiting now uses the same visitor IP as the rest of the plugin. Behind a CDN it previously saw only the CDN's address, so one attacker's failed logins could lock out every visitor at once.
* Fixed: a file-integrity scan that hits the file limit no longer reports every unscanned file as deleted, and no longer drops those files from the baseline — which silently left everything past the limit unmonitored from then on.

= 1.9.5 =
* Fixed PHP warnings and warning text appearing in the username field when login masking is enabled. The masked login loader now shares WordPress login globals with the login header, footer and authentication hooks, including interim-login state.

= 1.9.4 =
* Traffic history now defaults to 90 days. Existing saved retention choices are preserved.
* Unlimited history shows a readable orange warning beside Configure, with a link to Utilities.
* Added Utilities → Clean traffic table contents, with administrator permission checks and a confirmation before permanently deleting history. Existing IP blocks and settings are kept.
* Traffic cleanup now reports database failures instead of displaying a success message.

= 1.9.3 =
* Added a Check for updates text link on the Plugins screen to discover the latest WordPress.org directory release without waiting for the normal update-check cache.
* Added an explicit Update now action using the official WordPress.org ZIP and native WordPress replacement installer, with version, package and compatibility checks.
* Preserved plugin settings and activation during manual updates.

= 1.9.2 =
* Author URLs now use independent random tokens that survive WordPress salt changes. Existing salt-derived author URLs are retired during upgrade; regenerate links and clear page caches.
* Explain recovery-code login when a salt change makes the existing two-factor setup unreadable. After signing in, reset and re-enroll two-factor authentication.


= 1.9.1 =
* Asset cache tokens now use independent randomness; existing stored legacy salts are replaced on upgrade, even if masking is disabled.
* Hardened configuration, HTTP metadata and IP/CIDR validation, and escaped generated email-link labels.
* Added explicit nonce verification to authentication forms and administrative save handlers.
* Enqueued admin, password gate and two-factor styles/scripts through WordPress APIs.
* Limited dismissible scan notices to the dashboard and INI Protector pages.
* The email shortcode is now [inipr_obfuscate]. Replace any existing [obfuscate] shortcodes with [inipr_obfuscate].


= 1.9.0 =
* Renamed the plugin to INI Protector with the ini-protector translation domain.
* Removed the self-hosted updater for WordPress.org distribution.
* Preserved existing settings, cron hooks, database tables and integration identifiers.
* Removed the site URL from vulnerability lookup requests and documented external services.


= 1.8.2 =
* **The plugin can now be translated.** It was written to be translatable throughout, but shipped no translation template and pointed at a language folder that did not exist — so no translation could ever load. A template covering all 341 strings is now included, and the folder it needs comes with it.
* **Fix: four messages could never be translated even once that was in place**, because they were not tagged with the plugin's name internally. Three are the "please complete the verification challenge" errors shown on the login, registration and lost-password forms; the fourth is the message shown when feeds are disabled. They now appear in the translation template with everything else.
* **Fix: a request to `?author[]=1` wrote a PHP warning into the site's error log.** Anyone could trigger it, and on a site configured to display errors it appeared on the page. Such a request is still treated as an author-enumeration probe and still returns 404 — it just no longer produces the warning.
* Server detection for Apache/LiteSpeed now handles an unusual server name correctly.
* Housekeeping for the official Plugin Check tool: added the translator notes that explain what each number in a message refers to, and corrected suppression comments that were silencing nothing. No behaviour change.

= 1.8.1 =
* **Fix: on sites not set to UTC, the traffic log's time windows were wrong by the site's time offset.** A "last 24 hours" view actually showed the last 27 on a UTC+3 site, and every other window and the per-IP drill-down were stretched the same way. Requests are recorded in your site's own local time but were being compared against a UTC cut-off.
* **The same fix corrects pruning.** If you had set a retention window, requests were kept for your chosen period *plus* the time offset before being removed — a 7-day setting really kept 7 days and 3 hours. Nothing was lost, it was held slightly too long.
* Windows are now also correct across daylight-saving changes, rather than being an hour out for part of the year.
* Sites set to UTC were never affected, and no stored data needs correcting — only the comparisons were wrong, never what was written.

= 1.8.0 =
* **Traffic history is now kept indefinitely by default.** 1.7.0 made the limits adjustable but still shipped the old 14-day window and 50,000-request cap; both are now off out of the box, so nothing is deleted unless you ask for it.
* **After updating, sites that never chose a retention window will start keeping traffic history indefinitely.** Nothing already recorded is removed and nothing on the site slows down — requests are logged after the page has been sent — but the log will grow with your traffic, and it is included in database backups. The Traffic page shows what it currently costs and projects the growth; if that matters on your hosting, pick a window there.
* **The two settings are dropdowns instead of typed numbers.** Retention offers Forever, 7, 14, 30, 90 and 180 days, 1 year and 2 years; the request ceiling offers No limit, and 10,000 up to 1,000,000. You can no longer mistype a value that means something you did not intend, and "Forever" is now stated plainly rather than expressed as a 0.
* Note the two settings work together: the request ceiling still overrides the window, so leaving a low ceiling in place will cut a long retention window short. Both now default to no limit, so this only applies if you set one.
* Hardening: a dropdown that receives a value not in its own list now falls back to that setting's normal value instead of storing it.

= 1.7.0 =
* New: **you choose how long traffic history is kept.** The traffic monitor used to keep the last 14 days and at most 50,000 requests, with no way to change either. Both are now settings, and both can be switched off — set the retention to **0** to keep history indefinitely, and the row limit to **0** to remove the ceiling.
* New: a **Retention settings** window on the Traffic screen, next to a new line showing what the log currently costs — how many requests are stored, how much space they take, how far back they go, and the limits in force. The same settings remain available under Configure on the main settings page.
* Worth knowing before you switch retention off: keeping history costs **disk space and backup size, not page speed**. Requests are recorded after the page has already been sent to the visitor, and with both limits off the housekeeping step stops running altogether. The window shows the projected growth for your own site so the decision is an informed one. Bear in mind visitor IP addresses are personal data, so keeping them forever is a deliberate choice.
* The row limit is the one that usually runs out first: on a busy site 50,000 requests can be less than a day. If you want a longer history, raise or switch off **both** settings — the retention window alone will not do it.
* The Traffic screen now offers 30-day, 90-day and 1-year views, but only as far back as your retention setting actually keeps. Reading is capped at a year so a very wide view cannot bog the page down.
* Fix: typing something that is not a number into a settings box was read as 0. On the new settings that would have quietly meant "no limit", so a mistyped entry now falls back to the setting's normal value instead.

= 1.6.1 =
* Fix: **"View version details" could show "Plugin not found" instead of this changelog.** The link on the Plugins screen opens a details window; when it could not be answered from the update server, the request was handed on to the WordPress.org plugin directory, which has never heard of a self-hosted plugin and answers with an error. Nothing was actually wrong with the plugin or the update — but that is not what it looked like.
* The details window now **always answers**, and falls back to the description and changelog bundled with the installed copy when the update server cannot be reached. That covers a real outage and also the ten-minute pause after a single failed check, which is why the plugin row could correctly offer a new version while the details window errored — two separate caches on two separate schedules.
* Fix: **another plugin could overwrite our answer.** The hook that supplies these details is a filter, not a final word: WordPress keeps running every other plugin's callback afterwards, and one that was written without checking *which* plugin was asked about can discard a perfectly good result. (Elementor ships exactly such a callback, and its error text is the "Plugin not found." people were seeing.) The details are now re-asserted at the very end of that chain — only for this plugin, and only when what is on its way out is not already a usable answer, so no other plugin's details are affected.
* No change to how updates are downloaded or installed; this only affects the details window.

= 1.6.0 =
* New: **Rotate asset cache token** — a way to change the masked `?ver=` on every CSS and JS URL at once, forcing a clean re-fetch site-wide. Available from the new **INI Protector → Utilities** page and from WP-CLI.
* Why this exists: the masked token is derived from the version an asset **declares**, so it is only as fresh as that version. Plenty of real-world code enqueues a script with a hard-coded string that never changes — the file behind it is updated, the declared version is not, the URL stays the same, and every returning visitor keeps running the copy in their browser cache. Rotating is the blunt instrument for that case, and for anything else where a deploy is live on the server but not in front of visitors.
* New: **WP-CLI** — `wp secwp asset-salt rotate` and `wp secwp asset-salt show`. `rotate` runs without a confirmation prompt so it can sit at the end of a deploy script, after the step that syncs changed files; `--porcelain` prints just the new token. `show` reports the current token, whether masking is actually active, and who last rotated it.
* Rotating **costs a re-download**: every visitor fetches all CSS and JS once more. That is fine after a deploy and wasteful as a habit, so the cost is stated at both the button and the command rather than left to be discovered.
* Every rotation records **who did it, when, and from where** (admin or WP-CLI), kept as a rolling history of the last ten on the Utilities page — so a spike in cache-miss traffic can be explained rather than guessed at.
* Rotating while version masking is **off** is reported as such instead of as success: with the mask off, or with "Remove version on static assets" on, there is no token for visitors to see and the rotation changes nothing they receive.
* The token shown in the admin and by WP-CLI is a short fingerprint of the salt, never the salt itself — publishing the salt would make every masked token reversible to a real version number again, which is the whole point of masking.
* New: a `secwp_asset_salt_rotated` action fires on every rotation. If the site sits behind a page cache, purge it from there — cached HTML still carries the old asset URLs, so until it is purged the rotation is invisible.
* New: the platform state endpoint emits an `asset_salt_rotated` event for the INI WP control panel. Additive (schema_version unchanged); no connector/signing change.

= 1.5.0 =
* New: **File integrity monitoring** (Security). INI Protector hashes every code file on the site (SHA-256), stores a baseline, and re-checks it on a schedule — reporting every file that is **new**, **modified**, or **deleted**. Media is excluded, so a large uploads folder costs nothing: a 24,000-file site hashes in about two seconds.
* The alert **leaves the server before the baseline is updated**. A monitor whose only record lives on the machine an attacker controls can be rewritten to match whatever they planted; an email or webhook that has already been sent cannot. If every configured channel fails, the baseline is deliberately left alone so the change is reported again next run instead of being silently accepted.
* Every report carries a **sequence number** and a **chain of state digests**, so a suppressed report (a gap in the numbering) or a doctored baseline (a digest that does not match the previous message) is detectable from your mailbox alone, without trusting anything on the site.
* Changes in **critical locations** — WordPress core, wp-config.php, mu-plugins, .htaccess, theme function files, the web root — lead the report and are flagged in the admin. A file whose contents changed while its timestamp did not move is called out separately: that is a self-rewriting payload or a forged mtime, not an ordinary edit.
* New: a **INI Protector → File integrity** page — the changes from the last check, a rolling history, "Scan now", "Accept current state as the baseline", and a dashboard alert. It also states plainly when no alert channel is configured, or when WP-Cron is disabled, and prints the exact system-cron line to use instead.
* New: **WP-CLI** — `wp secwp integrity scan|baseline|status|list`. `scan` exits with status 1 when changes are found and 0 when clean, so system cron and monitoring can act on it directly; `--format=json` for machine-readable output.
* New: **Two-factor authentication** (Security). RFC 6238 TOTP with any standard authenticator app, enforceable per role. The password is checked first and the second factor is required **before a session cookie is issued** — not by clearing one that was already set.
* Two-factor: ten single-use **recovery codes** are issued at setup and can be regenerated at any time, and `wp secwp 2fa reset <user>` removes 2FA from the shell — the break-glass for a lost phone. `wp secwp 2fa status` shows who is covered, and the Users list gains a 2FA column.
* Two-factor: the enrolment QR code is generated **on this site** — the setup URI contains the shared secret and is never handed to an external QR service. TOTP secrets are encrypted at rest with a key derived from your wp-config salts, so a database-only compromise cannot mint codes.
* Two-factor: password authentication over XML-RPC or REST is **refused** for enrolled accounts, since a second factor cannot be prompted for there — otherwise 2FA would be bypassable by pointing the same stolen password at xmlrpc.php. Application passwords keep working: they are per-application, revocable, and can only be created from inside an already-protected session.
* New: the platform state endpoint (secwp/v1/state) exposes read-only `file_integrity` (status, counts, digests, delivery result) and `two_factor` (required roles, enrolled count, accounts still missing it) blocks for the INI WP control panel, and emits `integrity_change`, `2fa_enabled`, `2fa_disabled` and `2fa_recovery_used` events. Additive (schema_version unchanged); no connector/signing change.

= 1.4.2 =
* Fix: the vulnerability alert's **"Dismiss until something changes"** button now keeps its promise — the alert stays hidden across the daily re-scans as long as they keep finding the **same** vulnerabilities, and reappears only when the finding set actually changes (a new vuln appears, or a fixed one drops off). In 1.4.1 the dismissal was keyed to the scan timestamp as well as the findings, so every daily re-scan brought the banner back even though nothing had changed.
* Compatibility: sites upgrading from 1.4.1 keep their existing dismissal — the old timestamped token is recognized, so the banner doesn't pop back once after the update.

= 1.4.1 =
* Fix: the vulnerability-scan dashboard alert's **Dismiss** button now actually dismisses. The button is a nonce'd link, but the handler only read the action from POST data, so the click was ignored and the banner reappeared — it now reads the request regardless of method.
* Change: **"Dismiss until something changes"** now hides the vulnerability alert until the **next scan runs** (or the finding set changes), instead of staying hidden across re-scans as long as the same vulnerabilities were found. Dismissal is keyed to the scan timestamp + finding-set digest.
* Hardening: **Disable XML-RPC** now also hard-blocks a direct hit on xmlrpc.php with an early 403, before WordPress finishes loading — so bogus XML-RPC floods are cheap to absorb and scanners get a clean 403, not a 200/405. The existing method-neutralizing filters (pingback.ping, system.multicall, etc.) stay in place as defense-in-depth. No server config required; fully portable.

= 1.4.0 =
* New: a dedicated **INI Protector → IP Block** page — one home for blocking, separate from the Traffic monitor (which stays a read-only forensics view). It shows the system's suggested blocks alongside the IPs you've already blocked, with the manual add-IP box. The blocklist and add-IP box have moved here from the Traffic page.
* New: **Suggested by the system** — the traffic monitor's abuse-threshold candidates (the same ones the INI WP panel already saw) are now shown in the admin with a one-click **Apply block**. Previously these were computed but never surfaced in the UI.
* New: **Auto-block escalation** (Security toggle). Every 5 minutes the engine scores offending IPs and escalates **temporary** blocks on a ladder — 1 hour → 4 hours → 8 hours → 5 days → 2 weeks. By default it only **suggests** (Block Suggestion System); turn on **Enforce** for fully automatic **Auto-Block** mode.
* New: temporary, expiring blocks. Blocks now carry an expiry and a source (manual / suggested / auto); manual blocks stay permanent, while suggested-Apply and auto blocks ride the escalation ladder and expire on their own. Clicking **Apply** on a suggestion now creates a temporary, escalating block (not a permanent one).
* Safety: an IP/CIDR **allowlist** (IPv4 + IPv6) is never auto-blocked, and verified Googlebot/Bing/etc. (reverse + forward DNS) are always exempt — so the engine can't deindex your site or block your own ranges. It **never** issues a permanent block automatically, and an IP with no fresh offense for 30 days **decays** one level.
* New: the platform state endpoint (secwp/v1/state) exposes a read-only `autoblock` block (mode + escalation entries) and emits `autoblock_temp` events for the INI WP control panel. Additive (schema_version unchanged); no connector/signing change.

= 1.3.0 =
* New: **Vulnerability scan** (Security). Once a day INI Protector checks every installed plugin, theme, and your WordPress core version against the free WPVulnerability database (CC0, no API key) and flags any component whose installed version is affected by a known vulnerability.
* New: a dedicated **INI Protector → Vulnerabilities** page lists each finding — component, type, installed version, severity, CVE reference, the version it's fixed in, and whether an update is already available — sorted worst-first, with a "Scan now" button.
* New: a **dashboard alert** + a count bubble on the menu when vulnerabilities are found. Dismiss it and it stays gone until the set of findings actually changes (a new vulnerability brings it back).
* New: **opt-in email alert** on new findings only (never on every scan), with a configurable minimum severity and recipient.
* New: the platform state endpoint (secwp/v1/state) exposes a read-only `vulnerabilities` block (counts + findings) for the INI WP control panel. Additive (schema_version unchanged).
* Privacy: no data about your site is sent — only the public slug of each component is looked up; lookups are cached and the daily scan is gated by the toggle.

= 1.2.0 =
* New: **per-IP activity drill-down** in INI Protector → Traffic. Click any IP in "Top offender IPs" to see a full profile — a clean/watch/suspicious/hostile verdict with the signals behind it, status-code and reason breakdowns, top paths, user agents, and a request timeline — then Block or Unblock right from that page.
* New: a **verdict badge** on every IP in the Top-offenders list (clean / watch / suspicious / hostile), so risky IPs stand out at a glance. An expandable legend next to the day filters explains each level.
* New: the platform state endpoint (secwp/v1/state) exposes the same drill-down for the INI WP control panel — each top IP carries its verdict, and an optional ?detail_ip= returns the full per-IP profile. Additive (schema_version unchanged).

= 1.1.0 =
* New: settings toggles now save via AJAX — flipping a switch no longer reloads the page.
* New: toast notifications confirm every change (enabled / disabled / saved) and surface errors, replacing the old reload-and-show-notice flow. No-JS browsers keep the classic notice.
* New: **Mask version on static assets** (Head cleanup) — replaces the real `?ver=` on CSS/JS with an opaque, salted token. Hides the WordPress/plugin version while keeping cache-busting (the token still changes when the real version does), so it's safer than fully removing `?ver=`.
* New: **Disable oEmbed & REST discovery** (Head cleanup) — removes the REST API and oEmbed auto-discovery `<link>` tags, the `wp-json` HTTP Link header, and the version leak in oEmbed/feed output. The REST API itself keeps working; no endpoint is disabled.

= 1.0.4 =
* Maintenance: no functional changes. Refreshes the self-hosted update manifest so the "View details" → Changelog window renders the full, formatted version history (matching SeoWP). Safe to install.

= 1.0.3 =
* New: a built-in **INI Protector → Traffic** view for sites not on the INI WP platform — totals, top offender IPs, suspicious paths, recent suspicious requests, suggested blocks, and a 1h / 24h / 7d window selector. Renders the same data the platform pulls.
* New: **IP blocking** — block an offender (or any IP) straight from the Traffic view; blocked IPs get a 403 early in the request. Uses the spoof-resistant client IP, runs independently of the traffic monitor, and refuses to block your own current IP (no self-lockout). Admins always bypass.

= 1.0.2 =
* New: the platform state endpoint (secwp/v1/state) now includes an aggregated `traffic` summary — totals, top offender IPs, suspicious paths, a recent sample, and suggested block rules — for the INI WP control panel's Traffic tab. Reports `enabled:false` when the traffic monitor is off. Honours an optional `?hours=` look-back window hint. Additive (schema_version unchanged).

= 1.0.1 =
* New: "Require login for REST API" now has a per-namespace public whitelist — tick which registered REST namespaces stay public (e.g. a headless front-end, oEmbed, a contact-form endpoint); everything else requires login. Strict by default (nothing public until ticked).
* Safety: the INI WP family REST namespaces are always exempt and can never be blocked, so the control panel (wp.ini.bg) and integrating plugins can't be locked out. Family membership is read from the connector's registry (iniwp_family_rest_namespaces) when present, with a safe built-in fallback when standalone; INI Protector self-registers secwp/v1. The whitelist UI shows the always-public namespaces read-only.

= 1.0.0 =
* Initial release. Security / head-cleanup / SEO-privacy hardening extracted
  into a standalone plugin, plus the INI WP platform-state endpoint.
