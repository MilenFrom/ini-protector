# INI Protector

WordPress security and hardening with individually configurable features: file integrity monitoring, two-factor authentication, login protection, security headers, vulnerability scanning, and privacy utilities.

- [Install the stable plugin from WordPress.org](https://wordpress.org/plugins/ini-protector/)
- [Report a bug or request a feature](https://github.com/MilenFrom/ini-protector/issues)
- [Contribute](CONTRIBUTING.md) · [Development and testing](docs/testing.md) · [Security reporting](SECURITY.md)
- [Repository and release workflow](docs/repository-workflow.md)

## Requirements

WordPress 5.7 or later and PHP 7.4 or later. See [readme.txt](readme.txt) for feature details and the release changelog.

## Configuration constants

Optional, defined in `wp-config.php`:

| Constant | Purpose |
| --- | --- |
| `SECWP_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of your reverse proxy or CDN. Forwarded client-IP headers are honoured **only** when the connection comes from one of these, and `X-Forwarded-For` is read from the trusted end. Without it, client IPs come from the socket peer and cannot be forged. |
| `SECWP_TRUST_CF_CONNECTING_IP` | Set to `true` to also read `CF-Connecting-IP` from a declared proxy. Only when every entry in `SECWP_TRUSTED_PROXIES` is Cloudflare: other proxies pass the header through as the visitor sent it. Not needed for Cloudflare in general, which also appends the visitor to `X-Forwarded-For`. |
| `SECWP_TRUST_PROXY` | Legacy boolean form. Still honoured, but it cannot verify who sent the header, so it is limited to public addresses and reported as a warning by Security → Scan. Prefer `SECWP_TRUSTED_PROXIES`. |
| `SECWP_VULN_API_BASE` | Override the vulnerability database endpoint. |

```php
define( 'SECWP_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );
```

## Traffic log sizing

The traffic monitor is bounded by two limits, and whichever is reached first
applies: **90 days** of history and **250,000 requests** (roughly 90 MB). On a
busy site the row cap is usually the one that bites. Either can be set to "no
limit" in Configure → Traffic monitor; the Traffic page shows current usage and
projects growth. Requests inside the auto-block evaluation window are never
deleted by the row cap, so lowering it cannot starve automatic blocking. The
row count can therefore temporarily exceed the configured cap. Existing saved
limits are preserved when upgrading.

## Stable updates

On the WordPress **Plugins** screen, use **Check for updates** beside INI Protector
to check the WordPress.org directory without waiting for the normal update-check
cache. If a newer compatible release is available, **Update now** installs the
official WordPress.org ZIP through WordPress's installer. Settings and activation
are preserved. This check uses WordPress.org releases; GitHub development commits
are not offered as plugin updates.

## WordPress salt changes and recovery

Author URL tokens and asset cache tokens are independent of WordPress's
authentication salts. Changing those salts does not rotate these public tokens.
The 1.9.2 upgrade retired older salt-derived author URLs once; sites upgrading
from an earlier version should regenerate author links and clear page caches.

Two-factor authenticator secrets are encrypted using the site's secure-auth salts.
After rotating those salts, sign in with an unused recovery code, turn off 2FA
from your profile with a second unused recovery code in the confirmation box and
save, then enroll again and save the new recovery codes.
Without a recovery code, an authorized administrator can reset enrollment with
`wp secwp 2fa reset <user>`. Unreadable secrets do not silently disable 2FA.

Pending sign-ins and site-password cookies may also be invalidated: restart login
or re-enter the site password. Reload an open CAPTCHA form for a fresh challenge.

## Development installation

Clone this repository into a disposable WordPress installation's `wp-content/plugins/ini-protector` directory, then activate INI Protector. The default branch contains development code; use WordPress.org for stable installations.

```sh
git clone https://github.com/MilenFrom/ini-protector.git wp-content/plugins/ini-protector
wp plugin activate ini-protector
```

## Build

With Bash, rsync, zip, and unzip installed, run:

```sh
bash bin/build-zip.sh
```

The plugin ZIP is written to `dist/`. Development documentation, tests, and Git metadata are excluded. Building a ZIP does not publish a release.

## Contributing

Bug reports, documentation improvements, tests, and pull requests are welcome. Fork the repository, create a focused branch, and open a pull request against `main`. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before starting.

GitHub hosts development and contribution review. Approved plugin releases are distributed through WordPress.org SVN.

## License

GPL-2.0-or-later; see [LICENSE](LICENSE). The bundled ALTCHA widget is MIT licensed; see [its license](assets/altcha-LICENSE.txt).
