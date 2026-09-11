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
| `SECWP_TRUST_PROXY` | Legacy boolean form. Still honoured, but it cannot verify who sent the header, so it is limited to public addresses and reported as a warning by Security → Scan. Prefer `SECWP_TRUSTED_PROXIES`. |
| `SECWP_VULN_API_BASE` | Override the vulnerability database endpoint. |

## Traffic log sizing

The traffic monitor is bounded by two limits, and whichever is reached first
applies: **90 days** of history and **250,000 requests** (roughly 90 MB). On a
busy site the row cap is usually the one that bites. Either can be set to "no
limit" in Configure → Traffic monitor; the Traffic page shows current usage and
projects growth. Requests inside the auto-block evaluation window are never
deleted by the row cap, so lowering it cannot starve automatic blocking.

```php
define( 'SECWP_TRUSTED_PROXIES', '173.245.48.0/20, 2400:cb00::/32' );
```

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
