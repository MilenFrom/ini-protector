# INI Protector

WordPress security and hardening with individually configurable features: file integrity monitoring, two-factor authentication, login protection, security headers, vulnerability scanning, and privacy utilities.

- [Install the stable plugin from WordPress.org](https://wordpress.org/plugins/ini-protector/)
- [Report a bug or request a feature](https://github.com/MilenFrom/ini-protector/issues)
- [Contribute](CONTRIBUTING.md) · [Development and testing](docs/testing.md) · [Security reporting](SECURITY.md)

## Requirements

WordPress 5.7 or later and PHP 7.4 or later. See [readme.txt](readme.txt) for feature details and the release changelog.

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
