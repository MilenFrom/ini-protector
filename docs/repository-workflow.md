# Repository and release workflow

## Development repository

[MilenFrom/ini-protector](https://github.com/MilenFrom/ini-protector) is the canonical public development repository for INI Protector. Its default branch is `main`. Public development began on 2026-09-10 with a clean snapshot of the 1.9.5 plugin source; older release changes are recorded in [readme.txt](../readme.txt).

Developers can fork the repository and open pull requests against `main` without direct write access. Use [issues](https://github.com/MilenFrom/ini-protector/issues) for bugs and feature discussions, the [contribution guide](../CONTRIBUTING.md) for review expectations, and [private vulnerability reporting](../SECURITY.md) for security findings.

The plugin directory and main file are `ini-protector/` and `ini-protector.php`. Existing `SecurityWP_*` class names and `secwp` identifiers remain for compatibility; the repository name change is not a request to rename those interfaces or stored settings.

## Changes and verification

1. Create a focused branch from `main` in your fork.
2. Implement the change and run the relevant [development checks](testing.md).
3. Submit a pull request explaining the resulting behavior and verification results.
4. Address review feedback before the maintainer merges the change.

Keep deployment credentials, private infrastructure details, and test artifacts outside Git. Contributor testing uses disposable environments; maintainer infrastructure is not required to contribute.

## Distribution and releases

[WordPress.org](https://wordpress.org/plugins/ini-protector/) distributes stable installations. The `main` branch can contain unreleased changes, and a GitHub source archive is not the curated installable package produced by `bin/build-zip.sh`.

The maintainer prepares and verifies the plugin ZIP, coordinates version and changelog updates, and publishes approved versions through WordPress.org SVN. Merging a pull request or building a ZIP does not publish a release. SVN publication and release creation require explicit project-owner approval.

The public repository was introduced without changing the plugin version or publishing a new WordPress.org release.
