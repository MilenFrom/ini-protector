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

The public repository was introduced at 1.9.5 without publishing a release. Every version from 1.9.6 onward has been released from this repository.

### Release mechanics

For reference, and so a release can be audited after the fact:

1. Land the change on `main`. Three places carry the version and must agree: the `Version:` header and `SECWP_VERSION` in `ini-protector.php`, and `Stable tag:` in `readme.txt`. `Stable tag` is the lever that makes a version live, so it is bumped last, immediately before packaging.
2. Build with `bin/build-zip.sh` and test that exact package on a disposable or prerelease installation. Testing a package that is not the one you ship is not testing the release.
3. Tag the commit `vX.Y.Z` and push it, so the Git history has a fixed point matching the published version.
4. Sync `trunk/` in the SVN checkout from the built package, `svn cp trunk tags/X.Y.Z`, and commit both in one transaction.
5. Verify before and after. Diff `trunk/` and `tags/X.Y.Z` against the package before committing, and diff the ZIP that WordPress.org serves against it afterwards. They should be identical; if the tested package and the published package differ at all, the difference should be one line — `Stable tag` — and you should be able to say so from a diff rather than from memory.
6. Install the official ZIP on a test site and confirm `wp plugin verify-checksums ini-protector` passes and that saved settings survived.

The directory's plugin-information API can lag the SVN commit by some minutes. The tag and download URL going live before the API updates is normal and is not a packaging fault.
