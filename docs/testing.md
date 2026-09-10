# Development and testing

Use your own disposable WordPress installation with PHP 7.4 or newer, WP-CLI, and an administrator with user ID 1. Install this checkout as `wp-content/plugins/ini-protector` and activate it. Run WP-CLI commands from the WordPress root, replacing `/path/to/ini-protector` with the absolute checkout path.

The regression scripts change settings and may create users or exercise plugin replacement. Use a disposable database and plugin directory, and reset the installation between suites. Never run them on production or a shared site.

## Syntax and packaging

From the repository root:

```sh
find . -name '*.php' -not -path './dist/*' -not -path './.git/*' -exec php -l {} \;
bash -n bin/build-zip.sh
bash bin/build-zip.sh
```

Inspect the archive: it must have a single `ini-protector/` root and exclude `.git`, `.github`, `bin`, and development documentation.

## WordPress integration checks

With the plugin active, run the suite relevant to the change, resetting your disposable installation between suites:

```sh
wp eval-file /path/to/ini-protector/bin/smoke.php
wp eval-file /path/to/ini-protector/bin/review-regressions.php
wp eval-file /path/to/ini-protector/bin/salt-regressions.php
```

The update suites load the required plugin code themselves:

```sh
wp --skip-plugins=ini-protector eval-file /path/to/ini-protector/bin/update-check-regressions.php
wp --skip-plugins=ini-protector eval-file /path/to/ini-protector/bin/update-install-regressions.php
```

The installation suite requires PHP's ZipArchive extension and a writable disposable plugin directory. These scripts cover selected regressions, not every supported environment.

For user-facing changes, also exercise the affected admin and public flows. For update changes, verify settings and activation survive a successful update and a rejected package. Include environment versions and results in the pull request. Run the official WordPress Plugin Check tool when changing plugin APIs or packaging.

## Releases

The maintainer publishes approved releases to WordPress.org SVN. A pull request, GitHub merge, or local ZIP build does not publish a WordPress.org release.

See [repository and release workflow](repository-workflow.md) for the development and publication process.
