# Contributing to INI Protector

Contributions from other developers are welcome.

## Bugs and feature requests

Search existing issues first. For bugs, include reproduction steps, expected and actual behavior, and your WordPress, PHP, and plugin versions. Remove credentials, personal information, and private server details from logs and screenshots. For vulnerabilities, use [private security reporting](SECURITY.md).

For substantial features or architectural changes, open an issue to discuss the approach before implementing it.

## Pull requests

1. Fork this repository and create a branch from `main`.
2. Keep the change focused and follow the surrounding code style and WordPress conventions.
3. Preserve PHP 7.4 compatibility and existing settings, hooks, and `secwp` identifiers unless a migration is part of the agreed change.
4. Validate and sanitize input, check permissions and nonces for privileged actions, and escape output appropriately.
5. Run the relevant checks in [docs/testing.md](docs/testing.md). Add regression coverage when fixing behavior that could recur.
6. Open a pull request describing the problem, the change, and how you verified it. Disclose checks you could not run.

Do not include credentials, database dumps, private infrastructure information, build artifacts, or unrelated formatting changes. Version bumps and WordPress.org publication are handled by the maintainer.

By submitting a contribution, you agree that it may be distributed under the project's GPL-2.0-or-later license. Keep discussions respectful and constructive.
