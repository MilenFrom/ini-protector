# Security policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/MilenFrom/ini-protector/security/advisories/new). Do not publish exploitable details in an issue or pull request before a fix is coordinated.

Include affected versions, prerequisites, reproduction steps or a minimal proof of concept, and the impact you observed. Use test data and omit real credentials or personal information.

The maintainer will review the report and coordinate any fix and disclosure with the reporter. No response-time guarantee is currently offered.

## Versions

Use the latest stable version on WordPress.org. The development branch is not a published release, and older versions do not have a separate maintenance commitment.

Fixes ship in the next release rather than as backports, so "update to the current version" is the remediation for everything listed below.

## Security releases

Versions that contain security fixes, so you can tell whether an installation is affected. Full detail is in the [changelog](readme.txt).

### 1.9.7 — 2026-09-11

- Integrity webhooks refuse link-local destinations (169.254.0.0/16, fe80::/10), the cloud metadata endpoint on most hosts. Configurable only by an administrator, and the request returns nothing but a success/failure boolean, so this is hardening rather than a reachable disclosure.
- The traffic log row cap can no longer prune inside the auto-block evaluation window. Previously a busy site with a low cap could hand the blocker an incomplete window, weakening automatic blocking exactly where traffic was heaviest.

### 1.9.6 — 2026-09-11

- **Site password bypass via REST.** With site-password protection enabled, any logged-in account — including a subscriber — could read protected posts and pages through `/wp-json/` although the same request to the front-end returned the password form. Affects sites using the site-password feature that also allow low-privilege accounts or open registration.
- **Two-factor pending-login tokens could be held open indefinitely** by submitting wrong codes, and survived a password change or reset. Completing the login still required a valid second factor.
- **Authenticator secrets could be stored unencrypted** if libsodium was unavailable or encryption failed, contradicting the documented at-rest guarantee. Unreachable on supported WordPress versions, which bundle the sodium polyfill, but the code path existed and is now removed.
- **Forwarded client IPs were trusted without verifying the sender** when `SECWP_TRUST_PROXY` was enabled, allowing IP-block evasion or getting another address blocked. Replaced by `SECWP_TRUSTED_PROXIES`; see the [README](README.md).
- **Executable files in uploads, caches and backup folders were never checked** by integrity monitoring, and `.php5`-style extensions and `.user.ini` were missed by some scans entirely — the usual places and names a webshell uses.
- **A truncated integrity scan dropped unscanned files from the baseline,** silently leaving everything past the file limit unmonitored from then on.
- The site-password form and the login lockout are now rate-limited and fail fast respectively.

## Credit

Several of the issues above came from external review by people who examined the published source and reported what they found. That is welcome; please keep doing it. Reporters who want to be named in a release can say so in their report.
