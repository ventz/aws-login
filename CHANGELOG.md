# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

First release of the independent fork of HUIT's `aws-login-saml-cli` (last upstream version 2.0.4).
Upgrade notes: [Upgrading from Upstream](docs/install.md#upgrading-from-upstream).

### Changed

- **Breaking:** `login` logs in to every profile in `profile_map` and no longer prompts for a role. `[default]` is
  only changed when a profile name is given. `login_all` is now an alias for `login`.
- **Breaking:** long flags use two dashes (`--passkey`, `--headed`, `--show-config`, `--keyring=false`,
  `--autocomplete`, `--version`, `--help`); single-letter flags use one (`-v`, `-t`, `-d`, `-h`). The other spelling
  is rejected with a hint.
- **Breaking:** the config file moved to `~/.config/huit_aws/config.json` on every OS. An existing file in the old
  OS-specific location is copied over automatically.
- Only roles in `profile_map` are exchanged with STS, which makes login faster for users entitled to many roles.
- The default session duration is 8 hours, stepping down automatically (12h, 8h, 4h, 1h) for roles whose maximum is
  lower.
- Licensed under MIT.

### Added

- `login` prints which profiles were saved and which were not.
- `login` validates the profile name and argument count before authenticating.
- `--show-config` prints the config file path (to stderr, keeping stdout valid JSON).
- `--help` lists commands, flags, and the config file path.
- Passkey login (`--passkey`, `--headed`, `configure_passkey`, `forget_passkey`) with fully headless, unattended
  logins.

### Fixed

- `--help` printed only the flags, not the commands.
- Unknown commands exited with status 0.
- Shell completion listed a nonexistent `--completion` flag and omitted the passkey commands.
- AWS SDK configuration errors were ignored.
