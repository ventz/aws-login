# Usage Reference

```text
aws-login [flags] [command] [args]
```

With no command, `aws-login` runs `login`.

## Table of Contents

- [Commands](#commands)
- [Flags](#flags)
- [Shell Completion](#shell-completion)

## Commands

### login

```bash
aws-login login [profile]
```

Authenticates once and writes temporary credentials for **every** profile in your
[`profile_map`](configuration.md#profile_map) to `~/.aws/credentials`, plus a `region` entry per profile in
`~/.aws/config`. When it finishes, it lists which profiles were saved and which were not (role not granted to you,
or STS refused it).

- With no profile, `[default]` is left unchanged.
- With a profile, that profile is also copied into `[default]`.
- An unknown profile name is rejected **before** any password or MFA prompt.
- Only roles in `profile_map` are requested from STS; other roles you are entitled to are skipped.

```bash
aws-login login
aws-login login admints-dev
aws --profile admints-prod s3 ls
```

`login_all` is kept as an alias for `login` with no profile.

### list

```bash
aws-login list
```

Authenticates and prints every role ARN in your SAML assertion, without calling STS. Use it to build your
`profile_map`.

### list-role-map

```bash
aws-login list-role-map
```

Prints your saved profile mapping, sorted by role ARN:

```text
arn:aws:iam::111111111111:role/admints-dev-standard-saml-poweruser-iam-role@us-east-1 -> admints-dev
arn:aws:iam::222222222222:role/admints-prod-standard-saml-poweruser-iam-role@us-east-1 -> admints-prod
```

### switch

```bash
aws-login switch <profile>
```

Copies an existing profile's credentials into `[default]` without authenticating. The profile must already be in
`~/.aws/credentials` from an earlier `login`.

### assume

```bash
aws-login assume <role>
```

Assumes an IAM role defined in [`assumable_roles`](configuration.md#assumable_roles) and saves it as a profile of the
same name. If the role has a `required_profile`, that profile is switched to `[default]` first and used as the source
credentials; otherwise the current default AWS credentials (`[default]` or `AWS_PROFILE`) are used.

### configure_keyring

```bash
aws-login configure_keyring
```

Prompts for your username and password (twice) and stores the password in the OS keyring under the service name
`aws-login-saml-cli`. Later logins use it instead of prompting.

### configure_passkey / forget_passkey

```bash
aws-login configure_passkey
aws-login forget_passkey
```

Enroll or remove a passkey for unattended `--passkey` logins. See [Passkey Login](passkey.md).

## Flags

Single-letter flags use one dash; long flags use two. Flags go **before** the command.

| Flag                      | Description                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------------------|
| `-h`, `--help`            | Show help and quit                                                                                  |
| `--version`               | Print the version and quit                                                                          |
| `-v`                      | Verbose output                                                                                      |
| `-t <seconds>`            | STS session duration for every role, overriding config (see [Session Duration](configuration.md#session-duration)) |
| `-d`                      | Debug every API call. **Prints credentials, including your password, in cleartext**                 |
| `--keyring=false`         | Ignore the keyring and always prompt for the password                                               |
| `--passkey`               | Log in through the browser instead of password + push ([Passkey Login](passkey.md))                 |
| `--headed`                | With `--passkey`, show the browser immediately instead of trying headless first                     |
| `--show-config`           | Print the config file path (to stderr) and the loaded config as JSON (to stdout)                    |
| `--autocomplete <shell>`  | Print a completion script for `bash` or `zsh`                                                       |

Examples:

```bash
aws-login -v -t 3600 login admints-dev
aws-login --passkey --headed login
aws-login --show-config 2>/dev/null | jq '.profile_map'
```

## Shell Completion

Completion completes commands, flags, and your profile names. It requires `jq`.

```bash
# Bash: add to ~/.bashrc
source <(aws-login --autocomplete=bash)

# Zsh: add to ~/.zshrc (after compinit)
source <(aws-login --autocomplete=zsh)
```
