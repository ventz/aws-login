# Configuration

## Table of Contents

- [Config File Location](#config-file-location)
- [Example](#example)
- [Options](#options)
- [Session Duration](#session-duration)
- [What Gets Written](#what-gets-written)

## Config File Location

```text
~/.config/huit_aws/config.json
```

The path is the same on every OS. An empty `{}` file is created on first run. Print the path and the loaded config
with:

```bash
aws-login --show-config
```

## Example

```json
{
    "username": "user@harvard.edu",
    "default_timeout_secs": 14400,
    "role_timeout_secs": {
        "admints-prod": 3600
    },
    "profile_map": {
        "arn:aws:iam::111111111111:role/admints-dev-standard-saml-poweruser-iam-role@us-east-1": "admints-dev",
        "arn:aws:iam::222222222222:role/admints-prod-standard-saml-poweruser-iam-role@us-east-1": "admints-prod"
    },
    "assumable_roles": {
        "ecs-deploy-role": {
            "arn": "arn:aws:iam::111111111111:role/arm-ecs-deploy-role",
            "required_profile": "admints-dev"
        },
        "lambda-execution-role": {
            "arn": "arn:aws:iam::444444444444:role/arm-lambda-execution-role"
        }
    }
}
```

## Options

| Option                 | Required | Description                                                               |
|------------------------|----------|---------------------------------------------------------------------------|
| `username`             | No       | Harvard Key username. Prompted for if missing                             |
| `profile_map`          | For `login` | Role ARN → profile name. Only these roles are logged in to             |
| `default_timeout_secs` | No       | Session duration for every role, in seconds                               |
| `role_timeout_secs`    | No       | Per-profile session duration: profile name → seconds                      |
| `assumable_roles`      | No       | Extra IAM roles for `aws-login assume`                                    |

### profile_map

Keys are full role ARNs exactly as printed by `aws-login list`; values are the profile names written to
`~/.aws/credentials`. `login` refuses to run with an empty `profile_map`.

### role_timeout_secs

Keys are profile **names** from `profile_map`, not ARNs.

### assumable_roles

Each key is the profile name to save. Each entry has:

- `arn` (required): the role to assume.
- `required_profile` (optional): a `profile_map` profile to switch to `[default]` and use as the source credentials.

Assumed-role credentials do not record an expiration time.

## Session Duration

The duration requested for each role is the first of these that is set:

1. `-t <seconds>` on the command line
2. `role_timeout_secs` for that profile
3. `default_timeout_secs`
4. Built-in default: 8 hours

AWS caps every role at its IAM `MaxSessionDuration`, which the SAML assertion does not reveal. If STS rejects the
requested duration, `aws-login` retries that role at the next shorter step (12h, 8h, 4h, 1h) until one is accepted.
It never requests more than the resolved value, so a lower `-t` or config value is always respected.

## What Gets Written

- `~/.aws/credentials`: one section per saved profile with `aws_access_key_id`, `aws_secret_access_key`,
  `aws_session_token`, and `aws_session_expiration` (UTC). Other sections in the file are preserved.
- `~/.aws/config`: a `[profile <name>]` section with `region = us-east-1` for each profile.
- OS keyring, service `aws-login-saml-cli`: your password (`configure_keyring`) and the passkey credential
  (`configure_passkey`).
