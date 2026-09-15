# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/ventz/aws-login/security/advisories/new) rather than in
a public issue. Include steps to reproduce and the version (`aws-login --version`).

You should receive a response within a week. Fixes are released as soon as practical and credited to the reporter
unless you prefer otherwise.

## Supported Versions

Only the latest release on `main` receives security fixes.

## What `aws-login` Handles

Knowing where sensitive data lives helps when assessing a report:

| Data                         | Where it is stored                                                               |
|------------------------------|----------------------------------------------------------------------------------|
| Harvard Key password         | OS keyring, service `aws-login-saml-cli`, only after `configure_keyring`          |
| Passkey private key          | OS keyring, service `aws-login-saml-cli`, entry `passkey-credential`              |
| Okta session cookies         | Dedicated Chrome profile at `~/.config/huit_aws/chrome-profile`                   |
| Temporary AWS credentials    | `~/.aws/credentials`, in plain text, as the AWS CLI expects                       |

Known, intentional behaviors (not vulnerabilities on their own):

- `-d` prints every API exchange, including your password and credentials, in cleartext. The CLI warns and waits
  for confirmation before continuing.
- Anyone who can read your OS keyring can use a stored passkey to sign in as you. Remove it with
  `aws-login forget_passkey`.
