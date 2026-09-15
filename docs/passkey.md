# Passkey Login

`--passkey` replaces the terminal flow (username, password, Okta Verify push) with a Chrome-driven flow. Okta handles
authentication with **any factor you have enrolled**: passkey, Touch ID, security key, or Okta Verify push. The CLI
never sees your password.

## Table of Contents

- [Usage](#usage)
- [Login Modes](#login-modes)
- [Unattended Logins](#unattended-logins)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)

## Usage

```bash
aws-login --passkey login                  # all saved profiles
aws-login --passkey login admints-dev      # all saved profiles; admints-dev becomes [default]
aws-login --passkey list                   # list your role ARNs
aws-login --passkey --headed login         # show the browser immediately
```

Requires Google Chrome and an Okta factor enrolled at `login.harvard.edu`.

## Login Modes

The mode is picked automatically on every run:

| Mode                     | When                                                                  | What you see                   |
|--------------------------|-----------------------------------------------------------------------|--------------------------------|
| **Stored passkey**       | A passkey was saved with `configure_passkey`                          | Nothing; fully headless        |
| **Session cookie reuse** | No stored passkey, but a successful login within the last 8 hours     | Nothing; headless              |
| **Interactive**          | Neither of the above, a headless attempt fails, or `--headed` is set  | A Chrome window to sign in     |

Headless attempts give up after 20 seconds (a cookie attempt that lands on the sign-in form fails within a second or
two) and fall back to the interactive window, which allows 2 minutes. If `username` is set in your config, it is
filled in for you.

## Unattended Logins

Enroll once:

```bash
aws-login configure_passkey
```

1. Chrome opens. Sign in with your usual factor.
2. Go to your Okta security settings and find **Set up another Security Key or Biometric** (not Okta FastPass).
3. Press **Enter** in the terminal, then click the enrollment button in the browser.

A virtual authenticator creates the passkey, and its ECDSA P-256 private key is stored in the OS keyring (service
`aws-login-saml-cli`, entry `passkey-credential`). From then on, `--passkey` logins complete silently with no Touch
ID or push. The passkey is scoped to `login.harvard.edu`.

Remove it with:

```bash
aws-login forget_passkey
```

Treat the stored passkey like a password: anyone who can read your keyring can sign in as you.

## How It Works

1. Chrome starts with a dedicated profile at `~/.config/huit_aws/chrome-profile`, separate from your normal browser.
2. If a passkey is stored, it is loaded into a Chrome DevTools virtual authenticator before the page loads.
3. Chrome opens the Harvard Okta AWS app and authentication completes (passkey, cookie, or you in the window).
4. Okta posts a SAML assertion to `https://signin.aws.amazon.com/saml`. The CLI intercepts that request, extracts the
   assertion, and cancels it, so the AWS console never opens.
5. The assertion goes through the same STS exchange as the password flow.

## Troubleshooting

- **Force a fresh sign-in**: delete the session cookies and the stored passkey:

  ```bash
  rm ~/.config/huit_aws/chrome-profile/Default/Cookies*
  aws-login forget_passkey
  ```

- **See what the browser is doing**: add `--headed`.
- **"Restore pages?" bubbles**: suppressed on launch; if one still appears, it is safe to dismiss.
