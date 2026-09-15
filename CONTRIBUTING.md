# Contributing

Issues and pull requests are welcome.

## Table of Contents

- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Conventions](#conventions)
- [Pull Requests](#pull-requests)

## Development Setup

Requires Go 1.26 or newer.

```bash
git clone https://github.com/ventz/aws-login.git
cd aws-login
go build -o aws-login .
go vet ./...
go test ./...
```

Run your build as `./aws-login` so you are not testing an older copy on your `PATH`.

## Making Changes

- **Tests must not authenticate.** Unit tests cover parsing and decision logic (see `aws/aws_test.go`,
  `okta/okta_test.go`, `main_test.go`). Never commit captured tokens, SAML assertions, or real account IDs; use
  synthetic values such as `111111111111`.
- **Manual testing sends real MFA pushes.** `login` and `list` contact Okta. Errors that can be caught before
  authentication (bad arguments, unknown profiles) should be.
- **Never paste `-d` output.** Debug mode prints credentials, including your password, in cleartext.
- **Keep the docs in sync.** User-visible changes update `README.md` and the relevant page in `docs/`, plus an entry
  under *Unreleased* in `CHANGELOG.md`.

See [Architecture](docs/architecture.md) for how the pieces fit together.

## Conventions

- **Flags:** single-letter flags take one dash (`-v`), long flags take two (`--passkey`). `checkFlagDashes` in
  `main.go` enforces this; use the same spelling in help text, messages, completion scripts, and docs.
- **Formatting:** `gofmt`.
- **Spelling:** American English in code, messages, and docs.
- **Commit messages:** [Conventional Commits](https://www.conventionalcommits.org/), e.g.
  `feat(passkey): ...`, `fix(login): ...`, `docs: ...`.

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Make your change with tests where practical.
3. Confirm `go vet ./...` and `go test ./...` pass.
4. Open a pull request describing what changed and how you tested it.

Security issues should not be reported in public issues; see [SECURITY.md](SECURITY.md).
