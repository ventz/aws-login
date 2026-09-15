package okta

// One-time passkey enrollment for unattended (Tier 3) logins.
//
// Flow:
//   1. Launch headed Chrome to login.harvard.edu so the user can complete
//      identity verification with their real authenticator.
//   2. The user navigates to Okta Security Settings and clicks "Set up"
//      another "Security Key or Biometric".
//   3. RIGHT BEFORE clicking the enrollment button, the user presses ENTER
//      here. We then attach a CDP virtual FIDO2 authenticator.
//   4. The user clicks enroll. Chrome's WebAuthn API routes the
//      credentials.create() call to the virtual authenticator, which
//      generates an ECDSA P-256 keypair and emits WebAuthn.credentialAdded.
//   5. We capture the credential and store it in the OS keyring.
//
// Why the manual pause: WebAuthn.enable intercepts ALL navigator.credentials.*
// calls, so if we attach the virtual authenticator before identity
// verification it would block the user's real Touch ID, so it must only be
// enabled after the user has signed in.

import (
	"aws-login/config"
	"aws-login/credential"
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

const oktaLoginURL = "https://login.harvard.edu"

// RegisterPasskey runs the interactive enrollment flow and writes the new
// credential to the OS keyring on success.
func RegisterPasskey(runtimeContext config.RuntimeContext) error {
	verbose := *runtimeContext.Params.Verbose

	userDataDir := filepath.Join(os.Getenv("HOME"), ".config", "huit_aws", "chrome-profile")
	if err := os.MkdirAll(userDataDir, 0700); err != nil {
		return fmt.Errorf("create chrome profile dir: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.UserDataDir(userDataDir),
		chromedp.WindowSize(1000, 800),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Registration can take a while (user may need to look around Okta settings).
	ctx, cancel := context.WithTimeout(browserCtx, 10*time.Minute)
	defer cancel()

	// Listener captures the credential the moment the virtual authenticator
	// creates it. Buffered so we don't drop the event if read is slightly slow.
	credCh := make(chan *webauthn.Credential, 1)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		e, ok := ev.(*webauthn.EventCredentialAdded)
		if !ok {
			return
		}
		if verbose {
			fmt.Printf("WebAuthn.credentialAdded fired (rpId=%s)\n", e.Credential.RpID)
		}
		select {
		case credCh <- e.Credential:
		default:
		}
	})

	if err := chromedp.Run(ctx, chromedp.Navigate(oktaLoginURL)); err != nil {
		return fmt.Errorf("navigate to %s: %w", oktaLoginURL, err)
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("PHASE 1 — Identity Verification")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("In the browser window:")
	fmt.Println("  1. Sign in to Harvard Key as you normally would.")
	fmt.Println("  2. Open your Okta dashboard / Settings.")
	fmt.Println("  3. Find 'Security Key or Biometric' and click 'Set up'")
	fmt.Println("     (NOT Okta FastPass — that is not a WebAuthn factor).")
	fmt.Println("  4. If Okta re-prompts for verification, use your real Touch ID / push.")
	fmt.Println("  5. STOP when you see the 'Set up security key / Use passkey' prompt.")
	fmt.Println("     DO NOT click the enrollment button yet.")
	fmt.Println()
	prompt("Press ENTER here RIGHT BEFORE clicking the enrollment button")

	fmt.Println("\nActivating virtual authenticator…")
	authID, err := attachVirtualAuthenticator(ctx, verbose)
	if err != nil {
		return err
	}
	fmt.Printf("Virtual authenticator active: %s\n", authID)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("PHASE 2 — Click the enrollment button NOW")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("The virtual authenticator will handle the prompt silently.")
	fmt.Println("You should see 'WebAuthn.credentialAdded fired' if -v is set.")
	fmt.Println()

	// Wait for credential or user-confirm timeout
	select {
	case cred := <-credCh:
		fmt.Printf("Credential captured! rpId=%s, credentialId=%s…\n",
			cred.RpID, truncate(cred.CredentialID, 32))

		toStore := &credential.PasskeyCredential{
			CredentialID:         cred.CredentialID,
			RpID:                 cred.RpID,
			PrivateKey:           cred.PrivateKey,
			SignCount:            cred.SignCount,
			IsResidentCredential: true,
			UserHandle:           cred.UserHandle,
		}
		if err := credential.StorePasskeyCredential(toStore); err != nil {
			return fmt.Errorf("store credential in keyring: %w", err)
		}
		fmt.Println("Credential saved to OS keyring.")
		fmt.Println()
		fmt.Println("Future `aws-login --passkey ...` calls will use this credential")
		fmt.Println("automatically and run fully headless — no Touch ID prompts.")
		return nil

	case <-ctx.Done():
		return fmt.Errorf("registration timed out: %w", ctx.Err())
	}
}

func attachVirtualAuthenticator(ctx context.Context, verbose bool) (webauthn.AuthenticatorID, error) {
	if err := webauthn.Enable().WithEnableUI(false).Do(ctx); err != nil {
		return "", fmt.Errorf("WebAuthn.enable: %w", err)
	}
	authID, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Ctap2version:                webauthn.Ctap2versionCtap21,
		Transport:                   webauthn.AuthenticatorTransportInternal,
		HasResidentKey:              true,
		HasUserVerification:         true,
		IsUserVerified:              true,
		AutomaticPresenceSimulation: true,
	}).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("WebAuthn.addVirtualAuthenticator: %w", err)
	}
	return authID, nil
}

func prompt(msg string) {
	fmt.Printf("%s and press ENTER: ", msg)
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
