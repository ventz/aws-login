package okta

// Browser-driven SAML capture for passkey-based Harvard Key login.
//
// Three operating modes, chosen automatically per invocation:
//
//   Tier 3 — stored passkey + virtual authenticator (fully unattended)
//     If credential.GetPasskeyCredential() returns a credential, we inject it
//     into a CDP virtual FIDO2 authenticator before navigation. Okta's
//     navigator.credentials.get() is then satisfied silently by the virtual
//     device, and we run headless. No Touch ID, no user interaction.
//
//   Tier 1 — warm cookie reuse (headless, no virtual authenticator)
//     If no stored credential exists but the persisted Chrome profile has a
//     fresh Okta session cookie, the SAML POST is reached without any prompt
//     and we capture it headless. "Fresh" is gated by a self-written success
//     stamp (hasWarmCookie / cookieFreshTTL), and if the headless attempt does
//     land on the identifier form anyway it bails immediately rather than
//     waiting out headlessTimeout.
//
//   Fallback — headed mode for interactive auth
//     If headless attempt times out (no cookie, expired cookie, or virtual
//     authenticator rejected), we relaunch headed so the user can complete
//     whatever factor Okta prompts for. The --headed flag forces this path.
//
// In every mode the SAML POST to https://signin.aws.amazon.com/saml is
// intercepted via Fetch.requestPaused, the assertion is pulled out of the
// form body, and the request is aborted so the AWS Console never opens.

import (
	"aws-login/config"
	"aws-login/credential"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// Same URL the password flow hits in InitializeSession — the Harvard Okta tile
// for the AWS console. Hitting it unauthenticated triggers the full login
// chain and ends in a form POST to signin.aws.amazon.com/saml.
const oktaAwsAppURL = "https://login.harvard.edu/app/harvard_awsconsole_1/exk1u9wgsl2oD1XWo1d8/sso/saml"

const samlPostURL = "https://signin.aws.amazon.com/saml"

const (
	// Headless attempt is fast — if cookie is dead or virtual authenticator
	// can't satisfy Okta, we'd rather bail and retry headed than hang.
	headlessTimeout = 20 * time.Second
	// Headed attempt can sit on a Touch ID / Okta Verify prompt; give it real time.
	headedTimeout = 120 * time.Second
)

// GetSamlAssertionViaBrowser launches Chrome, lets the user complete auth,
// and returns the decoded SAML XML. See the package doc above for the
// three-tier decision logic.
func GetSamlAssertionViaBrowser(runtimeContext config.RuntimeContext) (string, error) {
	forceHeaded := runtimeContext.Params.Headed != nil && *runtimeContext.Params.Headed
	storedCred := credential.GetPasskeyCredential()
	verbose := *runtimeContext.Params.Verbose

	// Headless can only succeed via a stored passkey (Tier 3) or a warm Okta
	// cookie (Tier 1). With neither, the headless attempt is guaranteed to time
	// out — so skip it and go straight to headed instead of eating headlessTimeout.
	if !forceHeaded && storedCred == nil && !hasWarmCookie() {
		if verbose {
			fmt.Println("No stored passkey and no warm cookie — skipping headless, launching headed.")
		}
		forceHeaded = true
	}

	// Tier 1 / Tier 3: try headless first (unless explicitly forced headed).
	if !forceHeaded {
		if storedCred != nil {
			if verbose {
				fmt.Println("Using stored passkey credential (headless mode).")
			}
		} else if verbose {
			fmt.Println("Trying headless mode (cookie reuse)...")
		}
		saml, err := runBrowserCapture(runtimeContext, true, storedCred, headlessTimeout)
		if err == nil {
			return saml, nil
		}
		if verbose {
			fmt.Printf("Headless attempt did not complete: %v\n", err)
		}
		fmt.Println("Falling back to headed browser for interactive auth...")
	}

	// Fallback / explicit headed: real browser window for interactive auth.
	return runBrowserCapture(runtimeContext, false, storedCred, headedTimeout)
}

// chromeProfileDir is the persisted user-data-dir for the automation browser.
func chromeProfileDir() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "huit_aws", "chrome-profile")
}

// cookieFreshTTL bounds how long after a successful login we still believe the
// Okta web-session cookie can carry a headless cookie-reuse attempt. Generous
// on purpose: the fail-fast watcher in runBrowserCapture caps the cost of a
// wrong guess at a couple of seconds, so this only needs to skip attempts that
// are *obviously* stale (e.g. first run of the day).
const cookieFreshTTL = 8 * time.Hour

// loginStampPath is touched after every successful capture; its mtime is our
// own freshness signal — far cheaper and more reliable than parsing the Okta
// session-cookie expiry out of Chrome's SQLite cookie store.
func loginStampPath() string {
	return filepath.Join(chromeProfileDir(), "last-login-success")
}

// recordLoginSuccess stamps "we authenticated just now" so the next invocation
// can decide whether a headless cookie-reuse attempt is worth trying.
func recordLoginSuccess() {
	_ = os.WriteFile(loginStampPath(), []byte(time.Now().Format(time.RFC3339)), 0600)
}

// hasWarmCookie reports whether the persisted Chrome profile holds a cookie
// store that is plausibly fresh enough for headless cookie reuse. Requires both
// a non-empty Cookies file AND a recent success stamp — a cookie file alone
// says nothing about whether the Okta session behind it is still valid, and
// betting on a stale one is exactly what burned ~10s of headlessTimeout before.
func hasWarmCookie() bool {
	info, err := os.Stat(filepath.Join(chromeProfileDir(), "Default", "Cookies"))
	if err != nil || info.Size() == 0 {
		return false
	}
	stamp, err := os.Stat(loginStampPath())
	if err != nil {
		return false // never logged in successfully here — don't trust the cookie
	}
	return time.Since(stamp.ModTime()) < cookieFreshTTL
}

// runBrowserCapture drives one chromedp session — either headless or headed,
// with or without an injected virtual authenticator — and returns the
// captured SAML assertion XML.
func runBrowserCapture(runtimeContext config.RuntimeContext, headless bool, storedCred *credential.PasskeyCredential, timeout time.Duration) (string, error) {
	verbose := *runtimeContext.Params.Verbose

	userDataDir := chromeProfileDir()
	if err := os.MkdirAll(userDataDir, 0700); err != nil {
		return "", fmt.Errorf("create chrome profile dir: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.UserDataDir(userDataDir),
		chromedp.WindowSize(900, 750),
		// chromedp hard-kills Chrome on context cancel, which leaves the
		// persisted profile flagged as crashed and pops a "Restore pages?"
		// bubble on the next headed launch. Suppress it.
		chromedp.Flag("hide-crash-restore-bubble", true),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Optional CLI override of the overall timeout — useful when an Okta MFA
	// push takes longer than the built-in 2-minute headed budget.
	if *runtimeContext.Params.Timeout > 0 {
		timeout = time.Duration(*runtimeContext.Params.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(browserCtx, timeout)
	defer cancel()

	var (
		mu       sync.Mutex
		samlXML  string
		captured = make(chan struct{}, 1)
	)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		if e.Request.URL != samlPostURL {
			go func() { _ = fetch.ContinueRequest(e.RequestID).Do(ctx) }()
			return
		}
		if verbose {
			fmt.Printf("Intercepted POST to %s\n", samlPostURL)
		}
		var body string
		for _, entry := range e.Request.PostDataEntries {
			raw, derr := base64.StdEncoding.DecodeString(entry.Bytes)
			if derr != nil {
				continue
			}
			body += string(raw)
		}
		if vals, perr := url.ParseQuery(body); perr == nil {
			if b64 := vals.Get("SAMLResponse"); b64 != "" {
				if raw, derr := base64.StdEncoding.DecodeString(b64); derr == nil {
					mu.Lock()
					samlXML = string(raw)
					mu.Unlock()
				}
			}
		}
		go func() { _ = fetch.FailRequest(e.RequestID, network.ErrorReasonAborted).Do(ctx) }()
		select {
		case captured <- struct{}{}:
		default:
		}
	})

	// Build the chromedp action list. Order matters:
	//   1. fetch.Enable       — install POST interception pattern
	//   2. (optional) webauthn.Enable + virtual authenticator + addCredential
	//      — must happen BEFORE navigation so navigator.credentials.get() is
	//        served by the virtual device
	//   3. Navigate           — fire the SAML flow
	actions := []chromedp.Action{
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: samlPostURL, RequestStage: fetch.RequestStageRequest},
		}),
	}
	if storedCred != nil {
		actions = append(actions,
			webauthn.Enable().WithEnableUI(false),
			&virtualAuthAction{cred: storedCred, verbose: verbose},
		)
	}
	actions = append(actions, chromedp.Navigate(oktaAwsAppURL))

	if err := chromedp.Run(ctx, actions...); err != nil {
		return "", fmt.Errorf("chromedp run: %w", err)
	}

	// Best-effort username prefill — only meaningful in headed interactive
	// mode (in headless modes the cookie or virtual authenticator carries us
	// past the identifier form entirely).
	if !headless && storedCred == nil && runtimeContext.UserConfig.Username != nil && *runtimeContext.UserConfig.Username != "" {
		go prefillUsername(ctx, *runtimeContext.UserConfig.Username, verbose)
	}

	// Tier 1 fail-fast: a headless cookie-reuse attempt that lands on the Okta
	// identifier form has already failed — the cookie didn't carry us through.
	// Bail in ~seconds instead of waiting out the full headlessTimeout.
	//
	// Deliberately NOT done for Tier 3 (storedCred != nil): with a virtual
	// authenticator the identifier form can legitimately appear *before* the
	// WebAuthn ceremony, so its presence is not a failure signal there.
	authFailed := make(chan struct{}, 1)
	if headless && storedCred == nil {
		go func() {
			watchCtx, watchCancel := context.WithCancel(ctx)
			defer watchCancel()
			if err := chromedp.Run(watchCtx,
				chromedp.WaitVisible(`input[name="identifier"]`, chromedp.ByQuery),
			); err == nil {
				select {
				case authFailed <- struct{}{}:
				default:
				}
			}
		}()
	}

	select {
	case <-captured:
	case <-authFailed:
		return "", fmt.Errorf("headless cookie reuse failed: Okta requires interactive login")
	case <-ctx.Done():
		return "", fmt.Errorf("timed out after %s waiting for SAML assertion", timeout)
	}

	mu.Lock()
	defer mu.Unlock()
	if samlXML == "" {
		return "", fmt.Errorf("intercepted POST but SAMLResponse was empty")
	}
	recordLoginSuccess() // stamp freshness so the next run can try cookie reuse
	return samlXML, nil
}

// virtualAuthAction is a chromedp.Action that adds a virtual authenticator
// and seeds it with the stored credential. Done as a custom action (rather
// than two separate calls) so we can capture authenticatorId between them.
type virtualAuthAction struct {
	cred    *credential.PasskeyCredential
	verbose bool
}

func (a *virtualAuthAction) Do(ctx context.Context) error {
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
		return fmt.Errorf("add virtual authenticator: %w", err)
	}
	if a.verbose {
		fmt.Printf("Virtual authenticator added: %s\n", authID)
	}

	cred := &webauthn.Credential{
		CredentialID:         a.cred.CredentialID,
		RpID:                 a.cred.RpID,
		PrivateKey:           a.cred.PrivateKey,
		SignCount:            a.cred.SignCount,
		IsResidentCredential: true, // forced — login.harvard.edu uses discoverable creds
		UserHandle:           a.cred.UserHandle,
	}
	if err := webauthn.AddCredential(authID, cred).Do(ctx); err != nil {
		return fmt.Errorf("add credential to virtual authenticator: %w", err)
	}
	if a.verbose {
		fmt.Printf("Credential injected (rpId=%s)\n", a.cred.RpID)
	}
	return nil
}

// prefillUsername waits up to ~15s for Okta's identifier input to appear and
// sets the configured username into it. Best-effort — silent on failure.
//
// Okta's login page is a React-controlled SPA, which defeats the naive
// Focus→Clear→SendKeys approach two ways:
//   - chromedp.Clear() clears the DOM but not React's internal value tracker,
//     so SendKeys then *appends* to the value React still believes is there —
//     this is what produced the doubled "user@xuser@x".
//   - Chrome autofill (from the persisted profile) can populate the field, and
//     React may remount the input, either of which clobbers a one-shot write.
//
// Fix: set .value via the native HTMLInputElement setter and dispatch a
// bubbling 'input' event so React's tracker is updated (the standard
// _valueTracker workaround), then read the value back and retry a few times so
// a late autofill or remount can't leave a wrong/doubled value behind.
func prefillUsername(ctx context.Context, username string, verbose bool) {
	prefillCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	const sel = `input[name="identifier"]`
	if err := chromedp.Run(prefillCtx, chromedp.WaitVisible(sel, chromedp.ByQuery)); err != nil {
		if verbose {
			fmt.Printf("username prefill skipped: %v\n", err)
		}
		return
	}

	// Embed the username as a JS string literal safely (handles quotes etc.).
	uj, _ := json.Marshal(username)
	js := fmt.Sprintf(`(function(){
		var el = document.querySelector('input[name="identifier"]');
		if (!el) return '';
		var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
		setter.call(el, %s);
		el.dispatchEvent(new Event('input',  {bubbles:true}));
		el.dispatchEvent(new Event('change', {bubbles:true}));
		return el.value;
	})()`, string(uj))

	for i := 0; i < 5; i++ {
		var got string
		if err := chromedp.Run(prefillCtx, chromedp.Evaluate(js, &got)); err != nil {
			if verbose {
				fmt.Printf("username prefill attempt failed: %v\n", err)
			}
			return
		}
		if got == username {
			if verbose {
				fmt.Printf("Pre-filled username: %s\n", username)
			}
			return
		}
		select {
		case <-prefillCtx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
	if verbose {
		fmt.Println("username prefill could not stabilize the field value")
	}
}
