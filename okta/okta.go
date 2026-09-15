package okta

import (
	"aws-login/config"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

type Sess struct {
	nonce       string
	stateToken  string
	stateHandle string
}

type UserCredentials struct {
	Username string
	Password string
}

type MfaOption struct {
	Id     string
	Name   string
	Method string
}

type OktaResponse struct {
	remediation    map[string]any
	messages       map[string]any
	authenticators map[string]any
	success        map[string]any
	cancel         map[string]any
}

func GetUserMfaOption(runtimeContext *config.RuntimeContext, mfaOptions []MfaOption) (*MfaOption, error) {
	if len(mfaOptions) == 0 {
		panic(fmt.Errorf("No MFA options found.\n"))
	}

	for _, mfaOption := range mfaOptions {
		if mfaOption.Name == "Okta Verify" && mfaOption.Method == "push" {
			if *runtimeContext.Params.Verbose {
				fmt.Printf("Using MFA %s: %s (%s)\n", mfaOption.Id, mfaOption.Name, mfaOption.Method)
			}
			return &mfaOption, nil
		}
	}
	return nil, fmt.Errorf("Could not find an Okta Verify (push) MFA option - please see the documentation for configuring Okta Verify for your account.\n")
}

func getBodyContent(body io.ReadCloser) string {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(body)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func postJson(runtimeContext config.RuntimeContext, client *http.Client, payload map[string]interface{}, urlStr string) (map[string]any, error) {
	var payloadBuffer *bytes.Buffer = nil

	if payload != nil {
		jsonPayload, _ := json.Marshal(payload)
		payloadBuffer = bytes.NewBuffer(jsonPayload)
	} else {
		payloadBuffer = bytes.NewBuffer([]byte{})
	}

	req, err := http.NewRequest("POST", urlStr, payloadBuffer)
	if err != nil {
		return nil, fmt.Errorf("building POST %s: %w", urlStr, err)
	}
	req.Header.Add("Content-Type", "application/json")

	if *runtimeContext.Params.Debug {
		fmt.Printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
		fmt.Printf("POST URL: %s\n", urlStr)
		fmt.Printf("Request:\n%s\n---\n", payloadBuffer.String())
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", urlStr, err)
	}
	defer resp.Body.Close()
	respRaw := getBodyContent(resp.Body)
	if *runtimeContext.Params.Debug {
		fmt.Printf("Response (HTTP %d):\n%s\n", resp.StatusCode, respRaw)
	}

	var jsonResult map[string]any
	if err := json.Unmarshal([]byte(respRaw), &jsonResult); err != nil {
		return nil, fmt.Errorf("decoding response from %s (HTTP %d): %w", urlStr, resp.StatusCode, err)
	}
	return jsonResult, nil
}

// errorFromMessages extracts a human-readable error from an Okta "messages"
// block if one is present and contains a class=ERROR entry. Returns nil if
// none found.
func errorFromMessages(jsonResult map[string]any) error {
	raw, ok := jsonResult["messages"].(map[string]any)
	if !ok {
		return nil
	}
	values, ok := raw["value"].([]any)
	if !ok {
		return nil
	}
	for _, v := range values {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		msg, _ := m["message"].(string)
		class, _ := m["class"].(string)
		if class == "ERROR" && msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	return nil
}

func Challenge(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess, mfaOption *MfaOption) ([]MfaOption, error) {
	urlStr := "https://login.harvard.edu/idp/idx/challenge"
	var authenticator = map[string]string{
		"methodType": mfaOption.Method,
		"id":         mfaOption.Id,
	}
	payload := map[string]interface{}{
		"authenticator": authenticator,
		"stateHandle":   sess.stateHandle,
	}
	jsonResult, err := postJson(runtimeContext, client, payload, urlStr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return nil, err
	}
	if err := errorFromMessages(jsonResult); err != nil {
		return nil, fmt.Errorf("challenge rejected: %w", err)
	}
	sh, ok := jsonResult["stateHandle"].(string)
	if !ok {
		return nil, fmt.Errorf("challenge response missing stateHandle")
	}
	sess.stateHandle = sh

	return createMfaOptions(runtimeContext, jsonResult), nil

}

func ChallengePoll(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess) error {
	const maxAttempts = 60
	const delay = 2 * time.Second

	fmt.Printf("Waiting for user to ack.")
	for attempt := 0; attempt < maxAttempts; attempt++ {
		urlStr := "https://login.harvard.edu/idp/idx/authenticators/poll"
		payload := map[string]interface{}{
			"autoChallenge": true,
			"stateHandle":   sess.stateHandle,
		}
		jsonResult, err := postJson(runtimeContext, client, payload, urlStr)
		if err != nil {
			fmt.Printf("\n")
			return fmt.Errorf("polling for MFA ack: %w", err)
		}

		if err := errorFromMessages(jsonResult); err != nil {
			fmt.Printf("\n")
			return fmt.Errorf("MFA challenge rejected: %w", err)
		}

		// Refresh stateHandle if present; otherwise the session has been invalidated.
		if sh, ok := jsonResult["stateHandle"].(string); ok {
			sess.stateHandle = sh
		} else {
			fmt.Printf("\n")
			return fmt.Errorf("MFA poll response missing stateHandle (session likely expired)")
		}

		// Looking for remediation.value[0].name == "keep-me-signed-in".
		remediation, exists := jsonResult["remediation"].(map[string]any)
		if !exists {
			if *runtimeContext.Params.Verbose {
				fmt.Printf("\nNo remediation needed.\n")
			}
			return nil
		}
		values, ok := remediation["value"].([]any)
		if !ok || len(values) == 0 {
			fmt.Printf(".")
			time.Sleep(delay)
			continue
		}
		first, _ := values[0].(map[string]any)
		name, _ := first["name"].(string)
		if name == "keep-me-signed-in" {
			fmt.Printf("\nAuthenticated.\n")
			return nil
		}
		fmt.Printf(".")
		time.Sleep(delay)
	}
	fmt.Printf("\n")
	return fmt.Errorf("timed out waiting for MFA acknowledgement after %s", time.Duration(maxAttempts)*delay)
}

func KeepMeSignedIn(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess) (string, error) {
	urlStr := "https://login.harvard.edu/idp/idx/keep-me-signed-in"
	payload := map[string]interface{}{
		"keepMeSignedIn": true,
		"stateHandle":    sess.stateHandle,
	}
	jsonResult, err := postJson(runtimeContext, client, payload, urlStr)
	if err != nil {
		return "", err
	}
	if err := errorFromMessages(jsonResult); err != nil {
		return "", fmt.Errorf("keep-me-signed-in rejected: %w", err)
	}
	success, ok := jsonResult["success"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("keep-me-signed-in response missing 'success' (session may have expired)")
	}
	href, ok := success["href"].(string)
	if !ok {
		return "", fmt.Errorf("keep-me-signed-in 'success' block missing 'href'")
	}
	return href, nil
}

func GetSamlAssertion(runtimeContext config.RuntimeContext, client *http.Client, urlStr string) (string, error) {
	req, _ := http.NewRequest("GET", urlStr, nil)

	u, _ := url.Parse(urlStr)
	cookies := client.Jar.Cookies(u)
	if cookies == nil {
		fmt.Printf("No cookies found")
	}

	if *runtimeContext.Params.Debug {
		fmt.Printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
		fmt.Printf("GET URL: %s\n", urlStr)
	}

	resp, _ := client.Do(req)
	respRaw := getBodyContent(resp.Body)

	if *runtimeContext.Params.Debug {
		fmt.Printf("Response:\n%s\n", respRaw)
	}

	// Looking for <input name="SAMLResponse"
	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(respRaw))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return "", err
	}

	var samlResponse string = ""
	doc.Find("input[name='SAMLResponse']").Each(func(index int, item *goquery.Selection) {
		samlResponseBase64, exists := item.Attr("value")
		if exists {
			samlResponseBytes, _ := base64.StdEncoding.DecodeString(samlResponseBase64)
			samlResponse = string(samlResponseBytes)
		}
	})

	return samlResponse, nil
}

/*
*
Example json:

	{
	  "authenticators": {
		"type": "array",
		"value": [
		  {
			"type": "federated",
			"key": "external_idp",
			"id": "aut1rm57k0irRJc6v1d8",
			"displayName": "Duo",
			"methods": [
			  {
				"type": "idp"
			  }
			],
			"allowedFor": "none",
			"logoUri": "https://ok3static.oktacdn.com/fs/bcg/24/gfs1ulq9xxy9Ja4LC1d8"
		  },
		}
	}
*/
func createMfaOptions(runtimeContext config.RuntimeContext, jsonResponse map[string]any) []MfaOption {
	var mfaOptions []MfaOption

	// Navigate to the displayName
	authenticators := jsonResponse["authenticators"].(map[string]any)
	values := authenticators["value"].([]any)
	for _, value := range values {
		authenticator := value.(map[string]any)
		displayName := authenticator["displayName"].(string)
		id := authenticator["id"].(string)
		methods, exists := authenticator["methods"].([]any)

		if exists {
			for _, method := range methods {
				methodMap := method.(map[string]any)
				methodVal := methodMap["type"].(string)
				if *runtimeContext.Params.Verbose {
					fmt.Printf("Adding mfa option %s:%s (%s)\n", id, displayName, methodVal)
				}
				mfaOptions = append(mfaOptions, MfaOption{
					Id:     id,
					Name:   displayName,
					Method: methodVal,
				})
			}
		} else {
			fmt.Printf("No methods found for %s\n", displayName)
		}
	}

	return mfaOptions
}

func ChallengeAnswer(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess, userCredentials UserCredentials) ([]MfaOption, error) {
	var mfaOptions []MfaOption
	urlStr := "https://login.harvard.edu/idp/idx/challenge/answer"
	var creds = map[string]string{
		"passcode": userCredentials.Password,
	}
	payload := map[string]interface{}{
		"credentials": creds,
		"stateHandle": sess.stateHandle,
	}

	jsonResult, err := postJson(runtimeContext, client, payload, urlStr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	if jsonResult["messages"] != nil {
		messagesContainer := jsonResult["messages"].(map[string]any)
		messages := messagesContainer["value"].([]any)

		for _, messageJson := range messages {
			message := messageJson.(map[string]any)
			msgStr := message["message"].(string)
			msgType := message["class"].(string)

			if msgType == "ERROR" {
				return nil, fmt.Errorf("%s", msgStr)
			}
		}
	}

	sh, ok := jsonResult["stateHandle"].(string)
	if !ok {
		return nil, fmt.Errorf("challenge/answer response missing stateHandle")
	}
	sess.stateHandle = sh
	mfaOptions = createMfaOptions(runtimeContext, jsonResult)

	return mfaOptions, nil
}

func Identify(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess, userCredentials UserCredentials) ([]MfaOption, error) {
	urlStr := "https://login.harvard.edu/idp/idx/identify"
	payload := map[string]interface{}{
		"identifier":  userCredentials.Username,
		"stateHandle": sess.stateHandle,
	}

	jsonResult, err := postJson(runtimeContext, client, payload, urlStr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return nil, err
	}
	if err := errorFromMessages(jsonResult); err != nil {
		return nil, fmt.Errorf("identify rejected: %w", err)
	}
	mfaOptions := createMfaOptions(runtimeContext, jsonResult)
	sh, ok := jsonResult["stateHandle"].(string)
	if !ok {
		return nil, fmt.Errorf("identify response missing stateHandle")
	}
	sess.stateHandle = sh
	return mfaOptions, nil
}

func parseStateTokenFromBody(runtimeContext config.RuntimeContext, body string) (string, error) {
	regex := `\b(?:let|var|const)\s+stateToken\s*=\s*['"]([^'"]+)['"]`
	re := regexp.MustCompile(regex)

	if !re.MatchString(body) {
		return "", fmt.Errorf("No stateToken found in body")
	}

	matches := re.FindStringSubmatch(body)
	// NOTE: 0 is the full match (e.g. 'var stateToken="xxxxxx"', 1 is the first captured group (e.g. 'xxxxx').
	stateToken, err := strconv.Unquote(`"` + matches[1] + `"`)
	if err != nil {
		return "", fmt.Errorf("Error unquoting stateToken: %v", err)
	}
	if *runtimeContext.Params.Verbose {
		fmt.Printf("Found stateToken: %s\n", stateToken)
	}

	return stateToken, nil
}

func InitializeSession(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess) {
	urlStr := "https://login.harvard.edu/app/harvard_awsconsole_1/exk1u9wgsl2oD1XWo1d8/sso/saml"
	req, _ := http.NewRequest("GET", urlStr, nil)

	if *runtimeContext.Params.Debug {
		fmt.Printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
		fmt.Printf("GET URL: %s\n", urlStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	respRaw := getBodyContent(resp.Body)

	if *runtimeContext.Params.Debug {
		fmt.Printf("Response:\n%s\n", respRaw)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(respRaw))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	doc.Find("script[nonce]").Each(func(index int, item *goquery.Selection) {
		var exists bool
		sess.nonce, exists = item.Attr("nonce")
		if !exists {
			fmt.Printf("Could not find nonce: %v\n", err)
			return
		}

		body := item.Text()
		stateToken, err := parseStateTokenFromBody(runtimeContext, body)
		if err == nil {
			sess.stateToken = stateToken
		} else if *runtimeContext.Params.Verbose {
			fmt.Printf("Error parsing stateToken: %v\n", err)
		}
	})
	if sess.stateToken == "" {
		panic("Could not find stateToken.")
	}
}

func Introspect(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess) {
	payload := map[string]interface{}{
		"stateToken": sess.stateToken,
	}
	urlStr := "https://login.harvard.edu/idp/idx/introspect"

	jsonResult, err := postJson(runtimeContext, client, payload, urlStr)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if *runtimeContext.Params.Verbose {
		fmt.Printf("Introspect Response:\n%v\n", jsonResult)
	}
	sess.stateHandle = jsonResult["stateHandle"].(string)
}

func GetNonce(runtimeContext config.RuntimeContext, client *http.Client, sess *Sess) {
	urlStr := "https://login.harvard.edu/api/v1/internal/device/nonce"
	jsonResult, err := postJson(runtimeContext, client, nil, urlStr)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	sess.nonce = jsonResult["nonce"].(string)
}
