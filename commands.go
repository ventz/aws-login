package main

import (
	"aws-login/aws"
	"aws-login/config"
	"aws-login/credential"
	"aws-login/okta"
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/term"
	"gopkg.in/ini.v1"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

func getMfaOptions(runtimeContext config.RuntimeContext, sess *okta.Sess, client *http.Client, userCredentials okta.UserCredentials) ([]okta.MfaOption, error) {
	var err error

	var mfaOptions []okta.MfaOption
	mfaOptions, err = okta.Identify(runtimeContext, client, sess, userCredentials)
	if *runtimeContext.Params.Verbose {
		fmt.Printf("Idenitfy mfaOPtions: %v\n", mfaOptions)
	}
	if err != nil {
		return nil, err
	}

	var passwordOption *okta.MfaOption
	var oktaVerifyPushOption *okta.MfaOption
	for _, mfaOption := range mfaOptions {
		if mfaOption.Name == "Okta Verify" && mfaOption.Method == "push" {
			if *runtimeContext.Params.Verbose {
				fmt.Printf("Found Okta Verify Option\n")
			}
			oktaVerifyPushOption = &mfaOption
		}
		if mfaOption.Name == "Password" && mfaOption.Method == "password" {
			if *runtimeContext.Params.Verbose {
				fmt.Printf("Found Password Option\n")
			}
			passwordOption = &mfaOption
		}
	}

	if oktaVerifyPushOption == nil {
		if *runtimeContext.Params.Verbose {
			fmt.Printf("Okta Verify is nil\n")
		}
		// Choose password then get the list again.
		mfaOptions, _ = okta.Challenge(runtimeContext, client, sess, passwordOption)
		if *runtimeContext.Params.Verbose {
			fmt.Printf("First challenge options mfaOPtions: %v\n", mfaOptions)
		}
	}

	mfaOptions, err = okta.ChallengeAnswer(runtimeContext, client, sess, userCredentials)
	return mfaOptions, err
}

func createHttpClient() *http.Client {
	cookieJar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     cookieJar,
		Timeout: 30 * time.Second,
	}
}

func getAwsCredentials(runtimeContext config.RuntimeContext) ([]aws.AwsCredentials, error) {
	var samlAssertion string
	var credentials []aws.AwsCredentials
	var err error

	// Passkey path: drive a browser, capture the SAML assertion, skip the
	// password+MFA IDX dance entirely.
	if runtimeContext.Params.Passkey != nil && *runtimeContext.Params.Passkey {
		samlAssertion, err = okta.GetSamlAssertionViaBrowser(runtimeContext)
		if err != nil {
			return nil, err
		}
		return aws.GetAwsCredentials(runtimeContext, samlAssertion)
	}

	userCredentials := promptUserCredentials(runtimeContext)
	client := createHttpClient()
	sess := &okta.Sess{}

	okta.InitializeSession(runtimeContext, client, sess)
	okta.Introspect(runtimeContext, client, sess)
	okta.GetNonce(runtimeContext, client, sess)

	var mfaOptions []okta.MfaOption
	mfaOptions, err = getMfaOptions(runtimeContext, sess, client, userCredentials)
	if err != nil {
		return nil, err
	}

	userMfaOption, err := okta.GetUserMfaOption(&runtimeContext, mfaOptions)
	if err != nil {
		return nil, err
	}
	_, err = okta.Challenge(runtimeContext, client, sess, userMfaOption)
	if err != nil {
		return nil, err
	}

	err = okta.ChallengePoll(runtimeContext, client, sess)
	if err != nil {
		return nil, err
	}
	redirect, err := okta.KeepMeSignedIn(runtimeContext, client, sess)
	if err != nil {
		return nil, err
	}
	samlAssertion, err = okta.GetSamlAssertion(runtimeContext, client, redirect)
	if err != nil {
		return nil, err
	}

	credentials, err = aws.GetAwsCredentials(runtimeContext, samlAssertion)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// login writes every saved profile (profile_map). An optional profile argument
// is also copied into [default]; without one, [default] is left untouched.
func login(runtimeContext config.RuntimeContext) error {
	userConfig := runtimeContext.UserConfig
	if len(userConfig.ProfileMap) == 0 {
		return fmt.Errorf("no saved profiles: add a \"profile_map\" to %s (run `aws-login list` to see your role ARNs)", *config.GetConfigFileName(nil))
	}
	if len(runtimeContext.Params.ExtraArgs) > 1 {
		return fmt.Errorf("login takes at most one profile, got %d: %s", len(runtimeContext.Params.ExtraArgs), strings.Join(runtimeContext.Params.ExtraArgs, " "))
	}
	// Validate the alias before authenticating so a typo doesn't cost an MFA prompt.
	if len(runtimeContext.Params.ExtraArgs) == 1 && profileArn(userConfig, runtimeContext.Params.ExtraArgs[0]) == "" {
		return fmt.Errorf("no saved profile named %q (see `aws-login list-role-map`)", runtimeContext.Params.ExtraArgs[0])
	}

	credentials, err := getAwsCredentials(runtimeContext)
	if err != nil {
		return err
	}
	defaultCredential := getDefaultLoginCredentials(runtimeContext, credentials)
	aws.SaveAwsCredentials(runtimeContext, credentials, defaultCredential)
	reportSavedProfiles(runtimeContext, credentials)

	if len(credentials) == 0 {
		return fmt.Errorf("no profiles were saved")
	}
	if len(runtimeContext.Params.ExtraArgs) == 1 && defaultCredential == nil {
		return fmt.Errorf("profile %q was not granted, so [default] was not changed", runtimeContext.Params.ExtraArgs[0])
	}
	return nil
}

func login_all(runtimeContext config.RuntimeContext) error {
	runtimeContext.Params.ExtraArgs = nil
	return login(runtimeContext)
}

// profileArn returns the role ARN mapped to a profile alias, or "" if none.
func profileArn(userConfig config.UserConfig, alias string) string {
	for arn, name := range userConfig.ProfileMap {
		if name == alias {
			return arn
		}
	}
	return ""
}

// reportSavedProfiles prints which saved profiles got credentials and which
// did not (role not in the SAML assertion, or STS rejected it).
func reportSavedProfiles(runtimeContext config.RuntimeContext, credentials []aws.AwsCredentials) {
	got := make(map[string]bool, len(credentials))
	for _, c := range credentials {
		got[c.RoleArn] = true
	}
	var saved, missing []string
	for arn, name := range runtimeContext.UserConfig.ProfileMap {
		if got[arn] {
			saved = append(saved, name)
		} else {
			missing = append(missing, name)
		}
	}
	sort.Strings(saved)
	sort.Strings(missing)
	fmt.Printf("Saved %d profile(s): %s\n", len(saved), strings.Join(saved, ", "))
	if len(missing) > 0 {
		fmt.Printf("Not saved (not granted or STS failed): %s\n", strings.Join(missing, ", "))
	}
}

func assumeRole(runtimeContext config.RuntimeContext) error {
	// Get the role ARN from the config file
	if len(runtimeContext.Params.ExtraArgs) != 1 {
		return fmt.Errorf("No role alias provided")
	}

	var roleAlias = runtimeContext.Params.ExtraArgs[0]
	var err error
	var ok bool

	assumableProfileMap, ok := runtimeContext.UserConfig.AssumableRolesMap[roleAlias]
	if !ok {
		return fmt.Errorf("No role with the alias %s found!\n", roleAlias)
	}

	roleArn, ok := assumableProfileMap["arn"]
	if !ok {
		return fmt.Errorf("No arn for assumable role %s found!\n", roleAlias)
	}
	requiredProfile, hasRequiredProfile := assumableProfileMap["required_profile"]

	if hasRequiredProfile {
		fmt.Printf("Using required profile %s\n", requiredProfile)
		err = switchRoles(runtimeContext, requiredProfile)
		if err != nil {
			return fmt.Errorf("Error switching to required profile %s: %v\n", requiredProfile, err)
		}
	}
	credentials, err := aws.AssumeRole(runtimeContext, roleArn)
	if err != nil {
		return err
	}
	fmt.Printf("Assuming role %s\n", roleAlias)
	aws.AddAwsCredentialsAssumedRole(runtimeContext, roleAlias, credentials)
	return nil
}

func listRoles(runtimeContext config.RuntimeContext) error {
	// `list` only needs the entitlements in the SAML assertion — STS roundtrips
	// for every role are wasted work. Get the assertion, parse, print.
	samlAssertion, err := getSamlAssertion(runtimeContext)
	if err != nil {
		return err
	}
	roleArns, err := aws.ListRoleArnsFromSaml(samlAssertion)
	if err != nil {
		return err
	}
	fmt.Printf("\nYour available roles:\n")
	for _, arn := range roleArns {
		fmt.Printf("%s\n", arn)
	}
	return nil
}

// getSamlAssertion returns the raw SAML XML for the current auth mode,
// without doing any STS work.
func getSamlAssertion(runtimeContext config.RuntimeContext) (string, error) {
	if runtimeContext.Params.Passkey != nil && *runtimeContext.Params.Passkey {
		return okta.GetSamlAssertionViaBrowser(runtimeContext)
	}

	userCredentials := promptUserCredentials(runtimeContext)
	client := createHttpClient()
	sess := &okta.Sess{}

	okta.InitializeSession(runtimeContext, client, sess)
	okta.Introspect(runtimeContext, client, sess)
	okta.GetNonce(runtimeContext, client, sess)

	mfaOptions, err := getMfaOptions(runtimeContext, sess, client, userCredentials)
	if err != nil {
		return "", err
	}
	userMfaOption, err := okta.GetUserMfaOption(&runtimeContext, mfaOptions)
	if err != nil {
		return "", err
	}
	if _, err = okta.Challenge(runtimeContext, client, sess, userMfaOption); err != nil {
		return "", err
	}
	if err = okta.ChallengePoll(runtimeContext, client, sess); err != nil {
		return "", err
	}
	redirect, err := okta.KeepMeSignedIn(runtimeContext, client, sess)
	if err != nil {
		return "", err
	}
	return okta.GetSamlAssertion(runtimeContext, client, redirect)
}

func listRoleMap(runtimeContext config.RuntimeContext) error {
	var keysSorted = make([]string, 0, len(runtimeContext.UserConfig.ProfileMap))
	for key, _ := range runtimeContext.UserConfig.ProfileMap {
		keysSorted = append(keysSorted, key)
	}
	sort.Strings(keysSorted)
	for _, key := range keysSorted {
		value := runtimeContext.UserConfig.ProfileMap[key]
		fmt.Printf("%s -> %s\n", key, value)
	}
	return nil
}

func showConfigJson(runtimeContext config.RuntimeContext) error {
	configData, err := json.MarshalIndent(runtimeContext.UserConfig, "", "   ")
	if err != nil {
		return err
	}
	// Path goes to stderr so stdout stays pure JSON for `aws-login --show-config | jq`
	// (the shell completion scripts rely on that).
	fmt.Fprintf(os.Stderr, "Config file: %s\n", *config.GetConfigFileName(nil))
	fmt.Printf("%s\n", configData)

	return nil
}

func switchRoles(runtimeContext config.RuntimeContext, newRoleName string) error {
	awsCredentialsFile, err := aws.GetAwsCredentialsFile()
	if err != nil {
		fmt.Printf("Error reading aws config file: %v", err)
		return err
	}
	ini.DEFAULT_SECTION = uuid.New().String()
	ini.DefaultSection = uuid.New().String()

	newDefault, err := awsCredentialsFile.GetSection(newRoleName)

	if err != nil {
		return fmt.Errorf("No role with the name %s found!\n", newRoleName)
	}
	fmt.Printf("Switching to role %s\n", newRoleName)

	newAccessKey := newDefault.Key("aws_access_key_id").Value()
	newSecretAccessKey := newDefault.Key("aws_secret_access_key").Value()
	newSessionToken := newDefault.Key("aws_session_token").Value()

	defaultSection := awsCredentialsFile.Section("default")
	defaultSection.Key("aws_access_key_id").SetValue(newAccessKey)
	defaultSection.Key("aws_secret_access_key").SetValue(newSecretAccessKey)
	defaultSection.Key("aws_session_token").SetValue(newSessionToken)

	err = awsCredentialsFile.SaveTo(aws.AwsCredentialsFileName())
	return err
}

func promptUserCredentials(runtimeContext config.RuntimeContext) okta.UserCredentials {
	reader := bufio.NewReader(os.Stdin)

	var username string
	if runtimeContext.UserConfig.Username == nil {
		fmt.Print("Enter Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.ReplaceAll(username, "\n", "")
		username = strings.ReplaceAll(username, "\r", "")
	} else {
		fmt.Printf("Using username %s\n", *runtimeContext.UserConfig.Username)
		username = *runtimeContext.UserConfig.Username
	}

	// Try to get password from keyring
	var password string
	password = credential.GetPassword(username)

	// If password not found in keyring or the user has overridden the keyring, prompt for it
	if password == "" || *runtimeContext.Params.Keyring == false {
		if *runtimeContext.Params.Verbose {
			fmt.Printf("Could not find a password in the keyring for %s\n", credential.ServiceName)
		}
		fmt.Print("Enter Password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		password = string(bytePassword)
		fmt.Printf("\n")
	} else {
		fmt.Println("Using password from system keyring.")
	}

	// Return credentials for authentication
	return okta.UserCredentials{
		Username: username,
		Password: password,
	}
}

func configurePasskey(runtimeContext config.RuntimeContext) error {
	return okta.RegisterPasskey(runtimeContext)
}

func forgetPasskey(runtimeContext config.RuntimeContext) error {
	if credential.GetPasskeyCredential() == nil {
		fmt.Println("No stored passkey credential found.")
		return nil
	}
	if err := credential.DeletePasskeyCredential(); err != nil {
		return fmt.Errorf("delete passkey credential: %w", err)
	}
	fmt.Println("Stored passkey credential removed from OS keyring.")
	return nil
}

func configureKeyring(runtimeContext config.RuntimeContext) error {
	matched := false

	var username string
	var password1 string
	var password2 string

	fmt.Print("Enter Username: ")
	reader := bufio.NewReader(os.Stdin)
	username, _ = reader.ReadString('\n')
	username = strings.ReplaceAll(username, "\n", "")
	username = strings.ReplaceAll(username, "\r", "")

	for !matched {
		fmt.Print("Enter Password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		password1 = string(bytePassword)
		fmt.Printf("\n")

		fmt.Print("Enter Password Again: ")
		bytePassword, _ = term.ReadPassword(int(syscall.Stdin))
		password2 = string(bytePassword)
		fmt.Printf("\n")

		if password1 == password2 {
			matched = true
		} else {
			fmt.Println("Passwords do not match. Please try again.")
		}
	}

	err := credential.StorePassword(username, password1)
	return err
}

func generateAutocomplete(runtimeContext config.RuntimeContext) error {
	if *runtimeContext.Params.AutoCompletion == "bash" {
		fmt.Print(generateAutocompleteBash(runtimeContext))
	} else if *runtimeContext.Params.AutoCompletion == "zsh" {
		fmt.Print(generateAutocompleteZsh(runtimeContext))
	} else {
		return fmt.Errorf("Unknown autocomplete type %s\n", *runtimeContext.Params.AutoCompletion)
	}
	return nil
}

func generateAutocompleteBash(runtimeContext config.RuntimeContext) string {
	return `
# Bash completion script for aws-login
_aws_login_completions() {
	local cur prev opts profiles
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="login login_all list list-role-map switch assume configure_keyring configure_passkey forget_passkey"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--autocomplete --help --version --show-config --passkey --headed --keyring=false -v -t -d -h" -- ${cur}) )
        return 0
	fi

  case "${prev}" in
    	login|switch)
			# Fetch profiles dynamically from aws-login --show-config
			profiles=$(aws-login --show-config | jq -r '.profile_map[]')
			COMPREPLY=( $(compgen -W "${profiles}" -- ${cur}) )
			return 0
		;;
    esac

    if [[ "${prev}" == "assume" ]]; then
		# Fetch assumable roles
        profiles=$(aws-login --show-config | jq -r '.assumable_roles // {} | keys[]')
        COMPREPLY=( $(compgen -W "${profiles}" -- ${cur}) )
        return 0
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _aws_login_completions aws-login
`
}
func generateAutocompleteZsh(runtimeContext config.RuntimeContext) string {
	return `
# Zsh completion script for aws-login
_aws_login_completions() {
    local -a commands
    commands=(
        "login:Login to all saved profiles (optionally set default)"
        "login_all:Login to all saved profiles"
        "list:List available roles"
        "list-role-map:List role map"
        "switch:Switch roles"
        "assume:Assume a role"
        "configure_keyring:Configure OS keyring"
        "configure_passkey:Enroll a passkey for unattended logins"
        "forget_passkey:Remove the stored passkey"
    )

	case "${words[2]}" in
		login|switch)
			# Fetch profiles dynamically from aws-login show-config
			local profiles
			profiles=($(aws-login --show-config | jq -r '.profile_map[]'))
			_describe 'profiles' profiles
			return
		;;
	esac

	if [[ "$words[2]" == "assume" ]]; then
		# Fetch assumable roles
		local profiles
		profiles=($(aws-login --show-config | jq -r '.assumable_roles // {} | keys[]'))
		_describe 'profiles' profiles
		return
	fi

    _describe 'commands' commands
}
compdef _aws_login_completions aws-login
`
}

func getDefaultLoginCredentials(runtimeContext config.RuntimeContext, credentials []aws.AwsCredentials) *aws.AwsCredentials {
	//
	// If the user provided an alias we need to find the ARN associated with it and find the credential that matches.
	//
	if len(runtimeContext.Params.ExtraArgs) == 0 {
		return nil
	}
	requestedLogin := runtimeContext.Params.ExtraArgs[0]
	if *runtimeContext.Params.Verbose {
		fmt.Printf("Requested login: %s\n", requestedLogin)
	}
	arn := profileArn(runtimeContext.UserConfig, requestedLogin)
	if arn == "" {
		return nil
	}
	for i := range credentials {
		if credentials[i].RoleArn == arn {
			return &credentials[i]
		}
	}
	return nil
}
