package okta

import (
	"aws-login/config"
	"testing"
)

const EXPECTED_TOKEN = `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0-unit-test-only_not-a-real-token.ZmFrZS10YWc`

func createEmptyContext() *config.RuntimeContext {
	verbose := true
	runtimeContext := &config.RuntimeContext{
		Params: config.Params{
			Verbose: &verbose,
		},
	}
	return runtimeContext
}

func TestParseStateTokenFromBodyNoBody(t *testing.T) {
	// Mock runtime context
	runtimeContext := createEmptyContext()

	_, err := parseStateTokenFromBody(*runtimeContext, "")

	if err == nil {
		t.Errorf("Error should be found getting stateToken")
		return
	}

	if err.Error() != "No stateToken found in body" {
		t.Errorf("Wrong error found getting stateToken: %s", err.Error())
	}
}
func TestParseStateTokenFromBodyNoMatches(t *testing.T) {
	// Mock runtime context
	runtimeContext := createEmptyContext()

	_, err := parseStateTokenFromBody(*runtimeContext, "kdflaksdjflaksdjflaksjfa;sl")

	if err == nil {
		t.Errorf("Error should be found getting stateToken")
		return
	}
	if err.Error() != "No stateToken found in body" {
		t.Errorf("Wrong error found getting stateToken: %s", err.Error())
	}
}

func testStateToken(t *testing.T, body string, expectedStateToken string) {
	// Mock runtime context
	runtimeContext := createEmptyContext()

	token, err := parseStateTokenFromBody(*runtimeContext, body)

	if err != nil {
		t.Errorf("Could not find the stateToken in body.")
		return
	}

	if token != expectedStateToken {
		t.Errorf("stateToken incorrect")
		t.Errorf("Expected: %s", expectedStateToken)
		t.Errorf("Found:    %s", token)
		return
	}
}

func TestParseStateTokenFromBodyOneMatchReal(t *testing.T) {
	// Mock runtime context
	body := `
		(function(){
		  var baseUrl = 'https\x3A\x2F\x2Flogin.harvard.edu';
		  var suppliedRedirectUri = '';
		  var repost = false;
		  var stateToken = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0-unit\x2Dtest-only_not\x2Da-real-token.ZmFrZS10YWc';
		  var fromUri = '\x2Fapp\x2Fharvard_awsconsole_1\x2Fexk1u9wgsl2oD1XWo1d8\x2Fsso\x2Fsaml';
		  var username = '';
		  var rememberMe = true;
	`

	testStateToken(t, body, EXPECTED_TOKEN)
}
func TestParseStateTokenFromBodyMultipleMatchReal(t *testing.T) {
	// Mock runtime context
	body := `
		(function(){
		  var baseUrl = 'https\x3A\x2F\x2Flogin.harvard.edu';
		  var suppliedRedirectUri = '';
		  var repost = false;
		  var stateToken = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0-unit\x2Dtest-only_not\x2Da-real-token.ZmFrZS10YWc';
          var stateTokens = "something else"
		  var fromUri = '\x2Fapp\x2Fharvard_awsconsole_1\x2Fexk1u9wgsl2oD1XWo1d8\x2Fsso\x2Fsaml';
		  var username = '';
		  var rememberMe = true;
	`

	testStateToken(t, body, EXPECTED_TOKEN)
}
func TestParseStateTokenFromBodyMultipleMatchDoubleQuotes(t *testing.T) {
	// Mock runtime context
	body := `
		(function(){
		  var baseUrl = 'https\x3A\x2F\x2Flogin.harvard.edu';
		  var suppliedRedirectUri = '';
		  var repost = false;
		  var stateToken = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0-unit\x2Dtest-only_not\x2Da-real-token.ZmFrZS10YWc";
          var stateTokens = "something else"
		  var fromUri = '\x2Fapp\x2Fharvard_awsconsole_1\x2Fexk1u9wgsl2oD1XWo1d8\x2Fsso\x2Fsaml';
		  var username = '';
		  var rememberMe = true;
	`

	testStateToken(t, body, EXPECTED_TOKEN)
}
func TestParseStateTokenFromBodyMultipleMatchLet(t *testing.T) {
	// Mock runtime context
	body := `
		(function(){
		  var baseUrl = 'https\x3A\x2F\x2Flogin.harvard.edu';
		  var suppliedRedirectUri = '';
		  var repost = false;
		  let stateToken = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0\x2Dunit\x2Dtest\x2Donly_not\x2Da\x2Dreal\x2Dtoken.ZmFrZS10YWc";
          var stateTokens = "something else"
		  var fromUri = '\x2Fapp\x2Fharvard_awsconsole_1\x2Fexk1u9wgsl2oD1XWo1d8\x2Fsso\x2Fsaml';
		  var username = '';
		  var rememberMe = true;
	`

	testStateToken(t, body, EXPECTED_TOKEN)
}
func TestParseStateTokenFromBodyMultipleDiffOrder(t *testing.T) {
	// Mock runtime context
	body := `
		(function(){
		  var baseUrl = 'https\x3A\x2F\x2Flogin.harvard.edu';
		  var suppliedRedirectUri = '';
		  var repost = false;
          var stateTokens="something else"
		  var stateToken="eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZmFrZS1pdg.ZmFrZS1jaXBoZXJ0ZXh0\x2Dunit\x2Dtest\x2Donly_not\x2Da\x2Dreal\x2Dtoken.ZmFrZS10YWc";
		  var fromUri = '\x2Fapp\x2Fharvard_awsconsole_1\x2Fexk1u9wgsl2oD1XWo1d8\x2Fsso\x2Fsaml';
		  var username = '';
		  var rememberMe = true;
	`

	testStateToken(t, body, EXPECTED_TOKEN)
}
