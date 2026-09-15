package aws

import (
	cfg "aws-login/config"
	"encoding/base64"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/net/context"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultSessionDurationSecs is the duration we REQUEST when nothing overrides
// it. Set greedily to 8h: AssumeRoleWithSAML never reveals a role's
// MaxSessionDuration, so the only way to land the longest valid session is to
// ask high and let assumeRoleWithFallback step down on rejection. Roles whose
// max is lower (e.g. 4h) auto-fall-back; roles allowing 8h get the full 8h.
const defaultSessionDurationSecs = 8 * 60 * 60 // 8 hours

// durationFallbackLadder lists session durations (seconds), high → low, that we
// step down through when STS rejects a request for exceeding a role's
// MaxSessionDuration. Tuned to the common HUIT maxes (12h/8h/4h/1h) so a typical
// 4h role costs at most one extra STS call (8h → 4h).
var durationFallbackLadder = []int32{12 * 3600, 8 * 3600, 4 * 3600, 3600}

// Maximum concurrent AssumeRoleWithSAML calls. STS handles bursts fine; ~10
// keeps login latency roughly constant in #entitlements.
const stsConcurrency = 10

type AwsCredentials struct {
	RoleArn         string
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      *time.Time
}

type Entitlement struct {
	PrincipalArn string
	RoleArn      string
}

// For sorting.
type ByRoleArn []AwsCredentials

func (a ByRoleArn) Len() int {
	return len(a)
}
func (a ByRoleArn) Less(i, j int) bool {
	aRoleName := strings.Split(a[i].RoleArn, "/")
	bRoleName := strings.Split(a[j].RoleArn, "/")

	if len(aRoleName) != 2 || len(bRoleName) != 2 {
		return a[i].RoleArn < a[j].RoleArn
	}

	return aRoleName[1] < bRoleName[1]
}
func (a ByRoleArn) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func GetAwsCredentials(runtimeContext cfg.RuntimeContext, samlAssertion string) ([]AwsCredentials, error) {
	entitlements, err := getEntitlementsFromSaml(samlAssertion)
	var awsCredentials []AwsCredentials

	if err != nil {
		return awsCredentials, err
	}

	// Only saved profiles get written, so skip STS for entitled roles that
	// aren't in profile_map.
	if len(runtimeContext.UserConfig.ProfileMap) > 0 {
		mapped := entitlements[:0]
		for _, ent := range entitlements {
			if _, ok := runtimeContext.UserConfig.ProfileMap[ent.RoleArn]; ok {
				mapped = append(mapped, ent)
			}
		}
		entitlements = mapped
	}

	aws_cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return awsCredentials, fmt.Errorf("load AWS SDK config: %w", err)
	}
	client := sts.NewFromConfig(aws_cfg)

	// Define the SAML assertion and role ARN
	samlAssertionBase64 := base64.StdEncoding.EncodeToString([]byte(samlAssertion))

	// Fan out STS calls across stsConcurrency workers. Each worker resolves
	// its own per-role timeout and calls AssumeRoleWithSAML. Results are
	// gathered through a single mutex-guarded slice.
	verbose := *runtimeContext.Params.Verbose
	sem := make(chan struct{}, stsConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ent := range entitlements {
		ent := ent
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if verbose {
				fmt.Printf(" - Fetching credentials for %s\n", ent.RoleArn)
			}

			timeoutSeconds := resolveRoleTimeout(runtimeContext, ent.RoleArn)
			params := &sts.AssumeRoleWithSAMLInput{
				RoleArn:       aws.String(ent.RoleArn),
				PrincipalArn:  aws.String(ent.PrincipalArn),
				SAMLAssertion: aws.String(samlAssertionBase64),
			}
			output, callErr := assumeRoleWithFallback(client, params, *timeoutSeconds, verbose)
			if callErr != nil {
				fmt.Printf("Warning: failed to assume role: %s - %s\n", ent.RoleArn, callErr.Error())
				return
			}
			mu.Lock()
			awsCredentials = append(awsCredentials, AwsCredentials{
				RoleArn:         ent.RoleArn,
				AccessKeyId:     *output.Credentials.AccessKeyId,
				SecretAccessKey: *output.Credentials.SecretAccessKey,
				SessionToken:    *output.Credentials.SessionToken,
				Expiration:      output.Credentials.Expiration,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Sort the results before returning.
	sort.Sort(ByRoleArn(awsCredentials))

	return awsCredentials, nil
}

// resolveRoleTimeout applies the documented priority chain:
// CLI -t > per-role config > default config > built-in default (8h).
func resolveRoleTimeout(runtimeContext cfg.RuntimeContext, roleArn string) *int32 {
	if runtimeContext.Params.Timeout != nil && *runtimeContext.Params.Timeout > 0 {
		v := int32(*runtimeContext.Params.Timeout)
		return &v
	}
	if alias, ok := runtimeContext.UserConfig.ProfileMap[roleArn]; ok {
		if secs, ok := runtimeContext.UserConfig.RoleTimeoutSecs[alias]; ok {
			v := int32(secs)
			return &v
		}
	}
	if runtimeContext.UserConfig.DefaultTimeoutSecs != nil {
		v := int32(*runtimeContext.UserConfig.DefaultTimeoutSecs)
		return &v
	}
	v := int32(defaultSessionDurationSecs)
	return &v
}

// assumeRoleWithFallback calls AssumeRoleWithSAML starting at `desired` seconds
// and, when STS rejects the request for exceeding the role's MaxSessionDuration,
// retries with progressively shorter durations from durationFallbackLadder until
// one is accepted (or the ladder below `desired` is exhausted). This lets a mixed
// fleet — some roles capped at 4h, some at 8h — each get the longest session it
// permits without any per-role config. The requested `desired` is treated as an
// upper bound: we only ever step DOWN, never above what was asked for.
func assumeRoleWithFallback(client *sts.Client, base *sts.AssumeRoleWithSAMLInput, desired int32, verbose bool) (*sts.AssumeRoleWithSAMLOutput, error) {
	attempt := desired
	tried := make(map[int32]bool)
	for {
		in := *base
		in.DurationSeconds = aws.Int32(attempt)
		out, err := client.AssumeRoleWithSAML(context.Background(), &in)
		if err == nil {
			return out, nil
		}
		if !isMaxSessionDurationError(err) {
			return nil, err
		}
		tried[attempt] = true
		next := nextLowerDuration(attempt, tried)
		if next == 0 {
			return nil, err
		}
		if verbose {
			fmt.Printf("   %s rejected %ds (exceeds role max session); retrying at %ds\n", *base.RoleArn, attempt, next)
		}
		attempt = next
	}
}

// isMaxSessionDurationError reports whether an STS error is the "requested
// DurationSeconds exceeds the MaxSessionDuration set for this role" validation
// error. The SDK surfaces no typed error for this, so we match the message.
func isMaxSessionDurationError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "MaxSessionDuration")
}

// nextLowerDuration returns the largest ladder value strictly less than current
// that has not yet been tried, or 0 when the ladder below current is exhausted.
func nextLowerDuration(current int32, tried map[int32]bool) int32 {
	var best int32
	for _, d := range durationFallbackLadder {
		if d < current && !tried[d] && d > best {
			best = d
		}
	}
	return best
}

// ListRoleArnsFromSaml returns the role ARNs entitled by the SAML assertion
// without calling STS — used by the `list` command for a fast preview.
func ListRoleArnsFromSaml(samlAssertion string) ([]string, error) {
	ents, err := getEntitlementsFromSaml(samlAssertion)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.RoleArn)
	}
	sort.Strings(out)
	return out, nil
}

// Parse the SAML assertion (XML) and extract the entitlements
func getEntitlementsFromSaml(samlAssertion string) ([]Entitlement, error) {
	doc, err := xmlquery.Parse(strings.NewReader(samlAssertion))
	if err != nil {
		return nil, err
	}

	var entitlements []Entitlement

	var query string
	query = "//saml2:Attribute[@Name=\"https://aws.amazon.com/SAML/Attributes/Role\"]/saml2:AttributeValue"
	nodes := xmlquery.Find(doc, query)

	//fmt.Println("Roles:")
	for _, node := range nodes {
		toks := strings.Split(strings.TrimSpace(node.InnerText()), ",")
		//fmt.Printf(" - %+v --- %v\n", toks[0], toks[1])
		entitlements = append(entitlements, Entitlement{
			PrincipalArn: toks[0],
			RoleArn:      toks[1],
		})
	}

	return entitlements, nil
}

func AssumeRole(runtimeContext cfg.RuntimeContext, roleArn string) (*AwsCredentials, error) {
	var err error

	aws_cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	client := sts.NewFromConfig(aws_cfg)

	// Assume a role - the session name seems to be informational
	sessionName := "aws-login-saml-cli"
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	}

	role, err := client.AssumeRole(context.Background(), input)
	if err != nil {
		return nil, err
	}

	aws_credentials := AwsCredentials{
		RoleArn:         roleArn,
		AccessKeyId:     *role.Credentials.AccessKeyId,
		SecretAccessKey: *role.Credentials.SecretAccessKey,
		SessionToken:    *role.Credentials.SessionToken,
	}

	return &aws_credentials, nil
}
