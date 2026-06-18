package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	akeyless "github.com/akeylesslabs/akeyless-go/v2"
	flags "github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora/v4"
	"github.com/vito/twentythousandtonnesofcrudeoil"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	Token             string `short:"t" long:"token" description:"Akeyless token" required:"false"`
	ApiGatewayUrl     string `short:"u" long:"api-gateway-url" description:"Akeyless API Gateway URL used to list gateways" required:"false" default:"https://api.akeyless.io"`
	GatewayNameFilter string `short:"g" long:"gateway-name-filter" description:"Only inspect gateways whose name starts with this value" required:"false"`
	Kubeconfig        string `short:"k" long:"kubeconfig" description:"Path to the kubeconfig file (overrides the KUBECONFIG env var and the default ~/.kube/config)" required:"false"`
	Context           string `short:"c" long:"context" description:"kubeconfig context to validate (defaults to the current-context)" required:"false"`
	Output            string `short:"o" long:"output" description:"Output format: text or json" required:"false" default:"text"`
	Verbose           bool   `short:"V" long:"verbose" description:"Show verbose debug information (on stderr)"`
	Version           bool   `short:"v" long:"version" description:"Print the version number and exit" required:"false"`
}

// Build-time variables set via -ldflags.
var version string
var commit string
var date string

var timeout = 30 * time.Second

const GATEWAY_RUNNING_STATUS = "Running"
const EXIT_CODE_SUCCESS = 0
const EXIT_CODE_ERROR = 1

const (
	verdictPass    = "pass"
	verdictFail    = "fail"
	verdictNoMatch = "no-match"
)

// tokenNotSetMessage is the single source of truth for the missing-token error.
// It is surfaced both as the fail-fast guard in main and as the library
// precondition in retrieveListOfGatewaysUsingToken.
const tokenNotSetMessage = "Akeyless token is not set. Please set the token using the -t or --token flag or set the AKEYLESS_TOKEN environment variable"

var options Options

func main() {
	parser := flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash)
	parser.NamespaceDelimiter = "-"
	twentythousandtonnesofcrudeoil.TheEnvironmentIsPerfectlySafe(parser, "AKEYLESS_")

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			fmt.Println(err)
			os.Exit(EXIT_CODE_SUCCESS)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(EXIT_CODE_ERROR)
	}

	if options.Version {
		fmt.Println("Version:", version)
		fmt.Println("Commit:", commit)
		fmt.Println("Date:", date)
		os.Exit(EXIT_CODE_SUCCESS)
	}

	if options.Output != "text" && options.Output != "json" {
		fatal("invalid --output value " + options.Output + " (want text or json)")
	}
	if options.Token == "" {
		fatal(tokenNotSetMessage)
	}
	if options.ApiGatewayUrl == "" {
		fatal("Akeyless API Gateway URL is not set")
	}

	// Resolve the Kubernetes cluster the user is currently pointed at. This is
	// the cluster we validate the Akeyless k8s auth configuration against.
	kube, err := loadKubeContext(options)
	if err != nil {
		fatal("loading kubeconfig: " + err.Error())
	}
	debugf("kubernetes API server CA (base64): %s", base64.StdEncoding.EncodeToString(kube.caPEM))

	// Discover every gateway registered to this account.
	saasAPI := newGatewayAPI(options.ApiGatewayUrl)
	gwList, err := retrieveListOfGatewaysUsingToken(saasAPI, options.Token)
	if err != nil {
		fatal(err.Error())
	}

	rep := runValidation(kube, gwList)

	if options.Output == "json" {
		renderJSON(rep)
	} else {
		renderText(rep)
	}

	if rep.Verdict != verdictPass {
		os.Exit(EXIT_CODE_ERROR)
	}
}

// tokenReviewResult is the outcome of submitting a reviewer JWT to the cluster.
type tokenReviewResult struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	Error         string `json:"error,omitempty"`
}

// configResult is the per-config validation outcome.
type configResult struct {
	Gateway     string             `json:"gateway"`
	Config      string             `json:"config"`
	AccessID    string             `json:"access_id,omitempty"`
	K8sHost     string             `json:"k8s_host,omitempty"`
	CAMatch     bool               `json:"ca_match"`
	TokenReview *tokenReviewResult `json:"token_review,omitempty"`
	Error       string             `json:"error,omitempty"`
	Valid       bool               `json:"valid"`
}

// configRef identifies a k8s auth config by the gateway it lives on.
type configRef struct {
	Gateway string `json:"gateway"`
	Config  string `json:"config"`
}

// report is the full validation result, shared by both renderers and emitted
// verbatim as the JSON integration contract.
type report struct {
	Context    string         `json:"context"`
	Cluster    string         `json:"cluster"`
	Server     string         `json:"server"`
	Matched    []configResult `json:"matched"`
	LocalCAJwt []configRef    `json:"local_ca_jwt,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Verdict    string         `json:"verdict"`
}

func (r report) failedCount() int {
	n := 0
	for _, m := range r.Matched {
		if !m.Valid {
			n++
		}
	}
	return n
}

// runValidation is the single source of validation logic. It correlates each
// gateway's k8s auth configs to the current cluster by CA certificate and, for
// matches, performs a live TokenReview. It returns a structured report; it does
// not print, so both the text and JSON renderers consume the same result.
func runValidation(kube kubeTarget, gwList akeyless.GatewaysListResponse) report {
	// Matched is initialized (not nil) so it always marshals as a JSON array,
	// never null, keeping the integration contract simple for consumers.
	rep := report{Context: kube.contextName, Cluster: kube.clusterName, Server: kube.server, Matched: []configResult{}}
	if len(kube.caPEM) == 0 {
		rep.Warnings = append(rep.Warnings, "current context has no CA certificate data; cannot correlate gateway configs to this cluster by CA")
	}

	for _, gateway := range gwList.GetClusters() {
		name := usableGatewayName(gateway)

		if gateway.GetStatus() != GATEWAY_RUNNING_STATUS {
			debugf("skipping gateway %q (status %s)", name, gateway.GetStatus())
			continue
		}
		if !gatewayMatchesFilter(name, options.GatewayNameFilter) {
			debugf("skipping gateway %q (name filter)", name)
			continue
		}
		clusterURL, ok := gateway.GetClusterUrlOk()
		if !ok || *clusterURL == "" {
			debugf("skipping gateway %q (no cluster URL)", name)
			continue
		}

		// Normalize the gateway base URL once. The gateway serves its /config
		// REST endpoints at the root and the Akeyless v2 API methods under the
		// /api/v2 prefix (the SaaS serves the v2 methods at the root instead).
		gatewayBase := strings.TrimRight(*clusterURL, "/")

		// The unified gateway summarizes /config/k8s-auths (names only), so we
		// enumerate names here and fetch the full detail per config below.
		authNames, err := listK8sAuthConfigNames(gatewayBase, options.Token)
		if err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("skipping gateway %q (%s): %v", name, *clusterURL, err))
			continue
		}
		debugf("gateway %q has %d k8s auth config(s): %v", name, len(authNames), authNames)

		gwAPI := newGatewayAPI(gatewayBase + "/api/v2")
		// A gateway runs in exactly one cluster. We only treat its local-CA-JWT
		// configs as relevant to the current cluster once another config on the
		// same gateway has been CA-matched to it, which proves co-location.
		gatewayMatched := false
		var gatewayLocalCAConfigs []string
		for _, authName := range authNames {
			detail, err := getK8sAuthConfigDetail(gwAPI, options.Token, authName)
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("could not read k8s auth config %q on %q: %v", authName, name, err))
				continue
			}

			if detail.GetUseLocalCaJwt() {
				gatewayLocalCAConfigs = append(gatewayLocalCAConfigs, authName)
				continue
			}

			if !caCertMatches(detail.GetK8sCaCert(), kube.caPEM) {
				debugf("config %q CA does not match current cluster; skipping", authName)
				continue
			}

			res := configResult{
				Gateway:  name,
				Config:   detail.GetName(),
				AccessID: detail.GetAuthMethodAccessId(),
				K8sHost:  detail.GetK8sHost(),
				CAMatch:  true,
			}
			gatewayMatched = true

			switch {
			case detail.GetK8sTokenReviewerJwt() == "":
				res.Error = "token reviewer JWT not set on this config; cannot validate TokenReview"
			default:
				review, err := reviewToken(kube.restConfig, detail.GetK8sTokenReviewerJwt())
				if err != nil {
					res.TokenReview = &tokenReviewResult{Error: fmt.Sprintf("TokenReview request failed: %v", err)}
				} else if review.Status.Authenticated {
					res.TokenReview = &tokenReviewResult{Authenticated: true, Username: review.Status.User.Username}
					res.Valid = true
				} else {
					msg := review.Status.Error
					if msg == "" {
						msg = "not authenticated"
					}
					res.TokenReview = &tokenReviewResult{Error: msg}
				}
			}
			rep.Matched = append(rep.Matched, res)
		}

		// Only surface this gateway's local-CA-JWT configs if the gateway was
		// confirmed (by CA match) to serve the current cluster.
		if gatewayMatched {
			for _, c := range gatewayLocalCAConfigs {
				rep.LocalCAJwt = append(rep.LocalCAJwt, configRef{Gateway: name, Config: c})
			}
		} else if len(gatewayLocalCAConfigs) > 0 {
			debugf("gateway %q has %d local-CA-JWT config(s) but no config matching the current cluster; not reporting", name, len(gatewayLocalCAConfigs))
		}
	}

	switch {
	case len(rep.Matched) == 0:
		rep.Verdict = verdictNoMatch
	case rep.failedCount() > 0:
		rep.Verdict = verdictFail
	default:
		rep.Verdict = verdictPass
	}
	return rep
}

func renderJSON(rep report) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
		os.Exit(EXIT_CODE_ERROR)
	}
}

func renderText(rep report) {
	fmt.Println("Context:", aurora.BrightGreen(rep.Context))
	fmt.Println("Cluster:", aurora.BrightGreen(rep.Cluster))
	fmt.Println("API server:", aurora.BrightGreen(rep.Server))
	if options.GatewayNameFilter != "" {
		fmt.Println("Gateway name filter:", aurora.BrightCyan(options.GatewayNameFilter))
	}
	fmt.Println("Listing gateways via:", aurora.BrightCyan(options.ApiGatewayUrl))
	for _, w := range rep.Warnings {
		fmt.Println(aurora.BrightYellow("Warning: " + w))
	}

	for _, m := range rep.Matched {
		fmt.Println()
		fmt.Println("Matched gateway:", aurora.BrightGreen(m.Gateway))
		fmt.Println("  K8S auth config name:", aurora.BrightGreen(m.Config))
		fmt.Println("  Auth method access ID:", aurora.BrightGreen(m.AccessID))
		fmt.Println("  Configured k8s host:", aurora.BrightGreen(m.K8sHost))
		fmt.Println("  CA certificate:", aurora.BrightGreen("matches current cluster"))
		switch {
		case m.Error != "":
			fmt.Println("  Token reviewer JWT:", aurora.BrightRed(m.Error))
		case m.TokenReview == nil:
			fmt.Println("  Token reviewer JWT:", aurora.BrightRed("not validated"))
		case m.TokenReview.Authenticated:
			fmt.Println("  Token reviewer JWT:", aurora.BrightGreen("valid, authenticated as "+m.TokenReview.Username))
		default:
			fmt.Println("  Token reviewer JWT:", aurora.BrightRed(m.TokenReview.Error))
		}
	}

	fmt.Println()
	if len(rep.LocalCAJwt) > 0 {
		fmt.Println(aurora.BrightCyan("The following k8s auth config(s) use local CA JWT (the gateway's own in-cluster"))
		fmt.Println(aurora.BrightCyan("service account) and cannot be validated from outside the cluster:"))
		for _, c := range rep.LocalCAJwt {
			fmt.Printf("  - %s (gateway %q)\n", c.Config, c.Gateway)
		}
		fmt.Println()
	}

	switch rep.Verdict {
	case verdictNoMatch:
		printErrorMessages(rep.Server, "No Akeyless k8s auth config has a CA certificate matching your current cluster:")
	case verdictFail:
		printErrorMessages("", fmt.Sprintf("%d of %d matching k8s auth config(s) failed validation", rep.failedCount(), len(rep.Matched)))
	default:
		fmt.Println(aurora.BrightGreen(fmt.Sprintf("All %d matching k8s auth config(s) validated successfully.", len(rep.Matched))))
	}
}

// kubeTarget holds everything we need about the cluster being validated.
type kubeTarget struct {
	contextName string
	clusterName string
	server      string
	caPEM       []byte
	restConfig  *rest.Config
}

// loadKubeContext resolves the kubeconfig honoring, in order: the --kubeconfig
// flag, the KUBECONFIG environment variable, then the default ~/.kube/config.
// The --context flag overrides the current-context.
func loadKubeContext(opts Options) (kubeTarget, error) {
	var kt kubeTarget

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		rules.ExplicitPath = opts.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	raw, err := clientConfig.RawConfig()
	if err != nil {
		return kt, err
	}

	kt.contextName = opts.Context
	if kt.contextName == "" {
		kt.contextName = raw.CurrentContext
	}
	if kt.contextName == "" {
		return kt, errors.New("no current-context is set in the kubeconfig (use --context to select one)")
	}
	kctx, ok := raw.Contexts[kt.contextName]
	if !ok {
		return kt, fmt.Errorf("context %q not found in kubeconfig", kt.contextName)
	}
	kt.clusterName = kctx.Cluster

	kt.restConfig, err = clientConfig.ClientConfig()
	if err != nil {
		return kt, err
	}
	kt.server = kt.restConfig.Host
	kt.caPEM, err = resolveCAPEM(kt.restConfig)
	if err != nil {
		return kt, err
	}
	return kt, nil
}

// resolveCAPEM returns the cluster CA in PEM form, reading the CA file if the
// kubeconfig referenced it by path rather than inlining the data.
func resolveCAPEM(cfg *rest.Config) ([]byte, error) {
	if len(cfg.TLSClientConfig.CAData) > 0 {
		return cfg.TLSClientConfig.CAData, nil
	}
	if cfg.TLSClientConfig.CAFile != "" {
		return os.ReadFile(cfg.TLSClientConfig.CAFile)
	}
	return nil, nil
}

// caCertMatches reports whether the base64-encoded PEM stored on an Akeyless
// k8s auth config is the same certificate the current cluster presents. This is
// the correlation key between a gateway config and the current cluster, because
// the unified gateway stores the in-cluster host (kubernetes.default.svc) rather
// than the externally reachable API server URL.
func caCertMatches(configCAB64 string, clusterCAPEM []byte) bool {
	if configCAB64 == "" || len(clusterCAPEM) == 0 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(configCAB64)
	if err != nil {
		// Some deployments store the PEM directly rather than base64-encoded.
		decoded = []byte(configCAB64)
	}
	return bytes.Equal(bytes.TrimSpace(decoded), bytes.TrimSpace(clusterCAPEM))
}

// reviewToken submits the token reviewer JWT to the current cluster's
// TokenReview API. Authenticating as the reviewer JWT and reviewing that same
// JWT proves three things at once: the JWT is a valid service-account token, it
// can reach and authenticate to the API server, and it holds the RBAC needed to
// create TokenReviews. The request runs against the kubeconfig's reachable API
// server with proper TLS verification, not the in-cluster host stored on the
// config (which is unreachable from outside the cluster).
func reviewToken(base *rest.Config, reviewerJWT string) (*authv1.TokenReview, error) {
	cfg := rest.AnonymousClientConfig(base)
	cfg.BearerToken = reviewerJWT
	cfg.Timeout = timeout

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return clientset.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{Token: reviewerJWT},
	}, metav1.CreateOptions{})
}

// newGatewayAPI builds an Akeyless v2 API client bound to a specific URL.
func newGatewayAPI(url string) *akeyless.V2ApiService {
	return akeyless.NewAPIClient(&akeyless.Configuration{
		Servers:    akeyless.ServerConfigurations{{URL: url}},
		HTTPClient: &http.Client{Timeout: timeout},
	}).V2Api
}

func retrieveListOfGatewaysUsingToken(client *akeyless.V2ApiService, token string) (akeyless.GatewaysListResponse, error) {
	if token == "" {
		return akeyless.GatewaysListResponse{}, errors.New(tokenNotSetMessage)
	}
	body := akeyless.ListGateways{Token: &token}
	resp, _, err := client.ListGateways(context.Background()).Body(body).Execute()
	if err != nil {
		return akeyless.GatewaysListResponse{}, fmt.Errorf("unable to retrieve list of gateways with provided token: %w", err)
	}
	return resp, nil
}

// listK8sAuthConfigNames enumerates the k8s auth config names on a gateway. The
// gateway's /config/k8s-auths endpoint returns a summary list (names only on
// the unified gateway), which is why detail is fetched separately per config.
func listK8sAuthConfigNames(gatewayBaseURL, token string) ([]string, error) {
	endpoint := gatewayBaseURL + "/config/k8s-auths"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: timeout}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config/k8s-auths returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var wrapper struct {
		K8sAuths []struct {
			Name string `json:"name"`
		} `json:"k8s_auths"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding k8s-auths list: %w", err)
	}

	names := make([]string, 0, len(wrapper.K8sAuths))
	for _, a := range wrapper.K8sAuths {
		if a.Name != "" {
			names = append(names, a.Name)
		}
	}
	return names, nil
}

func getK8sAuthConfigDetail(api *akeyless.V2ApiService, token, name string) (akeyless.GatewayGetK8SAuthConfigOutput, error) {
	body := akeyless.GatewayGetK8SAuthConfig{Name: name, Token: &token}
	out, _, err := api.GatewayGetK8SAuthConfig(context.Background()).Body(body).Execute()
	if err != nil {
		return akeyless.GatewayGetK8SAuthConfigOutput{}, err
	}
	return out, nil
}

// usableGatewayName mirrors the Akeyless web console: prefer the display name,
// then the short cluster name, then the full cluster name.
func usableGatewayName(g akeyless.GwClusterIdentity) string {
	if display := g.GetDisplayName(); display != "" {
		return display
	}
	clusterName := g.GetClusterName()
	if short := afterLastSlash(clusterName); short != "" && short != "defaultCluster" {
		return short
	}
	return clusterName
}

func gatewayMatchesFilter(gatewayName, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.HasPrefix(gatewayName, filter)
}

func afterLastSlash(s string) string {
	if i := strings.LastIndex(s, "/"); i != -1 {
		return s[i+1:]
	}
	return s
}

func printErrorMessages(context string, messages ...string) {
	fmt.Println(aurora.BrightRed("========================================================================================================================="))
	for _, msg := range messages {
		if len(context) > 0 {
			fmt.Println(aurora.BrightRed(msg), context)
		} else {
			fmt.Println(aurora.BrightRed(msg))
		}
	}
	fmt.Println(aurora.BrightRed("========================================================================================================================="))
}

// debugf writes verbose diagnostics to stderr so stdout carries only the
// chosen output (text summary or JSON), never debug noise.
func debugf(format string, a ...interface{}) {
	if options.Verbose {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

// fatal writes a setup error to stderr and exits, keeping stdout clean for the
// JSON contract.
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error: "+msg)
	os.Exit(EXIT_CODE_ERROR)
}
