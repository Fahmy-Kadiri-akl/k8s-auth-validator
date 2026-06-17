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
	Verbose           bool   `short:"V" long:"verbose" description:"Show verbose debug information"`
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

	if options.Token == "" {
		fatal("Akeyless token is not set. Please set the token using the -t or --token flag or set the AKEYLESS_TOKEN environment variable")
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

	fmt.Println("Context:", aurora.BrightGreen(kube.contextName))
	fmt.Println("Cluster:", aurora.BrightGreen(kube.clusterName))
	fmt.Println("API server:", aurora.BrightGreen(kube.server))
	if options.GatewayNameFilter != "" {
		fmt.Println("Gateway name filter:", aurora.BrightCyan(options.GatewayNameFilter))
	}
	if options.ApiGatewayUrl != "https://api.akeyless.io" {
		fmt.Println("Akeyless API Gateway URL:", aurora.BrightCyan(options.ApiGatewayUrl))
	}
	if len(kube.caPEM) == 0 {
		fmt.Println(aurora.BrightYellow("Warning: current context has no CA certificate data; cannot correlate gateway configs to this cluster by CA."))
	}
	if options.Verbose {
		fmt.Println("Kubernetes API server CA (base64):", base64.StdEncoding.EncodeToString(kube.caPEM))
	}

	// Discover every gateway registered to this account.
	saasAPI := newGatewayAPI(options.ApiGatewayUrl)
	gwList, err := retrieveListOfGatewaysUsingToken(saasAPI, options.Token)
	if err != nil {
		fatal(err.Error())
	}

	matched := 0
	failed := 0
	// Configs that authenticate with the gateway's own in-cluster identity
	// (use_local_ca_jwt) store no CA, host, or reviewer JWT, so they cannot be
	// correlated or validated from outside the cluster. They are surfaced
	// explicitly rather than dropped.
	var localCAJwtConfigs []configRef

	for _, gateway := range gwList.GetClusters() {
		name := usableGatewayName(gateway)

		if gateway.GetStatus() != GATEWAY_RUNNING_STATUS {
			if options.Verbose {
				fmt.Println("Skipping gateway (not Running):", aurora.BrightYellow(name), aurora.BrightYellow(gateway.GetStatus()))
			}
			continue
		}
		if !gatewayMatchesFilter(gateway, options.GatewayNameFilter) {
			if options.Verbose {
				fmt.Println("Skipping gateway (name filter):", aurora.BrightYellow(name))
			}
			continue
		}
		clusterURL, ok := gateway.GetClusterUrlOk()
		if !ok || *clusterURL == "" {
			if options.Verbose {
				fmt.Println("Skipping gateway (no cluster URL):", aurora.BrightYellow(name))
			}
			continue
		}

		// The unified gateway summarizes /config/k8s-auths (names only), so we
		// enumerate names here and fetch the full detail per config below.
		authNames, err := listK8sAuthConfigNames(*clusterURL, options.Token)
		if err != nil {
			fmt.Println(aurora.BrightYellow(fmt.Sprintf("Skipping gateway %q (%s): %v", name, *clusterURL, err)))
			continue
		}
		if options.Verbose {
			fmt.Printf("Gateway %q has %d k8s auth config(s): %v\n", name, len(authNames), authNames)
		}

		// The unified gateway serves the Akeyless v2 API methods under the
		// /api/v2 prefix (the SaaS serves them at the root). The per-config
		// detail call therefore targets that prefix, while the name listing
		// above uses the gateway's /config REST endpoint at the root.
		gwAPI := newGatewayAPI(strings.TrimRight(*clusterURL, "/") + "/api/v2")
		// A gateway runs in exactly one cluster. We only treat its local-CA-JWT
		// configs as relevant to the current cluster once another config on the
		// same gateway has been CA-matched to it, which proves co-location.
		gatewayMatched := false
		var gatewayLocalCAConfigs []string
		for _, authName := range authNames {
			detail, err := getK8sAuthConfigDetail(gwAPI, options.Token, authName)
			if err != nil {
				fmt.Println(aurora.BrightYellow(fmt.Sprintf("Could not read k8s auth config %q on %q: %v", authName, name, err)))
				continue
			}

			if detail.GetUseLocalCaJwt() {
				gatewayLocalCAConfigs = append(gatewayLocalCAConfigs, authName)
				continue
			}

			if !caCertMatches(detail.GetK8sCaCert(), kube.caPEM) {
				if options.Verbose {
					fmt.Printf("Config %q CA does not match current cluster; skipping\n", authName)
				}
				continue
			}

			matched++
			gatewayMatched = true
			fmt.Println()
			fmt.Println("Matched gateway:", aurora.BrightGreen(name))
			fmt.Println("  K8S auth config name:", aurora.BrightGreen(detail.GetName()))
			fmt.Println("  Auth method access ID:", aurora.BrightGreen(detail.GetAuthMethodAccessId()))
			fmt.Println("  Configured k8s host:", aurora.BrightGreen(detail.GetK8sHost()))
			fmt.Println("  CA certificate:", aurora.BrightGreen("matches current cluster"))

			if detail.GetK8sTokenReviewerJwt() == "" {
				failed++
				fmt.Println("  Token reviewer JWT:", aurora.BrightRed("not set on this config; cannot validate TokenReview"))
				continue
			}

			review, err := reviewToken(kube.restConfig, detail.GetK8sTokenReviewerJwt())
			if err != nil {
				failed++
				fmt.Println("  TokenReview request:", aurora.BrightRed(fmt.Sprintf("failed: %v", err)))
				continue
			}
			if review.Status.Authenticated {
				fmt.Println("  Token reviewer JWT:", aurora.BrightGreen("valid, authenticated as "+review.Status.User.Username))
			} else {
				failed++
				msg := "not authenticated"
				if review.Status.Error != "" {
					msg = review.Status.Error
				}
				fmt.Println("  Token reviewer JWT:", aurora.BrightRed(msg))
			}
		}

		// Only surface this gateway's local-CA-JWT configs if the gateway was
		// confirmed (by CA match) to serve the current cluster.
		if gatewayMatched {
			for _, c := range gatewayLocalCAConfigs {
				localCAJwtConfigs = append(localCAJwtConfigs, configRef{gateway: name, config: c})
			}
		} else if options.Verbose && len(gatewayLocalCAConfigs) > 0 {
			fmt.Printf("Gateway %q has %d local-CA-JWT config(s) but no config matching the current cluster; not reporting them\n", name, len(gatewayLocalCAConfigs))
		}
	}

	fmt.Println()
	if len(localCAJwtConfigs) > 0 {
		fmt.Println(aurora.BrightCyan("The following k8s auth config(s) use local CA JWT (the gateway's own in-cluster"))
		fmt.Println(aurora.BrightCyan("service account) and cannot be validated from outside the cluster:"))
		for _, c := range localCAJwtConfigs {
			fmt.Printf("  - %s (gateway %q)\n", c.config, c.gateway)
		}
		fmt.Println()
	}
	if matched == 0 {
		printErrorMessages(kube.server, "No Akeyless k8s auth config has a CA certificate matching your current cluster:")
		os.Exit(EXIT_CODE_ERROR)
	}
	if failed > 0 {
		printErrorMessages("", fmt.Sprintf("%d of %d matching k8s auth config(s) failed validation", failed, matched))
		os.Exit(EXIT_CODE_ERROR)
	}
	fmt.Println(aurora.BrightGreen(fmt.Sprintf("All %d matching k8s auth config(s) validated successfully.", matched)))
}

// configRef identifies a k8s auth config by the gateway it lives on.
type configRef struct {
	gateway string
	config  string
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
		return akeyless.GatewaysListResponse{}, errors.New("Akeyless token is not set. Please set the token using the -t or --token flag or set the AKEYLESS_TOKEN environment variable")
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
func listK8sAuthConfigNames(clusterURL, token string) ([]string, error) {
	endpoint := strings.TrimRight(clusterURL, "/") + "/config/k8s-auths"
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

func gatewayMatchesFilter(g akeyless.GwClusterIdentity, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.HasPrefix(usableGatewayName(g), filter)
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

func fatal(msg string) {
	printErrorMessages("", msg)
	os.Exit(EXIT_CODE_ERROR)
}
