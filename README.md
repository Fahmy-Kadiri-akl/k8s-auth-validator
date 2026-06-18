# Kubernetes auth Akeyless Validator

This Go CLI validates the Akeyless Kubernetes (k8s) auth configuration for the cluster your kubeconfig currently points at.

It lists the gateways registered to your account, reads each gateway's k8s auth configs, finds the one whose CA certificate matches your current cluster, and then proves the configured token reviewer JWT can perform a TokenReview against that cluster. It works against the Akeyless unified gateway, which serves the v2 API methods under the `/api/v2` path prefix.

## Example

[![asciicast](https://asciinema.org/a/588498.svg)](https://asciinema.org/a/588498)

## Installation

### Homebrew install

```sh
brew install akeyless-community/kav/kav
```

### Other installation methods

Navigate to [the releases page](https://github.com/akeyless-community/k8s-auth-validator/releases) and find the correct release binary for your operating system and system architecture. Download the binary and make it executable to connect to the appropriate kubernetes cluster through kubectl.

## Running the CLI

### Running the CLI with token

```sh
k8s-auth-validator -t "t-432xxxxxxx234354grdsg443"
```

### Running the CLI with environment variable token

```sh
export AKEYLESS_TOKEN="t-432xxxxxxx234354grdsg443"
k8s-auth-validator
```

## Inputs

### Command Line Arguments

The program takes the following command line arguments:

- `--token, -t`: Akeyless token, required for making authenticated requests to the Akeyless API Gateway.
- `--api-gateway-url, -u`: The URL used to list gateways. By default, it is set to "https://api.akeyless.io".
- `--gateway-name-filter, -g`: A filter for the name of the Akeyless Gateway.
- `--kubeconfig, -k`: Path to the kubeconfig file. Overrides the `KUBECONFIG` environment variable and the default `~/.kube/config`.
- `--context, -c`: The kubeconfig context to validate. Defaults to the current-context.
- `--output, -o`: Output format, `text` (default) or `json`. In `json` mode stdout carries only the JSON report (per-config results plus an overall `verdict` of `pass`, `fail`, or `no-match`); diagnostics and errors go to stderr. This is the contract other tooling consumes.
- `--verbose, -V`: Enables verbose logging on stderr.
- `--version, -v`: Prints the version of the program and exits.

#### Token

The Akeyless `Token` is required for making authenticated requests to the Akeyless API Gateway. It can be obtained from the Akeyless Web Console or through the gateways web console.

#### API Gateway URL

The `API Gateway URL` can be used to connect to a local Akeyless Gateway API. This can be useful for single tenant deployments of Akeyless or for customers with customer fragments protecting their secrets.

#### Gateway Name Filter

Using the `Gateway Name Filter` can be useful for when you only want to focus on a single gateway and not loop through all the running gateway clusters. 

The `Gateway Name Filter` will first match against the Gateway Display Name and if no match is found, it will match against the Gateway Cluster name as long as the cluster name is not the default value of "defaultCluster", and if the flag is not set it will attempt to match against the full Gateway Name found within the Gateway screen of the Akeyless Web Console.

### Environment Variables

All arguments can be prefixed with "AKEYLESS_" when used as environment variables, simply replace the any remaining dashes with underscores.

```sh
#export AKEYLESS_TOKEN="t-23fds32432tg8wws23543"
export AKEYLESS_API_GATEWAY_URL="https://mylocalgateway.company.com:8081"
#export AKEYLESS_GATEWAY_NAME_FILTER="Gateway1-GKE"
#export AKEYLESS_GATEWAY_NAME_FILTER="acc-xf4cbk7dmj0kk/p-wyv8r36au41uy/Gateway1-GKE"
#export AKEYLESS_GATEWAY_NAME_FILTER="Gateway 1 in GKE"
#export AKEYLESS_VERBOSE="true"
```


## Kubeconfig

The program resolves the kubeconfig honoring, in order: the `--kubeconfig` flag, the `KUBECONFIG` environment variable, then the default `~/.kube/config`. Use `--context` to validate a context other than the current-context without changing your kubeconfig.

## How it works

1. Lists the gateways registered to the account using the token (`--api-gateway-url`, default `https://api.akeyless.io`).
2. For each running gateway, enumerates its k8s auth config names from the gateway's `/config/k8s-auths` endpoint and fetches each config's detail from `<cluster_url>/api/v2/gateway-get-k8s-auth-config`.
3. Correlates configs to your current cluster by **CA certificate**, not by host. The unified gateway stores the in-cluster API host (`https://kubernetes.default.svc`), which is not reachable from outside the cluster and is not unique per cluster, so the CA certificate is used as the correlation key.
4. For each matching config, performs a `TokenReview` using the configured token reviewer JWT against your current cluster's reachable API server, with TLS verified against the kubeconfig CA. Authenticating as the reviewer JWT and reviewing that same JWT confirms in one call that the JWT is valid, can reach and authenticate to the API server, and holds the RBAC needed to create TokenReviews.

Configs that use `use_local_ca_jwt` authenticate with the gateway's own in-cluster service account and store no CA, host, or reviewer JWT. They cannot be validated from outside the cluster, so they are reported separately (only for a gateway that is otherwise CA-matched to your current cluster) rather than silently skipped.

## Outputs

The program prints:

1. The context, cluster name, and API server of the cluster being validated.
2. For each matching config: the gateway, config name, auth method Access ID, configured k8s host, CA match result, and the TokenReview result (the authenticated reviewer identity, or the failure reason).
3. Any `use_local_ca_jwt` configs on a matched gateway that cannot be validated externally.

The program exits non-zero if no config matches the current cluster's CA, or if any matched config fails validation.
