package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	akeyless "github.com/akeylesslabs/akeyless-go/v2"
	"github.com/stretchr/testify/assert"
)

// newMockGatewaysServer mocks the Akeyless v2 /list-gateways endpoint. The SDK
// sends the token in the JSON request body, so the response is selected by the
// token value rather than a query string.
func newMockGatewaysServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/list-gateways" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)

		w.Header().Set("Content-Type", "application/json")
		switch body.Token {
		case "expired":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"token expired"}`))
		case "empty":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"clusters":[]}`))
		case "error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"clusters":[{"cluster_name":"acc/p/test-gateway","status":"Running","cluster_url":"https://gw.example"}]}`))
		}
	}))
}

func TestRetrieveListOfGatewaysUsingToken(t *testing.T) {
	mockServer := newMockGatewaysServer()
	defer mockServer.Close()

	client := akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: akeyless.ServerConfigurations{{URL: mockServer.URL}},
	}).V2Api

	t.Run("Successful call", func(t *testing.T) {
		resp, err := retrieveListOfGatewaysUsingToken(client, "valid-token")
		assert.NoError(t, err)
		assert.NotEmpty(t, resp.GetClusters())
	})

	t.Run("Expired token", func(t *testing.T) {
		_, err := retrieveListOfGatewaysUsingToken(client, "expired")
		assert.Error(t, err)
	})

	t.Run("Token not set", func(t *testing.T) {
		_, err := retrieveListOfGatewaysUsingToken(client, "")
		assert.Error(t, err)
	})

	t.Run("Empty list of gateways", func(t *testing.T) {
		resp, err := retrieveListOfGatewaysUsingToken(client, "empty")
		assert.NoError(t, err)
		assert.Empty(t, resp.GetClusters())
	})

	t.Run("Error response from API Gateway", func(t *testing.T) {
		_, err := retrieveListOfGatewaysUsingToken(client, "error")
		assert.Error(t, err)
	})
}

func TestCACertMatches(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAN...\n-----END CERTIFICATE-----\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(pem))

	t.Run("matching base64 PEM", func(t *testing.T) {
		assert.True(t, caCertMatches(b64, []byte(pem)))
	})

	t.Run("matching ignores surrounding whitespace", func(t *testing.T) {
		assert.True(t, caCertMatches(b64, []byte("\n  "+pem+"  \n")))
	})

	t.Run("different certificate does not match", func(t *testing.T) {
		other := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nDIFFERENT\n-----END CERTIFICATE-----\n"))
		assert.False(t, caCertMatches(other, []byte(pem)))
	})

	t.Run("empty inputs do not match", func(t *testing.T) {
		assert.False(t, caCertMatches("", []byte(pem)))
		assert.False(t, caCertMatches(b64, nil))
	})
}

func TestUsableGatewayNameAndFilter(t *testing.T) {
	withDisplay := akeyless.GwClusterIdentity{}
	withDisplay.SetDisplayName("gcp-microk8s")
	withDisplay.SetClusterName("acc-x/p-y/gcp-microk8s")

	noDisplay := akeyless.GwClusterIdentity{}
	noDisplay.SetClusterName("acc-x/p-y/aws-microk8s")

	defaultCluster := akeyless.GwClusterIdentity{}
	defaultCluster.SetClusterName("acc-x/p-y/defaultCluster")

	assert.Equal(t, "gcp-microk8s", usableGatewayName(withDisplay))
	assert.Equal(t, "aws-microk8s", usableGatewayName(noDisplay))
	assert.Equal(t, "acc-x/p-y/defaultCluster", usableGatewayName(defaultCluster))

	assert.True(t, gatewayMatchesFilter(usableGatewayName(withDisplay), ""))
	assert.True(t, gatewayMatchesFilter(usableGatewayName(withDisplay), "gcp"))
	assert.False(t, gatewayMatchesFilter(usableGatewayName(withDisplay), "aws"))
	assert.True(t, gatewayMatchesFilter(usableGatewayName(noDisplay), "aws-microk8s"))
}
