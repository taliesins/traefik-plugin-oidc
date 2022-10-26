package jwks

import (
	"github.com/taliesins/traefik-plugin-oidc/assert"
	"testing"
)

func TestDownloadOpenIdConnectDiscoveryUriSuccess(t *testing.T) {
	jwksUri, err := DownloadOpenIdConnectDiscoveryUri("https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/.well-known/openid-configuration")
	assert.NoError(t, err)
	assert.NotEmpty(t, jwksUri, "jwks uri")
}

func TestDownloadJwksUriSuccess(t *testing.T) {
	jwks, err := DownloadJwksUri("https://login.microsoftonline.com/775527ff-9a37-4307-8b3d-cc311f58d925/discovery/v2.0/keys")
	assert.NoError(t, err)
	assert.NotEmpty(t, jwks, "jwks")
}
