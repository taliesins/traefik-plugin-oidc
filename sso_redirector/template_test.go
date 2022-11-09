package sso_redirector

import (
	"net/url"
	"testing"
	"text/template"

	"github.com/taliesins/traefik-plugin-oidc/assert"
)

func TestTemplate(t *testing.T) {
	templateToRender := "http://keycloak.localhost/realms/whoami/protocol/openid-connect/auth?client_id=whoami-middleware-oidc-keycloak&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token"
	template, err := template.New("SsoRedirectUrl").Parse(templateToRender)
	assert.NoError(t, err)
	url := &url.URL{}
	nonce := "nonceString"
	expectedQuery := "client_id=whoami-middleware-oidc-keycloak&nonce=nonceString&redirect_uri=http%3A%2F%2Fwhoami.localhost%2Foauth2%2Fcallback&state=&scope=openid&response_type=id_token"
	url.Scheme = "http"
	url.Host = "whoami.localhost"
	url.Path = "/oauth2/callback"
	res, err := RenderSsoRedirectUrlTemplate(template, url, nonce, "2022")
	assert.NoError(t, err)
	assert.True(t, res.RawQuery == expectedQuery, "Expected : %s, Actual: %s", res.RawQuery, expectedQuery)

}
