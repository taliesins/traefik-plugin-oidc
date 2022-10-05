package integration

import (
	"fmt"
	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/taliesins/traefik-plugin-oidc"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// *****************  Authorization Header Test

func TestWithClientSecretInAuthorizationHeaderSuccess(t *testing.T) {
	RunTestWithClientSecretSuccess(t, "mySecret", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithClientSecretInAuthorizationHeaderWrongSecretFailure(t *testing.T) {
	RunTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithClientSecretInQuerystringSuccess(t *testing.T) {
	RunTestWithClientSecretSuccess(t, "mySecret", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
}

func TestWithClientSecretInQuerystringWrongSecretFailure(t *testing.T) {
	RunTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
}

func TestWithClientSecretInCookieSuccess(t *testing.T) {
	RunTestWithClientSecretSuccess(t, "mySecret", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
}

func TestWithClientSecretInCookieWrongSecretFailure(t *testing.T) {
	RunTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
}

// ***************** Signing with Public Key Tests

func TestWithPublicKeyInAuthorizationHeaderSuccess(t *testing.T) {
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithPublicKeyInAuthorizationHeaderFailure(t *testing.T) {
	//As long as the cert we are using is different
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es512", "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es256", "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es256", "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS256, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS384, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS512, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS256, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS384, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS512, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithPublicKeyInQuerystringSuccess(t *testing.T) {
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
}

func TestWithPublicKeyInQuerystringFailure(t *testing.T) {
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/another.es256", "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/another.es384", "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/another.es512", "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.ParameterTokenInjector(sso_redirector.IdTokenBookmarkParameterName)))
}

func TestWithPublicKeyInCookieSuccess(t *testing.T) {
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
}

func TestWithPublicKeyInCookieFailure(t *testing.T) {
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/another.es256", "../integration/fixtures/signing/es256", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/another.es384", "../integration/fixtures/signing/es384", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/another.es512", "../integration/fixtures/signing/es512", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/another.rsa", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName)))
}

func TestWithSignedRsaPublicKeySuccess(t *testing.T) {
	RunTestWithPublicKeySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/https/snitest.com", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithRsaPublicKeySignedWithWrongPrivateKeyFailure(t *testing.T) {
	RunTestWithPublicKeyFailure(t, jwtgo.SigningMethodRS256, "../integration/fixtures/https/snitest.com", "../integration/fixtures/signing/rsa", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

// ***************** Signing using Oidc to get signing method Tests

func TestWithOidcInAuthorizationHeaderSuccess(t *testing.T) {
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es256", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es384", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es512", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithOidcInAuthorizationHeaderFailure(t *testing.T) {
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodES256, "../integration/fixtures/signing/es256", "../integration/fixtures/signing/another.es256", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodES384, "../integration/fixtures/signing/es384", "../integration/fixtures/signing/another.es384", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodES512, "../integration/fixtures/signing/es512", "../integration/fixtures/signing/another.es512", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodPS256, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodPS384, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodPS512, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodRS384, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
	RunTestWithDiscoveryFailure(t, jwtgo.SigningMethodRS512, "../integration/fixtures/signing/rsa", "../integration/fixtures/signing/another.rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithRS256UsingJwksUriSuccess(t *testing.T) {
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", true, false, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithRS256UsingOpenIdConnectDiscoveryUriSuccess(t *testing.T) {
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", false, true, false, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithRS256UsingIssuerUriSuccess(t *testing.T) {
	RunTestWithDiscoverySuccess(t, jwtgo.SigningMethodRS256, "../integration/fixtures/signing/rsa", false, false, true, jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}

func TestWithNoAuthenticationAndNoSsoProvidedFailure(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		return pluginConfig
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	expectedBody := "\n"
	assert.EqualValues(t, expectedBody, string(body), "they should be equal")
}

func TestWithNoAuthenticationAndSsoProvidedFailure(t *testing.T) {
	var expectedSsoAddressTemplate string

	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		expectedSsoAddressTemplate = pluginConfig.SsoAddressTemplate

		return pluginConfig
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, nonce, _, _, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)

	expectedRedirectUri, err := url.Parse(res.Request.URL.String())
	if err != nil {
		panic(err)
	}

	expectedRedirectUri.Path = sso_redirector.CallbackPath

	expectedBodyRegex, err := regexp.Compile("\n<!DOCTYPE html><html><head><title></title></head><body>\n\n<script>\nwindow.location.replace\\('(.*)'\\);\n</script>\nPlease sign in at <a href='(.*)'>(.*)</a>\n</body></html>\n\n")
	expectedBodyMatches := expectedBodyRegex.FindStringSubmatch(string(body))
	assert.Len(t, expectedBodyMatches, 4, "Expect 4 matches")
	bodyMatch := expectedBodyMatches[1]

	redirectUrlRegex := strings.Replace(strings.Replace(strings.Replace(sso_redirector.TemplateToRegexFixer(expectedSsoAddressTemplate), "{{.CallbackUrl}}", "(.*)", -1), "{{.State}}", "(.*)", -1), "{{.Nonce}}", "(.*)", -1)
	expectedRedirectUrlRegex, err := regexp.Compile(redirectUrlRegex)
	expectedRedirectUrlMatches := expectedRedirectUrlRegex.FindStringSubmatch(bodyMatch)
	assert.Len(t, expectedRedirectUrlMatches, 4, "Expect 4 matches")
	nonceMatch := expectedRedirectUrlMatches[1]
	redirectUriMatch := expectedRedirectUrlMatches[2]
	stateMatch := expectedRedirectUrlMatches[3]

	assert.Equal(t, nonce, nonceMatch, "nonce should be specified")
	assert.EqualValues(t, url.QueryEscape(expectedRedirectUri.String()), redirectUriMatch, "redirect_uri should be specified")
	assert.NotEqual(t, url.QueryEscape(""), stateMatch, "state should be specified")
}

func TestWithRedirectFromSsoButIdTokenIsStoredInBookmarkSuccess(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		return pluginConfig
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, clientRequestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	//Work out the url that the SSO would redirect back to
	expectedReturnUrl := fmt.Sprintf("%s://%s%s?%s=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, sso_redirector.CallbackPath, sso_redirector.RedirectUriQuerystringParameterName, url.QueryEscape(clientRequestUrl.String()))
	expectedRedirectorUrl := fmt.Sprintf("%s://%s%s", clientRequestUrl.Scheme, clientRequestUrl.Host, sso_redirector.RedirectorPath)

	req := MustNewRequest(http.MethodGet, expectedReturnUrl, nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)

	//	expectedBodyTemplate := "\n<!DOCTYPE html><html><head><title></title></head><body>\n<script>\nfunction getBookMarkParameterByName(name, url) {\n    if (!url) url = window.location.hash;\n    name = name.replace(/[\\[\\]]/g, \"\\\\$&\");\n    var regex = new RegExp(\"[#&?]\" + name + \"(=([^&#]*)|&|#|$)\"), results = regex.exec(url);\n    if (!results) return null;\n    if (!results[2]) return '';\n    return decodeURIComponent(results[2].replace(/\\+/g, \" \"));\n}\n\nstate = getBookMarkParameterByName('state');\nif (state) {\n\tid_token = getBookMarkParameterByName('id_token');\n\tif (id_token) {\n\n\t\tdocument.cookie = 'id_token=' + id_token + '; domain=' + document.domain + '; path=/; secure';\n\t\twindow.location.replace('%s?' + state);\n\n\t}\n}\n</script>\nPlease change the '#' in the url to '&' and goto link\n</body></html>\n\n"
	expectedBodyTemplate := "\n<!DOCTYPE html><html><head><title></title></head><body>\n<script>\nfunction getBookMarkParameterByName(name, url) {\n    if (!url) url = window.location.hash;\n    name = name.replace(/[\\[\\]]/g, \"\\\\$&\");\n    var regex = new RegExp(\"[#&?]\" + name + \"(=([^&#]*)|&|#|$)\"), results = regex.exec(url);\n    if (!results) return null;\n    if (!results[2]) return '';\n    return decodeURIComponent(results[2].replace(/\\+/g, \" \"));\n}\n\nfunction post(path, params, method) {\n    method = method || \"post\"; // Set method to post by default if not specified.\n\n    // The rest of this code assumes you are not using a library.\n    // It can be made less wordy if you use one.\n    var form = document.createElement(\"form\");\n    form.setAttribute(\"method\", method);\n    form.setAttribute(\"action\", path);\n\n    for(var key in params) {\n        if(params.hasOwnProperty(key)) {\n            var hiddenField = document.createElement(\"input\");\n            hiddenField.setAttribute(\"type\", \"hidden\");\n            hiddenField.setAttribute(\"name\", key);\n            hiddenField.setAttribute(\"value\", params[key]);\n\n            form.appendChild(hiddenField);\n        }\n    }\n\n    document.body.appendChild(form);\n    form.submit();\n}\n\nstate = getBookMarkParameterByName('state');\nif (state) {\n\tid_token = getBookMarkParameterByName('id_token');\n\tif (id_token) {\n\n\t\tpost('%s?' + state, {id_token: id_token});\n\n\t}\n}\n</script>\nPlease change the '#' in the url to '&' and goto link\n</body></html>\n\n"

	assert.EqualValues(t, fmt.Sprintf(expectedBodyTemplate, expectedRedirectorUrl), string(body), "Should be equal")
}

func TestRedirectorWithValidCookieAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		return pluginConfig
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, clientRequestUrl, expectedRedirectorUrl, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName))
	tokenInjector(req, signedToken)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned")

	if len(cookies) == 1 {
		assert.EqualValues(t, sso_redirector.SessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := io.ReadAll(res.Body)
	assert.EqualValues(t, fmt.Sprintf("<a href=\"%s\">See Other</a>.\n\n", clientRequestUrl), string(body), "Should be equal")
}

func TestRedirectorWithInvalidCookieAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		return pluginConfig
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, _, expectedRedirectorUrl, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)

	cookie := &http.Cookie{
		Name:  sso_redirector.SessionCookieName,
		Value: signedToken + "dodgy_token",
	}
	req.AddCookie(cookie)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned")

	if len(cookies) == 1 {
		assert.EqualValues(t, sso_redirector.SessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Before(time.Now().UTC()), "Session cookie should be expired")
		assert.True(t, cookies[0].MaxAge < 0, "Session cookie should be expired")
	}

	body, err := io.ReadAll(res.Body)
	assert.EqualValues(t, "\n", string(body), "Should be equal")
}

func TestRedirectorWithValidCookieAndValidHashAndUsingDiscoveryAddressSuccess(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.OidcDiscoveryAddress = oidcDiscoveryUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		return pluginConfig
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, clientRequestUrl, expectedRedirectorUrl, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.CookieTokenInjector(sso_redirector.SessionCookieName))
	tokenInjector(req, signedToken)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned")

	if len(cookies) == 1 {
		assert.EqualValues(t, sso_redirector.SessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := io.ReadAll(res.Body)
	assert.EqualValues(t, fmt.Sprintf("<a href=\"%s\">See Other</a>.\n\n", clientRequestUrl), string(body), "Should be equal")
}

func TestRedirectorWithValidPostAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()

		return pluginConfig
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, _, expectedRedirectorUrl, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodPost, expectedRedirectorUrl.String(), strings.NewReader("id_token="+signedToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned")

	if len(cookies) == 1 {
		assert.EqualValues(t, sso_redirector.SessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := io.ReadAll(res.Body)
	assert.EqualValues(t, "", string(body), "Should be equal")
}

func TestWithNoAuthenticationAndIgnorePathMatched(t *testing.T) {
	//var expectedSsoAddressTemplate string

	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()
		pluginConfig.IgnorePathRegex = "/"

		//expectedSsoAddressTemplate = pluginConfig.SsoAddressTemplate

		return pluginConfig
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	stringBody := string(body)

	assert.Equal(t, "{\"RequestUri\":\"/\", \"Referer\":\"\"}\n", stringBody, "they should equal")
}

func TestWithNoAuthenticationAndIgnorePathNotMatched(t *testing.T) {
	var expectedSsoAddressTemplate string

	certificate, jwksServer, pluginServer, err := BuildTestServers("../integration/fixtures/signing/rsa", "../integration/fixtures/signing/rsa", func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.Issuer = issuerUri.String()
		pluginConfig.SsoAddressTemplate = ssoAddressTemplate
		pluginConfig.UrlMacPrivateKey = certificate.KeyFile.String()
		pluginConfig.IgnorePathRegex = "!/"

		expectedSsoAddressTemplate = pluginConfig.SsoAddressTemplate

		return pluginConfig
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, nonce, _, _, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, jwtgo.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)

	expectedRedirectUri, err := url.Parse(res.Request.URL.String())
	if err != nil {
		panic(err)
	}

	expectedRedirectUri.Path = sso_redirector.CallbackPath

	expectedBodyRegex, err := regexp.Compile("\n<!DOCTYPE html><html><head><title></title></head><body>\n\n<script>\nwindow.location.replace\\('(.*)'\\);\n</script>\nPlease sign in at <a href='(.*)'>(.*)</a>\n</body></html>\n\n")
	expectedBodyMatches := expectedBodyRegex.FindStringSubmatch(string(body))
	assert.Len(t, expectedBodyMatches, 4, "Expect 4 matches")
	bodyMatch := expectedBodyMatches[1]

	redirectUrlRegex := strings.Replace(strings.Replace(strings.Replace(sso_redirector.TemplateToRegexFixer(expectedSsoAddressTemplate), "{{.CallbackUrl}}", "(.*)", -1), "{{.State}}", "(.*)", -1), "{{.Nonce}}", "(.*)", -1)
	expectedRedirectUrlRegex, err := regexp.Compile(redirectUrlRegex)
	expectedRedirectUrlMatches := expectedRedirectUrlRegex.FindStringSubmatch(bodyMatch)
	assert.Len(t, expectedRedirectUrlMatches, 4, "Expect 4 matches")
	nonceMatch := expectedRedirectUrlMatches[1]
	redirectUriMatch := expectedRedirectUrlMatches[2]
	stateMatch := expectedRedirectUrlMatches[3]

	assert.Equal(t, nonce, nonceMatch, "nonce should be specified")
	assert.EqualValues(t, url.QueryEscape(expectedRedirectUri.String()), redirectUriMatch, "redirect_uri should be specified")
	assert.NotEqual(t, url.QueryEscape(""), stateMatch, "state should be specified")
}

func TestWithValidCredentialsAndAlgorithmRegexSuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.AlgorithmValidationRegex = "RS256"
		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationSuccess(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndAlgorithmRegexFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.AlgorithmValidationRegex = "NotMatched"

		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationFailure(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndIssuerRegexSuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.IssuerValidationRegex = "https://.*"
		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationSuccess(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndIssuerRegexFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.IssuerValidationRegex = "NotMatched"

		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationFailure(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndAudienceRegexSuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.AudienceValidationRegex = "aud"
		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationSuccess(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndAudienceRegexFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.AudienceValidationRegex = "NotMatched"

		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationFailure(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndSubjectRegexSuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.SubjectValidationRegex = "sub"
		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationSuccess(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndSubjectRegexFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.SubjectValidationRegex = "NotMatched"

		return pluginConfig
	}

	RunTestAuthenticationWithConfigurationFailure(t, signingMethod, certificatePath, tokenInjector, configuration)
}

func TestWithValidCredentialsAndDynamicValidationMatchPrimarySuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.UseDynamicValidation = true
		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	dynamicCertificatePath := "../integration/fixtures/signing/another.rsa"
	dynamicOidcDiscoveryUriPath := "/.well-known/openid-configuration"
	dynamicJwksUriPath := "/common/discovery/keys"
	_, dynamicJwksServer, err := BuildTestJwkServer(dynamicCertificatePath, dynamicCertificatePath, dynamicOidcDiscoveryUriPath, dynamicJwksUriPath)
	defer dynamicJwksServer.Close()

	//Client is making request with a token that is signed by the primary jwks server
	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should be equal")
}

func TestWithValidCredentialsAndDynamicValidationMatchDynamicSuccess(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.UseDynamicValidation = true
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	dynamicCertificatePath := "../integration/fixtures/signing/another.rsa"
	dynamicOidcDiscoveryUriPath := "/.well-known/openid-configuration"
	dynamicJwksUriPath := "/common/discovery/keys"
	dynamicCertificate, dynamicJwksServer, err := BuildTestJwkServer(dynamicCertificatePath, dynamicCertificatePath, dynamicOidcDiscoveryUriPath, dynamicJwksUriPath)
	defer dynamicJwksServer.Close()

	//Client is making request with a token that is signed by the dynamic jwks server
	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(dynamicCertificate, "", dynamicJwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should be equal")
}

func TestWithValidCredentialsAndDynamicValidationMatchPrimaryFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.UseDynamicValidation = true
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	dynamicCertificatePath := "../integration/fixtures/signing/rsa"
	dynamicOidcDiscoveryUriPath := "/.well-known/openid-configuration"
	dynamicJwksUriPath := "/common/discovery/keys"
	_, dynamicJwksServer, err := BuildTestJwkServer(dynamicCertificatePath, dynamicCertificatePath, dynamicOidcDiscoveryUriPath, dynamicJwksUriPath)
	defer dynamicJwksServer.Close()

	//Client is making request with a token that is signed by a dodgy certificate that will be validated by the primary jwks server
	dodgyCertificatePath := "../integration/fixtures/signing/another.rsa"
	dodgyCertificate, err := GetCertificateFromPath(dodgyCertificatePath, dodgyCertificatePath)
	if err != nil {
		panic(err)
	}
	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(dodgyCertificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")
}

func TestWithValidCredentialsAndDynamicValidationMatchDynamicFailure(t *testing.T) {
	signingMethod := jwtgo.SigningMethodRS256
	certificatePath := "../integration/fixtures/signing/rsa"
	tokenInjector := jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector)

	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.JwksAddress = jwksUri.String()
		pluginConfig.UseDynamicValidation = true
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	dynamicCertificatePath := "../integration/fixtures/signing/rsa"
	dynamicOidcDiscoveryUriPath := "/.well-known/openid-configuration"
	dynamicJwksUriPath := "/common/discovery/keys"
	_, dynamicJwksServer, err := BuildTestJwkServer(dynamicCertificatePath, dynamicCertificatePath, dynamicOidcDiscoveryUriPath, dynamicJwksUriPath)
	defer dynamicJwksServer.Close()

	//Client is making request with a token that is signed by a dodgy certificate that will be validated by the dynamic jwks server
	dodgyCertificatePath := "../integration/fixtures/signing/another.rsa"
	dodgyCertificate, err := GetCertificateFromPath(dodgyCertificatePath, dodgyCertificatePath)
	if err != nil {
		panic(err)
	}
	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(dodgyCertificate, "", dynamicJwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")
}
