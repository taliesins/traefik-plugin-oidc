package integration

import (
	"crypto/tls"
	"fmt"
	guuid "github.com/google/uuid"
	traefikPluginOidc "github.com/taliesins/traefik-plugin-oidc"
	"github.com/taliesins/traefik-plugin-oidc/assert"
	jwtgo "github.com/taliesins/traefik-plugin-oidc/jwt"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"github.com/taliesins/traefik-plugin-oidc/test_utils"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type overrideClient func(*http.Client) *http.Client

type overrideClaims func(claims *jwtgo.RegisteredClaims, certificate *jwt_certificate.Certificate, jwksServer *httptest.Server, middlwareServer *httptest.Server) *jwtgo.RegisteredClaims

type overrideToken func(*jwtgo.Token)

func BuildTestClient(certificate *jwt_certificate.Certificate, clientSecret string, jwksServer *httptest.Server, middlwareServer *httptest.Server, tokenSigningMethod jwtgo.SigningMethod, requestPath string, overrideClient overrideClient, overrideClaims overrideClaims, overrideToken overrideToken) (client *http.Client, nonce string, issuedAt string, signedToken string, clientRequestUrl *url.URL, expectedRedirectorUrl *url.URL, err error) {
	client = &http.Client{}
	if overrideClient != nil {
		overrideClient(client)
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if requestPath == "" {
		requestPath = "/"
	}
	clientRequestPath, err := url.Parse(requestPath)
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	base, err := url.Parse(middlwareServer.URL)
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	clientRequestUrl = base.ResolveReference(clientRequestPath)

	nonce = guuid.NewString()
	issuedAt = strconv.FormatInt(time.Now().UTC().Unix(), 10)

	//Work out the url that the SSO would redirect back to
	expectedRedirectorUrl, err = url.Parse(fmt.Sprintf("%s://%s%s?iat=%s&nonce=%s&redirect_uri=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, sso_redirector.RedirectorPath, issuedAt, nonce, url.QueryEscape(clientRequestUrl.String())))
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	var privateKey interface{}
	if clientSecret != "" {
		if tokenSigningMethod.Alg() != jwtgo.SigningMethodHS256.Name && tokenSigningMethod.Alg() != jwtgo.SigningMethodHS384.Name && tokenSigningMethod.Alg() != jwtgo.SigningMethodHS512.Name {
			return nil, "", "", "", nil, nil, fmt.Errorf("certificate needs to be specified with this signing method")
		}

		privateKey = []byte(clientSecret)
	} else if certificate != nil {
		if tokenSigningMethod.Alg() == jwtgo.SigningMethodHS256.Name || tokenSigningMethod.Alg() == jwtgo.SigningMethodHS384.Name || tokenSigningMethod.Alg() == jwtgo.SigningMethodHS512.Name {
			return nil, "", "", "", nil, nil, fmt.Errorf("client secret needs to be specified with this signing method")
		}

		//Need the signing key to use for mac of url, so just use the one we use for JWT
		privateKeyPemData, err := certificate.KeyFile.Read()
		if err != nil {
			return nil, "", "", "", nil, nil, err
		}

		privateKey, err = jwt_certificate.GetPrivateKey(privateKeyPemData)
		if err != nil {
			return nil, "", "", "", nil, nil, err
		}
	} else {
		return nil, "", "", "", nil, nil, fmt.Errorf("certificate and client secret not specified, there is no way to sign request")
	}

	macStrength := sso_redirector.HmacStrength_256
	err = sso_redirector.AddMacHashToUrl(expectedRedirectorUrl, privateKey, macStrength)
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	claims := &jwtgo.RegisteredClaims{}
	if overrideClaims != nil {
		overrideClaims(claims, certificate, jwksServer, middlwareServer)
	} else {
		claims.Issuer = jwksServer.URL
		claims.Subject = "sub"
		claims.Audience = jwtgo.ClaimStrings{"aud"}
	}

	token := jwtgo.NewWithClaims(tokenSigningMethod, claims)
	if overrideToken != nil {
		overrideToken(token)
	}

	signedToken, err = token.SignedString(privateKey)
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	return client, nonce, issuedAt, signedToken, clientRequestUrl, expectedRedirectorUrl, nil
}

// MustNewRequest creates a new http get request or panics if it can't.
func MustNewRequest(method, urlStr string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err

	}
	return request, nil
}

func RunTestAuthenticationWithConfigurationSuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector, configuration func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config) {
	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) { token.Header["kid"] = "0" })
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.EqualValues(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should be equal")
}

func RunTestAuthenticationWithConfigurationFailure(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector, configuration func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config) {
	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) { token.Header["kid"] = "0" })
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")
}

func RunTestWithClientSecretSuccess(t *testing.T, clientSecret string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		pluginConfig.ClientSecret = clientSecret
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers("", "", configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(nil, clientSecret, jwksServer, pluginServer, jwtgo.SigningMethodHS256, "", nil, nil, func(token *jwtgo.Token) {})
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func RunTestWithClientSecretFailure(t *testing.T, serverClientSecret string, clientClientSecret string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		pluginConfig.ClientSecret = serverClientSecret
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers("", "", configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(nil, clientClientSecret, jwksServer, pluginServer, jwtgo.SigningMethodHS256, "", nil, nil, func(token *jwtgo.Token) {})
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}

func RunTestWithPublicKeySuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		certContent, err := certificate.CertFile.Read()
		assert.NoError(t, err)

		pluginConfig.PublicKey = string(certContent)

		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) {})
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func RunTestWithPublicKeyFailure(t *testing.T, signingMethod jwtgo.SigningMethod, publicKeyRootPath string, privateKeyRootPath string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		certContent, err := certificate.CertFile.Read()
		assert.NoError(t, err)

		pluginConfig.PublicKey = string(certContent)

		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(publicKeyRootPath, privateKeyRootPath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) {})
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}

func RunTestWithDiscoverySuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		if setIssuer {
			pluginConfig.Issuer = issuerUri.String()
		}
		if setOidcDiscoveryUri {
			pluginConfig.OidcDiscoveryAddress = oidcDiscoveryUri.String()
		}
		if setJwksUri {
			pluginConfig.JwksAddress = jwksUri.String()
		}

		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) { token.Header["kid"] = "0" })
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.EqualValues(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should be equal")
}

func RunTestWithDiscoveryFailure(t *testing.T, signingMethod jwtgo.SigningMethod, serverCertificatePath string, clientCertificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config {
		if setIssuer {
			pluginConfig.Issuer = issuerUri.String()
		}
		if setOidcDiscoveryUri {
			pluginConfig.OidcDiscoveryAddress = oidcDiscoveryUri.String()
		}
		if setJwksUri {
			pluginConfig.JwksAddress = jwksUri.String()
		}

		return pluginConfig
	}
	_, jwksServer, pluginServer, err := BuildTestServers(serverCertificatePath, serverCertificatePath, configuration)
	assert.NoError(t, err)

	defer jwksServer.Close()
	defer pluginServer.Close()

	clientCertificate, err := test_utils.GetCertificateFromPath(clientCertificatePath, clientCertificatePath)
	assert.NoError(t, err)

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(clientCertificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, func(token *jwtgo.Token) { token.Header["kid"] = "0" })
	assert.NoError(t, err)

	req, err := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	assert.NoError(t, err)

	tokenInjector(req, signedToken)

	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}
