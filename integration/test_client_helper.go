package integration

import (
	"crypto/tls"
	"fmt"
	jwtgo "github.com/golang-jwt/jwt/v4"
	guuid "github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	pluginoidc "github.com/taliesins/traefik-plugin-oidc"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type overrideClient func(*http.Client) *http.Client

type overrideClaims func(claims *jwtgo.RegisteredClaims, certificate *traefiktls.Certificate, jwksServer *httptest.Server, middlwareServer *httptest.Server) *jwtgo.RegisteredClaims

type overrideToken func(*jwtgo.Token)

func BuildTestClient(certificate *traefiktls.Certificate, clientSecret string, jwksServer *httptest.Server, middlwareServer *httptest.Server, tokenSigningMethod jwtgo.SigningMethod, requestPath string, overrideClient overrideClient, overrideClaims overrideClaims, overrideToken overrideToken) (client *http.Client, nonce string, issuedAt string, signedToken string, clientRequestUrl *url.URL, expectedRedirectorUrl *url.URL, err error) {
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
	base, err := url.Parse(middlwareServer.URL)
	clientRequestUrl = base.ResolveReference(clientRequestPath)

	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	nonce = guuid.NewString()
	issuedAt = strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

	//Work out the url that the SSO would redirect back to
	expectedRedirectorUrl, err = url.Parse(fmt.Sprintf("%s://%s%s?iat=%s&nonce=%s&redirect_uri=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, sso_redirector.RedirectorPath, issuedAt, nonce, url.QueryEscape(clientRequestUrl.String())))
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	var privateKey interface{}
	if clientSecret != "" {
		if tokenSigningMethod != jwtgo.SigningMethodHS256 && tokenSigningMethod != jwtgo.SigningMethodHS384 && tokenSigningMethod != jwtgo.SigningMethodHS512 {
			return nil, "", "", "", nil, nil, fmt.Errorf("certificate needs to be specified with this signing method")
		}

		privateKey = []byte(clientSecret)
	} else if certificate != nil {
		if tokenSigningMethod == jwtgo.SigningMethodHS256 || tokenSigningMethod == jwtgo.SigningMethodHS384 || tokenSigningMethod == jwtgo.SigningMethodHS512 {
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

	macStrength := sso_redirector.MacStrength_256
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
	} else {
		token.Header["kid"] = "0"
	}

	signedToken, err = token.SignedString(privateKey)
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	return client, nonce, issuedAt, signedToken, clientRequestUrl, expectedRedirectorUrl, nil
}

// MustNewRequest creates a new http get request or panics if it can't.
func MustNewRequest(method, urlStr string, body io.Reader) *http.Request {
	request, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		panic(fmt.Sprintf("failed to create HTTP %s Request for '%s': %s", method, urlStr, err))
	}
	return request
}

func RunTestAuthenticationWithConfigurationSuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector, configuration func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config) {
	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

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

func RunTestAuthenticationWithConfigurationFailure(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector, configuration func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config) {
	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")
}

func RunTestWithClientSecretSuccess(t *testing.T, clientSecret string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.ClientSecret = clientSecret
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers("", "", configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(nil, clientSecret, jwksServer, pluginServer, jwtgo.SigningMethodHS256, "", nil, nil, func(token *jwtgo.Token) {})

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func RunTestWithClientSecretFailure(t *testing.T, serverClientSecret string, clientClientSecret string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		pluginConfig.ClientSecret = serverClientSecret
		return pluginConfig
	}

	_, jwksServer, pluginServer, err := BuildTestServers("", "", configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(nil, clientClientSecret, jwksServer, pluginServer, jwtgo.SigningMethodHS256, "", nil, nil, func(token *jwtgo.Token) {})

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}

func RunTestWithPublicKeySuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		certContent, err := certificate.CertFile.Read()
		if err != nil {
			panic(err)
		}

		pluginConfig.PublicKey = string(certContent)

		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(certificatePath, certificatePath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func RunTestWithPublicKeyFailure(t *testing.T, signingMethod jwtgo.SigningMethod, publicKeyRootPath string, privateKeyRootPath string, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
		certContent, err := certificate.CertFile.Read()
		if err != nil {
			panic(err)
		}

		pluginConfig.PublicKey = string(certContent)

		return pluginConfig
	}

	certificate, jwksServer, pluginServer, err := BuildTestServers(publicKeyRootPath, privateKeyRootPath, configuration)
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(certificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}

func RunTestWithDiscoverySuccess(t *testing.T, signingMethod jwtgo.SigningMethod, certificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
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
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

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

func RunTestWithDiscoveryFailure(t *testing.T, signingMethod jwtgo.SigningMethod, serverCertificatePath string, clientCertificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenInjector jwt_flow.TokenInjector) {
	configuration := func(pluginConfig *pluginoidc.Config, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *pluginoidc.Config {
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
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer pluginServer.Close()

	clientCertificate, err := GetCertificateFromPath(clientCertificatePath, clientCertificatePath)
	if err != nil {
		panic(err)
	}

	client, _, _, signedToken, requestUrl, _, err := BuildTestClient(clientCertificate, "", jwksServer, pluginServer, signingMethod, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	tokenInjector(req, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}`+"\n", string(body), "they should not be equal")
}
