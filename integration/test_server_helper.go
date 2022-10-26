package integration

import (
	"context"
	"encoding/json"
	"fmt"
	traefikPluginOidc "github.com/taliesins/traefik-plugin-oidc"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

func GetCertificateFromPath(publicKeyRootPath string, privateKeyRootPath string) (*jwt_certificate.Certificate, error) {
	_, filename, _, _ := runtime.Caller(0)

	currentDirectory := path.Dir(filename)
	currentDirectoryName := filepath.Base(currentDirectory)
	if currentDirectoryName == "reflect" {
		// We are running the tests using yeagi so fix the path by getting it relative to the GOPATH
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}

		goPath := filepath.Dir(filepath.Dir(ex))

		if os.PathSeparator == '\\' {
			currentDirectory = path.Join(goPath, "src\\github.com\\taliesins\\traefik-plugin-oidc\\integration")
		} else {
			currentDirectory = path.Join(goPath, "src/github.com/taliesins/traefik-plugin-oidc/integration")
		}
	}

	publicKeyPath := fmt.Sprintf("%s.crt", path.Join(currentDirectory, publicKeyRootPath))
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", path.Join(currentDirectory, publicKeyRootPath))
	}

	privateKeyPath := fmt.Sprintf("%s.key", path.Join(currentDirectory, privateKeyRootPath))

	certificate := &jwt_certificate.Certificate{
		CertFile: jwt_certificate.FileOrContent(publicKeyPath),
		KeyFile:  jwt_certificate.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	return certificate, nil
}

func getJsonWebset(certificate *jwt_certificate.Certificate) (*jose.JSONWebKeySet, error) {
	publicKeyData, err := certificate.CertFile.Read()
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt_certificate.GetPublicKey(publicKeyData)
	if err != nil {
		return nil, err
	}

	algorithm, _, _, _, err := jwt_certificate.GetJwtParametersFromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	jsonWebKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       publicKey,
				KeyID:     "0",
				Use:       "sig",
				Algorithm: algorithm,
			},
		},
	}

	return jsonWebKeySet, nil
}

func BuildTestJwkServer(publicKeyRootPath string, privateKeyRootPath string, oidcDiscoveryUriPath string, jwksUriPath string) (certificate *jwt_certificate.Certificate, jwksServer *httptest.Server, err error) {
	if publicKeyRootPath == "" {
		publicKeyRootPath = "fixtures/signing/rsa"
	}

	if privateKeyRootPath == "" {
		privateKeyRootPath = "fixtures/signing/rsa"
	}

	certificate, err = GetCertificateFromPath(publicKeyRootPath, privateKeyRootPath)
	if err != nil {
		return nil, nil, err
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		return nil, nil, err
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		return nil, nil, err
	}

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			jwksUri := fmt.Sprintf("https://%s%s", r.Host, jwksUriPath)
			_, err := fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
			if err != nil {
				return
			}
		} else if r.RequestURI == jwksUriPath {
			_, err2 := w.Write(jsonWebKeySetJson)
			if err2 != nil {
				return
			}
		} else {
			panic("Don't know how to handle request")
		}
	}))

	return certificate, jwksServer, nil
}

func buildPluginServer(cfg *traefikPluginOidc.Config) (server *httptest.Server, err error) {
	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, fmt.Sprintf(`{"RequestUri":"%s", "Referer":"%s"}`, r.URL.String(), r.Referer()))
		if err != nil {
			return
		}
	})

	handler, err := traefikPluginOidc.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		return nil, err
	}

	pluginServer := httptest.NewTLSServer(handler)

	return pluginServer, nil
}

type overridePluginConfiguration func(pluginConfig *traefikPluginOidc.Config, certificate *jwt_certificate.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) *traefikPluginOidc.Config

func BuildTestServers(publicKeyRootPath string, privateKeyRootPath string, overridePluginConfiguration overridePluginConfiguration) (certificate *jwt_certificate.Certificate, jwksServer *httptest.Server, pluginServer *httptest.Server, err error) {
	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	certificate, jwksServer, err = BuildTestJwkServer(publicKeyRootPath, privateKeyRootPath, oidcDiscoveryUriPath, jwksUriPath)
	if err != nil {
		return nil, nil, nil, err
	}

	ssoAddressTemplate := "https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
	issuerUri, err := url.Parse(jwksServer.URL)
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	oidcDiscoveryUri, err := url.Parse(fmt.Sprintf("%s%s", jwksServer.URL, oidcDiscoveryUriPath))
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	jwksUri, err := url.Parse(fmt.Sprintf("%s%s", jwksServer.URL, jwksUriPath))
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	pluginConfiguration := traefikPluginOidc.CreateConfig()

	if overridePluginConfiguration != nil {
		overridePluginConfiguration(pluginConfiguration, certificate, ssoAddressTemplate, issuerUri, oidcDiscoveryUri, jwksUri)
	} else {
		pluginConfiguration.OidcDiscoveryAddress = oidcDiscoveryUri.String()
		pluginConfiguration.SsoRedirectUrlAddressTemplate = ssoAddressTemplate
		pluginConfiguration.SsoRedirectUrlMacPrivateKey = certificate.KeyFile.String()
	}

	pluginServer, err = buildPluginServer(pluginConfiguration)
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	return certificate, jwksServer, pluginServer, nil
}
