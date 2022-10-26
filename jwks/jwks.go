package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/taliesins/traefik-plugin-oidc/jwt_certificate"
)

var lruCache *lru.Cache

type openIdConnectDiscoveryCacheValue struct {
	JwksUri string
}

type jwksCacheValue struct {
	SigningAlgorithm x509.SignatureAlgorithm
	Data             interface{}
	Expiry           time.Time
}

func init() {
	l, err := lru.NewWithEvict(128, func(key interface{}, value interface{}) {})
	if err != nil {
		log.Fatal("Cannot initialize cache")
	}
	lruCache = l
}

func DownloadOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(openIdConnectDiscoveryUri)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	err = resp.Body.Close()
	if err != nil {
		return "", err
	}

	data := make(map[string]interface{})
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	jwksUri, ok := data["jwks_uri"].(string)

	if !ok {
		return "", fmt.Errorf("json does not contain jwks_uri: %s", err)
	}

	return jwksUri, nil
}

func GetJwksUriFromOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri string) (jwksUri string, err error) {
	// Try to get and return existing entry from cache. If cache is expired,
	// it will try to proceed with rest of the function call
	cached, ok := lruCache.Get(openIdConnectDiscoveryUri)
	if ok {
		jwksUri = cached.(*openIdConnectDiscoveryCacheValue).JwksUri
		return jwksUri, nil
	}

	jwksUri, err = DownloadOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri)

	if err != nil {
		return "", err
	}

	lruCache.Add(openIdConnectDiscoveryUri, &openIdConnectDiscoveryCacheValue{
		JwksUri: jwksUri,
	})

	return jwksUri, nil
}

func GetPublicKeyFromOpenIdConnectDiscoveryUri(kid string, openIdConnectDiscoveryUri string) (interface{}, x509.SignatureAlgorithm, error) {
	explicitJwksUri, err := GetJwksUriFromOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unable to retrieve jwks uri: %s", err)
	}

	return GetPublicKeyFromJwksUri(kid, explicitJwksUri)
}

func GetPublicKeyFromIssuerUri(kid string, issuerUri string) (interface{}, x509.SignatureAlgorithm, error) {
	wellKnownUri, err := url.Parse(".well-known/openid-configuration")
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	openIdConnectDiscoveryUri, err := url.Parse(issuerUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	openIdConnectDiscoveryUri = openIdConnectDiscoveryUri.ResolveReference(wellKnownUri)

	return GetPublicKeyFromOpenIdConnectDiscoveryUri(kid, openIdConnectDiscoveryUri.String())
}

func DownloadJwksUri(jwksUri string) (*JSONWebKeySet, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(jwksUri)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	jwks := &JSONWebKeySet{}
	err = json.Unmarshal(body, jwks)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func GetPublicKeyFromJwksUri(kid string, jwksUri string) (interface{}, x509.SignatureAlgorithm, error) {
	cacheKey := fmt.Sprintf("%s|%s", jwksUri, kid)

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try to proceed with rest of the function call
	cached, ok := lruCache.Get(cacheKey)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, val.SigningAlgorithm, nil
		}
	}

	jwks, err := DownloadJwksUri(jwksUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	publicKey, signingAlgorithm, err := GetPublicKeyFromJwks(jwks, kid)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	lruCache.Add(cacheKey, &jwksCacheValue{
		SigningAlgorithm: signingAlgorithm,
		Data:             publicKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return publicKey, signingAlgorithm, nil
}

func GetPrivateKeyFromFileOrContent(certificateFileOrContents string) (interface{}, x509.SignatureAlgorithm, error) {
	// Try to get and return existing entry from cache. If cache is expired,
	// it will try to proceed with rest of the function call
	cached, ok := lruCache.Get(certificateFileOrContents)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, val.SigningAlgorithm, nil
		}
	}

	pemData, err := jwt_certificate.FileOrContent(certificateFileOrContents).Read()
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	privateKey, err := jwt_certificate.GetPrivateKey(pemData)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	// Store value in cache
	lruCache.Add(certificateFileOrContents, &jwksCacheValue{
		SigningAlgorithm: x509.UnknownSignatureAlgorithm,
		Data:             privateKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return privateKey, x509.UnknownSignatureAlgorithm, nil
}

func GetPublicKeyFromJwks(jwks *JSONWebKeySet, kid string) (interface{}, x509.SignatureAlgorithm, error) {
	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			if !key.Valid() {
				return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("invalid JWKS key")
			}
			if len(key.Certificates) > 0 {
				return key.Key, key.Certificates[0].SignatureAlgorithm, nil
			} else {
				return key.Key, x509.UnknownSignatureAlgorithm, nil
			}
		}
	}

	jwksJson, _ := json.Marshal(jwks)
	return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("JsonWebKeySet does not contain key: kid=%s jwks=%s", kid, jwksJson)
}

func GetPublicKeyFromFileOrContent(certificateFileOrContents string) (interface{}, x509.SignatureAlgorithm, error) {
	// Try to get and return existing entry from cache. If cache is expired,
	// it will try to proceed with rest of the function call
	cached, ok := lruCache.Get(certificateFileOrContents)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, val.SigningAlgorithm, nil
		}
	}

	pemData, err := jwt_certificate.FileOrContent(certificateFileOrContents).Read()
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	publicKey, err := jwt_certificate.GetPublicKey(pemData)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	_, _, _, signingAlgorithm, err := jwt_certificate.GetJwtParametersFromPublicKey(publicKey)

	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	// Store value in cache
	lruCache.Add(certificateFileOrContents, &jwksCacheValue{
		SigningAlgorithm: signingAlgorithm,
		Data:             publicKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return publicKey, signingAlgorithm, nil
}

// JSONWebKeySet represents a JWK Set object.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey represents a public or private key in JWK format.
type JSONWebKey struct {
	// Cryptographic key, can be a symmetric or asymmetric key.
	Key interface{}
	// Key identifier, parsed from `kid` header.
	KeyID string
	// Key algorithm, parsed from `alg` header.
	Algorithm string
	// Key use, parsed from `use` header.
	Use string

	// X.509 certificate chain, parsed from `x5c` header.
	Certificates []*x509.Certificate
	// X.509 certificate URL, parsed from `x5u` header.
	CertificatesURL *url.URL
	// X.509 certificate thumbprint (SHA-1), parsed from `x5t` header.
	CertificateThumbprintSHA1 []byte
	// X.509 certificate thumbprint (SHA-256), parsed from `x5t#S256` header.
	CertificateThumbprintSHA256 []byte
}

// Valid checks that the key contains the expected parameters.
func (k *JSONWebKey) Valid() bool {
	if k.Key == nil {
		return false
	}
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.X == nil || key.Y == nil {
			return false
		}
	case *ecdsa.PrivateKey:
		if key.Curve == nil || key.X == nil || key.Y == nil || key.D == nil {
			return false
		}
	case *rsa.PublicKey:
		if key.N == nil || key.E == 0 {
			return false
		}
	case *rsa.PrivateKey:
		if key.N == nil || key.E == 0 || key.D == nil || len(key.Primes) < 2 {
			return false
		}
	case ed25519.PublicKey:
		if len(key) != 32 {
			return false
		}
	case ed25519.PrivateKey:
		if len(key) != 64 {
			return false
		}
	default:
		return false
	}
	return true
}
