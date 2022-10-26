package jwt_certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/url"
)

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

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
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

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken struct {
	payload           func(k interface{}) ([]byte, error)
	unverifiedPayload func() []byte
	Headers           []Header
}

// Header represents the read-only JOSE header for JWE/JWS objects.
type Header struct {
	KeyID      string
	JSONWebKey *JSONWebKey
	Algorithm  string
	Nonce      string

	// Unverified certificate chain parsed from x5c header.
	certificates []*x509.Certificate

	// Any headers not recognised above get unmarshalled
	// from JSON in a generic manner and placed in this map.
	ExtraHeaders map[HeaderKey]interface{}
}

type HeaderKey string
