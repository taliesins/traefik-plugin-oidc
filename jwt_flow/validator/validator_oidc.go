package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/jwks"
	"github.com/taliesins/traefik-plugin-oidc/jwt"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/log"
	"net/url"
	"regexp"
	"time"
)

func OidcTokenValidator(
	algorithmValidationRegex *regexp.Regexp,
	issuerValidationRegex *regexp.Regexp,
	audienceValidationRegex *regexp.Regexp,
	subjectValidationRegex *regexp.Regexp,
	idValidationRegex *regexp.Regexp,
	allowedClockSkew time.Duration,

	clientSecret []byte,
	publicKey interface{},
	issuer string,
	jwksAddress string,
	oidcDiscoveryAddress string,
	useDynamicValidation bool,

) jwt_flow.ValidateToken {
	return func(logger *log.Logger, ctx context.Context, tokenString string) (interface{}, error) {
		//TODO
		token, err := jwt.Parse(tokenString, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("could not parse the token: %w", err)
		}

		key, err := keyFunc(token, algorithmValidationRegex, issuerValidationRegex, clientSecret, publicKey, issuer, jwksAddress, oidcDiscoveryAddress, useDynamicValidation)
		if err != nil {
			return nil, err
		}

		clockTime := time.Now()
		validatedClaims, err := validateClaims(err, token, key, issuerValidationRegex, subjectValidationRegex, idValidationRegex, audienceValidationRegex, allowedClockSkew, clockTime)
		if err != nil {
			return nil, err
		}

		return validatedClaims, nil
	}
}

func validateClaims(err error, token *jwt.Token, key interface{}, issuerValidationRegex *regexp.Regexp, subjectValidationRegex *regexp.Regexp, idValidationRegex *regexp.Regexp, audienceValidationRegex *regexp.Regexp, allowedClockSkew time.Duration, clockTime time.Time) (*ValidatedClaims, error) {
	// claimDest := []interface{}{&jwt.Claims{}}

	if err = token.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	registeredClaims := token.Claims.(jwt.RegisteredClaims)

	if issuerValidationRegex != nil && !issuerValidationRegex.MatchString(registeredClaims.Issuer) {
		return nil, jwt.ErrTokenInvalidIssuer
	}

	if subjectValidationRegex != nil && !subjectValidationRegex.MatchString(registeredClaims.Subject) {
		//TODO
		return nil, jwt.ErrTokenMalformed
	}

	if idValidationRegex != nil && !idValidationRegex.MatchString(registeredClaims.ID) {
		return nil, jwt.ErrTokenInvalidId
	}

	if audienceValidationRegex != nil {
		for _, v := range registeredClaims.Audience {
			if !audienceValidationRegex.MatchString(v) {
				return nil, jwt.ErrTokenInvalidAudience
			}
		}
	}

	if !clockTime.IsZero() {
		if registeredClaims.NotBefore != nil && clockTime.Add(allowedClockSkew).Before(registeredClaims.NotBefore.Time) {
			return nil, jwt.ErrTokenNotValidYet
		}

		if registeredClaims.ExpiresAt != nil && clockTime.Add(-allowedClockSkew).After(registeredClaims.ExpiresAt.Time) {
			return nil, jwt.ErrTokenExpired
		}

		// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
		// something is misconfigured if this happens and we should not trust it.
		if registeredClaims.IssuedAt != nil && clockTime.Add(allowedClockSkew).Before(registeredClaims.IssuedAt.Time) {
			return nil, jwt.ErrTokenUsedBeforeIssued
		}
	}

	validatedClaims := &ValidatedClaims{
		RegisteredClaims: RegisteredClaims{
			Issuer:   registeredClaims.Issuer,
			Subject:  registeredClaims.Subject,
			Audience: registeredClaims.Audience,
			ID:       registeredClaims.ID,
		},
	}
	return validatedClaims, nil
}

func keyFunc(token *jwt.Token, algorithmValidationRegex *regexp.Regexp, issuerValidationRegex *regexp.Regexp, clientSecret []byte, publicKey interface{}, issuer string, jwksAddress string, oidcDiscoveryAddress string, useDynamicValidation bool) (interface{}, error) {
	currentAlgorithm := token.Header["Algorithm"].(string)
	currentKeyId := token.Header["KeyID"].(string)

	if algorithmValidationRegex != nil && !algorithmValidationRegex.MatchString(currentAlgorithm) {
		return nil, fmt.Errorf(
			"unsupported signing currentAlgorithm as token specified %q",
			currentAlgorithm,
		)
	}

	// HMAC with a config provided client secret
	if clientSecret != nil && currentKeyId == "" && (currentAlgorithm == "HS256" || currentAlgorithm == "HS384" || currentAlgorithm == "HS512") {
		return clientSecret, nil
	}

	if publicKey != nil && currentKeyId == "" {
		return publicKey, nil
	}

	if currentKeyId != "" && jwksAddress != "" {
		publicKey, _, err := jwks.GetPublicKeyFromJwksUri(currentKeyId, jwksAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to get public key from jwks address %s for currentKeyId %s with error %s", jwksAddress, currentKeyId, err)
		}
		return publicKey, nil
	}

	if currentKeyId != "" && oidcDiscoveryAddress != "" {
		publicKey, _, err := jwks.GetPublicKeyFromOpenIdConnectDiscoveryUri(currentKeyId, oidcDiscoveryAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to get public key from discovery address %s for currentKeyId %s with error %s", oidcDiscoveryAddress, currentKeyId, err)
		}
		return publicKey, nil
	}

	if currentKeyId != "" && useDynamicValidation {
		currentIssuer := ""
		// unsafeClaimsWithoutVerification := &jwt.Claims{}
		// err := token.UnsafeClaimsWithoutVerification(unsafeClaimsWithoutVerification)
		err := token.Claims.Valid()
		if err == nil {
			currentIssuer = token.Claims.(jwt.RegisteredClaims).Issuer
			if issuer != "" && currentIssuer != issuer {
				return nil, fmt.Errorf("failed validation on %s claim as value is %s", "iss", currentIssuer)
			}
			if currentIssuer != "" && issuerValidationRegex != nil && !issuerValidationRegex.MatchString(currentIssuer) {
				return nil, fmt.Errorf("failed validation on %s claim as value is %s", "iss", currentIssuer)
			}
		} else {
			err = nil
		}

		publicKey, _, err := jwks.GetPublicKeyFromIssuerUri(currentKeyId, currentIssuer)
		if err != nil {
			return nil, fmt.Errorf("unable to get public key from issuer %s for currentKeyId %s with error %s", currentIssuer, currentKeyId, err)
		}
		return publicKey, nil
	}

	return nil, fmt.Errorf("unable to get key to decode JWT. alg=%q, kid=%q", currentAlgorithm, currentKeyId)
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
