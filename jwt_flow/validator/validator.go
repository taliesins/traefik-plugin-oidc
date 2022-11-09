package validator

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/taliesins/traefik-plugin-oidc/jwt"
	"time"
)

// Signature algorithms
const (
	EdDSA = SignatureAlgorithm("EdDSA")
	HS256 = SignatureAlgorithm("HS256") // HMAC using SHA-256
	HS384 = SignatureAlgorithm("HS384") // HMAC using SHA-384
	HS512 = SignatureAlgorithm("HS512") // HMAC using SHA-512
	RS256 = SignatureAlgorithm("RS256") // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = SignatureAlgorithm("RS384") // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = SignatureAlgorithm("RS512") // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = SignatureAlgorithm("ES256") // ECDSA using P-256 and SHA-256
	ES384 = SignatureAlgorithm("ES384") // ECDSA using P-384 and SHA-384
	ES512 = SignatureAlgorithm("ES512") // ECDSA using P-521 and SHA-512
	PS256 = SignatureAlgorithm("PS256") // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = SignatureAlgorithm("PS384") // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = SignatureAlgorithm("PS512") // RSASSA-PSS using SHA512 and MGF1-SHA512
)

// Validator to use with the jose v2 package.
type Validator struct {
	keyFunc            func(context.Context) (interface{}, error) // Required.
	signatureAlgorithm SignatureAlgorithm                         // Required.
	expectedClaims     jwt.Claims                                 // Internal.
	customClaims       func() CustomClaims                        // Optional.
	allowedClockSkew   time.Duration                              // Optional.
}

// SignatureAlgorithm is a signature algorithm.
type SignatureAlgorithm string

var allowedSigningAlgorithms = map[SignatureAlgorithm]bool{
	EdDSA: true,
	HS256: true,
	HS384: true,
	HS512: true,
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
}

// New sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
func New(
	keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm SignatureAlgorithm,
	issuerURL string,
	audience []string,
	opts ...Option,
) (*Validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}
	if issuerURL == "" {
		return nil, errors.New("issuer url is required but was empty")
	}
	if audience == nil {
		return nil, errors.New("audience is required but was nil")
	}
	if _, ok := allowedSigningAlgorithms[signatureAlgorithm]; !ok {
		return nil, errors.New("unsupported signature algorithm")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		expectedClaims: jwt.RegisteredClaims{
			Issuer:   issuerURL,
			Audience: audience,
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	//TODO
	token, err := jwt.Parse(tokenString, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}
	if string(v.signatureAlgorithm) != token.Header["Algorithm"] {
		return nil, fmt.Errorf(
			"expected %q signing algorithm but token specified %q",
			v.signatureAlgorithm,
			token.Header["Algorithm"],
		)
	}

	_, err = v.keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	// claimDest := []interface{}{&jwt.Claims}
	claimDest := []interface{}{}

	if v.customClaims != nil {
		claimDest = append(claimDest, v.customClaims())
	}

	if err = token.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	registeredClaims := *claimDest[0].(*jwt.RegisteredClaims)
	//TODO
	if err = registeredClaims.Valid(); err != nil {
		return nil, fmt.Errorf("expected claims not validated: %w", err)
	}

	validatedClaims := &ValidatedClaims{
		RegisteredClaims: RegisteredClaims{
			Issuer:   registeredClaims.Issuer,
			Subject:  registeredClaims.Subject,
			Audience: registeredClaims.Audience,
			ID:       registeredClaims.ID,
		},
	}

	if registeredClaims.ExpiresAt != nil {
		validatedClaims.RegisteredClaims.Expiry = registeredClaims.ExpiresAt.Unix()
	}

	if registeredClaims.NotBefore != nil {
		validatedClaims.RegisteredClaims.NotBefore = registeredClaims.NotBefore.Unix()
	}

	if registeredClaims.IssuedAt != nil {
		validatedClaims.RegisteredClaims.IssuedAt = registeredClaims.IssuedAt.Unix()
	}

	if v.customClaims != nil {
		validatedClaims.CustomClaims = claimDest[1].(CustomClaims)
		if err = validatedClaims.CustomClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	return validatedClaims, nil
}
