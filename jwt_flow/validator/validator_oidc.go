package validator

import (
	"context"
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/jwks"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"gopkg.in/square/go-jose.v2/jwt"
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
	return func(ctx context.Context, tokenString string) (interface{}, error) {
		token, err := jwt.ParseSigned(tokenString)
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

func validateClaims(err error, token *jwt.JSONWebToken, key interface{}, issuerValidationRegex *regexp.Regexp, subjectValidationRegex *regexp.Regexp, idValidationRegex *regexp.Regexp, audienceValidationRegex *regexp.Regexp, allowedClockSkew time.Duration, clockTime time.Time) (*ValidatedClaims, error) {
	claimDest := []interface{}{&jwt.Claims{}}

	if err = token.Claims(key, claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	registeredClaims := *claimDest[0].(*jwt.Claims)

	if issuerValidationRegex != nil && !issuerValidationRegex.MatchString(registeredClaims.Issuer) {
		return nil, jwt.ErrInvalidIssuer
	}

	if subjectValidationRegex != nil && !subjectValidationRegex.MatchString(registeredClaims.Subject) {
		return nil, jwt.ErrInvalidSubject
	}

	if idValidationRegex != nil && !idValidationRegex.MatchString(registeredClaims.ID) {
		return nil, jwt.ErrInvalidID
	}

	if audienceValidationRegex != nil {
		for _, v := range registeredClaims.Audience {
			if !issuerValidationRegex.MatchString(v) {
				return nil, jwt.ErrInvalidAudience
			}
		}
	}

	if !clockTime.IsZero() {
		if registeredClaims.NotBefore != nil && clockTime.Add(allowedClockSkew).Before(registeredClaims.NotBefore.Time()) {
			return nil, jwt.ErrNotValidYet
		}

		if registeredClaims.Expiry != nil && clockTime.Add(-allowedClockSkew).After(registeredClaims.Expiry.Time()) {
			return nil, jwt.ErrExpired
		}

		// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
		// something is misconfigured if this happens and we should not trust it.
		if registeredClaims.IssuedAt != nil && clockTime.Add(allowedClockSkew).Before(registeredClaims.IssuedAt.Time()) {
			return nil, jwt.ErrIssuedInTheFuture
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

func keyFunc(token *jwt.JSONWebToken, algorithmValidationRegex *regexp.Regexp, issuerValidationRegex *regexp.Regexp, clientSecret []byte, publicKey interface{}, issuer string, jwksAddress string, oidcDiscoveryAddress string, useDynamicValidation bool) (interface{}, error) {
	currentAlgorithm := token.Headers[0].Algorithm
	currentKeyId := token.Headers[0].KeyID

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

	if publicKey != nil && currentKeyId == "" && (issuer == "" && jwksAddress == "" && oidcDiscoveryAddress == "" && !useDynamicValidation) {
		//TODO: Validate for ES256,ES384,ES512?
		return publicKey, nil
	}

	if publicKey == nil && currentKeyId != "" && jwksAddress != "" {
		publicKey, _, err := jwks.GetPublicKeyFromJwksUri(currentKeyId, jwksAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to get public key from jwks address %s for currentKeyId %s with error %s", jwksAddress, currentKeyId, err)
		}
		return publicKey, nil
	}

	if publicKey == nil && currentKeyId != "" && oidcDiscoveryAddress != "" {
		publicKey, _, err := jwks.GetPublicKeyFromOpenIdConnectDiscoveryUri(currentKeyId, oidcDiscoveryAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to get public key from discovery address %s for currentKeyId %s with error %s", oidcDiscoveryAddress, currentKeyId, err)
		}
		return publicKey, nil
	}

	if publicKey == nil && currentKeyId == "" && useDynamicValidation {
		currentIssuer := ""
		unsafeClaimsWithoutVerification := &jwt.Claims{}
		err := token.UnsafeClaimsWithoutVerification(unsafeClaimsWithoutVerification)
		if err == nil {
			currentIssuer = unsafeClaimsWithoutVerification.Issuer
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
