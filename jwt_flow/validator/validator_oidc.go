package validator

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/taliesins/traefik-plugin-oidc/jwks"
	"github.com/taliesins/traefik-plugin-oidc/jwt"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
	"github.com/taliesins/traefik-plugin-oidc/log"
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
		// token, err := jwt.Parse(tokenString, keyFunc)
		// if err != nil {
		// 	return nil, fmt.Errorf("could not parse the token: %w", err)
		// }

		// key, err := keyFunc(token, algorithmValidationRegex, issuerValidationRegex, clientSecret, publicKey, issuer, jwksAddress, oidcDiscoveryAddress, useDynamicValidation)
		// if err != nil {
		// 	return nil, err
		// }

		// clockTime := time.Now()
		// validatedClaims, err := validateClaims(err, token, key, issuerValidationRegex, subjectValidationRegex, idValidationRegex, audienceValidationRegex, allowedClockSkew, clockTime)
		// if err != nil {
		// 	return nil, err
		// }
		//Here parse will do all the stuff
		token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			currentAlgorithm := token.Method.Alg()
			currentKeyId := ""
			if token.Header["kid"] != nil {
				currentKeyId = token.Header["kid"].(string)
			}

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
				jwksPublicKey, _, err := jwks.GetPublicKeyFromJwksUri(currentKeyId, jwksAddress)
				if err != nil {
					return nil, fmt.Errorf("unable to get public key from jwks address %s for currentKeyId %s with error %s", jwksAddress, currentKeyId, err)
				}
				return jwksPublicKey, nil
			}

			if currentKeyId != "" && oidcDiscoveryAddress != "" {
				jwksPublicKey, _, err := jwks.GetPublicKeyFromOpenIdConnectDiscoveryUri(currentKeyId, oidcDiscoveryAddress)
				if err != nil {
					return nil, fmt.Errorf("unable to get public key from discovery address %s for currentKeyId %s with error %s", oidcDiscoveryAddress, currentKeyId, err)
				}
				return jwksPublicKey, nil
			}

			if currentKeyId != "" && useDynamicValidation {
				currentIssuer := ""
				// unsafeClaimsWithoutVerification := &jwt.Claims{}
				// err := token.UnsafeClaimsWithoutVerification(unsafeClaimsWithoutVerification)
				err := token.Claims.Valid()
				if err == nil {
					currentIssuer = token.Claims.(*jwt.RegisteredClaims).Issuer
					if issuer != "" && currentIssuer != issuer {
						return nil, fmt.Errorf("failed validation on %s claim as value is %s", "iss", currentIssuer)
					}
					if currentIssuer != "" && issuerValidationRegex != nil && !issuerValidationRegex.MatchString(currentIssuer) {
						return nil, fmt.Errorf("failed validation on %s claim as value is %s", "iss", currentIssuer)
					}
				} else {
					err = nil
				}

				issuerPublicKey, _, err := jwks.GetPublicKeyFromIssuerUri(currentKeyId, currentIssuer)
				if err != nil {
					return nil, fmt.Errorf("unable to get public key from issuer %s for currentKeyId %s with error %s", currentIssuer, currentKeyId, err)
				}
				return issuerPublicKey, nil
			}

			return nil, fmt.Errorf("unable to get key to decode JWT. alg=%q, kid=%q", currentAlgorithm, currentKeyId)
		})

		if err != nil {
			return nil, err
		}
		clockTime := time.Now()
		validatedClaims, err := validateClaims(err, token, issuerValidationRegex, subjectValidationRegex, idValidationRegex, audienceValidationRegex, allowedClockSkew, clockTime)
		if err != nil {
			return nil, err
		}

		return validatedClaims, nil
	}
}

func validateClaims(err error, token *jwt.Token, issuerValidationRegex *regexp.Regexp, subjectValidationRegex *regexp.Regexp, idValidationRegex *regexp.Regexp, audienceValidationRegex *regexp.Regexp, allowedClockSkew time.Duration, clockTime time.Time) (*ValidatedClaims, error) {

	if err = token.Claims.Valid(); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}
	registeredClaims := token.Claims.(*jwt.RegisteredClaims)

	if issuerValidationRegex != nil && !issuerValidationRegex.MatchString(registeredClaims.Issuer) {
		return nil, jwt.ErrTokenInvalidIssuer
	}

	if subjectValidationRegex != nil && !subjectValidationRegex.MatchString(registeredClaims.Subject) {
		return nil, jwt.ErrTokenInvalidSubject
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
