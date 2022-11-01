package jwt_flow

import (
	"context"
	"fmt"
	"github.com/taliesins/traefik-plugin-oidc/log"
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
	"net/http"
	"regexp"
)

// ContextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
type ContextKey struct{}

type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	successHandler      SuccessHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
	ignorePathRegex     *regexp.Regexp
}

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(logger *log.Logger, context context.Context, token string) (interface{}, error)

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
func New(validateToken ValidateToken, opts ...Option) *JWTMiddleware {
	m := &JWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultErrorHandler,
		successHandler:      DefaultSuccessHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
		ignorePathRegex:     nil,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Flow is the orchestration flow that is used
type Flow func(logger *log.Logger, w http.ResponseWriter, r *http.Request)

// DefaultFlow is jwt token extraction, jwt token validation and then either success or failure handlers
func (m *JWTMiddleware) DefaultFlow(next http.Handler) Flow {
	return func(logger *log.Logger, w http.ResponseWriter, r *http.Request) {
		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			logger.Debug("Skipping validation as its an options request", []encoder.Field{encoder.String("requestMethod", r.Method)})
			m.successHandler(logger, next, w, r, "")
			return
		}

		if m.ignorePathRegex != nil && m.ignorePathRegex.MatchString(r.URL.Path) {
			logger.Debug("Skipping validation as request matches ignore regex path", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path)})
			m.successHandler(logger, next, w, r, "")
			return
		}

		token, err := m.tokenExtractor(logger, r)
		if err != nil {
			// This is not ErrJWTMissing because an error here means that the
			// tokenExtractor had an error and _not_ that the token was missing.
			logger.Debug("Was not able to extract token", []encoder.Field{encoder.Error(err), encoder.String("requestUrlPath", r.URL.Path)})
			m.errorHandler(logger, w, r, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if token == "" {
			// If credentials are optional continue
			// onto next without validating.
			if m.credentialsOptional {
				logger.Debug("Credentials have not been supplied but they are optional", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path)})
				m.successHandler(logger, next, w, r, "")
				return
			}

			// Credentials were not optional so we error.
			logger.Debug("Token is empty and it is not optional", []encoder.Field{encoder.Error(err), encoder.String("requestUrlPath", r.URL.Path)})
			m.errorHandler(logger, w, r, ErrJWTMissing)
			return
		}

		// Validate the token using the token validator.
		validToken, err := m.validateToken(logger, r.Context(), token)
		if err != nil {
			logger.Debug("Not able to validate token", []encoder.Field{encoder.Error(err), encoder.String("token", token)})
			m.errorHandler(logger, w, r, &invalidError{details: err})
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
		logger.Debug("Valid token", []encoder.Field{encoder.String("token", token)})
		m.successHandler(logger, next, w, r, token)
		return
	}
}
