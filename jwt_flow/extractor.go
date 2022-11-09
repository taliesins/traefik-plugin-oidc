package jwt_flow

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/taliesins/traefik-plugin-oidc/log"
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
)

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error. An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed. In the case where a token is simply not present, this should not
// be treated as an error. An empty string should be returned in that case.
type TokenExtractor func(logger *log.Logger, r *http.Request) (string, error)

// AuthHeaderTokenExtractor is a TokenExtractor that takes a request
// and extracts the token from the Authorization header.
func AuthHeaderTokenExtractor(logger *log.Logger, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no JWT.
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	token := authHeaderParts[1]
	if token != "" {
		logger.Debug("Token extracted from auth header", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path)})
		return token, nil
	}

	return "", nil // No error, just no JWT.
}

// CookieTokenExtractor builds a TokenExtractor that takes a request and
// extracts the token from the cookie using the passed in cookieName.
func CookieTokenExtractor(cookieName string) TokenExtractor {
	return func(logger *log.Logger, r *http.Request) (string, error) {
		logger.Debug("[CookieTokenExtractor] Request url query : ", []encoder.Field{encoder.String("RawQuery", r.URL.RawQuery)})
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			if err == http.ErrNoCookie {
				logger.Debug("[CookieTokenExtractor] No cookie found", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("Cookie", cookieName)})
				return "", nil // No error, just no JWT.
			}
			return "", err
		}

		if cookie != nil {
			token := cookie.Value
			if token != "" {
				logger.Debug("[CookieTokenExtractor] Token extracted from cookie", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("Cookie", cookie.Name)})
				return token, nil
			}
		}

		logger.Debug("[CookieTokenExtractor] Unable to extract token extracted from cookie", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("Cookie", cookie.Name)})

		return "", nil // No error, just no JWT.
	}
}

// FormTokenExtractor returns a TokenExtractor that extracts
// the token from a form post.
func FormTokenExtractor(urlPathPrefix string, param string) TokenExtractor {
	return func(logger *log.Logger, r *http.Request) (string, error) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, urlPathPrefix) {
			err := r.ParseForm()
			if err == nil {
				token := r.Form.Get(param)
				if token != "" {
					logger.Debug("[FormTokenExtractor] Token extracted from form post", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("param", param)})
					return token, nil
				}
			}
		}
		logger.Debug("[FormTokenExtractor] No token extracted from form post", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("param", param)})

		return "", nil // No error, just no JWT.
	}
}

// ParameterTokenExtractor returns a TokenExtractor that extracts
// the token from the specified query string parameter.
func ParameterTokenExtractor(param string) TokenExtractor {
	return func(logger *log.Logger, r *http.Request) (string, error) {
		token := r.URL.Query().Get(param)
		if token != "" {
			logger.Debug("[ParameterTokenExtractor] Token extracted from parameter", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("param", param)})
			return token, nil
		}

		logger.Debug("[ParameterTokenExtractor] No token extracted from parameter", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("param", param)})

		return "", nil // No error, just no JWT.
	}
}

// MultiTokenExtractor returns a TokenExtractor that runs multiple TokenExtractors
// and takes the one that does not return an empty token. If a TokenExtractor
// returns an error that error is immediately returned.
func MultiTokenExtractor(extractors ...TokenExtractor) TokenExtractor {
	return func(logger *log.Logger, r *http.Request) (string, error) {
		for _, ex := range extractors {
			token, err := ex(logger, r)
			if err != nil {
				return "", err
			}

			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}
