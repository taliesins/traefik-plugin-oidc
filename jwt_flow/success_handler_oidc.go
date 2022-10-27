package jwt_flow

import (
	"github.com/taliesins/traefik-plugin-oidc/log"
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"net/http"
	"strings"
	"time"
)

// OidcSuccessHandler is the oidc error handler implementation for the
// JWTMiddleware.
func OidcSuccessHandler(
	ssoRedirectUrlMacSigningKey interface{},
	ssoRedirectUrlMacStrength sso_redirector.HmacStrength,
	ssoRedirectUrlMacAllowedClockSkew time.Duration,
) SuccessHandler {
	return func(logger *log.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, token string) {
		if strings.HasPrefix(r.URL.Path, sso_redirector.RedirectorPath) {
			if token == "" {
				logger.Debug("No token was passed for the request", encoder.String("requestUrlPath", r.URL.Path))
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			redirectUrl, err := sso_redirector.GetRedirectUrl(r, ssoRedirectUrlMacSigningKey, ssoRedirectUrlMacStrength, ssoRedirectUrlMacAllowedClockSkew)
			if err != nil {
				logger.Error("No token was passed for the request", encoder.Error(err))
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}

			logger.Debug("Adding token session cookie and redirecting to redirect url", encoder.String("requestUrlPath", r.URL.Path), encoder.String("redirectUrl", redirectUrl.String()))
			// var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
			sessionCookie := sso_redirector.GetCookie(r.URL, token)
			http.SetCookie(w, sessionCookie)
			http.Redirect(w, r, redirectUrl.String(), http.StatusSeeOther)
			return
		}

		logger.Debug("Request passed validation and is passed onto the next handler", encoder.String("requestUrlPath", r.URL.Path))
		next.ServeHTTP(w, r)
		return
	}
}
