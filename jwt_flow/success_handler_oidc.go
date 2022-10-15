package jwt_flow

import (
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"net/http"
	"strings"
	"time"
)

// OidcSuccessHandler is the oidc error handler implementation for the
// JWTMiddleware.
func OidcSuccessHandler(
	key interface{},
	macStrength sso_redirector.MacStrength,
	allowedClockSkew time.Duration,
) SuccessHandler {
	return func(next http.Handler, w http.ResponseWriter, r *http.Request, token string) {
		if strings.HasPrefix(r.URL.Path, sso_redirector.RedirectorPath) {
			if token != "" {
				redirectUrl, err := sso_redirector.GetRedirectUrl(r, key, macStrength, allowedClockSkew)
				if err != nil {
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}

				// var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
				sessionCookie := sso_redirector.GetCookie(r.URL, token)
				http.SetCookie(w, sessionCookie)
				http.Redirect(w, r, redirectUrl.String(), http.StatusSeeOther)
				return
			} else {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
		}

		next.ServeHTTP(w, r)
		return
	}
}
