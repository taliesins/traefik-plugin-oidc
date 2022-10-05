package jwt_flow

import (
	"fmt"
	guuid "github.com/google/uuid"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// OidcErrorHandler is the oidc error handler implementation for the
// JWTMiddleware.
func OidcErrorHandler(
	ssoRedirectUrlTemplate *template.Template,
	key interface{},
	macStrength sso_redirector.MacStrength,
) ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if ssoRedirectUrlTemplate == nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.RedirectorPath) {
			//Drop any pre-existing cookie as it should be dead now
			sessionCookie := sso_redirector.GetExpiredSessionCookie(r.URL)
			http.SetCookie(w, sessionCookie)

			//Prevent endless loop if callback address, no one should be calling this directly without an id_token set
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		nonce := guuid.NewString()
		issuedAt := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

		var redirectorUrl *url.URL
		if key != nil {
			redirectorUrl, err = sso_redirector.GetRedirectorUrl(r, key, macStrength, nonce, issuedAt)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.CallbackPath) {
			if strings.HasPrefix(r.Referer(), sso_redirector.CallbackPath) {
				//Referrer was from callbackPath, so stop endless loop
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			//callback page for sso
			ssoCallbackPage, err := sso_redirector.RenderSsoCallbackPageTemplate(redirectorUrl)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			//The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, ssoCallbackPage)
			return
		}

		ssoRedirectUrl, err := sso_redirector.RenderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate, redirectorUrl, nonce, issuedAt)
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		//This will allow browsers to default to implicit flow
		redirectToSsoPage, err := sso_redirector.RenderRedirectToSsoPageTemplate(ssoRedirectUrl, "")
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, redirectToSsoPage)
	}
}
