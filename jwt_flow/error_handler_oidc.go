package jwt_flow

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	guuid "github.com/google/uuid"
	"github.com/taliesins/traefik-plugin-oidc/log"
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
)

// OidcErrorHandler is the oidc error handler implementation for the
// JWTMiddleware.
func OidcErrorHandler(
	ssoRedirectUrlTemplate *template.Template,
	ssoRedirectUrlMacSigningKey interface{},
	ssoRedirectUrlMacStrength sso_redirector.HmacStrength,
) ErrorHandler {
	return func(logger *log.Logger, w http.ResponseWriter, r *http.Request, err error) {

		if ssoRedirectUrlTemplate == nil {
			logger.Debug("No ssoRedirectUrlTemplate specified", nil)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.RedirectorPath) {
			logger.Debug("Drop token session cookie as we need to be redirected to SSO for an expired/invalid token", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("redirectorPath", sso_redirector.RedirectorPath)})

			//Drop any pre-existing cookie as it should be dead now
			sessionCookie := sso_redirector.GetExpiredSessionCookie(r.URL)
			http.SetCookie(w, sessionCookie)

			//Prevent endless loop if callback address, no one should be calling this directly without an id_token set
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		nonce := guuid.NewString()
		issuedAt := strconv.FormatInt(time.Now().UTC().Unix(), 10)

		var redirectorUrl *url.URL
		if ssoRedirectUrlMacSigningKey != nil {
			redirectorUrl, err = sso_redirector.GetRedirectorUrl(r, ssoRedirectUrlMacSigningKey, ssoRedirectUrlMacStrength, nonce, issuedAt)
			if err != nil {
				logger.Error("Unable to get redirector url", []encoder.Field{encoder.Error(err)})
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
		} else {
			logger.Error("No ssoRedirectUrlMacSigningKey specified", nil)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.CallbackPath) {
			if strings.HasPrefix(r.Referer(), sso_redirector.CallbackPath) {
				logger.Debug("Dropping request to prevent endless loop when referrer was from callbackPath", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path), encoder.String("referer", r.Referer()), encoder.String("redirectorPath", sso_redirector.RedirectorPath)})

				//Referrer was from callbackPath, so stop endless loop
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			//callback page for sso
			ssoCallbackPage, err := sso_redirector.RenderSsoCallbackPageTemplate(redirectorUrl)
			if err != nil {
				logger.Error("Unable to render sso callback page template", []encoder.Field{encoder.Error(err), encoder.String("redirectorUrl", redirectorUrl.String())})
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			//The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value
			logger.Debug("The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path)})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, ssoCallbackPage)
			return
		}

		ssoRedirectUrl, err := sso_redirector.RenderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate, redirectorUrl, nonce, issuedAt)
		if err != nil {
			logger.Error("Unable to render sso redirect url template", []encoder.Field{encoder.Error(err), encoder.String("redirectorUrl", redirectorUrl.String()), encoder.String("nonce", nonce), encoder.String("issuedAt", issuedAt)})
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		//This will allow browsers to default to implicit flow
		redirectToSsoPage, err := sso_redirector.RenderRedirectToSsoPageTemplate(ssoRedirectUrl, "")
		if err != nil {
			logger.Error("Unable to render sso redirect to sso page template", []encoder.Field{encoder.Error(err), encoder.String("ssoRedirectUrl", ssoRedirectUrl.String()), encoder.String("nonce", nonce), encoder.String("issuedAt", issuedAt)})
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Debug("Redirect to sso page using javascript", []encoder.Field{encoder.String("requestUrlPath", r.URL.Path)})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, redirectToSsoPage)
	}
}
