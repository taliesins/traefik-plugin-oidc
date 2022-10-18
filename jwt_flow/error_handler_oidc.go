package jwt_flow

import (
	"fmt"
	guuid "github.com/google/uuid"
	"github.com/taliesins/traefik-plugin-oidc/sso_redirector"
	"go.uber.org/zap"
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
	ssoRedirectUrlMacSigningKey interface{},
	ssoRedirectUrlMacStrength sso_redirector.MacStrength,
) ErrorHandler {
	return func(logger *zap.Logger, w http.ResponseWriter, r *http.Request, err error) {
		if ssoRedirectUrlTemplate == nil {
			logger.Debug("No ssoRedirectUrlTemplate specified")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.RedirectorPath) {
			logger.Debug("Drop token session cookie as we need to be redirected to SSO for an expired/invalid token", zap.String("requestUrlPath", r.URL.Path), zap.String("redirectorPath", sso_redirector.RedirectorPath))

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
				logger.Error("Unable to get redirecor url", zap.Error(err))
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
		} else {
			logger.Error("No ssoRedirectUrlMacSigningKey specified")
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		if strings.HasPrefix(r.URL.Path, sso_redirector.CallbackPath) {
			if strings.HasPrefix(r.Referer(), sso_redirector.CallbackPath) {
				logger.Debug("Dropping request to prevent endless loop when referrer was from callbackPath", zap.String("requestUrlPath", r.URL.Path), zap.String("referer", r.Referer()), zap.String("redirectorPath", sso_redirector.RedirectorPath))

				//Referrer was from callbackPath, so stop endless loop
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			//callback page for sso
			ssoCallbackPage, err := sso_redirector.RenderSsoCallbackPageTemplate(redirectorUrl)
			if err != nil {
				logger.Error("Unable to render sso callback page template", zap.Error(err), zap.String("redirectorUrl", redirectorUrl.String()))
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			//The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value
			logger.Debug("The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value", zap.String("requestUrlPath", r.URL.Path))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, ssoCallbackPage)
			return
		}

		ssoRedirectUrl, err := sso_redirector.RenderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate, redirectorUrl, nonce, issuedAt)
		if err != nil {
			logger.Error("Unable to render sso redirect url template", zap.Error(err), zap.String("redirectorUrl", redirectorUrl.String()), zap.String("nonce", nonce), zap.String("issuedAt", issuedAt))
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		//This will allow browsers to default to implicit flow
		redirectToSsoPage, err := sso_redirector.RenderRedirectToSsoPageTemplate(ssoRedirectUrl, "")
		if err != nil {
			logger.Error("Unable to render sso redirect to sso page template", zap.Error(err), zap.String("ssoRedirectUrl", ssoRedirectUrl.String()), zap.String("nonce", nonce), zap.String("issuedAt", issuedAt))
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		logger.Debug("Redirect to sso page using javascript", zap.String("requestUrlPath", r.URL.Path))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, redirectToSsoPage)
	}
}
