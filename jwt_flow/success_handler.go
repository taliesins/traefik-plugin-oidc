package jwt_flow

import (
	"github.com/taliesins/traefik-plugin-oidc/log"
	"net/http"
)

// SuccessHandler is a handler which is called when a token is validated in the
// JWTMiddleware.
type SuccessHandler func(logger *log.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, token string)

// DefaultSuccessHandler is the default success handler implementation for the
// JWTMiddleware. If a success handler is not provided via the WithSuccessHandler
// option this will be used.
func DefaultSuccessHandler(logger *log.Logger, next http.Handler, w http.ResponseWriter, r *http.Request, token string) {
	next.ServeHTTP(w, r)
	return
}
