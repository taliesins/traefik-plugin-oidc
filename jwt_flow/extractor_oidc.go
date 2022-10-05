package jwt_flow

import "github.com/taliesins/traefik-plugin-oidc/sso_redirector"

// OidcTokenExtractor is the default token extractor implementation for the
// JWTMiddleware. If an token extractor is not provided via the WithTokenExtractor
// option this will be used.
func OidcTokenExtractor() TokenExtractor {
	return MultiTokenExtractor(
		AuthHeaderTokenExtractor,
		CookieTokenExtractor(sso_redirector.SessionCookieName),
		FormTokenExtractor(sso_redirector.RedirectorPath, sso_redirector.IdTokenBookmarkParameterName),
		ParameterTokenExtractor(sso_redirector.IdTokenBookmarkParameterName),
	)
}
