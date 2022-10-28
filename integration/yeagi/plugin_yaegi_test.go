package integration_yaegi

import (
	"testing"

	"github.com/taliesins/traefik-plugin-oidc/integration"
	"github.com/taliesins/traefik-plugin-oidc/jwt_flow"
)

// *****************  Authorization Header Test

func TestWithClientSecretInAuthorizationHeaderWrongSecretFailure(t *testing.T) {
	integration.RunTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", jwt_flow.MultiTokenInjector(jwt_flow.AuthHeaderTokenInjector))
}
