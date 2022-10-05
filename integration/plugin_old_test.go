package integration_test

import (
	"context"
	pluginoidc "github.com/taliesins/traefik-plugin-oidc"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDemo(t *testing.T) {
	cfg := pluginoidc.CreateConfig()
	//Configure plugin

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := pluginoidc.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Host", "localhost")
	assertHeader(t, req, "X-URL", "http://localhost")
	assertHeader(t, req, "X-Method", "GET")
	assertHeader(t, req, "X-Plugin", "test")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
