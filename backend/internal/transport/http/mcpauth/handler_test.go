package mcpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	mcpauthapp "github.com/chenyme/grok2api/backend/internal/application/mcpauth"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/gin-gonic/gin"
)

type allowAllLimiter struct{}

func (allowAllLimiter) Allow(context.Context, string, int, time.Time) (bool, error) { return true, nil }

func TestDiscoveryRegistrationAndConsentPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	db, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "oauth-http.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	service := mcpauthapp.NewService(relational.NewMCPOAuthRepository(db), nil, nil, allowAllLimiter{})
	handler := NewHandler(service, func() string { return "https://api.example/prefix" })
	router := gin.New()
	handler.Register(router)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"resource":"https://api.example/prefix/mcp"`) {
		t.Fatalf("unexpected discovery: %d %s", response.Code, response.Body.String())
	}

	body := `{"client_name":"测试客户端","redirect_uris":["https://client.example/callback?next=https%3A%2F%2Fevil.example%2F"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`
	request = httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("registration failed: %d %s", response.Code, response.Body.String())
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}

	query := url.Values{
		"response_type": {"code"}, "client_id": {registered.ClientID},
		"redirect_uri": {"https://client.example/callback?next=https%3A%2F%2Fevil.example%2F"}, "state": {"state"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"},
		"code_challenge_method": {"S256"}, "resource": {"https://api.example/prefix/mcp"}, "scope": {"search"},
	}
	request = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("consent failed: %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `type="password"`) || !strings.Contains(response.Body.String(), `value="deny"`) {
		t.Fatalf("consent controls missing: %s", response.Body.String())
	}
	_, sources, found := strings.Cut(response.Header().Get("Content-Security-Policy"), "form-action ")
	sources, _, _ = strings.Cut(sources, ";")
	if !found || !slices.Equal(strings.Fields(sources), []string{"'self'", "https://client.example"}) {
		t.Fatalf("OAuth redirect is blocked or an unrelated origin is allowed: %q", sources)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("CSRF cookie is not secure: %#v", cookies)
	}
	query.Set("redirect_uri", "https://attacker.example/callback")
	request = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unregistered callback accepted: %d", response.Code)
	}
}
