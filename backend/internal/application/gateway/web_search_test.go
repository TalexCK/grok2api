package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/clientkey"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
)

type searchCaptureAdapter struct {
	webStoredResponseAdapter
	request provider.ResponseResourceRequest
}

func (a *searchCaptureAdapter) Definition() provider.Definition {
	definition := a.webStoredResponseAdapter.Definition()
	definition.Conversation.ChatCompletions = true
	return definition
}
func (a *searchCaptureAdapter) ForwardResponse(ctx context.Context, request provider.ResponseResourceRequest) (*provider.Response, error) {
	a.request = request
	return a.webStoredResponseAdapter.ForwardResponse(ctx, request)
}

func TestWebSearchPinsFastDespitePublicAliasesAndRetainsModelPolicy(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	models := relational.NewModelRepository(database)
	audits := relational.NewAuditRepository(database)
	credential, _, err := accounts.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderWeb, AuthType: account.AuthTypeSSO, WebTier: account.WebTierBasic,
		Name: "web-search", SourceKey: "web-search", EncryptedAccessToken: "encrypted", Enabled: true,
		AuthStatus: account.AuthStatusActive, MaxConcurrent: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.UpsertRoutes(ctx, []modeldomain.Route{{PublicID: "renamed-fast", Provider: account.ProviderWeb, UpstreamModel: "grok-chat-fast", Capability: modeldomain.CapabilityChat, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := models.ReplaceAccountCapabilities(ctx, credential.ID, []string{"grok-chat-fast"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	route, err := models.GetByProviderUpstream(ctx, account.ProviderWeb, "grok-chat-fast")
	if err != nil {
		t.Fatal(err)
	}
	key, err := relational.NewClientKeyRepository(database).Create(ctx, clientkey.Key{Name: "search", Prefix: "search-key", SecretHash: strings.Repeat("a", 64), EncryptedSecret: "encrypted", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &searchCaptureAdapter{}
	registry := provider.NewRegistry(adapter)
	sticky := memory.NewStickyStore()
	accountService := accountapp.NewService(accounts, audits, memory.NewDeviceSessionStore(), sticky, registry, testCipher(t), nil)
	selector := NewSelector(accounts, memory.NewConcurrencyLimiter(), sticky, registry, time.Hour, time.Second, time.Minute)
	// Public aliases deliberately resolve to another model; trusted searches must bypass them.
	resolver := &aliasRouteResolver{
		byUp:     map[string]modeldomain.Route{string(account.ProviderWeb) + "/grok-chat-fast": route},
		byPublic: map[string][]modeldomain.Route{route.PublicID: {{ID: 999, PublicID: route.PublicID, Provider: account.ProviderWeb, UpstreamModel: "grok-chat-expert", Enabled: true}}},
	}
	service := NewService(resolver, audits, accountService, clientkeyapp.NewService(nil, nil, nil, 60, 4, nil), registry, selector, relational.NewResponseRepository(database), 1)
	const prompt = "  search exactly\n\"今天\"  "
	result, err := service.CreateWebSearch(ctx, Input{RequestID: "mcp-search", ClientKey: key, PublicModel: "some-other-model", Streaming: true, Method: "POST", Path: "/mcp"}, prompt)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, result.Body)
	result.Body.Close()
	result.Finalize(Usage{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Messages []struct{ Role, Content string }
		Stream   bool
	}
	if err := json.Unmarshal(adapter.request.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if adapter.request.Model != "grok-chat-fast" || payload.Stream || len(payload.Messages) != 1 || payload.Messages[0].Role != "user" || payload.Messages[0].Content != prompt {
		t.Fatalf("model=%q payload=%s", adapter.request.Model, adapter.request.Body)
	}
	key.AllowedModels = []uint64{999}
	if _, err := service.CreateWebSearch(ctx, Input{ClientKey: key}, prompt); !errors.Is(err, clientkeyapp.ErrModelNotAllowed) {
		t.Fatalf("restricted model policy: %v", err)
	}
}
