package mcpauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	mcpauth "github.com/chenyme/grok2api/backend/internal/application/mcpauth"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestAuthorizationCodePKCEReplayRefreshRotationAndRevoke(t *testing.T) {
	ctx := context.Background()
	db, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := relational.NewMCPOAuthRepository(db)
	service := mcpauth.NewService(repo, nil, nil, nil)

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	now := time.Now().UTC()
	client := repository.MCPOAuthClient{ID: "client", Name: "测试客户端", RedirectURI: "https://client.example/callback", CreatedAt: now}
	if err := repo.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	tx := repository.MCPOAuthTransaction{
		ID: "transaction", CSRFHash: security.HashToken("csrf"), ClientID: client.ID,
		RedirectURI: client.RedirectURI, State: "state", CodeChallenge: challenge,
		Resource: "https://api.example/mcp", Scope: mcpauth.Scope, ExpiresAt: now.Add(time.Minute),
	}
	if err := repo.CreateTransaction(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decide(ctx, tx.ID, "wrong-csrf", "unused", true); !errors.Is(err, mcpauth.ErrInvalidGrant) {
		t.Fatalf("CSRF mismatch accepted: %v", err)
	}

	code := "authorization-code"
	grant := repository.MCPOAuthCode{
		Hash: security.HashToken(code), ClientID: client.ID, RedirectURI: client.RedirectURI,
		CodeChallenge: challenge, Resource: tx.Resource, Scope: tx.Scope, ExpiresAt: now.Add(time.Minute),
	}
	if err := repo.ApproveTransaction(ctx, tx.ID, "encrypted-key", grant); err != nil {
		t.Fatal(err)
	}
	invalid := map[string][3]string{
		"bad redirect": {"https://evil.example/callback", verifier, tx.Resource},
		"bad PKCE":     {client.RedirectURI, "wrong-verifier-that-is-long-enough-abcdefghijklmnopqrstuvwxyz", tx.Resource},
		"bad resource": {client.RedirectURI, verifier, "https://evil.example/mcp"},
	}
	for name, values := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := service.ExchangeCode(ctx, code, client.ID, values[0], values[1], values[2]); !errors.Is(err, mcpauth.ErrInvalidGrant) {
				t.Fatalf("expected invalid grant, got %v", err)
			}
		})
	}
	tokens, err := service.ExchangeCode(ctx, code, client.ID, client.RedirectURI, verifier, tx.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExchangeCode(ctx, code, client.ID, client.RedirectURI, verifier, tx.Resource); !errors.Is(err, mcpauth.ErrInvalidGrant) {
		t.Fatalf("code replay accepted: %v", err)
	}
	rotated, err := service.Refresh(ctx, tokens.RefreshToken, client.ID, tx.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Refresh(ctx, tokens.RefreshToken, client.ID, tx.Resource); !errors.Is(err, mcpauth.ErrInvalidGrant) {
		t.Fatalf("refresh replay accepted: %v", err)
	}
	if _, err := repo.GetAccessToken(ctx, security.HashToken(rotated.AccessToken), time.Now().UTC()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("refresh replay did not revoke active family: %v", err)
	}
	tx2 := tx
	tx2.ID = "transaction-revoke"
	if err := repo.CreateTransaction(ctx, tx2); err != nil {
		t.Fatal(err)
	}
	code2 := "authorization-code-revoke"
	grant.Hash = security.HashToken(code2)
	if err := repo.ApproveTransaction(ctx, tx2.ID, "encrypted-key", grant); err != nil {
		t.Fatal(err)
	}
	revoked, err := service.ExchangeCode(ctx, code2, client.ID, client.RedirectURI, verifier, tx.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, revoked.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetAccessToken(ctx, security.HashToken(revoked.AccessToken), time.Now().UTC()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("revoked family access remains valid: %v", err)
	}
	tx3 := tx
	tx3.ID = "transaction-race"
	if err := repo.CreateTransaction(ctx, tx3); err != nil {
		t.Fatal(err)
	}
	code3 := "authorization-code-race"
	grant.Hash = security.HashToken(code3)
	if err := repo.ApproveTransaction(ctx, tx3.ID, "encrypted-key", grant); err != nil {
		t.Fatal(err)
	}
	raceTokens, err := service.ExchangeCode(ctx, code3, client.ID, client.RedirectURI, verifier, tx.Resource)
	if err != nil {
		t.Fatal(err)
	}
	refreshResult := make(chan struct {
		tokens mcpauth.Tokens
		err    error
	}, 1)
	revokeResult := make(chan error, 1)
	go func() {
		value, err := service.Refresh(ctx, raceTokens.RefreshToken, client.ID, tx.Resource)
		refreshResult <- struct {
			tokens mcpauth.Tokens
			err    error
		}{value, err}
	}()
	go func() { revokeResult <- service.Revoke(ctx, raceTokens.RefreshToken) }()
	refreshed, revokeErr := <-refreshResult, <-revokeResult
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if refreshed.err == nil {
		if _, err := repo.GetAccessToken(ctx, security.HashToken(refreshed.tokens.AccessToken), time.Now().UTC()); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("revoke/rotate race leaked active token: %v", err)
		}
	}
}

func TestValidRedirectURI(t *testing.T) {
	cases := map[string]bool{
		"https://client.example/callback":          true,
		"https://client.example/callback?tenant=1": true,
		"http://localhost:3000/callback":           true,
		"http://127.0.0.1/callback":                true,
		"http://client.example/callback":           false,
		"https://user@client.example/callback":     false,
		"https://client.example/callback#secret":   false,
		"/callback":                                false,
	}
	for raw, want := range cases {
		if got := mcpauth.ValidRedirectURI(raw); got != want {
			t.Errorf("ValidRedirectURI(%q)=%v, want %v", raw, got, want)
		}
	}
}
