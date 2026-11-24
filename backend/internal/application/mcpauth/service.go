package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	clientkeydomain "github.com/chenyme/grok2api/backend/internal/domain/clientkey"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

var (
	ErrInvalidRequest     = errors.New("OAuth 请求无效")
	ErrInvalidClient      = errors.New("OAuth 客户端无效")
	ErrInvalidGrant       = errors.New("OAuth 授权凭据无效")
	ErrAccessDenied       = errors.New("用户拒绝授权")
	ErrInvalidToken       = errors.New("OAuth 访问令牌无效")
	ErrRuntimeUnavailable = errors.New("OAuth 服务暂不可用")
	ErrRateLimited        = errors.New("请求过于频繁")
)

const Scope = "search"
const (
	authorizationTTL = 10 * time.Minute
	codeTTL          = 5 * time.Minute
	accessTTL        = time.Hour
	refreshTTL       = 30 * 24 * time.Hour
)

type Service struct {
	repo    repository.MCPOAuthRepository
	keys    *clientkeyapp.Service
	cipher  *security.Cipher
	limiter repository.RateLimiter
}

func NewService(repo repository.MCPOAuthRepository, keys *clientkeyapp.Service, cipher *security.Cipher, limiter repository.RateLimiter) *Service {
	return &Service{repo: repo, keys: keys, cipher: cipher, limiter: limiter}
}

type Authorization struct {
	ID, CSRF, ClientName string
	ExpiresAt            time.Time
}
type Tokens struct {
	AccessToken, RefreshToken, Scope string
	ExpiresIn                        int
}

func (s *Service) AllowPublic(ctx context.Context, key string, limit int) error {
	allowed, err := s.limiter.Allow(ctx, "mcp-oauth:"+key, limit, time.Now().UTC())
	if err != nil {
		return ErrRuntimeUnavailable
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}

func (s *Service) RegisterClient(ctx context.Context, name, redirect string) (repository.MCPOAuthClient, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 || !ValidRedirectURI(redirect) {
		return repository.MCPOAuthClient{}, ErrInvalidRequest
	}
	id, err := randomToken()
	if err != nil {
		return repository.MCPOAuthClient{}, ErrRuntimeUnavailable
	}
	client := repository.MCPOAuthClient{ID: id, Name: name, RedirectURI: redirect, CreatedAt: time.Now().UTC()}
	if err := s.repo.CreateClient(ctx, client); err != nil {
		return repository.MCPOAuthClient{}, ErrRuntimeUnavailable
	}
	return client, nil
}

func (s *Service) BeginAuthorization(ctx context.Context, clientID, redirect, state, challenge, method, resource, scope string) (Authorization, error) {
	if state == "" || len(state) > 512 || method != "S256" || !validChallenge(challenge) || scope != Scope || resource == "" {
		return Authorization{}, ErrInvalidRequest
	}
	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		return Authorization{}, ErrInvalidClient
	}
	if client.RedirectURI != redirect {
		return Authorization{}, ErrInvalidRequest
	}
	id, err := randomToken()
	if err != nil {
		return Authorization{}, ErrRuntimeUnavailable
	}
	csrf, err := randomToken()
	if err != nil {
		return Authorization{}, ErrRuntimeUnavailable
	}
	now := time.Now().UTC()
	tx := repository.MCPOAuthTransaction{
		ID: id, CSRFHash: security.HashToken(csrf), ClientID: clientID, RedirectURI: redirect,
		State: state, CodeChallenge: challenge, Resource: resource, Scope: scope, ExpiresAt: now.Add(authorizationTTL),
	}
	if err := s.repo.CreateTransaction(ctx, tx); err != nil {
		return Authorization{}, ErrRuntimeUnavailable
	}
	_ = s.repo.Cleanup(ctx, now)
	return Authorization{ID: id, CSRF: csrf, ClientName: client.Name, ExpiresAt: tx.ExpiresAt}, nil
}

func (s *Service) GetAuthorization(ctx context.Context, id string) (repository.MCPOAuthTransaction, repository.MCPOAuthClient, error) {
	tx, err := s.repo.GetTransaction(ctx, id)
	if err != nil || time.Now().UTC().After(tx.ExpiresAt) {
		return repository.MCPOAuthTransaction{}, repository.MCPOAuthClient{}, ErrInvalidGrant
	}
	client, err := s.repo.GetClient(ctx, tx.ClientID)
	if err != nil {
		return repository.MCPOAuthTransaction{}, repository.MCPOAuthClient{}, ErrInvalidClient
	}
	return tx, client, nil
}

func (s *Service) Decide(ctx context.Context, id, csrf, rawKey string, approve bool) (string, error) {
	tx, _, err := s.GetAuthorization(ctx, id)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(security.HashToken(csrf)), []byte(tx.CSRFHash)) != 1 {
		return "", ErrInvalidGrant
	}
	if !approve {
		_ = s.repo.DeleteTransaction(ctx, id)
		return redirectResult(tx, "", ErrAccessDenied), ErrAccessDenied
	}
	keyText := strings.TrimSpace(rawKey)
	_, release, err := s.keys.Authenticate(ctx, keyText)
	if err != nil {
		return "", mapKeyError(err)
	}
	release()
	encrypted, err := s.cipher.Encrypt(keyText)
	if err != nil {
		return "", ErrRuntimeUnavailable
	}
	code, err := randomToken()
	if err != nil {
		return "", ErrRuntimeUnavailable
	}
	grant := repository.MCPOAuthCode{
		Hash: security.HashToken(code), ClientID: tx.ClientID, RedirectURI: tx.RedirectURI,
		CodeChallenge: tx.CodeChallenge, Resource: tx.Resource, Scope: tx.Scope, ExpiresAt: time.Now().UTC().Add(codeTTL),
	}
	if err := s.repo.ApproveTransaction(ctx, id, encrypted, grant); err != nil {
		return "", grantError(err)
	}
	return redirectResult(tx, code, nil), nil
}

func redirectResult(tx repository.MCPOAuthTransaction, code string, result error) string {
	u, _ := url.Parse(tx.RedirectURI)
	query := u.Query()
	query.Set("state", tx.State)
	query.Set("iss", strings.TrimSuffix(tx.Resource, "/mcp"))
	if result == nil {
		query.Set("code", code)
	} else {
		query.Set("error", "access_denied")
		query.Set("error_description", "用户拒绝授权")
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *Service) ExchangeCode(ctx context.Context, code, clientID, redirect, verifier, resource string) (Tokens, error) {
	now := time.Now().UTC()
	grant, err := s.repo.GetCode(ctx, security.HashToken(code), now)
	if err != nil {
		return Tokens{}, grantError(err)
	}
	if grant.ClientID != clientID || grant.RedirectURI != redirect || grant.Resource != resource || !verifyPKCE(verifier, grant.CodeChallenge) {
		return Tokens{}, ErrInvalidGrant
	}
	return s.issue(ctx, grant.Hash, "", grant.ClientID, grant.Resource, grant.Scope, grant.EncryptedClientKey, now, false)
}

func (s *Service) Refresh(ctx context.Context, raw, clientID, resource string) (Tokens, error) {
	now := time.Now().UTC()
	hash := security.HashToken(raw)
	old, err := s.repo.GetRefreshToken(ctx, hash, now)
	if err != nil {
		return Tokens{}, grantError(err)
	}
	if old.ClientID != clientID || old.Resource != resource {
		return Tokens{}, ErrInvalidGrant
	}
	return s.issue(ctx, hash, old.FamilyID, old.ClientID, old.Resource, old.Scope, old.EncryptedClientKey, now, true)
}

func (s *Service) issue(ctx context.Context, oldHash, family, clientID, resource, scope, encrypted string, now time.Time, rotate bool) (Tokens, error) {
	access, err := randomToken()
	if err != nil {
		return Tokens{}, ErrRuntimeUnavailable
	}
	refresh, err := randomToken()
	if err != nil {
		return Tokens{}, ErrRuntimeUnavailable
	}
	if family == "" {
		family, err = randomToken()
		if err != nil {
			return Tokens{}, ErrRuntimeUnavailable
		}
	}
	a := repository.MCPOAuthToken{Hash: security.HashToken(access), FamilyID: family, Kind: "access", ClientID: clientID, Resource: resource, Scope: scope, EncryptedClientKey: encrypted, ExpiresAt: now.Add(accessTTL)}
	r := repository.MCPOAuthToken{Hash: security.HashToken(refresh), FamilyID: family, Kind: "refresh", ClientID: clientID, Resource: resource, Scope: scope, EncryptedClientKey: encrypted, ExpiresAt: now.Add(refreshTTL)}
	if rotate {
		err = s.repo.RotateRefresh(ctx, oldHash, now, a, r)
	} else {
		err = s.repo.ExchangeCode(ctx, oldHash, now, a, r)
	}
	if err != nil {
		return Tokens{}, grantError(err)
	}
	return Tokens{AccessToken: access, RefreshToken: refresh, Scope: scope, ExpiresIn: int(accessTTL.Seconds())}, nil
}

func (s *Service) Revoke(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	if err := s.repo.Revoke(ctx, security.HashToken(raw), time.Now().UTC()); err != nil {
		return ErrRuntimeUnavailable
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, raw, resource string) (clientkeydomain.Key, func(), error) {
	token, err := s.repo.GetAccessToken(ctx, security.HashToken(raw), time.Now().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return clientkeydomain.Key{}, nil, ErrInvalidToken
		}
		return clientkeydomain.Key{}, nil, ErrRuntimeUnavailable
	}
	if token.Resource != resource || token.Scope != Scope {
		return clientkeydomain.Key{}, nil, ErrInvalidToken
	}
	keyText, err := s.cipher.Decrypt(token.EncryptedClientKey)
	if err != nil {
		return clientkeydomain.Key{}, nil, ErrRuntimeUnavailable
	}
	key, release, err := s.keys.Authenticate(ctx, keyText)
	if err != nil {
		return clientkeydomain.Key{}, nil, mapKeyError(err)
	}
	return key, release, nil
}

func ValidRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil || u.Hostname() == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}

func validChallenge(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func verifyPKCE(verifier, expected string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func mapKeyError(err error) error {
	switch {
	case errors.Is(err, clientkeyapp.ErrRateLimited), errors.Is(err, clientkeyapp.ErrConcurrencyLimit), errors.Is(err, clientkeyapp.ErrBillingLimit):
		return ErrRateLimited
	case errors.Is(err, clientkeyapp.ErrRuntimeUnavailable):
		return ErrRuntimeUnavailable
	default:
		return fmt.Errorf("%w", ErrInvalidToken)
	}
}

func grantError(err error) error {
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrConflict) {
		return ErrInvalidGrant
	}
	return ErrRuntimeUnavailable
}
