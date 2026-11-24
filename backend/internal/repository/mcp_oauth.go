package repository

import (
	"context"
	"time"
)

// MCPOAuthClient is a dynamically registered public OAuth client.
type MCPOAuthClient struct {
	ID, Name, RedirectURI string
	CreatedAt             time.Time
}

// MCPOAuthTransaction binds one browser authorization interaction.
type MCPOAuthTransaction struct {
	ID, CSRFHash, ClientID, RedirectURI, State, CodeChallenge, Resource, Scope string
	ExpiresAt                                                                  time.Time
}

// MCPOAuthCode is the single-use authorization grant.
type MCPOAuthCode struct {
	Hash, ClientID, RedirectURI, CodeChallenge, Resource, Scope, EncryptedClientKey string
	ExpiresAt                                                                       time.Time
}

// MCPOAuthToken is the durable access or refresh token record.
type MCPOAuthToken struct {
	Hash, FamilyID, Kind, ClientID, Resource, Scope, EncryptedClientKey string
	ExpiresAt                                                           time.Time
	RevokedAt                                                           *time.Time
}

// MCPOAuthRepository stores OAuth state shared by every application instance.
type MCPOAuthRepository interface {
	CreateClient(context.Context, MCPOAuthClient) error
	GetClient(context.Context, string) (MCPOAuthClient, error)
	CreateTransaction(context.Context, MCPOAuthTransaction) error
	GetTransaction(context.Context, string) (MCPOAuthTransaction, error)
	ApproveTransaction(context.Context, string, string, MCPOAuthCode) error
	DeleteTransaction(context.Context, string) error
	GetCode(context.Context, string, time.Time) (MCPOAuthCode, error)
	ExchangeCode(context.Context, string, time.Time, MCPOAuthToken, MCPOAuthToken) error
	RotateRefresh(context.Context, string, time.Time, MCPOAuthToken, MCPOAuthToken) error
	GetAccessToken(context.Context, string, time.Time) (MCPOAuthToken, error)
	GetRefreshToken(context.Context, string, time.Time) (MCPOAuthToken, error)
	Revoke(context.Context, string, time.Time) error
	Cleanup(context.Context, time.Time) error
}
