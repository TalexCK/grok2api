package relational

import (
	"context"
	"errors"
	"time"

	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type mcpOAuthClientModel struct {
	ID          string    `gorm:"size:64;primaryKey"`
	Name        string    `gorm:"size:200;not null"`
	RedirectURI string    `gorm:"size:2048;not null"`
	CreatedAt   time.Time `gorm:"not null"`
}

func (mcpOAuthClientModel) TableName() string { return "mcp_oauth_clients" }

type mcpOAuthTransactionModel struct {
	ID            string    `gorm:"size:64;primaryKey"`
	CSRFHash      string    `gorm:"size:64;not null"`
	ClientID      string    `gorm:"size:64;not null;index"`
	RedirectURI   string    `gorm:"size:2048;not null"`
	State         string    `gorm:"size:512;not null"`
	CodeChallenge string    `gorm:"size:128;not null"`
	Resource      string    `gorm:"size:2048;not null"`
	Scope         string    `gorm:"size:128;not null"`
	ExpiresAt     time.Time `gorm:"not null;index"`
}

func (mcpOAuthTransactionModel) TableName() string { return "mcp_oauth_transactions" }

type mcpOAuthCodeModel struct {
	Hash               string    `gorm:"size:64;primaryKey"`
	ClientID           string    `gorm:"size:64;not null"`
	RedirectURI        string    `gorm:"size:2048;not null"`
	CodeChallenge      string    `gorm:"size:128;not null"`
	Resource           string    `gorm:"size:2048;not null"`
	Scope              string    `gorm:"size:128;not null"`
	EncryptedClientKey string    `gorm:"type:text;not null"`
	ExpiresAt          time.Time `gorm:"not null;index"`
}

func (mcpOAuthCodeModel) TableName() string { return "mcp_oauth_codes" }

type mcpOAuthTokenModel struct {
	Hash               string    `gorm:"size:64;primaryKey"`
	FamilyID           string    `gorm:"size:64;not null;index"`
	Kind               string    `gorm:"size:16;not null"`
	ClientID           string    `gorm:"size:64;not null"`
	Resource           string    `gorm:"size:2048;not null"`
	Scope              string    `gorm:"size:128;not null"`
	EncryptedClientKey string    `gorm:"type:text;not null"`
	ExpiresAt          time.Time `gorm:"not null;index"`
	RevokedAt          *time.Time
}

func (mcpOAuthTokenModel) TableName() string { return "mcp_oauth_tokens" }

type mcpOAuthFamilyModel struct {
	ID        string `gorm:"size:64;primaryKey"`
	RevokedAt *time.Time
	UpdatedAt time.Time `gorm:"not null"`
}

func (mcpOAuthFamilyModel) TableName() string { return "mcp_oauth_families" }

type MCPOAuthRepository struct{ db *Database }

func NewMCPOAuthRepository(db *Database) *MCPOAuthRepository { return &MCPOAuthRepository{db: db} }

func (r *MCPOAuthRepository) CreateClient(ctx context.Context, value repository.MCPOAuthClient) error {
	row := mcpOAuthClientModel{ID: value.ID, Name: value.Name, RedirectURI: value.RedirectURI, CreatedAt: value.CreatedAt}
	return mapError(r.db.db.WithContext(ctx).Create(&row).Error)
}

func (r *MCPOAuthRepository) GetClient(ctx context.Context, id string) (repository.MCPOAuthClient, error) {
	var row mcpOAuthClientModel
	if err := r.db.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return repository.MCPOAuthClient{}, mapError(err)
	}
	return repository.MCPOAuthClient{ID: row.ID, Name: row.Name, RedirectURI: row.RedirectURI, CreatedAt: row.CreatedAt}, nil
}

func (r *MCPOAuthRepository) CreateTransaction(ctx context.Context, value repository.MCPOAuthTransaction) error {
	return r.db.db.WithContext(ctx).Create(transactionModel(value)).Error
}

func (r *MCPOAuthRepository) GetTransaction(ctx context.Context, id string) (repository.MCPOAuthTransaction, error) {
	var row mcpOAuthTransactionModel
	if err := r.db.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return repository.MCPOAuthTransaction{}, mapError(err)
	}
	return transactionDomain(row), nil
}

func (r *MCPOAuthRepository) DeleteTransaction(ctx context.Context, id string) error {
	return r.db.db.WithContext(ctx).Delete(&mcpOAuthTransactionModel{}, "id = ?", id).Error
}

func (r *MCPOAuthRepository) ApproveTransaction(ctx context.Context, id, encrypted string, code repository.MCPOAuthCode) error {
	return r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row mcpOAuthTransactionModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&row, "id = ? AND expires_at > ?", id, time.Now().UTC()).Error; err != nil {
			return mapError(err)
		}
		code.EncryptedClientKey = encrypted
		if err := tx.Create(codeModel(code)).Error; err != nil {
			return err
		}
		result := tx.Delete(&mcpOAuthTransactionModel{}, "id = ?", id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return repository.ErrConflict
		}
		return nil
	})
}

func (r *MCPOAuthRepository) GetCode(ctx context.Context, hash string, now time.Time) (repository.MCPOAuthCode, error) {
	var row mcpOAuthCodeModel
	if err := r.db.db.WithContext(ctx).First(&row, "hash = ? AND expires_at > ?", hash, now).Error; err != nil {
		return repository.MCPOAuthCode{}, mapError(err)
	}
	return repository.MCPOAuthCode{Hash: row.Hash, ClientID: row.ClientID, RedirectURI: row.RedirectURI, CodeChallenge: row.CodeChallenge, Resource: row.Resource, Scope: row.Scope, EncryptedClientKey: row.EncryptedClientKey, ExpiresAt: row.ExpiresAt}, nil
}

func (r *MCPOAuthRepository) ExchangeCode(ctx context.Context, hash string, now time.Time, access, refresh repository.MCPOAuthToken) error {
	return r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var code mcpOAuthCodeModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&code, "hash = ? AND expires_at > ?", hash, now).Error; err != nil {
			return mapError(err)
		}
		if err := tx.Create(&mcpOAuthFamilyModel{ID: access.FamilyID, UpdatedAt: now}).Error; err != nil {
			return err
		}
		if err := tx.Create([]mcpOAuthTokenModel{tokenModel(access), tokenModel(refresh)}).Error; err != nil {
			return err
		}
		result := tx.Delete(&mcpOAuthCodeModel{}, "hash = ?", hash)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return repository.ErrConflict
		}
		return nil
	})
}

func (r *MCPOAuthRepository) GetRefreshToken(ctx context.Context, hash string, now time.Time) (repository.MCPOAuthToken, error) {
	var row mcpOAuthTokenModel
	if err := r.db.db.WithContext(ctx).First(&row, "hash = ? AND kind = 'refresh' AND expires_at > ?", hash, now).Error; err != nil {
		return repository.MCPOAuthToken{}, mapError(err)
	}
	return tokenDomain(row), nil
}

func (r *MCPOAuthRepository) RotateRefresh(ctx context.Context, hash string, now time.Time, access, refresh repository.MCPOAuthToken) error {
	replayed := false
	err := r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var old mcpOAuthTokenModel
		if err := tx.First(&old, "hash = ? AND kind = 'refresh' AND expires_at > ?", hash, now).Error; err != nil {
			return mapError(err)
		}
		var family mcpOAuthFamilyModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&family, "id = ?", old.FamilyID).Error; err != nil {
			return mapError(err)
		}
		// Re-read after the family lock: another instance may have consumed this token while we waited.
		if err := tx.First(&old, "hash = ? AND kind = 'refresh' AND expires_at > ?", hash, now).Error; err != nil {
			return mapError(err)
		}
		if family.RevokedAt != nil || old.RevokedAt != nil {
			replayed = true
			if family.RevokedAt == nil {
				if err := tx.Model(&family).Updates(map[string]any{"revoked_at": now, "updated_at": now}).Error; err != nil {
					return err
				}
				if err := tx.Model(&mcpOAuthTokenModel{}).Where("family_id = ? AND revoked_at IS NULL", old.FamilyID).Update("revoked_at", now).Error; err != nil {
					return err
				}
			}
			return nil
		}
		if err := tx.Model(&old).Update("revoked_at", now).Error; err != nil {
			return err
		}
		if err := tx.Model(&family).Update("updated_at", now).Error; err != nil {
			return err
		}
		return tx.Create([]mcpOAuthTokenModel{tokenModel(access), tokenModel(refresh)}).Error
	})
	if err != nil {
		return err
	}
	if replayed {
		return repository.ErrConflict
	}
	return nil
}

func (r *MCPOAuthRepository) GetAccessToken(ctx context.Context, hash string, now time.Time) (repository.MCPOAuthToken, error) {
	var row mcpOAuthTokenModel
	if err := r.db.db.WithContext(ctx).First(&row, "hash = ? AND kind = 'access' AND revoked_at IS NULL AND expires_at > ?", hash, now).Error; err != nil {
		return repository.MCPOAuthToken{}, mapError(err)
	}
	return tokenDomain(row), nil
}

func (r *MCPOAuthRepository) Revoke(ctx context.Context, hash string, now time.Time) error {
	return r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var token mcpOAuthTokenModel
		err := tx.First(&token, "hash = ?", hash).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var family mcpOAuthFamilyModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&family, "id = ?", token.FamilyID).Error; err != nil {
			return mapError(err)
		}
		if family.RevokedAt == nil {
			if err := tx.Model(&family).Updates(map[string]any{"revoked_at": now, "updated_at": now}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&mcpOAuthTokenModel{}).Where("family_id = ? AND revoked_at IS NULL", token.FamilyID).Update("revoked_at", now).Error
	})
}

func (r *MCPOAuthRepository) Cleanup(ctx context.Context, now time.Time) error {
	return r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, model := range []any{&mcpOAuthTransactionModel{}, &mcpOAuthCodeModel{}, &mcpOAuthTokenModel{}} {
			if err := tx.Where("expires_at <= ?", now).Delete(model).Error; err != nil {
				return err
			}
		}
		return tx.Where("id NOT IN (?)", tx.Model(&mcpOAuthTokenModel{}).Select("family_id")).Delete(&mcpOAuthFamilyModel{}).Error
	})
}

func transactionModel(value repository.MCPOAuthTransaction) *mcpOAuthTransactionModel {
	return &mcpOAuthTransactionModel{ID: value.ID, CSRFHash: value.CSRFHash, ClientID: value.ClientID, RedirectURI: value.RedirectURI, State: value.State, CodeChallenge: value.CodeChallenge, Resource: value.Resource, Scope: value.Scope, ExpiresAt: value.ExpiresAt}
}
func transactionDomain(row mcpOAuthTransactionModel) repository.MCPOAuthTransaction {
	return repository.MCPOAuthTransaction{ID: row.ID, CSRFHash: row.CSRFHash, ClientID: row.ClientID, RedirectURI: row.RedirectURI, State: row.State, CodeChallenge: row.CodeChallenge, Resource: row.Resource, Scope: row.Scope, ExpiresAt: row.ExpiresAt}
}
func codeModel(value repository.MCPOAuthCode) *mcpOAuthCodeModel {
	return &mcpOAuthCodeModel{Hash: value.Hash, ClientID: value.ClientID, RedirectURI: value.RedirectURI, CodeChallenge: value.CodeChallenge, Resource: value.Resource, Scope: value.Scope, EncryptedClientKey: value.EncryptedClientKey, ExpiresAt: value.ExpiresAt}
}
func tokenModel(value repository.MCPOAuthToken) mcpOAuthTokenModel {
	return mcpOAuthTokenModel{Hash: value.Hash, FamilyID: value.FamilyID, Kind: value.Kind, ClientID: value.ClientID, Resource: value.Resource, Scope: value.Scope, EncryptedClientKey: value.EncryptedClientKey, ExpiresAt: value.ExpiresAt, RevokedAt: value.RevokedAt}
}
func tokenDomain(row mcpOAuthTokenModel) repository.MCPOAuthToken {
	return repository.MCPOAuthToken{Hash: row.Hash, FamilyID: row.FamilyID, Kind: row.Kind, ClientID: row.ClientID, Resource: row.Resource, Scope: row.Scope, EncryptedClientKey: row.EncryptedClientKey, ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt}
}
