package gateway

import (
	"context"
	"encoding/json"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
)

// CreateWebSearch keeps MCP searches on Web fast even when public model names are customized.
func (s *Service) CreateWebSearch(ctx context.Context, input Input, prompt string) (*Result, error) {
	route, err := s.models.GetByProviderUpstream(ctx, account.ProviderWeb, "grok-chat-fast")
	if err != nil || !route.Enabled {
		return nil, ErrModelNotFound
	}
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	input.Body, err = json.Marshal(struct {
		Model    string    `json:"model"`
		Messages []message `json:"messages"`
		Stream   bool      `json:"stream"`
	}{Model: "grok-chat-fast", Messages: []message{{Role: "user", Content: prompt}}})
	if err != nil {
		return nil, err
	}
	input.PublicModel = route.PublicID
	input.modelRoute = &route
	input.Streaming = false
	input.Operation = audit.OperationChat
	return s.createResponseAt(ctx, input, "/responses")
}
