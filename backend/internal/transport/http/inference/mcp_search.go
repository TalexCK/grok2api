package inference

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	"github.com/chenyme/grok2api/backend/internal/application/gateway"
	clientkeydomain "github.com/chenyme/grok2api/backend/internal/domain/clientkey"
	"github.com/chenyme/grok2api/backend/internal/transport/http/middleware"
	"github.com/gin-gonic/gin"
)

// Search forwards the exact prompt through the normal quota, scheduling and audit path.
func (h *Handler) Search(c *gin.Context, prompt string) (string, error) {
	value, _ := c.Get(middleware.ClientKey)
	key, ok := value.(clientkeydomain.Key)
	if !ok {
		return "", errors.New("MCP 授权无效，请重新连接")
	}
	result, err := h.gateway.CreateWebSearch(c.Request.Context(), gateway.Input{
		RequestID: c.GetString(middleware.RequestIDKey), ClientKey: key,
		Method: c.Request.Method, Path: c.Request.URL.Path,
	}, prompt)
	if err != nil {
		switch {
		case errors.Is(err, gateway.ErrModelNotFound):
			return "", errors.New("Grok Web fast 模型未启用")
		case errors.Is(err, clientkeyapp.ErrModelNotAllowed):
			return "", errors.New("当前 Client Key 未获准使用 Grok Web fast")
		case errors.Is(err, clientkeyapp.ErrBillingLimit):
			return "", errors.New("当前 Client Key 额度不足")
		default:
			return "", errors.New("Grok Web fast 暂不可用，请稍后重试")
		}
	}
	return readSearchReply(result)
}

func readSearchReply(result *gateway.Result) (string, error) {
	metadata := responseMetadata{}
	errorCode := ""
	defer result.Body.Close()
	defer func() { result.Finalize(metadata.Usage, metadata.ResponseID, errorCode) }()
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		errorCode = "upstream_error"
		return "", fmt.Errorf("Grok Web fast 请求失败（HTTP %d）", result.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(result.Body, maxJSONMetadataInspectionBytes+1))
	if err != nil || len(body) > maxJSONMetadataInspectionBytes {
		errorCode = "response_transfer_failed"
		return "", errors.New("读取 Grok Web fast 回复失败或回复超过 8 MiB")
	}
	metadata = extractMetadata(body)
	var reply struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &reply) != nil || len(reply.Choices) != 1 {
		errorCode = "invalid_upstream_response"
		return "", errors.New("Grok Web fast 返回了无效回复")
	}
	choice := reply.Choices[0]
	text := choice.Message.Content
	if text == "" {
		text = choice.Message.Refusal
	}
	if strings.TrimSpace(text) == "" {
		errorCode = "upstream_response_empty"
		return "", errors.New("Grok Web fast 未返回文本回复")
	}
	metadata.Usage.OutputObserved = true
	if choice.FinishReason != "stop" {
		errorCode = "upstream_response_incomplete"
		return "", errors.New("Grok Web fast 回复未完整结束，请重试")
	}
	return text, nil
}
