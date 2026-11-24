package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

const maxBodyBytes int64 = 1 << 20

var protocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

type Handler struct {
	search        func(*gin.Context, string) (string, error)
	publicBaseURL func() string
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

func NewHandler(search func(*gin.Context, string) (string, error), publicBaseURL func() string) *Handler {
	return &Handler{search: search, publicBaseURL: publicBaseURL}
}

func (h *Handler) Register(router *gin.RouterGroup) {
	router.POST("", h.post)
	router.GET("", func(c *gin.Context) {
		c.Header("Allow", http.MethodPost)
		c.Status(http.StatusMethodNotAllowed)
	})
}

func (h *Handler) post(c *gin.Context) {
	if !h.validOrigin(c.GetHeader("Origin")) {
		c.Status(http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		c.Status(http.StatusUnsupportedMediaType)
		return
	}
	if !acceptsJSON(c.GetHeader("Accept")) {
		c.Status(http.StatusNotAcceptable)
		return
	}
	if version := c.GetHeader("MCP-Protocol-Version"); version != "" && !protocolVersions[version] {
		c.JSON(http.StatusBadRequest, response{JSONRPC: "2.0", ID: nil, Error: &rpcError{Code: -32600, Message: "Unsupported MCP protocol version"}})
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyBytes+1))
	if err != nil || int64(len(body)) > maxBodyBytes {
		c.Status(http.StatusRequestEntityTooLarge)
		return
	}
	var req request
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		h.writeError(c, nil, -32700, "Parse error")
		return
	}
	id, validID := parseID(req.ID)
	if req.JSONRPC != "2.0" || req.Method == "" || !validID {
		h.writeError(c, id, -32600, "Invalid Request")
		return
	}
	if len(req.ID) == 0 {
		if req.Method == "notifications/initialized" && validEmptyParams(req.Params) {
			c.Status(http.StatusAccepted)
			return
		}
		c.Status(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		h.initialize(c, id, req.Params)
	case "ping":
		if !validEmptyParams(req.Params) {
			h.writeError(c, id, -32602, "Invalid params")
			return
		}
		c.JSON(http.StatusOK, response{JSONRPC: "2.0", ID: id, Result: gin.H{}})
	case "tools/list":
		if !validEmptyParams(req.Params) {
			h.writeError(c, id, -32602, "Invalid params")
			return
		}
		c.JSON(http.StatusOK, response{JSONRPC: "2.0", ID: id, Result: gin.H{"tools": []any{searchTool()}}})
	case "tools/call":
		h.call(c, id, req.Params)
	default:
		h.writeError(c, id, -32601, "Method not found")
	}
}

func (h *Handler) initialize(c *gin.Context, id any, raw json.RawMessage) {
	var params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ClientInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Title   string `json:"title,omitempty"`
		} `json:"clientInfo"`
		Meta json.RawMessage `json:"_meta,omitempty"`
	}
	if json.Unmarshal(raw, &params) != nil || params.ProtocolVersion == "" || params.Capabilities == nil || params.ClientInfo.Name == "" || params.ClientInfo.Version == "" {
		h.writeError(c, id, -32602, "Invalid params")
		return
	}
	if !protocolVersions[params.ProtocolVersion] {
		params.ProtocolVersion = "2025-11-25"
	}
	c.Header("MCP-Protocol-Version", params.ProtocolVersion)
	c.JSON(http.StatusOK, response{JSONRPC: "2.0", ID: id, Result: gin.H{
		"protocolVersion": params.ProtocolVersion,
		"capabilities":    gin.H{"tools": gin.H{}},
		"serverInfo":      gin.H{"name": "grok-search", "version": "1.0.0"},
	}})
}

func (h *Handler) call(c *gin.Context, id any, raw json.RawMessage) {
	var params struct {
		Name      string          `json:"name"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
		Arguments struct {
			SearchPrompt string `json:"search_prompt"`
		} `json:"arguments"`
	}
	if decodeStrict(raw, &params) != nil || params.Name != "search" || strings.TrimSpace(params.Arguments.SearchPrompt) == "" || h.search == nil {
		h.writeError(c, id, -32602, "Invalid params")
		return
	}
	reply, err := h.search(c, params.Arguments.SearchPrompt)
	result := gin.H{"content": []gin.H{{"type": "text", "text": reply}}}
	if err != nil {
		result["content"] = []gin.H{{"type": "text", "text": err.Error()}}
		result["isError"] = true
	}
	c.JSON(http.StatusOK, response{JSONRPC: "2.0", ID: id, Result: result})
}

func searchTool() gin.H {
	security := []gin.H{{"type": "oauth2", "scopes": []string{"search"}}}
	return gin.H{
		"name":        "search",
		"description": "Search the web with Grok.",
		"inputSchema": gin.H{
			"type": "object", "additionalProperties": false,
			"properties": gin.H{"search_prompt": gin.H{"type": "string", "minLength": 1}},
			"required":   []string{"search_prompt"},
		},
		"annotations":     gin.H{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true},
		"securitySchemes": security,
		"_meta":           gin.H{"securitySchemes": security},
	}
}

func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("missing params")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func validEmptyParams(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var params struct {
		Meta   json.RawMessage `json:"_meta,omitempty"`
		Cursor string          `json:"cursor,omitempty"`
	}
	return decodeStrict(raw, &params) == nil
}

func parseID(raw json.RawMessage) (any, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	if string(raw) == "null" {
		return nil, false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	switch value.(type) {
	case string, json.Number:
		return value, true
	default:
		return nil, false
	}
}

func acceptsJSON(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	for _, part := range strings.Split(value, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && params["q"] != "0" && (mediaType == "application/json" || mediaType == "*/*" || mediaType == "application/*") {
			return true
		}
	}
	return false
}

func (h *Handler) validOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	candidate, err := url.Parse(origin)
	if err != nil || candidate.Scheme == "" || candidate.Host == "" || candidate.User != nil || candidate.Path != "" || candidate.RawQuery != "" || candidate.Fragment != "" {
		return false
	}
	if candidate.Scheme == "https" && strings.EqualFold(candidate.Host, "chatgpt.com") {
		return true
	}
	baseURL, err := h.canonicalBaseURL()
	if err != nil {
		return false
	}
	base, err := url.Parse(baseURL)
	return err == nil && strings.EqualFold(candidate.Scheme, base.Scheme) && strings.EqualFold(candidate.Host, base.Host)
}

func (h *Handler) writeError(c *gin.Context, id any, code int, message string) {
	c.JSON(http.StatusOK, response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}})
}
