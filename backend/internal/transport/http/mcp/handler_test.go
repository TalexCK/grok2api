package mcp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func testRouter(search func(*gin.Context, string) (string, error), base string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewHandler(search, func() string { return base })
	handler.Register(router.Group("/mcp"))
	handler.RegisterDownload(router)
	return router
}

func rpcRequest(router http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestToolsListExposesOnlySearch(t *testing.T) {
	recorder := rpcRequest(testRouter(nil, "https://api.example.com"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	result := decodeResponse(t, recorder)["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "search" {
		t.Fatalf("tools = %#v", tools)
	}
	tool := tools[0].(map[string]any)
	schema := tool["inputSchema"].(map[string]any)
	if schema["additionalProperties"] != false || len(schema["required"].([]any)) != 1 {
		t.Fatalf("input schema = %#v", schema)
	}
	if _, ok := tool["securitySchemes"]; !ok {
		t.Fatal("missing top-level securitySchemes")
	}
	if _, ok := tool["_meta"].(map[string]any)["securitySchemes"]; !ok {
		t.Fatal("missing _meta securitySchemes")
	}
}

func TestToolCallPassesPromptVerbatim(t *testing.T) {
	var prompt string
	router := testRouter(func(_ *gin.Context, value string) (string, error) {
		prompt = value
		return "answer", nil
	}, "https://api.example.com")
	recorder := rpcRequest(router, `{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"search","_meta":{"progressToken":"call-1"},"arguments":{"search_prompt":"  exact prompt  "}}}`)
	if prompt != "  exact prompt  " {
		t.Fatalf("prompt = %q", prompt)
	}
	result := decodeResponse(t, recorder)["result"].(map[string]any)
	content := result["content"].([]any)
	if content[0].(map[string]any)["text"] != "answer" {
		t.Fatalf("content = %#v", content)
	}
}

func TestInitializeNegotiatesNewerClientVersion(t *testing.T) {
	payload := decodeResponse(t, rpcRequest(testRouter(nil, "https://api.example.com"), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"ChatGPT","version":"1","websiteUrl":"https://chatgpt.com"}}}`))
	result, ok := payload["result"].(map[string]any)
	if !ok || result["protocolVersion"] != "2025-11-25" {
		t.Fatalf("negotiation = %#v", payload)
	}
}

func TestRejectsInvalidRequestsAndArguments(t *testing.T) {
	router := testRouter(func(_ *gin.Context, value string) (string, error) { return value, nil }, "https://api.example.com")
	for _, test := range []struct {
		name string
		body string
		code float64
	}{
		{"malformed", `{`, -32700},
		{"bad id", `{"jsonrpc":"2.0","id":{},"method":"ping"}`, -32600},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, -32601},
		{"unknown argument", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"search_prompt":"x","extra":true}}}`, -32602},
		{"empty prompt", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"search_prompt":" "}}}`, -32602},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := decodeResponse(t, rpcRequest(router, test.body))
			if payload["error"].(map[string]any)["code"] != test.code {
				t.Fatalf("response = %#v", payload)
			}
		})
	}
}

func TestNotificationsAndTransportValidation(t *testing.T) {
	router := testRouter(nil, "https://api.example.com")
	if recorder := rpcRequest(router, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); recorder.Code != http.StatusAccepted || recorder.Body.Len() != 0 {
		t.Fatalf("notification status = %d body = %q", recorder.Code, recorder.Body.String())
	}

	for _, origin := range []struct {
		value string
		want  int
	}{{"https://api.example.com", http.StatusOK}, {"https://chatgpt.com", http.StatusOK}, {"https://evil.example", http.StatusForbidden}} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Origin", origin.value)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != origin.want {
			t.Fatalf("origin %q status = %d", origin.value, recorder.Code)
		}
	}
}

func TestPluginZIPUsesCanonicalPublicURL(t *testing.T) {
	router := testRouter(nil, "https://api.example.com/")
	request := httptest.NewRequest(http.MethodGet, "/mcp/plugin.zip", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Disposition"), "grok-search-plugin.zip") {
		t.Fatalf("status = %d headers = %#v", recorder.Code, recorder.Header())
	}
	reader, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{}
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name], err = io.ReadAll(opened)
		opened.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(entries) != 2 || entries["plugin.json"] == nil || entries["mcp.json"] == nil {
		t.Fatalf("entries = %#v", entries)
	}
	var manifest struct {
		Servers map[string]struct {
			URL string `json:"url"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(entries["mcp.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Servers["grok"].URL != "https://api.example.com/mcp" {
		t.Fatalf("URL = %q", manifest.Servers["grok"].URL)
	}
}

func TestPluginZIPRejectsInvalidPublicURL(t *testing.T) {
	router := testRouter(nil, "")
	request := httptest.NewRequest(http.MethodGet, "/mcp/plugin.zip", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
}
