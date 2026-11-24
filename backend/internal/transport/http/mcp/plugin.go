package mcp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handler) RegisterDownload(router *gin.Engine) {
	router.GET("/mcp/plugin.zip", h.download)
}

func (h *Handler) download(c *gin.Context) {
	base, err := h.canonicalBaseURL()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MCP public URL is not configured"})
		return
	}
	payload, err := pluginZIP(base)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build plugin package"})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="grok-search-plugin.zip"`)
	c.Data(http.StatusOK, "application/zip", payload)
}

func (h *Handler) canonicalBaseURL() (string, error) {
	if h.publicBaseURL == nil {
		return "", errors.New("missing public URL")
	}
	raw := strings.TrimRight(strings.TrimSpace(h.publicBaseURL()), "/")
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid public URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func pluginZIP(base string) ([]byte, error) {
	plugin := map[string]any{
		"$schema":     "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
		"name":        "grok-search",
		"version":     "1.0.0",
		"description": "Search the web with Grok through a stateless MCP server.",
	}
	mcp := map[string]any{
		"$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
		"mcpServers": map[string]any{"grok": map[string]any{
			"type": "streamable-http",
			"url":  base + "/mcp",
			"extensions": map[string]any{"com.openai": map[string]any{
				"auth": map[string]any{"type": "oauth", "baseScopes": []string{"search"}, "client": map[string]string{"mode": "dcr"}},
			}},
		}},
	}

	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range []struct {
		name string
		data any
	}{{"plugin.json", plugin}, {"mcp.json", mcp}} {
		data, err := json.MarshalIndent(file.data, "", "  ")
		if err != nil {
			return nil, err
		}
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetModTime(time.Unix(0, 0).UTC())
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(append(data, '\n')); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
