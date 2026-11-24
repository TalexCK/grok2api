package mcpauth

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	mcpauthapp "github.com/chenyme/grok2api/backend/internal/application/mcpauth"
	"github.com/chenyme/grok2api/backend/internal/transport/http/middleware"
	"github.com/gin-gonic/gin"
)

const (
	maxOAuthBody = 64 << 10
	csrfCookie   = "mcp_oauth_csrf"
)

type Handler struct {
	service   *mcpauthapp.Service
	publicURL func() string
}

func NewHandler(service *mcpauthapp.Service, publicURL func() string) *Handler {
	return &Handler{service: service, publicURL: publicURL}
}

func (h *Handler) Register(router *gin.Engine) {
	router.GET("/.well-known/oauth-protected-resource", h.protectedResource)
	router.GET("/.well-known/oauth-protected-resource/mcp", h.protectedResource)
	router.GET("/.well-known/oauth-authorization-server", h.authorizationServer)
	router.GET("/.well-known/oauth-authorization-server/*issuerPath", h.authorizationServer)
	router.GET("/oauth/authorize", h.authorizeGET)
	router.POST("/oauth/authorize", h.limitBody(), h.authorizePOST)
	router.POST("/oauth/token", h.limitBody(), h.token)
	router.POST("/oauth/register", h.limitBody(), h.register)
	router.POST("/oauth/revoke", h.limitBody(), h.revoke)
}

func (h *Handler) base() string     { return strings.TrimRight(h.publicURL(), "/") }
func (h *Handler) resource() string { return h.base() + "/mcp" }

func (h *Handler) protectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"resource": h.resource(), "authorization_servers": []string{h.base()},
		"bearer_methods_supported": []string{"header"}, "scopes_supported": []string{mcpauthapp.Scope},
	})
}

func (h *Handler) authorizationServer(c *gin.Context) {
	base := h.base()
	c.JSON(http.StatusOK, gin.H{
		"issuer": base, "authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint": base + "/oauth/token", "registration_endpoint": base + "/oauth/register",
		"revocation_endpoint": base + "/oauth/revoke", "response_types_supported": []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": []string{mcpauthapp.Scope},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (h *Handler) limitBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxOAuthBody)
		c.Next()
	}
}

func (h *Handler) publicLimit(c *gin.Context, kind string) bool {
	if err := h.service.AllowPublic(c.Request.Context(), kind+":"+c.ClientIP(), 30); err != nil {
		status := http.StatusTooManyRequests
		if errors.Is(err, mcpauthapp.ErrRuntimeUnavailable) {
			status = http.StatusServiceUnavailable
		}
		oauthError(c, status, "temporarily_unavailable", "服务暂不可用")
		return false
	}
	return true
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

func (h *Handler) register(c *gin.Context) {
	if !h.publicLimit(c, "register") {
		return
	}
	var in registrationRequest
	if err := c.ShouldBindJSON(&in); err != nil || len(in.RedirectURIs) != 1 ||
		(in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none") ||
		!onlyValues(in.GrantTypes, "authorization_code", "refresh_token") || !onlyValues(in.ResponseTypes, "code") {
		oauthError(c, http.StatusBadRequest, "invalid_client_metadata", "客户端注册信息无效")
		return
	}
	client, err := h.service.RegisterClient(c.Request.Context(), in.ClientName, in.RedirectURIs[0])
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_client_metadata", "客户端注册信息无效")
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id": client.ID, "client_name": client.Name, "redirect_uris": []string{client.RedirectURI},
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
	})
}

func (h *Handler) authorizeGET(c *gin.Context) {
	if !h.publicLimit(c, "authorize") {
		return
	}
	q := c.Request.URL.Query()
	if q.Get("response_type") != "code" || q.Get("resource") != h.resource() {
		oauthError(c, http.StatusBadRequest, "invalid_request", "授权请求无效")
		return
	}
	auth, err := h.service.BeginAuthorization(c.Request.Context(), q.Get("client_id"), q.Get("redirect_uri"), q.Get("state"), q.Get("code_challenge"), q.Get("code_challenge_method"), q.Get("resource"), q.Get("scope"))
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request", "授权请求无效")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: csrfCookie, Value: auth.CSRF, HttpOnly: true, Secure: strings.HasPrefix(h.base(), "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(c.Writer, gin.H{"ID": auth.ID, "Client": auth.ClientName})
}

func (h *Handler) authorizePOST(c *gin.Context) {
	if !h.publicLimit(c, "authorize") {
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request", "提交内容无效")
		return
	}
	csrf, err := c.Cookie(csrfCookie)
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request", "授权会话已失效")
		return
	}
	decision := c.PostForm("decision")
	if decision != "approve" && decision != "deny" {
		oauthError(c, http.StatusBadRequest, "invalid_request", "请选择允许或拒绝")
		return
	}
	location, err := h.service.Decide(c.Request.Context(), c.PostForm("transaction"), csrf, c.PostForm("client_key"), decision == "approve")
	if location != "" {
		c.Redirect(http.StatusFound, location)
		return
	}
	status := http.StatusUnauthorized
	if errors.Is(err, mcpauthapp.ErrRateLimited) {
		status = http.StatusTooManyRequests
	}
	if errors.Is(err, mcpauthapp.ErrRuntimeUnavailable) {
		status = http.StatusServiceUnavailable
	}
	oauthError(c, status, "access_denied", "Client Key 无效或不可用")
}

func (h *Handler) token(c *gin.Context) {
	if !h.publicLimit(c, "token") {
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request", "令牌请求无效")
		return
	}
	var out mcpauthapp.Tokens
	var err error
	switch c.PostForm("grant_type") {
	case "authorization_code":
		out, err = h.service.ExchangeCode(c.Request.Context(), c.PostForm("code"), c.PostForm("client_id"), c.PostForm("redirect_uri"), c.PostForm("code_verifier"), c.PostForm("resource"))
	case "refresh_token":
		out, err = h.service.Refresh(c.Request.Context(), c.PostForm("refresh_token"), c.PostForm("client_id"), c.PostForm("resource"))
	default:
		oauthError(c, http.StatusBadRequest, "unsupported_grant_type", "不支持的授权类型")
		return
	}
	if err != nil {
		status, code := http.StatusBadRequest, "invalid_grant"
		if errors.Is(err, mcpauthapp.ErrRuntimeUnavailable) {
			status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
		}
		oauthError(c, status, code, "授权凭据无效")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{"access_token": out.AccessToken, "token_type": "Bearer", "expires_in": out.ExpiresIn, "refresh_token": out.RefreshToken, "scope": out.Scope})
}

func (h *Handler) revoke(c *gin.Context) {
	if !h.publicLimit(c, "revoke") {
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request", "撤销请求无效")
		return
	}
	if err := h.service.Revoke(c.Request.Context(), c.PostForm("token")); err != nil {
		oauthError(c, http.StatusServiceUnavailable, "temporarily_unavailable", "服务暂不可用")
		return
	}
	c.Status(http.StatusOK)
}

func (h *Handler) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := bearer(c.GetHeader("Authorization"))
		if !ok {
			h.challenge(c, http.StatusUnauthorized, "invalid_token")
			return
		}
		key, release, err := h.service.Authenticate(c.Request.Context(), raw, h.resource())
		if err != nil {
			status, code := http.StatusUnauthorized, "invalid_token"
			if errors.Is(err, mcpauthapp.ErrRateLimited) {
				status, code = http.StatusTooManyRequests, "temporarily_unavailable"
			}
			if errors.Is(err, mcpauthapp.ErrRuntimeUnavailable) {
				status, code = http.StatusServiceUnavailable, "temporarily_unavailable"
			}
			h.challenge(c, status, code)
			return
		}
		defer release()
		c.Set(middleware.ClientKey, key)
		c.Next()
	}
}

func onlyValues(values []string, allowed ...string) bool {
	for _, value := range values {
		valid := false
		for _, candidate := range allowed {
			if value == candidate {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}
	return true
}

func (h *Handler) challenge(c *gin.Context, status int, code string) {
	c.Header("WWW-Authenticate", `Bearer resource_metadata="`+h.base()+`/.well-known/oauth-protected-resource", scope="search", error="`+code+`"`)
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

func bearer(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func oauthError(c *gin.Context, status int, code, description string) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": code, "error_description": description})
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权搜索访问</title><style>
body{margin:0;background:#f4f1e8;color:#17231b;font:17px/1.6 Georgia,"Noto Serif SC",serif}main{max-width:36rem;margin:8vh auto;padding:2rem;background:#fffdf7;border:1px solid #b8b09d;box-shadow:8px 8px 0 #d7ceba}h1{font-size:2rem;line-height:1.2;margin-top:0}label{display:block;font-weight:700;margin:1.5rem 0 .4rem}input{box-sizing:border-box;width:100%;min-height:48px;padding:.7rem;border:2px solid #405747;font:inherit}.actions{display:flex;gap:1rem;margin-top:1.5rem}button{min-height:48px;padding:.65rem 1.25rem;border:2px solid #17231b;background:#17231b;color:white;font:700 1rem Georgia,serif;cursor:pointer}button[value=deny]{background:white;color:#17231b}button:focus-visible,input:focus-visible{outline:4px solid #d0792b;outline-offset:3px}
</style></head><body><main><h1>允许搜索访问？</h1><p><strong>{{.Client}}</strong> 请求使用你的 Grok 搜索能力。</p><p>授权后，它只能调用 <strong>search</strong> 工具。你的 Client Key 不会发送给该客户端。</p><form method="post"><input type="hidden" name="transaction" value="{{.ID}}"><label for="client_key">Client Key</label><input id="client_key" name="client_key" type="password" autocomplete="off" required aria-describedby="key-help"><p id="key-help">仅用于验证并绑定本次授权。</p><div class="actions"><button type="submit" name="decision" value="approve">允许</button><button type="submit" name="decision" value="deny" formnovalidate>拒绝</button></div></form></main></body></html>`))
