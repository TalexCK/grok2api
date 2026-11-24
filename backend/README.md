# Grok2API Backend

Grok2API 的 Go 后端，负责上游账号调度、协议转换、额度管理、请求审计和管理 API，并可直接托管前端构建产物。

## 技术栈

- Go 1.26、Gin、GORM
- SQLite / PostgreSQL
- Memory / Redis
- Grok Build OAuth、Grok Web SSO 与 Grok Console SSO Provider

## 本地运行

配置文件位于仓库根目录。首次运行前创建本地配置并设置安全密钥：

```bash
cp config.example.yaml config.yaml
openssl rand -hex 32
openssl rand -base64 32
```

将生成值写入 `config.yaml` 的 `secrets`，并修改 `bootstrapAdmin` 初始密码，然后启动：

```bash
cd backend
go run ./cmd/grok2api
```

服务默认监听 `http://127.0.0.1:8000`。也可以显式指定配置文件或监听地址：

```bash
go run ./cmd/grok2api --config /path/to/config.yaml --listen 0.0.0.0:8000
```

## 配置与存储

启动配置统一由根目录 `config.yaml` 管理，启动阶段字段见 [`config.example.yaml`](../config.example.yaml)。Provider、服务容量、批量任务、路由、媒体、审计和客户端密钥默认限制由管理端设置页持久化；除页面明确标记“重启生效”的字段外均会热加载。

PostgreSQL DSN 也可通过非空的 `GROK2API_DATABASE_URL` 注入；它的优先级高于 YAML，并会自动将数据库驱动切换为 `postgres`。空值不覆盖 YAML，程序不会隐式读取通用的 `DATABASE_URL`。

| 场景 | 数据库 | 运行态存储 |
| --- | --- | --- |
| 本地开发 / 单实例 | SQLite | Memory |
| 多实例部署 | PostgreSQL | Redis |

关系型数据库保存账号、凭据、模型、额度、客户端密钥、审计和媒体任务；Redis 仅承载限流、并发租约、粘滞路由、分布式锁和事件通知。敏感凭据使用 `credentialEncryptionKey` 加密，该密钥必须长期保留且不得提交到版本库。

运行设置与代理参数由管理端设置页维护；数据库驱动、监听地址、Redis、JWT 与加密密钥仍通过 YAML 配置并在启动时生效。

## 服务入口

- `/v1/*`：兼容 API
- `/api/admin/v1/*`：管理 API
- `/healthz`、`/readyz`：健康与就绪探针
- `/swagger/index.html`：公开 API Swagger，仅在 `server.swaggerEnabled: true` 时注册
- `/mcp`：供 ChatGPT Web 使用的 Streamable HTTP MCP，仅提供 `search(search_prompt)`
- `/mcp/plugin.zip`：动态生成带当前公开地址的 OpenAI 插件 ZIP，不包含凭据
- `/.well-known/oauth-*`、`/oauth/*`：MCP OAuth 发现、授权、令牌与撤销接口
- `frontend.staticPath`：前端静态目录，默认 `./frontend/dist`

详细协议说明见 [`docs`](./docs)。

修改公开接口注释后，在仓库根目录执行 `make swagger` 更新 `backend/docs/docs.go`、`swagger.json` 与 `swagger.yaml`。生产配置应保持 `server.swaggerEnabled: false`。

## ChatGPT Web MCP

1. 在管理端导入可用的 Grok Web SSO 账号，启用 `grok-chat-fast`，创建有权调用该模型的 Client Key。MCP 固定使用 Web fast，不经过公开模型别名，也不会回退到 Build、Console 或其他模型。
2. 将服务部署到可从 ChatGPT 访问的 HTTPS 地址，在管理端设置「公开 API 地址」为该地址（或通过 `frontend.publicApiBaseURL` 启动配置设置）。反向代理须转发 `/mcp`、`/oauth/*` 和 `/.well-known/*`；不要缓冲或截断长时间运行的 MCP POST。
3. 在 [ChatGPT Plugins](https://chatgpt.com/plugins) 添加自定义 MCP server，URL 填 `https://你的域名/mcp`，认证选择 OAuth（Dynamic Client Registration）。在跳转到本服务的授权页中输入 Client Key，确认仅授予 `search` 权限。Client Key 只提交给本服务，不会交给 ChatGPT。
4. 如果需要插件包，下载 `https://你的域名/mcp/plugin.zip`。ZIP 根目录包含 `plugin.json` 和 `mcp.json`，自动使用已配置的公开地址；修改域名后需重新下载。可按 [OpenAI 插件打包与安装指南](https://developers.openai.com/plugins/build/plugins)使用，公开目录上传入口为 [Plugins](https://platform.openai.com/plugins)。ZIP 不包含服务端程序，不能替代已部署的 MCP。

唯一工具：

```json
{"name":"search","arguments":{"search_prompt":"需要交给 Grok 的完整问题"}}
```

`search_prompt` 原样作为一条 user 消息发送给 Grok Web fast，等待完整回复后返回 MCP 文本结果。工具名不代表强制联网搜索；是否检索由 Grok 自身决定。输入也不会被追加系统提示或转换成 `search`/`fetch` 文档协议。

OAuth 使用授权码、PKCE S256、短期 access token 和轮换 refresh token。授权状态存入关系型数据库，Client Key 加密保存，每次调用继续校验原 Key 的启用状态、有效期、模型权限、额度、RPM 与并发限制，并复用原有请求审计；禁用或删除 Client Key 可停止该授权访问。OAuth 令牌只能用于 `/mcp`，不能调用 `/v1` 或管理 API。请使用专用、限权限额的 Client Key；查询内容会发送给 Grok，回复也会传给 ChatGPT。

授权页的 CSP 仅允许本站与已注册的回调来源，避免 Chrome 拦截提交后的跨域 OAuth 跳转；反向代理不要额外叠加仅含 `form-action 'self'` 的 CSP。若旧版本曾显示验证成功但没有跳转，请更新服务后从 ChatGPT 重新开始授权，不要重复提交已经消费的一次性授权页。

本地 HTTP 仅适合开发；ChatGPT 远程连接需使用公开 HTTPS（或自行配置受支持的安全隧道）。本项目不自动发布插件、不自动确认 ChatGPT 的风险提示，也不代理 Grok 账号登录。

## 代码结构

```text
cmd/grok2api/       进程入口
internal/domain/    领域模型与规则
internal/application/ 应用服务与用例
internal/infra/     数据库、Provider、运行态与安全实现
internal/transport/ HTTP 路由、鉴权与协议适配
internal/repository/ 持久化接口
```

依赖方向保持为 Transport → Application → Domain，基础设施通过接口接入，不在领域层依赖 HTTP、数据库或具体 Provider。

三个 Provider 通过声明式 Definition 和小型能力接口注册：Build 使用远程模型目录与 Billing，Web 使用按等级过滤的静态目录与上游额度窗口，Console 使用静态目录和无状态 Responses。Gateway 只根据能力声明完成路由与调度，不在通用 Handler 中拼装 Provider 私有请求。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/grok2api
```
