# 外部项目自助登记 OIDC 客户端设计

## 意图与范围

新增本地项目接入 SSO 时，项目维护者应只在自己的仓库编写客户端配置并运行通用注册命令，不再修改本仓库的项目列表或 Go 登录服务。现有 `demo-a`、`demo-b`、`reimbursement-web`、`multica-web` 的客户端 ID、回调、scope、同意页和退出行为保持原样。

本次只改客户端注册工具、现有客户端的配置载体、脚本测试和使用文档。各项目的 OIDC 登录、会话、权限与退出处理仍由该项目负责；不增加 SSO 管理后台，不开放 Hydra Admin API 到公网，不改数据库结构或身份 claim。

## 考虑过的方案

1. **继续把每个项目写进 `client-config.ps1`：**改动最少，但每次接入仍需提交 SSO 仓库，不能解决问题。
2. **通用命令读取项目仓库中的 JSON 配置：**复用当前 PowerShell 与 Hydra Admin API，接入流程轻量，适合当前个人本地开发。**采用此方案。**
3. **建设管理后台或动态客户端注册 API：**适合多团队自助审批与审计；当前会引入新的管理身份、权限与运维负担，暂不建设。

## 配置与命令契约

- 将现有四个客户端迁到本仓库受版本控制的默认 JSON 配置。无参数执行 `scripts/register-clients.ps1` 时仍登记这四个客户端，原有启动步骤不变。
- 新项目在自己的仓库保存一个 JSON 文件，调用 `scripts/register-clients.ps1 -ConfigPath <文件路径>`。该命令只处理传入文件中的客户端，不顺带更新或删除默认客户端；相对路径按调用者当前目录解析。
- 每个客户端配置包含 `client_id`、非空 `redirect_uris`、非空 `post_logout_redirect_uris`、`scope`；可选 `backchannel_logout_uri` 和 `skip_consent`。本地 Web 客户端固定采用 authorization code、PKCE、公有客户端（`token_endpoint_auth_method=none`）。`scope` 使用包含 `openid` 的数组，注册时转换为 Hydra 需要的空格分隔字符串。
- URI 必须是完整的 `http` 或 `https` URL，禁止 URL 凭据与 fragment；客户端 ID、scope 和配置字段严格校验。允许本地开发所需的 `localhost`、Compose 服务名及 `host.docker.internal` 地址。配置文件不包含密钥。
- 先读取并校验完整文件，再向 Hydra 发送任何写请求。重复执行且配置未变时只读、不更新。已存在客户端的受管理字段发生变化时显示差异；只有显式指定 `-Update` 才更新，且不得清除未受管理字段。发现不兼容的现有客户端类型或无法安全保留字段时拒绝更新。
- 注册仅允许访问本机可达的 Hydra Admin 地址；默认 `http://localhost:4445`，可通过显式参数指定其他受信任的管理地址，不能把管理入口暴露给浏览器或项目运行时代码。

示例（新项目仓库中的 `sso-client.json`）：

```json
{
  "client_id": "example-web",
  "redirect_uris": ["http://localhost:4200/auth/callback"],
  "post_logout_redirect_uris": ["http://localhost:4200/logged-out"],
  "backchannel_logout_uri": "http://host.docker.internal:4200/auth/backchannel-logout",
  "scope": ["openid", "profile", "feishu_identity"],
  "skip_consent": false
}
```

新项目的真实接入仍需实现授权码 + PKCE、ID Token 验签与 claim 校验、本地会话管理。若要求从任一项目退出后立即失效，还需实现后端退出通知及会话撤销状态检查。客户端登记本身不提供这些能力。

## 兼容与验收

- 默认配置生成的四个 Hydra 客户端字段与当前 `Get-SSOClients` 输出完全一致；首次执行不改变现有客户端的注册信息或登录行为。
- 脚本测试覆盖默认四客户端、外部文件注册、重复执行无写入、显式更新、无 `-Update` 时拒绝覆盖、无效 URI/字段在任何写请求前失败，以及其他客户端不受影响。
- 对本地 Hydra 先做只读对照，再运行默认注册和一个临时外部客户端的创建/重复注册/显式更新验证；最后删除临时客户端。实际测试企业成员的登录与跨项目退出沿用现有验收路径。
- 本次不迁移现有应用仓库。它们将来只有需要自行维护登记配置时，才添加各自的 JSON 文件；保留客户端 ID 和 URL 时无需修改应用登录代码。
