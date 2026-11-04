# 飞书企业成员 SSO（本地开发版）

多个本地 Go 项目共用一个 OIDC 登录中心。飞书测试企业的自建应用是唯一登录入口。Ory Hydra 提供 OIDC 协议、客户端登记及令牌；本项目的 Go 服务处理飞书授权回调。两个演示项目用于验证同一成员在不同项目获得相同的 `sub`。

## 运行条件

- Docker Desktop 和 Docker Compose
- Go 1.27（也可以用 Docker 的 `golang:1.27.1` 镜像编译）
- 已创建并启用的飞书企业自建应用，应用可用范围包含测试成员；登录回调地址为 `http://localhost:9000/auth/feishu/callback`

把 `.env.example` 复制为 `.env`，填入 App ID、App Secret、回调地址、测试企业的 `tenant_key`、本机数据库连接地址和不少于 32 字符的 `SSO_SERVICE_KEY`。同一个服务密钥必须配置到报销项目的 `.env.local`；报销 Go API 使用它调用 `/internal/session-status` 校验登录会话。`tenant_key` 必须与飞书登录用户信息返回的 `tenant_key` 完全一致；未配置时登录服务拒绝启动，字段缺失或不匹配时拒绝登录。可在飞书开放平台的[「获取登录用户信息」接口](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get)调试页使用测试成员身份确认该字段。`.env` 已被 Git 忽略。不要把真实凭证写入提交或问题反馈。

为了让报销 Web 与机器人识别同一企业成员，SSO 应用还需开通获取用户 user ID 的通讯录字段权限 `contact:user.employee_id:readonly`，并将测试员工纳入可见范围。SSO 在登录时使用本应用凭证查询 `user_id`；查询失败会拒绝登录，不会按姓名或应用 `open_id` 猜测跨应用身份。

## 启动

在仓库目录执行：

```powershell
docker compose up -d --build
./scripts/register-clients.ps1
```

`docker compose` 会启动 PostgreSQL、Hydra、Go 登录服务和项目 A/B。浏览器继续使用 `http://localhost:9000`；同一 Compose 网络中的项目通过 `sso:9000` 查询会话状态。需要单独调试 Go 服务时，先停止 `sso` 容器，再运行 `go run ./cmd/sso`。

`register-clients.ps1` 还会登记 Multica 的本地 OIDC 客户端 `multica-web`：授权码回调为 `http://localhost:8080/auth/feishu/callback`，退出回调为 `http://localhost:8080/auth/feishu/logged-out`（再跳转到网页登录页），允许 `openid profile email feishu_identity` scope。Multica 以 PKCE 发起授权请求；飞书工作邮箱通过 `email` claim 传递，`email_verified` 为 `false`。

若 Windows 尚未安装 Go，可用已有的 Go Docker 镜像编译 Windows 程序：

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace -e GOOS=windows -e GOARCH=amd64 golang:1.27.1 go build -o bin/sso.exe ./cmd/sso
./bin/sso.exe
```

打开 [项目 A](http://localhost:3100) 登录，再打开 [项目 B](http://localhost:3101)；两处显示的成员 ID 应一致。从任一项目点“退出所有项目”后，刷新两个项目均应显示已退出，重新登录需重新走授权。换另一名成员时，用独立浏览器会话分别测试。OIDC 发现文档位于 `http://localhost:4444/.well-known/openid-configuration`。

## 本地端口

| 服务 | 地址 |
| --- | --- |
| Hydra OIDC 公开端口 | `http://localhost:4444` |
| Hydra 管理端口，仅绑定本机 | `http://localhost:4445` |
| PostgreSQL，仅绑定本机 | `127.0.0.1:5433` |
| Go 飞书登录服务 | `http://localhost:9000` |
| 演示项目 A / B | `http://localhost:3100` / `http://localhost:3101` |

Hydra 与 PostgreSQL 容器使用固定的**本地开发专用**密钥和密码，不能直接用于线上。`demo-a`、`demo-b` 是公开客户端，使用授权码和 PKCE，并登记后端退出通知地址。新增本地项目时，在 Hydra 登记独立客户端 ID、精确回调地址、退出后地址与后端退出地址；如需退出后立即停止访问受保护页面，也需查询本 SSO 的会话撤销状态。

## 当前边界

- 成员资格依赖飞书企业自建应用的企业归属与可用范围，并在登录时核对 `tenant_key`。未另外同步通讯录或实现实时禁用事件；已签发的离线令牌不会因此自动撤回。
- Hydra 2.3 的后端退出通知是异步的。演示项目在每次提供受保护页面前额外查询已撤销会话；SSO 或数据库不可用时拒绝访问。
- 内部 `sub` 根据 App ID 与飞书 `open_id` 稳定生成。切换飞书应用会产生新的 `sub`；当前没有账户迁移流程。
- 初版登录链路已由两名测试成员验证；加入企业标识校验后，测试企业成员已在项目 A/B 实测登录与统一退出。另一名成员在同时登录时是否保持独立会话，仍建议用独立浏览器会话验证。飞书回调若不接受 localhost，需要调整飞书平台和 `.env` 中的地址，并提供能到达本机的 HTTPS 回调入口。

架构细节见 [设计说明](docs/architecture.md)。

## 持续集成

`.github/workflows/ci.yml` 在 push 和 pull request 时使用临时 PostgreSQL 执行 `go test ./...`、`go vet ./...` 与 SSO 二进制构建。数据库测试会通过 `TEST_DATABASE_URL` 运行；真实飞书授权、Hydra 联调和跨项目退出仍需按上面的本地路径验收。
