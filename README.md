# 飞书企业成员 SSO（本地开发版）

多个本地 Go 项目共用一个 OIDC 登录中心。飞书测试企业的自建应用是唯一登录入口。Ory Hydra 提供 OIDC 协议、客户端登记及令牌；本项目的 Go 服务处理飞书授权回调。两个演示项目用于验证同一成员在不同项目获得相同的 `sub`。

## 运行条件

- Docker Desktop 和 Docker Compose
- Go 1.27（也可以用 Docker 的 `golang:1.27.1` 镜像编译）
- 已创建并启用的飞书企业自建应用，应用可用范围包含测试成员；登录回调地址为 `http://localhost:9000/auth/feishu/callback`

把 `.env.example` 复制为 `.env`，填入 App ID、App Secret、回调地址和测试企业的 `tenant_key`。`tenant_key` 必须与飞书登录用户信息返回的 `tenant_key` 完全一致；未配置时登录服务拒绝启动，字段缺失或不匹配时拒绝登录。可在飞书开放平台的「获取登录用户信息」API 调试页使用测试成员身份确认该字段。`.env` 已被 Git 忽略。不要把真实凭证写入提交或问题反馈。

## 启动

在仓库目录执行：

```powershell
docker compose up -d
./scripts/register-clients.ps1
go run ./cmd/sso
```

另开两个终端：

```powershell
go run ./cmd/demo -port 3100
go run ./cmd/demo -port 3101
```

若 Windows 尚未安装 Go，可用已有的 Go Docker 镜像编译 Windows 程序：

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace -e GOOS=windows -e GOARCH=amd64 golang:1.27.1 go build -o bin/sso.exe ./cmd/sso
docker run --rm -v "${PWD}:/workspace" -w /workspace -e GOOS=windows -e GOARCH=amd64 golang:1.27.1 go build -o bin/demo.exe ./cmd/demo
./bin/sso.exe
./bin/demo.exe -port 3100
./bin/demo.exe -port 3101
```

这些进程需分别占用终端。打开 [项目 A](http://localhost:3100) 登录，再打开 [项目 B](http://localhost:3101)；两处显示的成员 ID 应一致。换另一名成员时，用独立浏览器会话分别测试。OIDC 发现文档位于 `http://localhost:4444/.well-known/openid-configuration`。

## 本地端口

| 服务 | 地址 |
| --- | --- |
| Hydra OIDC 公开端口 | `http://localhost:4444` |
| Hydra 管理端口，仅绑定本机 | `http://localhost:4445` |
| Go 飞书登录服务 | `http://localhost:9000` |
| 演示项目 A / B | `http://localhost:3100` / `http://localhost:3101` |

Hydra 与 PostgreSQL 容器使用固定的**本地开发专用**密钥和密码，不能直接用于线上。`demo-a`、`demo-b` 是公开客户端，使用授权码和 PKCE。新增本地项目时，在 Hydra 登记独立客户端 ID 与精确回调地址，并按 OIDC 发现文档集成。

## 当前边界

- 成员资格依赖飞书企业自建应用的企业归属与可用范围，以及登录时飞书返回的有效用户信息。未另外同步通讯录或实现实时禁用事件。
- 演示项目的“退出此应用”只清除该项目的本地会话；Hydra 登录会话仍可能使再次登录自动完成。跨项目统一退出尚未实现。
- 内部 `sub` 根据 App ID 与飞书 `open_id` 稳定生成。切换飞书应用会产生新的 `sub`；当前没有账户迁移流程。
- 尚未在真实飞书浏览器登录中验证完整链路。飞书回调若不接受 localhost，需要调整飞书平台和 `.env` 中的地址，并提供能到达本机的 HTTPS 回调入口。

架构细节见 [设计说明](docs/architecture.md)。
