# RustGate —— 基于 Rust 的 Web 应用防火墙（WAF）

[![CI](https://github.com/ettry/rustgate/actions/workflows/ci.yml/badge.svg)](https://github.com/ettry/rustgate/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ettry/rustgate/branch/main/graph/badge.svg)](https://codecov.io/gh/ettry/rustgate)

RustGate 是一个高性能、可热加载规则的 Web 应用防火墙：
反向代理流量 → 规则引擎检测 → 拦截或流式转发到后端。

- **核心引擎**：字面量（Aho-Corasick 多模式，ASCII 大小写不敏感）+ 正则（regex），打分制判定
- **请求归一化**：URL 解码、控制字节（NUL 等）归一化、按 header 名细分匹配
- **CC 防护**：每 IP 令牌桶限流，参数进 `rules.toml`
- **规则热加载**：定期轮询（1s），新规则失败保留旧引擎
- **审计日志**：拦截事件 JSONL 落盘，10MB×5 轮转，连续重复告警去重（保留 count）
- **管理 API + Web UI**：`/api/stats`、`/api/alerts`、`/ws/alerts`，内嵌零依赖 Web 仪表盘
- **可选 Flutter 面板**：`flutter_dashboard/`（跨端展示，日常用 Web UI 即可）

## 架构

```
客户端
  │
  ▼
RustGate WAF (127.0.0.1:9000)         管理 API (127.0.0.1:9001)
  │ 限流 → 规则引擎 → 放行/拦截          ├─ /api/stats     统计
  ▼                                      ├─ /api/alerts    最近告警
后端服务 (RUSTGATE_BACKEND)              ├─ /ws/alerts     WebSocket 实时告警
                                         └─ /              Web 仪表盘
```

## 快速开始

### 1. 编译

```bash
cargo build --release
sudo cp target/release/rustgate /usr/local/bin/rustgate
```

### 2. 准备配置目录

```bash
sudo mkdir -p /var/lib/rustgate/log
sudo cp rules/rules.toml /var/lib/rustgate/rules.toml
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustgate
sudo chown -R rustgate:rustgate /var/lib/rustgate
```

> 若 `/var` 不可写（开发环境），用环境变量覆盖：
> `export RUSTGATE_CONFIG_DIR=/tmp/rustgate`。

### 3. 设置

-s：web端监听地址，-t：UI api令牌，-a：UI api监听地址，-l：软件监听地址，-c：cert，-k：key  
（如果-s协议为https必须添加-c和-k参数）  

```bash
rustgate --setting \
  -s http://127.0.0.1:8080 \
  -t my-secret-token \
  -a 127.0.0.1:9090 \
  -l 127.0.0.1:80 \
  -c /home/test/test.pem \
  -k /hoem/test/test.key
```

### 4. 启动 WAF

```bash
rustgate waf  
```

### 5. 打开 Web 面板

浏览器访问 -a参数设置的地址并设置token即可使用。

### 6. 验证拦截

```bash
# 正常请求 → 200
curl -i http://127.0.0.1:9000/index.html

# SQL 注入 → 403
curl -i "http://127.0.0.1:9000/?q=1+union+select"  
```

## 规则配置（rules.toml）

```toml
score_threshold = 20        # 累计分数 >= 阈值即拦截
cc_capacity = 100           # CC 令牌桶容量
cc_refill_per_sec = 10      # CC 每秒补充

[[rules]]
id = 1
name = "SQLi: union select"
category = "sqli"
field = "Args"              # Url | Args | Header | Body | Method
pattern = "union select"    # 字面量；"regex:" 前缀走正则
score = 20
header = "User-Agent"       # 可选：仅 field="Header" 时按指定 header 匹配
```

编辑 `rules.toml` 保存后 5 秒内自动热加载，无需重启；新规则解析失败会保留旧引擎并打 WARN。
`cc_capacity` / `cc_refill_per_sec` 也会一并热加载生效（代价是所有 IP 的令牌桶重置）。

## 测试

```bash
cargo test                                # 单元测试（当前 94 个：lib 35 + bin 24 + 集成 35）
bash tests/qa/run_qa.sh                         # QA 端到端
cargo llvm-cov --all-targets              # 覆盖率
cargo clippy --all-targets -- -W clippy::cognitive_complexity   # 复杂度
cargo audit                               # 依赖漏洞扫描
cargo mutants -f 'src/engine.rs' -f 'src/limiter.rs' -f 'src/bus.rs' -- --bin rustgate  # 变异测试
cd fuzz && cargo +nightly fuzz run engine_fuzz -- -max_len=512 -runs=20000  # Fuzz
```

手工 curl 攻击用例备忘见项目根目录 `test` 文件（QA 脚本已自动化这些用例）。
BDD 场景见 `tests/qa/features/waf.feature`（Gherkin），与 `tests/qa/run_qa.sh` 用例一一映射。

```bash
bash tests/qa/soak_test.sh 30         # Soak：30s 混合流量，观察内存/fd 泄漏
bash tests/qa/fault_injection.sh      # 错误注入：后端宕机/慢响应/恢复
```

## systemd 部署

完整 unit 文件见 `deploy/rustgate.service`，核心配置：

```ini
[Service]
User=rustgate
Group=rustgate
ExecStart=/usr/local/bin/rustgate waf
Environment=RUSTGATE_CONFIG_DIR=/var/lib/rustgate
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rustgate
Restart=on-failure
```

安装：

```bash
sudo cp deploy/rustgate.service /etc/systemd/system/rustgate.service
sudo systemctl daemon-reload
sudo systemctl enable --now rustgate
```

## 部署规范与安全建议

以下为生产环境推荐配置，请按清单逐项核对后再对外暴露流量。

### 1. 管理 API 与 Web 面板：只绑内网，不要监听外网

`-a`（api_addr）只允许绑 `127.0.0.1` 或内网地址，**严禁**绑定 `0.0.0.0` 对外暴露：

```bash
# ✅ 推荐
rustgate --setting ... -a 127.0.0.1:9090 ...

# ❌ 禁止
rustgate --setting ... -a 0.0.0.0:9090 ...
```

远程管理方式（任选其一）：

- **SSH 隧道**（最推荐）：`ssh -L 9090:127.0.0.1:9090 user@server`，本地浏览器访问 `http://127.0.0.1:9090`
- **TLS 反代**：用 Caddy/nginx 在管理 API 前终结 HTTPS，且仅对受信任来源放行
- 管理 API 本身**不支持** HTTPS（代码里未实现），明文 HTTP 直接暴露公网会导致 token 被链路窃听

### 2. API token 强度

- token 长度**至少 16 位**，建议 **32+ 位**随机串（本审计建议下限 10 位以上，生产请更高）：

```bash
# 生成随机 token
openssl rand -hex 32
```

- 不要使用默认占位值 `dev-token-change-me`，也不要复用明文出现在代码/脚本里的 token
- 管理 API 无认证失败限速，token 越强越安全

### 3. 绑定 80/443 端口（<1024）

非 root 用户（`User=rustgate`）绑定 <1024 端口需要授权能力，在 `deploy/rustgate.service` 取消注释：

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

> 若运营商封 80/443（常见），继续用高端口（如 19191/19193）即可，无需此能力。

### 4. 文件与权限

| 路径 | 权限 | 说明 |
|---|---|---|
| `/usr/local/bin/rustgate` | 750（root:rustgate） | 运行用户只读+执行 |
| `/var/lib/rustgate` | 700（rustgate:rustgate） | 配置目录 |
| `/var/lib/rustgate/settings` | 600 | 含 token，勿放宽 |
| `/var/lib/rustgate/log/` 审计日志 | 目录 700 / 文件 600 | 自动按此创建 |
| TLS 私钥 | 640（root:rustgate） | 仅运行用户可读 |

### 5. 可信代理与真实 IP

- WAF 直连客户端时：**不要**设置 `RUSTGATE_TRUSTED_PROXIES`，WAF 直接用 TCP 对端 IP（防 XFF 伪造）
- WAF 前面还有 Caddy/nginx 时：必须把代理地址填入 `RUSTGATE_TRUSTED_PROXIES`，否则会误把代理 IP 当真实客户端
- 转发到后端时 WAF 会剥离伪造的 `X-Forwarded-For` 并写入真实客户端 IP

### 6. 部署后自检清单

```bash
# 1) 管理 API 是否只监听内网？
ss -lntp | grep 9090      # 应显示 127.0.0.1:9090，而不是 0.0.0.0

# 2) token 是否过弱？
cat /var/lib/rustgate/settings | sed -n 2p | awk '{print length}'   # 长度 ≥ 16

# 3) 权限是否正确？
ls -l /usr/local/bin/rustgate /var/lib/rustgate /var/lib/rustgate/settings

# 4) 远程访问面板是否走了 SSH 隧道或 TLS？
# 5) 依赖漏洞扫描？
cargo audit
```

## 目录结构

```
rustgate/
├── src/                    # Rust 源码（lib + bin）
│   ├── lib.rs              # 库入口（测试/fuzz 复用）
│   ├── main.rs             # 二进制入口：CLI、反代、热加载
│   ├── engine.rs           # 规则引擎 + 请求归一化
│   ├── config.rs           # rules.toml 解析
│   ├── limiter.rs          # 令牌桶限流
│   ├── block.rs            # 内存 IP 黑名单（管理 API 封禁）
│   ├── bus.rs              # 告警总线（统计/去重/广播）
│   └── api.rs              # 管理 API + Web UI + WebSocket
├── rules/rules.toml        # 规则模板
├── deploy/                 # systemd unit 文件
├── flutter_dashboard/      # 可选 Flutter 面板
├── tests/                  # 测试目录 
│   ├─ fuzz                 # fuzz测试目录
│   ├─ api_integration.rs   # 网络io测试
│   └─ qa                   # qa测试目录
└── .github/workflows/      # CI（fmt/clippy/test）
```

## 安全说明

- 审计日志只记拦截事件；放行请求用 `RUST_LOG=rustgate=debug` 查看

## License

MIT
