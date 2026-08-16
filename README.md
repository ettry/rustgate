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
  ▼                                     ├─ /api/alerts    最近告警
后端服务 (RUSTGATE_BACKEND)             ├─ /ws/alerts     WebSocket 实时告警
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
> `export RUSTGATE_CONFIG_DIR=/tmp/rustgate`，并把 `rules.toml` 放进去。

### 3. 设置后端与 token

```bash
rustgate --setting -s http://127.0.0.1:8080 -t my-secret-token
```

### 4. 启动 WAF

```bash
rustgate waf                 # 默认监听 127.0.0.1:9000
rustgate waf 0.0.0.0:9000   # 自定义监听地址
```

### 5. 打开 Web 面板

浏览器访问 `http://127.0.0.1:9001`，点 ⚙ 设置填 token 即可。

### 6. 验证拦截

```bash
# 正常请求 → 200
curl -i http://127.0.0.1:9000/index.html

# SQL 注入 → 403
curl -i "http://127.0.0.1:9000/?q=1+union+select"
```

## 命令行

```
rustgate waf [监听地址]                     启动 WAF
rustgate --setting -s <后端> -t <token>     保存后端地址与 API token
rustgate --help                             帮助
```

`--setting` 可选参数：`-a <api地址>`、`-l <waf监听地址>`。
同名环境变量（`RUSTGATE_BACKEND` / `RUSTGATE_API_TOKEN` / `RUSTGATE_API`）优先于 settings 文件。

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

编辑 `rules.toml` 保存后 1 秒内自动热加载，无需重启；新规则解析失败会保留旧引擎并打 WARN。

## 测试

```bash
cargo test                                # 单元测试（10 个）
bash qa/run_qa.sh                         # QA 端到端（10 个用例）
cargo llvm-cov --all-targets              # 覆盖率
cargo clippy --all-targets -- -W clippy::cognitive_complexity   # 复杂度
cargo audit                               # 依赖漏洞扫描
cargo mutants -f 'src/engine.rs' -f 'src/limiter.rs' -f 'src/bus.rs' -- --bin rustgate  # 变异测试
cd fuzz && cargo +nightly fuzz run engine_fuzz -- -max_len=512 -runs=20000  # Fuzz
```

手工 curl 攻击用例备忘见项目根目录 `test` 文件（QA 脚本已自动化这些用例）。
BDD 场景见 `qa/features/waf.feature`（Gherkin），与 `qa/run_qa.sh` 用例一一映射。

```bash
bash qa/soak_test.sh 30         # Soak：30s 混合流量，观察内存/fd 泄漏
bash qa/fault_injection.sh      # 错误注入：后端宕机/慢响应/恢复
```

## systemd 部署

见 `qa/` 目录外，完整 unit 示例：

```ini
[Service]
User=rustgate
Group=rustgate
ExecStart=/usr/local/bin/rustgate waf
Environment=RUSTGATE_CONFIG_DIR=/var/lib/rustgate
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rustgate
Restart=on-failure
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
│   ├── bus.rs              # 告警总线（统计/去重/广播）
│   └── api.rs              # 管理 API + Web UI + WebSocket
├── rules/rules.toml        # 规则模板
├── qa/                     # QA 脚本 + Gherkin feature
├── fuzz/                   # cargo-fuzz 目标
├── bench/                  # 压测说明
├── data/                   # 答辩数据（项目指标/测试数据/答辩要点）
├── flutter_dashboard/      # 可选 Flutter 面板
└── .github/workflows/      # CI（fmt/clippy/test）
```

## 安全说明

- 管理 API 默认只监听 `127.0.0.1:9001`；远程访问请用 nginx/caddy 终结 TLS 后反代
- settings 文件保存为 0600 权限，token 打印时脱敏
- 不要以 root 长期运行；绑定 80/443 请用 `CAP_NET_BIND_SERVICE` 或前置反代
- 审计日志只记拦截事件；放行请求用 `RUST_LOG=rustgate=debug` 查看

## License

MIT（示例项目可自行调整）
