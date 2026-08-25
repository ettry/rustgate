# RustGate 压测

## 前置

安装 [oha](https://github.com/hatoo/oha)（或 wrk）：

```bash
sudo pacman -S oha
# 或
cargo install oha
```

## 测试端口

### server
| 端口  | 用途                       | 协议              |
|-------|----------------------------|-------------------|
| 19191 | RustGate WAF 前端          | HTTPS（TLS 证书） |
| 19192 | whoami 直连（无 WAF 基线） | HTTP              |
| 19193 | RustGate 管理 Web UI       | HTTP              |

### local
| 端口  | 用途                       | 协议              |
|-------|----------------------------|-------------------|
| 19000 | RustGate WAF 前端          | HTTPS（TLS 证书） |
| 18080 | whoami 直连（无 WAF 基线） | HTTP              |
| 19193 | RustGate 管理 Web UI       | HTTP              |
## 启动服务

```bash
# 1.启动服务设置日志等级
RUST_LOG=rustgate=warn ./target/release/rustgate waf

# 2. 确认三个端口已监听
ss -lntp | grep -E '19191|19192|19193'

# 3. whoami 直连基线（如未运行）
podman run -d --name whoami -p 127.0.0.1:19192:80 traefik/whoami
```

## 压测前须调高 CC 限流，否则单 IP 高并发会被 429

规则文件默认 `cc_capacity = 100`、`cc_refill_per_sec = 10`。
单ip压测会瞬间触发默认设置的100次cc限流。

压测“放行”和“拦截”场景前，修改 `/var/lib/rustgate/rules.toml` 里的：

```toml
cc_capacity = 1000000
cc_refill_per_sec = 1000000
```

规则与 CC 参数 1 秒热加载生效，不用重启（CC 热加载会重置各 IP 令牌桶）。

## 压测命令

```bash
# 基线：直连 whoami（无 WAF）
oha -n 100000 -c 200 http://127.0.0.1:19192/

# 放行：经过 WAF 的正常流量（WAF 是 TLS 终止，所以用 https）
oha -n 100000 -c 200 https://127.0.0.1:19191/index.html

# 拦截：攻击流量（规则命中，WAF 不再转发后端）
oha -n 10000 -c 200 "https://127.0.0.1:19191/?q=1+union+select"
```

## 记录结果

### 服务器实测（i5-7200u，测试后端为whoami网站）

| 场景 | 并发 | QPS | 平均延迟 | 备注 |
|---|---|---|---|---|
| 基线（无 WAF） | 200 | 12504.3 | 16.0 ms | 直连 whoami 19192 |
| 放行 | 200 | 8035.5 | 24.8 ms | WAF HTTPS 19191 → whoami 19192 |
| 拦截 | 200 | 19486.2 | 9.7 ms | 规则命中 403，不转发后端 |

### 本机实测（AMD Ryzen 7 6800H，测试后端为极简自编译网站）

| 场景 | 并发 | QPS | 平均延迟 | 备注 |
|---|---|---|---|---|
| 基线（无 WAF） | 200 | 523834.0 | 0.3559 ms | 直连 bench_backend 18080 |
| 放行-HTTP | 200 | 98253.9 | 2.0117 ms | WAF HTTP 19000 → 18080 |
| 拦截-HTTP | 200 | 48899.8 | 3.8774 ms | 规则命中 403，不转发 |

## 说明

- 放行吞吐主要消耗在：TLS 握手/加解密 → 连接建立 → 限流检查 → body 读取 → 规则匹配 → 转发 → 响应流式透传
- 拦截路径少一次后端转发；本机测试中拦截 QPS 低于放行，是因为拦截路径命中规则引擎
  后在高并发下 CPU 竞争更集中，且与放行路径的响应流式透传成本不同
- 服务器 CPU 为 i5-7200u（2 核 4 线程），压测时关闭其它吃 CPU 的服务，并保持 CPU 频率策略为 performance
