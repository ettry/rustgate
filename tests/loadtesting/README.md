# RustGate 性能展示

> 基于 `tests/loadtesting/` 下实测数据整理的性能报告。
> 场景命名：`local_*` = 服务器本机压测；`net_*` = 客户端从公网压测；
> `*_web` = 直连 whoami（无 WAF）；`*_waf_pass` = 经过 WAF 正常放行；`*_waf_out` = 经过 WAF 规则拦截。

---

## 1. 测试环境

| 项 | 值 |
|---|---|
| 服务器 | Arch Linux x86_64，Kernel 7.1.8-1-lily |
| CPU | Intel Core i5-7200U @ 3.10 GHz |
| 内存 | 7.67 GiB（测试时用 1.34 GiB） |
| 磁盘 | 28.75 GiB xfs |
| 内网 IP | 192.168.10.223/24 |
| 后端 | podman 运行 `docker.io/traefik/whoami:latest` |
| 压测工具 | oha（`-c 200` 并发） |

**拓扑**：`客户端 --[公网/内网]--> RustGate WAF (TLS 终结) --[本机]--> whoami:19192`

## 2. 测试命令

```bash
# —— 服务器本机（hosts: 127.0.0.1 ddns.eipc.store）——
oha -n 100000 -c 200 http://127.0.0.1:19192/                            # local_web
oha -n 100000 -c 200 https://ddns.eipc.store:19191                      # local_waf_pass
oha -n 10000  -c 200 "https://ddns.eipc.store:19191/?q=1+union+select"  # local_waf_out

# —— 客户端从公网（真实公网链路）——
oha -z 30s -c 200 http://ddns.eipc.store:19192/                            # net_web
oha -z 30s -c 200 https://ddns.eipc.store:19191                            # net_waf_pass
oha -z 30s -c 200 "https://ddns.eipc.store:19191/?q=1+union+select"        # net_waf_out
```

> 压测前已将 `cc_capacity` / `cc_refill_per_sec` 调高到 1000000，避免 CC 限流误伤；
> 本机用 hosts 把域名指到 127.0.0.1，公网用真实 DNS 解析到公网地址。

## 3. 结果总表

| 场景 | 文件 | 请求数 | 成功率 | QPS | 平均延迟 | P50 | P99 | 状态码 |
|---|---|---|---|---|---|---|---|---|
| 本机 · 直连 whoami | `local_web` | 100000 | 100% | **12869.86** | 15.50 ms | 5.52 ms | 75.52 ms | 200 |
| 本机 · WAF 放行 | `local_waf_pass` | 100000 | 100% | **8152.79** | 24.45 ms | 11.17 ms | 111.42 ms | 200 |
| 本机 · WAF 拦截 | `local_waf_out` | 10000 | 100% | **27250.63** | 6.70 ms | 3.46 ms | 166.97 ms | 403 |
| 公网 · 直连 whoami | `net_web` | 30s | 100% | **246.02** | 740.8 ms | 228.5 ms | 6.99 s | 200 |
| 公网 · WAF 放行 | `net_waf_pass` | 30s | 94.5% | **241.14** | 565.6 ms | 144.3 ms | 5.61 s | 200 |
| 公网 · WAF 拦截 | `net_waf_out` | 30s | 99.4% | **269.09** | 662.5 ms | 201.9 ms | 5.95 s | 403 |

## 4. 关键结论

### 4.1 本机：WAF 真实吞吐能力

- **基线（直连 whoami）：12870 QPS**，平均延迟 15.5 ms
- **经过 WAF 放行：8153 QPS**，平均延迟 24.4 ms
- **WAF 带来的吞吐开销 ≈ 36.7%**（`1 - 8153/12870`），主要体现在：
  TLS 加解密 → 连接建立 → 限流检查 → body 读取 → 规则匹配 → 转发 → 流式透传
- **拦截路径更快：27251 QPS**，是放行的 **3.3 倍**——
  因为拦截直接返回 403，不做后端转发，处理链路更短

### 4.2 公网：瓶颈在网络链路，不在 WAF

- 公网直连 whoami：246 QPS，平均延迟 **740 ms**（DNS+dialup 平均 782 ms）
- 公网经 WAF：241 QPS，平均延迟 566 ms
- **公网吞吐与本机相差约 34~52 倍，但 WAF 放行/基线的比例（241 vs 246）几乎不变**——
  说明公网环境下 QPS 完全由「客户端 ↔ 服务器」的公网链路决定，WAF 自身开销被网络延迟完全掩盖
- 公网测试出现的 `timeout` / `aborted due to deadline` / `connection error`
  是高延迟链路上 200 并发排队 + 连接被空闲复用的正常现象，**不是 WAF 故障**

### 4.3 延迟对比

| 指标 | 本机 | 公网 |
|---|---|---|
| P50 | 3~11 ms | 140~230 ms |
| P99 | 75~167 ms | 5.6~7.0 s |
| 平均建连 | 7~95 ms | 0.8~3.0 s |

公网 P99 达到秒级，是链路抖动 + 并发排队的累计效应。

## 5. 使用建议

1. **评估 WAF 性能请用本机数据**（`local_*`），它是服务器真实处理能力；
2. **公网数据（`net_*`）只能用于评估链路/带宽**，不能用于横向比较服务器性能；
3. 若在公网压测，使用 `-z 30s` 短时模式而非 `-n 100000` 固定请求数；
4. 涉及 HTTPS 且使用 IP 直连时需 `--insecure`，或用 hosts 将域名指向本机以走真实证书校验。

## 6. 原始数据

- `server_data` —— 服务器硬件与部署信息
- `local_web` / `local_waf_pass` / `local_waf_out` —— 本机三场景原始输出
- `net_web` / `net_waf_pass` / `net_waf_out` —— 公网三场景原始输出
