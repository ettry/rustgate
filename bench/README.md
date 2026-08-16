# RustGate 压测

## 前置

安装 [oha](https://github.com/hatoo/oha)（或 wrk）：

```bash
cargo install oha
# 或
sudo pacman -S oha
```

## 启动压测环境

```bash
# 1. 编译 release
cargo build --release

# 2. 启动一个简单后端（返回 ok）
python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=b'ok'; self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',18080),H).serve_forever()
PY

# 3. 启动 WAF（release 二进制）
RUSTGATE_CONFIG_DIR=/var/lib/rustgate ./target/release/rustgate waf 127.0.0.1:9000
```

## 压测命令

```bash
# 放行请求吞吐（正常流量）
oha -n 100000 -c 200 http://127.0.0.1:9000/index.html

# 拦截请求（攻击流量，WAF 不再转发后端）
oha -n 10000 -c 50 "http://127.0.0.1:9000/?q=1+union+select"
```

## 记录结果

把两次 `oha` 输出里的 `Requests/sec` 和 `Latency` 填入下表：

| 场景 | 并发 | QPS | 平均延迟 | 备注 |
|---|---|---|---|---|
| 放行 | 200 | 待填写 | 待填写 | WAF 转发到后端 |
| 拦截 | 50 | 待填写 | 待填写 | 规则命中，不转发 |

> 答辩前运行上方压测命令，把 oha 输出里的 Requests/sec 和平均延迟
> 填入本表，作为性能数据的实测依据。

## 说明

- 放行吞吐主要消耗在：连接建立 → 限流检查 → body 读取 → 规则匹配 → 转发 → 响应流式透传
- 拦截路径少一次后端转发，QPS 应明显高于放行
- 压测时把 WAF 日志级别调高避免日志影响结果：`RUST_LOG=rustgate=warn`
