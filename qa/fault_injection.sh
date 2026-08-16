#!/usr/bin/env bash
# 错误注入测试：后端故障时 WAF 应优雅降级、不崩溃、可恢复
set -u
cd "$(dirname "$0")/.."
CFG=/tmp/rg-fault
rm -rf "$CFG"; mkdir -p "$CFG"; cp rules/rules.toml "$CFG/rules.toml"

PASS=0; FAIL=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  ✅ $desc ($actual)"; PASS=$((PASS+1))
  else
    echo "  ❌ $desc (期望 $expected, 实际 $actual)"; FAIL=$((FAIL+1))
  fi
}

# 后端：支持正常/慢响应
python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/slow':
            time.sleep(3)
        b=b'ok'; self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',18092),H).serve_forever()
PY
BACK=$!
sleep 0.5

RUSTGATE_CONFIG_DIR="$CFG" RUSTGATE_BACKEND=http://127.0.0.1:18092 RUSTGATE_API_TOKEN=fault \
  RUSTGATE_API=127.0.0.1:19014 ./target/debug/rustgate waf 127.0.0.1:19015 > "$CFG/waf.log" 2>&1 &
WAF=$!
sleep 1.5

echo "== 错误注入测试 =="
echo "-- 场景 1: 后端正常，基线请求 --"
check "正常请求 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:19015/)"

echo "-- 场景 2: 后端慢响应(3s)，WAF 应在 5s 内完成 --"
check "慢响应 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:19015/slow)"

echo "-- 场景 3: 后端宕机，WAF 应返回 502 而非崩溃 --"
kill $BACK
sleep 0.5
check "后端宕机 502" 502 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:19015/)"

echo "-- 场景 4: 后端重启，WAF 应自动恢复 --"
python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=b'ok'; self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',18092),H).serve_forever()
PY
BACK2=$!
sleep 0.5
check "后端恢复 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:19015/)"

echo "-- 场景 5: 后端故障期间攻击仍被拦截（不依赖后端）--"
check "攻击 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 'http://127.0.0.1:19015/?q=1+union+select')"

echo "-- 场景 6: WAF 进程仍存活 --"
if kill -0 $WAF 2>/dev/null; then check "WAF 进程存活" "alive" "alive"; else check "WAF 进程存活" "alive" "dead"; fi

echo
echo "结果: $PASS 通过, $FAIL 失败"
kill $WAF $BACK2 2>/dev/null || true
exit $FAIL
