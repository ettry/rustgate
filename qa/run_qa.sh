#!/usr/bin/env bash
# RustGate QA 端到端功能测试
set -u
cd "$(dirname "$0")/.."

CFG=/tmp/rg-qa
rm -rf "$CFG"; mkdir -p "$CFG"
cp rules/rules.toml "$CFG/rules.toml"

# 后端
python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=b'ok'; self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        n=int(self.headers.get('Content-Length') or 0); self.rfile.read(n)
        b=b'ok'; self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',18088),H).serve_forever()
PY
BACK=$!
sleep 0.5

RUSTGATE_CONFIG_DIR="$CFG" RUSTGATE_BACKEND=http://127.0.0.1:18088 RUSTGATE_API_TOKEN=qatest \
  RUSTGATE_API=127.0.0.1:19008 ./target/debug/rustgate waf 127.0.0.1:19009 > "$CFG/waf.log" 2>&1 &
WAF=$!
sleep 1.5

PASS=0; FAIL=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  ✅ $desc ($actual)"; PASS=$((PASS+1))
  else
    echo "  ❌ $desc (期望 $expected, 实际 $actual)"; FAIL=$((FAIL+1))
  fi
}

echo "== QA 用例 =="
check "正常请求放行"               200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19009/index.html)"
check "SQLi 小写"                  403 "$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:19009/?q=1+union+select')"
check "SQLi 大写(大小写绕过)"      403 "$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:19009/?q=1+UNION+SELECT')"
check "XSS script 标签"            403 "$(curl -s -o /dev/null -w '%{http_code}' -X POST -d '<script>alert(1)</script>' http://127.0.0.1:19009/)"
check "路径穿越"                   403 "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is 'http://127.0.0.1:19009/../../etc/passwd')"
check "命令注入"                   403 "$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:19009/?q=;cat+/etc/passwd')"
check "NUL 截断绕过"               403 "$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:19009/?q=1+union%00select')"
check "大body跨帧流式(300KB)"      200 "$(head -c 300000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @- http://127.0.0.1:19009/)"
check "管理API鉴权失败"            401 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19008/api/stats)"
check "管理API鉴权成功"            200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer qatest' http://127.0.0.1:19008/api/stats)"

echo
echo "结果: $PASS 通过, $FAIL 失败"
echo "审计日志行数: $(wc -l < "$CFG/log/audit.jsonl" 2>/dev/null || echo 0)"
kill $WAF $BACK 2>/dev/null || true
exit $FAIL
