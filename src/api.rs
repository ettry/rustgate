//! 管理 API + WebSocket 实时告警推送（供 Flutter 面板消费）。
//!
//! 端点：
//!   GET     /api/stats       —— 统计（总请求 / 拦截数 / QPS）
//!   GET     /api/alerts      —— 最近 100 条告警
//!   GET     /api/blocked     —— 当前封禁 IP 列表
//!   POST    /api/block       —— 手动封禁 IP（JSON: `{"ip":"1.2.3.4","duration_secs":300}`）
//!   DELETE  `/api/block/{ip}`  —— 手动解封 IP
//!   WS      /ws/alerts       —— 实时告警流
//!
//! 鉴权：所有端点要求 `Authorization: Bearer <token>`，
//! token 由启动时环境变量 `RUSTGATE_API_TOKEN` 指定（或 settings 文件提供）。
//!
//! 安全说明：
//! * 管理 API 默认只监听 127.0.0.1:9001，不直接暴露公网；
//! * 若需要远程访问面板，请在前面用 nginx/caddy 终结 TLS 后反代，
//!   不要直接把 9001 明文暴露到公网；
//! * WebSocket 握手用 `?token=` 传 token（部分客户端无法自定义 header），
//!   因此 WS 必须走 TLS 反代，否则 token 会出现在 URL 里被日志/历史记录。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use hyper::StatusCode;
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::block::BlockList;
use crate::bus::AlertBus;

/// 管理 API 共享状态：告警总线 + 鉴权 token + 封禁黑名单。
#[derive(Clone)]
pub struct AppState {
    pub bus: Arc<AlertBus>,
    pub token: String,
    pub block_list: Arc<BlockList>,
}

pub fn router(bus: Arc<AlertBus>, token: String, block_list: Arc<BlockList>) -> Router {
    let state = AppState {
        bus,
        token,
        block_list,
    };
    Router::new()
        .route("/", get(index))
        .route("/api/stats", get(stats))
        .route("/api/alerts", get(alerts))
        .route("/api/blocked", get(blocked))
        .route("/api/block", post(block))
        .route("/api/block/{ip}", delete(unblock))
        .route("/ws/alerts", get(ws_alerts))
        // 全部路由走鉴权中间件
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// 内置 Web 仪表盘（单文件 HTML+JS，打开即用）。
async fn index() -> impl IntoResponse {
    // S3：给页面加安全响应头，防点击劫持（封禁/解封按钮）、MIME 嗅探与信息泄漏。
    // 页面使用内联 <style>/<script> 并 fetch/WS 连接任意 base，故 CSP 需放行 unsafe-inline
    // 与任意 http(s)/ws(s) 目标；`frame-ancestors 'none'` 禁止被嵌入（防点击劫持）。
    let mut resp = axum::response::Html(INDEX_HTML).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; \
             style-src 'unsafe-inline'; connect-src http: https: ws: wss:; \
             frame-ancestors 'none'",
        ),
    );
    resp
}

/// Bearer token 鉴权中间件：校验失败返回 401。
///
/// * REST 端点只接受 `Authorization: Bearer <token>` 头；
/// * `?token=` 查询参数**仅**对 `/ws/alerts` WebSocket 握手放行
///   （部分 WS 客户端无法自定义握手 header），减少 token 进 URL/日志的面。
/// * token 比较使用恒定时间比较，降低时序侧信道风险。
async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    const MAX_TOKEN_LEN: usize = 4096;
    // 仪表盘页面公开
    if req.uri().path() == "/" {
        return next.run(req).await;
    }

    let is_ws = req.uri().path() == "/ws/alerts";

    let token_from = if is_ws {
        // WebSocket: 从 Query 取 &str（注意：没有调用 to_string()！）
        req.uri().query().and_then(|q| {
            q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == "token").then_some(v) // 直接返回 &str，零分配！
            })
        })
    } else {
        // REST API: 从 Header 取 &str
        req.headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
    };

    // 先检查是否存在，再检查长度（此时 token 还是切片，没发生复制）
    match token_from {
        Some(token) if token.len() <= MAX_TOKEN_LEN => {
            // 长度合法，进行恒定时间比较
            if constant_time_eq(token.as_bytes(), state.token.as_bytes()) {
                next.run(req).await
            } else {
                unauthorized()
            }
        }
        Some(_) => {
            // 长度超限，直接拒绝（此时 token 是切片，内存安全）
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "Token too large (max 4096 bytes)" })),
            )
                .into_response()
        }
        None => unauthorized(),
    }
}

/// 辅助函数：返回 401 Unauthorized 响应
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

/// 恒定时间比较两个字节串（长度不等时直接返回 false，不暴露长度差时序）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.bus.stats())
}

async fn alerts(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.bus.recent_alerts(100))
}

/// GET /api/blocked：返回当前生效的封禁 IP 列表（已自动过滤过期项）。
async fn blocked(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.block_list.list())
}

/// POST /api/block 请求体：`ip` 必填，`duration_secs` 默认 300 秒。
#[derive(Debug, Deserialize)]
struct BlockRequest {
    ip: String,
    #[serde(default = "default_block_secs")]
    duration_secs: u64,
}

/// 封禁默认时长：300 秒（5 分钟）。
fn default_block_secs() -> u64 {
    300
}

/// 封禁时长上限：7 天。防止恶意传入超大 `duration_secs`
/// （如 `u64::MAX`）触发 `Instant` 溢出 panic（`BlockList::block` 内部也有 `checked_add` 兜底）。
const MAX_BLOCK_SECS: u64 = 7 * 24 * 60 * 60;

/// IPv6 文本形式最长 45 字符（含 `[ ]`），超长的一律拒绝，避免无谓解析。
const MAX_IP_LEN: usize = 45;

/// POST /api/block：手动封禁一个 IP，返回封禁记录；IP 非法返回 400。
async fn block(State(state): State<AppState>, Json(req): Json<BlockRequest>) -> impl IntoResponse {
    // 输入校验：时长必须在 1~MAX_BLOCK_SECS 之间，IP 长度不能超限。
    // axum 的 Json 提取器默认还有 2MB 请求体上限，超大请求体会先被 413 拒绝，不会进到这里。
    if req.duration_secs == 0 || req.duration_secs > MAX_BLOCK_SECS {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("duration_secs 必须在 1~{MAX_BLOCK_SECS} 之间")
            })),
        )
            .into_response();
    }
    if req.ip.len() > MAX_IP_LEN {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "IP 长度非法" })),
        )
            .into_response();
    }

    let duration = Duration::from_secs(req.duration_secs);
    match state.block_list.block(&req.ip, duration) {
        Ok(entry) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "blocked": entry })),
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

/// DELETE /api/block/{ip}：手动解封一个 IP。
///
/// * 成功移除 → 200 `{"ok":true}`；
/// * 该 IP 本就不在封禁列表 → 404；
/// * IP 格式非法 → 400。
async fn unblock(State(state): State<AppState>, Path(ip): Path<String>) -> impl IntoResponse {
    match state.block_list.unblock(&ip) {
        Ok(true) => Json(serde_json::json!({ "ok": true, "unblocked": ip })).into_response(),
        Ok(false) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "IP 不在封禁列表" })),
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

/// WebSocket：实时推送拦截告警。
async fn ws_alerts(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        stream_alerts(socket, state.bus).await;
    })
}

/// 心跳间隔：定期发 Ping 以发现"半开"的客户端连接（客户端断电/网络中断）。
const WS_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);

async fn stream_alerts(mut socket: WebSocket, bus: Arc<AlertBus>) {
    let mut rx = bus.subscribe();
    let mut heartbeat = tokio::time::interval(WS_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // tokio interval 第一次 tick 会立即触发；先消费掉，避免刚建立连接就立刻发一个
    // 心跳 Ping，与首条告警抢占顺序（否则慢环境下客户端会先收到 Ping 而非告警）。
    heartbeat.tick().await;

    loop {
        tokio::select! {
            // 收到新告警 -> 推给客户端
            msg = rx.recv() => {
                match msg {
                    Ok(alert) => {
                        let json = serde_json::to_string(&alert).unwrap_or_default();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break; // 客户端断开
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // 慢消费者落后 n 条：不踢连接，继续追最新告警。
                        // 告警侧已按 count 去重，Lagged 在极端广播压力下才可能发生。
                        tracing::warn!(lagged = n, "WS 订阅者落后，已跳过过期告警");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // 心跳：定期 Ping；发送失败说明连接已死，退出并释放
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Bytes::from_static(b"ping"))).await.is_err() {
                    break;
                }
            }
            // 客户端消息（pong/close 等）
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    // Pong（心跳回包）及其他消息均忽略
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

/// 内置 Web 仪表盘页面：深色主题，零依赖，打开即用。
///
/// 功能：连接设置（token）、统计卡片（总请求/拦截/拦截率/QPS）、
/// 实时告警、攻击类型、来源 IP。所有数据来自本服务的 REST + WebSocket API。
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RustGate WAF 监控</title>
<style>
  :root { --bg:#0e1116; --card:#171c24; --line:rgba(255,255,255,.12); --txt:#fff; --sub:#9aa4b2; --red:#ef4444; --blue:#3b82f6; --amber:#f59e0b; --green:#00c853; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--txt); font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; }
  header { display:flex; align-items:center; justify-content:space-between; padding:12px 16px; border-bottom:1px solid var(--line); }
  h1 { font-size:18px; font-weight:600; }
  button { background:#1f2937; color:var(--txt); border:1px solid var(--line); border-radius:8px; padding:8px 14px; cursor:pointer; font-size:13px; }
  button:hover { border-color:#3b82f6; }
  main { padding:16px; max-width:1100px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card .v { font-size:28px; font-weight:700; margin-top:6px; }
  .card .l { color:var(--sub); font-size:13px; }
  .err { background:#7f1d1d; color:#fff; padding:8px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; display:none; }
  .tabs { display:flex; gap:8px; margin-bottom:12px; }
  .tab { background:var(--card); border:1px solid var(--line); border-radius:8px 8px 0 0; padding:8px 16px; cursor:pointer; font-size:14px; color:var(--sub); }
  .tab.active { color:var(--txt); border-bottom:2px solid var(--green); }
  .panel { display:none; }
  .panel.active { display:block; }
  ul { list-style:none; }
  .alert { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 12px; margin-bottom:8px; font-size:13px; }
  .alert b { color:var(--red); }
  .alert .meta { color:var(--sub); font-size:12px; margin-top:4px; }
  .bar-row { display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:13px; }
  .bar { height:18px; background:linear-gradient(90deg,#3b82f6,#ef4444); border-radius:4px; min-width:2px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }
  th { color:var(--sub); font-weight:500; }
  .settings { display:none; position:fixed; inset:0; background:rgba(0,0,0,.55); align-items:center; justify-content:center; z-index:9; }
  .settings .box { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; width:min(420px,90vw); }
  .settings label { display:block; font-size:13px; color:var(--sub); margin:10px 0 4px; }
  .settings input { width:100%; background:#0b0e13; color:var(--txt); border:1px solid var(--line); border-radius:8px; padding:9px 12px; font-size:14px; }
  .form-row { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; align-items:center; }
  .form-row input { background:#0b0e13; color:var(--txt); border:1px solid var(--line); border-radius:8px; padding:9px 12px; font-size:14px; flex:1; min-width:160px; }
  .form-row .hint { color:var(--sub); font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>🛡 RustGate WAF 实时监控</h1>
  <div><button onclick="openSettings()">⚙ 连接设置</button>
  <button onclick="refreshAll()">🔄 刷新</button></div>
</header>
<main>
  <div class="err" id="err"></div>
  <div class="cards">
    <div class="card"><div class="l">总请求</div><div class="v" id="total">0</div></div>
    <div class="card"><div class="l">拦截数</div><div class="v" id="blocked" style="color:var(--red)">0</div></div>
    <div class="card"><div class="l">拦截率</div><div class="v" id="rate" style="color:var(--amber)">--</div></div>
    <div class="card"><div class="l">QPS</div><div class="v" id="qps" style="color:var(--green)">0</div></div>
  </div>
  <div class="tabs">
    <div class="tab active" onclick="tab(0)">实时告警</div>
    <div class="tab" onclick="tab(1)">攻击类型</div>
    <div class="tab" onclick="tab(2)">来源 IP</div>
    <div class="tab" onclick="tab(3)">封禁管理</div>
  </div>
  <div class="panel active" id="p0"><ul id="alerts"><li style="color:var(--sub)">暂无告警 —— 尝试发一个恶意请求</li></ul></div>
  <div class="panel" id="p1"><div id="cats" style="color:var(--sub)">暂无数据</div></div>
  <div class="panel" id="p2"><div id="ips" style="color:var(--sub)">暂无数据</div></div>
  <div class="panel" id="p3">
    <div class="form-row">
      <input id="bip" placeholder="要封禁的 IP，如 1.2.3.4" maxlength="45">
      <input id="bsecs" type="number" value="300" min="1" max="604800" title="封禁时长（秒），最多 7 天">
      <span class="hint">秒（最多 604800）</span>
      <button onclick="doBlock()">🔒 封禁</button>
      <button onclick="refreshBlocked()">🔄 刷新列表</button>
    </div>
    <div id="blocked-list" style="color:var(--sub)">当前没有封禁的 IP</div>
  </div>
</main>

<div class="settings" id="settings">
  <div class="box">
    <h2 style="font-size:16px">连接设置</h2>
    <label>API Token（与 WAF 的 RUSTGATE_API_TOKEN 一致）</label>
    <input id="token" type="password" placeholder="dev-token-change-me">
    <label>管理 API 地址</label>
    <input id="base" placeholder="http://127.0.0.1:9001">
    <div style="display:flex;gap:10px;margin-top:18px">
      <button onclick="saveSettings()">保存并重连</button>
      <button onclick="closeSettings()">取消</button>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem('rg_token') || 'dev-token-change-me';
let base = localStorage.getItem('rg_base') || location.origin;
let alerts = [];
let ws = null;
let fatalErr = false;   // 已显示 URI/token 错误时，轮询与 WS 不再覆盖红框

function api(path) {
  return fetch(base + path, { headers: { 'Authorization': 'Bearer ' + token } });
}
function apiJson(path, method, body) {
  return fetch(base + path, {
    method: method || 'GET',
    headers: Object.assign({ 'Authorization': 'Bearer ' + token }, body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
}
function showErr(msg) { const e = document.getElementById('err'); if (msg) { e.style.display='block'; e.textContent = msg; } else { e.style.display='none'; } }
function showFatal(msg) { fatalErr = true; showErr(msg); }
function clearErr() { fatalErr = false; showErr(null); }
function fmtTime(t) { return new Date(t*1000).toLocaleTimeString('zh-CN', { hour12:false }); }
// HTML 转义：所有服务端数据（尤其攻击者可控的 path/category/ip）插入 innerHTML
// 前必须转义，防止存储型 XSS（token 存在 localStorage，一旦 XSS 即凭证失窃）。
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function refreshStats() {
  if (fatalErr) return; // 红框已显示 URI/token 错误，轮询不再覆盖它
  try {
    const r = await api('/api/stats');
    if (r.status === 401) { showFatal('可能是 token 错误：管理 API 返回 401，请点击 ⚙ 连接设置 修改 token'); return; }
    if (!r.ok) { showFatal('管理 API 错误：HTTP ' + r.status); return; }
    const s = await r.json();
    document.getElementById('total').textContent = s.total_requests ?? 0;
    document.getElementById('blocked').textContent = s.blocked ?? 0;
    document.getElementById('rate').textContent = s.total_requests > 0 ? (s.blocked*100/s.total_requests).toFixed(1)+'%' : '--';
    document.getElementById('qps').textContent = (s.qps ?? 0).toFixed(1);
    showErr(null);
  } catch(e) {
    showFatal('URI 错误：无法连接管理 API 地址 ' + base + '，请点击 ⚙ 连接设置 修改地址');
  }
}

async function refreshAlerts() {
  if (fatalErr) return;
  try {
    const r = await api('/api/alerts');
    if (r.status === 401) { showFatal('可能是 token 错误：管理 API 返回 401，请点击 ⚙ 连接设置 修改 token'); return; }
    if (!r.ok) return;
    const list = await r.json();
    alerts = list.slice().reverse(); // 服务端倒序返回，正过来
    renderAlerts(); renderCats(); renderIps();
  } catch(_) {}
}

function renderAlerts() {
  const ul = document.getElementById('alerts');
  if (!alerts.length) { ul.innerHTML = '<li style="color:var(--sub)">暂无告警 —— 尝试发一个恶意请求</li>'; return; }
  ul.innerHTML = alerts.slice(0,200).map(a => {
    const extra = a.hits && a.hits.length > 1 ? ' +' + (a.hits.length-1) + ' 条规则' : '';
    const cnt = a.count > 1 ? ' ×' + a.count : '';
    return `<li class="alert"><b>[${esc(a.category)}]</b> ${esc(a.method)} ${esc(a.path)}${cnt}
      <div class="meta">${esc(a.ip)} · ${esc(a.detail)} · score=${a.score}${extra} · ${fmtTime(a.time)}</div></li>`;
  }).join('');
}

function renderCats() {
  const m = {};
  alerts.forEach(a => m[a.category] = (m[a.category]||0) + (a.count||1));
  const entries = Object.entries(m).sort((x,y)=>y[1]-x[1]);
  const max = entries.length ? entries[0][1] : 1;
  document.getElementById('cats').innerHTML = entries.length
    ? entries.map(([k,v]) => `<div class="bar-row"><span style="width:120px">${esc(k)}</span>
        <div class="bar" style="width:${Math.max(2, v/max*300)}px"></div><span>${v}</span></div>`).join('')
    : '暂无数据';
}

function renderIps() {
  const m = {};
  alerts.forEach(a => m[a.ip] = (m[a.ip]||0) + (a.count||1));
  const entries = Object.entries(m).sort((x,y)=>y[1]-x[1]).slice(0,20);
  document.getElementById('ips').innerHTML = entries.length
    ? `<table><tr><th>IP</th><th>告警次数</th></tr>${entries.map(([ip,c]) => `<tr><td>${esc(ip)}</td><td>${c}</td></tr>`).join('')}</table>`
    : '暂无数据';
}

async function refreshBlocked() {
  if (fatalErr) return;
  try {
    const r = await api('/api/blocked');
    if (r.status === 401) { showFatal('可能是 token 错误：管理 API 返回 401，请点击 ⚙ 连接设置 修改 token'); return; }
    if (!r.ok) return;
    const list = await r.json();
    const el = document.getElementById('blocked-list');
    if (!list.length) { el.innerHTML = '<div style="color:var(--sub)">当前没有封禁的 IP</div>'; return; }
    el.innerHTML = '<table><tr><th>IP</th><th>解封时间</th><th></th></tr>' + list.map(b =>
      `<tr><td>${esc(b.ip)}</td><td>${fmtTime(b.expires_at)}</td>` +
      `<td><button onclick="doUnblock('${b.ip}')">解封</button></td></tr>`
    ).join('') + '</table>';
  } catch(_) {}
}

async function doBlock() {
  const ip = document.getElementById('bip').value.trim();
  let secs = parseInt(document.getElementById('bsecs').value || '300', 10) || 300;
  secs = Math.max(1, Math.min(secs, 604800)); // 前端兜底：1 ~ 7 天
  if (!ip) { showErr('请输入要封禁的 IP'); return; }
  if (ip.length > 45) { showErr('IP 长度非法'); return; }
  const r = await apiJson('/api/block', 'POST', { ip: ip, duration_secs: secs });
  if (r.status === 401) { showFatal('可能是 token 错误：管理 API 返回 401，请点击 ⚙ 连接设置 修改 token'); return; }
  const j = await r.json().catch(()=>({}));
  if (r.ok) {
    showErr(null);
    document.getElementById('bip').value = '';
    refreshBlocked();
  } else {
    showErr(j.error ? '封禁失败：' + j.error : ('封禁失败：HTTP ' + r.status));
  }
}

async function doUnblock(ip) {
  const r = await apiJson('/api/block/' + encodeURIComponent(ip), 'DELETE');
  if (r.status === 401) { showFatal('可能是 token 错误：管理 API 返回 401，请点击 ⚙ 连接设置 修改 token'); return; }
  const j = await r.json().catch(()=>({}));
  if (r.ok) {
    showErr(null);
    refreshBlocked();
  } else {
    showErr(j.error ? '解封失败：' + j.error : ('解封失败：HTTP ' + r.status));
  }
}

function connectWs() {
  if (fatalErr) return; // 红框已显示 URI/token 错误，不再尝试重连与覆盖
  if (ws) { ws.close(); }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = base.replace(/^http/, 'ws') + '/ws/alerts?token=' + encodeURIComponent(token);
  ws = new WebSocket(wsUrl);
  ws.onmessage = ev => {
    try {
      const a = JSON.parse(ev.data);
      const idx = alerts.findIndex(x => x.time === a.time && x.path === a.path && x.ip === a.ip && x.category === a.category && x.detail === a.detail);
      if (idx >= 0) { alerts[idx].count = (alerts[idx].count||1) + 1; }
      else { alerts.unshift(a); if (alerts.length > 200) alerts.pop(); }
      renderAlerts(); renderCats(); renderIps();
    } catch(_) {}
  };
  ws.onerror = () => {}; // 错误统一由 REST 轮询在红框报告，避免消息来回跳
  ws.onopen = () => {};
  ws.onclose = () => {}; // 静默重连由下方定时器负责
}

function tab(i) {
  document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('active', j===i));
  document.querySelectorAll('.panel').forEach((p,j)=>p.classList.toggle('active', j===i));
}
function openSettings() {
  document.getElementById('token').value = token;
  document.getElementById('base').value = base;
  document.getElementById('settings').style.display = 'flex';
}
function closeSettings() { document.getElementById('settings').style.display = 'none'; }
function saveSettings() {
  token = document.getElementById('token').value.trim() || 'dev-token-change-me';
  base = document.getElementById('base').value.trim().replace(/\/$/,'') || location.origin;
  localStorage.setItem('rg_token', token);
  localStorage.setItem('rg_base', base);
  closeSettings();
  alerts = [];
  clearErr();   // 重新用新 token/地址尝试，清除旧的 URI/token 错误
  refreshAll();
  connectWs();
}
function refreshAll() { refreshStats(); refreshAlerts(); refreshBlocked(); }

refreshAll();
connectWs();
setInterval(refreshStats, 2000);
setInterval(() => { if (!fatalErr && (!ws || ws.readyState > 1)) connectWs(); }, 3000);
</script>
</body>
</html>
"#;
