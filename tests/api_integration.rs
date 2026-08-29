//! api.rs 网络 IO 层集成测试：真实启动 axum router + HTTP 客户端请求。
//!
//! 覆盖：Web UI 页面、鉴权中间件、stats/alerts 端点、WebSocket 告警推送。

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::TokioIo;
use rustgate::api;
use rustgate::block::BlockList;
use rustgate::bus::AlertBus;

/// 启动一个监听随机端口的 API 服务，返回 (addr, bus)。
async fn spawn_api(token: &str) -> (std::net::SocketAddr, Arc<AlertBus>) {
    let bus = Arc::new(AlertBus::new());
    let block_list = Arc::new(BlockList::new());
    let app = api::router(Arc::clone(&bus), token.to_string(), block_list);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // 等服务就绪
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (addr, bus)
}

/// 建立 http1 连接，返回 sender（conn 后台跑）。
async fn connect(
    addr: std::net::SocketAddr,
) -> hyper::client::conn::http1::SendRequest<Empty<Bytes>> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        conn.await.unwrap();
    });
    sender
}

/// 发送请求并返回 (status, body 文本)。
async fn request(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    path: &str,
    auth: Option<&str>,
) -> (hyper::StatusCode, String) {
    let mut builder = hyper::Request::builder().uri(path);
    if let Some(t) = auth {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// 发送请求并返回 (status, headers, body 文本)。
async fn request_with_headers(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    path: &str,
) -> (hyper::StatusCode, hyper::HeaderMap, String) {
    let req = hyper::Request::builder()
        .uri(path)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

/// 建立支持带 body 请求的 http1 连接，返回 sender。
async fn connect_full() -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    let stream = tokio::net::TcpStream::connect(spawn_api("test-token").await.0)
        .await
        .unwrap();
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        conn.await.unwrap();
    });
    sender
}

/// 发送任意方法/可选 JSON body 的请求，返回 (status, body 文本)。
async fn request_body(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    method: hyper::Method,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> (hyper::StatusCode, String) {
    let mut builder = hyper::Request::builder().method(method).uri(path);
    if let Some(t) = auth {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    if body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    let payload = body.map_or_else(
        || Full::new(Bytes::new()),
        |b| Full::new(Bytes::from(b.to_string())),
    );
    let req = builder.body(payload).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn web_ui_is_public_and_serves_html() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, body) = request(&mut sender, "/", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("<title>RustGate WAF 监控</title>"));
    assert!(body.contains("连接设置"));
}

#[tokio::test]
async fn web_ui_sets_security_headers() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, headers, _body) = request_with_headers(&mut sender, "/").await;
    assert_eq!(status, hyper::StatusCode::OK);
    // S3：防点击劫持 + MIME 嗅探 + 信息泄漏
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY",
        "应设置 X-Frame-Options: DENY"
    );
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "应设置 X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "no-referrer",
        "应设置 Referrer-Policy: no-referrer"
    );
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP 应禁止被嵌入(防点击劫持): {csp}"
    );
}

#[tokio::test]
async fn rest_api_requires_bearer_token() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    // 无 token → 401
    let (status, _) = request(&mut sender, "/api/stats", None).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 错误 token → 401
    let (status, _) = request(&mut sender, "/api/stats", Some("wrong")).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 前缀相同、仅后续字节不同的错误 token → 401
    // （专门暴露恒定时间比较中 |= 退化为 &= 的变异）
    let (status, _) = request(&mut sender, "/api/stats", Some("tesu-token")).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 正确 token → 200
    let (status, body) = request(&mut sender, "/api/stats", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"total_requests\""));
}

#[tokio::test]
async fn stats_reflects_published_alerts() {
    let (addr, bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    // 发一条告警：直接 publish（模拟拦截）
    let alert = rustgate::bus::Alert::new(
        "1.2.3.4",
        &hyper::Method::GET,
        "/?q=union+select",
        "sqli",
        "rule #1",
        1,
        20,
    );
    let _ = bus.publish(alert);
    bus.count_request();

    let (status, body) = request(&mut sender, "/api/stats", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"total_requests\":1"), "body: {body}");
    assert!(body.contains("\"blocked\":1"), "body: {body}");

    // alerts 端点应返回 1 条
    let (status, body) = request(&mut sender, "/api/alerts", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"category\":\"sqli\""), "body: {body}");
}

#[tokio::test]
async fn rest_api_rejects_query_token() {
    // ?token= 只允许 /ws/alerts，REST 端点应 401
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, _) = request(&mut sender, "/api/stats?token=test-token", None).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_alerts_pushes_alert_to_subscriber() {
    let (addr, bus) = spawn_api("test-token").await;

    // 用 tokio-tungstenite 客户端连 WS
    let url = format!("ws://{addr}/ws/alerts?token=test-token");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();

    // 等握手稳定后发一条告警
    let alert = rustgate::bus::Alert::new(
        "5.6.7.8",
        &hyper::Method::POST,
        "/login",
        "xss",
        "rule #4",
        4,
        25,
    );
    let _ = bus.publish(alert);

    // 收消息：WS 控制帧（Ping/Pong）可能在告警前后到达，需跳过直到拿到 Text
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("超时未收到 WS 告警")
            .expect("WS 流结束")
            .expect("WS 消息错误");
        match msg {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                assert!(text.contains("\"category\":\"xss\""), "text: {text}");
                break;
            }
            // 控制帧与二进制帧与本次断言无关，继续等 Text
            tokio_tungstenite::tungstenite::Message::Ping(_)
            | tokio_tungstenite::tungstenite::Message::Pong(_)
            | tokio_tungstenite::tungstenite::Message::Binary(_) => continue,
            other => panic!("期望文本消息，收到 {other:?}"),
        }
    }
}

#[tokio::test]
async fn web_ui_contains_block_management() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, body) = request(&mut sender, "/", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("封禁管理"), "body 应包含封禁管理标签");
    assert!(body.contains("doBlock"), "body 应包含封禁按钮逻辑");
    assert!(body.contains("doUnblock"), "body 应包含解封按钮逻辑");
}

#[tokio::test]
async fn block_management_endpoints_require_token() {
    // 封禁管理的全部端点（列表/解封）无 token 必须 401，防止未授权操作
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, _) = request(&mut sender, "/api/blocked", None).await;
    assert_eq!(
        status,
        hyper::StatusCode::UNAUTHORIZED,
        "GET /api/blocked 无 token 应 401"
    );

    // DELETE 无 token → 401（即使 IP 非法也先由鉴权拦截）
    let req = hyper::Request::builder()
        .method(hyper::Method::DELETE)
        .uri("/api/block/203.0.113.7")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        hyper::StatusCode::UNAUTHORIZED,
        "DELETE /api/block 无 token 应 401"
    );
}

#[tokio::test]
async fn web_ui_escapes_attacker_controlled_fields() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, body) = request(&mut sender, "/", None).await;
    assert_eq!(status, hyper::StatusCode::OK);

    // 存在 HTML 转义工具函数
    assert!(body.contains("function esc("), "页面应包含 HTML 转义函数");

    // 攻击者可控字段（path/category/method/ip/detail）必须经 esc() 渲染
    for expr in [
        "esc(a.path)",
        "esc(a.category)",
        "esc(a.method)",
        "esc(a.ip)",
        "esc(a.detail)",
    ] {
        assert!(body.contains(expr), "页面应使用 {expr} 转义后渲染");
    }

    // 不应存在未转义直接插进 innerHTML 的攻击者可控字段（旧版实际模式）
    for raw in [
        "${a.path}${cnt}",
        "${a.method} ${a.path}",
        "${a.ip} · ${a.detail}",
    ] {
        assert!(!body.contains(raw), "不应出现未转义直插: {raw}");
    }
}

#[tokio::test]
async fn block_and_unblock_endpoints_work() {
    let mut sender = connect_full().await;

    // 无 token → 401
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        None,
        Some(r#"{"ip":"203.0.113.7","duration_secs":300}"#),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 封禁 IP → 200
    let (status, body) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        Some("test-token"),
        Some(r#"{"ip":"203.0.113.7","duration_secs":300}"#),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("203.0.113.7"), "body: {body}");

    // 非法 IP → 400
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        Some("test-token"),
        Some(r#"{"ip":"not-an-ip","duration_secs":300}"#),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);

    // duration_secs = 0 → 400
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        Some("test-token"),
        Some(r#"{"ip":"203.0.113.7","duration_secs":0}"#),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);

    // duration_secs = u64::MAX → 400（不得 panic，服务必须继续响应）
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        Some("test-token"),
        Some(r#"{"ip":"203.0.113.7","duration_secs":18446744073709551615}"#),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);

    // 超长 IP 串 → 400
    let long_ip_body = format!(r#"{{"ip":"{}","duration_secs":300}}"#, "a".repeat(100));
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::POST,
        "/api/block",
        Some("test-token"),
        Some(&long_ip_body),
    )
    .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);

    // 列表包含被封 IP
    let (status, body) = request_body(
        &mut sender,
        hyper::Method::GET,
        "/api/blocked",
        Some("test-token"),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("203.0.113.7"), "body: {body}");

    // 解封 → 200
    let (status, body) = request_body(
        &mut sender,
        hyper::Method::DELETE,
        "/api/block/203.0.113.7",
        Some("test-token"),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"ok\":true"), "body: {body}");

    // 再次解封（已不存在）→ 404
    let (status, _) = request_body(
        &mut sender,
        hyper::Method::DELETE,
        "/api/block/203.0.113.7",
        Some("test-token"),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::NOT_FOUND);

    // 列表不再包含
    let (status, body) = request_body(
        &mut sender,
        hyper::Method::GET,
        "/api/blocked",
        Some("test-token"),
        None,
    )
    .await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(!body.contains("203.0.113.7"), "body: {body}");
}
