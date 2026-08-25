//! `RustGate` —— 基于 Rust 的高性能 Web 应用防火墙(WAF)
//!
//! 最小可运行骨架：
//!   1. HTTP 反向代理(hyper)
//!   2. 规则引擎(字面量: aho-corasick, 正则: regex, 打分制)
//!   3. IP 频率限制(令牌桶, CC 防护雏形)
//!   4. 结构化告警日志(JSON)
//!
//! 用法:
//!   rustgate --setting -s <server> -t <token> -a <api> -l <listen>  # 保存运行常量
//!   rustgate waf                                # 启动 WAF 服务
//!   rustgate --help                             # 显示帮助
//!
//! 运行 `waf` 前会检查 -s/-t/-a/-l 是否已通过 settings 文件或环境变量配置。
//! 若同时设置 `RUSTGATE_TLS_CERT` 与 `RUSTGATE_TLS_KEY`，WAF 前端以 `HTTPS` 监听。
//! 后端挂任意 `HTTP`/`HTTPS` 服务(如 `DVWA` / 一个简单 `Flask` 靶场)即可演示拦截。

use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::process::exit;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::{Stream, StreamExt};

use rustgate::block::BlockList;
use rustgate::bus::{Alert, AlertBus, AlertHit};
use rustgate::config::Config;
use rustgate::engine::{Engine, Hit, Verdict};
use rustgate::limiter::RateLimiter;

type BoxError = Box<dyn Error + Send + Sync>;
/// 统一响应/请求体：`Full<Bytes>`(拦截页) 与 `Incoming`(流式转发) 都能装箱。
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

// ---------------------------------------------------------------------------
// 配置文件路径：统一放在系统 /var 目录下。
//
// * 目录基地址默认 /var/lib/rustgate；
// * 可用环境变量 RUSTGATE_CONFIG_DIR 覆盖（便于只读文件系统/开发环境测试）。
// ---------------------------------------------------------------------------

/// 运行时提示中使用的程序名 = `argv[0]`（可能是 `rustgate` 或完整路径），
/// 不再硬编码 `cargo run --`，使直接运行二进制时帮助/报错也正确。
fn argv0() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "rustgate".to_string())
}

/// 统一打印人类可读的致命错误并退出。
///
/// 启动阶段所有无法继续的错误都走这里，不再把 Rust 裸错误（`Error: Os { ... }`）
/// 冒泡给用户。
fn fatal(context: &str, e: &dyn std::fmt::Display) -> ! {
    eprintln!("错误: {context}: {e}");
    std::process::exit(1);
}

/// 审计日志写入器：所有审计落盘通过同一个 mpsc 单消费者串行执行，
/// 避免多请求并发 `append_audit` 时出现"同时判定超限、并发 rename"的竞态。
#[derive(Clone)]
struct AuditLogger {
    tx: tokio::sync::mpsc::Sender<String>,
}

impl AuditLogger {
    fn new() -> (Self, tokio::sync::mpsc::Receiver<String>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        (AuditLogger { tx }, rx)
    }

    /// 发送一行 JSONL 给后台审计任务；通道满时等待（背压）。
    async fn append(&self, line: String) {
        let _ = self.tx.send(line).await;
    }
}

/// 审计后台任务：单消费者，顺序落盘；写失败只打 ERROR 不阻断。
async fn audit_worker(mut rx: tokio::sync::mpsc::Receiver<String>) {
    while let Some(line) = rx.recv().await {
        let base = config_dir();
        match tokio::task::spawn_blocking(move || append_audit_to(&base, &line)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "审计日志写入失败"),
            Err(e) => tracing::error!(error = %e, "审计日志任务异常"),
        }
    }
}

/// 以 0600 权限写文件（仅所有者可读写），用于保存含 token 的 settings。
///
/// 非 Unix 平台退化为普通写入（权限语义由文件系统决定）。
fn write_private_file(path: &str, content: &str) -> Result<(), BoxError> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(content.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// 配置目录基地址。
fn config_dir() -> String {
    std::env::var("RUSTGATE_CONFIG_DIR").unwrap_or_else(|_| "/var/lib/rustgate".to_string())
}

/// 规则文件路径。
fn rules_path() -> String {
    format!("{}/rules.toml", config_dir())
}

/// `--setting` 持久化文件路径。
fn settings_path() -> String {
    format!("{}/settings", config_dir())
}

/// 审计日志目录：拦截告警按 JSONL 落盘。
fn audit_dir_for(base: &str) -> String {
    format!("{base}/log")
}

fn audit_path_for(base: &str) -> String {
    format!("{}/audit.jsonl", audit_dir_for(base))
}

/// 支持 http/https 的连接器：HTTP 直连 + HTTPS 走 rustls。
type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
/// hyper 1.x 的高层 legacy client：内置连接池 + keep-alive，必须全局共享复用。
type Client = hyper_util::client::legacy::Client<HttpsConnector, BoxBody>;

/// 带帧间超时的请求体流：防 Slowloris 变种（慢速正文）。
type TimedBodyStream = tokio_stream::adapters::Timeout<http_body_util::BodyStream<Incoming>>;
/// `Timeout` 含 `Sleep`，不是 `Unpin`；用 `Pin<Box<_>>` 承载以满足 `Body` 实现。
type PinnedTimedBodyStream = std::pin::Pin<Box<TimedBodyStream>>;
/// body 相邻两帧之间的最大等待时间。
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// 构建支持 http + https 的连接器，TLS 证书用系统根证书校验。
fn https_connector() -> HttpsConnector {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    // 允许 IPv6（纯 IPv6 服务器必须开启）
    http.enforce_http(false);
    http.set_connect_timeout(Some(std::time::Duration::from_secs(10)));

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_certs())
        .with_no_client_auth();

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http)
}

/// 从系统 CA 商店加载根证书（权威 CA 签发的证书即可校验通过）。
/// 加载失败时返回空 store，此时连 https 后端会给出明确错误。
fn root_certs() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    if !result.certs.is_empty() {
        let (ok, bad) = store.add_parsable_certificates(result.certs);
        tracing::debug!(ok, bad, "加载系统根证书");
    }
    if !result.errors.is_empty() {
        tracing::debug!(count = result.errors.len(), "部分系统证书加载失败");
    }
    store
}

/// 构建 WAF 前端 HTTPS 监听所需的 `TlsAcceptor`。
///
/// 证书与私钥均为 PEM 格式；`with_single_cert` 会自动按证书链组装。
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, BoxError> {
    let cert_bytes = std::fs::read(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_bytes.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(format!("证书文件 `{cert_path}` 中没有找到 PEM 证书").into());
    }

    let key_bytes = std::fs::read(key_path)?;
    let mut key_reader = std::io::BufReader::new(key_bytes.as_slice());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| format!("私钥文件 `{key_path}` 中没有找到 PEM 私钥"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 可信反向代理列表：只有来自这些地址的请求才解析 `X-Forwarded-For`。
///
/// 支持精确 IP 和 CIDR（`192.168.1.0/24`、`fe80::/10`）。
#[derive(Clone, Debug, Default)]
struct TrustedProxies {
    exact: Vec<IpAddr>,
    cidrs: Vec<(IpAddr, u32)>,
}

impl TrustedProxies {
    /// 解析逗号分隔的代理列表；无法解析的条目忽略并打日志。
    fn parse(raw: &str) -> Self {
        let mut out = TrustedProxies::default();
        for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            parse_trusted_item(item, &mut out);
        }
        out
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        if self.exact.contains(&ip) {
            return true;
        }
        self.cidrs
            .iter()
            .any(|(base, prefix)| cidr_match(*base, *prefix, ip))
    }
}

/// 解析单个可信代理条目：`ip` 或 `ip/prefix`，成功时写入 `out`。
fn parse_trusted_item(item: &str, out: &mut TrustedProxies) {
    if let Some((base, prefix)) = item.split_once('/') {
        parse_trusted_cidr(item, base, prefix, out);
    } else if let Ok(ip) = item.parse::<IpAddr>() {
        out.exact.push(canonical_ip(ip));
    } else {
        tracing::warn!(item, "忽略无效的可信代理地址");
    }
}

/// 解析 `ip/prefix` 形式的 CIDR 条目；地址、前缀或掩码非法时忽略。
fn parse_trusted_cidr(item: &str, base: &str, prefix: &str, out: &mut TrustedProxies) {
    let Ok(base) = base.parse::<IpAddr>() else {
        tracing::warn!(item, "忽略无效的可信代理 CIDR");
        return;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        tracing::warn!(item, "忽略无效的可信代理 CIDR");
        return;
    };
    let max = if base.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        tracing::warn!(item, "忽略无效的可信代理 CIDR");
        return;
    }
    out.cidrs.push((canonical_ip(base), prefix));
}

/// IPv4-mapped IPv6 地址（`::ffff:1.2.3.4`）归一化为 IPv4，保证匹配/限流 key 稳定。
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn cidr_match(base: IpAddr, prefix: u32, ip: IpAddr) -> bool {
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(b) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(b), IpAddr::V6(i)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(b) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// 计算真实客户端 IP：
/// * 对端不在可信代理列表 -> 直接用 TCP 对端 IP，忽略伪造的 XFF；
/// * 对端是可信代理 -> 从右往左找第一个不在可信列表的 XFF IP；
/// * 整条 XFF 都是可信代理 -> 取 XFF 最左侧 IP。
fn client_ip(peer: IpAddr, headers: &hyper::HeaderMap, trusted: &TrustedProxies) -> String {
    let peer = canonical_ip(peer);
    if !trusted.contains(peer) {
        return normalize_ip(peer);
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let ips: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        for ip in ips.iter().rev() {
            let c = canonical_ip(*ip);
            if !trusted.contains(c) {
                return normalize_ip(c);
            }
        }
        if let Some(first) = ips.first() {
            return normalize_ip(canonical_ip(*first));
        }
    }

    normalize_ip(peer)
}

/// 请求边界校验（防请求走私）：
/// * `Content-Length` 与 `Transfer-Encoding` 不能同时存在；
/// * 多个 `Content-Length` 必须完全一致且为合法十进制整数；
/// * `Transfer-Encoding` 只允许单个 `chunked`。
fn valid_request_boundaries(headers: &hyper::HeaderMap) -> bool {
    let mut content_length: Option<String> = None;
    let mut cl_count = 0usize;
    for v in headers.get_all(hyper::header::CONTENT_LENGTH) {
        cl_count += 1;
        let s = v.to_str().unwrap_or("").trim().to_string();
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if let Some(prev) = &content_length {
            if prev != &s {
                return false;
            }
        } else {
            content_length = Some(s);
        }
    }

    let te_values: Vec<String> = headers
        .get_all(hyper::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    if !te_values.is_empty() {
        // TE 与 CL 同时出现是最经典的走私形态，直接拒绝
        if cl_count > 0 {
            return false;
        }
        if te_values.len() != 1 || te_values[0] != "chunked" {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 命令行解析 & 安全设置（settings）
// ---------------------------------------------------------------------------

/// 顶层的命令行子命令。
enum Cli {
    /// `waf`：启动 WAF 服务（监听地址等常量从 settings / 环境变量读取）。
    Waf,
    /// `--setting -s <server> -t <token> [-a <api>] [-l <listen>] [-c <cert>] [-k <key>] [--trusted-proxies <list>]`：保存运行常量。
    Setting {
        server: Option<String>,
        token: Option<String>,
        api_addr: Option<SocketAddr>,
        listen_addr: Option<SocketAddr>,
        tls_cert: Option<String>,
        tls_key: Option<String>,
        trusted_proxies: Option<String>,
    },
    /// `-h` / `--help`：显示帮助后退出。
    Help,
}

impl Cli {
    /// 解析 `std::env::args()`。
    ///
    /// 命令形态：
    ///   * `cargo run waf` / `cargo run -- waf`            -> Waf
    ///   * `cargo run --setting ...` / `cargo run -- --setting ...` -> Setting
    ///   * `cargo run --help` / `cargo run -- -h`           -> Help（任意位置生效）
    ///
    /// `waf` 不接受额外参数：监听地址等常量一律通过 `--setting -l` 或环境变量
    /// `RUSTGATE_LISTEN` 配置。
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();

        // 帮助优先级最高，任意位置出现都生效。
        if args.iter().any(|a| a == "-h" || a == "--help") {
            return Cli::Help;
        }

        // 正向扫描：先找 `--setting`/`--settings` 或 `waf`。
        if let Some(pos) = args
            .iter()
            .position(|a| a == "--setting" || a == "--settings")
        {
            return Cli::parse_setting(&args[pos + 1..]);
        }
        if let Some(pos) = args.iter().position(|a| a == "waf") {
            let rest = &args[pos + 1..];
            if !rest.is_empty() {
                eprintln!(
                    "错误: `waf` 不接受额外参数 `{}`（监听地址请用 `--setting -l <addr>` 配置，查看帮助: {} --help）",
                    rest.join(" "),
                    argv0()
                );
                exit(2);
            }
            return Cli::Waf;
        }

        // 无参数 `cargo run` 也进入 WAF（沿用 settings / 环境变量里的配置）。
        if args.is_empty() {
            return Cli::Waf;
        }

        eprintln!(
            "错误: 未知参数 `{}`（查看帮助: {} --help）",
            args.join(" "),
            argv0()
        );
        exit(2);
    }

    /// 解析 `--setting` 之后的参数：`-s <backend> -t <token> [-a <api>] [-l <listen>] [-c <cert>] [-k <key>]`。
    fn parse_setting(args: &[String]) -> Self {
        let (mut server, mut token, mut api_addr, mut listen_addr, mut tls_cert, mut tls_key) =
            (None, None, None, None, None, None);
        let mut trusted_proxies = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = || {
                it.next().cloned().unwrap_or_else(|| {
                    eprintln!("错误: 参数 `{a}` 缺少值（查看帮助: {} --help）", argv0());
                    exit(2);
                })
            };
            match a.as_str() {
                "-s" | "--server" => server = Some(val()),
                "-t" | "--token" => token = Some(val()),
                "-a" | "--api" => {
                    let v = val();
                    api_addr = Some(v.parse().unwrap_or_else(|e| {
                        eprintln!("错误: 无效 API 监听地址 `{v}`: {e}");
                        exit(2);
                    }));
                }
                "-l" | "--listen" => {
                    let v = val();
                    listen_addr = Some(v.parse().unwrap_or_else(|e| {
                        eprintln!("错误: 无效 WAF 监听地址 `{v}`: {e}");
                        exit(2);
                    }));
                }
                "-c" | "--tls-cert" => tls_cert = Some(val()),
                "-k" | "--tls-key" => tls_key = Some(val()),
                "--trusted-proxies" => trusted_proxies = Some(val()),
                other => {
                    eprintln!("错误: 未知参数 `{other}`（查看帮助: {} --help）", argv0());
                    exit(2);
                }
            }
        }
        Cli::Setting {
            server,
            token,
            api_addr,
            listen_addr,
            tls_cert,
            tls_key,
            trusted_proxies,
        }
    }
}

/// 打印使用帮助。
fn print_help() {
    let p = argv0();
    println!(
        r"RustGate —— 基于 Rust 的 Web 应用防火墙(WAF)

用法:
  {p} waf                               启动 WAF 服务(运行前检查必填项是否已配置)
  {p} --setting -s <server> -t <token> -a <api> -l <listen> [-c <cert>] [-k <key>]
                                             保存运行常量(后端、token、API 端口、WAF 监听地址、TLS 证书)
  {p} --help | -h                       显示本帮助

常量设置项:
  -s, --server   <url>      受保护的后端服务地址, 对应 RUSTGATE_BACKEND (必填)
  -t, --token    <token>    管理 API 鉴权密钥, 对应 RUSTGATE_API_TOKEN (必填)
  -a, --api      <addr>     管理 API 监听地址, 对应 RUSTGATE_API (必填)
  -l, --listen   <addr>     WAF 反向代理监听地址, 对应 RUSTGATE_LISTEN (必填)
  -c, --tls-cert <path>     WAF 前端 HTTPS 证书路径, 对应 RUSTGATE_TLS_CERT (可选)
  -k, --tls-key  <path>     WAF 前端 HTTPS 私钥路径, 对应 RUSTGATE_TLS_KEY (可选)
      --trusted-proxies <list>  可信反向代理列表(逗号分隔, 支持 CIDR), 对应 RUSTGATE_TRUSTED_PROXIES (可选)

  `--setting` 把常量持久化到 /var/lib/rustgate/settings; 之后 `{p} waf` 会自动读取。
  运行 `{p} waf` 前会检查 -s/-t/-a/-l 是否都已配置(环境变量或 settings 文件);
  存在未设置项时会列出缺失项并退出。
  规则文件位于 /var/lib/rustgate/rules.toml; 可用环境变量 RUSTGATE_CONFIG_DIR 覆盖目录。
  同名环境变量优先于 settings 文件。
  若同时设置 RUSTGATE_TLS_CERT 与 RUSTGATE_TLS_KEY, WAF 前端以 HTTPS 监听(证书必须为 PEM)。
  仅当请求来自可信代理时才会解析 X-Forwarded-For 获取真实客户端 IP。

示例:
  {p} --setting -s http://127.0.0.1:8080 -t my-token -a 127.0.0.1:9001 -l 0.0.0.0:9000
  {p} --setting -s https://ddns.eipc.store:19192 -t my-token -a 127.0.0.1:9001 -l '[::]:19193' -c /etc/caddy/certs/ddns.eipc.store.pem -k /etc/caddy/certs/ddns.eipc.store.key --trusted-proxies '127.0.0.1,::1,192.168.10.0/24'
  {p} waf
"
    );
}

/// 持久化的运行常量，落盘到 `/var/lib/rustgate/settings`。
///
/// 采用简单文本格式(不是 TOML/JSON，避免引入额外解析开销)，每行一项：
///   line 1: backend       (受保护服务地址)
///   line 2: token         (管理 API 鉴权 token)
///   line 3: `api_addr`      (管理 API 监听地址)
///   line 4: `listen_addr`   (WAF 反向代理监听地址)
///   line 5: `tls_cert`      (WAF 前端 HTTPS 证书路径，空串表示不启用)
///   line 6: `tls_key`       (WAF 前端 HTTPS 私钥路径，空串表示不启用)
///   line 7: `trusted_proxies` (可信反向代理列表，逗号分隔，支持 CIDR)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Settings {
    backend: String,
    token: String,
    api_addr: String,
    listen_addr: String,
    tls_cert: String,
    tls_key: String,
    trusted_proxies: String,
}

impl Settings {
    /// 持久化文件路径（跟随 `RUSTGATE_CONFIG_DIR`，默认 /var/lib/rustgate/settings）。
    fn path() -> String {
        settings_path()
    }

    /// 返回开发默认值，供未配置时兜底。
    fn defaults() -> Self {
        Settings {
            backend: String::new(),
            token: String::new(),
            api_addr: String::new(),
            listen_addr: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
            trusted_proxies: String::new(),
        }
    }

    /// 返回必填项中未设置的字段名（-s/-t/-a/-l），用于启动前检查。
    fn missing_required(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.backend.is_empty() {
            missing.push("RUSTGATE_BACKEND (-s)");
        }
        if self.token.is_empty() {
            missing.push("RUSTGATE_API_TOKEN (-t)");
        }
        if self.api_addr.is_empty() {
            missing.push("RUSTGATE_API (-a)");
        }
        if self.listen_addr.is_empty() {
            missing.push("RUSTGATE_LISTEN (-l)");
        }
        missing
    }

    /// 在已有配置基础上，用命令行给定项覆盖（用作 `--setting` 的部分更新）。
    fn merge(&self, overrides: &Cli) -> Self {
        let mut out = self.clone();
        if let Cli::Setting {
            server,
            token,
            api_addr,
            listen_addr,
            tls_cert,
            tls_key,
            trusted_proxies,
        } = overrides
        {
            if let Some(v) = server {
                out.backend.clone_from(v);
            }
            if let Some(v) = token {
                out.token.clone_from(v);
            }
            if let Some(v) = api_addr {
                out.api_addr = v.to_string();
            }
            if let Some(v) = listen_addr {
                out.listen_addr = v.to_string();
            }
            if let Some(v) = tls_cert {
                out.tls_cert.clone_from(v);
            }
            if let Some(v) = tls_key {
                out.tls_key.clone_from(v);
            }
            if let Some(v) = trusted_proxies {
                out.trusted_proxies.clone_from(v);
            }
        }
        out
    }

    /// 写盘。token 等字段可能含换行等敏感字符，故做 utf-8 编码转义存储。
    /// 会自动创建配置目录；文件权限设为 0600（仅所有者可读写）。
    fn save(&self) -> Result<(), BoxError> {
        let content = [
            Settings::escape(&self.backend),
            Settings::escape(&self.token),
            Settings::escape(&self.api_addr),
            Settings::escape(&self.listen_addr),
            Settings::escape(&self.tls_cert),
            Settings::escape(&self.tls_key),
            Settings::escape(&self.trusted_proxies),
        ]
        .join("\n")
            + "\n";
        let path = Settings::path();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private_file(&path, &content)?;
        println!("配置文件已保存到: {path}");
        println!("  backend     = {}", self.backend);
        println!("  token       = ********（已保存，不显示明文）");
        println!("  api_addr    = {}", self.api_addr);
        println!("  listen_addr = {}", self.listen_addr);
        println!(
            "  tls_cert    = {}",
            if self.tls_cert.is_empty() {
                "(未设置)"
            } else {
                &self.tls_cert
            }
        );
        println!(
            "  tls_key     = {}",
            if self.tls_key.is_empty() {
                "(未设置)"
            } else {
                &self.tls_key
            }
        );
        println!(
            "  trusted_proxies = {}",
            if self.trusted_proxies.is_empty() {
                "(未设置，不解析 X-Forwarded-For)"
            } else {
                &self.trusted_proxies
            }
        );
        println!();
        println!("之后用 `{} waf` 启动即可生效。", argv0());
        Ok(())
    }

    /// 读取 settings。兼容旧版 4/6 行格式：缺少的字段按空串处理。
    fn load() -> Result<Self, BoxError> {
        let content = std::fs::read_to_string(Settings::path())?;
        let mut lines = content.lines().map(Settings::unescape);
        let backend = lines.next().ok_or("settings: 缺少 backend 行")?;
        let token = lines.next().ok_or("settings: 缺少 token 行")?;
        let api_addr = lines.next().ok_or("settings: 缺少 api_addr 行")?;
        let listen_addr = lines.next().ok_or("settings: 缺少 listen_addr 行")?;
        let tls_cert = lines.next().unwrap_or_default();
        let tls_key = lines.next().unwrap_or_default();
        let trusted_proxies = lines.next().unwrap_or_default();
        Ok(Settings {
            backend,
            token,
            api_addr,
            listen_addr,
            tls_cert,
            tls_key,
            trusted_proxies,
        })
    }

    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    fn unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') | None => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        }
        out
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // 启动流程长但线性，拆分为子函数收益有限
async fn main() {
    // 先解析命令行。--setting / --help 在此处理完即返回，不进入 WAF 事件循环；
    // `waf` 分支进入服务主循环，运行常量从 settings 文件 / 环境变量读取。
    let cli = Cli::parse();
    match &cli {
        Cli::Help => {
            print_help();
            return;
        }
        Cli::Setting { .. } => {
            // `--setting`：合并到已有 settings 后再落盘，实现部分更新。
            let merged = Settings::load()
                .unwrap_or_else(|_| Settings::defaults())
                .merge(&cli);
            // 校验 backend 必须以 http:// 或 https:// 开头，避免保存后转发时才报错。
            if !merged.backend.is_empty()
                && !merged.backend.starts_with("http://")
                && !merged.backend.starts_with("https://")
            {
                eprintln!(
                    "错误: 后端地址 `{}` 必须以 http:// 或 https:// 开头（例如 http://127.0.0.1:80）",
                    merged.backend
                );
                exit(1);
            }
            if let Err(e) = merged.save() {
                eprintln!("错误: 配置保存失败: {e}");
                eprintln!(
                    "提示: 默认配置目录 {} 可能没有写权限（或为只读文件系统）。",
                    config_dir()
                );
                eprintln!("      可设置 RUSTGATE_CONFIG_DIR 指向可写目录，例如:");
                eprintln!(
                    "      RUSTGATE_CONFIG_DIR=/tmp/rustgate {} --setting -s <后端地址> -t <token>",
                    argv0()
                );
                exit(1);
            }
            let missing = merged.missing_required();
            if !missing.is_empty() {
                eprintln!("警告: 以下必填项尚未设置: {}", missing.join(", "));
                eprintln!(
                    "      请在启动 `{} waf` 前通过 --setting 或环境变量补齐这些项。",
                    argv0()
                );
            }
            return;
        }
        Cli::Waf => {}
    }

    // rustls 0.23 需要显式安装 crypto provider（ring）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rustgate=info".into()),
        )
        .init();

    // 读取持久化常量（文件存在则视为用户已配置；不存在返回 None 表示从未配置）。
    let saved_opt = Settings::load().ok();
    let saved = saved_opt.unwrap_or_else(Settings::defaults);

    // 环境变量优先于 settings 文件；重启后只要 settings 文件存在就会自动读取。
    let env_backend = std::env::var("RUSTGATE_BACKEND").ok();
    let env_token = std::env::var("RUSTGATE_API_TOKEN").ok();
    let env_api = std::env::var("RUSTGATE_API").ok();
    let env_listen = std::env::var("RUSTGATE_LISTEN").ok();
    let env_trusted = std::env::var("RUSTGATE_TRUSTED_PROXIES").ok();

    // 启动 `waf` 前必须保证 -s/-t/-a/-l 都已配置（环境变量或 settings 文件），
    // 否则列出缺失项并退出，不允许带着占位默认值裸奔。
    let mut missing = Vec::new();
    if env_backend.is_none() && saved.backend.is_empty() {
        missing.push("RUSTGATE_BACKEND (-s)");
    }
    if env_token.is_none() && saved.token.is_empty() {
        missing.push("RUSTGATE_API_TOKEN (-t)");
    }
    if env_api.is_none() && saved.api_addr.is_empty() {
        missing.push("RUSTGATE_API (-a)");
    }
    if env_listen.is_none() && saved.listen_addr.is_empty() {
        missing.push("RUSTGATE_LISTEN (-l)");
    }
    if !missing.is_empty() {
        eprintln!("错误: 存在未设置项: {}", missing.join(", "));
        eprintln!(
            "提示: 请先运行 `{} --setting -s <后端地址> -t <token> -a <api地址> -l <监听地址>`，\n\
             或设置对应环境变量。",
            argv0()
        );
        std::process::exit(1);
    }

    // 可信反向代理列表：环境变量 RUSTGATE_TRUSTED_PROXIES > settings。
    // 只有这些来源的 X-Forwarded-For 才会被采信。
    let trusted_raw = env_trusted.unwrap_or_else(|| saved.trusted_proxies.clone());
    let trusted = Arc::new(TrustedProxies::parse(&trusted_raw));

    // WAF 监听地址：环境变量 RUSTGATE_LISTEN > settings。
    let listen: SocketAddr = match env_listen {
        Some(v) => match v.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("错误: 环境变量 RUSTGATE_LISTEN 不是合法监听地址: `{v}`");
                fatal("无法解析监听地址", &e);
            }
        },
        None => match saved.listen_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!(
                    "错误: settings 里的 listen_addr 不是合法监听地址: `{}`",
                    saved.listen_addr
                );
                fatal("无法解析监听地址", &e);
            }
        },
    };

    // 后端目标(要保护的 Web 服务)：环境变量 > settings。
    let backend = env_backend.unwrap_or_else(|| saved.backend.clone());

    // 前端 HTTPS 证书/私钥：环境变量优先于 settings；两者都设置时启用 TLS 监听。
    let tls_cert = std::env::var("RUSTGATE_TLS_CERT").unwrap_or_else(|_| saved.tls_cert.clone());
    let tls_key = std::env::var("RUSTGATE_TLS_KEY").unwrap_or_else(|_| saved.tls_key.clone());
    let tls_acceptor: Option<TlsAcceptor> = match (tls_cert.is_empty(), tls_key.is_empty()) {
        (true, true) => None,
        (false, false) => Some(build_tls_acceptor(&tls_cert, &tls_key).unwrap_or_else(|e| {
            fatal(
                "TLS 证书加载失败（请检查 RUSTGATE_TLS_CERT / RUSTGATE_TLS_KEY 路径）",
                &e,
            )
        })),
        _ => {
            eprintln!(
                "错误: RUSTGATE_TLS_CERT 与 RUSTGATE_TLS_KEY 必须同时设置（当前只设置了其中一个）"
            );
            exit(1);
        }
    };

    let rules_file = rules_path();
    let config = match Config::load(&rules_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("错误: 规则文件加载失败: {e}");
            eprintln!("提示: 请确认规则文件存在且可读: {rules_file}");
            eprintln!("      可复制项目自带的规则文件:");
            eprintln!("      sudo cp rules/rules.toml {rules_file}");
            eprintln!("      sudo chown <运行用户> {rules_file}");
            exit(1);
        }
    };
    tracing::info!(
        rules = config.rules.len(),
        threshold = config.score_threshold,
        path = %rules_file,
        "规则加载"
    );
    // 引擎用 RwLock<Arc<Engine>> 包装：热加载任务原子替换内部 Arc，
    // 服务中的请求每次都 `read().clone()` 拿到当下最新的引擎，无锁竞争热点。
    // CC 限流参数来自 rules.toml（cc_capacity / cc_refill_per_sec），不再是写死的 100/10。
    let (cc_capacity, cc_refill) = (config.cc_capacity, config.cc_refill_per_sec);
    let engine: Arc<RwLock<Arc<Engine>>> = match Engine::new(config) {
        Ok(e) => Arc::new(RwLock::new(Arc::new(e))),
        Err(e) => fatal(
            "规则引擎初始化失败（请检查 rules.toml 中的正则/规则格式）",
            &e,
        ),
    };
    let limiter = Arc::new(RwLock::new(Arc::new(RateLimiter::new(
        cc_capacity,
        cc_refill,
    ))));
    let block_list = Arc::new(BlockList::new());
    tracing::info!(cc_capacity, cc_refill_per_sec = cc_refill, "限流器初始化");

    // 全局共享的 HTTP 客户端：连接池 + keep-alive，避免每请求重建 TCP 连接。
    // 使用 HttpsConnector 以支持 http/https 两种后端，TLS 证书走系统根证书校验。
    // pool_idle_timeout: 空闲连接保活 75s；max_idle_per_host: 每后端最多复用 32 条空闲连接。
    let connector = https_connector();
    let client: Client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(75))
            .pool_max_idle_per_host(32)
            .build(connector);
    let client = Arc::new(client);

    // 告警总线 + 管理 API（供 Flutter 面板）
    let bus = Arc::new(AlertBus::new());
    let (audit, audit_rx) = AuditLogger::new();
    tokio::spawn(async move { audit_worker(audit_rx).await });
    // API 监听地址：环境变量 RUSTGATE_API > settings。
    let api_addr: SocketAddr = match env_api {
        Some(v) => match v.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("错误: 环境变量 RUSTGATE_API 不是合法监听地址: `{v}`");
                fatal("无法解析管理 API 地址", &e);
            }
        },
        None => match saved.api_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!(
                    "错误: settings 里的 api_addr 不是合法监听地址: `{}`",
                    saved.api_addr
                );
                fatal("无法解析管理 API 地址", &e);
            }
        },
    };
    // 管理 API 鉴权 token：环境变量 > settings（已通过关键变量校验）。
    let api_token = env_token.unwrap_or_else(|| saved.token.clone());
    let api_router = rustgate::api::router(Arc::clone(&bus), api_token, Arc::clone(&block_list));
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(api_addr).await {
            Ok(listener) => {
                tracing::info!(%api_addr, "管理 API 启动");
                if let Err(e) = axum::serve(listener, api_router).await {
                    tracing::error!(error = %e, "管理 API 运行失败");
                }
            }
            Err(e) => {
                // 不 panic：API 绑定失败不应拖垮 WAF 主进程
                tracing::error!(%api_addr, error = %e, "管理 API 启动失败(端口占用?)");
            }
        }
    });

    // 规则热加载：独立后台任务定时轮询规则文件的指纹，
    // 变化后重新加载并原子替换引擎；解析失败保留旧引擎并告警。
    // CC 限流参数（cc_capacity / cc_refill_per_sec）也随热加载一并重建，
    // 因此修改 rules.toml 中的 CC 配置无需重启进程。
    {
        let engine = Arc::clone(&engine);
        let limiter = Arc::clone(&limiter);
        let rules_file = rules_path();
        tokio::spawn(async move {
            hot_reload_loop(engine, limiter, &rules_file).await;
        });
    }

    tracing::info!(%listen, backend, tls = tls_acceptor.is_some(), "RustGate 启动");

    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("错误: 无法绑定 WAF 监听地址 {listen}");
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("提示: 端口 <1024 需要 root 或 CAP_NET_BIND_SERVICE；也可改用高端口，如 `{} waf 127.0.0.1:9000`", argv0());
            } else if e.kind() == std::io::ErrorKind::AddrInUse {
                eprintln!(
                    "提示: 端口已被占用，可换一个监听端口，如 `{} waf 127.0.0.1:9001`",
                    argv0()
                );
            }
            fatal("WAF 监听端口绑定失败", &e);
        }
    };

    // 最大并发连接数：防 Slowloris / 连接耗尽（超出后新连接排队等待）。
    let conn_limiter = Arc::new(tokio::sync::Semaphore::new(1024));

    loop {
        match listener.accept().await {
            Ok((stream, remote_addr)) => {
                let engine = Arc::clone(&engine);
                let limiter = Arc::clone(&limiter);
                let block_list = Arc::clone(&block_list);
                let trusted = Arc::clone(&trusted);
                let backend = backend.clone();
                let client = Arc::clone(&client);
                let bus = Arc::clone(&bus);
                let audit = audit.clone();
                let conn_limiter = Arc::clone(&conn_limiter);
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    // 并发保护：超过上限时在此等待，不无限接收连接
                    let Ok(permit) = conn_limiter.acquire().await else {
                        return;
                    };

                    match tls_acceptor {
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                serve_conn(
                                    TokioIo::new(tls_stream),
                                    remote_addr,
                                    engine,
                                    limiter,
                                    block_list,
                                    trusted,
                                    backend,
                                    client,
                                    bus,
                                    audit,
                                )
                                .await;
                            }
                            Err(e) => {
                                tracing::debug!(%remote_addr, error = %e, "TLS 握手失败");
                            }
                        },
                        None => {
                            serve_conn(
                                TokioIo::new(stream),
                                remote_addr,
                                engine,
                                limiter,
                                block_list,
                                trusted,
                                backend,
                                client,
                                bus,
                                audit,
                            )
                            .await;
                        }
                    }

                    drop(permit);
                });
            }
            Err(e) => {
                // accept 偶发错误不终止服务，记录后继续
                tracing::error!(error = %e, "接受连接失败，继续运行");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// 单个连接的服务入口：构建 hyper service 并以 HTTP/1 服务该连接。
#[allow(clippy::too_many_arguments)] // 每个参数都是请求处理所需上下文
/// 统一的 502 响应：固定文案，不含任何内部错误细节。
///
/// 后端地址、连接失败原因等只写服务端日志；把原始错误回给客户端
/// 会暴露内部拓扑（如 `tcp connect error: 10.0.0.5:8080`）。
fn bad_gateway_response() -> Response<BoxBody> {
    let resp = Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"Bad Gateway")))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Bad Gateway"))));
    boxed_full(resp)
}

#[allow(clippy::too_many_arguments)] // 各参数都是连接处理必需上下文
async fn serve_conn<I>(
    io: I,
    remote_addr: SocketAddr,
    engine: Arc<RwLock<Arc<Engine>>>,
    limiter: Arc<RwLock<Arc<RateLimiter>>>,
    block_list: Arc<BlockList>,
    trusted: Arc<TrustedProxies>,
    backend: String,
    client: Arc<Client>,
    bus: Arc<AlertBus>,
    audit: AuditLogger,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let engine = Arc::clone(&engine);
        let limiter = Arc::clone(&limiter);
        let block_list = Arc::clone(&block_list);
        let trusted = Arc::clone(&trusted);
        let backend = backend.clone();
        let client = Arc::clone(&client);
        let bus = Arc::clone(&bus);
        let audit = audit.clone();
        async move {
            match handle(
                req,
                remote_addr,
                engine,
                limiter,
                block_list,
                trusted,
                backend,
                client,
                bus,
                audit,
            )
            .await
            {
                Ok(resp) => Ok::<_, Infallible>(resp),
                Err(e) => {
                    // 错误细节（后端地址/连接原因等）只进日志，不回给客户端，
                    // 防止外部探测内部拓扑（信息泄漏）。
                    tracing::warn!(%remote_addr, error = %e, "请求处理失败");
                    Ok(bad_gateway_response())
                }
            }
        }
    });

    // header 读取超时收紧到 10s（hyper 默认 30s），
    // 防止攻击者以极慢速度发 header 占住连接（Slowloris）。
    let mut http1 = http1::Builder::new();
    http1.timer(TokioTimer::new());
    http1.header_read_timeout(std::time::Duration::from_secs(10));
    if let Err(e) = http1.serve_connection(io, service).await {
        tracing::debug!(%remote_addr, error = %e, "连接错误");
    }
}

// ---------------------------------------------------------------------------
// 规则热加载（定期轮询）
// ---------------------------------------------------------------------------

/// 规则文件指纹：文件元数据 + 内容哈希。
///
/// 只用 mtime/length 不够可靠（编辑器原子替换、mtime 回退等边界场景），
/// 这里叠加内容哈希，保证"文本确实变了才重载"。
#[derive(Debug, PartialEq, Eq)]
struct RuleFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
    hash: u64,
}

/// 计算规则文件指纹；文件不存在返回 None。
fn fingerprint(path: &str) -> Option<RuleFingerprint> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    let meta = std::fs::metadata(path).ok()?;
    Some(RuleFingerprint {
        len: meta.len(),
        modified: meta.modified().ok(),
        hash: hasher.finish(),
    })
}

/// 热加载循环：每 5 秒检查一次 rules 文件，变化后重建引擎与限流器并原子替换。
///
/// * 只读文件、不引入文件系统事件 API，兼容 NFS / 容器卷 / WSL2 等无 inotify 的环境；
/// * 新规则解析或编译失败时**保留旧引擎/旧限流器**并打 WARN，服务不中断；
/// * 限流器随 CC 参数一并重建：修改 `cc_capacity` / `cc_refill_per_sec` 后 5 秒内生效，
///   代价是热重载会清空所有 IP 的令牌桶（下一次请求按新容量重新打满）。
async fn hot_reload_loop(
    engine: Arc<RwLock<Arc<Engine>>>,
    limiter: Arc<RwLock<Arc<RateLimiter>>>,
    path: &str,
) {
    let path = path.to_string();
    let mut last = fingerprint(&path);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let current = probe_fingerprint(&path).await;
        match current {
            Some(fp) if last.as_ref() == Some(&fp) => {} // 无变化
            Some(fp) => {
                last = Some(fp);
                apply_hot_reload(&engine, &limiter, &path).await;
            }
            None => last = None, // 文件被删/不可读，等它恢复
        }
    }
}

/// 在 blocking 线程池里读取规则文件指纹，出错返回 None。
async fn probe_fingerprint(path: &str) -> Option<RuleFingerprint> {
    let owned = path.to_string();
    match tokio::task::spawn_blocking(move || fingerprint(&owned)).await {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!(error = %e, "热加载任务异常");
            None
        }
    }
}

/// 重新加载规则和 CC 限流参数，并原子替换引擎/限流器；失败保留旧的。
async fn apply_hot_reload(
    engine: &Arc<RwLock<Arc<Engine>>>,
    limiter: &Arc<RwLock<Arc<RateLimiter>>>,
    path: &str,
) {
    tracing::info!("检测到规则文件变化，重新加载…");
    let owned = path.to_string();
    let result = tokio::task::spawn_blocking(move || reload_runtime(&owned)).await;
    install_reloaded(engine, limiter, result);
}

/// 处理重载结果：成功则同时替换引擎和限流器，失败打日志保留旧的。
fn install_reloaded(
    engine: &Arc<RwLock<Arc<Engine>>>,
    limiter: &Arc<RwLock<Arc<RateLimiter>>>,
    result: Result<Result<(Engine, RateLimiter), BoxError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok((new_engine, new_limiter))) => {
            *engine
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_engine);
            *limiter
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_limiter);
            tracing::info!("规则与限流器热加载成功（CC 参数已应用）");
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "规则热加载失败，继续使用旧引擎/旧限流器"),
        Err(e) => tracing::warn!(error = %e, "热加载任务异常，继续使用旧引擎/旧限流器"),
    }
}

/// 纯函数式重载：读规则 + 编译引擎 + 按新 CC 参数重建限流器（在 blocking 线程内调用）。
fn reload_runtime(path: &str) -> Result<(Engine, RateLimiter), BoxError> {
    let cfg = Config::load(path)?;
    let cc_capacity = cfg.cc_capacity;
    let cc_refill = cfg.cc_refill_per_sec;
    let engine = Engine::new(cfg)?;
    let limiter = RateLimiter::new(cc_capacity, cc_refill);
    Ok((engine, limiter))
}

/// 反代核心：转发前 hook 检查。
///
/// * 源 IP 规范化：IPv4-mapped IPv6（`::ffff:1.2.3.4`）还原为 IPv4，保证限流/审计 key 稳定；
/// * 请求体「边检测边转发」：只累积前 [`BODY_INSPECT_LIMIT`] 字节做规则匹配，
///   每块数据原样写入转发通道，不整体缓冲，避免大 body 打爆内存；
/// * 响应体流式透传，不整体收集。
const BODY_INSPECT_LIMIT: usize = 64 * 1024;

#[allow(clippy::too_many_arguments)] // 各参数都是请求处理必需上下文
async fn handle(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    engine: Arc<RwLock<Arc<Engine>>>,
    limiter: Arc<RwLock<Arc<RateLimiter>>>,
    block_list: Arc<BlockList>,
    trusted: Arc<TrustedProxies>,
    backend: String,
    client: Arc<Client>,
    bus: Arc<AlertBus>,
    audit: AuditLogger,
) -> Result<Response<BoxBody>, BoxError> {
    // 先解构 request，后面所有步骤都借用 parts 而不是克隆整张 HeaderMap / method / uri
    // （P5：每请求省去一次完整 HeaderMap + Method + Uri 克隆）。
    let (parts, incoming) = req.into_parts();
    let headers = &parts.headers;
    let method = &parts.method;
    let uri = &parts.uri;

    // 真实客户端 IP：仅当 TCP 对端是可信代理时才解析 X-Forwarded-For。
    let ip = client_ip(remote_addr.ip(), headers, &trusted);

    // 0. 请求边界校验（防请求走私）。
    if !valid_request_boundaries(headers) {
        bus.count_request();
        let alert = Alert::new(
            &ip,
            method,
            &uri.to_string(),
            "smuggling",
            "Content-Length/Transfer-Encoding 边界冲突",
            0,
            0,
        );
        return report_and_block(&bus, &audit, alert, hyper::StatusCode::BAD_REQUEST).await;
    }

    // 1. 总请求数：所有进入 WAF 的请求都计入（含之后被限流/规则拦截的），
    //    这样 total = 放行 + 拦截，拦截率才正确（blocked / total ≤ 100%）。
    bus.count_request();

    // 2. 手动封禁黑名单：命中直接拒绝，不依赖规则引擎。
    if block_list.is_blocked(&ip) {
        let alert = Alert::new(&ip, method, &uri.to_string(), "block", "IP 已封禁", 0, 0);
        return report_and_block(&bus, &audit, alert, hyper::StatusCode::FORBIDDEN).await;
    }

    // 3. IP 频率限制(CC 防护雏形)
    // 先 clone 当前限流器 Arc：热加载会原子替换内部 Arc，读锁只持续一瞬间，
    // 避免在 check() 期间一直持有读写锁。
    let limiter = limiter
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if limiter.check(&ip) {
        let alert = Alert::new(&ip, method, &uri.to_string(), "cc", "IP 频率超限", 0, 0);
        return report_and_block(&bus, &audit, alert, hyper::StatusCode::TOO_MANY_REQUESTS).await;
    }

    // 4. 规则引擎检查前先读当前引擎（热加载会原子替换这里的 Arc）。
    //    若无任何 Body 规则，跳过 body 前缀读取，请求体零拷贝透传。
    let engine = engine
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let body_head = if engine.needs_body() {
        read_body_prefix(incoming).await?
    } else {
        // 无 Body 规则：不读任何 body 字节，整个流直接透传（零拷贝），
        // 但同样加帧间超时，防慢速正文。
        BodyHead {
            head: String::new(),
            prefix: VecDeque::new(),
            rest: Box::pin(tokio_stream::StreamExt::timeout(
                incoming.into_stream(),
                BODY_READ_TIMEOUT,
            )),
            saw_end: false,
        }
    };

    // 5. 规则检查（无 Body 规则时 body 为空串，只检查 Url/Args/Header/Method）
    if let Some((hits, score)) = check_rules(&engine, method, uri, headers, &body_head.head) {
        let first = &hits[0];
        let mut alert = Alert::new(
            &ip,
            method,
            &uri.to_string(),
            &first.category,
            &format!("rule #{}", first.rule_id),
            first.rule_id,
            score,
        );
        alert.hits = hits
            .iter()
            .map(|h| AlertHit {
                rule_id: h.rule_id,
                category: h.category.clone(),
                score: h.score,
            })
            .collect();
        return report_and_block(&bus, &audit, alert, hyper::StatusCode::FORBIDDEN).await;
    }

    // 放行请求只打 debug（默认不刷屏）；需要逐请求访问日志时用 RUST_LOG=rustgate=debug 打开
    tracing::debug!(%ip, method = %method, uri = %uri, "放行");

    // 4. 转发到后端：已读前缀 + 剩余流拼接（无 Body 规则时 prefix 为空，整流透传）。
    let body = PrefixedBody {
        prefix: body_head.prefix,
        rest: if body_head.saw_end {
            None
        } else {
            Some(body_head.rest)
        },
    };
    let out_req = Request::from_parts(parts, body);
    forward(client, backend, out_req, ip).await
}

/// body 前缀读取结果：检测所需的头部字节 + 暂存的已读数据帧 + 剩余流。
struct BodyHead {
    /// 检测用的 body 前段文本（≤ `BODY_INSPECT_LIMIT` 字节）。
    head: String,
    /// 已读到的原始帧（转发时先吐出去）。
    prefix: VecDeque<Frame<Bytes>>,
    /// 尚未消费的剩余流（带帧间超时）。
    rest: PinnedTimedBodyStream,
    /// 是否已读到 body 流末尾。
    saw_end: bool,
}

/// 读取 body 前 `BODY_INSPECT_LIMIT` 字节做检测，同时保留已读帧供转发。
/// 帧间超时由 `TimedBodyStream` 保证，防慢速正文占用连接。
async fn read_body_prefix(incoming: Incoming) -> Result<BodyHead, BoxError> {
    let mut rest = Box::pin(tokio_stream::StreamExt::timeout(
        incoming.into_stream(),
        BODY_READ_TIMEOUT,
    ));
    let mut prefix: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut head = Vec::new();
    let mut saw_end = false;

    while head.len() < BODY_INSPECT_LIMIT {
        match rest.next().await {
            Some(Ok(Ok(frame))) => {
                if let Some(chunk) = frame.data_ref() {
                    let room = BODY_INSPECT_LIMIT - head.len();
                    head.extend_from_slice(&chunk[..chunk.len().min(room)]);
                }
                prefix.push_back(frame);
            }
            Some(Ok(Err(e))) => return Err(Box::new(e) as BoxError),
            Some(Err(_elapsed)) => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "body 读取超时",
                )) as BoxError);
            }
            None => {
                saw_end = true;
                break;
            }
        }
    }

    Ok(BodyHead {
        head: String::from_utf8_lossy(&head).into_owned(),
        prefix,
        rest,
        saw_end,
    })
}

/// 规则检查：命中则返回 (分类, 规则 id, 分数)，否则 None。
fn check_rules(
    engine: &Engine,
    method: &hyper::Method,
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
    body: &str,
) -> Option<(Vec<Hit>, u32)> {
    // 按引擎需要归一化：无 Header 规则时跳过 header 拼接（P4 优化）
    let normalized = engine.normalize(method, uri, headers, body);
    match engine.inspect(&normalized) {
        Verdict::Allow => None,
        Verdict::Block { hits, score } => Some((hits, score)),
    }
}

/// 记录告警并返回对应状态的拦截响应。
///
/// 审计日志写失败只打 ERROR，不影响拦截响应——防护第一，日志故障不阻断防护。
async fn report_and_block(
    bus: &AlertBus,
    audit: &AuditLogger,
    alert: Alert,
    status: hyper::StatusCode,
) -> Result<Response<BoxBody>, BoxError> {
    // P6：只序列化一次，tracing 日志与审计落盘共用同一份 JSON
    let line = serde_json::to_string(&alert)?;
    tracing::warn!(alert = %line, "拦截");
    if bus.publish(alert.clone()) {
        // 去重后仍保留的告警交给审计后台任务落盘（单消费者，无并发竞态）
        audit.append(line).await;
    }
    // 对外只回通用拦截页（不泄漏规则命中细节，防 WAF 指纹探测）
    Ok(boxed_full(Alert::block_response(status)))
}

/// 审计日志：单文件大小上限（超过即轮转）。
const AUDIT_MAX_SIZE: u64 = 10 * 1024 * 1024; // 10MB
/// 审计日志：保留的历史份数（.1 .. .keep）。
const AUDIT_KEEP: usize = 5;

/// 把一行 JSONL 追加到审计日志；超过大小上限时先轮转。
///
/// 审计日志含流量数据（IP/URL），目录 0700、文件 0600，仅运行用户可读，
/// 与 settings（0600）保持一致，避免本机其他用户读到攻击/访问流量。
fn append_audit_to(base: &str, line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    let dir = audit_dir_for(base);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&dir)?;
    let path = audit_path_for(base);
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= AUDIT_MAX_SIZE {
            rotate_audit_in(base);
        }
    }
    let mut f = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?
        }
    };
    writeln!(f, "{line}")?;
    Ok(())
}

/// 轮转审计日志：audit.jsonl → audit.jsonl.1 → ... → audit.jsonl.keep(删除)。
fn rotate_audit_in(base: &str) {
    let path = audit_path_for(base);
    // 最老的一份直接删除
    let oldest = format!("{path}.{AUDIT_KEEP}");
    let _ = std::fs::remove_file(&oldest);
    // 从后往前移位：.4→.5、.3→.4、…、.1→.2
    for i in (1..AUDIT_KEEP).rev() {
        let from = format!("{path}.{i}");
        let to = format!("{path}.{}", i + 1);
        let _ = std::fs::rename(&from, &to);
    }
    // 当前文件 → .1
    let _ = std::fs::rename(&path, format!("{path}.1"));
}

/// RFC 7230 §6.1 定义的逐跳头（hop-by-hop），代理转发请求/响应时必须剥离。
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// 解析 `Connection` 头点名的头名（小写）——它们同样属于逐跳头（RFC 7230 §6.1）。
fn connection_hop_tokens(headers: &hyper::HeaderMap) -> Vec<String> {
    let mut named: Vec<String> = Vec::new();
    for v in headers.get_all(hyper::header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    named.push(t);
                }
            }
        }
    }
    named
}

/// 判断某个请求头是否应透传给后端。
///
/// 排除：`Host`（由目标 URI 决定）、逐跳头、`Connection` 点名的头、
/// 以及可被客户端伪造的 `X-Forwarded-For` / `X-Real-IP`。
#[must_use]
fn is_forwardable_header(name: &hyper::header::HeaderName, hop_tokens: &[String]) -> bool {
    if name == hyper::header::HOST {
        return false;
    }
    if HOP_BY_HOP_HEADERS.contains(&name.as_str()) {
        return false;
    }
    if hop_tokens.iter().any(|t| t == name.as_str()) {
        return false;
    }
    !matches!(name.as_str(), "x-forwarded-for" | "x-real-ip")
}

/// 剥离响应头里的逐跳头（S4：后端响应透传前清洗，RFC 7230 §6.1）。
fn strip_response_hop_by_hop(headers: &mut hyper::HeaderMap) {
    // 先收集 Connection 点名的头（Connection 头本身也要被移除）
    let hop_tokens = connection_hop_tokens(headers);
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for token in hop_tokens {
        headers.remove(&token);
    }
}

/// 把规范化后的请求转发给受保护的后端，响应体流式透传。
async fn forward<B>(
    client: Arc<Client>,
    backend: String,
    req: Request<B>,
    client_ip: String,
) -> Result<Response<BoxBody>, BoxError>
where
    B: Body<Data = Bytes, Error = BoxError> + Send + Sync + 'static,
{
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);

    // 目标 URI：仅替换 scheme/authority，保留 path+query 原样。
    let target = format!("{backend}{path_and_query}");

    let mut builder = Request::builder()
        .method(parts.method)
        .uri(target)
        .version(parts.version);
    // 头部透传（零拷贝，不建中间 HeaderMap）：
    // 剥离逐跳头与伪造 XFF/X-Real-IP，Host 交给后端目标决定。
    let hop_tokens = connection_hop_tokens(&parts.headers);
    for (k, v) in &parts.headers {
        if is_forwardable_header(k, &hop_tokens) {
            builder = builder.header(k, v);
        }
    }
    // 写入 WAF 判定的真实客户端 IP（替换可能被伪造的入站值）
    if let Ok(v) = hyper::header::HeaderValue::from_str(&client_ip) {
        builder = builder.header("x-forwarded-for", v);
    }
    let out_req = builder.body(body.boxed())?;

    // 响应体(Incoming)流式透传，转成统一 BoxBody 返回；
    // 响应头先剥离逐跳头（S4），避免后端 Connection/TE 等干扰与客户端连接语义。
    let mut resp = client
        .request(out_req)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
    strip_response_hop_by_hop(resp.headers_mut());
    Ok(resp.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed()))
}

/// 源 IP 规范化：IPv4-mapped IPv6（`::ffff:a.b.c.d`）还原为点分 IPv4。
fn normalize_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        std::net::IpAddr::V4(v4) => v4.to_string(),
    }
}

/// 把 `Full<Bytes>` 响应体转成统一 BoxBody（错误统一为 `BoxError`）。
fn boxed_full(resp: hyper::Response<http_body_util::Full<Bytes>>) -> hyper::Response<BoxBody> {
    resp.map(|b| b.map_err(|e| match e {}).boxed())
}

/// 拼接「已读前缀 + 剩余流」的请求体。
///
/// * 前缀是检查阶段已读到的数据帧（有界，≤ 64KB + 少量 trailer），先吐出；
/// * 剩余部分是尚未消费的 Incoming 流，随后原样透传；
/// * 这样既能先检查再决定放行/拦截，又能流式转发超大 body，不整体缓冲。
struct PrefixedBody {
    prefix: VecDeque<Frame<Bytes>>,
    rest: Option<PinnedTimedBodyStream>,
}

impl Body for PrefixedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(frame) = this.prefix.pop_front() {
            return std::task::Poll::Ready(Some(Ok(frame)));
        }
        match this.rest.as_mut() {
            Some(rest) => match rest.as_mut().poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(Ok(frame)))) => {
                    std::task::Poll::Ready(Some(Ok(frame)))
                }
                std::task::Poll::Ready(Some(Ok(Err(e)))) => {
                    std::task::Poll::Ready(Some(Err(Box::new(e) as BoxError)))
                }
                std::task::Poll::Ready(Some(Err(_elapsed))) => {
                    std::task::Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "body 读取超时",
                    )) as BoxError)))
                }
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
            None => std::task::Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn rotate_audit_shifts_files_and_drops_oldest() {
        // 纯函数测试：直接传入临时目录，不再修改全局环境变量
        let dir = std::env::temp_dir().join(format!("rg-rotate-test-{}", std::process::id()));
        let base = dir.to_str().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(audit_dir_for(base)).unwrap();
        std::fs::write(audit_path_for(base), "current").unwrap();
        std::fs::write(format!("{}.1", audit_path_for(base)), "old1").unwrap();

        rotate_audit_in(base);

        // current → .1；原 .1 → .2
        assert_eq!(
            std::fs::read_to_string(format!("{}.1", audit_path_for(base))).unwrap(),
            "current"
        );
        assert_eq!(
            std::fs::read_to_string(format!("{}.2", audit_path_for(base))).unwrap(),
            "old1"
        );
        assert!(!std::path::Path::new(&audit_path_for(base)).exists());

        // 清理
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod hot_reload_tests {
    use super::*;

    #[tokio::test]
    async fn reload_runtime_rebuilds_limiter_with_new_cc_params() {
        let dir = std::env::temp_dir().join(format!("rg-reload-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        std::fs::write(
            &path,
            "score_threshold = 30\ncc_capacity = 42\ncc_refill_per_sec = 7\n",
        )
        .unwrap();

        let (engine, limiter) = reload_runtime(path.to_str().unwrap()).unwrap();
        // 规则引擎成功重建（无规则时 needs_body 为 false）
        assert!(!engine.needs_body());
        // 新限流器按文件中的 cc_capacity 初始化
        assert_eq!(limiter.tokens_left("1.1.1.1"), 42);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod forward_header_tests {
    use super::*;

    fn mk_headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    /// 复刻 [`forward`] 里对请求头的处理：逐个判定 + 重写 XFF。
    /// 返回「应透传」的头集合 + 重写后的 XFF 值（用于测试 forward 的清洗语义）。
    fn forwardable(headers: &hyper::HeaderMap) -> (Vec<String>, Vec<String>) {
        let hop = connection_hop_tokens(headers);
        let mut keep = Vec::new();
        let mut xff = Vec::new();
        for (k, v) in headers {
            if is_forwardable_header(k, &hop) {
                keep.push(format!("{}: {}", k, v.to_str().unwrap()));
            } else if k.as_str() == "x-forwarded-for" || k.as_str() == "x-real-ip" {
                xff.push(k.as_str().to_string());
            }
        }
        (keep, xff)
    }

    #[test]
    fn connection_hop_tokens_parses_and_lowercases() {
        let h = mk_headers(&[("connection", "keep-alive, X-Custom-Hop")]);
        let tokens = connection_hop_tokens(&h);
        assert_eq!(tokens, vec!["keep-alive", "x-custom-hop"]);
    }

    #[test]
    fn strips_hop_by_hop_and_forged_headers() {
        let h = mk_headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-connection", "keep-alive"),
            ("x-forwarded-for", "6.6.6.6, 7.7.7.7"),
            ("x-real-ip", "8.8.8.8"),
            ("user-agent", "curl/8"),
        ]);
        let (keep, forged) = forwardable(&h);

        // 逐跳头与伪造来源头都不应透传
        assert!(
            !keep.iter().any(|l| l.starts_with("connection:")
                || l.starts_with("keep-alive:")
                || l.starts_with("transfer-encoding:")
                || l.starts_with("te:")
                || l.starts_with("upgrade:")
                || l.starts_with("proxy-connection:")),
            "逐跳头不应透传: {keep:?}"
        );
        assert!(keep.iter().any(|l| l == "user-agent: curl/8"));
        // XFF/X-Real-IP 被识别为需重写/删除
        assert_eq!(forged, vec!["x-forwarded-for", "x-real-ip"]);
    }

    #[test]
    fn strips_headers_named_by_connection() {
        // Connection 点名的头也属于逐跳头（RFC 7230 §6.1）
        let h = mk_headers(&[
            ("connection", "X-Custom-Hop"),
            ("x-custom-hop", "secret"),
            ("user-agent", "curl/8"),
        ]);
        let (keep, _) = forwardable(&h);
        assert!(
            !keep.iter().any(|l| l.starts_with("x-custom-hop:")),
            "Connection 点名的头应被剥离: {keep:?}"
        );
        assert!(keep.iter().any(|l| l == "user-agent: curl/8"));
    }

    #[test]
    fn keeps_end_to_end_headers() {
        let h = mk_headers(&[
            ("content-length", "5"),
            ("content-type", "application/json"),
            ("cookie", "a=b"),
        ]);
        let (keep, _) = forwardable(&h);
        assert!(keep.iter().any(|l| l == "content-length: 5"));
        assert!(keep.iter().any(|l| l == "content-type: application/json"));
        assert!(keep.iter().any(|l| l == "cookie: a=b"));
    }

    #[test]
    fn host_is_never_forwarded() {
        // Host 由后端目标 URI 决定，不能透传客户端伪造的 Host
        let h = mk_headers(&[("host", "evil.example.com"), ("user-agent", "curl/8")]);
        let (keep, _) = forwardable(&h);
        assert!(
            !keep.iter().any(|l| l.starts_with("host:")),
            "Host 不应透传"
        );
    }

    #[test]
    fn response_hop_by_hop_headers_are_stripped() {
        let mut resp_headers = mk_headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("content-type", "text/plain"),
            ("content-length", "3"),
        ]);
        strip_response_hop_by_hop(&mut resp_headers);

        for name in ["connection", "keep-alive", "transfer-encoding", "upgrade"] {
            assert!(resp_headers.get(name).is_none(), "{name} 应从响应剥离");
        }
        // 端到端头保留
        assert_eq!(resp_headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(resp_headers.get("content-length").unwrap(), "3");
    }

    #[tokio::test]
    async fn bad_gateway_response_hides_error_details() {
        let resp = bad_gateway_response();
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert_eq!(text, "Bad Gateway");
        // 不再回显后端地址/错误详情
        assert!(!text.contains("127.0.0.1"), "502 不应泄漏内部地址");
    }
}

#[cfg(all(test, unix))]
mod audit_perm_tests {
    use super::*;

    #[test]
    fn audit_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rg-audit-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let base = dir.to_str().unwrap();

        append_audit_to(base, "{\"t\":1}").unwrap();

        let file_mode = std::fs::metadata(audit_path_for(base))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "审计文件应为 0600，实际 {file_mode:o}");

        let dir_mode = std::fs::metadata(audit_dir_for(base))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "审计目录应为 0700，实际 {dir_mode:o}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod security_helper_tests {
    use super::*;

    fn mk_headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    // ---------- 可信代理解析 / 匹配 ----------

    #[test]
    fn trusted_proxies_parse_exact_and_cidr() {
        let t = TrustedProxies::parse("192.168.1.5,10.0.0.0/8,::1,2001:db8::/32");
        assert!(t.contains("192.168.1.5".parse().unwrap()));
        assert!(t.contains("10.20.30.40".parse().unwrap())); // 命中 10.0.0.0/8
        assert!(!t.contains("11.0.0.1".parse().unwrap()));
        assert!(t.contains("::1".parse().unwrap()));
        assert!(t.contains("2001:db8::1234".parse().unwrap()));
        assert!(!t.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn trusted_proxies_ignore_invalid_entries() {
        let t = TrustedProxies::parse("not-an-ip,1.2.3.4/99,2.3.4.5");
        // 非法项被忽略，合法项保留
        assert!(t.contains("2.3.4.5".parse().unwrap()));
        assert!(!t.contains("1.2.3.4".parse().unwrap())); // /99 非法，整条丢弃
        assert!(!t.contains("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn canonical_ip_normalizes_v4_mapped_v6() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip("::ffff:1.2.3.4".parse().unwrap()), v4);
        assert_eq!(canonical_ip("2001:db8::1".parse().unwrap()), v6);
        assert_eq!(canonical_ip(v4), v4);
    }

    #[test]
    fn cidr_match_v4_v6_and_zero_prefix() {
        assert!(cidr_match(
            "10.0.0.0".parse().unwrap(),
            8,
            "10.5.6.7".parse().unwrap()
        ));
        assert!(!cidr_match(
            "10.0.0.0".parse().unwrap(),
            8,
            "11.5.6.7".parse().unwrap()
        ));
        assert!(cidr_match(
            "2001:db8::".parse().unwrap(),
            32,
            "2001:db8::ffff".parse().unwrap()
        ));
        // prefix 0 = 全网段
        assert!(cidr_match(
            "0.0.0.0".parse().unwrap(),
            0,
            "8.8.8.8".parse().unwrap()
        ));
    }

    // ---------- 真实客户端 IP（XFF 信任） ----------

    #[test]
    fn client_ip_uses_peer_when_not_trusted() {
        // 对端不可信 → 忽略任何伪造 XFF，直接用 TCP 对端 IP
        let t = TrustedProxies::parse("192.168.1.5");
        let headers = mk_headers(&[("x-forwarded-for", "6.6.6.6")]);
        assert_eq!(
            client_ip("1.2.3.4".parse().unwrap(), &headers, &t),
            "1.2.3.4"
        );
    }

    #[test]
    fn client_ip_walks_trusted_chain_right_to_left() {
        // 对端可信 → 从右往左找第一个不可信 IP
        let t = TrustedProxies::parse("127.0.0.1,192.168.1.5");
        let headers = mk_headers(&[("x-forwarded-for", "203.0.113.7, 192.168.1.5")]);
        assert_eq!(
            client_ip("127.0.0.1".parse().unwrap(), &headers, &t),
            "203.0.113.7"
        );
    }

    #[test]
    fn client_ip_all_trusted_uses_leftmost() {
        // 两个 XFF IP 都在可信列表 → 整条可信 → 取最左侧
        let t = TrustedProxies::parse("127.0.0.1,192.168.1.5,192.168.1.9");
        let headers = mk_headers(&[("x-forwarded-for", "192.168.1.9, 192.168.1.5")]);
        assert_eq!(
            client_ip("127.0.0.1".parse().unwrap(), &headers, &t),
            "192.168.1.9"
        );
    }

    #[test]
    fn client_ip_empty_xff_falls_back_to_peer() {
        let t = TrustedProxies::parse("127.0.0.1");
        let headers = mk_headers(&[("x-forwarded-for", "not-an-ip")]);
        // XFF 无法解析 → 退回 TCP 对端
        assert_eq!(
            client_ip("127.0.0.1".parse().unwrap(), &headers, &t),
            "127.0.0.1"
        );
    }

    // ---------- 请求边界校验（防走私） ----------

    #[test]
    fn valid_boundaries_accepts_normal_cl_and_te() {
        assert!(valid_request_boundaries(&mk_headers(&[(
            "content-length",
            "5"
        )])));
        assert!(valid_request_boundaries(&mk_headers(&[(
            "transfer-encoding",
            "chunked"
        )])));
        assert!(valid_request_boundaries(&hyper::HeaderMap::new()));
    }

    #[test]
    fn valid_boundaries_rejects_cl_plus_te() {
        // CL 与 TE 同时出现 = 最经典走私形态
        assert!(!valid_request_boundaries(&mk_headers(&[
            ("content-length", "5"),
            ("transfer-encoding", "chunked"),
        ])));
    }

    #[test]
    fn valid_boundaries_rejects_duplicate_or_bad_cl() {
        // 重复 CL（值不同）：必须用 append 构建，insert 会覆盖前一个
        let mut dup = hyper::HeaderMap::new();
        dup.append("content-length", "5".parse().unwrap());
        dup.append("content-length", "6".parse().unwrap());
        assert!(!valid_request_boundaries(&dup));
        assert!(!valid_request_boundaries(&mk_headers(&[(
            "content-length",
            "abc"
        )])));
    }

    #[test]
    fn valid_boundaries_rejects_bad_te() {
        assert!(!valid_request_boundaries(&mk_headers(&[(
            "transfer-encoding",
            "gzip"
        )])));
        assert!(!valid_request_boundaries(&mk_headers(&[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "gzip"),
        ])));
    }

    // ---------- settings 转义 ----------

    #[test]
    fn settings_escape_unescape_roundtrip() {
        let cases = [
            "plain-token-123",
            "a\\b",
            "line1\nline2",
            "cr\rlf",
            "mix\\n\\r",
        ];
        for c in cases {
            let esc = Settings::escape(c);
            assert!(!esc.contains('\n'), "转义后不应有裸换行");
            assert_eq!(Settings::unescape(&esc), c, "往返应一致: {c:?}");
        }
    }

    // ---------- forward 端到端 ----------

    #[tokio::test]
    async fn forward_rewrites_xff_and_strips_host() {
        // 与 main() 启动一致：注册 rustls 默认 CryptoProvider（ring）
        let _ = rustls::crypto::ring::default_provider().install_default();
        // 起一个极简后端，回显收到的 x-forwarded-for / user-agent / host
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let h = |k: &str| {
                        req.headers()
                            .get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string()
                    };
                    let body = format!(
                        "xff={}|ua={}|host={}",
                        h("x-forwarded-for"),
                        h("user-agent"),
                        h("host")
                    );
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                tokio::spawn(async move {
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        let client = Arc::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https_connector()),
        );
        // 客户端伪造 XFF 与 Host，forward 必须重写/剥离
        let body: BoxBody = Full::new(Bytes::new())
            .map_err(|never: Infallible| match never {})
            .boxed();
        let req = Request::builder()
            .uri("/index.html")
            .header("user-agent", "curl/8")
            .header("x-forwarded-for", "6.6.6.6")
            .header("host", "evil.example.com")
            .body(body)
            .unwrap();

        let resp = forward(client, format!("http://{addr}"), req, "9.9.9.9".to_string())
            .await
            .unwrap();
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&text).into_owned();

        assert!(
            text.contains("xff=9.9.9.9"),
            "XFF 应被重写为真实 IP: {text}"
        );
        assert!(text.contains("ua=curl/8"), "端到端头应透传: {text}");
        assert!(
            !text.contains("evil.example.com"),
            "伪造 Host 不应透传: {text}"
        );
    }
}
