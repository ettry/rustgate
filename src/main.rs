//! `RustGate` —— 基于 Rust 的高性能 Web 应用防火墙(WAF)
//!
//! 最小可运行骨架：
//!   1. HTTP 反向代理(hyper)
//!   2. 规则引擎(字面量: aho-corasick, 正则: regex, 打分制)
//!   3. IP 频率限制(令牌桶, CC 防护雏形)
//!   4. 结构化告警日志(JSON)
//!
//! 用法:
//!   rustgate --setting -s <server> -t <token>   # 设置后端地址与 API token
//!   rustgate waf                                # 启动 WAF 服务
//!   rustgate --help                             # 显示帮助
//!
//! 后端挂任意 HTTP 服务(如 DVWA / 一个简单 Flask 靶场)即可演示拦截。

use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;
use std::sync::RwLock;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio_stream::{Stream, StreamExt};

use rustgate::bus::{Alert, AlertBus, AlertHit};
use rustgate::config::Config;
use rustgate::engine::{Engine, Hit, NormalizedRequest, Verdict};
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

// ---------------------------------------------------------------------------
// 命令行解析 & 安全设置（settings）
// ---------------------------------------------------------------------------

/// 顶层的命令行子命令。
enum Cli {
    /// `waf`：启动 WAF 服务（可选附加监听地址，未配置时读 settings）。
    Waf { listen: Option<SocketAddr> },
    /// `--setting -s <server> -t <token> [-a <api>] [-l <listen>]`：保存运行常量。
    Setting {
        server: Option<String>,
        token: Option<String>,
        api_addr: Option<SocketAddr>,
        listen_addr: Option<SocketAddr>,
    },
    /// `-h` / `--help`：显示帮助后退出。
    Help,
}

impl Cli {
    /// 解析 `std::env::args()`。
    ///
    /// 命令形态：
    ///   * `cargo run waf` / `cargo run -- waf [监听地址]`  -> Waf
    ///   * `cargo run --setting ...` / `cargo run -- --setting ...` -> Setting
    ///   * `cargo run --help` / `cargo run -- -h`           -> Help（任意位置生效）
    ///
    /// `--setting` 与 `waf` 之间没有空格分隔的要求；`--setting` 本身不带值，
    /// 其下用 `-s/-t/-a/-l` 指定各项常量。
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
            let listen = match rest.split_first() {
                Some((addr, extra)) => {
                    if !extra.is_empty() {
                        eprintln!(
                            "错误: waf 只接受一个可选监听地址（查看帮助: {} --help）",
                            argv0()
                        );
                        exit(2);
                    }
                    Some(addr.as_str().parse().unwrap_or_else(|e| {
                        eprintln!("错误: 无效监听地址 `{addr}`: {e}");
                        exit(2);
                    }))
                }
                None => None,
            };
            return Cli::Waf { listen };
        }

        // 兼容旧用法：第一个参数直接是监听地址，等同于 `waf <addr>`。
        if args.len() == 1 {
            if let Ok(addr) = args[0].parse::<SocketAddr>() {
                return Cli::Waf { listen: Some(addr) };
            }
        }

        // 无参数 `cargo run` 也进入 WAF（沿用 settings 里的监听地址）。
        if args.is_empty() {
            return Cli::Waf { listen: None };
        }

        eprintln!(
            "错误: 未知参数 `{}`（查看帮助: {} --help）",
            args.join(" "),
            argv0()
        );
        exit(2);
    }

    /// 解析 `--setting` 之后的参数：`-s <backend> -t <token> [-a <api>] [-l <listen>]`。
    fn parse_setting(args: &[String]) -> Self {
        let (mut server, mut token, mut api_addr, mut listen_addr) = (None, None, None, None);
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
        }
    }
}

/// 打印使用帮助。
fn print_help() {
    let p = argv0();
    println!(
        r"RustGate —— 基于 Rust 的 Web 应用防火墙(WAF)

用法:
  {p} waf [监听地址]                    启动 WAF 服务
  {p} --setting -s <server> -t <token> [-a <api>] [-l <listen>]
                                             保存运行常量(后端地址、token、API 端口、WAF 监听地址)
  {p} --help | -h                       显示本帮助

常量设置项:
  -s, --server   <url>      受保护的后端服务地址, 对应 RUSTGATE_BACKEND
  -t, --token    <token>    管理 API 鉴权密钥, 对应 RUSTGATE_API_TOKEN
  -a, --api      <addr>     管理 API 监听地址, 对应 RUSTGATE_API (默认 127.0.0.1:9001)
  -l, --listen   <addr>     WAF 反向代理监听地址 (默认 127.0.0.1:9000)

  `--setting` 把常量持久化到 /var/lib/rustgate/settings; 之后 `{p} waf` 会自动读取。
  规则文件位于 /var/lib/rustgate/rules.toml; 可用环境变量 RUSTGATE_CONFIG_DIR 覆盖目录。
  同名环境变量优先于 settings 文件; 两者都未设置时使用开发默认值。

示例:
  {p} --setting -s http://127.0.0.1:8080 -t my-secret-token
  {p} --setting -s http://127.0.0.1:8080 -t my-token -a 0.0.0.0:9001 -l 0.0.0.0:9000
  {p} waf
  {p} waf 0.0.0.0:9000
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Settings {
    backend: String,
    token: String,
    api_addr: String,
    listen_addr: String,
}

impl Settings {
    /// 持久化文件路径（跟随 `RUSTGATE_CONFIG_DIR`，默认 /var/lib/rustgate/settings）。
    fn path() -> String {
        settings_path()
    }

    /// 返回开发默认值，供未配置时兜底。
    fn defaults() -> Self {
        Settings {
            backend: "http://127.0.0.1:80".to_string(),
            token: "dev-token-change-me".to_string(),
            api_addr: "127.0.0.1:9001".to_string(),
            listen_addr: "127.0.0.1:9000".to_string(),
        }
    }

    /// 在已有配置基础上，用命令行给定项覆盖（用作 `--setting` 的部分更新）。
    fn merge(&self, overrides: &Cli) -> Self {
        let mut out = self.clone();
        if let Cli::Setting {
            server,
            token,
            api_addr,
            listen_addr,
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
        println!();
        println!("之后用 `{} waf` 启动即可生效。", argv0());
        Ok(())
    }

    fn load() -> Result<Self, BoxError> {
        let content = std::fs::read_to_string(Settings::path())?;
        let mut lines = content.lines().map(Settings::unescape);
        let backend = lines.next().ok_or("settings: 缺少 backend 行")?;
        let token = lines.next().ok_or("settings: 缺少 token 行")?;
        let api_addr = lines.next().ok_or("settings: 缺少 api_addr 行")?;
        let listen_addr = lines.next().ok_or("settings: 缺少 listen_addr 行")?;
        Ok(Settings {
            backend,
            token,
            api_addr,
            listen_addr,
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
    // `waf` 分支返回可选监听地址（None 表示读 settings 文件）。
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
            if !merged.backend.starts_with("http://") && !merged.backend.starts_with("https://") {
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
            return;
        }
        Cli::Waf { .. } => {}
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

    // 关键变量校验：RUSTGATE_BACKEND 与 RUSTGATE_API_TOKEN 必须显式配置（环境变量或 settings 文件），
    // 否则提示未设置关键变量并退出进程，不允许带着占位默认值裸奔。
    let env_backend = std::env::var("RUSTGATE_BACKEND").ok();
    let env_token = std::env::var("RUSTGATE_API_TOKEN").ok();

    let backend_configured =
        env_backend.is_some() || saved_opt.as_ref().is_some_and(|s| !s.backend.is_empty());
    let token_configured =
        env_token.is_some() || saved_opt.as_ref().is_some_and(|s| !s.token.is_empty());

    if !backend_configured || !token_configured {
        let mut missing = Vec::new();
        if !backend_configured {
            missing.push("RUSTGATE_BACKEND");
        }
        if !token_configured {
            missing.push("RUSTGATE_API_TOKEN");
        }
        eprintln!("错误: 未设置关键变量: {}", missing.join(", "));
        eprintln!(
            "提示: 请先运行 `{} --setting -s <后端地址> -t <token>`，\n\
             或设置环境变量 RUSTGATE_BACKEND / RUSTGATE_API_TOKEN。",
            argv0()
        );
        std::process::exit(1);
    }

    let saved = saved_opt.unwrap_or_else(Settings::defaults);

    // WAF 监听地址：命令行 `waf <addr>` 优先 > 环境变量 > settings > 默认。
    let listen: SocketAddr = if let Cli::Waf { listen: Some(addr) } = &cli {
        *addr
    } else if let Ok(v) = std::env::var("RUSTGATE_LISTEN") {
        match v.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("错误: 环境变量 RUSTGATE_LISTEN 不是合法监听地址: `{v}`");
                fatal("无法解析监听地址", &e);
            }
        }
    } else {
        match saved.listen_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!(
                    "错误: settings 里的 listen_addr 不是合法监听地址: `{}`",
                    saved.listen_addr
                );
                fatal("无法解析监听地址", &e);
            }
        }
    };

    // 后端目标(要保护的 Web 服务)：环境变量 > settings（已通过关键变量校验）。
    let backend = env_backend.unwrap_or_else(|| saved.backend.clone());

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
    let limiter = Arc::new(RateLimiter::new(cc_capacity, cc_refill));
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
    // API 监听地址：环境变量 > settings > 默认。
    let api_addr: SocketAddr = match std::env::var("RUSTGATE_API")
        .unwrap_or_else(|_| saved.api_addr.clone())
        .parse()
    {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("错误: 管理 API 监听地址无效（RUSTGATE_API 或 settings 里的 api_addr）");
            fatal("无法解析管理 API 地址", &e);
        }
    };
    // 管理 API 鉴权 token：环境变量 > settings（已通过关键变量校验）。
    let api_token = env_token.unwrap_or_else(|| saved.token.clone());
    let api_router = rustgate::api::router(Arc::clone(&bus), api_token);
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
    {
        let engine = Arc::clone(&engine);
        let rules_file = rules_path();
        tokio::spawn(async move {
            hot_reload_loop(engine, &rules_file).await;
        });
    }

    tracing::info!(%listen, backend, "RustGate 启动");

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
                let backend = backend.clone();
                let client = Arc::clone(&client);
                let bus = Arc::clone(&bus);
                let audit = audit.clone();
                let conn_limiter = Arc::clone(&conn_limiter);

                tokio::spawn(async move {
                    // 并发保护：超过上限时在此等待，不无限接收连接
                    let Ok(permit) = conn_limiter.acquire().await else {
                        return;
                    };
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let engine = Arc::clone(&engine);
                        let limiter = Arc::clone(&limiter);
                        let backend = backend.clone();
                        let client = Arc::clone(&client);
                        let bus = Arc::clone(&bus);
                        let audit = audit.clone();
                        async move {
                            match handle(
                                req,
                                remote_addr,
                                backend,
                                client,
                                bus,
                                audit,
                                engine,
                                limiter,
                            )
                            .await
                            {
                                Ok(resp) => Ok::<_, Infallible>(resp),
                                Err(e) => {
                                    let body = Bytes::from(format!("网关错误: {e}"));
                                    let resp = match Response::builder()
                                        .status(hyper::StatusCode::BAD_GATEWAY)
                                        .body(Full::new(body))
                                    {
                                        Ok(r) => r,
                                        Err(_) => Response::new(Full::new(Bytes::from("网关错误"))),
                                    };
                                    Ok(boxed_full(resp))
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

/// 热加载循环：每 1 秒检查一次 rules 文件，变化后重建引擎并原子替换。
///
/// * 只读文件、不引入文件系统事件 API，兼容 NFS / 容器卷 / WSL2 等无 inotify 的环境；
/// * 新规则解析或编译失败时**保留旧引擎**并打 WARN，服务不中断。
async fn hot_reload_loop(engine: Arc<RwLock<Arc<Engine>>>, path: &str) {
    let path = path.to_string();
    let mut last = fingerprint(&path);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let current = probe_fingerprint(&path).await;
        match current {
            Some(fp) if last.as_ref() == Some(&fp) => {} // 无变化
            Some(fp) => {
                last = Some(fp);
                apply_hot_reload(&engine, &path).await;
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

/// 重新加载规则并原子替换引擎；失败保留旧引擎。
async fn apply_hot_reload(engine: &Arc<RwLock<Arc<Engine>>>, path: &str) {
    tracing::info!("检测到规则文件变化，重新加载…");
    let owned = path.to_string();
    let result = tokio::task::spawn_blocking(move || reload_engine(&owned)).await;
    install_engine(engine, result);
}

/// 处理重载结果：成功则替换引擎，失败打日志保留旧引擎。
fn install_engine(
    engine: &Arc<RwLock<Arc<Engine>>>,
    result: Result<Result<Engine, BoxError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(new_engine)) => {
            *engine
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_engine);
            tracing::info!("规则热加载成功");
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "规则热加载失败，继续使用旧引擎"),
        Err(e) => tracing::warn!(error = %e, "热加载任务异常，继续使用旧引擎"),
    }
}

/// 纯函数式重载：读规则 + 编译引擎（在 blocking 线程内调用）。
fn reload_engine(path: &str) -> Result<Engine, BoxError> {
    let cfg = Config::load(path)?;
    Engine::new(cfg)
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
    backend: String,
    client: Arc<Client>,
    bus: Arc<AlertBus>,
    audit: AuditLogger,
    engine: Arc<RwLock<Arc<Engine>>>,
    limiter: Arc<RateLimiter>,
) -> Result<Response<BoxBody>, BoxError> {
    let ip = normalize_ip(remote_addr.ip());
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // 0. 总请求数：所有进入 WAF 的请求都计入（含之后被限流/规则拦截的），
    //    这样 total = 放行 + 拦截，拦截率才正确（blocked / total ≤ 100%）。
    bus.count_request().await;

    // 1. IP 频率限制(CC 防护雏形)
    if limiter.check(&ip).await {
        let alert = Alert::new(&ip, &method, &uri.to_string(), "cc", "IP 频率超限", 0, 0);
        return report_and_block(&bus, &audit, alert, hyper::StatusCode::TOO_MANY_REQUESTS).await;
    }

    // 2. 规则引擎检查前先读当前引擎（热加载会原子替换这里的 Arc）。
    //    若无任何 Body 规则，跳过 body 前缀读取，请求体零拷贝透传。
    let engine = engine
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let (mut req_parts, incoming) = req.into_parts();
    let body_head = if engine.needs_body() {
        read_body_prefix(incoming).await?
    } else {
        // 无 Body 规则：不读任何 body 字节，整个流直接透传（零拷贝）
        BodyHead {
            head: String::new(),
            prefix: VecDeque::new(),
            rest: incoming.into_stream(),
            saw_end: false,
        }
    };

    // 3. 规则检查（无 Body 规则时 body 为空串，只检查 Url/Args/Header/Method）
    if let Some((hits, score)) = check_rules(&engine, &method, &uri, &headers, &body_head.head) {
        let first = &hits[0];
        let mut alert = Alert::new(
            &ip,
            &method,
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
    req_parts.headers = headers;
    let out_req = Request::from_parts(req_parts, body);
    forward(client, backend, out_req).await
}

/// body 前缀读取结果：检测所需的头部字节 + 暂存的已读数据帧 + 剩余流。
struct BodyHead {
    /// 检测用的 body 前段文本（≤ `BODY_INSPECT_LIMIT` 字节）。
    head: String,
    /// 已读到的原始帧（转发时先吐出去）。
    prefix: VecDeque<Frame<Bytes>>,
    /// 尚未消费的剩余流。
    rest: http_body_util::BodyStream<Incoming>,
    /// 是否已读到 body 流末尾。
    saw_end: bool,
}

/// 读取 body 前 `BODY_INSPECT_LIMIT` 字节做检测，同时保留已读帧供转发。
async fn read_body_prefix(incoming: Incoming) -> Result<BodyHead, BoxError> {
    let mut rest = incoming.into_stream();
    let mut prefix: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut head = Vec::new();
    let mut saw_end = false;

    while head.len() < BODY_INSPECT_LIMIT {
        match rest.next().await {
            Some(Ok(frame)) => {
                if let Some(chunk) = frame.data_ref() {
                    let room = BODY_INSPECT_LIMIT - head.len();
                    head.extend_from_slice(&chunk[..chunk.len().min(room)]);
                }
                prefix.push_back(frame);
            }
            Some(Err(e)) => return Err(Box::new(e) as BoxError),
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
    let normalized = NormalizedRequest::from_parts(method, uri, headers, body);
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
    tracing::warn!(alert = %serde_json::to_string(&alert)?, "拦截");
    if bus.publish(alert.clone()).await {
        // 去重后仍保留的告警交给审计后台任务落盘（单消费者，无并发竞态）
        match serde_json::to_string(&alert) {
            Ok(line) => audit.append(line).await,
            Err(e) => tracing::error!(error = %e, "告警序列化失败，跳过审计落盘"),
        }
    }
    Ok(boxed_full(alert.into_response(status)))
}

/// 审计日志：单文件大小上限（超过即轮转）。
const AUDIT_MAX_SIZE: u64 = 10 * 1024 * 1024; // 10MB
/// 审计日志：保留的历史份数（.1 .. .keep）。
const AUDIT_KEEP: usize = 5;

/// 把一行 JSONL 追加到审计日志；超过大小上限时先轮转。
fn append_audit_to(base: &str, line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    let dir = audit_dir_for(base);
    std::fs::create_dir_all(&dir)?;
    let path = audit_path_for(base);
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= AUDIT_MAX_SIZE {
            rotate_audit_in(base);
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
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

/// 把规范化后的请求转发给受保护的后端，响应体流式透传。
async fn forward<B>(
    client: Arc<Client>,
    backend: String,
    req: Request<B>,
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
    // 头部透传，但 Host 交给后端目标决定
    for (k, v) in &parts.headers {
        if k != hyper::header::HOST {
            builder = builder.header(k, v);
        }
    }
    let out_req = builder.body(body.boxed())?;

    // 响应体(Incoming)流式透传，转成统一 BoxBody 返回
    let resp = client
        .request(out_req)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
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
    rest: Option<http_body_util::BodyStream<Incoming>>,
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
            Some(rest) => match std::pin::Pin::new(rest).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(frame))) => std::task::Poll::Ready(Some(Ok(frame))),
                std::task::Poll::Ready(Some(Err(e))) => {
                    std::task::Poll::Ready(Some(Err(Box::new(e) as BoxError)))
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
