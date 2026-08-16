#![no_main]

use libfuzzer_sys::fuzz_target;
use rustgate::config::{Config, Rule, RuleField};
use rustgate::engine::{Engine, NormalizedRequest};

/// 对规则引擎做随机输入 fuzz：任意字节流构造 URI 与 body，
/// 断言 Engine::inspect 不会 panic、不会崩溃（发现解析/匹配中的隐患）。
fuzz_target!(|data: &[u8]| {
    let cfg = Config {
        score_threshold: 20,
        cc_capacity: 100,
        cc_refill_per_sec: 10,
        rules: vec![
            Rule {
                id: 1,
                name: "sqli".into(),
                category: "sqli".into(),
                field: RuleField::Args,
                header: None,
                pattern: "union select".into(),
                score: 20,
            },
            Rule {
                id: 2,
                name: "xss".into(),
                category: "xss".into(),
                field: RuleField::Body,
                header: None,
                pattern: "regex:(?i)onerror\\s*=".into(),
                score: 25,
            },
        ],
    };
    let Ok(engine) = Engine::new(cfg) else { return };

    let mid = data.len() / 2;
    let url_part = String::from_utf8_lossy(&data[..mid]);
    let body_part = String::from_utf8_lossy(&data[mid..]);

    // 只有能解析成合法 URI 的输入才走完整引擎路径
    if let Ok(uri) = format!("/{url_part}").parse::<hyper::Uri>() {
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &uri,
            &hyper::HeaderMap::new(),
            &body_part,
        );
        let _ = engine.inspect(&req);
    }
});
