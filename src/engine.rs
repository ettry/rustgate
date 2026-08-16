//! 规则引擎：把请求标准化后做多模式匹配 + 打分判定。

use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;

use crate::config::{Config, Rule, RuleField};

/// 字面量分组键：(字段, 小写 header 名) → (模式列表, 规则索引列表)。
type LiteralGroupMap = HashMap<(RuleField, Option<String>), (Vec<String>, Vec<usize>)>;

/// 字面量规则按 (字段, header 名) 分组，每组一个 Aho-Corasick 多模式自动机。
struct LiteralGroup {
    field: RuleField,
    /// 小写 header 名（仅 field=Header 且指定了 header 的规则）
    header: Option<String>,
    ac: AhoCorasick,
    /// pattern id -> rules 索引
    rule_idx: Vec<usize>,
}

/// 阈值内嵌——保持简单，运行时类型包括预编译匹配器与分数。
pub struct Engine {
    threshold: u32,
    literals: Vec<LiteralGroup>,
    regexes: Vec<(usize, RuleField, u32, Regex)>,
    rules: Vec<Rule>,
    /// 是否存在 field = "Body" 的规则；没有则请求体可零拷贝透传。
    needs_body: bool,
}

/// 标准化后的请求，供匹配器逐字段检查。
pub struct NormalizedRequest {
    pub method: String,
    pub url: String,  // 完整 path + query(已解码 + 控制字节归一化)
    pub args: String, // query 部分(已解码 + 控制字节归一化)
    pub headers: String,
    pub body: String,
    /// 小写 header 名 → 值（同名 header 用逗号拼接），
    /// 供 `field = "Header"` 且指定了具体 header 名的规则使用。
    pub header_values: HashMap<String, String>,
    /// 可疑度加分：请求中出现 NUL/控制字节等异常信号时累积。
    /// 这些字节在正常流量中几乎不出现，本身即是攻击信号；
    /// 额外计分可让「单条特征被 NUL 拆碎」的绕过手段仍被拦截。
    pub suspicious: u32,
}

/// 单条命中的规则。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub rule_id: u32,
    pub category: String,
    pub score: u32,
}

/// 引擎判定结果。Block 携带全部命中的规则（hits[0] 为第一条）。
#[derive(Debug)]
pub enum Verdict {
    Allow,
    Block { hits: Vec<Hit>, score: u32 },
}

impl NormalizedRequest {
    pub fn from_parts(
        method: &hyper::Method,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        body: &str,
    ) -> Self {
        let path_query = uri
            .path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str)
            .to_string();
        let args = uri.query().unwrap_or("").to_string();

        // WAF 必须先 URL 解码，否则 `union%20select` 会绕过规则；
        // 解码后再对控制字节做归一化，防止 `union%00select` 这类 NUL 截断绕过。
        let (url, url_suspicious) = decode_and_normalize(&path_query);
        let (args, args_suspicious) = decode_and_normalize(&args);
        let suspicious = url_suspicious + args_suspicious;

        let mut header_flat = String::new();
        let mut header_values: HashMap<String, String> = HashMap::new();
        for (k, v) in headers {
            header_flat.push_str(k.as_str());
            header_flat.push('=');
            let value = String::from_utf8_lossy(v.as_bytes());
            header_flat.push_str(&value);
            header_flat.push(' ');

            let name = k.as_str().to_ascii_lowercase();
            header_values
                .entry(name)
                .and_modify(|old| {
                    old.push_str(", ");
                    old.push_str(&value);
                })
                .or_insert_with(|| value.into_owned());
        }
        NormalizedRequest {
            method: method.to_string(),
            url,
            args,
            headers: header_flat,
            header_values,
            body: body.to_string(),
            suspicious,
        }
    }

    fn field(&self, f: RuleField) -> &str {
        match f {
            RuleField::Url => &self.url,
            RuleField::Args => &self.args,
            RuleField::Header => &self.headers,
            RuleField::Body => &self.body,
            RuleField::Method => &self.method,
        }
    }

    /// 取规则要匹配的字段值。
    ///
    /// `field = "Header"` 且规则指定了 `header = "User-Agent"` 时，
    /// 只取该 header 的值（小写名匹配）；未指定 header 名时退回整串 headers。
    fn field_value(&self, f: RuleField, header: Option<&str>) -> &str {
        match (f, header) {
            (RuleField::Header, Some(name)) => self
                .header_values
                .get(&name.to_ascii_lowercase())
                .map_or("", std::string::String::as_str),
            _ => self.field(f),
        }
    }
}

const REGEX_PREFIX: &str = "regex:";

/// URL 解码 + 控制字节归一化。
///
/// 1. `%XX` 转字节，`+` 转空格；
/// 2. 解码后的 NUL / 控制字节统一替换为空格，防止攻击者用不可打印字节
///    拆碎攻击特征(如 `union%00select` 被后端截断解释为 `union select`)；
/// 3. 统计出现的危险控制字节数量作为「可疑度」，正常流量中几乎不会出现。
///
/// ## 双重编码立场
///
/// 本函数**只解码一层**。`%2520` 解码一次后是 `%20`，如果后端再次解码会
/// 变成空格，理论上存在二次解码绕过（WAF 看 `%20`，后端看空格）。
///
/// 这里刻意不做二次解码：多轮解码会显著增加误报（正常数据里 `%25` 开头的
/// 合法序列很常见），且"后端是否会二次解码"取决于后端框架，WAF 无法可靠
/// 预判。防护二次解码绕过的正确姿势是：后端在取得 WAF 已解码的归一化输入
/// 后不应再次解码，或由后端框架自身保证单次解码语义。
///
/// 返回 `(归一化后的字符串, 可疑度)`。
fn decode_and_normalize(s: &str) -> (String, u32) {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut suspicious = 0u32;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    let decoded = hi * 16 + lo;
                    match class_control(decoded) {
                        ControlClass::None => out.push(decoded),
                        // 危险控制字节：替换为空格 + 计可疑分
                        ControlClass::Dangerous => {
                            out.push(b' ');
                            suspicious += 1;
                        }
                        // 温和控制字节(如 tab)：仅替换，不计分，避免误杀
                        ControlClass::Benign => out.push(b' '),
                    }
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                // 未编码但直接出现的控制字节，同样归一化
                match class_control(b) {
                    ControlClass::None => out.push(b),
                    ControlClass::Dangerous => {
                        out.push(b' ');
                        suspicious += 1;
                    }
                    ControlClass::Benign => out.push(b' '),
                }
                i += 1;
            }
        }
    }

    (String::from_utf8_lossy(&out).into_owned(), suspicious)
}

/// 控制字节分级：
/// - `Dangerous`: NUL 及大多数控制字符，正常流量不出现，属攻击信号
/// - `Benign`: 空格/tab 等无害空白，仅归一化不计分
/// - `None`: 普通可打印字节及多字节 UTF-8 序列
enum ControlClass {
    None,
    Dangerous,
    Benign,
}

fn class_control(b: u8) -> ControlClass {
    match b {
        // NUL 截断是最经典的绕过手段；除 tab/lf/cr 外的控制字符都视为危险
        b'\0' | 0x01..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f => ControlClass::Dangerous,
        // 无害空白：归一化为空格即可
        b'\t' | b'\n' | b'\r' => ControlClass::Benign,
        // 高位字节属 UTF-8 多字节序列的一部分，交给 from_utf8_lossy 处理
        _ => ControlClass::None,
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl Engine {
    /// # Errors
    ///
    /// 规则中的正则表达式语法错误时返回错误（TOML 解析错误在 `Config::load` 阶段处理）。
    pub fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut regexes = Vec::new();
        let needs_body = cfg.rules.iter().any(|r| r.field == RuleField::Body);

        // 字面量规则按 (field, header) 分组，每组一个多模式自动机，
        // 一次扫描即可匹配组内所有模式；且 ASCII 大小写不敏感。
        let mut group_order: Vec<(RuleField, Option<String>)> = Vec::new();
        let mut group_map: LiteralGroupMap = HashMap::new();

        for (idx, rule) in cfg.rules.iter().enumerate() {
            if let Some(re) = rule.pattern.strip_prefix(REGEX_PREFIX) {
                regexes.push((idx, rule.field, rule.score, Regex::new(re)?));
            } else if !rule.pattern.is_empty() {
                let key = (
                    rule.field,
                    rule.header.as_ref().map(|h| h.to_ascii_lowercase()),
                );
                let entry = group_map
                    .entry(key.clone())
                    .or_insert_with(|| (Vec::new(), Vec::new()));
                entry.0.push(rule.pattern.clone());
                entry.1.push(idx);
                if !group_order.contains(&key) {
                    group_order.push(key);
                }
            }
        }

        let mut literals = Vec::new();
        for (field, header) in group_order {
            let Some((patterns, rule_idx)) = group_map.remove(&(field, header.clone())) else {
                continue; // 理论上不可达：key 来自 group_order，一定在 map 中
            };
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&patterns)?;
            literals.push(LiteralGroup {
                field,
                header,
                ac,
                rule_idx,
            });
        }

        Ok(Engine {
            threshold: cfg.score_threshold,
            literals,
            regexes,
            needs_body,
            rules: cfg.rules,
        })
    }

    /// 是否存在需要检查 body 的规则；没有时 handle 可跳过 body 前缀读取。
    #[must_use]
    pub fn needs_body(&self) -> bool {
        self.needs_body
    }

    // 可疑字节本身计分：正常请求不应出现 NUL/控制字节，
    // 出现即视为攻击信号，避免「单条特征被拆碎后低于阈值」的绕过。
    const SUSPICIOUS_BYTE_SCORE: u32 = 5;

    pub fn inspect(&self, req: &NormalizedRequest) -> Verdict {
        let mut total_score = req.suspicious * Self::SUSPICIOUS_BYTE_SCORE;
        // 记录第一个命中规则，用于拦截时携带真实攻击类型
        let mut first_hit_rule: Option<(u32, &str)> = None;

        let mut hits: Vec<Hit> = Vec::new();

        for group in &self.literals {
            let hay = req.field_value(group.field, group.header.as_deref());
            let mut seen: HashSet<usize> = HashSet::new();
            for m in group.ac.find_iter(hay) {
                let pid = m.pattern().as_usize();
                if !seen.insert(pid) {
                    continue; // 同一规则同组内只计一次
                }
                let ridx = group.rule_idx[pid];
                total_score += self.rules[ridx].score;
                hits.push(Hit {
                    rule_id: self.rules[ridx].id,
                    category: self.rules[ridx].category.clone(),
                    score: self.rules[ridx].score,
                });
                if first_hit_rule.is_none() {
                    first_hit_rule =
                        Some((self.rules[ridx].id, self.rules[ridx].category.as_str()));
                }
                tracing::debug!(
                    rule_id = self.rules[ridx].id,
                    score = self.rules[ridx].score,
                    "字面量规则命中"
                );
            }
        }

        for (idx, field, score, re) in &self.regexes {
            let hay = req.field_value(*field, self.rules[*idx].header.as_deref());
            if re.is_match(hay) {
                total_score += score;
                hits.push(Hit {
                    rule_id: self.rules[*idx].id,
                    category: self.rules[*idx].category.clone(),
                    score: *score,
                });
                first_hit_rule
                    .get_or_insert((self.rules[*idx].id, self.rules[*idx].category.as_str()));
                tracing::debug!(
                    rule_id = self.rules[*idx].id,
                    score = *score,
                    "正则规则命中"
                );
            }
        }

        if total_score >= self.threshold {
            if hits.is_empty() {
                // 仅可疑字节触发拦截，归为 suspicious
                hits.push(Hit {
                    rule_id: 0,
                    category: "suspicious".to_string(),
                    score: total_score,
                });
            }
            Verdict::Block {
                hits,
                score: total_score,
            }
        } else {
            Verdict::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Rule, RuleField};

    fn header_map(ua: &str) -> hyper::HeaderMap {
        let mut m = hyper::HeaderMap::new();
        m.insert("user-agent", ua.parse().unwrap());
        m
    }

    fn test_config(rules: Vec<Rule>) -> Config {
        Config {
            score_threshold: 20,
            cc_capacity: 100,
            cc_refill_per_sec: 10,
            rules,
        }
    }

    #[test]
    fn header_specific_rule_only_matches_that_header() {
        let cfg = test_config(vec![Rule {
            id: 100,
            name: "bad ua".into(),
            category: "scanner".into(),
            field: RuleField::Header,
            header: Some("User-Agent".into()),
            pattern: "badagent".into(),
            score: 25,
        }]);
        let engine = Engine::new(cfg).unwrap();

        // 指定 header 命中
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/".parse().unwrap(),
            &header_map("badagent/1.0"),
            "",
        );
        assert!(
            matches!(&engine.inspect(&req), Verdict::Block { hits, .. } if hits[0].category == "scanner")
        );

        // 其它 header 带相同值，但 User-Agent 正常 → 不拦
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/".parse().unwrap(),
            &header_map("normal-agent"),
            "",
        );
        assert!(matches!(engine.inspect(&req), Verdict::Allow));
    }

    #[test]
    fn percent_decode_handles_nul_bypass() {
        // `union%00select` 解码后 NUL 被替换为空格并计可疑分
        let (s, suspicious) = decode_and_normalize("union%00select");
        assert_eq!(s, "union select");
        assert_eq!(suspicious, 1);

        // `+` 解码为空格
        let (s, _) = decode_and_normalize("a+b");
        assert_eq!(s, "a b");
    }

    #[test]
    fn score_accumulates_until_threshold() {
        let cfg = test_config(vec![
            Rule {
                id: 1,
                name: "a".into(),
                category: "x".into(),
                field: RuleField::Args,
                header: None,
                pattern: "alpha".into(),
                score: 8,
            },
            Rule {
                id: 2,
                name: "b".into(),
                category: "y".into(),
                field: RuleField::Args,
                header: None,
                pattern: "beta".into(),
                score: 8,
            },
        ]);
        let engine = Engine::new(cfg).unwrap();

        // 单条 8 分 < 20 阈值 → 放行
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/?q=alpha".parse().unwrap(),
            &hyper::HeaderMap::new(),
            "",
        );
        assert!(matches!(engine.inspect(&req), Verdict::Allow));

        // 两条累计 16 分仍 < 20 → 放行
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/?q=alpha+beta".parse().unwrap(),
            &hyper::HeaderMap::new(),
            "",
        );
        assert!(matches!(engine.inspect(&req), Verdict::Allow));

        // 加上 NUL 可疑字节 5 分 → 21 >= 20 → 拦截
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/?q=alpha%00beta".parse().unwrap(),
            &hyper::HeaderMap::new(),
            "",
        );
        assert!(matches!(engine.inspect(&req), Verdict::Block { score, .. } if score >= 20));
    }
}

#[cfg(test)]
mod case_tests {
    use super::*;
    use crate::config::{Config, Rule, RuleField};

    #[test]
    fn literal_rules_are_ascii_case_insensitive() {
        let cfg = Config {
            score_threshold: 20,
            cc_capacity: 100,
            cc_refill_per_sec: 10,
            rules: vec![Rule {
                id: 1,
                name: "sqli".into(),
                category: "sqli".into(),
                field: RuleField::Args,
                header: None,
                pattern: "union select".into(),
                score: 20,
            }],
        };
        let engine = Engine::new(cfg).unwrap();

        // 大小写混合也不能绕过字面量规则
        let req = NormalizedRequest::from_parts(
            &hyper::Method::GET,
            &"/?q=UNION+SeLeCt".parse().unwrap(),
            &hyper::HeaderMap::new(),
            "",
        );
        assert!(
            matches!(&engine.inspect(&req), Verdict::Block { hits, .. } if hits[0].category == "sqli")
        );
    }
}
