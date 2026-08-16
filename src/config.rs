//! 配置加载：规则文件 + 全局阈值 + CC 限流参数。

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub score_threshold: u32,
    /// CC 令牌桶容量（每 IP），默认 100。
    #[serde(default = "default_cc_capacity")]
    pub cc_capacity: u32,
    /// CC 令牌桶每秒补充速率，默认 10。
    #[serde(default = "default_cc_refill")]
    pub cc_refill_per_sec: u32,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_cc_capacity() -> u32 {
    100
}

fn default_cc_refill() -> u32 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub category: String,
    pub field: RuleField,
    pub pattern: String,
    pub score: u32,
    /// 可选：仅当 `field = "Header"` 时有效，表示只匹配该名称的 header
    /// （如 "User-Agent"、"Cookie"、"Referer"）。不填则匹配所有 header 拼接串。
    #[serde(default)]
    pub header: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum RuleField {
    Url,
    Args,
    Header,
    Body,
    Method,
}

impl Config {
    /// # Errors
    ///
    /// 文件不存在/不可读、或 TOML 语法错误时返回错误（TOML 错误信息包含行号列号）。
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_error_reports_line_number() {
        let path = std::env::temp_dir().join(format!("rg-bad-config-{}.toml", std::process::id()));
        std::fs::write(&path, "score_threshold = 20\n[[rules\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line"), "TOML 错误应包含行号: {msg}");
        let _ = std::fs::remove_file(&path);
    }
}
