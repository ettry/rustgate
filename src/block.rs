//! 内存 IP 黑名单：管理 API 手动封禁，支持定时自动解封。
//!
//! * 仅保存在内存中，进程重启后清空（WAF 层临时封禁，不替代系统防火墙）；
//! * 以规范化后的 IP 字符串为 key（IPv4-mapped IPv6 归一化为 IPv4）；
//! * 定时清理过期条目，避免哈希表无限膨胀。
//!
//! 性能设计（`is_blocked` 在热路径上每请求调用一次）：
//! * **逐条目 O(1) 判过期**：命中 key 才看时间，已过期立即移除，
//!   保证「定时解封」语义精确且不扫描全表；
//! * **全表清理时间门控**：全表扫描每 [`CLEANUP_INTERVAL`] 最多一次，
//!   回收「从未被查询」的过期条目，避免内存膨胀（同 limiter 的策略）；
//! * 临界区内无 await，使用 `std::sync::Mutex`，方法均为同步。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 全表清理间隔：最多每 30 秒扫一次全表，回收从未被查询的过期条目。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// 一条封禁记录（用于 API 返回）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockedEntry {
    pub ip: String,
    /// 解封时刻的 UNIX 秒。
    pub expires_at: u64,
}

/// 内部状态：封禁表 + 上次全表清理时间。
struct Inner {
    map: HashMap<String, Instant>,
    last_cleanup: Instant,
}

#[derive(Clone)]
pub struct BlockList {
    inner: Arc<Mutex<Inner>>,
}

impl Default for BlockList {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockList {
    #[must_use]
    pub fn new() -> Self {
        BlockList {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
        }
    }

    /// 封禁一个 IP，`duration` 为封禁时长。
    ///
    /// 使用 `checked_add` 防止 `duration` 过大导致 `Instant` 溢出 panic
    /// （例如调用方传入 `u64::MAX` 秒）。溢出时返回错误而不是崩溃。
    ///
    /// # Errors
    ///
    /// * IP 字符串非法时返回错误（`无效 IP: ...`）；
    /// * `duration` 过大导致解封时刻溢出 `Instant` 时返回错误。
    pub fn block(&self, ip: &str, duration: Duration) -> Result<BlockedEntry, String> {
        let key = normalize_ip_str(ip)?;
        let now = Instant::now();
        let expires_at = now
            .checked_add(duration)
            .ok_or_else(|| "封禁时长过大，无法计算解封时间".to_string())?;
        let mut inner = self.lock();
        inner.map.insert(key.clone(), expires_at);
        Ok(BlockedEntry {
            ip: key,
            expires_at: unix_secs(expires_at),
        })
    }

    /// 手动解封一个 IP；成功移除返回 `true`，IP 本就不在列表返回 `false`。
    ///
    /// # Errors
    ///
    /// IP 字符串非法时返回错误（`无效 IP: ...`）。
    pub fn unblock(&self, ip: &str) -> Result<bool, String> {
        let key = normalize_ip_str(ip)?;
        let mut inner = self.lock();
        Ok(inner.map.remove(&key).is_some())
    }

    /// 是否处于封禁状态。
    ///
    /// 只检查当前 IP 的条目：已过期则即时移除并返回 `false`（O(1) 精确解封），
    /// 不扫描全表；全表清理交给 [`Self::maybe_sweep`] 的时间门控。
    #[must_use]
    pub fn is_blocked(&self, ip: &str) -> bool {
        let Ok(key) = normalize_ip_str(ip) else {
            return false;
        };
        let now = Instant::now();
        let mut inner = self.lock();
        Self::maybe_sweep(&mut inner, now);
        match inner.map.get(&key) {
            Some(at) if *at > now => true,
            Some(_) => {
                // 已过期：按条目移除（精确解封，不等全表清理）
                inner.map.remove(&key);
                false
            }
            None => false,
        }
    }

    /// 当前封禁列表（顺带全量清理过期项）。
    #[must_use]
    pub fn list(&self) -> Vec<BlockedEntry> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.map.retain(|_, at| *at > now);
        inner.last_cleanup = now;
        inner
            .map
            .iter()
            .map(|(ip, at)| BlockedEntry {
                ip: ip.clone(),
                expires_at: unix_secs(*at),
            })
            .collect()
    }

    /// 时间门控的全表清理：回收从未被查询的过期条目，最多每 [`CLEANUP_INTERVAL`] 一次。
    fn maybe_sweep(inner: &mut Inner, now: Instant) {
        if now.duration_since(inner.last_cleanup) >= CLEANUP_INTERVAL {
            inner.map.retain(|_, at| *at > now);
            inner.last_cleanup = now;
        }
    }

    /// 拿内部锁；中毒时恢复（单点 panic 不应拖垮封禁功能）。
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn unix_secs(at: Instant) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + at.saturating_duration_since(Instant::now()).as_secs()
}

/// 解析并规范化 IP：IPv4-mapped IPv6（`::ffff:a.b.c.d`）归为 IPv4。
fn normalize_ip_str(ip: &str) -> Result<String, String> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| format!("无效 IP: {ip}"))?;
    let canonical = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    };
    Ok(canonical.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_and_auto_expire() {
        let list = BlockList::new();
        list.block("::ffff:1.2.3.4", Duration::from_millis(50))
            .unwrap();

        // IPv4-mapped IPv6 与 IPv4 视为同一 key
        assert!(list.is_blocked("1.2.3.4"));

        std::thread::sleep(Duration::from_millis(80));
        // 过期后即使未到全表清理间隔，逐条目判过期也应立刻解封
        assert!(!list.is_blocked("1.2.3.4"));
    }

    #[test]
    fn unblock_removes_entry() {
        let list = BlockList::new();
        list.block("10.0.0.8", Duration::from_secs(300)).unwrap();
        assert!(list.is_blocked("10.0.0.8"));
        assert!(list.unblock("10.0.0.8").unwrap());
        assert!(!list.is_blocked("10.0.0.8"));
    }

    #[test]
    fn invalid_ip_is_rejected() {
        assert!(normalize_ip_str("not-an-ip").is_err());
    }

    #[test]
    fn block_rejects_overflow_duration() {
        // u64::MAX 秒会导致 Instant 溢出，应返回错误而不是 panic。
        let list = BlockList::new();
        let err = list
            .block("1.2.3.4", Duration::from_secs(u64::MAX))
            .unwrap_err();
        assert!(err.contains("过大"), "错误信息: {err}");
    }

    #[test]
    fn default_is_empty() {
        // Default 实现等价于 new()
        let list = BlockList::default();
        assert!(!list.is_blocked("1.2.3.4"));
        assert!(list.list().is_empty());
    }

    #[test]
    fn block_returns_expiry_in_unix_seconds_range() {
        // expires_at 必须是「当前 unix 秒 + 时长」附近，捕获 unix_secs 恒 0/1 或运算符变异
        let list = BlockList::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = list.block("1.2.3.4", Duration::from_secs(300)).unwrap();
        // unix_secs 用 as_secs 向下取整，允许截断 1 秒
        assert!(
            entry.expires_at >= now + 299,
            "解封时间不应早于 now+299: {} vs {}",
            entry.expires_at,
            now + 299
        );
        assert!(
            entry.expires_at <= now + 301,
            "解封时间不应晚于 now+301: {}",
            entry.expires_at
        );
    }

    #[test]
    fn list_drops_expired_entries() {
        let list = BlockList::new();
        list.block("1.1.1.1", Duration::from_millis(50)).unwrap();
        list.block("2.2.2.2", Duration::from_secs(300)).unwrap();

        // 等第一条过期后，list() 应只保留未过期的
        std::thread::sleep(Duration::from_millis(80));
        let entries = list.list();
        assert!(entries.iter().any(|e| e.ip == "2.2.2.2"));
        assert!(
            !entries.iter().any(|e| e.ip == "1.1.1.1"),
            "过期条目应被 list 清理"
        );
    }

    #[test]
    fn maybe_sweep_reclaims_expired_never_queried_entries() {
        // 直接构造一个 last_cleanup 很久以前的 Inner，验证时间门控全表清理
        let now = Instant::now();
        let mut inner = Inner {
            map: HashMap::new(),
            last_cleanup: now
                .checked_sub(Duration::from_secs(CLEANUP_INTERVAL.as_secs() + 1))
                .unwrap(),
        };
        // 已过期但从未被查询的条目
        inner.map.insert(
            "10.0.0.1".into(),
            now.checked_sub(Duration::from_secs(1)).unwrap(),
        );
        // 未过期条目应保留
        inner
            .map
            .insert("10.0.0.2".into(), now + Duration::from_secs(300));

        BlockList::maybe_sweep(&mut inner, now);

        assert!(!inner.map.contains_key("10.0.0.1"), "过期条目应被回收");
        assert!(inner.map.contains_key("10.0.0.2"), "未过期条目应保留");
        assert_eq!(inner.last_cleanup, now);
    }
}
