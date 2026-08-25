//! 告警总线：拦截事件入队 + 广播给所有订阅者（Flutter 面板经 WebSocket 订阅）。
//!
//! 用 `tokio::sync::broadcast` 实现一对多推送；
//! 另维护一个带锁的历史缓冲，供管理 API 读取最近告警与统计。
//! 统计中的 QPS 用滑动窗口计算（最近 1 秒内的放行请求数）。
//!
//! 性能设计（`count_request` 在热路径上每请求调用一次）：
//! * `total_requests` / `blocked` 用 `AtomicU64` 无锁累加；
//! * 历史/去重/QPS 窗口用 `std::sync::Mutex`（临界区内无 await，比异步锁快），
//!   因此 `count_request`/`publish`/`stats`/`recent_alerts` 都是同步方法；
//! * QPS 窗口每次 push 后立即修剪过期项（均摊 O(1)：每条最多被 pop 一次），
//!   内存稳定在「1 秒样本量」，不会像旧版那样堆积到上百万条再修剪。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

/// QPS 滑动窗口时长。
const QPS_WINDOW: Duration = Duration::from_secs(1);
/// 历史告警环形保留上限。
const MAX_ALERTS: usize = 500;

/// 单条命中规则（告警里携带全部命中，hits[0] 为第一条）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertHit {
    pub rule_id: u32,
    pub category: String,
    pub score: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    pub time: u64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub category: String,
    pub detail: String,
    pub rule_id: u32,
    pub score: u32,
    pub action: &'static str,
    /// 连续重复次数：首次出现为 1，后续相同的告警去重时累加。
    /// 展示层只保留一条（防刷屏），但真实次数通过该字段保留。
    pub count: u32,
    /// 本次请求命中的全部规则（第一条为主展示规则）。
    #[serde(default)]
    pub hits: Vec<AlertHit>,
}

impl Alert {
    /// 构造一条拦截告警。
    #[must_use]
    pub fn new(
        ip: &str,
        method: &hyper::Method,
        path: &str,
        category: &str,
        detail: &str,
        rule_id: u32,
        score: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Alert {
            time: now,
            ip: ip.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            category: category.to_string(),
            detail: detail.to_string(),
            rule_id,
            score,
            action: "block",
            count: 1,
            hits: Vec::new(),
        }
    }

    /// 去重键：忽略时间，只看「同一来源 + 同一攻击特征」的字段。
    ///
    /// 字段：ip + method + path + category + detail。
    /// 用于拦截日志瘦身：连续重复的相同告警只保留第一条，
    /// 其余直接略过（不写内存、不广播、不落盘），仅累加 blocked 计数。
    #[must_use]
    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.ip, self.method, self.path, self.category, self.detail
        )
    }

    /// 对外返回的通用拦截响应。
    ///
    /// 响应体是**固定的通用拦截页**：不回显 `rule_id`/`score`/`hits`/请求路径等细节，
    /// 防止攻击者据此探测规则阈值、精确构造低于阈值的绕过载荷（WAF 指纹）。
    /// 详细命中信息只通过管理 API（`/api/alerts`）与审计日志提供给运维方。
    ///
    /// 构建响应在合法输入下不会失败；极端情况兜底为最简响应，不 panic。
    #[must_use]
    pub fn block_response(
        code: hyper::StatusCode,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        hyper::Response::builder()
            .status(code)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(
                b"{\"action\":\"block\"}",
            )))
            .unwrap_or_else(|_| {
                hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from_static(
                    b"{\"action\":\"block\"}",
                )))
            })
    }
}

/// 面板统计快照
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub total_requests: u64,
    pub blocked: u64,
    pub qps: f64,
}

#[derive(Debug, Default)]
struct Inner {
    /// 最近告警（环形保留，上限 [`MAX_ALERTS`]；`VecDeque` 两端 O(1)）
    alerts: VecDeque<Alert>,
    /// 放行请求时间戳（QPS 滑动窗口；每次 push 后即时修剪）
    request_times: VecDeque<Instant>,
    /// 上一条已落盘/已展示告警的去重键（用于日志瘦身）
    last_dedup_key: Option<String>,
}

#[derive(Clone)]
pub struct AlertBus {
    tx: broadcast::Sender<Alert>,
    /// 总请求数：热路径每请求 +1，原子操作无锁。
    total_requests: Arc<AtomicU64>,
    /// 拦截总数：每次 publish +1，原子操作无锁。
    blocked: Arc<AtomicU64>,
    inner: Arc<Mutex<Inner>>,
}

impl AlertBus {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        AlertBus {
            tx,
            total_requests: Arc::new(AtomicU64::new(0)),
            blocked: Arc::new(AtomicU64::new(0)),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// 记录一次拦截：
    /// * `blocked` 计数总是累加；
    /// * 若与上一条告警的去重键相同（除时间外同一攻击），则只把上一条的
    ///   `count` +1，不写新条目、不广播，返回 `false`（调用方无需落盘）；
    /// * 否则写入历史、广播给订阅者、更新去重键，返回 `true`（调用方应落盘）。
    #[must_use]
    pub fn publish(&self, alert: Alert) -> bool {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        let dedup_key = alert.dedup_key();
        {
            let mut inner = self.lock();
            if inner.last_dedup_key.as_deref() == Some(dedup_key.as_str()) {
                // 连续重复：真实次数累加到最后一条（即上一条相同告警）
                if let Some(last) = inner.alerts.back_mut() {
                    last.count += 1;
                }
                return false; // 略过新增条目
            }
            inner.last_dedup_key = Some(dedup_key);
            inner.alerts.push_back(alert.clone());
            if inner.alerts.len() > MAX_ALERTS {
                inner.alerts.pop_front();
            }
        }
        // 没有订阅者时 send 会出错，忽略即可
        let _ = self.tx.send(alert);
        true
    }

    /// 记录一次放行请求（累计总数 + 滑动窗口计数）。
    ///
    /// 窗口每次 push 后立即修剪 1 秒外的旧时间戳：均摊 O(1)
    /// （每条时间戳最多入队/出队各一次），内存恒定在 1 秒样本量。
    pub fn count_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let cutoff = now.checked_sub(QPS_WINDOW).unwrap_or(now);
        let mut inner = self.lock();
        inner.request_times.push_back(now);
        while inner.request_times.front().is_some_and(|t| *t < cutoff) {
            inner.request_times.pop_front();
        }
    }

    /// 订阅实时告警流。
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.tx.subscribe()
    }

    /// 读取统计快照。QPS = 最近 1 秒内的请求数（滑动窗口，取整）。
    #[must_use]
    pub fn stats(&self) -> Stats {
        let now = Instant::now();
        let cutoff = now.checked_sub(QPS_WINDOW).unwrap_or(now);
        let inner = self.lock();
        // 修剪窗口，保证 QPS 精确反映最近一秒
        //（count_request 已即时修剪，这里兜底应对长时间无人请求后的一次查询）
        let qps = inner.request_times.iter().filter(|t| **t >= cutoff).count();
        Stats {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            #[allow(clippy::cast_precision_loss)] // 1 秒内样本数，f64 精确
            qps: qps as f64,
        }
    }

    /// 最近 N 条告警（倒序，最新的在前）。
    #[must_use]
    pub fn recent_alerts(&self, n: usize) -> Vec<Alert> {
        let inner = self.lock();
        inner.alerts.iter().rev().take(n).cloned().collect()
    }

    /// 拿内部锁；中毒时恢复（单点 panic 不应拖垮统计）。
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for AlertBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn sample_alert() -> Alert {
        Alert::new(
            "1.2.3.4",
            &hyper::Method::GET,
            "/?a=1%20union%20select",
            "sqli",
            "rule #1",
            1,
            20,
        )
    }

    #[tokio::test]
    async fn consecutive_duplicates_are_dropped() {
        let bus = AlertBus::new();

        // 第一条：保留
        let _ = bus.publish(sample_alert());
        // 完全相同的第二条（仅 time 可能不同）：略过，但 count 累加
        let _ = bus.publish(sample_alert());
        // 不同 path：保留
        let mut other = sample_alert();
        other.path = "/?a=2".into();
        let _ = bus.publish(other);

        let stats = bus.stats();
        assert_eq!(stats.blocked, 3); // 计数全部累加

        let recent = bus.recent_alerts(100);
        assert_eq!(recent.len(), 2); // 但只保留 2 条（重复的被略过）
                                     // 第一条的 count 应为 2（1 原始 + 1 重复）
        assert_eq!(recent[0].count, 1); // 最新的是 /?a=2
        assert_eq!(recent[1].count, 2); // /?a=1%20union%20select 出现过两次
    }

    #[tokio::test]
    async fn non_consecutive_same_alert_keeps_both() {
        let bus = AlertBus::new();
        let _ = bus.publish(sample_alert());
        let mut other = sample_alert();
        other.path = "/?x".into();
        let _ = bus.publish(other);
        // 第三条又和第一条相同——因为中间隔了一条，不算“连续重复”，应保留
        let _ = bus.publish(sample_alert());

        assert_eq!(bus.recent_alerts(100).len(), 3);
    }

    #[tokio::test]
    async fn block_response_hides_rule_details() {
        // 拦截响应必须是不含规则命中的通用页，防止攻击者探测 WAF 规则（防指纹）
        let resp = Alert::block_response(hyper::StatusCode::FORBIDDEN);
        assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert_eq!(text, r#"{"action":"block"}"#);
        // 不得泄漏路径/规则 id/分数/命中详情
        for leaked in ["union select", "rule_id", "\"score\"", "\"hits\""] {
            assert!(!text.contains(leaked), "拦截响应不应包含: {leaked}");
        }
    }

    #[test]
    fn default_bus_starts_empty() {
        // Default 实现等价于 new()，且初始统计为零
        let bus = AlertBus::default();
        let s = bus.stats();
        assert_eq!(s.total_requests, 0);
        assert_eq!(s.blocked, 0);
        assert!(s.qps < f64::EPSILON, "初始 QPS 应为 0，实际 {}", s.qps);
        assert!(bus.recent_alerts(10).is_empty());
    }

    #[test]
    fn alerts_history_capped_at_max() {
        // 超过 MAX_ALERTS 条时淘汰最旧，但 blocked 计数仍精确
        let bus = AlertBus::new();
        for i in 0..(MAX_ALERTS + 50) {
            let mut a = sample_alert();
            a.path = format!("/?i={i}");
            let _ = bus.publish(a);
        }
        assert_eq!(bus.recent_alerts(10000).len(), MAX_ALERTS);
        assert_eq!(bus.stats().blocked, (MAX_ALERTS + 50) as u64);
    }

    #[test]
    fn stats_prunes_stale_window_entries() {
        // 手动塞入一个超过 1 秒的旧时间戳，stats() 应立即修剪，QPS 不含它
        let bus = AlertBus::new();
        {
            let mut inner = bus.inner.lock().unwrap();
            inner
                .request_times
                .push_back(Instant::now().checked_sub(Duration::from_secs(5)).unwrap());
        }
        let s = bus.stats();
        assert!(
            s.qps < f64::EPSILON,
            "超过窗口的旧样本不应计入 QPS，实际 {}",
            s.qps
        );
    }
}
