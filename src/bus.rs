//! 告警总线：拦截事件入队 + 广播给所有订阅者（Flutter 面板经 WebSocket 订阅）。
//!
//! 用 `tokio::sync::broadcast` 实现一对多推送；
//! 另维护一个带锁的历史缓冲，供管理 API 读取最近告警与统计。
//! 统计中的 QPS 用滑动窗口计算（最近 1 秒内的放行请求数）。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex};

/// QPS 滑动窗口时长。
const QPS_WINDOW: Duration = Duration::from_secs(1);
/// 窗口内最多保留的时间戳数量（防极端 QPS 下队列膨胀）。
const MAX_WINDOW_SAMPLES: usize = 1_000_000;

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

    /// 把告警转成 HTTP 响应（用于反代直接返回拦截页 / JSON）。
    ///
    /// 构建响应在合法输入下不会失败；极端情况兜底为最简 500 响应，不 panic。
    pub fn into_response(
        self,
        code: hyper::StatusCode,
    ) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
        let body = serde_json::to_string(&self).unwrap_or_else(|_| "{\"action\":\"block\"}".into());
        hyper::Response::builder()
            .status(code)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .unwrap_or_else(|_| {
                hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(
                    "{\"action\":\"block\"}",
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
    /// 最近告警（环形保留，上限 500；VecDeque 两端 O(1)）
    alerts: std::collections::VecDeque<Alert>,
    total_requests: u64,
    blocked: u64,
    /// 放行请求时间戳（QPS 滑动窗口）
    request_times: VecDeque<Instant>,
    /// 上一条已落盘/已展示告警的去重键（用于日志瘦身）
    last_dedup_key: Option<String>,
}

#[derive(Clone)]
pub struct AlertBus {
    tx: broadcast::Sender<Alert>,
    inner: Arc<Mutex<Inner>>,
}

impl AlertBus {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        AlertBus {
            tx,
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// 记录一次拦截：
    /// * `blocked` 计数总是累加；
    /// * 若与上一条告警的去重键相同（除时间外同一攻击），则只把上一条的
    ///   `count` +1，不写新条目、不广播，返回 `false`（调用方无需落盘）；
    /// * 否则写入历史、广播给订阅者、更新去重键，返回 `true`（调用方应落盘）。
    pub async fn publish(&self, alert: Alert) -> bool {
        let dedup_key = alert.dedup_key();
        {
            let mut inner = self.inner.lock().await;
            inner.blocked += 1;
            if inner.last_dedup_key.as_deref() == Some(dedup_key.as_str()) {
                // 连续重复：真实次数累加到最后一条（即上一条相同告警）
                if let Some(last) = inner.alerts.back_mut() {
                    last.count += 1;
                }
                return false; // 略过新增条目
            }
            inner.last_dedup_key = Some(dedup_key);
            inner.alerts.push_back(alert.clone());
            if inner.alerts.len() > 500 {
                inner.alerts.pop_front();
            }
        }
        // 没有订阅者时 send 会出错，忽略即可
        let _ = self.tx.send(alert);
        true
    }

    /// 记录一次放行请求（累计总数 + 滑动窗口计数）。
    pub async fn count_request(&self) {
        let mut inner = self.inner.lock().await;
        inner.total_requests += 1;
        let now = Instant::now();
        inner.request_times.push_back(now);
        // 懒惰清理：只在队列过长时修剪窗口外的旧时间戳
        if inner.request_times.len() > MAX_WINDOW_SAMPLES {
            let cutoff = now.checked_sub(QPS_WINDOW).unwrap_or(now);
            while inner.request_times.front().is_some_and(|t| *t < cutoff) {
                inner.request_times.pop_front();
            }
        }
    }

    /// 订阅实时告警流。
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.tx.subscribe()
    }

    /// 读取统计快照。QPS = 最近 1 秒内的请求数（滑动窗口，取整）。
    pub async fn stats(&self) -> Stats {
        let now = Instant::now();
        let cutoff = now.checked_sub(QPS_WINDOW).unwrap_or(now);
        let mut inner = self.inner.lock().await;
        // 修剪窗口，保证 QPS 精确反映最近一秒
        while inner.request_times.front().is_some_and(|t| *t < cutoff) {
            inner.request_times.pop_front();
        }
        #[allow(clippy::cast_precision_loss)] // 窗口样本数 ≤ 1e6，f64 完全精确
        let qps = inner.request_times.len() as f64;
        Stats {
            total_requests: inner.total_requests,
            blocked: inner.blocked,
            qps,
        }
    }

    /// 最近 N 条告警（倒序，最新的在前）。
    pub async fn recent_alerts(&self, n: usize) -> Vec<Alert> {
        let inner = self.inner.lock().await;
        inner.alerts.iter().rev().take(n).cloned().collect()
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
        bus.publish(sample_alert()).await;
        // 完全相同的第二条（仅 time 可能不同）：略过，但 count 累加
        bus.publish(sample_alert()).await;
        // 不同 path：保留
        let mut other = sample_alert();
        other.path = "/?a=2".into();
        bus.publish(other).await;

        let stats = bus.stats().await;
        assert_eq!(stats.blocked, 3); // 计数全部累加

        let recent = bus.recent_alerts(100).await;
        assert_eq!(recent.len(), 2); // 但只保留 2 条（重复的被略过）
                                     // 第一条的 count 应为 2（1 原始 + 1 重复）
        assert_eq!(recent[0].count, 1); // 最新的是 /?a=2
        assert_eq!(recent[1].count, 2); // /?a=1%20union%20select 出现过两次
    }

    #[tokio::test]
    async fn non_consecutive_same_alert_keeps_both() {
        let bus = AlertBus::new();
        bus.publish(sample_alert()).await;
        let mut other = sample_alert();
        other.path = "/?x".into();
        bus.publish(other).await;
        // 第三条又和第一条相同——因为中间隔了一条，不算“连续重复”，应保留
        bus.publish(sample_alert()).await;

        assert_eq!(bus.recent_alerts(100).await.len(), 3);
    }
}
