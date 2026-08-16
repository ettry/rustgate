//! 每 IP 令牌桶限流（CC 攻击防护）。
//!
//! * 使用 `tokio::sync::Mutex`（异步友好，不在 async 上下文阻塞线程）；
//! * 定期清理超时未活跃的桶，防止伪造海量源 IP 导致内存膨胀；
//! * 锁中毒时通过 `into_inner` 恢复，不让单点 panic 拖垮 WAF 进程。

use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// 桶不活跃超过该时长即视为可回收（默认 5 分钟）。
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(300);
/// 清理间隔：桶表超过阈值后，最多每 10 秒做一次全表扫描，
/// 避免高基数（伪造海量源 IP）攻击时每个请求都 O(n) 扫描。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

pub struct RateLimiter {
    capacity: u32,
    refill_per_sec: u32,
    buckets: Mutex<std::collections::HashMap<String, Bucket>>,
    /// 上次清理闲置桶的时间。
    last_cleanup: Mutex<Instant>,
}

struct Bucket {
    tokens: u32,
    last: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        RateLimiter {
            capacity,
            refill_per_sec,
            buckets: Mutex::new(std::collections::HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// 消耗一个 token；返回 true 表示超限（应拦截）。
    /// 由调用方（异步上下文）`await` 调用。
    pub async fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().await;

        // 桶表超过阈值后按间隔清理，不每个请求都全表扫描
        if map.len() >= 1024 {
            let mut last_cleanup = self.last_cleanup.lock().await;
            if now.duration_since(*last_cleanup) >= CLEANUP_INTERVAL {
                map.retain(|_, b| now.duration_since(b.last) < BUCKET_IDLE_TTL);
                *last_cleanup = now;
            }
        }

        let b = map.entry(ip.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });

        let elapsed = now.duration_since(b.last).as_secs_f64();
        // 令牌补充量向下取整；结果受 capacity 上限约束，截断是预期行为
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let add = (elapsed * f64::from(self.refill_per_sec)) as u32;
        if add > 0 {
            b.tokens = (b.tokens + add).min(self.capacity);
            b.last = now;
        }

        if b.tokens > 0 {
            b.tokens -= 1;
            false
        } else {
            true
        }
    }

    /// 剩余 token 数（调试/面板用）。
    pub async fn tokens_left(&self, ip: &str) -> u32 {
        let map = self.buckets.lock().await;
        map.get(ip).map_or(self.capacity, |b| b.tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn token_bucket_capacity_limits_burst() {
        let rl = RateLimiter::new(2, 0); // 容量 2，不补充

        assert!(!rl.check("1.1.1.1").await);
        assert!(!rl.check("1.1.1.1").await);
        // 第 3 个请求超限
        assert!(rl.check("1.1.1.1").await);
        // 其它 IP 不受影响
        assert!(!rl.check("2.2.2.2").await);
    }

    #[tokio::test]
    async fn tokens_left_reports_remaining() {
        let rl = RateLimiter::new(3, 0);
        assert_eq!(rl.tokens_left("1.1.1.1").await, 3);
        rl.check("1.1.1.1").await;
        assert_eq!(rl.tokens_left("1.1.1.1").await, 2);
    }
}
