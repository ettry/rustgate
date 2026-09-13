//! 每 IP 令牌桶限流（CC 攻击防护）。
//!
//! 性能设计（`check` 在热路径上每请求调用一次）：
//! * **分片锁**：桶表按 IP 哈希分成 [`SHARDS`] 个 `std::sync::Mutex` 分片，
//!   并发请求只锁自己所在分片，把全局锁竞争降到 1/SHARDS；
//! * 临界区内无 await，使用同步锁（比异步锁快，无任务调度开销），
//!   因此 `check` / `tokens_left` 都是同步方法；
//! * 定期清理超时未活跃的桶，防止伪造海量源 IP 导致内存膨胀；
//! * **桶数硬上限**（[`SHARD_MAX_BUCKETS`]）：时间门控清理存在最长
//!   [`CLEANUP_INTERVAL`] 的空窗，可信代理后伪造海量 XFF IP 可在窗口内
//!   无限建桶；硬上限在插入前即时逐出最旧桶，保证内存恒有界；
//! * 锁中毒时通过 `into_inner` 恢复，不让单点 panic 拖垮 WAF 进程。

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 桶不活跃超过该时长即视为可回收（默认 5 分钟）。
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(300);
/// 清理间隔：桶表超过阈值后，最多每 10 秒做一次全表扫描，
/// 避免高基数（伪造海量源 IP）攻击时每个请求都 O(n) 扫描。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
/// 分片数：把全局锁切成多把，降低并发竞争。
/// 每片清理阈值 = 1024 / SHARDS，保持与旧版全局行为等量。
const SHARDS: usize = 16;
/// 每个分片的桶数阈值（触发时间门控清理）。
const SHARD_CLEANUP_THRESHOLD: usize = 1024 / SHARDS;
/// 每个分片的桶数硬上限：达到后立即逐出最旧的四分之一桶（全局 4096）。
///
/// 时间门控清理（阈值 + 间隔）负责常态回收，但在两次清理之间最多有
/// [`CLEANUP_INTERVAL`] 的空窗；若攻击者（可信代理后伪造海量 XFF IP）
/// 以每请求一个新 IP 的速率洪泛，窗口内桶数会无界增长。
/// 硬上限补上这个洞：插入新桶前检查，超限即逐出最旧桶，内存恒有界。
/// 闲置越久的桶越先被逐出，正常活跃桶基本不受影响；
/// 超过该容量的部署（>4096 个并发活跃 IP）应同步调大本常量与
/// [`SHARD_CLEANUP_THRESHOLD`]。
const SHARD_MAX_BUCKETS: usize = 256;

/// 每个分片的独立状态：桶表 + 上次清理时间。
/// 时间戳放在同一个 Mutex 里，避免额外加锁。
struct Shard {
    buckets: HashMap<String, Bucket>,
    last_cleanup: Instant,
}

pub struct RateLimiter {
    capacity: u32,
    refill_per_sec: u32,
    shards: Vec<Mutex<Shard>>,
}

struct Bucket {
    tokens: u32,
    last: Instant,
}

impl RateLimiter {
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    buckets: HashMap::new(),
                    last_cleanup: Instant::now(),
                })
            })
            .collect();
        RateLimiter {
            capacity,
            refill_per_sec,
            shards,
        }
    }

    /// 消耗一个 token；返回 true 表示超限（应拦截）。
    pub fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let idx = shard_index(ip);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // 桶表超过阈值后按间隔清理，不每个请求都全表扫描
        if shard.buckets.len() >= SHARD_CLEANUP_THRESHOLD
            && now.duration_since(shard.last_cleanup) >= CLEANUP_INTERVAL
        {
            shard
                .buckets
                .retain(|_, b| now.duration_since(b.last) < BUCKET_IDLE_TTL);
            shard.last_cleanup = now;
        }

        // 硬上限兜底：清理间隔的空窗内桶数也不能无界增长
        // （防「可信代理后伪造海量 XFF IP」洪泛撑爆内存）。
        if shard.buckets.len() >= SHARD_MAX_BUCKETS {
            evict_oldest_quarter(&mut shard.buckets);
        }

        let b = shard.buckets.entry(ip.to_string()).or_insert(Bucket {
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
    pub fn tokens_left(&self, ip: &str) -> u32 {
        let idx = shard_index(ip);
        let shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shard.buckets.get(ip).map_or(self.capacity, |b| b.tokens)
    }
}

/// IP 字符串 → 分片索引。`DefaultHasher` 足够快且分布良好，无需密码学强度。
///
/// `u64` 哈希转 `usize` 后取模：取低位与取整个哈希对分片均匀性影响可忽略，
/// 允许截断。
#[allow(clippy::cast_possible_truncation)]
fn shard_index(ip: &str) -> usize {
    let mut h = DefaultHasher::new();
    h.write(ip.as_bytes());
    (h.finish() as usize) % SHARDS
}

/// 逐出最旧的四分之一桶（按 `last` 活跃时间）。
///
/// 用 `select_nth_unstable` 找第 1/4 旧分位的时间点，再整表 `retain`：
/// * 闲置越久的桶越先被逐出，正常活跃桶（最近有请求）天然保留；
/// * 洪泛场景（所有桶 `last` 都很新甚至相同）也保证至少逐出四分之一，
///   硬上限始终有效——被逐的正常桶下次请求会按容量重建，只损失一次
///   突发余量，不会拒绝服务。
fn evict_oldest_quarter(buckets: &mut HashMap<String, Bucket>) {
    let evict = buckets.len() / 4;
    if evict == 0 {
        return;
    }
    let mut times: Vec<Instant> = buckets.values().map(|b| b.last).collect();
    // 第 evict 旧的时间点（0-based 下标 evict-1）：
    // select_nth 保证至少 evict 个值 <= 它，retain 用严格大于即可逐出足量。
    times.select_nth_unstable_by_key(evict - 1, |t| *t);
    let cutoff = times[evict - 1];
    buckets.retain(|_, b| b.last > cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成「n 秒前」的 Instant（测试构造过期桶用）。
    fn past(secs: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn token_bucket_capacity_limits_burst() {
        let rl = RateLimiter::new(2, 0); // 容量 2，不补充

        assert!(!rl.check("1.1.1.1"));
        assert!(!rl.check("1.1.1.1"));
        // 第 3 个请求超限
        assert!(rl.check("1.1.1.1"));
        // 其它 IP 不受影响
        assert!(!rl.check("2.2.2.2"));
    }

    #[test]
    fn tokens_left_reports_remaining() {
        let rl = RateLimiter::new(3, 0);
        assert_eq!(rl.tokens_left("1.1.1.1"), 3);
        rl.check("1.1.1.1");
        assert_eq!(rl.tokens_left("1.1.1.1"), 2);
    }

    #[test]
    fn shard_index_spreads_across_shards() {
        // 不同 IP 应尽量分散到不同分片（用 32 个 IP 验证至少命中 2 片）
        let mut seen = std::collections::HashSet::new();
        for i in 0..32 {
            seen.insert(shard_index(&format!("10.0.0.{i}")));
        }
        assert!(
            seen.len() >= 2,
            "分片应能分散 IP，实际命中 {} 片",
            seen.len()
        );
    }

    #[test]
    fn tokens_left_unknown_ip_returns_capacity() {
        // 从未出现过的 IP：tokens_left 应返回满容量
        let rl = RateLimiter::new(7, 0);
        assert_eq!(rl.tokens_left("9.9.9.9"), 7);
    }

    #[test]
    fn stale_buckets_are_cleaned_after_interval() {
        // 验证时间门控清理：超过阈值条目 + 距上次清理超 10s → retain 回收过期桶
        let rl = RateLimiter::new(10, 0);
        let idx = shard_index("1.2.3.4");

        {
            let mut shard = rl.shards[idx].lock().unwrap();
            // 塞满过期桶（超过清理阈值 64），并把 last_cleanup 拨回 11 秒前
            for i in 0..80 {
                shard.buckets.insert(
                    format!("10.0.{}.{i}", i / 250),
                    Bucket {
                        tokens: 1,
                        last: past(400), // 早已闲置
                    },
                );
            }
            shard.last_cleanup = past(11);
            assert_eq!(shard.buckets.len(), 80);
        }

        // 触发一次 check：应执行清理，回收全部闲置桶
        assert!(!rl.check("1.2.3.4"));

        let shard = rl.shards[idx].lock().unwrap();
        assert!(
            shard.buckets.len() <= 1,
            "闲置桶应被清理，剩余 {}",
            shard.buckets.len()
        );
    }

    #[test]
    fn cleanup_does_not_remove_active_buckets() {
        let rl = RateLimiter::new(10, 0);
        let idx = shard_index("1.2.3.4");
        {
            let mut shard = rl.shards[idx].lock().unwrap();
            // 多数桶闲置，但少数最近活跃；被查询的 IP 本身是活跃桶之一
            for i in 0..80 {
                let ip = if i == 0 {
                    "1.2.3.4".to_string()
                } else {
                    format!("10.0.{}.{i}", i / 250)
                };
                shard.buckets.insert(
                    ip,
                    Bucket {
                        tokens: 1,
                        last: if i % 2 == 0 {
                            Instant::now()
                        } else {
                            past(400)
                        },
                    },
                );
            }
            shard.last_cleanup = past(11);
        }

        rl.check("1.2.3.4");

        let shard = rl.shards[idx].lock().unwrap();
        // 40 个活跃桶应保留（含被查询的 1.2.3.4），40 个闲置桶被回收
        assert_eq!(shard.buckets.len(), 40, "活跃桶不应被清理");
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        // refill > 0 时，经过一段时间后 token 应恢复（覆盖补充逻辑）
        let rl = RateLimiter::new(10, 1000); // 每秒补充 1000
        assert!(!rl.check("1.2.3.4"));
        assert_eq!(rl.tokens_left("1.2.3.4"), 9);

        // 等 15ms：应补充约 15 个（受容量 10 上限截断）→ 补满 10，再消费 1 → 剩 9
        std::thread::sleep(Duration::from_millis(15));
        assert!(!rl.check("1.2.3.4"), "补充后不应再被限流");
        assert_eq!(rl.tokens_left("1.2.3.4"), 9);
    }

    #[test]
    fn partial_refill_without_cap_clamp_distinguishes_arithmetic() {
        // 让补充量不触顶，区分「tokens + add」与变异「tokens * add」：
        // 先消耗到 50，等待几 ms 补充少量（~2-5）→ 正确 51-55；变异 * 则 50*N 触顶到 100-1=99
        let rl = RateLimiter::new(100, 1000);
        for _ in 0..50 {
            rl.check("1.2.3.4");
        }
        assert_eq!(rl.tokens_left("1.2.3.4"), 50);

        std::thread::sleep(Duration::from_millis(3));
        rl.check("1.2.3.4"); // 补充少量再消费 1
        let left = rl.tokens_left("1.2.3.4");
        assert!(
            (51..90).contains(&left),
            "部分补充应相加（未触顶），实际 {left}（变异 * 会得到 99）"
        );
    }

    #[test]
    fn cleanup_requires_both_size_and_interval() {
        // 距上次清理已超过间隔，但桶数未达阈值 → 不应全表清理（捕获 && → || 变异）
        let rl = RateLimiter::new(10, 0);
        let idx = shard_index("1.2.3.4");
        {
            let mut shard = rl.shards[idx].lock().unwrap();
            // 远低于阈值（5 个），其中 1 个已闲置过期
            for i in 0..5 {
                shard.buckets.insert(
                    format!("10.0.0.{i}"),
                    Bucket {
                        tokens: 1,
                        last: if i == 0 { past(400) } else { Instant::now() },
                    },
                );
            }
            shard.last_cleanup = past(11);
        }

        rl.check("1.2.3.4");

        let shard = rl.shards[idx].lock().unwrap();
        // 正确逻辑（&&）：桶数 < 阈值 → 不清理 → 过期桶保留，共 6 个
        // 若被变异成 ||，则过期桶被回收 → 只剩 2 个
        assert_eq!(shard.buckets.len(), 6, "未达阈值不应触发全表清理");
    }

    #[test]
    fn hard_cap_evicts_oldest_and_bounds_memory() {
        // 回归（RUST-03）：分片桶数达到硬上限时必须逐出最旧桶，内存有界。
        // 直接构造超限分片：190 个早已闲置的旧桶 + 远超上限总数的新桶。
        let rl = RateLimiter::new(10, 0);
        let idx = shard_index("1.2.3.4");
        {
            let mut shard = rl.shards[idx].lock().unwrap();
            for i in 0..(SHARD_MAX_BUCKETS + 4) {
                shard.buckets.insert(
                    format!("10.0.{i}.1"),
                    Bucket {
                        tokens: 1,
                        // 前 190 个早已闲置（会被逐出），其余刚刚活跃（应保留）
                        last: if i < 190 { past(400) } else { Instant::now() },
                    },
                );
            }
            assert_eq!(shard.buckets.len(), SHARD_MAX_BUCKETS + 4);
        }

        // 触发一次 check：硬上限应逐出一批桶（时间门控清理因间隔未到不参与）
        assert!(!rl.check("1.2.3.4"));

        let shard = rl.shards[idx].lock().unwrap();
        assert!(
            shard.buckets.len() <= SHARD_MAX_BUCKETS,
            "桶数必须被限制在硬上限内，实际 {}",
            shard.buckets.len()
        );
        // 闲置桶被逐出、活跃桶保留（70 个新桶 + 刚插入的 1.2.3.4）
        let active = shard
            .buckets
            .values()
            .filter(|b| b.last > past(300))
            .count();
        assert!(active >= 65, "活跃桶应基本保留，实际 {active}");
    }

    #[test]
    fn flood_of_new_ips_never_exceeds_hard_cap() {
        // 回归（RUST-03）：模拟「每请求一个新 IP」洪泛（可信代理后伪造 XFF），
        // 插入 2 倍于全局硬上限总量的不同 IP，总桶数仍不得超过上限总量。
        let rl = RateLimiter::new(10, 0);
        let flood = SHARD_MAX_BUCKETS * SHARDS * 2;
        for i in 0..flood {
            let _ = rl.check(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256));
        }

        let total: usize = rl
            .shards
            .iter()
            .map(|s| s.lock().unwrap().buckets.len())
            .sum();
        assert!(
            total <= SHARD_MAX_BUCKETS * SHARDS,
            "洪泛 {flood} 个 IP 后总桶数 {total} 应 <= 硬上限总量 {}",
            SHARD_MAX_BUCKETS * SHARDS
        );
    }
}
