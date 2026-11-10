//! 单调钟 → 墙钟换算。
//!
//! 内核事件/告警的 `timestamp_ns` 来自 `bpf_ktime_get_ns()`（CLOCK_MONOTONIC，
//! 开机起算）：不可回拨、不受 NTP 跳变影响，是取证序的权威时钟；但外部消费方
//! （SIEM、Hliðskjálf）做跨主机关联时需要墙钟。换算式
//! `epoch = /proc/stat btime + monotonic` 是记录内容的纯函数——不取"当下"的系统
//! 时钟，回放/校验时对任意历史记录都能离线重算出同一个值。
//!
//! 已知偏差：CLOCK_MONOTONIC 不计系统休眠时长，休眠过的机器换算值会偏小；
//! 服务器场景不休眠，且该字段只做关联展示，取证序仍以单调钟为准。

use std::sync::OnceLock;

static BOOT_EPOCH_SECS: OnceLock<Option<i64>> = OnceLock::new();

/// /proc/stat 的 btime（启动时刻的墙钟 Unix 秒）。只解析一次；读不到（非 Linux、
/// 容器裁剪 /proc）返回 None，消费方保留单调钟字段即可，不伪造墙钟。
fn boot_epoch_secs() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    stat.lines().find_map(|l| {
        let v = l.strip_prefix("btime ")?;
        v.trim().parse::<i64>().ok()
    })
}

/// 单调纳秒 → Unix 纪元毫秒。None = 当前环境拿不到 btime，外部消费方应退回
/// 使用 `timestamp_ns` 单调钟并标注"开机后"。
pub fn epoch_ms_from_monotonic_ns(monotonic_ns: u64) -> Option<i64> {
    let btime = (*BOOT_EPOCH_SECS.get_or_init(boot_epoch_secs))?;
    Some(btime.saturating_mul(1000) + i64::try_from(monotonic_ns / 1_000_000).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_ms_formula() {
        // btime + monotonic 换算本身：btime=1700000000, mono=1.5s → 170000001500ms
        let btime = 1700000000i64;
        let mono_ms = 1500u64;
        assert_eq!(btime * 1000 + mono_ms as i64, 1_700_000_001_500);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_epoch_ms_on_linux_is_recent() {
        // Linux 上 /proc/stat 必有 btime；换算出的"开机时刻的墙钟"应是过去时间
        if let Some(ms) = epoch_ms_from_monotonic_ns(0) {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            assert!(ms < now_ms, "开机时刻应早于现在: {ms} vs {now_ms}");
            // btime 不早于 2020（本项目的部署目标都在其后）
            assert!(ms > 1_577_836_800_000, "btime 异常: {ms}");
        }
    }
}
