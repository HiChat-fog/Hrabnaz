//! H-7 验收示例：直接消费 hrabnaz-engine 完成与 CLI `start` 等价的事件处理。
//!
//! 本示例不依赖 hrabnaz-cli：建引擎 → tick 循环消费效果 → shutdown 收尾，
//! 用非循环 mock 事件源所以无需 root/内核即可跑完（CI 可复现）。
//!
//! 运行: cargo run -p hrabnaz-engine --example embed_demo

use hrabnaz_engine::config::Config;
use hrabnaz_engine::engine::{AlertSource, Engine, EngineEffect, EngineOptions, EventSourceSpec};
use hrabnaz_engine::event_source::{MockEventSource, MockScenario};
use hrabnaz_engine::forensic::ForensicLogger;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let log_dir = std::env::temp_dir().join("ks-embed-demo");
    let _ = std::fs::remove_dir_all(&log_dir);

    // 1. 生命周期：组装全部检测组件（规则/关联/基线/ML/取证链/阻断/心跳）
    let mut engine = Engine::start(EngineOptions {
        config: Config::default(),
        rules_dir: rules_dir.to_string_lossy().into_owned(),
        log_dir: log_dir.to_string_lossy().into_owned(),
        // 嵌入方可注入任意 EventSource（真实探针/自有采集器/测试 mock）
        source: EventSourceSpec::Provided(
            Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
            None,
        ),
        heartbeat_path: None,
        ml_observe_sec: None,
    })
    .await?;
    let info = engine.info();
    println!(
        "事件源: {} | 规则 {} 条 | 取证: {}",
        info.source_desc,
        info.rules_total,
        info.forensic_path.display()
    );
    let forensic_path = info.forensic_path.clone();

    // 2. 自有循环：tick 批量消费，效果按发生顺序返回，呈现方式完全由消费方决定
    let mut alert_count = 0usize;
    let mut consumed = 0usize;
    loop {
        let outcome = engine.tick().await?;
        consumed += outcome.consumed;
        for effect in &outcome.effects {
            if let EngineEffect::Alert(raised) = effect {
                alert_count += 1;
                let kind = match &raised.source {
                    AlertSource::Rule => "rule",
                    AlertSource::Correlation { .. } => "correlation",
                    AlertSource::BaselineDeviation => "baseline",
                    AlertSource::MlAnomaly => "ml",
                    AlertSource::ProcessTree { .. } => "process-tree",
                };
                println!(
                    "[{kind}] {} {} (pid={})",
                    raised.alert.severity, raised.alert.title, raised.alert.process.pid
                );
            }
        }
        if outcome.exhausted {
            break;
        }
    }

    // 3. 终态：shutdown 停任务/flush 取证链，返回统计
    let summary = engine.shutdown().await?;
    println!(
        "\n消费 {consumed} | 入链事件 {} | 入链告警 {} | 运行 {:.2}s\n链尾哈希: {}",
        summary.events_logged, summary.alerts_logged, summary.elapsed_secs, summary.chain_tail_hash
    );

    // 4. 取证链自证
    let v = ForensicLogger::verify_chain(&forensic_path)?;
    println!(
        "取证链校验: {} ({} 条记录)",
        if v.is_valid {
            "通过 ✓"
        } else {
            "断裂 ✗"
        },
        v.total_records
    );
    assert!(v.is_valid, "引擎产出的取证链必须完整");
    assert_eq!(alert_count, summary.alerts_logged as usize);
    Ok(())
}
