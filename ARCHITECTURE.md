# Hrabnaz — Architecture

## Overview

Hrabnaz is an eBPF-based endpoint threat detection system for Linux servers. The system ships as a single musl-statically-linked binary that embeds all eBPF bytecode and kernel BTF profiles needed for deployment.

Probes attach to kernel entry points across four paths: syscalls, VFS, network stack, and process scheduling. Detection decisions are layered:

- **Kernel space** performs integer risk scoring and noise filtering. Evaluation is restricted to integer comparisons; overhead is bounded by a single map lookup.
- **User space (Rust engine)** runs YAML rule matching, cross-event correlation, behavioral baselines, and anomaly detection on the filtered event stream.
- **Forensics** writes every event and alert to a SHA-256 hash-chained JSONL log with an externally anchored chain head.

Three invariants hold across all tiers and code paths:

1. **Verifier-guaranteed safety.** An eBPF program that fails the kernel verifier is rejected at load time. This constrains kernel-space logic to integer arithmetic and bounded loops.
2. **Portable detection semantics.** Built-in rules describe facts that hold across Linux environments. Environment-specific behavior is handled through deployment-layer configuration, never by recompiling probes.
3. **Forensic integrity first.** The ability to prove post-incident that logs were tamper-free is a hard constraint. Log readability and storage footprint rank below it.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ CLI Layer (hrabnaz-cli)                                        │
│   start stop status watch replay baseline correlation          │
│   block unblock blocked watchdog rules-digest completion       │
├────────────────────────────────────────────────────────────────┤
│ User-Space Engine (hrabnaz-engine)                             │
│   Event Source (tier routing / unified consumption)            │
│   → Aggregation & Decoding (IP restore / argv rebuild)         │
│   → Rule Engine (YAML) ┐                                       │
│   → Correlation (window/seq/tree) ├→ Alert Pipeline           │
│   → Baseline/ML (z-score + EWMA)  ┘  └→ Forensic Log (hash)   │
│   → Attack Chain Reconstruction → BlockManager                │
├────────────────────────────────────────────────────────────────┤
│ Core Types (hrabnaz-core)                                      │
│   #[repr(C)] shared structs + compile-time size assertions     │
├────────────────────────────────────────────────────────────────┤
│ Kernel Probe Layer (hrabnaz-ebpf, C)                           │
│   Single entry hrabnaz_main.bpf.c, includes 10 probe headers  │
│   5-tier conditional compilation: modern/legacy/ancient/*     │
│   In-kernel inference + smart filtering + enforcement          │
└────────────────────────────────────────────────────────────────┘
```

**Upstream flow**: Probe events traverse ringbuf or perfbuf channels, are decoded by the aggregator into `DecodedEvent` instances, and dispatched to the rule, correlation, and baseline/ML engines. All events—matching or otherwise—are persisted to the forensic log.

**Downstream flow**: The `BlockManager` writes enforcement verdicts into the kernel `block_decisions` map. Kernel probes query this map along the syscall path to execute termination.

## Kernel Probe Layer

The probe layer compiles from a single entry point (`hrabnaz_main.bpf.c`) that sequentially includes probe headers. Conditional compilation flags (`HRABNAZ_TIER_MODERN`, `HRABNAZ_TIER_LEGACY`, `HRABNAZ_TIER_ANCIENT`, `HRABNAZ_NOBTF`) select the target tier at build time. Probes attach to the following kernel entry points:

| SEC Section | Type | Source | Events & Behavior |
|---|---|---|---|
| `raw_syscalls/sys_enter` | tracepoint | `hrabnaz_probes_syscall.h` | Captures syscall context (including exec argv) for whitelisted calls; stores in `syscall_ctxs`. |
| `raw_syscalls/sys_exit` | tracepoint | `hrabnaz_probes_syscall.h` | Emits exec, open, write, delete, rename, chmod, connect, ptrace, signal, lkm_load events; counts remaining syscalls for frequency. |
| `sched_process_fork/exec/exit` | tracepoint ×3 | `hrabnaz_probes_process_tree.h` | Emits process-tree lifecycle events; fork events only on anomalous parent-child relations or inherited risk. |
| `vfs_open` | kprobe | `hrabnaz_probes_vfs.h` | Updates smart filter statistics; no events. |
| `vfs_write` | kprobe | `hrabnaz_probes_vfs.h` | Emits file_write (threshold-gated). |
| `vfs_unlink` | kprobe | `hrabnaz_probes_vfs.h` | Emits file_delete. |
| `tcp_v4_connect` / `tcp_v6_connect` | kprobe ×2 | `hrabnaz_probes_net.h` | Emits net_connect. |
| `udp_sendmsg` | kprobe | `hrabnaz_probes_net.h` | Emits net_dns (port 53) / net_send. |
| `tcp_set_state` | kprobe | `hrabnaz_probes_netflow.h` | Emits flow lifecycle events; flags exfil on large transfers. |
| `tcp_sendmsg` | kprobe | `hrabnaz_probes_netflow.h` | Accumulates flow byte counts; no standalone events. |
| `commit_creds` | kprobe | `hrabnaz_probes_container.h` | Emits container_escape. |
| `do_init_module` | kprobe | `hrabnaz_probes_lkm.h` | Emits lkm_load. |
| `security_bpf_prog_free` | kprobe | `hrabnaz_probes_self_protect.h` | Emits ebpf_tamper. |

kprobe attachment paths bypass the smart filter. Only the `sys_exit` main path is governed by filtering and blocking logic.

### In-Kernel Inference

At the syscall exit point, the kernel computes a per-process risk score using integer arithmetic across four dimensions: path sensitivity, network destination, behavior frequency, and process context. Thresholds are stored in the `infer_config` map and adjustable from user space at runtime. The risk score travels upstream as event metadata; the kernel itself generates no alerts.

On modern kernels, when enforce mode is active and the risk score reaches the kill threshold, the probe calls `bpf_send_signal(SIGKILL)` directly. Processes in `protected_pids` or `protected_comms` are short-circuited before this logic.

### Smart Filtering

The kernel applies a three-stage funnel to reduce ringbuf pressure:

1. **Duplicate I/O folding**: Consecutive `open`/`read`/`write` on the same `(pid, path)` within a time window emit only the first event. Delete, rename, and chmod are never folded.
2. **Safe pattern matching**: `(comm, path_prefix)` pairs recorded in `safe_patterns` drop matching events in kernel space.
3. **High-sensitivity passthrough**: High-risk events bypass folding.

The engine's own I/O to the forensic directory is excluded by directory prefix to prevent a self-feeding loop.

### BPF Map Inventory

| Map | Type | Purpose |
|---|---|---|
| `events` | RINGBUF / PERF_ARRAY | Main event channel |
| `tree_events` / `freq_events` / `flow_events` | RINGBUF / PERF_ARRAY | Sideband channels (process tree, frequency, flow) |
| `syscall_ctxs` | HASH | Syscall enter context staging |
| `process_tree` | LRU_HASH | Process topology nodes |
| `risk_scores` | LRU_HASH | Per-process risk scores |
| `freq_counters` | LRU_HASH | 60s window behavior counters |
| `net_flows` | LRU_HASH | TCP flow state machines |
| `net_conn_history` | LRU_HASH | Connection frequency history |
| `port_scan_map` | LRU_HASH | Port scan tracking |
| `block_decisions` | LRU_HASH | Enforcement verdicts (pid → expire + reason) |
| `protected_pids` / `protected_comms` | LRU_HASH | Exemption lists |
| `safe_patterns` | HASH | Smart filter safe patterns |
| `anomaly_relations` | HASH | Anomalous parent-child mappings |
| `infer_config` | ARRAY | In-kernel inference configuration |
| per-CPU maps | PERCPU_ARRAY | Scratch buffers and counters |

Under the `ancient` tier, `LRU_HASH` degrades to standard `HASH` (3.10 lacks LRU semantics). Long-running instances on this tier require periodic restarts to flush state tables.

### Event Types

Event type constants are defined in `hrabnaz_base.h` and probe headers. The userspace `EventType` enum covers types routed through the primary decode path; sideband types are consumed by the loader and passed to `decode()`.

| Range | Scope |
|---|---|
| 1–3 | Process lifecycle: exec / exit / clone |
| 10–15 | File operations: open / read / write / delete / rename / chmod |
| 20–24 | Network: connect / accept / send / recv / dns |
| 30–31 | Process control: ptrace / signal |
| 40–43 | Process tree: fork / exec / exit / anomaly |
| 50–54 | Flow: create / state / data / close / anomaly |
| 60–61 | Frequency: update / anomaly |
| 80–82 | High-risk: container escape / LKM load / eBPF tamper |

## User-Space Engine

### Event Source & Tier Routing

The loader detects the kernel tier at startup (version, BTF availability, embedded table match) and attaches the corresponding ringbuf or perfbuf channels via the Aya framework. All channels feed a unified consumption loop.

### Detection Engines

The aggregator decodes raw bytes into `DecodedEvent` (IP restoration, argv reconstruction, path extraction) and wraps them in `Arc` for zero-copy sharing across engines.

**Rule engine**: YAML rules parse into strongly typed `Field` and `Operator` enums. Invalid field names reject the entire rule file at load time; regex patterns are precompiled and cached. Rules are indexed by event type.

**Correlation engine**: Three modes—time window, event sequence, and process tree—operate over a bounded sliding window with per-rule cooldown. Sequence trackers are keyed by `(rule_idx, pid)` to prevent cross-rule interference.

**Behavioral baselines**: Six-dimension z-score baselines with training-phase locking. Anomalies are flagged only on one-sided deviation (frequency above baseline). An EWMA model runs in parallel for gradual drift. Naturally high-frequency processes are exempted via compiled-in defaults plus the `HRABNAZ_BASELINE_HIGHFREQ` deployment variable.

### Forensic Logging

JSONL log with SHA-256 hash chains: each record's hash incorporates its predecessor's hash. Sensitive argument redaction occurs before hashing. Logs rotate at size thresholds into gzip archives; expired archives are pruned by retention policy. The chain-tail hash is periodically exported to `chain_head.log`, providing tamper evidence even if the entire log directory is destroyed. Chain verification is streaming and reports the exact break position.

### Blocking

Two termination paths:

- **In-kernel**: On modern tiers, the probe calls `bpf_send_signal(SIGKILL)` when the risk score reaches the kill threshold and enforce mode is active.
- **Userspace killer**: On legacy/ancient tiers, a userspace process polls the pinned `block_decisions` map and sends SIGKILL to matching PIDs.

Three-layer exemption prevents lockout: `protected_pids` (engine self + PID 1), `protected_comms` (system processes with exe_path verification), and CLI validation (rejects PID 0/1 and self-kill). Expiration timestamps use `CLOCK_MONOTONIC` to stay synchronized with `bpf_ktime_get_ns` in kernel space.

## CLI

The CLI provides runtime control (`start`, `stop`), status (`status`, `watch`), forensics (`replay`), diagnostics (`baseline`, `correlation`), blocking (`block`, `unblock`, `blocked`), and operational tooling (`watchdog`, `rules-digest`, `completion`).

`--json` emits single-line JSON as a stable machine contract. Exit codes follow convention: 0 success, 1 runtime error, 2 usage error.

`replay` runs an eight-stage pipeline: hash chain verification → parsing → statistics → type distribution → severity distribution → MITRE mapping → attack chain reconstruction → process profiling.

## Cross-Kernel Compatibility

A single C probe codebase compiles into five bytecode tiers via conditional compilation:

| Tier | Kernels | Channel | CO-RE |
|---|---|---|---|
| modern | 5.8+ | ringbuf | embedded or system BTF |
| legacy | 4.10–5.7 | perfbuf | embedded or system BTF |
| ancient | 3.10–4.9 | perfbuf | embedded or system BTF |
| ancient_nobtf | 3.10–4.9 | perfbuf | hardcoded offsets |
| legacy_nobtf | 4.10–5.7 | perfbuf | hardcoded offsets |

BTF resolution order: `HRABNAZ_BTF_PATH` env → `/sys/kernel/btf/vmlinux` → embedded table. The embedded table requires exact `uname -r` match; fuzzy version guessing is rejected because struct offsets vary across kernel build configurations.

The embedded BTF pipeline: fetch full BTF files from the BTFHub archive → trim via `bpftool gen min_core_btf` to keep only probe-referenced types → deduplicate by content hash → embed via `include_bytes!`. A relocation correctness test compares each trimmed profile against full BTF instruction-by-instruction; Aya rewrites missing-type relocations to a poison immediate rather than erroring, so without this test, builds pass CI but fail the kernel verifier on target machines.

## Known Limitations

1. **In-kernel blocking** requires modern tier (5.8+). Legacy and ancient tiers rely on userspace polling.
2. **Small file writes** below the `vfs_write` probe's size threshold are invisible on the write path; partially compensated by subsequent rename, chmod, or open events.
3. **Environment variables** passed to `execve` are not captured; `LD_PRELOAD` injection is invisible.
4. **DNS capture** on 3.10 kernels is insufficient for reliable tunnel detection.
5. **DNS utility exclusions** in the tunnel rule trade detection coverage for false-positive reduction.
6. **Map eviction** on the ancient tier: LRU degrades to standard HASH, requiring periodic restarts for long-running instances.
