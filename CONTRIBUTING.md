# Contributing

> Of course, you don’t have to follow it exactly,do whatever you think is best. Thank you.

Thanks for looking at Hrabnaz. This page covers the things a new contributor cannot guess from the code: the invariants that the build and tests enforce, where each kind of change lands, and how to verify your work without a kernel lab.

[中文](CONTRIBUTING.zh-CN.md)

## Ground rules

1. **User-space code contains zero `unsafe`.** Event decoding reads eBPF memory through safe byte extraction and `nix` wrappers. If a change seems to need `unsafe`, the design is wrong somewhere.
2. **C/Rust structs are one contract.** Anything in `crates/hrabnaz-core/src/` marked `#[repr(C)]` is shared with the eBPF side. There are compile-time size asserts next to the definitions; a field change that breaks them fails the build, which is the point. Update both sides in the same commit.
3. **Kernel-side policy stays cheap.** The eBPF layer does integer scoring and filtering only. Regexes, correlation and baselines belong in `hrabnaz-engine`. If you are about to put a loop over strings into a probe, reconsider.
4. **Dialect-specific values stay out of default rules.** Rules ship only semantics true on every Linux. Cloud agents and site-specific noise are handled by the deployment allowlists (`HRABNAZ_SENSITIVE_PATH_ALLOW`, `HRABNAZ_RULE_PROC_ALLOW`, `HRABNAZ_BASELINE_HIGHFREQ`). A rule patch that hardcodes one vendor's daemon will be rejected.
5. **Blocking (`enforce: true`) rules need precision.** Match on exact comm/syscall, prove zero false positives in monitor mode first, and remember the protected-pids/protected-comms lists are a backstop, not an excuse.

## Where changes land

| Change | Place | Notes |
|---|---|---|
| A new detection rule | `rules/*.yml` | Follow the field/operator reference in the manual; add a negative test if the rule could fire on benign traffic |
| A new event source | `crates/hrabnaz-ebpf/src/bpf/` + `crates/hrabnaz-core/src/lib.rs` | New event type value, `event_type_name` mapping, `#[repr(C)]` struct, decoder in `hrabnaz-engine/src/aggregator.rs`, size assert |
| Engine logic (correlation, baseline, forensics) | `crates/hrabnaz-engine/src/` | Unit tests in the same file are the norm; integration tests live in `crates/hrabnaz-engine/tests/` |
| A CLI command | `crates/hrabnaz-cli/src/main.rs` + `cmds/` | Keep `--json` single-line output as the machine contract |
| Build/BTF | `crates/hrabnaz-ebpf/btf/`, `scripts/btf-*.sh`, build.rs | See "BTF pipeline" below |

## The BTF pipeline

The repo carries only minimal BTF blobs (149 files, ~322 KB), not full kernel BTF (600 MB+). Full BTF lives in a local cache that `scripts/btf-fetch.sh` fills from the btfhub archive; `scripts/btf-regen.sh` rebuilds `index.tsv` and `blobs/` from that cache. Both are idempotent.

If you add a kernel release:

```bash
scripts/btf-fetch.sh            # downloads full BTF into ~/.cache/hrabnaz/btf-full
scripts/btf-regen.sh            # rebuilds index.tsv + blobs/, verifies hashes
cargo test -p hrabnaz-engine --test btf_relocation_test
```

The relocation test compares every embedded minimal blob against the full BTF instruction by instruction and asserts the aya poison sentinel is present for out-of-table types. Without a local cache the test skips cleanly; with one it does the full proof. Do not commit `.btf` or `.btf.xz` files — `.gitignore` blocks them.

## Verifying without root

`cargo test --workspace` runs 242 tests with no root and no Linux-specific dependencies in the user-space path (a mock event source feeds the engine). The rule-layer ART repro tests (`crates/hrabnaz-engine/tests/art_rule_repro.rs`) feed recorded attack events through the real rule set; if you touch rules or field extraction, that file is the regression net.

Runtime checks that genuinely need a kernel:

```bash
sudo ./target/debug/hrabnaz start --rules-dir rules/ --log-dir /tmp/ks-try
./target/debug/hrabnaz status --watch          # probes attached, maps filling
./target/debug/hrabnaz replay --file /tmp/ks-try/events_*.jsonl
```



## CLA

By opening a pull request you grant the maintainer the right to use, modify, and distribute your contribution under GPLv3 or under a separate commercial license. You retain copyright to your contribution. The full text is in [CLA.md](CLA.md); CLA Assistant will prompt you on your first PR.
