> Huginn ok Muninn
>
> fljúga hverjan dag
>
> jörmungrund yfir;
>
> óumk ek of Hugin,
>
> at hann aptr ne komi,
>
> þó sjámk meirr um Munin.
>
> — Grímnismál, Poetic Edda

**Hrabnaz** · *Huginn thinks. Muninn remembers. Hrabnaz judges.*

# Hrabnaz

eBPF-based endpoint threat detection for Linux servers that can't be upgraded. One binary covers 3.10 through 7.x.

[![AtomGit G-Star](https://atomgit.com/HiChat-fog/Hrabnaz/star/new_badge.svg)](https://atomgit.com/HiChat-fog/Hrabnaz)

[中文文档](docs/README.zh-CN.md)

## How it works

eBPF probes capture events at kernel entry points. Detection state lives in kernel space: process topology, TCP flows, behavior frequencies, and a per-process risk score. Normal behavior produces no events.

The userspace engine runs YAML rules, cross-event correlation, behavioral baselines, and anomaly detection. Every event lands in a SHA-256 hash-chained JSONL log with an externally anchored chain head.

Blocking is kernel-side on modern kernels, userspace-polling on older ones. Default mode is monitor.

## Kernel support

| Tier | Kernels | Channel | CO-RE |
|---|---|---|---|
| modern | 5.8+ | ringbuf | embedded BTF |
| legacy | 4.10–5.7 | perfbuf | embedded BTF |
| ancient | 3.10–4.9 | perfbuf | embedded BTF |
| ancient_nobtf | 3.10–4.9 | perfbuf | fixed offsets |
| legacy_nobtf | 4.10–5.7 | perfbuf | fixed offsets |

Distribution kernel BTF profiles are trimmed and embedded at build time. Each profile is verified instruction-by-instruction against full BTF. Unlisted kernels are rejected at load time.

## Build

Linux, clang 18, libelf, Rust stable.

```bash
cargo build --release        # compiles all eBPF tiers, embeds BTF profiles
cargo test --workspace       # no root required
```

## Run

```bash
sudo ./target/release/hrabnaz start --rules-dir rules/
hrabnaz status
hrabnaz watch --severity high
hrabnaz replay --file /var/log/hrabnaz/events_*.jsonl
```

Monitor mode by default. Blocking requires `enforce: true` on individual rules.

## Documentation

- [Architecture](ARCHITECTURE.md)

## License

GPL-3.0. Third-party components: [aya](vendor/aya) (MIT/Apache-2.0), BTF profiles from [btfhub-archive](https://github.com/aquasecurity/btfhub-archive) (Apache-2.0).
