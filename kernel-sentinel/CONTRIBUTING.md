# Contributing to KernelSentinel

Thank you for your interest in contributing to KernelSentinel! This document outlines the guidelines for contributing to the project.

## Project structure

KernelSentinel is a Rust workspace based on the [aya](https://github.com/aya-rs/aya) framework. The workspace contains 4 crates:

| Crate | Description |
|-------|-------------|
| `ks-core` | Core types, error handling, shared utilities |
| `ks-engine` | Detection engine + eBPF loader (build.rs compiles C eBPF probes) |
| `ks-cli` | Command-line interface (`kernelsentinel` binary) |
| `ks-server` | REST API + WebSocket data service |

`ks-ebpf` is a pure C project (not a workspace member). Its source is compiled by `ks-engine/build.rs` into **5** tier-specific `.o` files at build time.

### eBPF tiers

`ks-engine/build.rs` compiles the single entry point `ks_main.bpf.c` into 5 tier-specific bytecode objects:

| Tier | Target kernel | Notes |
|------|--------------|-------|
| `modern` | 5.8+ (ringbuf) | Default for current kernels |
| `legacy` | 4.x (perfbuf) | Older kernels without ringbuf |
| `ancient` | 3.10+ with BTF | CO-RE, requires BTF backport |
| `ancient_nobtf` | 3.10+ without BTF | Hardcoded offsets; `.BTF.ext` stripped via `llvm-objcopy`; requires `3.10.0-1160` prefix guard |
| `legacy_nobtf` | 4.19 without BTF | Hardcoded offsets; `.BTF.ext` stripped; requires `4.19.` prefix guard |

## Development setup

### Prerequisites

- Rust (stable toolchain)
- clang (18+ recommended; 14+ minimum)
- llvm (provides `llvm-objcopy`, used by `ancient_nobtf` tier)
- libelf-dev
- libbpf-dev (provides `/usr/include/bpf/`)

On Ubuntu 22.04:

```bash
# Default clang (14) — sufficient for building/testing
sudo apt install clang llvm libelf-dev libbpf-dev

# Or clang-18 for the exact CI toolchain
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 18
sudo apt install libelf-dev libbpf-dev
```

### Building

```bash
# Build all workspace crates (triggers eBPF compilation)
cargo build --workspace

# Build release binary
cargo build --release -p ks-cli
```

### Running tests

```bash
cargo test --workspace
```

## Code style

### Rust formatting

All Rust code must pass `rustfmt`:

```bash
cargo fmt --all -- --check
```

To auto-format:

```bash
cargo fmt --all
```

### Clippy

All code must pass `clippy` with no warnings:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### eBPF C code

Follow the kernel's coding style for C files under `crates/ks-ebpf/src/bpf/`. Run `clang-format` if available.

### Shell scripts

All shell scripts under `scripts/` must pass `shellcheck`:

```bash
shellcheck scripts/*.sh
```

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Use |
|------|-----|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code refactoring (no behavior change) |
| `test` | Test additions/changes |
| `chore` | Build, CI, tooling changes |
| `perf` | Performance improvement |

Example:

```
feat(engine): add ransomware detection rule

Add detection for mass file encryption patterns in the VFS layer.
Closes #42.
```

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Ensure all CI checks pass locally before pushing:
   - `cargo test --workspace`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo fmt --all -- --check`
   - eBPF 5-tier compilation (all `.o` files generated)
   - `shellcheck scripts/*.sh`
3. Write a clear PR description using the pull request template.
4. Ensure no new compiler warnings are introduced.
5. Request review from maintainers.
6. Address review feedback by pushing additional commits (do not squash until merge).

### eBPF changes

If you modify eBPF probe code under `crates/ks-ebpf/src/bpf/`:

- Verify all 5 tier `.o` files compile successfully.
- Test on multiple kernel tiers if possible.
- Update `rules/*.yml` if detection rules change.

## Reporting issues

- Use the **bug report** template for bugs — include kernel version, architecture, and eBPF tier.
- Use the **feature request** template for feature suggestions.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
