# ==========================================================================
# 内核哨兵 (KernelSentinel) — 生产部署镜像 (多阶段构建)
# ==========================================================================
#
# 阶段:
#   1. builder  — Rust 1.82 + clang/llvm 编译 eBPF + Rust release 二进制
#   2. runtime  — debian:bookworm-slim 精简运行时 (< 200MB 目标)
#
# 构建:
#   docker build -t kernelsentinel:latest .
#   docker compose up -d
#
# 运行 (eBPF 需 privileged + 宿主 /sys/fs/bpf):
#   docker run --rm --privileged \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /proc:/proc \
#     -v /lib/modules:/lib/modules:ro \
#     -p 8080:8080 kernelsentinel:latest
#
# 说明:
#   - ks-engine/build.rs 在 cargo build 时用 clang-18 编译 eBPF C 探针为
#     字节码 (.o)，运行时由 aya 加载；故 builder 必须装 clang/llvm/libelf。
#   - 运行时镜像不需要 clang/llvm，仅 bpftool (调试) + libelf + iproute2。
#   - 构建两个二进制:
#       * kernelsentinel  (ks-cli，含 start 子命令，entrypoint 实际调用)
#       * ks-server-bin   (ks-server，独立 REST+WS 服务，备用)
#     注: spec 写 `-p ks-server-bin`，但 cargo `-p` 接受包名而非二进制名，
#     包名是 ks-server；为同时满足"构建 ks-server-bin"与"entrypoint 可用"，
#     改用 `--bin kernelsentinel --bin ks-server-bin` 显式指定两个二进制。
# ==========================================================================

# ──────────────────────────────────────────────────────────────────────────
# Stage 1: builder
# ──────────────────────────────────────────────────────────────────────────
FROM rust:1.82-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin

# 系统依赖: clang/llvm 编译 eBPF C; libelf-dev/libbpf-dev 提供头文件 (/usr/include/bpf)
RUN apt-get update && apt-get install -y --no-install-recommends \
        llvm-18 \
        clang-18 \
        libelf-dev \
        libbpf-dev \
        pkg-config \
        make \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# ---- 依赖缓存层 (仅 Cargo.toml 变化时重建) ----
# Cargo.toml 有 [patch.crates-io] aya → vendor/aya，必须一并复制
COPY Cargo.toml Cargo.lock* ./
COPY vendor/ ./vendor/

# 各 crate 的 Cargo.toml (workspace members)
COPY crates/ks-core/Cargo.toml   crates/ks-core/Cargo.toml
COPY crates/ks-engine/Cargo.toml crates/ks-engine/Cargo.toml
COPY crates/ks-cli/Cargo.toml    crates/ks-cli/Cargo.toml
COPY crates/ks-server/Cargo.toml crates/ks-server/Cargo.toml

# 创建空源文件占位，触发依赖编译缓存 (真实源码稍后 COPY 覆盖)
RUN mkdir -p crates/ks-core/src   && echo ""                       > crates/ks-core/src/lib.rs    \
 && mkdir -p crates/ks-engine/src && echo ""                       > crates/ks-engine/src/lib.rs  \
 && mkdir -p crates/ks-cli/src    && echo "fn main() {}"           > crates/ks-cli/src/main.rs    \
 && mkdir -p crates/ks-server/src && echo ""                       > crates/ks-server/src/lib.rs  \
 && mkdir -p crates/ks-server/src && echo "fn main() {}"           > crates/ks-server/src/main.rs

# 预编译依赖 (ks-engine/build.rs 此阶段无 eBPF 源码会 warn+跳过，不阻断)
RUN cargo build --release --bin kernelsentinel --bin ks-server-bin 2>/dev/null || true

# ---- 完整源码 ----
COPY . .

# 真实编译: 此时 ks-engine/build.rs 会用 clang-18 编译 eBPF 字节码
RUN cargo build --release --bin kernelsentinel --bin ks-server-bin

# ──────────────────────────────────────────────────────────────────────────
# Stage 2: runtime
# ──────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    RUST_LOG=info

# 运行时依赖:
#   libelf1    — libelf 共享库 (部分动态链接)
#   libbpf1   — bpftool 依赖
#   bpftool   — eBPF 调试/vmlinux.h 生成 (可选但实用)
#   iproute2  — 网络诊断 (网络探针场景)
#   ca-certificates — HTTPS 出站 (告警 webhook 等)
#   libgcc-s1 — Rust 二进制可能依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
        libbpf1 \
        bpftool \
        iproute2 \
        ca-certificates \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# 二进制
COPY --from=builder /workspace/target/release/kernelsentinel  /usr/local/bin/kernelsentinel
COPY --from=builder /workspace/target/release/ks-server-bin   /usr/local/bin/ks-server-bin

# 规则
COPY rules/ /etc/kernelsentinel/rules/

# 日志目录
RUN mkdir -p /var/log/kernelsentinel

# 入口脚本
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# REST API + WebSocket /metrics (8080); 备用 TLS/管理端口 (8443)
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--serve", "8080", "--rules-dir", "/etc/kernelsentinel/rules"]
