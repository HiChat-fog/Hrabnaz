# ==========================================================================
# 内核哨兵 (KernelSentinel) — 开发编译镜像
# ==========================================================================
#
# 用途:
#   1. 在非 Linux 环境下编译验证 eBPF C 代码 + Rust 项目
#   2. 生成 vmlinux.h (BTF)
#   3. 运行 Linux-only 的单元测试
#
# 限制:
#   - 不可用于端到端 eBPF 加载验证 (需要真实内核 + BTF)
#   - 不可用于性能测试
#   - --privileged 模式可加载 eBPF 到 WSL2 内核，但非生产环境
#
# 使用:
#   docker build -t ks-build .
#   docker run --rm -v $(pwd):/workspace ks-build
#
# 带完整 eBPF 编译:
#   docker run --rm -v $(pwd):/workspace ks-build ./scripts/build.sh
#
# ==========================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin

# ========== 系统依赖 ==========
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-15 \
    llvm-15 \
    libbpf-dev \
    linux-headers-generic \
    bpftool \
    pkg-config \
    libssl-dev \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ========== 安装 Rust ==========
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --target x86_64-unknown-linux-gnu

# ========== 工作目录 ==========
WORKDIR /workspace

# 先复制 Cargo 配置，利用 Docker 缓存层
# 注意: ks-server 目前不在 workspace 中 (已注释掉)，不复制其 Cargo.toml
COPY Cargo.toml Cargo.lock* ./
COPY crates/ks-core/Cargo.toml crates/ks-core/Cargo.toml
COPY crates/ks-engine/Cargo.toml crates/ks-engine/Cargo.toml
COPY crates/ks-cli/Cargo.toml crates/ks-cli/Cargo.toml

# 创建空源文件以缓存依赖编译
RUN mkdir -p crates/ks-core/src && echo "" > crates/ks-core/src/lib.rs \
 && mkdir -p crates/ks-engine/src && echo "" > crates/ks-engine/src/lib.rs \
 && mkdir -p crates/ks-cli/src && echo "fn main() {}" > crates/ks-cli/src/main.rs

# 依赖缓存层 (仅当 Cargo.toml 变化时重建)
RUN cargo build --workspace 2>/dev/null || true

# 复制完整源码
COPY . .

# 默认: 编译 + 测试
CMD ["cargo", "test", "--workspace", "--", "--nocapture"]
