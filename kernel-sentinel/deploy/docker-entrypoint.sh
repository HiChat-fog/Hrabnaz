#!/bin/bash
# ==========================================================================
# KernelSentinel Docker Entrypoint
# ==========================================================================
# 职责:
#   1. 前置检查: /sys/fs/bpf 挂载、CAP_BPF 能力
#   2. 设置信号陷阱，优雅退出
#   3. exec 启动 kernelsentinel start (替换为 PID 1，由 tokio::signal 处理 SIGTERM)
#
# 调用: CMD 透传，例如
#   CMD ["--serve", "8080", "--rules-dir", "/etc/kernelsentinel/rules"]
#   => exec kernelsentinel start --serve 8080 --rules-dir /etc/kernelsentinel/rules
# ==========================================================================
set -euo pipefail

KS_BIN="${KS_BIN:-/usr/local/bin/kernelsentinel}"

log() { echo "[entrypoint] $*"; }
warn() { echo "[entrypoint] WARN: $*" >&2; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# ── 1. /sys/fs/bpf 挂载检查 ──
# eBPF map 创建/挂载依赖 bpffs，未挂载则 aya 加载必然失败
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    die "/sys/fs/bpf 未挂载 (bpffs)，无法加载 eBPF。请以 --privileged 运行并挂载 -v /sys/fs/bpf:/sys/fs/bpf"
fi
log "/sys/fs/bpf 已挂载 (bpffs 就绪)"

# ── 2. 能力检查 (CAP_BPF / CAP_SYS_ADMIN) ──
# 容器以 privileged 运行时具备全部能力；非 privileged 需显式 cap_add
if command -v capsh >/dev/null 2>&1; then
    if capsh --print 2>/dev/null | grep -qiE 'cap_bpf|cap_sys_admin'; then
        log "能力检查通过 (CAP_BPF 或 CAP_SYS_ADMIN 可用)"
    else
        warn "CAP_BPF / CAP_SYS_ADMIN 未检测到，eBPF 加载可能失败 (建议 --privileged 或 cap_add CAP_BPF)"
    fi
else
    warn "capsh 不可用，跳过能力检查 (请确保容器具备 CAP_BPF)"
fi

# ── 3. /proc 检查 ──
if [[ ! -d /proc/1 ]]; then
    die "/proc 未挂载，探针无法读取进程信息。请挂载 -v /proc:/proc"
fi

# ── 4. 信号陷阱 (exec 前短暂窗口 + 兜底) ──
# 注: exec 后本 shell 被替换，信号由 kernelsentinel (tokio::signal) 直接处理，
#     实现 docker stop 时的优雅退出。此处 trap 主要覆盖 exec 前的检查阶段。
graceful() {
    log "收到终止信号，正在退出..."
    # 若已 exec，此处不会执行；若在检查阶段，直接退出
    exit 0
}
trap graceful SIGTERM SIGINT

log "启动 kernelsentinel: $KS_BIN start $*"
log "  (PID 1 将由 kernelsentinel 接管，docker stop 触发 SIGTERM 由 tokio 优雅处理)"

# exec 替换为 PID 1，直接接收 Docker 发来的 SIGTERM/SIGINT
exec "$KS_BIN" start "$@"
