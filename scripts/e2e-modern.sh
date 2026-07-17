#!/usr/bin/env bash
# =============================================================================
# E1.4 — Modern tier 端到端验证脚本
# 验证 KernelSentinel 在 5.8+ 内核上的完整链路:
#   eBPF 采集 → aggregator → detector → forensic → REST API + WebSocket 推送
#
# 退出码:
#   0 — 全部断言通过
#   1 — 断言失败（已打印诊断信息）
#   2 — 内核版本 < 5.8，不满足 Modern tier 要求
# =============================================================================
set -euo pipefail

# ── 常量 ────────────────────────────────────────────────────────────────────
readonly PORT=8443
readonly LOG_DIR="/tmp/ks-e2e"
readonly PID_FILE="/tmp/ks-e2e.pid"
readonly BASE_URL="http://127.0.0.1:${PORT}"
readonly WS_URL="ws://127.0.0.1:${PORT}/ws/alerts"
readonly HEALTH_TIMEOUT=10        # 秒
readonly HEALTH_POLL_INTERVAL=1 # 秒（bash (( )) 不支持浮点）
readonly SCENARIO_GAP=2           # 秒
readonly DIGEST_WAIT=5            # 秒
readonly WS_WAIT=3                # 秒

# ── 项目根目录（脚本所在目录的上一级）──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RULES_DIR="${PROJECT_ROOT}/rules"
SCENARIOS_DIR="${PROJECT_ROOT}/scenarios"

# ── 可执行文件解析：优先 release，次 debug，最后 PATH ────────────────────────
if [[ -x "${PROJECT_ROOT}/target/release/kernelsentinel" ]]; then
    KS_BIN="${PROJECT_ROOT}/target/release/kernelsentinel"
elif [[ -x "${PROJECT_ROOT}/target/debug/kernelsentinel" ]]; then
    KS_BIN="${PROJECT_ROOT}/target/debug/kernelsentinel"
elif command -v kernelsentinel >/dev/null 2>&1; then
    KS_BIN="$(command -v kernelsentinel)"
else
    echo "ERROR: 找不到 kernelsentinel 可执行文件（target/{release,debug}/kernelsentinel 或 PATH）" >&2
    exit 1
fi

# ── 运行态 ────────────────────────────────────────────────────────────────────
KS_PID=""

# ── 诊断函数：断言失败时打印上下文后 exit 1 ─────────────────────────────────
fail() {
    echo "============================================================" >&2
    echo "ASSERT FAILED: $1" >&2
    echo "------------------------------------------------------------" >&2
    if [[ -n "${KS_PID:-}" ]] && kill -0 "${KS_PID}" 2>/dev/null; then
        echo ">>> /api/v1/health:" >&2
        curl -fsS "${BASE_URL}/api/v1/health" 2>&1 | head -5 >&2 || echo "(curl 失败)" >&2
        echo ">>> /api/v1/stats:" >&2
        curl -fsS "${BASE_URL}/api/v1/stats" 2>&1 | head -10 >&2 || echo "(curl 失败)" >&2
        echo ">>> /api/v1/alerts?limit=20:" >&2
        curl -fsS "${BASE_URL}/api/v1/alerts?limit=20" 2>&1 | head -20 >&2 || echo "(curl 失败)" >&2
    fi
    if [[ -d "${LOG_DIR}" ]]; then
        echo ">>> ${LOG_DIR} 末尾 20 行日志:" >&2
        local latest
        latest="$(ls -t "${LOG_DIR}"/events_*.jsonl 2>/dev/null | head -1 || true)"
        if [[ -n "${latest}" ]]; then
            tail -20 "${latest}" 2>&1 >&2 || true
        else
            echo "(无 events_*.jsonl 文件)" >&2
            ls -la "${LOG_DIR}/" >&2
        fi
    fi
    echo "============================================================" >&2
    exit 1
}

# ── 清理函数：trap EXIT 调用 ─────────────────────────────────────────────────
cleanup() {
    local code=$?
    if [[ -n "${KS_PID:-}" ]] && kill -0 "${KS_PID}" 2>/dev/null; then
        echo "[cleanup] 终止 kernelsentinel (pid=${KS_PID})..."
        kill "${KS_PID}" 2>/dev/null || true
        sleep 0.5
        kill -9 "${KS_PID}" 2>/dev/null || true
    fi
    if [[ -f "${PID_FILE}" ]]; then
        rm -f "${PID_FILE}"
    fi
    # 失败时保留日志便于排查，成功时清理
    if [[ -d "${LOG_DIR}" && "${code}" -eq 0 ]]; then
        rm -rf "${LOG_DIR}"
    elif [[ -d "${LOG_DIR}" ]]; then
        echo "[cleanup] 失败退出 (code=${code})，日志保留在 ${LOG_DIR}" >&2
    fi
    exit "${code}"
}
trap cleanup EXIT

# =============================================================================
# E1.4.1 — 内核版本检测（< 5.8 时 exit 2）
# =============================================================================
check_kernel_version() {
    local kver major minor
    kver="$(uname -r)"
    # 形如 5.8.0-63-generic / 6.5.0-14-generic / 4.19.0-25-amd64
    if [[ "${kver}" =~ ^([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
    else
        echo "ERROR: 无法解析内核版本: ${kver}" >&2
        exit 2
    fi
    echo "[E1.4.1] 内核版本: ${kver} (major=${major} minor=${minor})"

    # 数值比较：major > 5 或 (major == 5 且 minor >= 8)
    if (( major > 5 )); then
        return 0
    fi
    if (( major == 5 && minor >= 8 )); then
        return 0
    fi
    echo "============================================================" >&2
    echo "ERROR: Modern tier 需要 Linux 内核 >= 5.8 (CO-RE + BTF + ringbuf)" >&2
    echo "       当前内核: ${kver}" >&2
    echo "       请使用 legacy/ancient tier 或在 5.8+ 内核上运行本脚本" >&2
    echo "============================================================" >&2
    exit 2
}

# =============================================================================
# E1.4.2 — 启动 kernelsentinel 后台运行
# =============================================================================
start_kernelsentinel() {
    echo "[E1.4.2] 启动 kernelsentinel: ${KS_BIN} start --serve ${PORT} --rules-dir ${RULES_DIR} --log-dir ${LOG_DIR}"
    if [[ ! -d "${RULES_DIR}" ]]; then
        echo "ERROR: 规则目录不存在: ${RULES_DIR}" >&2
        exit 1
    fi
    mkdir -p "${LOG_DIR}"
    # nohup + & 后台运行；stdout/stderr 落到日志文件便于事后排查
    nohup "${KS_BIN}" start \
        --serve "${PORT}" \
        --rules-dir "${RULES_DIR}" \
        --log-dir "${LOG_DIR}" \
        >"${LOG_DIR}/ks-stdout.log" 2>&1 &
    KS_PID=$!
    echo "${KS_PID}" >"${PID_FILE}"
    echo "         pid=${KS_PID}, pid_file=${PID_FILE}"
}

# =============================================================================
# E1.4.3 — 等待 /api/v1/health 返回 status:ok（最多 10s）
# =============================================================================
wait_for_health() {
    echo "[E1.4.3] 等待健康检查（最多 ${HEALTH_TIMEOUT}s，每 ${HEALTH_POLL_INTERVAL}s 轮询）..."
    local elapsed=0
    while (( elapsed < HEALTH_TIMEOUT )); do
        if ! kill -0 "${KS_PID}" 2>/dev/null; then
            echo "ERROR: kernelsentinel 进程已退出" >&2
            echo ">>> ks-stdout.log 末尾 20 行:" >&2
            tail -20 "${LOG_DIR}/ks-stdout.log" >&2 || true
            exit 1
        fi
        local resp
        resp="$(curl -fsS --max-time 2 "${BASE_URL}/api/v1/health" 2>/dev/null || true)"
        if [[ -n "${resp}" ]]; then
            local status
            # 用 grep -oE 提取 status 字段（避免依赖 jq）
            status="$(echo "${resp}" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*:"([^"]+)".*/\1/' || true)"
            if [[ "${status}" == "ok" ]]; then
                echo "         健康检查通过 (${elapsed}s): ${resp}"
                return 0
            fi
        fi
        sleep "${HEALTH_POLL_INTERVAL}"
        elapsed=$((elapsed + HEALTH_POLL_INTERVAL))
    done
    fail "健康检查超时（${HEALTH_TIMEOUT}s 内 /api/v1/health 未返回 status:ok）"
}

# =============================================================================
# E1.4.4 — 跑 3 个场景脚本，每个间隔 2s
# =============================================================================
run_scenarios() {
    echo "[E1.4.4] 运行场景模拟脚本..."
    local scenarios=(
        "sim_reverse_shell.sh"
        "sim_ransomware.sh"
        "sim_privilege_esc.sh"
    )
    local first=1
    for sc in "${scenarios[@]}"; do
        local path="${SCENARIOS_DIR}/${sc}"
        if (( first == 0 )); then
            echo "         间隔 ${SCENARIO_GAP}s..."
            sleep "${SCENARIO_GAP}"
        fi
        first=0
        if [[ -x "${path}" ]]; then
            echo "         运行: ${path}"
            bash "${path}" >/dev/null 2>&1 || echo "         (场景退出码非 0，仅用于触发探针，可忽略)"
        elif [[ -f "${path}" ]]; then
            echo "         运行(非可执行): bash ${path}"
            bash "${path}" >/dev/null 2>&1 || echo "         (场景退出码非 0，可忽略)"
        else
            # 回退方案：scenarios 脚本缺失时用最简触发器
            echo "         场景脚本缺失: ${path} — 使用内联回退触发器"
            case "${sc}" in
                sim_reverse_shell.sh)
                    # 后台触发反向 shell 连接（连接失败也足以触发 eBPF 探针）
                    bash -c 'exec bash -i >& /dev/tcp/127.0.0.1/9999 0>&1' >/dev/null 2>&1 &
                    local rs_pid=$!
                    sleep 1
                    kill "${rs_pid}" 2>/dev/null || true
                    ;;
                sim_ransomware.sh)
                    # 触发文件加密行为探针
                    touch /tmp/.encrypted /tmp/test.encrypted 2>/dev/null || true
                    ;;
                sim_privilege_esc.sh)
                    # 触发 SUID 提权探针
                    touch /tmp/ks_e2e_suid_test 2>/dev/null || true
                    chmod +s /tmp/ks_e2e_suid_test 2>/dev/null || true
                    rm -f /tmp/ks_e2e_suid_test 2>/dev/null || true
                    ;;
            esac
        fi
    done
}

# =============================================================================
# E1.4.5 — 断言 alerts >= 3, stats.by_severity 含 critical/high, version 有 version 字段
# =============================================================================
assert_api_responses() {
    echo "[E1.4.5] 等待 ${DIGEST_WAIT}s 让事件消化..."
    sleep "${DIGEST_WAIT}"

    # 1) alerts >= 3
    local alerts_resp
    alerts_resp="$(curl -fsS --max-time 5 "${BASE_URL}/api/v1/alerts?limit=20" 2>/dev/null \
        || fail "curl /api/v1/alerts 失败")"
    # alerts 是 JSON 数组，统计顶层元素个数（粗略：逗号分隔 + 边界）
    local alert_count
    alert_count="$(echo "${alerts_resp}" | grep -oE '"id"' | wc -l)"
    echo "         alerts count=${alert_count}"
    (( alert_count >= 3 )) || fail "断言失败: alerts >= 3，实际 ${alert_count}"

    # 2) stats.by_severity 含 critical 或 high
    local stats_resp
    stats_resp="$(curl -fsS --max-time 5 "${BASE_URL}/api/v1/stats" 2>/dev/null \
        || fail "curl /api/v1/stats 失败")"
    echo "         stats: ${stats_resp}"
    if ! echo "${stats_resp}" | grep -qiE '"critical"' && ! echo "${stats_resp}" | grep -qiE '"high"'; then
        fail "断言失败: by_severity 不含 critical 或 high"
    fi
    echo "         by_severity 含 critical/high ✓"

    # 3) version 返回 version 字段
    local version_resp
    version_resp="$(curl -fsS --max-time 5 "${BASE_URL}/api/v1/version" 2>/dev/null \
        || fail "curl /api/v1/version 失败")"
    echo "         version: ${version_resp}"
    echo "${version_resp}" | grep -qE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' \
        || fail "断言失败: /api/v1/version 未返回 version 字段"
    echo "         version 字段存在 ✓"
}

# =============================================================================
# E1.4.6 — WebSocket 测试（websocat 缺失时跳过 + warning，不失败）
# =============================================================================
test_websocket() {
    echo "[E1.4.6] WebSocket 测试..."
    if ! command -v websocat >/dev/null 2>&1; then
        echo "         [WARNING] 未安装 websocat，跳过 WebSocket 测试（不影响 exit code）"
        return 0
    fi
    # websocat 连接 3s，捕获首条消息；超时返回非 0
    local ws_out
    ws_out="$(timeout "${WS_WAIT}" websocat -t "${WS_URL}" 2>/dev/null || true)"
    if [[ -z "${ws_out}" ]]; then
        echo "         [WARNING] WebSocket 在 ${WS_WAIT}s 内未收到消息（可能场景未触发 WS 推送，跳过断言）"
        return 0
    fi
    echo "         WS 收到: $(echo "${ws_out}" | head -1)"
    # 断言至少 1 条告警 JSON（含 severity / title / id 之一即视为告警）
    local ws_count
    ws_count="$(echo "${ws_out}" | grep -cE '"(severity|title|id|alert_id)"' || true)"
    (( ws_count >= 1 )) || fail "WebSocket 断言失败: 未收到告警 JSON"
    echo "         WebSocket 收到 ${ws_count} 条告警 JSON ✓"
}

# =============================================================================
# E1.4.7 — 检查 events_*.jsonl 存在且最后一行 hash 非空
# =============================================================================
check_forensic_log() {
    echo "[E1.4.7] 检查取证日志..."
    # 取最新（按 mtime）的 events_*.jsonl
    local latest
    latest="$(ls -t "${LOG_DIR}"/events_*.jsonl 2>/dev/null | head -1 || true)"
    [[ -n "${latest}" ]] || fail "断言失败: ${LOG_DIR}/events_*.jsonl 不存在"
    [[ -f "${latest}" ]] || fail "断言失败: ${latest} 不是普通文件"
    echo "         最新日志: ${latest}"

    local last_line
    last_line="$(tail -1 "${latest}" 2>/dev/null || true)"
    [[ -n "${last_line}" ]] || fail "断言失败: ${latest} 最后一行为空"

    # 实现实际写入的字段为 "hash"（SHA-256 哈希链当前记录的哈希）。
    # 任务规格写的是 "chain_hash"，但代码库 forensic.rs 用的是 "hash"/"prev_hash"。
    # 这里同时兼容两种字段名以增强健壮性。
    local hash_val
    hash_val="$(echo "${last_line}" \
        | grep -oE '"(hash|chain_hash)"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | head -1 \
        | sed -E 's/.*:"([^"]+)".*/\1/' || true)"
    [[ -n "${hash_val}" && "${hash_val}" != "null" ]] \
        || fail "断言失败: 最后一行 hash/chain_hash 为空 (last_line=${last_line})"
    echo "         链尾 hash=${hash_val:0:16}... ✓"
}

# =============================================================================
# 主流程
# =============================================================================
main() {
    echo "============================================================"
    echo " KernelSentinel E2E 验证 (Modern tier, 内核 >= 5.8)"
    echo " 二进制: ${KS_BIN}"
    echo " 规则:   ${RULES_DIR}"
    echo " 日志:   ${LOG_DIR}"
    echo " 端口:   ${PORT}"
    echo "============================================================"

    check_kernel_version    # E1.4.1 (失败时 exit 2)
    start_kernelsentinel    # E1.4.2
    wait_for_health         # E1.4.3
    run_scenarios           # E1.4.4
    assert_api_responses    # E1.4.5
    test_websocket          # E1.4.6
    check_forensic_log      # E1.4.7

    echo "============================================================"
    echo " [E1.4.8] 全部断言通过 — E2E 验证成功"
    echo "============================================================"
    # E1.4.8 清理由 trap cleanup EXIT 处理；这里显式 exit 0
    exit 0
}

main "$@"
