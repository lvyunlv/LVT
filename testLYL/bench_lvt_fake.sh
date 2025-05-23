#!/usr/bin/env bash
set -euo pipefail

# 参数
FUNC_NAME=${1:-sigmoid}
FILE_FORMAT=${2:-txt}    # txt or bin
NET_CONF=${3:-""}        # 可选网络配置文件路径
PORT=23233
EXEC=../build/bin/test_lvt_fake
CACHE_DIR=../build/cache

# 参与方数量列表
PARTY_COUNTS=(2 4 8 16)

# 日志目录 & 合并日志文件
LOGDIR="./logs"
SUMMARY_LOG="${LOGDIR}/nonlinear_100000.log"
mkdir -p "${LOGDIR}"
: > "${SUMMARY_LOG}"

# 可执行文件检查
if [ ! -f "${EXEC}" ]; then
    echo "Error: Executable not found at ${EXEC}"
    exit 1
fi

clear_cache() {
    local func=$1
    rm -f "${CACHE_DIR}/lvt_fake_${func}_"*
}

for N in "${PARTY_COUNTS[@]}"; do
    echo "========== Testing with ${N} parties ==========" | tee -a "${SUMMARY_LOG}"

    PROCS=()
    # 启动所有参与方
    for (( i=1; i<=N; i++ )); do
        clear_cache "${FUNC_NAME}"

        CMD="${EXEC} ${i} ${PORT} ${N} ${FUNC_NAME} ${FILE_FORMAT}"
        [ -n "${NET_CONF}" ] && CMD+=" ${NET_CONF}"

        if [ "${i}" -eq 1 ]; then
            # 参与方1 的输出，先写入临时文件
            TMPLOG="${LOGDIR}/party1_n${N}.log"
            echo " Launching Party 1: ${CMD}" | tee -a "${SUMMARY_LOG}"
            ${CMD} > "${TMPLOG}" 2>&1 &
        else
            # 其他参与方，静默运行
            ${CMD} &
        fi
        PROCS+=($!)
    done

    # 等待所有参与方结束
    for pid in "${PROCS[@]}"; do
        wait "${pid}"
    done

    # 提取 Party 1 的 Offline/Online 时间到合并日志
    {
        echo "----- Results for N=${N} (Party 1) -----"
        grep -E "Offline time|Online time" "${TMPLOG}"
        echo ""
    } >> "${SUMMARY_LOG}"
done

echo "ALL TESTS COMPLETE. Summary in ${SUMMARY_LOG}"
