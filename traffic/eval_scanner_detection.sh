#!/usr/bin/env bash
set -euo pipefail

# 목적:
# 1) attack_traffic.py로 공격 트래픽 전송
# 2) scanner_only.rules 기반 Snort 탐지 건수 집계
# 3) 룰 매칭된 Snort 탐지 로그만 attack_log.txt에 누적 기록
# 4) 전송 건수 대비 탐지율(TPR) 출력

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACK_PY="${PROJECT_DIR}/traffic/attack_traffic.py"
ATTACK_LOG="${PROJECT_DIR}/attack_log.txt"
RULE_FILE="${RULE_FILE:-${PROJECT_DIR}/snort/rules/local_v3.rules}"
SNORT_CONF="/usr/local/etc/snort/snort.lua"
SNORT_BIN="/usr/local/bin/snort"

TYPE="${TYPE:-scan}"
COUNT="${COUNT:-100}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"

if [[ "${TYPE}" != "scan" ]]; then
  echo "[WARN] scanner UA 검증은 TYPE=scan 권장"
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${PROJECT_DIR}/logs/eval_${TYPE}_${timestamp}"
SNORT_DIR="${RUN_DIR}/snort"
mkdir -p "${SNORT_DIR}"

echo "=================================================="
echo "  Scanner 탐지 성능 검증 시작"
echo "  TYPE=${TYPE}, COUNT=${COUNT}"
echo "  ATTACK_LOG=${ATTACK_LOG}"
echo "  RUN_DIR=${RUN_DIR}"
echo "=================================================="

if [[ ! -f "${RULE_FILE}" ]]; then
  echo "[FAIL] rule file not found: ${RULE_FILE}"
  exit 1
fi

if [[ ! -x "${SNORT_BIN}" ]]; then
  echo "[FAIL] snort binary not found: ${SNORT_BIN}"
  exit 1
fi

if [[ ! -f "${ATTACK_PY}" ]]; then
  echo "[FAIL] attack script not found: ${ATTACK_PY}"
  exit 1
fi

# Snort 백그라운드 실행 (lo 인터페이스 실시간 캡처)
# 권한 문제를 피하려면 필요시 sudo로 실행.
if [[ "${EUID}" -eq 0 ]]; then
  SNORT_CMD=("${SNORT_BIN}" -q -c "${SNORT_CONF}" -R "${RULE_FILE}" -i lo -A alert_fast -l "${SNORT_DIR}")
else
  SNORT_CMD=(sudo "${SNORT_BIN}" -q -c "${SNORT_CONF}" -R "${RULE_FILE}" -i lo -A alert_fast -l "${SNORT_DIR}")
fi

echo "[INFO] starting snort..."
"${SNORT_CMD[@]}" >/dev/null 2>"${RUN_DIR}/snort.stderr" &
SNORT_PID=$!
sleep 1

cleanup() {
  if ps -p "${SNORT_PID}" >/dev/null 2>&1; then
    kill -INT "${SNORT_PID}" >/dev/null 2>&1 || true
    wait "${SNORT_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[INFO] sending attack traffic ..."

ATTACK_RUN_LOG="${RUN_DIR}/attack_run.log"
python3 "${ATTACK_PY}" --host "${HOST}" --port "${PORT}" --type "${TYPE}" --scan-count "${COUNT}" \
  | tee "${ATTACK_RUN_LOG}" >/dev/null

# Snort 종료 및 로그 flush
cleanup
trap - EXIT

ALERT_FILE="${SNORT_DIR}/alert_fast.txt"
if [[ ! -f "${ALERT_FILE}" ]]; then
  echo "[FAIL] snort alert file not found: ${ALERT_FILE}"
  echo "       (권한/인터페이스 문제 가능: snort.stderr 확인)"
  exit 1
fi

sent_count="$(rg -n '\[ATK\]' "${ATTACK_RUN_LOG}" | wc -l | tr -d ' ')"
detect_count="$(rg -n '1:1000004:' "${ALERT_FILE}" | wc -l | tr -d ' ')"

# attack_log.txt에는 Snort alert 원문 라인만 기록 (기존 포맷 유지)
cat "${ALERT_FILE}" >> "${ATTACK_LOG}"

tp="${detect_count}"
if (( tp > sent_count )); then
  tp="${sent_count}"
fi

if (( sent_count > 0 )); then
  tpr="$(awk -v tp="${tp}" -v s="${sent_count}" 'BEGIN { printf "%.2f", (tp/s)*100 }')"
else
  tpr="0.00"
fi

dup=0
if (( detect_count > sent_count )); then
  dup=$((detect_count - sent_count))
fi

echo ""
echo "================= 결과 요약 ================="
echo "전송 건수(attack run 기준): ${sent_count}"
echo "탐지 건수(sid:1000004):    ${detect_count}"
echo "중복 알림:                 ${dup}"
echo "TPR(최대 100% 제한):       ${tpr}%"
echo "attack 로그 파일(탐지만):   ${ATTACK_LOG}"
echo "snort alert 파일:          ${ALERT_FILE}"
echo "============================================="
