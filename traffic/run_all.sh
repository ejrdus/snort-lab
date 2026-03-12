#!/usr/bin/env bash
# ===================================================
#   통합 트래픽 실행 스크립트
#   연구용 실험 환경 - Snort 3 탐지 연구
# ===================================================
#
# 사용법:
#   bash run_all.sh                  # 기본 실행 (정상 50회 → 전체 공격)
#   bash run_all.sh --normal-only    # 정상 트래픽만 실행
#   bash run_all.sh --attack-only    # 공격 트래픽만 실행
#   bash run_all.sh --attack sqli    # 특정 공격 유형만 실행
#   NORMAL_COUNT=100 bash run_all.sh # 정상 트래픽 횟수 변경
# ===================================================

set -euo pipefail

# ─────────────────────────────────────────────
# 설정
# ─────────────────────────────────────────────
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
NORMAL_COUNT="${NORMAL_COUNT:-50}"
BRUTE_COUNT="${BRUTE_COUNT:-200}"
BRUTE_DELAY="${BRUTE_DELAY:-0.05}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="${PYTHON:-python3}"

NORMAL_ONLY=false
ATTACK_ONLY=false
ATTACK_TYPE="all"

# ─────────────────────────────────────────────
# 인자 파싱
# ─────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --normal-only) NORMAL_ONLY=true; shift ;;
        --attack-only) ATTACK_ONLY=true; shift ;;
        --attack)      ATTACK_TYPE="${2:-all}"; shift 2 ;;
        *) echo "알 수 없는 인자: $1"; exit 1 ;;
    esac
done

# ─────────────────────────────────────────────
# 유틸리티
# ─────────────────────────────────────────────
ts()      { date "+%H:%M:%S"; }
section() { echo; echo "══════════════════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════════════════"; }
info()    { echo "[$(ts)] [INFO] $1"; }
ok()      { echo "[$(ts)] [ OK ] $1"; }
fail()    { echo "[$(ts)] [FAIL] $1"; }

# ─────────────────────────────────────────────
# STEP 0: 서버 기동 확인
# ─────────────────────────────────────────────
check_server() {
    section "STEP 0: API 서버 연결 확인"
    local url="http://${HOST}:${PORT}/health"
    local retries=5

    for i in $(seq 1 $retries); do
        if curl -sf "$url" > /dev/null 2>&1; then
            ok "서버 응답 확인: $url"
            return 0
        fi
        info "서버 응답 없음. 재시도 $i/$retries ..."
        sleep 2
    done

    fail "서버에 연결할 수 없습니다."
    echo "  → API 서버를 먼저 실행하세요: cd api-server && python app.py"
    exit 1
}

# ─────────────────────────────────────────────
# STEP 1: 정상 트래픽
# ─────────────────────────────────────────────
run_normal() {
    section "STEP 1: 정상 트래픽 생성 (${NORMAL_COUNT}회)"
    "$PYTHON" "$SCRIPT_DIR/normal_traffic.py" \
        --host "$HOST" \
        --port "$PORT" \
        --count "$NORMAL_COUNT"
    ok "정상 트래픽 완료"
}

# ─────────────────────────────────────────────
# STEP 2: 공격 트래픽
# ─────────────────────────────────────────────
run_attack() {
    section "STEP 2: 공격 트래픽 생성 (유형: ${ATTACK_TYPE})"
    "$PYTHON" "$SCRIPT_DIR/attack_traffic.py" \
        --host "$HOST" \
        --port "$PORT" \
        --type "$ATTACK_TYPE" \
        --brute-count "$BRUTE_COUNT" \
        --brute-delay "$BRUTE_DELAY"
    ok "공격 트래픽 완료"
}

# ─────────────────────────────────────────────
# 메인 실행
# ─────────────────────────────────────────────
echo "══════════════════════════════════════════════════"
echo "  통합 트래픽 실행 스크립트"
echo "  대상 서버 : http://${HOST}:${PORT}"
echo "  정상 횟수 : ${NORMAL_COUNT}회"
echo "  공격 유형 : ${ATTACK_TYPE}"
echo "══════════════════════════════════════════════════"

START_TS=$(date +%s)

check_server

if $NORMAL_ONLY; then
    run_normal
elif $ATTACK_ONLY; then
    run_attack
else
    run_normal
    info "3초 후 공격 트래픽 시작..."
    sleep 3
    run_attack
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

section "완료"
ok "전체 실행 시간: ${ELAPSED}초"
echo "  로그 위치:"
echo "    API 요청 로그  → ${PROJECT_DIR}/api-server/logs/api_requests.log"
echo "    Snort 경보     → ${PROJECT_DIR}/logs/snort-alerts/"
echo ""
