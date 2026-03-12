"""
===================================================
  정상 트래픽 생성기 (Normal Traffic Generator)
  연구용 실험 환경 - Snort 3 탐지 연구
===================================================

실행 방법:
  python normal_traffic.py               # 기본 실행 (50회, 무제한 시간)
  python normal_traffic.py --count 100   # 요청 횟수 지정
  python normal_traffic.py --duration 30 # 실행 시간(초) 지정
  python normal_traffic.py --host 127.0.0.1 --port 5000

설명:
  실제 인터넷뱅킹 사용자의 행동 패턴을 모방하여
  정상 트래픽의 기준선(baseline)을 생성한다.
  Snort 규칙 오탐(False Positive) 검증에 사용된다.
"""

import argparse
import random
import time
import json
import sys
import datetime
import requests


# ─────────────────────────────────────────────
# 정상 사용자 데이터 (모의)
# ─────────────────────────────────────────────
NORMAL_ACCOUNTS = [
    "111-22-333333",
    "444-55-666666",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

TRANSFER_MEMOS = ["월세", "공과금", "식비", "교통비", "의류", "의료비", "용돈", "회비", "선물", "저축"]


# ─────────────────────────────────────────────
# 공통 유틸리티
# ─────────────────────────────────────────────
def get_headers():
    """랜덤 정상 User-Agent 헤더 반환."""
    return {
        "User-Agent": random.choice(NORMAL_USER_AGENTS),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def log(label: str, status: int, detail: str = ""):
    """콘솔 로그 출력."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    mark = "O" if status == 200 else "X"
    print(f"[{ts}] [{mark}] {label:<30} status={status}  {detail}")


# ─────────────────────────────────────────────
# 시나리오 1 - 계좌 조회 (GET /api/account)
# ─────────────────────────────────────────────
def scenario_account_query(base_url: str) -> bool:
    """정상 계좌 조회 요청."""
    account_no = random.choice(NORMAL_ACCOUNTS)
    try:
        resp = requests.get(
            f"{base_url}/api/account",
            params={"account_no": account_no},
            headers=get_headers(),
            timeout=5,
        )
        log("GET /api/account", resp.status_code, f"account_no={account_no}")
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"  [ERR] account_query: {e}")
        return False


# ─────────────────────────────────────────────
# 시나리오 2 - 소액 이체 (POST /api/transfer)
# ─────────────────────────────────────────────
def scenario_small_transfer(base_url: str) -> bool:
    """정상 소액 이체 요청 (1만 ~ 50만 원)."""
    from_acc, to_acc = random.sample(NORMAL_ACCOUNTS, 2)
    amount = random.randint(10_000, 500_000)
    memo = random.choice(TRANSFER_MEMOS)
    payload = {
        "from_account": from_acc,
        "to_account": to_acc,
        "amount": amount,
        "memo": memo,
    }
    try:
        resp = requests.post(
            f"{base_url}/api/transfer",
            headers=get_headers(),
            json=payload,
            timeout=5,
        )
        log("POST /api/transfer", resp.status_code, f"amount={amount:,} memo={memo}")
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"  [ERR] small_transfer: {e}")
        return False


# ─────────────────────────────────────────────
# 시나리오 3 - 헬스체크 (GET /health)
# ─────────────────────────────────────────────
def scenario_health_check(base_url: str) -> bool:
    """모니터링 시스템이 주기적으로 호출하는 헬스체크."""
    try:
        resp = requests.get(
            f"{base_url}/health",
            headers=get_headers(),
            timeout=5,
        )
        log("GET /health", resp.status_code)
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"  [ERR] health_check: {e}")
        return False


# ─────────────────────────────────────────────
# 시나리오 선택 가중치 (실제 사용 패턴 반영)
#   계좌 조회  60%, 소액 이체  30%, 헬스체크 10%
# ─────────────────────────────────────────────
SCENARIOS = [
    (scenario_account_query, 60),
    (scenario_small_transfer, 30),
    (scenario_health_check, 10),
]


def pick_scenario():
    """가중치 기반으로 시나리오 하나 선택."""
    funcs, weights = zip(*SCENARIOS)
    return random.choices(funcs, weights=weights, k=1)[0]


# ─────────────────────────────────────────────
# 서버 기동 확인
# ─────────────────────────────────────────────
def wait_for_server(base_url: str, retries: int = 5):
    """서버가 응답할 때까지 재시도."""
    for i in range(retries):
        try:
            resp = requests.get(f"{base_url}/health", timeout=3)
            if resp.status_code == 200:
                print(f"  서버 연결 확인: {base_url}")
                return True
        except requests.RequestException:
            pass
        print(f"  서버 응답 없음. 재시도 {i+1}/{retries} ...")
        time.sleep(2)
    return False


# ─────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────
def main():
    """
    CLI 진입점. 인자를 파싱하고 정상 트래픽 생성 루프를 실행한다.

    종료 조건 (둘 중 먼저 도달하는 조건에서 중단):
        --count    : 지정한 횟수만큼 요청을 보내면 종료 (0이면 무제한)
        --duration : 지정한 시간(초)이 경과하면 종료 (0이면 무제한)

    각 요청은 SCENARIOS 가중치에 따라 무작위로 선택되며,
    --delay-min ~ --delay-max 범위의 랜덤 간격으로 전송된다.
    서버 연결에 실패하면 즉시 종료(exit code 1)하고,
    KeyboardInterrupt(Ctrl+C)로 언제든지 중단할 수 있다.
    완료 후 총 요청 수, 성공/실패 횟수, 경과 시간을 출력한다.
    """
    parser = argparse.ArgumentParser(description="정상 트래픽 생성기")
    parser.add_argument("--host", default="127.0.0.1", help="API 서버 호스트")
    parser.add_argument("--port", default=5000, type=int, help="API 서버 포트")
    parser.add_argument("--count", default=50, type=int, help="총 요청 횟수 (0=무제한)")
    parser.add_argument("--duration", default=0, type=int, help="실행 시간(초) (0=무제한)")
    parser.add_argument("--delay-min", default=0.5, type=float, help="요청 간 최소 딜레이(초)")
    parser.add_argument("--delay-max", default=2.0, type=float, help="요청 간 최대 딜레이(초)")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"

    print("=" * 55)
    print("  정상 트래픽 생성기 시작")
    print(f"  대상 서버  : {base_url}")
    print(f"  요청 횟수  : {args.count if args.count else '무제한'}")
    print(f"  실행 시간  : {args.duration}초" if args.duration else "  실행 시간  : 무제한")
    print(f"  딜레이     : {args.delay_min}~{args.delay_max}초")
    print("=" * 55)

    if not wait_for_server(base_url):
        print("[FAIL] 서버에 연결할 수 없습니다. API 서버를 먼저 실행하세요.")
        sys.exit(1)

    success = 0
    fail = 0
    count = 0
    start_time = time.time()

    try:
        while True:
            # 종료 조건 확인
            if args.count and count >= args.count:
                break
            if args.duration and (time.time() - start_time) >= args.duration:
                break

            scenario = pick_scenario()
            ok = scenario(base_url)
            if ok:
                success += 1
            else:
                fail += 1
            count += 1

            delay = random.uniform(args.delay_min, args.delay_max)
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n  사용자에 의해 중단됨.")

    elapsed = time.time() - start_time
    print("\n" + "=" * 55)
    print(f"  완료: 총 {count}회 요청 | 성공 {success} | 실패 {fail} | 경과 {elapsed:.1f}초")
    print("=" * 55)


if __name__ == "__main__":
    main()
