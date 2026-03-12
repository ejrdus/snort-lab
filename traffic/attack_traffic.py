"""
===================================================
  공격 트래픽 생성기 (Attack Traffic Generator)
  연구용 실험 환경 - Snort 3 탐지 연구
===================================================

실행 방법:
  python attack_traffic.py               # 전체 공격 유형 순서대로 실행
  python attack_traffic.py --type sqli   # SQL Injection만 실행
  python attack_traffic.py --type hta    # 고액 이체만 실행
  python attack_traffic.py --type brute  # Brute Force만 실행
  python attack_traffic.py --type scan   # 스캐너 UA만 실행
  python attack_traffic.py --host 127.0.0.1 --port 5000

공격 유형:
  sqli  - SQL Injection (GET /api/account, http_uri 매칭)
  hta   - 고액 이체 (POST /api/transfer, http_client_body 매칭)
  brute - Brute Force (POST /api/transfer 고속 반복, detection_filter)
  scan  - 의심 User-Agent / 스캐너 모방 (http_header 매칭)

주의:
  본 스크립트는 Snort 3 탐지 규칙 연구 목적으로만 사용한다.
  반드시 허가된 실험 환경(localhost)에서만 실행할 것.
"""

import argparse
import time
import sys
import datetime
import requests


BASE_URL = "http://127.0.0.1:5000"


# ─────────────────────────────────────────────
# 공통 유틸리티
# ─────────────────────────────────────────────
def log(label: str, status: int, detail: str = ""):
    """
    공격 요청 결과를 타임스탬프와 함께 콘솔에 출력한다.

    Args:
        label  : 요청을 설명하는 짧은 레이블 (예: "GET /api/account [SQLi]")
        status : HTTP 응답 상태 코드
        detail : 추가로 표시할 정보 (선택, 기본값 빈 문자열)
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [ATK] {label:<35} status={status}  {detail}")


def section(title: str):
    """
    공격 유형 구분선과 제목을 콘솔에 출력한다.
    각 공격 단계의 시작을 시각적으로 구분하기 위해 사용한다.

    Args:
        title : 출력할 섹션 제목
    """
    print()
    print("─" * 55)
    print(f"  {title}")
    print("─" * 55)


def wait_for_server(base_url: str):
    """
    API 서버가 정상 기동 중인지 헬스체크 엔드포인트로 확인한다.
    서버가 응답하지 않으면 False를 반환하고, 공격 실행을 중단시킨다.

    Args:
        base_url : 확인할 서버의 베이스 URL (예: "http://127.0.0.1:5000")

    Returns:
        bool : 서버가 200 OK를 반환하면 True, 그렇지 않으면 False
    """
    try:
        resp = requests.get(f"{base_url}/health", timeout=3)
        if resp.status_code == 200:
            print(f"  서버 연결 확인: {base_url}")
            return True
    except requests.RequestException:
        pass
    return False


# ─────────────────────────────────────────────
# 공격 유형 1 - SQL Injection
#   대상: GET /api/account?account_no=<payload>
#   Snort 키워드: http_uri, content
# ─────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "111' AND 1=1--",
    "111' AND 1=2--",
    "' OR 1=1#",
    "' DROP TABLE accounts--",
    "' INSERT INTO accounts VALUES('hack')--",
    "1; SELECT * FROM users",
    "' OR 'x'='x",
    "\" OR \"1\"=\"1",
]


def attack_sqli(base_url: str, count: int = 12):
    """
    SQL Injection 공격을 시뮬레이션한다.

    SQLI_PAYLOADS 목록에서 페이로드를 순서대로 꺼내
    GET /api/account?account_no=<payload> 형태로 요청을 전송한다.
    Snort 규칙의 http_uri / content 키워드 매칭 여부를 검증하는 데 사용된다.

    Args:
        base_url : 요청을 보낼 서버의 베이스 URL
        count    : 전송할 페이로드 개수 (기본값 12, 목록 길이 이하로 제한됨)
    """
    section("공격 유형 1: SQL Injection (GET /api/account)")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json",
    }
    for i, payload in enumerate(SQLI_PAYLOADS[:count]):
        try:
            resp = requests.get(
                f"{base_url}/api/account",
                params={"account_no": payload},
                headers=headers,
                timeout=5,
            )
            log("GET /api/account [SQLi]", resp.status_code, f"payload={repr(payload)}")
        except requests.RequestException as e:
            print(f"  [ERR] {e}")
        time.sleep(0.3)


# ─────────────────────────────────────────────
# 공격 유형 2 - 비정상 고액 이체
#   대상: POST /api/transfer
#   Snort 키워드: http_client_body, content
# ─────────────────────────────="────────────
HTA_CASES = [
    {"from_account": "111-22-333333", "to_account": "999-99-999999", "amount": 999_999_999, "memo": ""},
    {"from_account": "111-22-333333", "to_account": "000-00-000000", "amount": 500_000_000, "memo": "urgent"},
    {"from_account": "444-55-666666", "to_account": "999-99-999999", "amount": 1_000_000_000, "memo": "wire"},
    {"from_account": "111-22-333333", "to_account": "123-45-678901", "amount": 750_000_000, "memo": ""},
    {"from_account": "444-55-666666", "to_account": "987-65-432100", "amount": 999_000_000, "memo": "transfer"},
]


def attack_high_transfer(base_url: str):
    """
    비정상 고액 이체 공격을 시뮬레이션한다.

    HTA_CASES에 정의된 5억~10억 원 규모의 이체 요청을
    POST /api/transfer 엔드포인트로 전송한다.
    Snort 규칙의 http_client_body / content 키워드 매칭 여부를 검증하는 데 사용된다.

    Args:
        base_url : 요청을 보낼 서버의 베이스 URL
    """
    section("공격 유형 2: 고액 이체 (POST /api/transfer)")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
        "Content-Type": "application/json",
    }
    for case in HTA_CASES:
        try:
            resp = requests.post(
                f"{base_url}/api/transfer",
                headers=headers,
                json=case,
                timeout=5,
            )
            log(
                "POST /api/transfer [HighAmt]",
                resp.status_code,
                f"amount={case['amount']:,}",
            )
        except requests.RequestException as e:
            print(f"  [ERR] {e}")
        time.sleep(0.3)


# ─────────────────────────────────────────────
# 공격 유형 3 - Brute Force / 고속 반복 요청
#   대상: POST /api/transfer
#   Snort 키워드: detection_filter (임계값 기반)
# ─────────────────────────────────────────────
def attack_brute_force(base_url: str, count: int = 200, delay: float = 0.05):
    """
    Brute Force / 고속 반복 요청 공격을 시뮬레이션한다.

    동일한 이체 페이로드를 짧은 간격으로 대량 반복 전송하여
    Snort 규칙의 detection_filter(임계값 기반 탐지) 동작을 검증한다.
    50회마다 진행 상황을 로그로 출력하며, 마지막에 성공률을 요약한다.

    Args:
        base_url : 요청을 보낼 서버의 베이스 URL
        count    : 총 요청 횟수 (기본값 200)
        delay    : 요청 간 대기 시간(초) (기본값 0.05초)
    """
    section(f"공격 유형 3: Brute Force (POST /api/transfer × {count}회, 간격 {delay}초)")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
        "Content-Type": "application/json",
    }
    payload = {
        "from_account": "111-22-333333",
        "to_account": "999-99-999999",
        "amount": 1_000,
        "memo": "test",
    }

    success = 0
    for i in range(1, count + 1):
        try:
            resp = requests.post(
                f"{base_url}/api/transfer",
                headers=headers,
                json=payload,
                timeout=5,
            )
            if i % 50 == 0 or i == 1:
                log(
                    f"POST /api/transfer [Brute #{i}]",
                    resp.status_code,
                    f"진행 {i}/{count}",
                )
            if resp.status_code == 200:
                success += 1
        except requests.RequestException as e:
            print(f"  [ERR] #{i}: {e}")
        time.sleep(delay)

    print(f"  완료: {count}회 요청 중 {success}회 성공")


# ─────────────────────────────────────────────
# 공격 유형 4 - 의심 User-Agent / 스캐너 모방
#   대상: GET /api/account, POST /api/transfer
#   Snort 키워드: http_header, content
# ─────────────────────────────────────────────
SCANNER_USER_AGENTS = [
    ("sqlmap", "sqlmap/1.7.8#stable (https://sqlmap.org)"),
    ("nikto",  "Nikto/2.1.6"),
    ("nmap",   "Nmap Scripting Engine"),
    ("dirbuster", "DirBuster-1.0-RC1"),
    ("zgrab",  "zgrab/0.x"),
    ("masscan","masscan/1.3"),
    ("burp",   "python-httpx/0.24.0"),
]

SCAN_TARGETS = [
    ("GET",  "/api/account", {"account_no": "111-22-333333"}, None),
    ("POST", "/api/transfer", None, {"from_account": "111-22-333333", "to_account": "444-55-666666", "amount": 1000}),
    ("GET",  "/health", {}, None),
]


def attack_scanner_ua(base_url: str):
    """
    보안 스캐너·공격 도구의 User-Agent를 사용한 요청을 시뮬레이션한다.

    sqlmap, Nikto, Nmap 등 알려진 도구의 User-Agent 문자열을 헤더에 설정하여
    GET /api/account 엔드포인트로 요청을 전송한다.
    Snort 규칙의 http_header / content 키워드 매칭 여부를 검증하는 데 사용된다.

    Args:
        base_url : 요청을 보낼 서버의 베이스 URL
    """
    section("공격 유형 4: 의심 User-Agent / 스캐너 모방")
    for tool_name, ua in SCANNER_USER_AGENTS:
        headers = {
            "User-Agent": ua,
            "Accept": "*/*",
            "Content-Type": "application/json",
        }
        method, path, params, body = SCAN_TARGETS[0]  # 계좌 조회로 통일
        try:
            if method == "GET":
                resp = requests.get(
                    f"{base_url}{path}",
                    params=params,
                    headers=headers,
                    timeout=5,
                )
            else:
                resp = requests.post(
                    f"{base_url}{path}",
                    headers=headers,
                    json=body,
                    timeout=5,
                )
            log(
                f"{method} {path} [{tool_name}]",
                resp.status_code,
                f"ua={ua[:40]}",
            )
        except requests.RequestException as e:
            print(f"  [ERR] {tool_name}: {e}")
        time.sleep(0.3)


# ─────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────
ATTACK_MAP = {
    "sqli":  attack_sqli,
    "hta":   attack_high_transfer,
    "brute": attack_brute_force,
    "scan":  attack_scanner_ua,
}


def main():
    """
    CLI 진입점. 인자를 파싱하고 선택된 공격 유형을 순서대로 실행한다.

    --type all   : sqli → hta → brute → scan 순서로 모든 공격 실행
    --type sqli  : SQL Injection만 실행
    --type hta   : 고액 이체만 실행
    --type brute : Brute Force만 실행 (--brute-count, --brute-delay 옵션 적용)
    --type scan  : 스캐너 UA 모방만 실행

    서버 연결에 실패하면 즉시 종료(exit code 1)하고,
    KeyboardInterrupt(Ctrl+C)로 언제든지 중단할 수 있다.
    """
    parser = argparse.ArgumentParser(description="공격 트래픽 생성기 (연구용)")
    parser.add_argument("--host", default="127.0.0.1", help="API 서버 호스트")
    parser.add_argument("--port", default=5000, type=int, help="API 서버 포트")
    parser.add_argument(
        "--type",
        default="all",
        choices=["all", "sqli", "hta", "brute", "scan"],
        help="공격 유형 선택 (기본: all)",
    )
    parser.add_argument("--brute-count", default=200, type=int, help="Brute Force 요청 횟수")
    parser.add_argument("--brute-delay", default=0.05, type=float, help="Brute Force 요청 간격(초)")
    args = parser.parse_args()

    global BASE_URL
    base_url = f"http://{args.host}:{args.port}"

    print("=" * 55)
    print("  공격 트래픽 생성기 시작 (연구용)")
    print(f"  대상 서버  : {base_url}")
    print(f"  공격 유형  : {args.type}")
    print("  경고: 허가된 실험 환경에서만 사용하세요.")
    print("=" * 55)

    if not wait_for_server(base_url):
        print("[FAIL] 서버에 연결할 수 없습니다. API 서버를 먼저 실행하세요.")
        sys.exit(1)

    start = time.time()

    try:
        if args.type == "all":
            attack_sqli(base_url)
            attack_high_transfer(base_url)
            attack_brute_force(base_url, args.brute_count, args.brute_delay)
            attack_scanner_ua(base_url)
        elif args.type == "brute":
            attack_brute_force(base_url, args.brute_count, args.brute_delay)
        else:
            ATTACK_MAP[args.type](base_url)
    except KeyboardInterrupt:
        print("\n  사용자에 의해 중단됨.")

    elapsed = time.time() - start
    print()
    print("=" * 55)
    print(f"  공격 트래픽 생성 완료 | 경과 {elapsed:.1f}초")
    print("=" * 55)


if __name__ == "__main__":
    main()
