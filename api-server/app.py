"""
===================================================
  모의 금융 API 서버 (Mock Financial API Server)
  연구용 실험 환경 - Snort 3 탐지 연구
===================================================

실행 방법:
  1. pip install flask
  2. python app.py
  3. 서버 주소: http://127.0.0.1:5000

API 목록:
  GET  /api/account   - 일반 계좌 조회 API
  POST /api/transfer  - 민감 거래(송금) API
  GET  /health        - 서버 상태 확인
"""

from flask import Flask, request, jsonify
import os
import json
import time
import datetime

# ─────────────────────────────────────────────
# 앱 초기화
# ─────────────────────────────────────────────
app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "api_requests.log")
os.makedirs(LOG_DIR, exist_ok=True)


# ─────────────────────────────────────────────
# 공통 로그 기록 함수
# ─────────────────────────────────────────────
def write_log(endpoint: str, method: str, status_code: int, extra: dict = None):
    """
    요청 정보를 JSON Lines 형식으로 logs/api_requests.log에 기록한다.
    Snort 경보 로그와 타임스탬프를 맞춰 비교할 수 있도록 Unix time과
    ISO 8601 두 가지 형식 모두 기록한다.
    """
    now = datetime.datetime.now()
    record = {
        "timestamp_unix": time.time(),
        "timestamp_iso": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "ip": request.remote_addr,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "user_agent": request.headers.get("User-Agent", ""),
        "content_type": request.headers.get("Content-Type", ""),
    }
    if extra:
        record.update(extra)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────
# 모의 데이터 (가짜 계좌 정보)
# ─────────────────────────────────────────────
MOCK_ACCOUNTS = {
    "111-22-333333": {"owner": "홍길동", "balance": 3_500_000, "bank": "한국은행"},
    "444-55-666666": {"owner": "김철수", "balance": 12_800_000, "bank": "한국은행"},
}

MOCK_TRANSACTIONS = [
    {"date": "2025-03-01", "type": "입금", "amount": 500_000, "memo": "급여"},
    {"date": "2025-03-05", "type": "출금", "amount": 120_000, "memo": "공과금"},
    {"date": "2025-03-09", "type": "출금", "amount": 30_000, "memo": "편의점"},
]


# ─────────────────────────────────────────────
# [API 1] GET /api/account  ← 일반 조회 API
# ─────────────────────────────────────────────
@app.route("/api/account", methods=["GET"])
def account():
    """
    계좌 정보 및 잔액 조회 API (일반 트래픽 대상).

    Query Parameters:
        account_no (str, optional): 조회할 계좌번호.
                                    없으면 기본 계좌 반환.

    Returns:
        200 JSON - 계좌 정보 및 최근 거래 내역
    """
    account_no = request.args.get("account_no", "111-22-333333")
    account_info = MOCK_ACCOUNTS.get(account_no, MOCK_ACCOUNTS["111-22-333333"])

    response_data = {
        "status": "success",
        "account_no": account_no,
        "owner": account_info["owner"],
        "bank": account_info["bank"],
        "balance": account_info["balance"],
        "currency": "KRW",
        "transactions": MOCK_TRANSACTIONS,
        "queried_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    }

    write_log(
        endpoint="/api/account",
        method="GET",
        status_code=200,
        extra={"account_no": account_no},
    )

    return jsonify(response_data), 200


# ─────────────────────────────────────────────
# [API 2] POST /api/transfer  ← 민감 거래 API
# ─────────────────────────────────────────────
@app.route("/api/transfer", methods=["POST"])
def transfer():
    """
    송금(이체) 요청 API (민감 거래 대상).

    Request Body (JSON):
        from_account (str): 출금 계좌번호
        to_account   (str): 입금 계좌번호
        amount       (int): 이체 금액 (KRW)
        memo         (str, optional): 적요

    Returns:
        200 JSON - 이체 처리 결과
        400 JSON - 필수 파라미터 누락 시
    """
    body = request.get_json(silent=True) or {}

    from_account = body.get("from_account", "")
    to_account   = body.get("to_account", "")
    amount       = body.get("amount", 0)
    memo         = body.get("memo", "")

    # 간단한 입력 유효성 검사 (실험용)
    if not from_account or not to_account or amount <= 0:
        write_log(
            endpoint="/api/transfer",
            method="POST",
            status_code=400,
            extra={"error": "missing_params", "body": body},
        )
        return jsonify({
            "status": "error",
            "message": "from_account, to_account, amount(>0) 는 필수 항목입니다.",
        }), 400

    # 이체 처리 결과 (모의)
    transaction_id = f"TXN-{int(time.time() * 1000)}"
    response_data = {
        "status": "success",
        "transaction_id": transaction_id,
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "currency": "KRW",
        "memo": memo,
        "processed_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "message": "이체가 정상적으로 처리되었습니다.",
    }

    write_log(
        endpoint="/api/transfer",
        method="POST",
        status_code=200,
        extra={
            "transaction_id": transaction_id,
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
        },
    )

    return jsonify(response_data), 200


# ─────────────────────────────────────────────
# [API 3] GET /health  ← 서버 상태 확인
# ─────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    """서버 생존 여부 확인용 엔드포인트."""
    return jsonify({
        "status": "ok",
        "server": "Mock Financial API Server",
        "time": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    }), 200


# ─────────────────────────────────────────────
# 서버 실행
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  모의 금융 API 서버 시작")
    print("  주소: http://127.0.0.1:5000")
    print("  로그: logs/api_requests.log")
    print("=" * 50)
    app.run(host="127.0.0.1", port=5000, debug=False)
