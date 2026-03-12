# Snort 3 금융 API 탐지 실험 환경

모의 금융 API 서버를 대상으로 정상/공격 트래픽을 생성하고 Snort 3으로 탐지하는 연구 환경입니다.

---

## 프로젝트 구조

```
project/
├── api-server/
│   └── app.py                  # 모의 금융 API 서버 (Flask)
├── traffic/
│   ├── normal_traffic.py       # 정상 트래픽 생성기
│   ├── attack_traffic.py       # 공격 트래픽 생성기
│   └── run_all.sh              # 통합 실행 스크립트
├── snort/
│   └── rules/                  # Snort 3 규칙 파일 위치
├── logs/
│   ├── server-logs/            # API 서버 로그
│   └── snort-alerts/           # Snort 경보 로그
└── docs/
```

---

## 사전 요구사항

- Python 3.10+
- Flask 3.x (`pip install flask`)
- requests (`pip install requests`)
- Snort 3.x (`/usr/local/bin/snort`)

---

## 실행 순서

### 1단계 — API 서버 실행

```bash
cd api-server
python3 app.py
```

서버가 `http://127.0.0.1:5000` 에서 시작됩니다.
`GET /health` 로 정상 기동 여부를 확인합니다.

```bash
python3 -c "import requests; print(requests.get('http://127.0.0.1:5000/health').json())"
```

---

### 2단계 — 트래픽 생성

#### 통합 실행 (정상 트래픽 → 공격 트래픽 순서)

```bash
bash traffic/run_all.sh
```

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `NORMAL_COUNT` | 50 | 정상 트래픽 요청 횟수 |
| `BRUTE_COUNT` | 200 | Brute Force 반복 횟수 |
| `BRUTE_DELAY` | 0.05 | Brute Force 요청 간격(초) |
| `HOST` | 127.0.0.1 | API 서버 호스트 |
| `PORT` | 5000 | API 서버 포트 |

```bash
# 예시: 정상 100회, Brute Force 300회
NORMAL_COUNT=100 BRUTE_COUNT=300 bash traffic/run_all.sh

# 정상 트래픽만 실행
bash traffic/run_all.sh --normal-only

# 공격 트래픽만 실행
bash traffic/run_all.sh --attack-only

# 특정 공격 유형만 실행
bash traffic/run_all.sh --attack sqli
```

---

#### 정상 트래픽 단독 실행

```bash
python3 traffic/normal_traffic.py
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--count` | 50 | 총 요청 횟수 (0=무제한) |
| `--duration` | 0 | 실행 시간(초, 0=무제한) |
| `--delay-min` | 0.5 | 요청 간 최소 딜레이(초) |
| `--delay-max` | 2.0 | 요청 간 최대 딜레이(초) |
| `--host` | 127.0.0.1 | API 서버 호스트 |
| `--port` | 5000 | API 서버 포트 |

```bash
# 100회 요청
python3 traffic/normal_traffic.py --count 100

# 60초 동안 실행
python3 traffic/normal_traffic.py --duration 60
```

시나리오 구성 (가중치 기반 랜덤):

| 시나리오 | 엔드포인트 | 비율 |
|---|---|---|
| 계좌 조회 | `GET /api/account` | 60% |
| 소액 이체 (1만~50만 원) | `POST /api/transfer` | 30% |
| 헬스체크 | `GET /health` | 10% |

---

#### 공격 트래픽 단독 실행

```bash
python3 traffic/attack_traffic.py [--type TYPE]
```

| `--type` | 공격 내용 | Snort 매칭 위치 |
|---|---|---|
| `sqli` | SQL Injection 페이로드 12종 | `http_uri` |
| `hta` | 고액 이체(1억 원 초과) 5종 | `http_client_body` |
| `brute` | 고속 반복 요청 (기본 200회) | `detection_filter` |
| `scan` | 의심 User-Agent 7종 | `http_header` |
| `all` | 위 4가지 순서대로 모두 실행 | (기본값) |

```bash
# SQL Injection만
python3 traffic/attack_traffic.py --type sqli

# Brute Force 횟수/간격 조정
python3 traffic/attack_traffic.py --type brute --brute-count 500 --brute-delay 0.02

# 전체 공격 유형 실행
python3 traffic/attack_traffic.py --type all
```

---

### 3단계 — 로그 확인

#### API 요청 로그

```bash
cat api-server/logs/api_requests.log
```

JSON Lines 형식으로 기록됩니다.

```json
{"timestamp_unix": 1741657200.0, "timestamp_iso": "2025-03-11T10:00:00", "ip": "127.0.0.1", "method": "GET", "endpoint": "/api/account", "status_code": 200, "user_agent": "Mozilla/5.0 ..."}
```

#### Snort 경보 로그

```
logs/snort-alerts/
```

---

## API 엔드포인트

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/account` | 계좌 조회 (`?account_no=111-22-333333`) |
| `POST` | `/api/transfer` | 송금 요청 (JSON body) |
| `GET` | `/health` | 서버 상태 확인 |

**`POST /api/transfer` 요청 예시:**

```json
{
  "from_account": "111-22-333333",
  "to_account":   "444-55-666666",
  "amount":       50000,
  "memo":         "월세"
}
```

---

## 담당자

| 번호 | 역할 | 담당자 |
|---|---|---|
| 1 | 환경 구축 및 통합 | - |
| 2 | 모의 금융 API 서버 | 이인화 |
| 3 | 정상/공격 트래픽 생성 | - |
| 4 | Snort 3 규칙 설계 및 탐지 | 윤서현 |
| 5 | 로그 분석 | - |
