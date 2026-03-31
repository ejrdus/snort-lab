"""
===================================================
  공격 트래픽 PCAP 생성기 (루트 권한 불필요)
  Snort 3 오프라인 분석용 합성 PCAP 파일 생성

  사용법:
    python3 generate_pcap.py
    python3 generate_pcap.py --output /path/to/attack.pcap
    python3 generate_pcap.py --sqli 100 --hta 100 --brute 200 --scan 100
===================================================
"""

import struct
import socket
import argparse
import os
import time
from typing import List, Tuple

# ─────────────────────────────────────────────
# 공격 페이로드 (attack_traffic.py와 동일)
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
    "' OR ''='",
    "admin'--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT 1,2,3--",
    "1' OR '1'='1' /*",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; EXEC xp_cmdshell('dir')--",
    "' HAVING 1=1--",
    "' GROUP BY columnnames HAVING 1=1--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1' WAITFOR DELAY '0:0:5'--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' AND SUBSTRING(username,1,1)='a'--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL,table_name FROM information_schema.tables--",
    "1 AND 1=1 UNION SELECT 1,2,3--",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "1'; SELECT * FROM information_schema.tables--",
    "' UNION SELECT load_file('/etc/passwd')--",
    "' INTO OUTFILE '/tmp/test.txt'--",
    "' OR BENCHMARK(10000000,SHA1('test'))--",
    "'; SHUTDOWN--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' OR UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

HTA_AMOUNTS = [
    999_999_999, 500_000_000, 1_000_000_000, 750_000_000, 999_000_000,
    800_000_000, 650_000_000, 900_000_000, 550_000_000, 1_500_000_000,
    2_000_000_000, 700_000_000, 850_000_000, 950_000_000, 600_000_000,
]

SCANNER_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine",
    "DirBuster-1.0-RC1",
    "zgrab/0.x",
    "masscan/1.3",
    "python-httpx/0.24.0",
    "sqlmap/1.8.1#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "gobuster/3.6",
    "Wfuzz/3.1.0",
    "Nuclei/3.1.0",
    "Fuzz Faster U Fool v2.1.0",
    "Mozilla/4.0 (Hydra)",
    "Arachni/v1.6.1",
    "OpenVAS/22.4",
    "w3af.org",
    "skipfish/2.10b",
    "WhatWeb/0.5.5",
    "WPScan v3.8.25",
]

# ─────────────────────────────────────────────
# 체크섬 계산
# ─────────────────────────────────────────────
def checksum(data: bytes) -> int:
    """인터넷 체크섬 (RFC 1071)"""
    if len(data) % 2 != 0:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def make_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int,
                   ip_id: int = 0) -> bytes:
    """IPv4 헤더 생성 (체크섬 포함)"""
    total_len = 20 + payload_len
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,       # version=4, IHL=5
        0,          # DSCP/ECN
        total_len,
        ip_id,
        0,          # flags + fragment offset
        64,         # TTL
        protocol,
        0,          # checksum (computed below)
        src,
        dst
    )
    csum = checksum(hdr)
    return hdr[:10] + struct.pack('!H', csum) + hdr[12:]


def make_tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
                    flags: int, src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    """TCP 헤더 생성 (체크섬 포함)"""
    tcp_hdr = struct.pack(
        '!HHIIHHHH',
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 12) | flags,   # data offset=5 (20 bytes), flags
        65535,               # window size
        0,                   # checksum (computed below)
        0,                   # urgent pointer
    )
    # TCP pseudo header for checksum
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_len = 20 + len(payload)
    pseudo = src + dst + struct.pack('!BBH', 0, 6, tcp_len)
    csum = checksum(pseudo + tcp_hdr + payload)
    return tcp_hdr[:16] + struct.pack('!H', csum) + tcp_hdr[18:]


def make_eth_header() -> bytes:
    """더미 Ethernet 헤더 (로컬 루프백 트래픽 모방)"""
    dst_mac = b'\x00\x00\x00\x00\x00\x01'
    src_mac = b'\x00\x00\x00\x00\x00\x02'
    ethertype = struct.pack('!H', 0x0800)  # IPv4
    return dst_mac + src_mac + ethertype


ETH_HDR = make_eth_header()

# ─────────────────────────────────────────────
# 패킷 생성 헬퍼
# ─────────────────────────────────────────────
_TCP_FLAGS = {
    'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04,
    'PSH': 0x08, 'ACK': 0x10, 'URG': 0x20,
}

def build_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 seq: int, ack: int, flags: str, payload: bytes = b'') -> bytes:
    flag_bits = sum(_TCP_FLAGS[f] for f in flags.split('+'))
    tcp_hdr = make_tcp_header(src_port, dst_port, seq, ack, flag_bits,
                               src_ip, dst_ip, payload)
    ip_hdr  = make_ip_header(src_ip, dst_ip, 6, len(tcp_hdr) + len(payload))
    return ETH_HDR + ip_hdr + tcp_hdr + payload


# ─────────────────────────────────────────────
# TCP 연결 + HTTP 요청 패킷 시퀀스 생성
# ─────────────────────────────────────────────
def make_http_session(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      http_request: bytes, base_ts: float) -> List[Tuple[float, bytes]]:
    """
    TCP 3-way handshake + HTTP 요청 데이터를 담은 패킷 리스트를 반환한다.
    각 항목: (타임스탬프, 원시 패킷 bytes)
    """
    pkts = []
    t = base_ts
    dt = 0.001  # 1ms 간격

    cli_ip, srv_ip = src_ip, dst_ip
    cli_port, srv_port = src_port, dst_port

    seq_c = 1000
    seq_s = 5000

    # SYN (client → server)
    pkts.append((t, build_packet(cli_ip, srv_ip, cli_port, srv_port,
                                  seq_c, 0, 'SYN')))
    t += dt; seq_c += 1

    # SYN-ACK (server → client)
    pkts.append((t, build_packet(srv_ip, cli_ip, srv_port, cli_port,
                                  seq_s, seq_c, 'SYN+ACK')))
    t += dt; seq_s += 1

    # ACK (client → server)
    pkts.append((t, build_packet(cli_ip, srv_ip, cli_port, srv_port,
                                  seq_c, seq_s, 'ACK')))
    t += dt

    # HTTP 요청 (client → server, PSH+ACK)
    pkts.append((t, build_packet(cli_ip, srv_ip, cli_port, srv_port,
                                  seq_c, seq_s, 'PSH+ACK', http_request)))
    t += dt; seq_c += len(http_request)

    # HTTP 응답 (server → client, 간략 200 OK)
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    pkts.append((t, build_packet(srv_ip, cli_ip, srv_port, cli_port,
                                  seq_s, seq_c, 'PSH+ACK', response)))
    t += dt; seq_s += len(response)

    # FIN (client → server)
    pkts.append((t, build_packet(cli_ip, srv_ip, cli_port, srv_port,
                                  seq_c, seq_s, 'FIN+ACK')))

    return pkts


# ─────────────────────────────────────────────
# PCAP 파일 I/O
# ─────────────────────────────────────────────
PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHiIII',
    0xa1b2c3d4,  # magic number
    2,           # major version
    4,           # minor version
    0,           # GMT offset
    0,           # timestamp accuracy
    65535,       # snapshot length
    1,           # link type: Ethernet
)


def write_pcap(path: str, packets: List[Tuple[float, bytes]]):
    """타임스탬프와 패킷 데이터를 PCAP 파일로 저장한다."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt in packets:
            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_len = len(pkt)
            f.write(struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len))
            f.write(pkt)


# ─────────────────────────────────────────────
# 공격 유형별 HTTP 패킷 생성
# ─────────────────────────────────────────────
def gen_sqli_packets(count: int, base_ts: float, port_start: int
                     ) -> List[Tuple[float, bytes]]:
    """SQL Injection 공격 패킷 생성 (GET /api/account?account_no=<payload>)"""
    pkts = []
    for i in range(count):
        payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
        encoded = payload.replace(' ', '%20').replace("'", "%27").replace('"', '%22')
        req = (
            f"GET /api/account?account_no={encoded} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:5000\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: application/json\r\n"
            f"\r\n"
        ).encode()
        ts = base_ts + i * 0.01
        pkts.extend(make_http_session(
            '127.0.0.1', '127.0.0.1',
            port_start + i, 5000,
            req, ts
        ))
    return pkts


def gen_hta_packets(count: int, base_ts: float, port_start: int
                    ) -> List[Tuple[float, bytes]]:
    """고액 이체 공격 패킷 생성 (POST /api/transfer with large amount)"""
    pkts = []
    for i in range(count):
        amount = HTA_AMOUNTS[i % len(HTA_AMOUNTS)]
        body = (
            f'{{"from_account":"111-22-333333","to_account":"999-99-999999",'
            f'"amount":{amount},"memo":"test"}}'
        ).encode()
        req = (
            f"POST /api/transfer HTTP/1.1\r\n"
            f"Host: 127.0.0.1:5000\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body
        ts = base_ts + i * 0.01
        pkts.extend(make_http_session(
            '127.0.0.1', '127.0.0.1',
            port_start + i, 5000,
            req, ts
        ))
    return pkts


def gen_brute_packets(count: int, base_ts: float, port_start: int
                      ) -> List[Tuple[float, bytes]]:
    """Brute Force 공격 패킷 생성 (동일 소스 IP로 고속 반복)"""
    pkts = []
    body = b'{"from_account":"111-22-333333","to_account":"999-99-999999","amount":1000,"memo":"test"}'
    for i in range(count):
        req = (
            f"POST /api/transfer HTTP/1.1\r\n"
            f"Host: 127.0.0.1:5000\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body
        # 동일 소스 IP, 짧은 간격 (detection_filter 임계값 트리거용)
        ts = base_ts + i * 0.04   # 25req/sec → 10초에 250건 (임계값 30건 초과)
        pkts.extend(make_http_session(
            '10.0.0.1', '127.0.0.1',
            port_start + (i % 1000), 5000,
            req, ts
        ))
    return pkts


def gen_scan_packets(count: int, base_ts: float, port_start: int
                     ) -> List[Tuple[float, bytes]]:
    """스캐너 User-Agent 공격 패킷 생성"""
    pkts = []
    for i in range(count):
        ua = SCANNER_USER_AGENTS[i % len(SCANNER_USER_AGENTS)]
        req = (
            f"GET /api/account?account_no=111-22-333333 HTTP/1.1\r\n"
            f"Host: 127.0.0.1:5000\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        ).encode()
        ts = base_ts + i * 0.01
        pkts.extend(make_http_session(
            '127.0.0.1', '127.0.0.1',
            port_start + i, 5000,
            req, ts
        ))
    return pkts


# ─────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Snort 3 분석용 공격 트래픽 PCAP 생성기')
    parser.add_argument('--output', default='../logs/benchmark_attack.pcap',
                        help='출력 PCAP 파일 경로')
    parser.add_argument('--sqli',  type=int, default=100, help='SQL Injection 요청 수')
    parser.add_argument('--hta',   type=int, default=100, help='고액 이체 요청 수')
    parser.add_argument('--brute', type=int, default=200, help='Brute Force 요청 수')
    parser.add_argument('--scan',  type=int, default=100, help='스캐너 UA 요청 수')
    args = parser.parse_args()

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print("=" * 55)
    print("  공격 트래픽 PCAP 생성")
    print(f"  출력 파일: {output_path}")
    print("=" * 55)

    all_pkts: List[Tuple[float, bytes]] = []
    base_ts = 1_700_000_000.0  # 기준 타임스탬프 (2023-11-14)

    # 공격 유형별 패킷 생성
    configs = [
        ("SQL Injection",     gen_sqli_packets,  args.sqli,  10000),
        ("고액 이체",          gen_hta_packets,   args.hta,   20000),
        ("Brute Force",       gen_brute_packets,  args.brute, 30000),
        ("스캐너 User-Agent", gen_scan_packets,   args.scan,  40000),
    ]

    ts_offset = 0.0
    for name, fn, count, port_base in configs:
        print(f"  [{name}] {count}건 패킷 생성 중...", end=' ', flush=True)
        pkts = fn(count, base_ts + ts_offset, port_base)
        all_pkts.extend(pkts)
        ts_offset += count * 0.01 + 1.0
        print(f"{len(pkts)} 패킷 생성 완료")

    # 타임스탬프 순서 정렬
    all_pkts.sort(key=lambda x: x[0])

    print(f"\n  총 {len(all_pkts)} 패킷 → {output_path} 저장 중...", end=' ', flush=True)
    write_pcap(output_path, all_pkts)
    size_kb = os.path.getsize(output_path) / 1024
    print(f"완료 ({size_kb:.1f} KB)")
    print()
    print(f"  사용법: snort -c snort.lua -R rules.file -r {output_path}")
    print("=" * 55)


if __name__ == '__main__':
    main()
