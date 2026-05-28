# =============================================================================
# 테스트용 PCAP 파일 생성기
# 5가지 트래픽 패턴: 정상 / SYN Flood / Slowloris / RUDY / 취약점 공격
# 실행: python generate_pcaps.py
# =============================================================================

import random
import struct
import time
from pathlib import Path

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR,
    Ether, ARP, wrpcap, Packet, RandShort
)

OUT_DIR = Path(__file__).parent / "sample_pcaps"
OUT_DIR.mkdir(exist_ok=True)

# ── 공통 유틸 ─────────────────────────────────────────────────────────────────

def ts(base: float, offset: float) -> float:
    """base 타임스탬프에 offset(초)를 더한 float 반환."""
    return base + offset

def rand_ip(prefix="10.0.0."):
    return prefix + str(random.randint(1, 254))

def set_time(pkt: Packet, t: float) -> Packet:
    pkt.time = t
    return pkt

BASE = 1_700_000_000.0   # 2023-11-14 기준 epoch

# =============================================================================
# 1. 정상 통신 (normal_traffic.pcap)
#    HTTP GET/Response, DNS Query/Reply, ICMP Echo, HTTPS(TLS), FTP 흐름
# =============================================================================
def gen_normal():
    pkts = []
    client = "192.168.1.10"
    server = "93.184.216.34"   # example.com
    dns_sv = "8.8.8.8"
    t = BASE

    # ── DNS Query / Reply ─────────────────────────────────────────
    dns_q = (IP(src=client, dst=dns_sv) /
             UDP(sport=54321, dport=53) /
             DNS(rd=1, qd=DNSQR(qname="example.com")))
    pkts.append(set_time(dns_q, t)); t += 0.002

    dns_r = (IP(src=dns_sv, dst=client) /
             UDP(sport=53, dport=54321) /
             DNS(qr=1, aa=1, qd=DNSQR(qname="example.com"),
                 an=DNSRR(rrname="example.com", ttl=300, rdata=server)))
    pkts.append(set_time(dns_r, t)); t += 0.010

    # ── TCP 3-Way Handshake ───────────────────────────────────────
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="S", seq=1000), t)); t += 0.012
    pkts.append(set_time(IP(src=server, dst=client)/TCP(sport=80, dport=50001, flags="SA", seq=5000, ack=1001), t)); t += 0.001
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="A", seq=1001, ack=5001), t)); t += 0.001

    # ── HTTP GET Request ──────────────────────────────────────────
    http_get = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n"
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="PA", seq=1001, ack=5001)/Raw(load=http_get), t)); t += 0.025

    # ── HTTP 200 OK Response ──────────────────────────────────────
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 648\r\nConnection: keep-alive\r\n\r\n<!DOCTYPE html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>"
    pkts.append(set_time(IP(src=server, dst=client)/TCP(sport=80, dport=50001, flags="PA", seq=5001, ack=len(http_get)+1001)/Raw(load=http_resp), t)); t += 0.002
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="A", seq=len(http_get)+1001, ack=5001+len(http_resp)), t)); t += 0.001

    # ── ICMP Echo Request / Reply ─────────────────────────────────
    for i in range(4):
        pkts.append(set_time(IP(src=client, dst="8.8.8.8")/ICMP(type=8, id=1, seq=i)/Raw(load=b"pingpingpingping"), t)); t += 0.040
        pkts.append(set_time(IP(src="8.8.8.8", dst=client)/ICMP(type=0, id=1, seq=i)/Raw(load=b"pingpingpingping"), t)); t += 0.001

    # ── HTTPS (TLS Client Hello 시뮬레이션) ───────────────────────
    tls_hello = bytes([
        0x16, 0x03, 0x01, 0x00, 0xf1,   # TLS Handshake, v1.0, length
        0x01, 0x00, 0x00, 0xed,          # ClientHello
        0x03, 0x03,                      # TLS 1.2
    ]) + bytes(random.getrandbits(8) for _ in range(32))  # random bytes
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50443, dport=443, flags="PA", seq=1, ack=1)/Raw(load=tls_hello), t)); t += 0.020

    # ── FTP Control 흐름 ─────────────────────────────────────────
    ftp_server = "192.168.1.1"
    pkts.append(set_time(IP(src=ftp_server, dst=client)/TCP(sport=21, dport=55001, flags="PA", seq=1, ack=1)/Raw(load=b"220 FTP Server ready\r\n"), t)); t += 0.010
    pkts.append(set_time(IP(src=client, dst=ftp_server)/TCP(sport=55001, dport=21, flags="PA", seq=1, ack=22)/Raw(load=b"USER anonymous\r\n"), t)); t += 0.008
    pkts.append(set_time(IP(src=ftp_server, dst=client)/TCP(sport=21, dport=55001, flags="PA", seq=22, ack=17)/Raw(load=b"331 Password required\r\n"), t)); t += 0.010
    pkts.append(set_time(IP(src=client, dst=ftp_server)/TCP(sport=55001, dport=21, flags="PA", seq=17, ack=45)/Raw(load=b"PASS anonymous@\r\n"), t)); t += 0.008
    pkts.append(set_time(IP(src=ftp_server, dst=client)/TCP(sport=21, dport=55001, flags="PA", seq=45, ack=33)/Raw(load=b"230 Login successful\r\n"), t)); t += 0.005

    # (ARP는 링크타입 불일치 방지를 위해 이 pcap에서 제외)

    # ── TCP FIN 종료 ─────────────────────────────────────────────
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="FA", seq=2000, ack=6000), t)); t += 0.005
    pkts.append(set_time(IP(src=server, dst=client)/TCP(sport=80, dport=50001, flags="FA", seq=6000, ack=2001), t)); t += 0.002
    pkts.append(set_time(IP(src=client, dst=server)/TCP(sport=50001, dport=80, flags="A",  seq=2001, ack=6001), t))

    out = OUT_DIR / "01_normal_traffic.pcap"
    wrpcap(str(out), pkts)
    print("[OK] %-40s %4d pkts" % (out.name, len(pkts)))


# =============================================================================
# 2. SYN Flood 공격 (syn_flood.pcap)
#    수백 개의 위조 IP에서 대량 SYN → 서버 백로그 포화
# =============================================================================
def gen_syn_flood():
    pkts = []
    target = "192.168.1.100"
    t = BASE

    # 공격 전 정상 트래픽 (베이스라인)
    legit = "192.168.1.50"
    pkts.append(set_time(IP(src=legit, dst=target)/TCP(sport=60001, dport=80, flags="S",  seq=9000), t)); t += 0.010
    pkts.append(set_time(IP(src=target, dst=legit)/TCP(sport=80, dport=60001, flags="SA", seq=1000, ack=9001), t)); t += 0.001
    pkts.append(set_time(IP(src=legit, dst=target)/TCP(sport=60001, dport=80, flags="A",  seq=9001, ack=1001), t)); t += 0.010

    # SYN Flood 본체: 서로 다른 위조 소스 IP에서 SYN만 쏟아냄
    for i in range(350):
        src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport  = random.randint(1024, 65535)
        seq    = random.randint(100000, 999999)
        pkt = IP(src=src_ip, dst=target) / TCP(sport=sport, dport=80, flags="S", seq=seq)
        # 빠른 간격으로 연속 전송 (초당 ~500 pps)
        pkts.append(set_time(pkt, t))
        t += 0.002

        # 서버 SYN-ACK 응답 (일부만)
        if i % 10 == 0:
            synack = IP(src=target, dst=src_ip) / TCP(sport=80, dport=sport, flags="SA", seq=random.randint(1,999999), ack=seq+1)
            pkts.append(set_time(synack, t))
            t += 0.0005

    # 공격 후 정상 사용자 연결 실패 (RST 응답)
    for j in range(10):
        victim = f"192.168.1.{j+200}"
        pkts.append(set_time(IP(src=victim, dst=target)/TCP(sport=61000+j, dport=80, flags="S", seq=5000+j), t)); t += 0.015
        pkts.append(set_time(IP(src=target, dst=victim)/TCP(sport=80, dport=61000+j, flags="R", seq=0, ack=5001+j), t)); t += 0.002

    out = OUT_DIR / "02_syn_flood.pcap"
    wrpcap(str(out), pkts)
    print("[OK] %-40s %4d pkts" % (out.name, len(pkts)))


# =============================================================================
# 3. Slowloris 공격 (slowloris.pcap)
#    수십 개의 소켓을 열고 HTTP 헤더를 매우 느리게 (몇 초 간격) 전송
#    → 서버 Connection 풀 고갈
# =============================================================================
def gen_slowloris():
    pkts = []
    attacker_base = "10.10.10."
    target = "192.168.1.100"
    t = BASE

    num_connections = 50   # 동시 연결 수
    conn_state = []        # (src_ip, sport, seq, ack) 추적

    # 모든 소켓 TCP 연결 수립
    for i in range(num_connections):
        src = attacker_base + str(i + 1)
        sport = 40000 + i
        seq = 10000 + i * 100

        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="S", seq=seq), t))
        t += 0.005
        pkts.append(set_time(IP(src=target, dst=src)/TCP(sport=80, dport=sport, flags="SA", seq=50000, ack=seq+1), t))
        t += 0.002
        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="A", seq=seq+1, ack=50001), t))
        t += 0.003

        # 불완전한 HTTP 헤더 첫 줄만 전송
        partial_header = f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode()
        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="PA", seq=seq+1, ack=50001)/Raw(load=partial_header), t))
        t += 0.002

        conn_state.append((src, sport, seq + 1 + len(partial_header), 50001))

    # 12초에 걸쳐 헤더를 조금씩 추가 전송 (Keep-Alive 유지용)
    # 진짜 Slowloris는 "X-a: b\r\n" 같은 dummy 헤더를 계속 보냄
    for round_num in range(6):
        t += 2.0  # 2초 대기
        for i, (src, sport, seq, ack) in enumerate(conn_state):
            dummy = f"X-Header-{round_num}: keep-alive-{i}\r\n".encode()
            pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="PA", seq=seq, ack=ack)/Raw(load=dummy), t))
            t += 0.001
            conn_state[i] = (src, sport, seq + len(dummy), ack)

        # 서버 ACK (연결은 살아있음)
        for i, (src, sport, seq, ack) in enumerate(conn_state[:10]):
            pkts.append(set_time(IP(src=target, dst=src)/TCP(sport=80, dport=sport, flags="A", seq=ack, ack=seq), t))
            t += 0.0005

    # 일부 연결 타임아웃 (서버 RST)
    for i in range(5):
        src, sport, seq, ack = conn_state[i]
        pkts.append(set_time(IP(src=target, dst=src)/TCP(sport=80, dport=sport, flags="R", seq=ack, ack=seq), t))
        t += 0.010

    out = OUT_DIR / "03_slowloris.pcap"
    wrpcap(str(out), pkts)
    print("[OK] %-40s %4d pkts" % (out.name, len(pkts)))


# =============================================================================
# 4. RUDY 공격 (rudy.pcap) — R-U-Dead-Yet
#    Content-Length를 크게 선언한 POST 요청을 보내고
#    본문(body)을 1바이트씩 매우 느리게 전송
# =============================================================================
def gen_rudy():
    pkts = []
    attacker_base = "172.16.0."
    target = "192.168.1.100"
    t = BASE

    num_connections = 30
    conn_state = []

    for i in range(num_connections):
        src = attacker_base + str(i + 1)
        sport = 45000 + i
        seq = 20000 + i * 200

        # TCP 핸드셰이크
        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="S", seq=seq), t)); t += 0.004
        pkts.append(set_time(IP(src=target, dst=src)/TCP(sport=80, dport=sport, flags="SA", seq=70000, ack=seq+1), t)); t += 0.002
        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="A", seq=seq+1, ack=70001), t)); t += 0.002

        # POST 헤더 전송 — Content-Length를 10000으로 선언
        post_header = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 10000\r\n"   # ← 본문을 10000바이트로 예고
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        pkts.append(set_time(IP(src=src, dst=target)/TCP(sport=sport, dport=80, flags="PA", seq=seq+1, ack=70001)/Raw(load=post_header), t))
        t += 0.002

        conn_state.append({
            "src": src, "sport": sport,
            "seq": seq + 1 + len(post_header),
            "ack": 70001, "sent": 0, "total": 10000
        })

    # 본문을 1~3바이트씩 천천히 전송 (1초 간격)
    for tick in range(40):
        t += 1.0
        for conn in conn_state:
            if conn["sent"] >= conn["total"]:
                continue
            # 1~3바이트씩만 전송
            chunk_size = random.randint(1, 3)
            chunk = (f"u={tick}&p=").encode()[:chunk_size]
            pkts.append(set_time(
                IP(src=conn["src"], dst=target) /
                TCP(sport=conn["sport"], dport=80, flags="PA",
                    seq=conn["seq"], ack=conn["ack"]) /
                Raw(load=chunk),
                t
            ))
            conn["seq"]  += len(chunk)
            conn["sent"] += len(chunk)
            t += 0.01

        # 서버 ACK (아직 응답 없음 — 본문 미완성)
        for conn in conn_state[:5]:
            pkts.append(set_time(
                IP(src=target, dst=conn["src"]) /
                TCP(sport=80, dport=conn["sport"], flags="A",
                    seq=conn["ack"], ack=conn["seq"]),
                t
            ))
            t += 0.001

    out = OUT_DIR / "04_rudy_attack.pcap"
    wrpcap(str(out), pkts)
    print("[OK] %-40s %4d pkts" % (out.name, len(pkts)))


# =============================================================================
# 5. 취약점 공격 패턴 (exploit.pcap)
#    ① 포트 스캔 (SYN Scan)
#    ② SQL Injection 시도
#    ③ Directory Traversal
#    ④ Shellcode 포함 버퍼 오버플로우 패턴
#    ⑤ C&C 서버 통신 (비정상 외부 IP 주기적 비콘)
# =============================================================================
def gen_exploit():
    pkts = []
    attacker = "10.99.99.99"
    victim   = "192.168.1.100"
    cnc      = "185.220.101.50"   # 가상 C&C IP
    t = BASE

    # ① 포트 스캔 (SYN Scan) ─────────────────────────────────────
    # 빠른 SYN 전송 후 응답 없으면 닫힌 포트
    scan_ports = list(range(20, 25)) + [53, 80, 110, 135, 139, 443, 445,
                                         1433, 3306, 3389, 5432, 8080, 8443]
    for port in scan_ports:
        pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=random.randint(49152,65535), dport=port, flags="S", seq=random.randint(1,99999)), t))
        t += 0.003
        # 열린 포트는 SYN-ACK, 닫힌 포트는 RST
        if port in [80, 443, 3306, 3389]:
            pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=port, dport=55555, flags="SA", seq=1, ack=2), t)); t += 0.001
            # 스캐너는 즉시 RST로 연결 끊음
            pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=55555, dport=port, flags="R", seq=2, ack=2), t)); t += 0.001
        else:
            pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=port, dport=55555, flags="R", seq=0, ack=1), t)); t += 0.001
    t += 0.5

    # ② SQL Injection 시도 ────────────────────────────────────────
    sqli_payloads = [
        b"GET /login?user=admin'--&pass=x HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
        b"GET /login?user=1' OR '1'='1&pass=x HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
        b"GET /search?q=1; DROP TABLE users;-- HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
        b"GET /item?id=1 UNION SELECT username,password,3 FROM users-- HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
    ]
    sport = 51000
    for payload in sqli_payloads:
        pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=80, flags="S", seq=1000), t)); t += 0.005
        pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=80, dport=sport, flags="SA", seq=2000, ack=1001), t)); t += 0.002
        pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=payload), t)); t += 0.010
        # 서버 에러 응답 (400 Bad Request 또는 500)
        err_resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
        pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=80, dport=sport, flags="PA", seq=2001, ack=1001+len(payload))/Raw(load=err_resp), t)); t += 0.005
        sport += 1
    t += 0.3

    # ③ Directory Traversal ───────────────────────────────────────
    traversal_payloads = [
        b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
        b"GET /..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
        b"GET /static/../../../windows/system32/cmd.exe HTTP/1.1\r\nHost: 192.168.1.100\r\n\r\n",
    ]
    for payload in traversal_payloads:
        pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=80, flags="S", seq=3000), t)); t += 0.005
        pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=80, dport=sport, flags="SA", seq=4000, ack=3001), t)); t += 0.002
        pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=80, flags="PA", seq=3001, ack=4001)/Raw(load=payload), t)); t += 0.008
        sport += 1
    t += 0.3

    # ④ 버퍼 오버플로우 (Shellcode 패턴) ─────────────────────────
    # NOP sled + 가상 셸코드 패턴 (실제 익스플로잇 아님, 패턴 시뮬레이션)
    nop_sled = b"\x90" * 100
    # MS17-010 EternalBlue 스타일 SMB 트랜잭션 헤더 시뮬레이션
    smb_header = bytes([
        0xff, 0x53, 0x4d, 0x42,   # \xffSMB 시그니처
        0x25,                      # SMB command: Trans2
        0x00, 0x00, 0x00, 0x00,   # NT Status
        0x18,                      # Flags
        0x01, 0x28,               # Flags2
        0x00, 0x00,               # PID High
    ])
    shellcode_sim = nop_sled + smb_header + b"A" * 50
    pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=445, flags="S", seq=5000), t)); t += 0.005
    pkts.append(set_time(IP(src=victim, dst=attacker)/TCP(sport=445, dport=sport, flags="SA", seq=6000, ack=5001), t)); t += 0.002
    pkts.append(set_time(IP(src=attacker, dst=victim)/TCP(sport=sport, dport=445, flags="PA", seq=5001, ack=6001)/Raw(load=shellcode_sim), t)); t += 0.005
    sport += 1
    t += 0.5

    # ⑤ C&C 비콘 통신 ────────────────────────────────────────────
    # 악성코드가 C&C 서버에 주기적으로 HTTP GET 비콘을 보내는 패턴
    infected = "192.168.1.55"
    beacon_interval = 30.0
    beacon_payload = b"GET /update?uid=abc123&v=2.1&os=win10 HTTP/1.1\r\nHost: cdn-update.net\r\nUser-Agent: Windows-Update/7.6\r\n\r\n"

    for beacon_num in range(6):
        pkts.append(set_time(IP(src=infected, dst=cnc)/TCP(sport=sport, dport=80, flags="S", seq=8000+beacon_num*100), t)); t += 0.050
        pkts.append(set_time(IP(src=cnc, dst=infected)/TCP(sport=80, dport=sport, flags="SA", seq=9000, ack=8001+beacon_num*100), t)); t += 0.100
        pkts.append(set_time(IP(src=infected, dst=cnc)/TCP(sport=sport, dport=80, flags="PA", seq=8001+beacon_num*100, ack=9001)/Raw(load=beacon_payload), t)); t += 0.100

        # C&C 명령 응답 (암호화된 것처럼 보이는 바이너리 데이터)
        cnc_cmd = b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n" + bytes(range(32))
        pkts.append(set_time(IP(src=cnc, dst=infected)/TCP(sport=80, dport=sport, flags="PA", seq=9001, ack=8001+beacon_num*100+len(beacon_payload))/Raw(load=cnc_cmd), t)); t += 0.050
        pkts.append(set_time(IP(src=infected, dst=cnc)/TCP(sport=sport, dport=80, flags="FA", seq=8001+beacon_num*100+len(beacon_payload), ack=9001+len(cnc_cmd)), t)); t += 0.010

        sport += 1
        t += beacon_interval - 0.31   # 다음 비콘까지 대기

    out = OUT_DIR / "05_exploit_patterns.pcap"
    wrpcap(str(out), pkts)
    print("[OK] %-40s %4d pkts" % (out.name, len(pkts)))


# =============================================================================
# 메인 실행
# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  PCAP Test File Generator")
    print("  Output: %s" % OUT_DIR)
    print("=" * 60)

    gen_normal()
    gen_syn_flood()
    gen_slowloris()
    gen_rudy()
    gen_exploit()

    print("=" * 60)
    print("  Done! Upload these files to the app:")
    for f in sorted(OUT_DIR.glob("*.pcap")):
        size_kb = f.stat().st_size / 1024
        print("  >> %-42s %6.1f KB" % (f.name, size_kb))
    print("=" * 60)
