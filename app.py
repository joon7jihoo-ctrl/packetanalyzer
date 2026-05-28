# =============================================================================
# KDN 패킷 분석기 — 클린 SaaS 대시보드 리뉴얼
# =============================================================================
# 실행 방법:
#   pip install streamlit scapy pandas plotly openai anthropic
#   streamlit run app.py
# =============================================================================

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import io
import tempfile
import os
from datetime import datetime
from collections import Counter

# ─── 페이지 기본 설정 ──────────────────────────────────────────────────────────
st.set_page_config(
    page_title="KDN 패킷 분석기",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── 커스텀 CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* ── 기본 폰트 & 배경 ─────────────────────────────────────────── */
html, body {
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
    font-size: 15px !important;
    line-height: 1.7 !important;
}
.stApp {
    background: #f9fafb !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}
* {
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}

/* ── Streamlit 불필요 요소 제거 ────────────────────────────────── */
footer,
#MainMenu,
[data-testid="stToolbar"],
header[data-testid="stHeader"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"] {
    display: none !important;
}
[data-testid="stAppViewBlockContainer"] {
    padding-top: 0 !important;
}
div.block-container {
    padding-top: 1rem !important;
    max-width: 1200px !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
}
.appview-container > section.main {
    padding-top: 0 !important;
}
/* Hide collapsed sidebar toggle */
[data-testid="collapsedControl"],
[data-testid="stSidebarNav"],
button[data-testid="baseButton-headerNoPadding"] {
    display: none !important;
}

/* ── 앱 헤더 영역 ───────────────────────────────────────────────── */
.app-header {
    background: #ffffff;
    border-bottom: 1px solid #e5e7eb;
    padding: 16px 0 0;
    margin-bottom: 0;
}
.app-header h1 {
    font-size: 1.25rem !important;
    font-weight: 700 !important;
    color: #111827 !important;
    margin: 0 0 0 !important;
    letter-spacing: -0.02em;
}

/* ── 탭 (상단 네비게이션) ───────────────────────────────────────── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: #ffffff !important;
    border-bottom: 1px solid #e5e7eb !important;
    padding: 0 !important;
    gap: 0 !important;
    border-radius: 0 !important;
    margin-bottom: 24px !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    font-size: 14px !important;
    font-weight: 500 !important;
    color: #6b7280 !important;
    background: transparent !important;
    border-radius: 0 !important;
    border-bottom: 2px solid transparent !important;
    padding: 12px 20px !important;
    margin-bottom: -1px;
    transition: color 0.15s, border-color 0.15s;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {
    color: #111827 !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: #2563eb !important;
    border-bottom-color: #2563eb !important;
    font-weight: 600 !important;
    background: transparent !important;
}
/* Override Streamlit default red tab indicator */
[data-testid="stTabs"] [data-baseweb="tab-highlight"],
[data-testid="stTabs"] [data-baseweb="tab"] [data-testid*="indicator"],
.stTabs [data-baseweb="tab-highlight"] {
    background-color: #2563eb !important;
    background: #2563eb !important;
}
/* Tab panel background */
[data-testid="stTabs"] [data-baseweb="tab-panel"] {
    background: transparent !important;
    padding: 0 !important;
}

/* ── KPI 카드 (st.metric) ───────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #ffffff !important;
    border: 1px solid #e5e7eb !important;
    border-radius: 12px !important;
    padding: 16px 20px !important;
}
[data-testid="stMetricValue"] {
    color: #111827 !important;
    font-weight: 700 !important;
    font-size: 1.5rem !important;
}
[data-testid="stMetricLabel"] {
    color: #6b7280 !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
[data-testid="stMetricDelta"] {
    font-size: 0.78rem !important;
}

/* ── 버튼 ───────────────────────────────────────────────────────── */
.stButton button {
    background: #ffffff !important;
    border: 1px solid #e5e7eb !important;
    color: #374151 !important;
    border-radius: 8px !important;
    font-size: 14px !important;
    font-weight: 500 !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
    transition: border-color 0.15s, color 0.15s;
}
.stButton button:hover {
    border-color: #2563eb !important;
    color: #2563eb !important;
}
.stButton button[kind="primary"] {
    background: #2563eb !important;
    border-color: #2563eb !important;
    color: #fff !important;
}
.stButton button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    border-color: #1d4ed8 !important;
}

/* ── 패스워드 입력 필드 (eye icon) ──────────────────────────────── */
[data-testid="stTextInput"] button,
[data-testid="stTextInput"] > div > div button {
    background: transparent !important;
    border: none !important;
    color: #9ca3af !important;
    box-shadow: none !important;
}
[data-testid="stTextInput"] button:hover {
    color: #374151 !important;
    background: transparent !important;
}

/* ── 채팅 입력 고정 컨테이너 ────────────────────────────────────── */
.stChatFloatingInputContainer,
[class*="stChatFloat"],
[data-testid="stChatInputContainer"],
.stElementContainer:has([data-testid="stChatInput"]) {
    background: #f9fafb !important;
}
/* Sticky bottom chat bar */
.stApp > div > div > div:last-child:has([data-testid="stChatInput"]) {
    background: #f9fafb !important;
}

/* ── 채팅 메시지 (Claude 스타일) ───────────────────────────────── */
[data-testid="stChatMessage"] {
    background: transparent !important;
    border: none !important;
    padding: 16px 0 !important;
    border-bottom: 1px solid #f3f4f6 !important;
    border-radius: 0 !important;
}
[data-testid="stChatMessage"]:last-child {
    border-bottom: none !important;
}
[data-testid="stChatMessage"] p {
    font-size: 15px !important;
    line-height: 1.75 !important;
    color: #1f2937 !important;
}
/* Chat input (all states including disabled) */
[data-testid="stChatInput"],
[data-testid="stChatInput"] > div,
[data-testid="stChatInput"] > div > div,
.stChatInput,
.stChatInput > div {
    border: 1px solid #e5e7eb !important;
    border-radius: 12px !important;
    background: #ffffff !important;
}
[data-testid="stChatInputTextArea"],
[data-testid="stChatInputTextArea"][disabled] {
    background: #ffffff !important;
    color: #9ca3af !important;
}
/* The whole chat container area */
.stElementContainer:has([data-testid="stChatInput"]) {
    background: #f9fafb !important;
}
/* The baseweb textarea wrapper inside chat input */
[data-testid="stChatInput"] [data-baseweb="textarea"],
[data-testid="stChatInput"] [data-baseweb="base-input"],
[data-testid="stChatInput"] [data-baseweb="textarea"] > div {
    background: #ffffff !important;
    border-radius: 12px !important;
}
/* Chat input wrapper that sits at the bottom */
[data-testid="stBottom"] {
    background: #f9fafb !important;
}
[data-testid="stBottom"] > div {
    background: #f9fafb !important;
}
[data-testid="stChatInput"]:focus-within {
    border-color: #2563eb !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.1) !important;
}
[data-testid="stChatInput"] textarea {
    font-size: 15px !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}

/* ── 데이터프레임 ───────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid #e5e7eb !important;
    border-radius: 12px !important;
    overflow: hidden !important;
    background: #ffffff !important;
}

/* ── 입력 필드 ─────────────────────────────────────────────────── */
[data-testid="stTextInput"] > div > div,
[data-testid="stNumberInput"] input {
    border: 1px solid #e5e7eb !important;
    border-radius: 8px !important;
    background: #ffffff !important;
    color: #111827 !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}
[data-testid="stMultiSelect"] > div > div {
    border: 1px solid #e5e7eb !important;
    border-radius: 8px !important;
    background: #ffffff !important;
}
/* Selectbox */
[data-testid="stSelectbox"] > div > div {
    border: 1px solid #e5e7eb !important;
    border-radius: 8px !important;
    background: #ffffff !important;
    color: #111827 !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] {
    background: #ffffff !important;
    border-color: #e5e7eb !important;
}
[data-testid="stSelectbox"] [data-baseweb="select"] > div {
    background: #ffffff !important;
    color: #111827 !important;
    border-color: #e5e7eb !important;
    border-radius: 8px !important;
}
/* Selectbox selected option text */
[data-testid="stSelectbox"] [data-baseweb="select"] > div > div > div {
    color: #111827 !important;
}
[data-testid="stSelectbox"] div[value] {
    color: #111827 !important;
}
input::placeholder, textarea::placeholder {
    color: #9ca3af !important;
}

/* ── 파일 업로더 ────────────────────────────────────────────────── */
[data-testid="stFileUploaderDropzone"] {
    background: #ffffff !important;
    border: 1.5px dashed #d1d5db !important;
    border-radius: 12px !important;
    transition: border-color 0.15s, background 0.15s;
}
[data-testid="stFileUploaderDropzone"]:hover {
    background: #f0f7ff !important;
    border-color: #2563eb !important;
}
/* Fix upload button text doubling artifact */
[data-testid="stFileUploaderDropzoneButton"],
[data-testid="stFileUploaderDropzone"] button,
[data-testid="stFileUploader"] button {
    background: #f9fafb !important;
    border: 1px solid #e5e7eb !important;
    color: #374151 !important;
    border-radius: 8px !important;
    font-size: 14px !important;
    box-shadow: none !important;
    text-shadow: none !important;
}
/* Hide the material icon "upload" text that doubles the button label */
[data-testid="stFileUploaderDropzone"] button [data-testid="stIconMaterial"] {
    display: none !important;
}
[data-testid="stFileUploaderDropzone"] p,
[data-testid="stFileUploaderDropzone"] small {
    color: #9ca3af !important;
    font-size: 13px !important;
}
/* Hide drag instructions text */
[data-testid="stFileUploaderDropzoneInstructions"] {
    display: none !important;
}
[data-testid="stFileUploaderDropzone"] {
    min-height: 60px !important;
    display: flex !important;
    align-items: center !important;
    padding: 12px 16px !important;
}

/* ── 섹션 제목 ─────────────────────────────────────────────────── */
.section-title {
    font-size: 14px;
    font-weight: 600;
    color: #374151;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    margin-bottom: 12px;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif;
}

/* ── 컨텐츠 카드 ────────────────────────────────────────────────── */
.content-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
}

/* ── 온보딩 카드 ────────────────────────────────────────────────── */
.onboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-top: 24px;
}
.onboard-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 22px 20px;
}
.onboard-card h4 {
    font-size: 0.95rem;
    font-weight: 600;
    color: #111827;
    margin: 0 0 8px;
}
.onboard-card p {
    font-size: 0.85rem;
    color: #6b7280;
    margin: 0;
    line-height: 1.6;
}
.onboard-step {
    display: inline-block;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: #eff6ff;
    color: #2563eb;
    font-size: 0.8rem;
    font-weight: 700;
    text-align: center;
    line-height: 28px;
    margin-bottom: 12px;
}

/* ── 구분선 ─────────────────────────────────────────────────────── */
hr { border-color: #e5e7eb !important; }

/* ── 경고 / 안내 텍스트 ─────────────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 8px !important;
}

/* ── 스크롤바 ───────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 3px; }

/* ── 헤딩 공통 ─────────────────────────────────────────────────── */
h1, h2, h3 {
    color: #111827 !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}
p, span, label, div {
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
}

/* ── 캡션 ──────────────────────────────────────────────────────── */
[data-testid="stCaptionContainer"], .stCaption {
    color: #9ca3af !important;
    font-size: 0.78rem !important;
}

/* ── 상태 배지 ─────────────────────────────────────────────────── */
.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    white-space: nowrap;
}
.status-ok {
    background: #f0fdf4;
    color: #16a34a;
    border: 1px solid #bbf7d0;
}
.status-warn {
    background: #fffbeb;
    color: #d97706;
    border: 1px solid #fde68a;
}
.status-info {
    background: #eff6ff;
    color: #2563eb;
    border: 1px solid #bfdbfe;
}

/* ── 멀티셀렉트 baseweb 내부 모두 화이트 ───────────────────────── */
[data-testid="stMultiSelect"] [data-baseweb="select"],
[data-testid="stMultiSelect"] [data-baseweb="select"] > div,
[data-testid="stMultiSelect"] [data-baseweb="select"] > div > div,
[data-testid="stMultiSelect"] [data-baseweb="input"],
[data-testid="stMultiSelect"] [data-baseweb="base-input"] {
    background: #ffffff !important;
    color: #111827 !important;
    border-color: #e5e7eb !important;
}
[data-testid="stMultiSelect"] * { color: #111827 !important; }
[data-testid="stMultiSelect"] input { color: #111827 !important; background: transparent !important; }
[data-testid="stMultiSelect"] span[data-baseweb="tag"] {
    background: #eff6ff !important;
    color: #2563eb !important;
    border: 1px solid #bfdbfe !important;
    border-radius: 6px !important;
}

/* ── 드롭다운 메뉴 팝업 (body 레벨 포털 포함) ──────────────── */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="popover"] > div > div {
    background: #ffffff !important;
    border: 1px solid #e5e7eb !important;
    border-radius: 8px !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.08) !important;
}
ul[data-baseweb="menu"],
[data-baseweb="menu"] {
    background: #ffffff !important;
    padding: 4px !important;
}
[data-baseweb="option"],
[role="option"],
ul[data-baseweb="menu"] li {
    background: #ffffff !important;
    color: #111827 !important;
    font-size: 14px !important;
    font-family: 'Inter', -apple-system, 'Malgun Gothic', sans-serif !important;
    border-radius: 4px !important;
}
[data-baseweb="option"]:hover,
[role="option"]:hover,
[data-baseweb="option"][aria-selected="true"] {
    background: #f3f4f6 !important;
    color: #111827 !important;
}
/* 멀티셀렉트 체크마크 */
[data-baseweb="option"] svg { color: #2563eb !important; }

/* ── 넘버 인풋 +/- 버튼 ──────────────────────────────────────── */
[data-testid="stNumberInput"] button {
    background: #f9fafb !important;
    border: 1px solid #e5e7eb !important;
    color: #374151 !important;
}

/* ── 셀렉트박스 드롭다운 내부 ────────────────────────────────── */
[data-testid="stSelectbox"] [data-baseweb="menu"],
[data-testid="stSelectbox"] li {
    background: #ffffff !important;
    color: #111827 !important;
}
[data-testid="stSelectbox"] li:hover {
    background: #f3f4f6 !important;
}
</style>
""", unsafe_allow_html=True)


# =============================================================================
# 세션 스테이트 초기화
# =============================================================================
def init_session_state():
    defaults = {
        "llm_provider": "openai",
        "api_key": "",
        "custom_base_url": "",
        "custom_model": "gpt-4o-mini",
        "api_configured": False,
        "df_packets": None,
        "pcap_filename": "",
        "chat_history": [],
        "context_injected": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


# =============================================================================
# pcap 파일 파싱 함수
# =============================================================================
@st.cache_data(show_spinner=False)
def parse_pcap(file_bytes: bytes, filename: str) -> pd.DataFrame:
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, IPv6
    except ImportError:
        st.error("scapy가 설치되지 않았습니다. `pip install scapy` 를 실행하세요.")
        return pd.DataFrame()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        os.unlink(tmp_path)

    rows = []
    base_time = None

    for i, pkt in enumerate(packets):
        ts = float(pkt.time)
        if base_time is None:
            base_time = ts

        proto = "Other"
        sport, dport, info = "", "", ""

        if pkt.haslayer(DNS):
            proto = "DNS"
        elif pkt.haslayer(TCP):
            proto = "TCP"
            sport = str(pkt[TCP].sport)
            dport = str(pkt[TCP].dport)
            flags = pkt[TCP].flags
            flag_str = str(flags)
            info = f"TCP {sport}→{dport} [{flag_str}]"
            known = {80: "HTTP", 443: "HTTPS", 21: "FTP",
                     22: "SSH", 25: "SMTP", 53: "DNS",
                     3306: "MySQL", 5432: "PostgreSQL"}
            for p in [int(sport), int(dport)]:
                if p in known:
                    proto = known[p]
                    break
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = str(pkt[UDP].sport)
            dport = str(pkt[UDP].dport)
            info = f"UDP {sport}→{dport}"
            if int(sport) == 53 or int(dport) == 53:
                proto = "DNS"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp_type = pkt[ICMP].type
            type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                        8: "Echo Request", 11: "Time Exceeded"}
            info = f"ICMP {type_map.get(icmp_type, f'Type {icmp_type}')}"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            info = f"ARP {pkt[ARP].op}"

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            proto = f"IPv6/{proto}" if proto != "Other" else "IPv6"
        else:
            src = pkt.src if hasattr(pkt, 'src') else "N/A"
            dst = pkt.dst if hasattr(pkt, 'dst') else "N/A"

        rows.append({
            "no":            i + 1,
            "time":          datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
            "relative_time": round(ts - base_time, 6),
            "src":           src,
            "dst":           dst,
            "protocol":      proto,
            "length":        len(pkt),
            "sport":         sport,
            "dport":         dport,
            "info":          info if info else proto,
        })

    df = pd.DataFrame(rows)
    return df


# =============================================================================
# AI 컨텍스트 생성 함수
# =============================================================================
def build_packet_context(df: pd.DataFrame) -> str:
    if df is None or df.empty:
        return "패킷 데이터 없음"

    total = len(df)
    proto_dist = df["protocol"].value_counts().head(10).to_dict()
    top_src = df["src"].value_counts().head(5).to_dict()
    top_dst = df["dst"].value_counts().head(5).to_dict()

    suspicious_hints = []
    if "TCP" in df["protocol"].values:
        tcp_df = df[df["protocol"] == "TCP"]
        if len(tcp_df) > 0:
            syn_ratio = tcp_df["info"].str.contains("S", na=False).mean()
            rst_count = tcp_df["info"].str.contains("R", na=False).sum()
            if syn_ratio > 0.7:
                suspicious_hints.append(f"SYN 패킷 비율 {syn_ratio:.0%} — SYN Flood 의심")
            if rst_count > 50:
                suspicious_hints.append(f"RST 패킷 {rst_count}개 — 연결 거부/스캔 의심")

    time_range = ""
    if "relative_time" in df.columns and total > 1:
        duration = df["relative_time"].max()
        pps = round(total / duration, 1) if duration > 0 else 0
        time_range = f"캡처 기간: {duration:.2f}초 / 평균 {pps} pps"

    ctx = f"""
=== 업로드된 pcap 파일 요약 ===
파일명: {st.session_state.get('pcap_filename', 'unknown')}
총 패킷 수: {total:,}
출발지 IP 수: {df['src'].nunique()}
목적지 IP 수: {df['dst'].nunique()}
{time_range}

[프로토콜 분포 (상위 10)]
{chr(10).join(f'  {k}: {v}개 ({v/total:.1%})' for k, v in proto_dist.items())}

[출발지 IP 상위 5]
{chr(10).join(f'  {k}: {v}패킷' for k, v in top_src.items())}

[목적지 IP 상위 5]
{chr(10).join(f'  {k}: {v}패킷' for k, v in top_dst.items())}

[평균 패킷 길이] {df['length'].mean():.1f} bytes
[최대 패킷 길이] {df['length'].max()} bytes

[이상 징후 힌트]
{chr(10).join(suspicious_hints) if suspicious_hints else '  특이사항 없음'}
""".strip()

    return ctx


# =============================================================================
# LLM API 호출 함수
# =============================================================================
def call_llm(messages: list) -> str:
    provider = st.session_state["llm_provider"]
    api_key  = st.session_state["api_key"]

    if not api_key:
        return "API 키가 설정되지 않았습니다. [API 설정] 탭에서 키를 입력하세요."

    if provider == "openai":
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                max_tokens=2000,
                temperature=0.3,
            )
            return resp.choices[0].message.content
        except ImportError:
            return "openai 패키지 미설치: `pip install openai`"
        except Exception as e:
            return f"OpenAI 오류: {e}"

    elif provider == "anthropic":
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            system_msg = ""
            chat_msgs = []
            for m in messages:
                if m["role"] == "system":
                    system_msg = m["content"]
                else:
                    chat_msgs.append({"role": m["role"], "content": m["content"]})

            resp = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=2000,
                system=system_msg if system_msg else "You are a helpful assistant.",
                messages=chat_msgs,
            )
            return resp.content[0].text
        except ImportError:
            return "anthropic 패키지 미설치: `pip install anthropic`"
        except Exception as e:
            return f"Claude 오류: {e}"

    elif provider == "custom":
        try:
            from openai import OpenAI
            base_url = st.session_state.get("custom_base_url", "").strip()
            model    = st.session_state.get("custom_model", "gpt-4o-mini").strip()
            if not base_url:
                return "커스텀 API의 Base URL을 설정하세요."
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=2000,
                temperature=0.3,
            )
            return resp.choices[0].message.content
        except ImportError:
            return "openai 패키지 미설치: `pip install openai`"
        except Exception as e:
            return f"커스텀 API 오류: {e}"

    return "지원하지 않는 LLM 공급자입니다."


# =============================================================================
# 시스템 프롬프트 생성
# =============================================================================
def build_system_prompt(packet_context: str) -> str:
    return f"""당신은 네트워크 보안 및 패킷 분석 전문가 AI 'PacketAI'입니다.
사용자가 업로드한 pcap 파일을 분석하여 아래 3가지 영역에서 전문적인 인사이트를 제공하세요.

전문 분석 영역 1: 네트워크 문제 해결
  - 통신 장애의 원인 파악 (라우팅 문제, ARP 브로드캐스트 폭주 등)
  - 패킷 손실(Packet Loss) 징후 탐지 (TCP 재전송, 중복 ACK 등)
  - 레이턴시(지연) 유발 구간 진단 (RTT 측정, TCP Window 크기 분석)

전문 분석 영역 2: 보안 및 악성코드 분석
  - 비정상적인 트래픽 패턴 탐지 (포트 스캔, DDoS, SYN Flood)
  - 외부 해킹 시도 및 침투 흔적 분석
  - 악성코드 C&C(Command & Control) 서버 통신 내역 탐지 및 경고
  - DNS Tunneling, 데이터 유출(Data Exfiltration) 패턴 확인

전문 분석 영역 3: 개발 및 디버깅
  - 네트워크 프로토콜 개발 검증 (요청/응답 패턴 확인)
  - API 통신 세션 오류 분석 (TCP 3-Way Handshake 실패, TLS 협상 오류)
  - HTTP/HTTPS 통신 이상 탐지 (비정상 상태 코드, 응답 지연 등)

답변 원칙:
1. 한국어로 답변하되, 기술 용어는 영문 원어를 병기하세요.
2. 구체적인 IP 주소, 포트 번호, 패킷 수 등 데이터 기반 근거를 제시하세요.
3. 발견된 이상 징후는 위험도(낮음/중간/높음)를 표시하세요.
4. 대응 방안 또는 추가 확인이 필요한 사항을 제안하세요.

현재 분석 중인 패킷 데이터 컨텍스트:
{packet_context}
"""


# =============================================================================
# 앱 상단 타이틀
# =============================================================================
df_packets  = st.session_state["df_packets"]
api_ok      = st.session_state["api_configured"]
pcap_name   = st.session_state.get("pcap_filename", "")
provider_lbl = {
    "openai":    "ChatGPT",
    "anthropic": "Claude",
    "custom":    "커스텀 API",
}.get(st.session_state.get("llm_provider", ""), "")

# 상태 배지 HTML
badges_html = ""
if api_ok:
    badges_html += f'<span class="status-badge status-ok">{provider_lbl} 연결됨</span>'
else:
    badges_html += '<span class="status-badge status-warn">API 미설정</span>'
if pcap_name:
    short_name = pcap_name if len(pcap_name) <= 28 else pcap_name[:26] + "…"
    badges_html += f'&nbsp;&nbsp;<span class="status-badge status-info">{short_name}</span>'

st.markdown(f"""
<div style="background:#ffffff;border-bottom:1px solid #e5e7eb;
            padding:16px 0 0;margin-bottom:0;">
  <div style="display:flex;justify-content:space-between;align-items:center;
              flex-wrap:wrap;gap:10px;padding-bottom:14px;">
    <h1 style="font-size:1.2rem;font-weight:700;color:#111827;margin:0;
               font-family:'Inter',-apple-system,'Malgun Gothic',sans-serif;
               letter-spacing:-0.02em;">
      KDN 패킷 분석기
    </h1>
    <div style="display:flex;align-items:center;gap:8px;">{badges_html}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# =============================================================================
# 메인 탭 네비게이션
# =============================================================================
tab_dash, tab_chat, tab_api = st.tabs(["대시보드", "패킷 분석기", "API 설정"])


# =============================================================================
# 탭 1: 대시보드
# =============================================================================
with tab_dash:

    # ── 파일 업로드 ─────────────────────────────────────────────────
    col_upload, col_status = st.columns([3, 1])
    with col_upload:
        uploaded_file = st.file_uploader(
            "pcap / pcapng 파일 업로드",
            type=["pcap", "pcapng", "cap"],
            help="Wireshark 등으로 캡처한 패킷 파일을 업로드하세요.",
            label_visibility="collapsed",
        )
    with col_status:
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            file_size_kb = len(file_bytes) / 1024
            st.markdown(
                f'<p style="font-size:13px;color:#374151;margin:8px 0 4px;font-weight:500;">'
                f'{uploaded_file.name}</p>'
                f'<p style="font-size:12px;color:#9ca3af;margin:0;">{file_size_kb:.1f} KB</p>',
                unsafe_allow_html=True
            )
            if st.session_state["pcap_filename"] != uploaded_file.name:
                with st.spinner("패킷 파싱 중..."):
                    df = parse_pcap(file_bytes, uploaded_file.name)
                    st.session_state["df_packets"]       = df
                    st.session_state["pcap_filename"]    = uploaded_file.name
                    st.session_state["chat_history"]     = []
                    st.session_state["context_injected"] = False
                st.rerun()

    # ── 데이터 없을 때 온보딩 ────────────────────────────────────────
    df_packets = st.session_state["df_packets"]
    if df_packets is None or df_packets.empty:
        st.markdown("""
        <div style="margin:32px 0 8px;">
          <p style="font-size:1rem;font-weight:600;color:#111827;margin:0 0 6px;">
            패킷 파일을 업로드하여 분석을 시작하세요
          </p>
          <p style="font-size:0.88rem;color:#6b7280;margin:0 0 24px;">
            pcap 또는 pcapng 형식의 파일을 위 영역에 드래그하거나 클릭하여 선택하세요.
          </p>
        </div>
        <div class="onboard-grid">
          <div class="onboard-card">
            <div class="onboard-step">1</div>
            <h4>파일 업로드</h4>
            <p>Wireshark 또는 tcpdump로 캡처한 pcap / pcapng 파일을 업로드하세요.</p>
          </div>
          <div class="onboard-card">
            <div class="onboard-step">2</div>
            <h4>트래픽 시각화</h4>
            <p>KPI 지표, 트래픽 트렌드 차트, 패킷 테이블로 데이터를 한눈에 확인하세요.</p>
          </div>
          <div class="onboard-card">
            <div class="onboard-step">3</div>
            <h4>AI 보안 분석</h4>
            <p>패킷 분석기 탭에서 AI에게 보안 위협, 성능 이슈, 통신 오류를 질문하세요.</p>
          </div>
        </div>
        <p style="font-size:0.8rem;color:#9ca3af;margin-top:20px;text-align:center;">
          샘플 파일:
          <a href="https://wiki.wireshark.org/SampleCaptures" target="_blank"
             style="color:#2563eb;text-decoration:underline;">
            Wireshark Sample Captures
          </a>
        </p>
        """, unsafe_allow_html=True)
    else:
        # ── KPI 메트릭 ────────────────────────────────────────────────
        total_packets = len(df_packets)
        unique_src    = df_packets["src"].nunique()
        unique_dst    = df_packets["dst"].nunique()
        unique_proto  = df_packets["protocol"].nunique()
        avg_pkt_size  = round(df_packets["length"].mean(), 1)
        duration      = df_packets["relative_time"].max() if "relative_time" in df_packets.columns else 0
        pps           = round(total_packets / duration, 1) if duration > 0 else 0

        kpi_cols = st.columns(6)
        kpi_data = [
            ("총 패킷 수",  f"{total_packets:,}"),
            ("출발지 IP",   f"{unique_src:,}"),
            ("목적지 IP",   f"{unique_dst:,}"),
            ("프로토콜",    f"{unique_proto}"),
            ("평균 크기",   f"{avg_pkt_size} B"),
            ("PPS",         f"{pps}"),
        ]
        for col, (label, value) in zip(kpi_cols, kpi_data):
            with col:
                st.metric(label, value)

        st.markdown('<div style="margin-bottom:8px;"></div>', unsafe_allow_html=True)

        # ── 트래픽 트렌드 차트 (1개만) ───────────────────────────────
        st.markdown('<p style="font-size:12px;font-weight:600;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin:16px 0 8px;">트래픽 트렌드</p>', unsafe_allow_html=True)
        df_time = df_packets.copy()
        # Use millisecond buckets for short captures, second buckets for longer ones
        time_range_val = df_packets["relative_time"].max() if "relative_time" in df_packets.columns else 0
        if time_range_val < 2.0 and time_range_val > 0:
            # Use 100ms buckets
            df_time["bucket"] = (df_time["relative_time"] * 10).astype(int) / 10.0
            x_label = "경과 시간 (초)"
        else:
            df_time["bucket"] = df_time["relative_time"].astype(int)
            x_label = "경과 시간 (초)"
        traffic_trend = df_time.groupby("bucket").size().reset_index(name="packets")
        traffic_trend = traffic_trend.rename(columns={"bucket": "second"})

        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=traffic_trend["second"],
            y=traffic_trend["packets"],
            mode="lines",
            fill="tozeroy",
            line=dict(color="#2563eb", width=2),
            fillcolor="rgba(37,99,235,0.08)",
            name="패킷 수",
        ))
        fig_trend.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#ffffff",
            font=dict(
                family="Inter, -apple-system, sans-serif",
                color="#6b7280",
                size=12,
            ),
            xaxis=dict(
                title=x_label,
                gridcolor="#f3f4f6",
                linecolor="#e5e7eb",
                tickcolor="#e5e7eb",
                zeroline=False,
                title_font=dict(size=12, color="#6b7280"),
            ),
            yaxis=dict(
                title="패킷 수",
                gridcolor="#f3f4f6",
                linecolor="#e5e7eb",
                tickcolor="#e5e7eb",
                zeroline=False,
                title_font=dict(size=12, color="#6b7280"),
            ),
            margin=dict(t=12, b=40, l=60, r=16),
            height=260,
            showlegend=False,
        )
        st.plotly_chart(fig_trend, use_container_width=True)

        # ── 패킷 테이블 필터 ─────────────────────────────────────────
        st.markdown('<p style="font-size:12px;font-weight:600;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin:20px 0 8px;">패킷 테이블</p>', unsafe_allow_html=True)
        col_f1, col_f2, col_f3 = st.columns([2, 2, 1])
        with col_f1:
            proto_filter = st.multiselect(
                "프로토콜 필터",
                options=sorted(df_packets["protocol"].unique()),
                default=[],
                placeholder="프로토콜 선택",
            )
        with col_f2:
            src_filter = st.text_input(
                "출발지 IP 검색",
                placeholder="예: 192.168.1.1",
            )
        with col_f3:
            max_rows = st.number_input(
                "최대 행",
                min_value=50, max_value=5000, value=200, step=50,
            )

        df_view = df_packets.copy()
        if proto_filter:
            df_view = df_view[df_view["protocol"].isin(proto_filter)]
        if src_filter.strip():
            df_view = df_view[df_view["src"].str.contains(src_filter.strip(), na=False)]

        st.dataframe(
            df_view.head(max_rows),
            use_container_width=True,
            hide_index=True,
            column_config={
                "no":       st.column_config.NumberColumn("No.", width=60),
                "time":     st.column_config.TextColumn("시간", width=110),
                "src":      st.column_config.TextColumn("출발지"),
                "dst":      st.column_config.TextColumn("목적지"),
                "protocol": st.column_config.TextColumn("프로토콜", width=100),
                "length":   st.column_config.NumberColumn("크기(B)", width=80),
                "info":     st.column_config.TextColumn("정보"),
            },
            height=400,
        )
        st.caption(f"전체 {total_packets:,}개 중 {min(len(df_view), max_rows):,}개 표시")


# =============================================================================
# 탭 2: 패킷 분석기 (AI 챗봇)
# =============================================================================
with tab_chat:

    # ── API 미설정 안내 ──────────────────────────────────────────────
    if not st.session_state["api_configured"]:
        st.markdown(
            '<p style="font-size:14px;color:#d97706;margin-bottom:16px;">'
            'API 키가 설정되지 않았습니다. [API 설정] 탭에서 LLM을 선택하고 API 키를 입력하세요.'
            '</p>',
            unsafe_allow_html=True
        )

    # ── 빠른 질문 버튼 ───────────────────────────────────────────────
    st.markdown('<p style="font-size:12px;font-weight:600;color:#374151;letter-spacing:0.06em;text-transform:uppercase;margin:0 0 8px;">빠른 질문</p>', unsafe_allow_html=True)
    quick_col1, quick_col2 = st.columns(2)
    quick_questions = [
        "트래픽 전체 요약",
        "보안 위협 탐지",
        "성능 문제 진단",
        "TCP 오류 분석",
    ]
    quick_triggered = None
    with quick_col1:
        if st.button(quick_questions[0], use_container_width=True):
            quick_triggered = quick_questions[0]
        if st.button(quick_questions[2], use_container_width=True):
            quick_triggered = quick_questions[2]
    with quick_col2:
        if st.button(quick_questions[1], use_container_width=True):
            quick_triggered = quick_questions[1]
        if st.button(quick_questions[3], use_container_width=True):
            quick_triggered = quick_questions[3]

    st.markdown('<hr style="margin:16px 0;">', unsafe_allow_html=True)

    # ── 채팅 이력 표시 ───────────────────────────────────────────────
    chat_container = st.container(height=440)
    with chat_container:
        if not st.session_state["chat_history"]:
            st.markdown("""
            <div style="display:flex;flex-direction:column;align-items:center;
                        justify-content:center;padding:60px 20px;text-align:center;">
              <div style="width:48px;height:48px;border-radius:12px;
                          background:#eff6ff;display:flex;align-items:center;
                          justify-content:center;margin-bottom:16px;">
                <svg width="24" height="24" fill="none" viewBox="0 0 24 24"
                     style="color:#2563eb;">
                  <path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8
                           a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3
                           13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                        stroke="#2563eb" stroke-width="2" stroke-linecap="round"
                        stroke-linejoin="round"/>
                </svg>
              </div>
              <p style="font-size:0.95rem;font-weight:600;color:#111827;margin:0 0 8px;">
                패킷 분석기
              </p>
              <p style="font-size:0.85rem;color:#6b7280;margin:0;
                        max-width:280px;line-height:1.65;">
                위의 빠른 질문을 클릭하거나 직접 질문을 입력하여 AI 보안 분석을 시작하세요.
              </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            for msg in st.session_state["chat_history"]:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

    # ── 채팅 입력 ────────────────────────────────────────────────────
    user_input = st.chat_input(
        "네트워크 보안 분석을 요청하세요...",
        disabled=not st.session_state["api_configured"],
    )

    if quick_triggered:
        user_input = quick_triggered

    if user_input:
        st.session_state["chat_history"].append({"role": "user", "content": user_input})

        df_packets = st.session_state["df_packets"]
        packet_context = build_packet_context(df_packets)
        system_prompt  = build_system_prompt(packet_context)

        api_messages = [{"role": "system", "content": system_prompt}]
        recent_history = st.session_state["chat_history"][-10:]
        api_messages.extend(recent_history)

        with st.spinner("분석 중..."):
            response = call_llm(api_messages)

        st.session_state["chat_history"].append({"role": "assistant", "content": response})
        st.rerun()


# =============================================================================
# 탭 3: API 설정
# =============================================================================
with tab_api:

    # ── 현재 상태 ────────────────────────────────────────────────────
    if st.session_state["api_configured"]:
        provider_label = {
            "openai":    "OpenAI GPT-4o-mini",
            "anthropic": "Claude Anthropic",
            "custom":    "커스텀 API",
        }.get(st.session_state["llm_provider"], "알 수 없음")
        st.markdown(
            f'<p style="font-size:14px;color:#16a34a;margin-bottom:20px;">'
            f'{provider_label} — 연결됨</p>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<p style="font-size:14px;color:#6b7280;margin-bottom:20px;">'
            'API 키가 설정되지 않았습니다.</p>',
            unsafe_allow_html=True
        )

    # ── 설정 폼 ──────────────────────────────────────────────────────
    provider_options = ["OpenAI GPT-4o-mini", "Claude Anthropic", "커스텀 API"]
    provider_map = {
        "OpenAI GPT-4o-mini": "openai",
        "Claude Anthropic":   "anthropic",
        "커스텀 API":          "custom",
    }
    provider_reverse_map = {v: k for k, v in provider_map.items()}

    current_provider_label = provider_reverse_map.get(
        st.session_state["llm_provider"], "OpenAI GPT-4o-mini"
    )

    selected_label = st.selectbox(
        "AI 모델",
        options=provider_options,
        index=provider_options.index(current_provider_label),
    )
    selected_provider = provider_map[selected_label]

    api_key_input = st.text_input(
        "API Key",
        value=st.session_state["api_key"],
        type="password",
        placeholder={
            "openai":    "sk-...",
            "anthropic": "sk-ant-...",
            "custom":    "Bearer 토큰 또는 API 키",
        }.get(selected_provider, ""),
    )

    custom_base_url = st.session_state.get("custom_base_url", "")
    custom_model    = st.session_state.get("custom_model", "gpt-4o-mini")

    if selected_provider == "custom":
        custom_base_url = st.text_input(
            "Base URL",
            value=custom_base_url,
            placeholder="https://api.example.com/v1",
        )
        custom_model = st.text_input(
            "모델 이름",
            value=custom_model,
            placeholder="gpt-4o-mini",
        )

    st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)

    col_save, col_reset = st.columns([1, 1])
    with col_save:
        if st.button("저장", type="primary", use_container_width=True):
            if not api_key_input.strip():
                st.error("API 키를 입력하세요.")
            else:
                st.session_state["llm_provider"]    = selected_provider
                st.session_state["api_key"]         = api_key_input.strip()
                st.session_state["custom_base_url"] = custom_base_url.strip() if selected_provider == "custom" else ""
                st.session_state["custom_model"]    = custom_model.strip() if selected_provider == "custom" else "gpt-4o-mini"
                st.session_state["api_configured"]  = True
                st.success("저장되었습니다.")
                st.rerun()
    with col_reset:
        if st.button("초기화", use_container_width=True):
            st.session_state["api_key"]        = ""
            st.session_state["api_configured"] = False
            st.rerun()
