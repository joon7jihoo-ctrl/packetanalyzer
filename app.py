# =============================================================================
# pcap 네트워크 패킷 분석 및 멀티 LLM 질의응답 대시보드
# KDN Vibe Coding 과정 - Python Streamlit AI 앱 개발
# =============================================================================
# 실행 방법:
#   pip install streamlit scapy pandas plotly openai anthropic
#   streamlit run app.py
# =============================================================================

import streamlit as st
import streamlit.components.v1 as components
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
    page_title="KDN 패킷 분석 대시보드",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="auto",
)

# ─── 커스텀 CSS (Pulse 대시보드 스타일) ──────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ════════════════════════════════════════════════════
   Pulse 디자인 토큰
   ════════════════════════════════════════════════════ */
:root {
    --bg:        #0b0e17;
    --side:      #11141d;
    --card:      #161a25;
    --card-h:    #1c2130;
    --border:    #232838;
    --text:      #e7e9ee;
    --text-dim:  #a4abbb;
    --text-mute: #6b7387;
    --accent:    #6366f1;
    --accent-2:  #22d3ee;
    --accent-s:  rgba(99,102,241,0.15);
    --success:   #22c55e;
    --warn:      #f59e0b;
    --danger:    #ef4444;
    --fs-xs:    clamp(0.70rem, 1.4vw, 0.75rem);
    --fs-sm:    clamp(0.80rem, 1.7vw, 0.85rem);
    --fs-base:  clamp(0.88rem, 1.9vw, 0.92rem);
    --fs-md:    clamp(0.95rem, 2.1vw, 1.0rem);
    --fs-lg:    clamp(1.15rem, 2.8vw, 1.4rem);
    --fs-xl:    clamp(1.3rem,  3.5vw, 1.6rem);
    --sp-xs: 6px;  --sp-sm: 12px; --sp-md: 18px; --sp-lg: 26px;
    --r-sm: 8px;   --r-md: 12px;  --r-lg: 16px;
    --touch: 44px;
    --ease: 0.15s ease;
}

/* ════════════════════════════════════════════════════
   기본 리셋
   ════════════════════════════════════════════════════ */
*, *::before, *::after { box-sizing: border-box; }
html, body, .stApp {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Inter', 'Pretendard', -apple-system, system-ui, sans-serif !important;
    font-size: var(--fs-base);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
}
.main .block-container,
div.block-container,
[data-testid="stAppViewBlockContainer"] {
    padding: var(--sp-md) var(--sp-lg) var(--sp-lg) !important;
    max-width: 1480px !important;
}

/* ════════════════════════════════════════════════════
   사이드바
   ════════════════════════════════════════════════════ */
[data-testid="stSidebar"] {
    background-color: var(--side) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] section { padding-top: var(--sp-sm) !important; }
[data-testid="stSidebar"] * { color: var(--text) !important; }
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span { color: var(--text-dim) !important; }
[data-testid="stSidebar"] hr { border-color: var(--border) !important; margin: var(--sp-sm) 0 !important; }
[data-testid="stSidebar"] h2 {
    color: var(--text) !important;
    font-size: var(--fs-md) !important;
    font-weight: 700 !important;
    letter-spacing: -0.01em;
}

/* 사이드바 브랜드 */
.pulse-brand {
    display: flex; align-items: center; gap: 10px;
    font-weight: 800; font-size: 1.05rem;
    padding: 4px 0 18px; letter-spacing: -.01em;
    color: var(--text) !important;
}
.pulse-mark {
    width: 24px; height: 24px; border-radius: 7px; flex-shrink: 0;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
}

/* ── 사이드바 네비게이션 ── */
.pulse-nav {
    display: flex; flex-direction: column; gap: 2px;
    margin-bottom: 16px;
}
.pulse-nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 9px 12px; border-radius: 8px;
    color: var(--text-dim); font-size: .88rem;
    font-family: inherit; font-weight: 400;
    cursor: pointer; transition: background .15s, color .15s;
    letter-spacing: 0; user-select: none;
}
.pulse-nav-item:hover {
    background: rgba(255,255,255,.04);
    color: var(--text);
}
.pulse-nav-item.active {
    background: rgba(99,102,241,.15);
    color: var(--accent);
    font-weight: 600;
}
.pulse-nav-item .nav-icon {
    font-size: 1rem; width: 20px; text-align: center; flex-shrink: 0;
}
.pulse-nav-divider {
    height: 1px; background: var(--border);
    margin: 8px 4px; border: none;
}

/* 파일 업로더 */
[data-testid="stFileUploaderDropzone"] {
    background: rgba(255,255,255,0.03) !important;
    border: 1.5px dashed var(--border) !important;
    border-radius: var(--r-md) !important;
    transition: border-color var(--ease), background var(--ease);
}
[data-testid="stFileUploaderDropzone"]:hover {
    background: rgba(99,102,241,0.06) !important;
    border-color: var(--accent) !important;
}
[data-testid="stFileUploaderDropzone"] * { color: var(--text-mute) !important; }
[data-testid="stFileUploaderDropzoneButton"],
[data-testid="stFileUploaderDropzone"] button,
[data-testid="stFileUploader"] button,
section[data-testid="stFileUploader"] button {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-dim) !important;
    border-radius: var(--r-sm) !important;
    min-height: var(--touch) !important;
    font-size: var(--fs-sm) !important;
    transition: all var(--ease) !important;
}
[data-testid="stFileUploaderDropzone"] button:hover,
[data-testid="stFileUploader"] button:hover {
    border-color: var(--accent) !important;
    background: var(--accent-s) !important;
    color: var(--accent) !important;
}
[data-testid="stFileUploaderFile"] {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--r-sm) !important;
}
[data-testid="stFileUploaderFile"] * { color: var(--text) !important; }

/* ════════════════════════════════════════════════════
   버튼
   ════════════════════════════════════════════════════ */
.stButton button {
    min-height: var(--touch) !important;
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text-dim) !important;
    border-radius: var(--r-sm) !important;
    font-size: var(--fs-sm) !important;
    font-weight: 500 !important;
    padding: 7px 14px !important;
    transition: all var(--ease) !important;
    font-family: inherit !important;
    cursor: pointer;
}
.stButton button:hover {
    background: var(--card-h) !important;
    color: var(--text) !important;
    border-color: var(--accent) !important;
}
.stButton button[kind="primary"] {
    background: var(--accent) !important;
    border-color: var(--accent) !important;
    color: #fff !important;
    font-weight: 600 !important;
}
.stButton button[kind="primary"]:hover {
    background: #5254d4 !important;
    border-color: #5254d4 !important;
}

/* ════════════════════════════════════════════════════
   Pulse 헤더 (Topbar)
   ════════════════════════════════════════════════════ */
.pulse-topbar {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: var(--sp-md);
}
.pulse-topbar-left h1 {
    margin: 0 0 3px;
    font-size: var(--fs-xl) !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em;
    color: var(--text) !important;
}
.pulse-topbar-left p {
    margin: 0;
    color: var(--text-mute);
    font-size: var(--fs-sm);
}
.pulse-topbar-right {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.pulse-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 5px 11px; border-radius: 999px;
    font-size: var(--fs-xs); font-weight: 600;
    letter-spacing: 0.2px; white-space: nowrap;
    border: 1px solid transparent;
}
.pulse-badge--ok   { background: rgba(34,197,94,.12); color: #4ade80; border-color: rgba(34,197,94,.25); }
.pulse-badge--warn { background: rgba(245,158,11,.12); color: #fbbf24; border-color: rgba(245,158,11,.25); }
.pulse-badge--info { background: var(--accent-s); color: #a5b4fc; border-color: rgba(99,102,241,.3); }

/* ════════════════════════════════════════════════════
   KPI 카드
   ════════════════════════════════════════════════════ */
[data-testid="stMetric"] {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--r-md) !important;
    padding: var(--sp-md) !important;
    transition: border-color var(--ease), background var(--ease);
}
[data-testid="stMetric"]:hover {
    border-color: var(--accent) !important;
    background: var(--card-h) !important;
}
[data-testid="stMetricValue"] {
    color: var(--text) !important;
    font-weight: 700 !important;
    font-size: var(--fs-lg) !important;
    letter-spacing: -0.01em;
}
[data-testid="stMetricLabel"] {
    color: var(--text-mute) !important;
    font-size: var(--fs-xs) !important;
    font-weight: 400 !important;
    letter-spacing: 0.01em;
}

/* ════════════════════════════════════════════════════
   탭
   ════════════════════════════════════════════════════ */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important; padding: 0 !important; border-radius: 0 !important;
    overflow-x: auto; -webkit-overflow-scrolling: touch;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    min-height: var(--touch) !important;
    font-size: var(--fs-sm) !important;
    font-weight: 500 !important;
    color: var(--text-dim) !important;
    background: transparent !important;
    border-radius: 0 !important;
    border-bottom: 2px solid transparent !important;
    padding: 10px 20px !important;
    margin-bottom: -1px;
    transition: color var(--ease), border-color var(--ease);
    white-space: nowrap; font-family: inherit !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover { color: var(--text) !important; }
[data-testid="stTabs"] [aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
    font-weight: 600 !important;
    background: transparent !important;
}

/* ════════════════════════════════════════════════════
   카드
   ════════════════════════════════════════════════════ */
.pulse-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: var(--sp-md) var(--sp-md) var(--sp-sm);
    margin-bottom: var(--sp-sm);
}
.pulse-card-head {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: var(--sp-sm);
}
.pulse-card-title {
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text);
    letter-spacing: -0.01em;
    margin: 0;
}
.pulse-card-sub {
    color: var(--text-mute);
    font-size: var(--fs-xs);
}

/* 필터 바 */
.pulse-filter {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: var(--sp-sm) var(--sp-md);
    margin-bottom: var(--sp-sm);
    display: flex; align-items: center; gap: 8px;
}
.pulse-filter-label {
    font-size: var(--fs-xs);
    font-weight: 600;
    color: var(--text-mute);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    white-space: nowrap;
    flex-shrink: 0;
}

/* ════════════════════════════════════════════════════
   입력 필드
   ════════════════════════════════════════════════════ */
[data-testid="stMultiSelect"] > div > div,
[data-testid="stTextInput"] > div > div > input,
[data-testid="stNumberInput"] input {
    background: var(--bg) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--r-sm) !important;
    color: var(--text) !important;
    font-size: var(--fs-sm) !important;
    min-height: var(--touch) !important;
    font-family: inherit !important;
}
[data-testid="stTextInput"] > div > div:focus-within,
[data-testid="stMultiSelect"] > div > div:focus-within,
[data-testid="stNumberInput"]:focus-within {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px var(--accent-s) !important;
}
input::placeholder, textarea::placeholder { color: var(--text-mute) !important; }
[data-testid="stMultiSelect"] span[data-baseweb="tag"] {
    background: var(--accent-s) !important;
    border: 1px solid rgba(99,102,241,.4) !important;
    color: #a5b4fc !important;
    border-radius: 6px !important;
    font-size: var(--fs-xs) !important;
}

/* 라디오 */
[data-testid="stRadio"] label span { color: var(--text) !important; }
[data-testid="stRadio"] [data-baseweb="radio"] div { border-color: var(--border) !important; }

/* ════════════════════════════════════════════════════
   채팅 AI 탭
   ════════════════════════════════════════════════════ */
[data-testid="stChatInput"] {
    background: var(--card) !important;
    border: 1.5px solid var(--border) !important;
    border-radius: var(--r-lg) !important;
    transition: border-color var(--ease), box-shadow var(--ease);
}
[data-testid="stChatInput"]:focus-within {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px var(--accent-s) !important;
}
[data-testid="stChatInput"] textarea {
    background: transparent !important;
    border: none !important;
    color: var(--text) !important;
    font-family: inherit !important;
}
[data-testid="stChatInput"] textarea::placeholder { color: var(--text-mute) !important; }
[data-testid="stChatMessage"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 1px solid var(--border) !important;
    border-radius: 0 !important;
    padding: var(--sp-md) 0 !important;
}
[data-testid="stChatMessage"]:last-child { border-bottom: none !important; }

/* ════════════════════════════════════════════════════
   Expander
   ════════════════════════════════════════════════════ */
[data-testid="stExpander"] {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--r-md) !important;
}
[data-testid="stExpander"]:hover { border-color: var(--accent) !important; }
[data-testid="stExpander"] summary {
    min-height: var(--touch) !important; color: var(--text) !important;
    font-weight: 500 !important; font-size: var(--fs-sm) !important;
    display: flex; align-items: center;
}

/* ════════════════════════════════════════════════════
   데이터프레임
   ════════════════════════════════════════════════════ */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--r-md) !important;
    overflow: hidden !important;
}
[data-testid="stDataFrame"] th {
    background: var(--card) !important;
    color: var(--text-mute) !important;
    font-size: var(--fs-xs) !important;
    text-transform: uppercase; letter-spacing: 0.04em;
    border-bottom: 1px solid var(--border) !important;
    padding: 8px 12px !important;
    font-weight: 500 !important;
}
[data-testid="stDataFrame"] td {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-size: var(--fs-sm) !important;
    border-bottom: 1px solid var(--border) !important;
}
[data-testid="stDataFrame"] tr:hover td { background: var(--card) !important; }

/* ════════════════════════════════════════════════════
   알림 박스
   ════════════════════════════════════════════════════ */
.alert-box {
    background: rgba(245,158,11,.08);
    border: 1px solid rgba(245,158,11,.3);
    border-left: 3px solid var(--warn);
    border-radius: var(--r-sm);
    padding: 10px 14px;
    color: #fbbf24;
    font-size: var(--fs-sm);
    margin: 6px 0;
}
.info-box {
    background: var(--accent-s);
    border: 1px solid rgba(99,102,241,.28);
    border-left: 3px solid var(--accent);
    border-radius: var(--r-sm);
    padding: 10px 14px;
    color: #a5b4fc;
    font-size: var(--fs-sm);
    margin: 6px 0;
}
.info-box a { color: var(--accent-2) !important; text-decoration: underline; }
[data-testid="stAlert"] { border-radius: var(--r-sm) !important; border-left-width: 3px !important; }

/* ════════════════════════════════════════════════════
   텍스트 / 헤딩
   ════════════════════════════════════════════════════ */
h1, h2, h3 { color: var(--text) !important; font-weight: 600 !important; letter-spacing: -0.01em; }
[data-testid="stSubheader"] { font-size: var(--fs-md) !important; color: var(--text) !important; }
[data-testid="stSubheader"] p { font-size: var(--fs-md) !important; }
[data-testid="stCaptionContainer"], .stCaption { color: var(--text-mute) !important; font-size: var(--fs-xs) !important; }
hr { border-color: var(--border) !important; margin: 10px 0 !important; }

/* Dialog */
[data-testid="stModal"] > div {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--r-lg) !important;
    color: var(--text) !important;
}

/* 스크롤바 */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ════════════════════════════════════════════════════
   Streamlit 불필요 요소 제거
   ════════════════════════════════════════════════════ */
footer, #MainMenu, [data-testid="stToolbar"],
[data-testid="stDecoration"], [data-testid="stStatusWidget"] { display: none !important; }
header[data-testid="stHeader"] {
    background: transparent !important; border-bottom: none !important;
    height: 0 !important; min-height: 0 !important;
    padding: 0 !important; overflow: hidden !important;
}
.appview-container > section.main { padding-top: 0 !important; }
.main .block-container,
div.block-container,
[data-testid="stAppViewBlockContainer"] { padding-top: var(--sp-md) !important; }

/* ════════════════════════════════════════════════════
   반응형
   ════════════════════════════════════════════════════ */
@media (max-width: 1024px) {
    .main .block-container { padding: var(--sp-sm) var(--sp-md) !important; }
    .pulse-topbar { flex-direction: column; align-items: flex-start; }
}
@media (max-width: 640px) {
    .main .block-container { padding: 8px 12px !important; }
    .pulse-topbar-left h1 { font-size: 1.25rem !important; }
    .stButton button { min-height: 48px !important; }
    [data-testid="stTabs"] [data-baseweb="tab"] { padding: 8px 12px !important; }
    [data-testid="stDataFrame"] td,
    [data-testid="stDataFrame"] th { font-size: 0.73rem !important; }
}
</style>
""", unsafe_allow_html=True)


# =============================================================================
# ① 세션 스테이트 초기화
#    st.session_state: Streamlit의 서버 메모리에 유지되는 딕셔너리
#    - 브라우저 새로고침 전까지 값이 유지됨
#    - API 키는 세션에만 저장하고 절대 디스크에 쓰지 않음
# =============================================================================
def init_session_state():
    """앱 최초 로드 시 필요한 상태 변수를 초기화한다."""
    defaults = {
        # ── API 설정 ──
        "llm_provider": "openai",         # 선택된 LLM 공급자
        "api_key": "",                     # API 키 (메모리에만 존재)
        "custom_base_url": "",             # 커스텀 OpenAI 호환 API URL
        "custom_model": "gpt-4o-mini",    # 커스텀 모델 이름
        "api_configured": False,           # API 키 설정 완료 여부
        # ── 데이터 ──
        "df_packets": None,                # 파싱된 패킷 DataFrame
        "pcap_filename": "",               # 업로드된 파일 이름
        # ── 채팅 ──
        "chat_history": [],                # [{"role": "user"/"assistant", "content": "..."}]
        "context_injected": False,         # 패킷 컨텍스트 주입 여부
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


# =============================================================================
# ② pcap 파일 파싱 함수
#    scapy: 저수준 패킷 조작/분석 라이브러리
#    rdpcap(): pcap 파일을 읽어 패킷 리스트를 반환
# =============================================================================
@st.cache_data(show_spinner=False)
def parse_pcap(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    pcap/pcapng 파일 바이트를 파싱하여 pandas DataFrame으로 반환한다.

    Returns:
        DataFrame 컬럼:
          no, time, relative_time, src, dst, protocol,
          length, sport, dport, info
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, IPv6
    except ImportError:
        st.error("scapy가 설치되지 않았습니다. `pip install scapy` 를 실행하세요.")
        return pd.DataFrame()

    # 임시 파일에 저장 후 scapy로 읽기 (scapy는 파일 경로를 요구)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        os.unlink(tmp_path)  # 임시 파일 즉시 삭제

    rows = []
    base_time = None  # 상대 시간 계산용 기준 타임스탬프

    for i, pkt in enumerate(packets):
        ts = float(pkt.time)
        if base_time is None:
            base_time = ts

        # ── 프로토콜 판별 ─────────────────────────────────────────
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
            # 잘 알려진 포트로 상위 프로토콜 추정
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

        # ── IP 레이어 ─────────────────────────────────────────────
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
# ③ AI 컨텍스트 생성 함수
#    업로드된 패킷 데이터를 LLM이 이해할 수 있는 텍스트 요약으로 변환
# =============================================================================
def build_packet_context(df: pd.DataFrame) -> str:
    """
    DataFrame 통계를 AI 프롬프트용 컨텍스트 문자열로 변환한다.
    토큰 낭비를 줄이기 위해 핵심 통계만 추출한다.
    """
    if df is None or df.empty:
        return "패킷 데이터 없음"

    total = len(df)
    proto_dist = df["protocol"].value_counts().head(10).to_dict()
    top_src = df["src"].value_counts().head(5).to_dict()
    top_dst = df["dst"].value_counts().head(5).to_dict()

    # TCP 플래그 이상 탐지 힌트 (RST, SYN 폭주 등)
    suspicious_hints = []
    if "TCP" in df["protocol"].values:
        tcp_df = df[df["protocol"] == "TCP"]
        if len(tcp_df) > 0:
            syn_ratio = tcp_df["info"].str.contains("S", na=False).mean()
            rst_count = tcp_df["info"].str.contains("R", na=False).sum()
            if syn_ratio > 0.7:
                suspicious_hints.append(f"⚠ SYN 패킷 비율 {syn_ratio:.0%} — SYN Flood 의심")
            if rst_count > 50:
                suspicious_hints.append(f"⚠ RST 패킷 {rst_count}개 — 연결 거부/스캔 의심")

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
# ④ LLM API 호출 함수 (OpenAI / Anthropic / 커스텀 분기)
# =============================================================================
def call_llm(messages: list) -> str:
    """
    선택된 LLM에 메시지 목록을 전송하고 응답 텍스트를 반환한다.

    Args:
        messages: [{"role": "system"/"user"/"assistant", "content": "..."}]

    Returns:
        AI 응답 문자열 (오류 시 오류 메시지 반환)
    """
    provider = st.session_state["llm_provider"]
    api_key  = st.session_state["api_key"]

    if not api_key:
        return "❌ API 키가 설정되지 않았습니다. 사이드바의 [API 키 설정] 버튼을 클릭하세요."

    # ── OpenAI (ChatGPT) ──────────────────────────────────────────
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
            return "❌ openai 패키지 미설치: `pip install openai`"
        except Exception as e:
            return f"❌ OpenAI 오류: {e}"

    # ── Anthropic (Claude) ────────────────────────────────────────
    elif provider == "anthropic":
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            # Anthropic API는 system 메시지를 별도 파라미터로 분리
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
            return "❌ anthropic 패키지 미설치: `pip install anthropic`"
        except Exception as e:
            return f"❌ Claude 오류: {e}"

    # ── 커스텀 OpenAI 호환 API ────────────────────────────────────
    elif provider == "custom":
        try:
            from openai import OpenAI
            base_url = st.session_state.get("custom_base_url", "").strip()
            model    = st.session_state.get("custom_model", "gpt-4o-mini").strip()
            if not base_url:
                return "❌ 커스텀 API의 Base URL을 설정하세요."
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=2000,
                temperature=0.3,
            )
            return resp.choices[0].message.content
        except ImportError:
            return "❌ openai 패키지 미설치: `pip install openai`"
        except Exception as e:
            return f"❌ 커스텀 API 오류: {e}"

    return "❌ 지원하지 않는 LLM 공급자입니다."


# =============================================================================
# ⑤ 시스템 프롬프트 생성
#    3대 전문 분석 영역을 명시한 전문가 페르소나 주입
# =============================================================================
def build_system_prompt(packet_context: str) -> str:
    return f"""당신은 네트워크 보안 및 패킷 분석 전문가 AI 'PacketAI'입니다.
사용자가 업로드한 pcap 파일을 분석하여 아래 3가지 영역에서 전문적인 인사이트를 제공하세요.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 전문 분석 영역 1: 네트워크 문제 해결
  - 통신 장애의 원인 파악 (라우팅 문제, ARP 브로드캐스트 폭주 등)
  - 패킷 손실(Packet Loss) 징후 탐지 (TCP 재전송, 중복 ACK 등)
  - 레이턴시(지연) 유발 구간 진단 (RTT 측정, TCP Window 크기 분석)

🛡 전문 분석 영역 2: 보안 및 악성코드 분석
  - 비정상적인 트래픽 패턴 탐지 (포트 스캔, DDoS, SYN Flood)
  - 외부 해킹 시도 및 침투 흔적 분석
  - 악성코드 C&C(Command & Control) 서버 통신 내역 탐지 및 경고
  - DNS Tunneling, 데이터 유출(Data Exfiltration) 패턴 확인

💻 전문 분석 영역 3: 개발 및 디버깅
  - 네트워크 프로토콜 개발 검증 (요청/응답 패턴 확인)
  - API 통신 세션 오류 분석 (TCP 3-Way Handshake 실패, TLS 협상 오류)
  - HTTP/HTTPS 통신 이상 탐지 (비정상 상태 코드, 응답 지연 등)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

답변 원칙:
1. 한국어로 답변하되, 기술 용어는 영문 원어를 병기하세요.
2. 구체적인 IP 주소, 포트 번호, 패킷 수 등 데이터 기반 근거를 제시하세요.
3. 발견된 이상 징후는 위험도(낮음/중간/높음)를 표시하세요.
4. 대응 방안 또는 추가 확인이 필요한 사항을 제안하세요.

현재 분석 중인 패킷 데이터 컨텍스트:
{packet_context}
"""


# =============================================================================
# ⑥ API 키 설정 팝업 (st.dialog 활용)
#    @st.dialog 데코레이터로 모달 창을 구현
# =============================================================================
@st.dialog("🔑 API 키 설정", width="large")
def api_key_dialog():
    """LLM 공급자 선택 및 API 키 입력 모달 창."""
    st.markdown("""
    <div class="info-box">
    ℹ API 키는 <strong>브라우저 세션 메모리에만</strong> 저장되며, 서버 디스크나 로그에 기록되지 않습니다.<br>
    페이지를 새로고침하면 키는 초기화됩니다.
    </div>
    """, unsafe_allow_html=True)

    # ── LLM 공급자 선택 ───────────────────────────────────────────
    provider = st.radio(
        "사용할 AI 모델을 선택하세요",
        options=["openai", "anthropic", "custom"],
        format_func=lambda x: {
            "openai":    "🤖 ChatGPT (OpenAI gpt-4o-mini)",
            "anthropic": "🧠 Claude (Anthropic claude-opus-4-5)",
            "custom":    "⚙️ 커스텀 (OpenAI 호환 API)",
        }[x],
        index=["openai", "anthropic", "custom"].index(
            st.session_state["llm_provider"]
        ),
        horizontal=True,
    )

    st.divider()

    # ── 공급자별 입력 폼 ──────────────────────────────────────────
    api_key = st.text_input(
        "API Key",
        value=st.session_state["api_key"],
        type="password",
        placeholder={
            "openai":    "sk-...",
            "anthropic": "sk-ant-...",
            "custom":    "Bearer 토큰 또는 API 키",
        }[provider],
        help="입력된 키는 이 세션에서만 유지됩니다.",
    )

    custom_base_url, custom_model = "", "gpt-4o-mini"
    if provider == "custom":
        col1, col2 = st.columns([2, 1])
        with col1:
            custom_base_url = st.text_input(
                "Base URL",
                value=st.session_state.get("custom_base_url", ""),
                placeholder="https://api.example.com/v1",
                help="OpenAI 호환 API의 엔드포인트 URL",
            )
        with col2:
            custom_model = st.text_input(
                "Model 이름",
                value=st.session_state.get("custom_model", "gpt-4o-mini"),
                placeholder="gpt-4o-mini",
            )

    # ── 저장 버튼 ─────────────────────────────────────────────────
    col_save, col_clear = st.columns([3, 1])
    with col_save:
        if st.button("✅ 저장 및 닫기", type="primary", use_container_width=True):
            if not api_key.strip():
                st.error("API 키를 입력해주세요.")
            else:
                # 세션 스테이트에 저장 (메모리에만 존재)
                st.session_state["llm_provider"]    = provider
                st.session_state["api_key"]         = api_key.strip()
                st.session_state["custom_base_url"] = custom_base_url.strip()
                st.session_state["custom_model"]    = custom_model.strip()
                st.session_state["api_configured"]  = True
                st.success("API 키가 세션에 저장되었습니다!")
                st.rerun()
    with col_clear:
        if st.button("🗑 초기화", use_container_width=True):
            st.session_state["api_key"]        = ""
            st.session_state["api_configured"] = False
            st.rerun()


# =============================================================================
# ⑦ 사이드바 구성
# =============================================================================
with st.sidebar:
    # ── 브랜드 + 네비게이션 ─────────────────────────────────────
    st.markdown("""
    <div class="pulse-brand">
      <div class="pulse-mark"></div>
      PacketAI
    </div>
    <nav class="pulse-nav">
      <div class="pulse-nav-item active" data-tab="0">
        <span class="nav-icon">📊</span> 대시보드 시각화
      </div>
      <div class="pulse-nav-item" data-tab="1">
        <span class="nav-icon">🤖</span> AI 패킷 분석가
      </div>
      <div class="pulse-nav-item" data-tab="0" data-scroll="packet-table">
        <span class="nav-icon">📋</span> 패킷 테이블
      </div>
    </nav>
    <hr class="pulse-nav-divider"/>
    <div style="font-size:.72rem;font-weight:600;color:var(--text-mute);
                text-transform:uppercase;letter-spacing:.05em;
                padding:0 12px 8px;">환경 설정</div>
    """, unsafe_allow_html=True)

    # ── API 키 상태 표시 및 설정 버튼 ────────────────────────────
    if st.session_state["api_configured"]:
        provider_label = {
            "openai":    "ChatGPT (OpenAI)",
            "anthropic": "Claude (Anthropic)",
            "custom":    "커스텀 API",
        }.get(st.session_state["llm_provider"], "Unknown")
        st.success(f"✅ {provider_label} 연결됨")
    else:
        st.warning("⚠ API 키 미설정")

    if st.button("🔑 API 키 설정", use_container_width=True, type="primary"):
        api_key_dialog()

    st.markdown("---")

    # ── pcap 파일 업로더 ──────────────────────────────────────────
    st.markdown("### 📁 파일 업로드")
    uploaded_file = st.file_uploader(
        "pcap / pcapng 파일",
        type=["pcap", "pcapng", "cap"],
        help="Wireshark 등으로 캡처한 패킷 파일을 업로드하세요.",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_size_kb = len(file_bytes) / 1024

        st.info(f"📄 {uploaded_file.name}\n{file_size_kb:.1f} KB")

        # 파일이 바뀌었을 때만 재파싱 (캐시 활용)
        if st.session_state["pcap_filename"] != uploaded_file.name:
            with st.spinner("패킷 파싱 중..."):
                df = parse_pcap(file_bytes, uploaded_file.name)
                st.session_state["df_packets"]        = df
                st.session_state["pcap_filename"]     = uploaded_file.name
                st.session_state["chat_history"]      = []
                st.session_state["context_injected"]  = False
            if not df.empty:
                st.success(f"✅ {len(df):,}개 패킷 로드 완료")

    st.markdown("---")

    # ── 채팅 초기화 ───────────────────────────────────────────────
    if st.button("🗑 대화 초기화", use_container_width=True):
        st.session_state["chat_history"]     = []
        st.session_state["context_injected"] = False
        st.rerun()

    st.markdown("---")
    st.markdown(
        "<div style='color:var(--text-mute);font-size:0.74rem;text-align:center;padding:4px 0;'>"
        "KDN Vibe Coding 과정<br>"
        "<span style='color:var(--text-dim);'>PacketAI Dashboard</span> · v2.0"
        "</div>",
        unsafe_allow_html=True
    )


# =============================================================================
# ⑧ 메인 화면 타이틀
# =============================================================================
df_packets   = st.session_state["df_packets"]
api_ok       = st.session_state["api_configured"]
pcap_name    = st.session_state.get("pcap_filename", "")
provider_lbl = {"openai": "ChatGPT", "anthropic": "Claude", "custom": "커스텀 API"}.get(
    st.session_state.get("llm_provider", ""), "")

# ── Pulse Topbar ─────────────────────────────────────────────────────────────
from datetime import date
today = date.today()
badges_html = ""
if api_ok:
    badges_html += f'<span class="pulse-badge pulse-badge--ok">● {provider_lbl} 연결됨</span>'
else:
    badges_html += '<span class="pulse-badge pulse-badge--warn">⚠ API 미설정</span>'
if pcap_name:
    short_name = pcap_name if len(pcap_name) <= 22 else pcap_name[:20] + "…"
    badges_html += f'<span class="pulse-badge pulse-badge--info">📄 {short_name}</span>'

st.markdown(f"""
<div class="pulse-topbar">
  <div class="pulse-topbar-left">
    <h1>KDN 패킷 분석 대시보드</h1>
    <p>pcap 업로드 → 트래픽 시각화 → AI 보안 분석</p>
  </div>
  <div class="pulse-topbar-right">{badges_html}</div>
</div>
""", unsafe_allow_html=True)

# ── 데이터 없을 때 온보딩 ─────────────────────────────────────────────────────
if df_packets is None or df_packets.empty:
    st.markdown("""
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin:28px 0 0;">
      <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 20px;">
        <div style="width:36px;height:36px;border-radius:8px;background:rgba(99,102,241,.15);
             display:flex;align-items:center;justify-content:center;font-size:1.1rem;margin-bottom:12px;">📁</div>
        <p style="font-weight:600;color:var(--text);margin:0 0 6px;font-size:.95rem;">1. 파일 업로드</p>
        <p style="color:var(--text-dim);font-size:.83rem;margin:0;line-height:1.6;">
          사이드바에서 <strong style="color:var(--text);">pcap / pcapng</strong> 파일을 드래그하거나 클릭해 선택하세요.
        </p>
      </div>
      <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 20px;">
        <div style="width:36px;height:36px;border-radius:8px;background:rgba(34,211,238,.12);
             display:flex;align-items:center;justify-content:center;font-size:1.1rem;margin-bottom:12px;">🔑</div>
        <p style="font-weight:600;color:var(--text);margin:0 0 6px;font-size:.95rem;">2. AI 모델 연결</p>
        <p style="color:var(--text-dim);font-size:.83rem;margin:0;line-height:1.6;">
          <strong style="color:var(--text);">API 키 설정</strong> 버튼으로 OpenAI · Claude · 커스텀 API를 선택하세요.
        </p>
      </div>
      <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 20px;">
        <div style="width:36px;height:36px;border-radius:8px;background:rgba(34,197,94,.12);
             display:flex;align-items:center;justify-content:center;font-size:1.1rem;margin-bottom:12px;">📊</div>
        <p style="font-weight:600;color:var(--text);margin:0 0 6px;font-size:.95rem;">3. 분석 시작</p>
        <p style="color:var(--text-dim);font-size:.83rem;margin:0;line-height:1.6;">
          트래픽 시각화와 AI 보안 분석을 탭에서 바로 확인할 수 있습니다.
        </p>
      </div>
    </div>
    <p style="color:var(--text-mute);font-size:.78rem;text-align:center;margin-top:20px;">
      샘플 파일 →
      <a href="https://wiki.wireshark.org/SampleCaptures" target="_blank"
         style="color:var(--accent-2);text-decoration:underline;">Wireshark Sample Captures</a>
    </p>
    """, unsafe_allow_html=True)
    st.stop()


# =============================================================================
# ⑨ KPI 메트릭 상단 배치 (st.metric)
# =============================================================================
total_packets  = len(df_packets)
unique_src     = df_packets["src"].nunique()
unique_dst     = df_packets["dst"].nunique()
unique_proto   = df_packets["protocol"].nunique()
avg_pkt_size   = round(df_packets["length"].mean(), 1)
duration       = df_packets["relative_time"].max() if "relative_time" in df_packets.columns else 0
pps            = round(total_packets / duration, 1) if duration > 0 else 0

kpi_data = [
    ("📦 총 패킷 수",     f"{total_packets:,}"),
    ("🖥 출발지 IP",      f"{unique_src:,}"),
    ("🎯 목적지 IP",      f"{unique_dst:,}"),
    ("🔌 프로토콜",       f"{unique_proto}"),
    ("📏 평균 크기",      f"{avg_pkt_size} B"),
    ("⚡ 평균 PPS",       f"{pps}"),
]
cols_kpi = st.columns(len(kpi_data))
for col, (label, value) in zip(cols_kpi, kpi_data):
    with col:
        st.metric(label, value)
st.markdown('<div style="margin-bottom:8px;"></div>', unsafe_allow_html=True)


# =============================================================================
# ⑩ 탭 분리: 대시보드 시각화 / AI 패킷 분석가
# =============================================================================
tab_dash, tab_ai = st.tabs(["📊 대시보드 시각화", "🤖 AI 패킷 분석가"])

# ── 사이드바 네비게이션 ↔ Streamlit 탭 연결 ─────────────────────────────────
components.html("""
<script>
(function () {
    function init() {
        var doc = window.parent.document;
        var navItems = doc.querySelectorAll('.pulse-nav-item[data-tab]');
        var stTabs  = doc.querySelectorAll('[data-baseweb="tab"]');

        if (!navItems.length || !stTabs.length) {
            setTimeout(init, 150);
            return;
        }

        /* 현재 활성 Streamlit 탭을 읽어 nav 싱크 */
        function syncNav() {
            var activeIdx = 0;
            stTabs.forEach(function (t, i) {
                if (t.getAttribute('aria-selected') === 'true') activeIdx = i;
            });
            navItems.forEach(function (n) { n.classList.remove('active'); });
            doc.querySelectorAll('.pulse-nav-item[data-tab="' + activeIdx + '"]')
               .forEach(function (n) { n.classList.add('active'); });
        }
        syncNav();

        /* 클릭 핸들러 */
        navItems.forEach(function (item) {
            item.onclick = function () {
                var idx = parseInt(this.getAttribute('data-tab'), 10);
                var allTabs = doc.querySelectorAll('[data-baseweb="tab"]');

                /* 탭 클릭 */
                if (allTabs[idx]) allTabs[idx].click();

                /* nav 활성 표시 즉시 반영 */
                navItems.forEach(function (n) { n.classList.remove('active'); });
                doc.querySelectorAll('.pulse-nav-item[data-tab="' + idx + '"]')
                   .forEach(function (n) { n.classList.add('active'); });

                /* 패킷 테이블 스크롤 */
                if (item.getAttribute('data-scroll') === 'packet-table') {
                    setTimeout(function () {
                        var tbl = doc.querySelector('[data-testid="stDataFrame"]');
                        if (tbl) tbl.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, 400);
                }
            };
        });

        /* Streamlit 탭 직접 클릭 시에도 nav 싱크 */
        stTabs.forEach(function (t) {
            t.addEventListener('click', function () {
                setTimeout(syncNav, 100);
            });
        });
    }

    setTimeout(init, 400);
})();
</script>
""", height=0)

# ─────────────────────────────────────────────────────────────────────────────
#  탭 1: 대시보드 시각화
# ─────────────────────────────────────────────────────────────────────────────
with tab_dash:

    # ── 차트 행 1: 프로토콜 분포 + 시간별 트래픽 ─────────────────
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("🔌 프로토콜별 패킷 분포")
        proto_counts = df_packets["protocol"].value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]

        fig_proto = px.pie(
            proto_counts,
            values="count",
            names="protocol",
            hole=0.5,
            color_discrete_sequence=["#6366f1","#22d3ee","#a78bfa","#f0abfc","#818cf8","#67e8f9","#c4b5fd","#a5f3fc"],
        )
        fig_proto.update_traces(
            textposition="inside",
            textinfo="percent+label",
            marker=dict(line=dict(color="#161a25", width=2)),
        )
        fig_proto.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#a4abbb",
            font_family="Inter, system-ui",
            showlegend=True,
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#6b7387"),
                        orientation="v", yanchor="middle", y=0.5),
            margin=dict(t=10, b=10, l=0, r=0),
            height=300,
        )
        st.plotly_chart(fig_proto, use_container_width=True)

    with col_chart2:
        st.subheader("📈 시간별 트래픽 트렌드")
        # 상대 시간을 1초 단위 버킷으로 집계
        df_time = df_packets.copy()
        df_time["second"] = df_time["relative_time"].astype(int)
        traffic_trend = df_time.groupby("second").size().reset_index(name="packets")

        fig_trend = px.area(
            traffic_trend,
            x="second",
            y="packets",
            labels={"second": "경과 시간 (초)", "packets": "패킷 수"},
            color_discrete_sequence=["#6366f1"],
        )
        fig_trend.update_traces(
            fillcolor="rgba(99,102,241,0.12)",
            line_color="#6366f1",
            line_width=2,
        )
        fig_trend.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#a4abbb",
            font_family="Inter, system-ui",
            xaxis=dict(gridcolor="#232838", color="#6b7387", zeroline=False),
            yaxis=dict(gridcolor="#232838", color="#6b7387", zeroline=False),
            margin=dict(t=10, b=10, l=0, r=0),
            height=300,
        )
        st.plotly_chart(fig_trend, use_container_width=True)

    # ── 차트 행 2: Top IP + 프로토콜별 패킷 크기 ─────────────────
    col_chart3, col_chart4 = st.columns(2)

    with col_chart3:
        st.subheader("🏆 출발지 IP 상위 10")
        top_src = df_packets["src"].value_counts().head(10).reset_index()
        top_src.columns = ["ip", "count"]

        fig_src = px.bar(
            top_src,
            x="count",
            y="ip",
            orientation="h",
            color="count",
            color_continuous_scale=[[0,"#1c2130"],[0.4,"#4f52c9"],[1,"#6366f1"]],
            labels={"count": "패킷 수", "ip": "IP 주소"},
        )
        fig_src.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#a4abbb",
            font_family="Inter, system-ui",
            xaxis=dict(gridcolor="#232838", color="#6b7387", zeroline=False),
            yaxis=dict(gridcolor="#232838", color="#6b7387", autorange="reversed"),
            coloraxis_showscale=False,
            margin=dict(t=10, b=10, l=0, r=0),
            height=300,
        )
        st.plotly_chart(fig_src, use_container_width=True)

    with col_chart4:
        st.subheader("📦 프로토콜별 평균 패킷 크기")
        proto_size = (
            df_packets.groupby("protocol")["length"]
            .mean()
            .round(1)
            .reset_index()
            .sort_values("length", ascending=False)
            .head(10)
        )
        fig_size = px.bar(
            proto_size,
            x="protocol",
            y="length",
            color="length",
            color_continuous_scale=[[0,"#0e1929"],[0.4,"#0e8fa0"],[1,"#22d3ee"]],
            labels={"length": "평균 크기 (bytes)", "protocol": "프로토콜"},
        )
        fig_size.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#a4abbb",
            font_family="Inter, system-ui",
            xaxis=dict(gridcolor="#232838", color="#6b7387", zeroline=False),
            yaxis=dict(gridcolor="#232838", color="#6b7387", zeroline=False),
            coloraxis_showscale=False,
            margin=dict(t=10, b=10, l=0, r=0),
            height=300,
        )
        st.plotly_chart(fig_size, use_container_width=True)

    # ── 패킷 테이블 ───────────────────────────────────────────────
    st.subheader("📋 패킷 상세 테이블")
    st.markdown('<div class="filter-bar"><p class="filter-bar-title">🔎 필터</p>', unsafe_allow_html=True)
    col_f1, col_f2, col_f3 = st.columns([2, 2, 1])
    with col_f1:
        proto_filter = st.multiselect(
            "프로토콜",
            options=sorted(df_packets["protocol"].unique()),
            default=[],
            label_visibility="collapsed",
            placeholder="프로토콜 선택…",
        )
    with col_f2:
        src_filter = st.text_input(
            "출발지 IP",
            placeholder="출발지 IP 검색 (예: 192.168.1.1)",
            label_visibility="collapsed",
        )
    with col_f3:
        max_rows = st.number_input(
            "최대 행",
            min_value=50, max_value=5000, value=200, step=50,
            label_visibility="collapsed",
        )
    st.markdown('</div>', unsafe_allow_html=True)

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
            "no":            st.column_config.NumberColumn("No.", width=60),
            "time":          st.column_config.TextColumn("시간", width=110),
            "src":           st.column_config.TextColumn("출발지"),
            "dst":           st.column_config.TextColumn("목적지"),
            "protocol":      st.column_config.TextColumn("프로토콜", width=100),
            "length":        st.column_config.NumberColumn("크기(B)", width=80),
            "info":          st.column_config.TextColumn("정보"),
        },
        height=400,
    )
    st.caption(f"전체 {total_packets:,}개 중 {min(len(df_view), max_rows):,}개 표시")


# ─────────────────────────────────────────────────────────────────────────────
#  탭 2: AI 패킷 분석가 (챗봇)
# ─────────────────────────────────────────────────────────────────────────────
with tab_ai:

    # ── API 키 미설정 경고 ────────────────────────────────────────
    if not st.session_state["api_configured"]:
        st.markdown("""
        <div class="alert-box">
        ⚠ <strong>API 키가 설정되지 않았습니다.</strong><br>
        사이드바의 [🔑 API 키 설정] 버튼을 클릭하여 LLM을 선택하고 API 키를 입력하세요.
        </div>
        """, unsafe_allow_html=True)

    # ── AI 분석 개요 ──────────────────────────────────────────────
    with st.expander("🧠 AI 분석가 소개 및 사용법", expanded=False):
        st.markdown("""
        **PacketAI**는 업로드된 pcap 파일을 바탕으로 3가지 전문 영역을 분석합니다:

        | 영역 | 주요 분석 내용 |
        |------|--------------|
        | 🔧 네트워크 문제 해결 | 패킷 손실, 레이턴시, ARP 이상 등 |
        | 🛡 보안/악성코드 분석 | 포트 스캔, DDoS, C&C 통신 탐지 |
        | 💻 개발/디버깅 | TCP Handshake 오류, API 세션 분석 |

        **빠른 시작 질문 예시:**
        - "이 pcap에서 비정상적인 트래픽 패턴이 있나요?"
        - "SYN Flood 공격 징후가 보이나요?"
        - "가장 많은 트래픽을 발생시킨 IP는 어디인가요?"
        - "TCP 재전송이 많이 발생한 구간이 있나요?"
        """)

    # ── 빠른 질문 버튼 ────────────────────────────────────────────
    st.markdown("**⚡ 빠른 질문**")
    quick_cols = st.columns(2)
    quick_questions = [
        "📊 트래픽 요약 및 이상 징후 분석",
        "🛡 보안 위협 및 공격 패턴 탐지",
        "🔧 네트워크 성능 문제 구간 진단",
        "💻 TCP 세션 오류 및 재전송 분석",
    ]
    quick_triggered = None
    for col, q in zip(quick_cols, quick_questions):
        with col:
            if st.button(q, use_container_width=True):
                quick_triggered = q.split(" ", 1)[1]  # 이모지 제거

    # ── 채팅 이력 표시 ────────────────────────────────────────────
    st.markdown("---")
    chat_container = st.container(height=450)

    with chat_container:
        if not st.session_state["chat_history"]:
            st.markdown("""
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                        padding:52px 20px;gap:14px;text-align:center;">
              <div style="width:52px;height:52px;border-radius:14px;
                          background:linear-gradient(135deg,#6366f1,#22d3ee);
                          display:flex;align-items:center;justify-content:center;
                          font-size:1.4rem;box-shadow:0 4px 20px rgba(99,102,241,0.35);">
                🤖
              </div>
              <p style="color:var(--text);font-weight:700;font-size:.95rem;margin:0;letter-spacing:-.01em;">
                PacketAI 분석가
              </p>
              <p style="color:var(--text-mute);font-size:.82rem;margin:0;max-width:280px;line-height:1.65;">
                네트워크 보안 분석을 시작하려면 빠른 질문을 클릭하거나 직접 입력하세요.
              </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            for msg in st.session_state["chat_history"]:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

    # ── 사용자 입력 처리 ──────────────────────────────────────────
    user_input = st.chat_input(
        "네트워크 보안 분석을 요청하세요...",
        disabled=not st.session_state["api_configured"],
    )

    # 빠른 질문 버튼 클릭 시 사용자 입력으로 처리
    if quick_triggered:
        user_input = quick_triggered

    if user_input:
        # 사용자 메시지 저장 및 표시
        st.session_state["chat_history"].append(
            {"role": "user", "content": user_input}
        )

        # ── 패킷 컨텍스트 포함 메시지 목록 구성 ──────────────────
        packet_context = build_packet_context(df_packets)
        system_prompt  = build_system_prompt(packet_context)

        # API 전송용 메시지 (시스템 + 이력 전체)
        api_messages = [{"role": "system", "content": system_prompt}]
        # 토큰 절약: 최근 10개 대화만 포함
        recent_history = st.session_state["chat_history"][-10:]
        api_messages.extend(recent_history)

        # ── AI 호출 ───────────────────────────────────────────────
        with st.spinner("🤖 PacketAI 분석 중..."):
            response = call_llm(api_messages)

        # 응답 저장
        st.session_state["chat_history"].append(
            {"role": "assistant", "content": response}
        )

        # 화면 갱신 (새 메시지 표시)
        st.rerun()
