"""
Network Threat Analyzer - Agentic Security System
Groq-powered | Supports raw logs AND .pcap file upload
"""

import streamlit as st
import json
import time
import os
import re
import requests
from agents.threat_agent import ThreatAnalysisAgent
from rag.knowledge_base import SecurityKnowledgeBase

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

st.set_page_config(
    page_title="Network Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');
:root {
    --bg: #0a0e1a; --panel: #0f1628; --border: #1e3a5f;
    --accent: #00d4ff; --accent2: #ff4757; --accent3: #2ed573;
    --warn: #ffa502; --text: #c8d6e5; --dim: #57606f;
}
html, body, [data-testid="stApp"] { background-color: var(--bg) !important; color: var(--text) !important; font-family: 'Exo 2', sans-serif; }
[data-testid="stSidebar"] { background: var(--panel) !important; border-right: 1px solid var(--border) !important; }
.stTextArea textarea { background: #060b18 !important; color: #00d4ff !important; font-family: 'Share Tech Mono', monospace !important; border: 1px solid var(--border) !important; border-radius: 4px !important; font-size: 13px !important; }
.stButton > button { background: linear-gradient(135deg, #00d4ff22, #00d4ff44) !important; color: #00d4ff !important; border: 1px solid #00d4ff88 !important; font-family: 'Exo 2', sans-serif !important; font-weight: 600 !important; letter-spacing: 1px !important; text-transform: uppercase !important; transition: all 0.2s !important; border-radius: 4px !important; }
.stButton > button:hover { background: linear-gradient(135deg, #00d4ff44, #00d4ff88) !important; box-shadow: 0 0 20px #00d4ff44 !important; }
.stTabs [data-baseweb="tab"] { color: var(--text) !important; font-family: 'Exo 2', sans-serif !important; }
.stTabs [aria-selected="true"] { color: #00d4ff !important; border-bottom: 2px solid #00d4ff !important; }
.threat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin: 10px 0; position: relative; overflow: hidden; }
.threat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%; }
.threat-HIGH::before { background: var(--accent2); }
.threat-MEDIUM::before { background: var(--warn); }
.threat-LOW::before { background: var(--accent3); }
.threat-badge { display: inline-block; padding: 4px 14px; border-radius: 20px; font-family: 'Share Tech Mono', monospace; font-size: 12px; font-weight: bold; letter-spacing: 2px; }
.badge-HIGH { background: #ff475722; border: 1px solid #ff4757; color: #ff4757; }
.badge-MEDIUM { background: #ffa50222; border: 1px solid #ffa502; color: #ffa502; }
.badge-LOW { background: #2ed57322; border: 1px solid #2ed573; color: #2ed573; }
.ip-tag { display: inline-block; background: #00d4ff11; border: 1px solid #00d4ff44; color: #00d4ff; padding: 2px 10px; border-radius: 3px; font-family: 'Share Tech Mono', monospace; font-size: 12px; margin: 2px; }
.action-item { padding: 8px 12px; background: #00d4ff08; border-left: 2px solid #00d4ff44; margin: 4px 0; border-radius: 0 4px 4px 0; font-size: 14px; }
.pcap-stat { background: #0f1628; border: 1px solid #1e3a5f; border-radius: 6px; padding: 12px 16px; text-align: center; }
.mono { font-family: 'Share Tech Mono', monospace; }
.dim { color: var(--dim); font-size: 12px; }
h1, h2, h3 { font-family: 'Exo 2', sans-serif !important; }
.scan-line { font-family: 'Share Tech Mono', monospace; color: #00d4ff; font-size: 12px; padding: 4px 0; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_knowledge_base():
    kb = SecurityKnowledgeBase()
    kb.build()
    return kb

@st.cache_resource
def load_agent(_kb, groq_key, groq_model):
    agent = ThreatAnalysisAgent(_kb, groq_api_key=groq_key, groq_model=groq_model)
    return agent


def parse_pcap(uploaded_file) -> tuple[str, dict]:
    """
    Parse .pcap file using scapy and convert to HTTP-style log lines.
    Returns (log_text, stats_dict).
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
    except ImportError:
        return None, {"error": "scapy not installed. Run: pip install scapy"}

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    except Exception as e:
        return None, {"error": f"Failed to read pcap: {str(e)}"}
    finally:
        os.unlink(tmp_path)

    log_lines = []
    stats = {
        "total_packets": len(packets),
        "tcp_packets": 0,
        "udp_packets": 0,
        "unique_src_ips": set(),
        "unique_dst_ips": set(),
        "http_requests": 0,
        "protocols": set(),
    }

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        stats["unique_src_ips"].add(src_ip)
        stats["unique_dst_ips"].add(dst_ip)

        if pkt.haslayer(TCP):
            stats["tcp_packets"] += 1
            stats["protocols"].add("TCP")
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # Try to extract HTTP payload
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                    # Look for HTTP request lines
                    http_match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/[\d.]+', payload)
                    if http_match:
                        method = http_match.group(1)
                        path = http_match.group(2)
                        # Infer status from response if available
                        status_match = re.search(r'HTTP/[\d.]+\s+(\d{3})', payload)
                        status = status_match.group(1) if status_match else "200"
                        log_line = f'{src_ip} - - [pcap] "{method} {path} HTTP/1.1" {status} -'
                        log_lines.append(log_line)
                        stats["http_requests"] += 1
                    else:
                        # Non-HTTP TCP — log as generic connection
                        log_line = f'{src_ip} - - [pcap] "CONNECT :{dport} TCP/1.0" 200 -'
                        log_lines.append(log_line)
                except Exception:
                    pass
            else:
                # SYN/ACK/etc with no payload — log port probe
                flags = pkt[TCP].flags
                if flags == 2:  # SYN
                    log_line = f'{src_ip} - - [pcap] "PROBE :{dport} SYN/1.0" 000 -'
                    log_lines.append(log_line)

        elif pkt.haslayer(UDP):
            stats["udp_packets"] += 1
            stats["protocols"].add("UDP")
            dport = pkt[UDP].dport
            log_line = f'{src_ip} - - [pcap] "UDP :{dport} UDP/1.0" 000 -'
            log_lines.append(log_line)

    # Convert sets to counts for display
    stats["unique_src_ips"] = len(stats["unique_src_ips"])
    stats["unique_dst_ips"] = len(stats["unique_dst_ips"])
    stats["protocols"] = ", ".join(stats["protocols"]) or "Unknown"

    log_text = "\n".join(log_lines[:500])  # cap at 500 lines
    return log_text, stats


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center; padding: 30px 0 10px;">
    <div style="font-family:'Share Tech Mono',monospace; color:#00d4ff44; font-size:11px; letter-spacing:4px;">
        AGENTIC SECURITY INTELLIGENCE PLATFORM
    </div>
    <h1 style="font-size:2.8rem; font-weight:700; margin:8px 0;
               background: linear-gradient(90deg, #00d4ff, #ffffff, #00d4ff);
               -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
        🛡️ Network Threat Analyzer
    </h1>
    <div style="color:#57606f; font-size:14px;">
        Detect · Analyze · Respond &nbsp;|&nbsp; Groq-Powered Agentic RAG System
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚡ Groq Settings")
    groq_key = st.text_input("Groq API Key", value=GROQ_API_KEY, type="password",
                              placeholder="gsk_...")
    groq_model = "llama3-8b-8192"

    if groq_key:
        st.success("✅ API key set")
    else:
        st.warning("⚠️ Get free key: console.groq.com")

    st.divider()
    st.markdown("### 📋 Sample Logs")

    sample_logs = {
        "Brute Force Attack": """192.168.1.10 - - [01/May/2026:10:23:01] "POST /login HTTP/1.1" 401 -
192.168.1.10 - - [01/May/2026:10:23:02] "POST /login HTTP/1.1" 401 -
192.168.1.10 - - [01/May/2026:10:23:03] "POST /login HTTP/1.1" 401 -
192.168.1.10 - - [01/May/2026:10:23:04] "POST /login HTTP/1.1" 401 -
192.168.1.10 - - [01/May/2026:10:23:05] "POST /login HTTP/1.1" 200 -
10.0.0.5 - - [01/May/2026:10:24:11] "GET /dashboard HTTP/1.1" 200 -""",

        "DDoS + Port Scan": """45.33.32.156 - - [01/May/2026:09:15:00] "GET / HTTP/1.1" 200 -
45.33.32.156 - - [01/May/2026:09:15:00] "GET / HTTP/1.1" 200 -
45.33.32.156 - - [01/May/2026:09:15:01] "GET / HTTP/1.1" 200 -
45.33.32.156 - - [01/May/2026:09:15:01] "GET / HTTP/1.1" 200 -
45.33.32.156 - - [01/May/2026:09:15:01] "GET / HTTP/1.1" 200 -
198.51.100.42 - - [01/May/2026:09:16:00] "GET /admin HTTP/1.1" 403 -
198.51.100.42 - - [01/May/2026:09:16:01] "GET /wp-admin HTTP/1.1" 404 -
198.51.100.42 - - [01/May/2026:09:16:02] "GET /.env HTTP/1.1" 404 -
198.51.100.42 - - [01/May/2026:09:16:03] "GET /config.php HTTP/1.1" 404 -""",

        "SQL Injection Attempt": """203.0.113.5 - - [01/May/2026:11:30:00] "GET /search?q=1' OR '1'='1 HTTP/1.1" 400 -
203.0.113.5 - - [01/May/2026:11:30:01] "GET /user?id=1 UNION SELECT * FROM users-- HTTP/1.1" 500 -
203.0.113.5 - - [01/May/2026:11:30:02] "POST /login HTTP/1.1" 401 -
10.0.0.25 - - [01/May/2026:11:31:00] "GET /products HTTP/1.1" 200 -"""
    }

    selected_sample = st.selectbox("Load sample:", ["— Select —"] + list(sample_logs.keys()))

    st.divider()
    st.markdown("""
    <div class="dim">
    <b>Agent Pipeline:</b><br>
    1️⃣ Anomaly Detection<br>
    2️⃣ IP Extraction<br>
    3️⃣ Threat Intel Lookup<br>
    4️⃣ RAG Knowledge Query<br>
    5️⃣ Groq AI Reasoning<br>
    6️⃣ Action Generation
    </div>
    """, unsafe_allow_html=True)


# ── Input Tabs ────────────────────────────────────────────────────────────────
tab_logs, tab_pcap = st.tabs(["📄 Paste Logs", "📦 Upload .pcap"])

log_input = ""
pcap_stats = None

with tab_logs:
    col1, col2 = st.columns([3, 1])
    with col1:
        default_log = sample_logs[selected_sample] if selected_sample != "— Select —" else ""
        log_input = st.text_area(
            "📥 Paste Network Logs",
            value=default_log,
            height=220,
            placeholder='Paste HTTP logs, login attempts, or network traffic here...',
            key="log_text"
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn_logs = st.button("🔍 ANALYZE THREATS", use_container_width=True, key="btn_logs")
        st.markdown("<br>", unsafe_allow_html=True)
        clear_btn = st.button("🗑 CLEAR", use_container_width=True)
        st.markdown("""
        <div style="margin-top:16px; padding:12px; background:#0f1628; border:1px solid #1e3a5f; border-radius:6px;">
        <div class="dim">Threat Levels:</div>
        <div style="margin-top:8px;">
            <span class="badge-HIGH threat-badge" style="display:block;margin:3px 0;text-align:center;">🔴 HIGH</span>
            <span class="badge-MEDIUM threat-badge" style="display:block;margin:3px 0;text-align:center;">🟡 MEDIUM</span>
            <span class="badge-LOW threat-badge" style="display:block;margin:3px 0;text-align:center;">🟢 LOW</span>
        </div>
        </div>
        """, unsafe_allow_html=True)

with tab_pcap:
    st.markdown("""
    <div style="padding:12px; background:#0f1628; border:1px solid #1e3a5f; border-radius:6px; margin-bottom:16px;">
    <div style="color:#00d4ff; font-size:13px; font-family:'Share Tech Mono',monospace;">📦 PCAP ANALYSIS</div>
    <div class="dim" style="margin-top:6px;">
        Upload a .pcap or .pcapng file captured via Wireshark, tcpdump, or any network tool.
        Packets are parsed, converted to log format, and run through the full threat pipeline.
    </div>
    </div>
    """, unsafe_allow_html=True)

    pcap_col1, pcap_col2 = st.columns([3, 1])
    with pcap_col1:
        uploaded_pcap = st.file_uploader(
            "Upload .pcap / .pcapng",
            type=["pcap", "pcapng", "cap"],
            help="Captured with Wireshark, tcpdump, etc."
        )
    with pcap_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn_pcap = st.button("🔍 ANALYZE PCAP", use_container_width=True, key="btn_pcap")

    if uploaded_pcap:
        st.info(f"📂 File: `{uploaded_pcap.name}` ({uploaded_pcap.size / 1024:.1f} KB)")

        try:
            from scapy.all import rdpcap
            scapy_available = True
        except ImportError:
            scapy_available = False

        if not scapy_available:
            st.error("⚠️ **scapy** is required for pcap parsing.")
            st.code("pip install scapy", language="bash")
        else:
            if analyze_btn_pcap:
                with st.spinner("Parsing pcap file..."):
                    pcap_log_text, pcap_stats = parse_pcap(uploaded_pcap)

                if pcap_stats and "error" in pcap_stats:
                    st.error(f"❌ {pcap_stats['error']}")
                elif pcap_log_text:
                    log_input = pcap_log_text

                    # Show pcap stats
                    st.markdown("### 📊 PCAP Summary")
                    sc1, sc2, sc3, sc4, sc5 = st.columns(5)
                    with sc1:
                        st.markdown(f'<div class="pcap-stat"><div class="dim">Total Packets</div><div style="font-size:24px;color:#00d4ff;font-weight:700;">{pcap_stats["total_packets"]}</div></div>', unsafe_allow_html=True)
                    with sc2:
                        st.markdown(f'<div class="pcap-stat"><div class="dim">TCP</div><div style="font-size:24px;color:#00d4ff;font-weight:700;">{pcap_stats["tcp_packets"]}</div></div>', unsafe_allow_html=True)
                    with sc3:
                        st.markdown(f'<div class="pcap-stat"><div class="dim">UDP</div><div style="font-size:24px;color:#ffa502;font-weight:700;">{pcap_stats["udp_packets"]}</div></div>', unsafe_allow_html=True)
                    with sc4:
                        st.markdown(f'<div class="pcap-stat"><div class="dim">Unique IPs</div><div style="font-size:24px;color:#2ed573;font-weight:700;">{pcap_stats["unique_src_ips"]}</div></div>', unsafe_allow_html=True)
                    with sc5:
                        st.markdown(f'<div class="pcap-stat"><div class="dim">HTTP Requests</div><div style="font-size:24px;color:#ff4757;font-weight:700;">{pcap_stats["http_requests"]}</div></div>', unsafe_allow_html=True)

                    st.markdown("### 📋 Extracted Log Lines (preview)")
                    st.text_area("", value=log_input[:1500] + ("\n..." if len(log_input) > 1500 else ""),
                                 height=150, disabled=True)
                else:
                    st.warning("No usable packets found in the pcap file.")


# ── Run Analysis ──────────────────────────────────────────────────────────────
run_analysis = (analyze_btn_logs and log_input.strip()) or (
    "analyze_btn_pcap" in dir() and analyze_btn_pcap and log_input.strip()
)

# Also trigger if pcap was parsed and log_input is populated
if "analyze_btn_pcap" in dir() and analyze_btn_pcap and log_input.strip():
    run_analysis = True

if run_analysis:
    if not groq_key:
        st.error("⚠️ Please enter your Groq API key in the sidebar. Get one free at console.groq.com")
        st.stop()

    with st.spinner("Initializing knowledge base..."):
        kb = load_knowledge_base()
        agent = load_agent(kb, groq_key, groq_model)

    st.divider()
    st.markdown("## 🔬 Analysis Pipeline")

    step_cols = st.columns(6)
    step_labels = ["Detect", "Extract IPs", "Threat Intel", "RAG Query", "Reasoning", "Actions"]
    step_icons = ["🔍", "📍", "🌐", "📚", "🧠", "🛠"]
    placeholders = []
    for i, (col, label, icon) in enumerate(zip(step_cols, step_labels, step_icons)):
        with col:
            ph = st.empty()
            ph.markdown(f"""
            <div style="text-align:center; padding:10px; background:#0f1628;
                        border:1px solid #1e3a5f33; border-radius:6px; opacity:0.4;">
                <div style="font-size:20px;">{icon}</div>
                <div class="dim">{label}</div>
            </div>
            """, unsafe_allow_html=True)
            placeholders.append(ph)

    def activate_step(idx):
        icon = step_icons[idx]
        label = step_labels[idx]
        placeholders[idx].markdown(f"""
        <div style="text-align:center; padding:10px; background:#00d4ff11;
                    border:1px solid #00d4ff66; border-radius:6px;">
            <div style="font-size:20px;">{icon}</div>
            <div style="color:#00d4ff; font-size:12px; font-weight:600;">{label}</div>
            <div style="color:#00d4ff; font-size:10px;">✓ DONE</div>
        </div>
        """, unsafe_allow_html=True)

    status_ph = st.empty()

    def on_step(step_idx, message):
        activate_step(step_idx)
        status_ph.markdown(f'<div class="scan-line">▶ {message}</div>', unsafe_allow_html=True)
        time.sleep(0.3)

    with st.spinner("Running agentic analysis..."):
        result = agent.analyze(log_input, on_step=on_step)

    status_ph.empty()

    st.divider()
    st.markdown("## 📊 Threat Report")

    level = result.get("threat_level", "LOW")

    st.markdown(f"""
    <div class="threat-card threat-{level}" style="display:flex; align-items:center; gap:20px;">
        <div style="font-size:48px;">{'🚨' if level=='HIGH' else '⚠️' if level=='MEDIUM' else '✅'}</div>
        <div>
            <div style="font-size:12px; color:#57606f; letter-spacing:2px; font-family:'Share Tech Mono',monospace;">OVERALL THREAT LEVEL</div>
            <span class="threat-badge badge-{level}" style="font-size:18px; padding:6px 20px;">{level}</span>
        </div>
        <div style="margin-left:auto; text-align:right;">
            <div class="dim">Suspicious IPs Detected</div>
            <div style="font-size:32px; font-weight:700; color:#00d4ff;">{len(result.get('suspicious_ips', []))}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_a, col_b, col_c = st.columns(3)

    with col_a:
        st.markdown("### 📍 Suspicious IPs")
        ips = result.get("suspicious_ips", [])
        if ips:
            for ip_info in ips:
                ip = ip_info.get("ip", "unknown")
                reason = ip_info.get("reason", "")
                threat = ip_info.get("threat_type", "Unknown")
                st.markdown(f"""
                <div class="threat-card" style="padding:12px;">
                    <div class="ip-tag">{ip}</div>
                    <div style="margin-top:6px; font-size:13px; color:#ffa502;">⚡ {threat}</div>
                    <div class="dim" style="margin-top:4px;">{reason}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No suspicious IPs found.")

    with col_b:
        st.markdown("### 🔎 Attack Patterns")
        patterns = result.get("attack_patterns", [])
        if patterns:
            for p in patterns:
                st.markdown(f"""
                <div style="padding:10px 12px; margin:6px 0; background:#0f1628;
                            border:1px solid #1e3a5f; border-radius:6px;">
                    <div style="font-size:13px; font-weight:600;">{p.get('name','')}</div>
                    <div class="dim">{p.get('description','')}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("### 📚 RAG Context Used")
        rag_ctx = result.get("rag_context", [])
        for ctx in rag_ctx[:3]:
            st.markdown(f'<div class="action-item dim">{ctx}</div>', unsafe_allow_html=True)

    with col_c:
        st.markdown("### 🛠 Recommended Actions")
        actions = result.get("recommended_actions", [])
        for i, action in enumerate(actions, 1):
            priority = action.get("priority", "MEDIUM")
            color = "#ff4757" if priority == "HIGH" else "#ffa502" if priority == "MEDIUM" else "#2ed573"
            st.markdown(f"""
            <div style="padding:10px 12px; margin:6px 0; background:#0f1628;
                        border-left:3px solid {color}; border-radius:0 6px 6px 0;">
                <div style="font-size:11px; color:{color}; font-family:'Share Tech Mono',monospace; letter-spacing:1px;">
                    [{priority}] ACTION {i}
                </div>
                <div style="font-size:13px; margin-top:4px;">{action.get('action','')}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("### 🧠 Analysis Reasoning")
    reasoning = result.get("reasoning", "No reasoning provided.")
    st.markdown(f"""
    <div class="threat-card">
        <div style="font-size:14px; line-height:1.7; color:#c8d6e5;">
            {reasoning.replace(chr(10), '<br>')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("🔩 Raw JSON Output"):
        st.json(result)

elif (analyze_btn_logs and not log_input.strip()):
    st.warning("Please paste some network logs first.")

if clear_btn:
    st.rerun()

st.divider()
st.markdown("""
<div style="text-align:center; color:#57606f; font-size:12px; font-family:'Share Tech Mono',monospace; padding:10px 0;">
    NETWORK THREAT ANALYZER · GROQ-POWERED AGENTIC RAG SYSTEM · v2.0
</div>
""", unsafe_allow_html=True)