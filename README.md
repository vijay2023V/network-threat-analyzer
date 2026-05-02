# 🛡️ Network Threat Analyzer

An **agentic AI security platform** that analyzes network logs, detects anomalies, queries threat intelligence, and generates actionable security recommendations using RAG + Claude AI.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Streamlit](https://img.shields.io/badge/UI-Streamlit-red) ![Claude](https://img.shields.io/badge/AI-Claude%20Sonnet-purple) ![RAG](https://img.shields.io/badge/RAG-FAISS%20Vector%20DB-green)

---

## 🎯 What It Does

A **6-step agentic pipeline** that doesn't just answer — it *acts*:

| Step | Agent Action |
|------|-------------|
| 1️⃣ | **Detect Anomalies** — Parse logs, find statistical outliers |
| 2️⃣ | **Extract Suspicious IPs** — Identify & deduplicate threat actors |
| 3️⃣ | **Threat Intel Lookup** — Query IP reputation database |
| 4️⃣ | **RAG Query** — Retrieve relevant security docs via vector search |
| 5️⃣ | **LLM Reasoning** — Claude generates expert analysis |
| 6️⃣ | **Action Generation** — Prioritized remediation recommendations |

---

## 🧰 Tech Stack

| Component | Technology |
|-----------|-----------|
| **UI** | Streamlit |
| **AI Agent** | Claude Sonnet (Anthropic API) |
| **RAG / Vector DB** | FAISS-style (NumPy TF-IDF vectors) |
| **Threat Intel** | Mock DB + heuristic rules |
| **Log Parser** | Custom regex-based parser |

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/network-threat-analyzer.git
cd network-threat-analyzer
pip install -r requirements.txt
```

### 2. Get API Key

Get your Anthropic API key from [console.anthropic.com](https://console.anthropic.com)

### 3. Run

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

### 4. Analyze

1. Enter your Anthropic API key in the sidebar
2. Paste network logs OR select a sample from the sidebar
3. Click **ANALYZE THREATS**
4. View the full threat report with IPs, patterns, and actions

---

## 📊 Output Format

```
🚨 THREAT LEVEL: HIGH

📍 Suspicious IPs:
  - 45.33.32.156  → TRAFFIC_SPIKE + DDoS
  - 192.168.1.10  → BRUTE_FORCE
  - 198.51.100.42 → PORT_SCAN + PATH_TRAVERSAL

📊 Reasoning:
  Two attack vectors detected simultaneously...

🛠 Recommended Actions:
  [HIGH]   Block 45.33.32.156 at firewall
  [HIGH]   Enable rate limiting on /login
  [MEDIUM] Review auth logs for successful logins
  [LOW]    Implement CAPTCHA on auth endpoints
```

---

## 📁 Project Structure

```
network-threat-analyzer/
├── app.py                    # Streamlit UI
├── requirements.txt          
├── agents/
│   └── threat_agent.py       # 6-step agentic pipeline
└── rag/
    └── knowledge_base.py     # FAISS vector store + security docs
```

---

## 🔒 Sample Log Formats Supported

**HTTP Access Logs:**
```
192.168.1.10 - - [01/May/2026:10:23:01] "POST /login HTTP/1.1" 401 -
```

**Simple Format:**
```
IP: 45.33.x.x → unusual traffic spike
IP: 192.168.1.10 → Failed login attempts
```

---

## 🛠 Extending the Project

- **Add real threat intel**: Integrate [AbuseIPDB API](https://www.abuseipdb.com/api)
- **Add FAISS**: Replace NumPy vectors with `faiss-cpu` for scale
- **Add LangChain**: Replace custom agent with LangChain agent executor
- **Add Slack alerts**: Send HIGH threat alerts to Slack webhook
- **Add log streaming**: Connect to live log sources via WebSocket

---

## 📄 License

MIT — free to use, modify, and distribute.
