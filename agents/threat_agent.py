"""
Agentic Threat Analysis Pipeline.
Multi-step agent that: detects anomalies → extracts IPs → queries threat intel
→ retrieves RAG context → generates LLM reasoning → produces actions.
"""

import re
import json
import time
import requests
from collections import defaultdict
from datetime import datetime

# ─────────────────────────────────────────────
# Threat Intel Database (mock + heuristics)
# ─────────────────────────────────────────────
KNOWN_MALICIOUS_RANGES = {
    "45.33": {"org": "Linode/Akamai", "reputation": "HIGH RISK - Known scanner"},
    "198.51.100": {"org": "TEST-NET-3", "reputation": "HIGH RISK - Documentation range, often spoofed"},
    "203.0.113": {"org": "TEST-NET-3", "reputation": "HIGH RISK - Known in attack reports"},
    "192.0.2": {"org": "TEST-NET-1", "reputation": "MEDIUM RISK - Reserved, often spoofed"},
}

PRIVATE_RANGES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                  "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                  "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]

SQL_PATTERNS = [
    "' OR ", "' AND ", "UNION SELECT", "DROP TABLE", "1=1", "OR 1=1",
    "' --", "\" --", "SLEEP(", "BENCHMARK(", "LOAD_FILE(", "INTO OUTFILE"
]

XSS_PATTERNS = [
    "<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"
]

SENSITIVE_PATHS = [
    "/.env", "/config", "/admin", "/wp-admin", "/phpmyadmin", "/.git",
    "/etc/passwd", "/proc/", "/backup", "/.htaccess", "/server-status"
]


class ThreatAnalysisAgent:
    """
    5-step agentic pipeline for threat analysis.
    """

    def __init__(self, knowledge_base,
                 ollama_base_url: str = "http://localhost:11434",
                 ollama_model: str = "llama3"):
        self.kb = knowledge_base
        self.ollama_base_url = ollama_base_url.rstrip("/")
        self.ollama_model = ollama_model

    # kept for backwards-compat so app.py callers don't break
    def set_api_key(self, key: str):
        pass

    # ─────────────────────────────────────────
    # STEP 1: Detect Anomalies
    # ─────────────────────────────────────────
    def _step1_detect_anomalies(self, log_text: str) -> dict:
        """Parse logs and detect statistical anomalies."""
        lines = [l.strip() for l in log_text.strip().split('\n') if l.strip()]

        ip_requests = defaultdict(list)
        ip_failures = defaultdict(int)
        ip_paths = defaultdict(set)
        anomalies = []
        attack_patterns = []

        for line in lines:
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            http_match = re.search(r'"(\w+)\s+([^\s"]+)[^"]*"\s+(\d+)', line)
            if http_match:
                method = http_match.group(1)
                path = http_match.group(2)
                status = int(http_match.group(3))
            else:
                method, path, status = "UNKNOWN", "/", 0

            ip_requests[ip].append({
                "method": method, "path": path, "status": status, "line": line
            })

            if status in [401, 403, 404, 500]:
                ip_failures[ip] += 1

            ip_paths[ip].add(path)

            for pattern in SQL_PATTERNS:
                if pattern.upper() in line.upper():
                    anomalies.append({"ip": ip, "type": "SQL_INJECTION", "evidence": pattern, "line": line})
                    if not any(p["name"] == "SQL Injection" for p in attack_patterns):
                        attack_patterns.append({"name": "SQL Injection", "description": "SQL keywords detected in request parameters"})
                    break

            for pattern in XSS_PATTERNS:
                if pattern.lower() in line.lower():
                    anomalies.append({"ip": ip, "type": "XSS_ATTEMPT", "evidence": pattern, "line": line})
                    break

            for sp in SENSITIVE_PATHS:
                if sp in path:
                    anomalies.append({"ip": ip, "type": "PATH_TRAVERSAL", "evidence": sp, "line": line})
                    if not any(p["name"] == "Reconnaissance Scanning" for p in attack_patterns):
                        attack_patterns.append({"name": "Reconnaissance Scanning", "description": "Probing sensitive endpoints and configuration files"})
                    break

        for ip, fail_count in ip_failures.items():
            if fail_count >= 3:
                anomalies.append({
                    "ip": ip, "type": "BRUTE_FORCE",
                    "evidence": f"{fail_count} failed requests", "line": ""
                })
                if not any(p["name"] == "Brute Force Attack" for p in attack_patterns):
                    attack_patterns.append({"name": "Brute Force Attack", "description": f"Multiple authentication failures detected"})

        for ip, reqs in ip_requests.items():
            if len(reqs) >= 4:
                anomalies.append({
                    "ip": ip, "type": "TRAFFIC_SPIKE",
                    "evidence": f"{len(reqs)} requests detected", "line": ""
                })
                if not any(p["name"] == "Traffic Spike / DDoS" for p in attack_patterns):
                    attack_patterns.append({"name": "Traffic Spike / DDoS", "description": "Unusually high request volume from single source"})

        for ip, paths in ip_paths.items():
            if len(paths) >= 4:
                if not any(a["ip"] == ip and a["type"] == "PORT_SCAN" for a in anomalies):
                    anomalies.append({
                        "ip": ip, "type": "PORT_SCAN",
                        "evidence": f"Probed {len(paths)} unique paths", "line": ""
                    })
                    if not any(p["name"] == "Port/Path Scanning" for p in attack_patterns):
                        attack_patterns.append({"name": "Port/Path Scanning", "description": "Multiple unique endpoints probed"})

        return {
            "anomalies": anomalies,
            "attack_patterns": attack_patterns,
            "ip_requests": dict(ip_requests),
            "ip_failures": dict(ip_failures),
            "total_lines": len(lines)
        }

    # ─────────────────────────────────────────
    # STEP 2: Extract Suspicious IPs
    # ─────────────────────────────────────────
    def _step2_extract_ips(self, anomalies: list, ip_requests: dict, ip_failures: dict) -> list:
        """Extract and deduplicate suspicious IPs with context."""
        ip_threats = defaultdict(lambda: {"types": set(), "evidence": [], "request_count": 0})

        for anomaly in anomalies:
            ip = anomaly["ip"]
            ip_threats[ip]["types"].add(anomaly["type"])
            if anomaly["evidence"]:
                ip_threats[ip]["evidence"].append(anomaly["evidence"])

        for ip in ip_requests:
            ip_threats[ip]["request_count"] = len(ip_requests[ip])

        suspicious = []
        for ip, data in ip_threats.items():
            is_private = any(ip.startswith(r) for r in PRIVATE_RANGES)
            threat_types = list(data["types"])

            suspicious.append({
                "ip": ip,
                "is_private": is_private,
                "threat_type": " + ".join(threat_types),
                "reason": "; ".join(set(data["evidence"])) or "Multiple anomalous behaviors",
                "request_count": data["request_count"],
                "threat_types_list": threat_types
            })

        suspicious.sort(key=lambda x: (x["is_private"], -len(x["threat_types_list"])))
        return suspicious

    # ─────────────────────────────────────────
    # STEP 3: Query Threat Intel
    # ─────────────────────────────────────────
    def _step3_threat_intel(self, suspicious_ips: list) -> list:
        """Query mock threat intelligence database."""
        enriched = []
        for ip_info in suspicious_ips:
            ip = ip_info["ip"]
            intel = {"ip": ip, "known_malicious": False, "org": "Unknown", "reputation": "No data"}

            for prefix, data in KNOWN_MALICIOUS_RANGES.items():
                if ip.startswith(prefix):
                    intel["known_malicious"] = True
                    intel["org"] = data["org"]
                    intel["reputation"] = data["reputation"]
                    break

            if any(ip.startswith(r) for r in PRIVATE_RANGES):
                intel["org"] = "Internal Network"
                intel["reputation"] = "Internal - Insider threat risk"

            enriched.append({**ip_info, "intel": intel})

        return enriched

    # ─────────────────────────────────────────
    # STEP 4: RAG Query
    # ─────────────────────────────────────────
    def _step4_rag_query(self, anomaly_data: dict, suspicious_ips: list) -> tuple[str, list]:
        """Retrieve relevant security knowledge."""
        all_types = []
        for ip in suspicious_ips:
            all_types.extend(ip.get("threat_types_list", []))

        attack_names = [p["name"] for p in anomaly_data.get("attack_patterns", [])]
        query = " ".join(set(all_types + attack_names)) or "network attack anomaly"

        context = self.kb.get_context(query)
        titles = self.kb.get_titles(query)

        return context, titles

    # ─────────────────────────────────────────
    # STEP 5 + 6: Ollama Reasoning + Actions
    # ─────────────────────────────────────────
    def _step5_llm_analyze(self, log_text: str, anomaly_data: dict,
                            suspicious_ips: list, rag_context: str) -> dict:
        """Call Ollama for reasoning and action generation."""

        ip_summary = json.dumps([{
            "ip": ip["ip"],
            "threat_type": ip["threat_type"],
            "request_count": ip["request_count"],
            "intel": ip.get("intel", {})
        } for ip in suspicious_ips[:5]], indent=2)

        patterns = json.dumps([p["name"] for p in anomaly_data.get("attack_patterns", [])], indent=2)

        prompt = f"""You are a cybersecurity analyst. Analyze this network threat report and respond in JSON.

=== DETECTED ANOMALIES ===
Suspicious IPs:
{ip_summary}

Attack Patterns Detected:
{patterns}

Total log lines analyzed: {anomaly_data.get('total_lines', 0)}

=== SECURITY KNOWLEDGE BASE (RAG) ===
{rag_context}

=== ORIGINAL LOGS ===
{log_text[:1500]}

Respond with ONLY valid JSON (no markdown, no extra text):
{{
  "threat_level": "HIGH|MEDIUM|LOW",
  "reasoning": "2-3 sentence expert analysis of what is happening and why it's dangerous",
  "recommended_actions": [
    {{"priority": "HIGH|MEDIUM|LOW", "action": "specific action to take"}},
    {{"priority": "HIGH|MEDIUM|LOW", "action": "specific action to take"}},
    {{"priority": "MEDIUM|LOW", "action": "specific action to take"}},
    {{"priority": "LOW", "action": "monitoring or long-term action"}}
  ]
}}"""

        try:
            response = requests.post(
                f"{self.ollama_base_url}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "system": "You are a cybersecurity expert. Respond ONLY with valid JSON — no markdown, no explanation.",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 1024},
                },
                timeout=120,
            )
            response.raise_for_status()
            text = response.json().get("response", "").strip()

            # Strip markdown fences if the model adds them
            text = re.sub(r'^```json\s*', '', text)
            text = re.sub(r'\s*```$', '', text)

            # Try to extract a JSON object if there's surrounding noise
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                text = match.group()

            return json.loads(text)

        except Exception as e:
            # Fallback: rule-based output
            has_high = any(
                ip.get("intel", {}).get("known_malicious") or
                "BRUTE_FORCE" in ip.get("threat_types_list", []) or
                "SQL_INJECTION" in ip.get("threat_types_list", [])
                for ip in suspicious_ips
            )
            level = "HIGH" if has_high else ("MEDIUM" if suspicious_ips else "LOW")

            return {
                "threat_level": level,
                "reasoning": (
                    f"Analysis detected {len(suspicious_ips)} suspicious IP(s) with patterns including: "
                    f"{', '.join(set(t for ip in suspicious_ips for t in ip.get('threat_types_list', [])))}. "
                    f"Immediate investigation recommended. (Ollama unavailable: {str(e)[:100]})"
                ),
                "recommended_actions": [
                    {"priority": "HIGH", "action": "Block all identified suspicious IPs at firewall level immediately"},
                    {"priority": "HIGH", "action": "Enable enhanced logging and alerting on affected endpoints"},
                    {"priority": "MEDIUM", "action": "Review authentication logs for successful logins after attack window"},
                    {"priority": "LOW", "action": "Implement rate limiting and CAPTCHA on login endpoints"}
                ]
            }

    # ─────────────────────────────────────────
    # Main analyze pipeline
    # ─────────────────────────────────────────
    def analyze(self, log_text: str, on_step=None) -> dict:
        """Run full 6-step agentic analysis pipeline."""

        def step(idx, msg):
            if on_step:
                on_step(idx, msg)

        step(0, "Detecting anomalies in network logs...")
        anomaly_data = self._step1_detect_anomalies(log_text)
        time.sleep(0.5)

        step(1, f"Extracting suspicious IPs from {len(anomaly_data['anomalies'])} anomalies...")
        suspicious_ips = self._step2_extract_ips(
            anomaly_data["anomalies"],
            anomaly_data["ip_requests"],
            anomaly_data["ip_failures"]
        )
        time.sleep(0.3)

        step(2, f"Querying threat intelligence for {len(suspicious_ips)} IPs...")
        suspicious_ips = self._step3_threat_intel(suspicious_ips)
        time.sleep(0.5)

        step(3, "Retrieving relevant security knowledge via RAG...")
        rag_context, rag_titles = self._step4_rag_query(anomaly_data, suspicious_ips)
        time.sleep(0.3)

        step(4, f"Running Ollama ({self.ollama_model}) reasoning and analysis...")
        llm_result = self._step5_llm_analyze(log_text, anomaly_data, suspicious_ips, rag_context)
        step(5, "Generating recommended actions...")
        time.sleep(0.3)

        return {
            "threat_level": llm_result.get("threat_level", "MEDIUM"),
            "suspicious_ips": suspicious_ips,
            "attack_patterns": anomaly_data.get("attack_patterns", []),
            "reasoning": llm_result.get("reasoning", ""),
            "recommended_actions": llm_result.get("recommended_actions", []),
            "rag_context": rag_titles,
            "stats": {
                "total_lines": anomaly_data.get("total_lines", 0),
                "anomalies_detected": len(anomaly_data.get("anomalies", [])),
                "suspicious_ips_count": len(suspicious_ips)
            }
        }