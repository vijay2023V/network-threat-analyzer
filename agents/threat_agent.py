"""
Agentic Threat Analysis Pipeline — v2.2
Supports HTTP logs AND protocol-aware pcap-derived logs (FTP, SSH, Telnet).
Correctly identifies attacker vs victim roles.
Robust Groq error handling — never leaks raw exceptions to UI.
"""

import re
import json
import time
import requests
from collections import defaultdict

# ── Threat Intel DB ───────────────────────────────────────────────────────────

KNOWN_MALICIOUS_RANGES = {
    "45.33":      {"org": "Linode/Akamai",    "reputation": "HIGH RISK - Known scanner"},
    "198.51.100": {"org": "TEST-NET-3",        "reputation": "HIGH RISK - Documentation range, often spoofed"},
    "203.0.113":  {"org": "TEST-NET-3",        "reputation": "HIGH RISK - Known in attack reports"},
    "192.0.2":    {"org": "TEST-NET-1",        "reputation": "MEDIUM RISK - Reserved, often spoofed"},
}

PRIVATE_RANGES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.",
]

# ── Signature patterns ────────────────────────────────────────────────────────

SQL_PATTERNS    = ["' OR ", "' AND ", "UNION SELECT", "DROP TABLE", "1=1",
                   "OR 1=1", "' --", "\" --", "SLEEP(", "BENCHMARK(",
                   "LOAD_FILE(", "INTO OUTFILE"]
XSS_PATTERNS    = ["<script", "javascript:", "onerror=", "onload=",
                   "alert(", "document.cookie"]
SENSITIVE_PATHS = ["/.env", "/config", "/admin", "/wp-admin", "/phpmyadmin",
                   "/.git", "/etc/passwd", "/proc/", "/backup",
                   "/.htaccess", "/server-status"]

# ── Thresholds (tuned to avoid false positives) ───────────────────────────────
BRUTE_FORCE_HTTP_THRESHOLD  = 5    # failed HTTP auth (401/403) from one IP
TRAFFIC_SPIKE_THRESHOLD     = 50   # total requests from one IP
PORT_SCAN_PATH_THRESHOLD    = 10   # unique paths probed by one IP
FTP_BRUTE_FORCE_THRESHOLD   = 5    # FTP 530 failures from one IP
SSH_BRUTE_FORCE_THRESHOLD   = 8    # SSH SYN probes to port 22 from one IP

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class ThreatAnalysisAgent:
    """Multi-step agentic pipeline: detect → extract → intel → RAG → reason → act."""

    def __init__(self, knowledge_base, groq_api_key: str = "",
                 groq_model: str = "llama3-8b-8192"):
        self.kb = knowledge_base
        self.groq_api_key = groq_api_key
        self.groq_model = groq_model

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Anomaly Detection
    # ─────────────────────────────────────────────────────────────────────────

    def _step1_detect_anomalies(self, log_text: str) -> dict:
        lines = [l.strip() for l in log_text.strip().splitlines() if l.strip()]
        anomalies: list[dict]      = []
        attack_patterns: list[dict] = []

        # ── Counters ─────────────────────────────────────────────────────────
        ip_requests  = defaultdict(list)   # all request records per IP
        ip_failures  = defaultdict(int)    # HTTP 4xx/5xx per IP
        ip_paths     = defaultdict(set)    # unique paths per IP

        # Protocol-specific counters
        ftp_failures  = defaultdict(int)   # 530 codes per source IP
        ftp_successes = defaultdict(int)   # 230 codes per source IP
        ftp_servers   = set()              # IPs that sent 530/230 (they are servers)
        ssh_syn_count = defaultdict(int)   # SYN probes to port 22 per source IP

        def _add_pattern(name: str, desc: str):
            if not any(p["name"] == name for p in attack_patterns):
                attack_patterns.append({"name": name, "description": desc})

        # ── Parse log lines ───────────────────────────────────────────────────
        for line in lines:
            # ── HTTP-style log: IP - - [date] "METHOD path HTTP/x" status - ──
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            http_match = re.search(r'"(\w+)\s+([^\s"]+)[^"]*"\s+(\d+)', line)
            if http_match:
                method = http_match.group(1)
                path   = http_match.group(2)
                status = int(http_match.group(3))
            else:
                method, path, status = "UNKNOWN", "/", 0

            # Protocol-specific methods are handled separately and must NOT
            # count toward generic traffic-spike or port-scan metrics.
            FTP_METHODS   = {"FTP_FAIL", "FTP_AUTH", "FTP_ATTEMPT"}
            PROBE_METHODS = {"PROBE", "UDP", "CONNECT"}

            if method in FTP_METHODS:
                if method == "FTP_FAIL":
                    ftp_failures[ip] += 1
                elif method == "FTP_AUTH":
                    ftp_successes[ip] += 1
                # Skip adding to ip_requests/ip_paths to avoid false TRAFFIC_SPIKE
                continue

            if method in PROBE_METHODS:
                if method == "PROBE" and ":22" in path:
                    ssh_syn_count[ip] += 1
                # Probes don't count toward HTTP traffic spike
                continue

            # ── HTTP / application-layer requests only from here ──────────
            ip_requests[ip].append({"method": method, "path": path,
                                    "status": status, "line": line})
            if status in [401, 403, 404, 500]:
                ip_failures[ip] += 1
            ip_paths[ip].add(path)

            # ── SQL injection ─────────────────────────────────────────────────
            for pat in SQL_PATTERNS:
                if pat.upper() in line.upper():
                    anomalies.append({"ip": ip, "type": "SQL_INJECTION",
                                      "evidence": f"SQL pattern: {pat}", "line": line})
                    _add_pattern("SQL Injection",
                                 "SQL keywords detected in request parameters")
                    break

            # ── XSS ───────────────────────────────────────────────────────────
            for pat in XSS_PATTERNS:
                if pat.lower() in line.lower():
                    anomalies.append({"ip": ip, "type": "XSS_ATTEMPT",
                                      "evidence": f"XSS pattern: {pat}", "line": line})
                    _add_pattern("XSS Attempt",
                                 "Script injection patterns detected in request")
                    break

            # ── Sensitive path probing ────────────────────────────────────────
            for sp in SENSITIVE_PATHS:
                if sp in path:
                    anomalies.append({"ip": ip, "type": "PATH_TRAVERSAL",
                                      "evidence": f"Sensitive path: {sp}", "line": line})
                    _add_pattern("Reconnaissance Scanning",
                                 "Probing sensitive endpoints and configuration files")
                    break

        # ── Threshold-based anomaly flagging ──────────────────────────────────

        # HTTP brute force
        for ip, fail_count in ip_failures.items():
            if fail_count >= BRUTE_FORCE_HTTP_THRESHOLD:
                anomalies.append({"ip": ip, "type": "BRUTE_FORCE_HTTP",
                                  "evidence": f"{fail_count} failed HTTP auth requests",
                                  "line": ""})
                _add_pattern("HTTP Brute Force",
                             "Multiple authentication failures on web endpoints")

        # Traffic spike (only flag IPs not identified as servers)
        for ip, reqs in ip_requests.items():
            if len(reqs) >= TRAFFIC_SPIKE_THRESHOLD and ip not in ftp_servers:
                anomalies.append({"ip": ip, "type": "TRAFFIC_SPIKE",
                                  "evidence": f"{len(reqs)} requests detected",
                                  "line": ""})
                _add_pattern("Traffic Spike / DDoS",
                             "Unusually high request volume from a single source")

        # Port/path scanning — only non-server IPs
        for ip, paths in ip_paths.items():
            if len(paths) >= PORT_SCAN_PATH_THRESHOLD and ip not in ftp_servers:
                anomalies.append({"ip": ip, "type": "PORT_SCAN",
                                  "evidence": f"Probed {len(paths)} unique paths/ports",
                                  "line": ""})
                _add_pattern("Port / Path Scanning",
                             "Multiple unique endpoints or ports probed from one source")

        # FTP brute force
        for ip, fail_count in ftp_failures.items():
            if fail_count >= FTP_BRUTE_FORCE_THRESHOLD:
                anomalies.append({"ip": ip, "type": "FTP_BRUTE_FORCE",
                                  "evidence": f"{fail_count} failed FTP logins (530 responses)",
                                  "line": ""})
                _add_pattern("FTP Brute Force",
                             "Repeated failed FTP authentication attempts (530 Login incorrect)")

        # FTP success after failures = likely compromised
        for ip in ftp_successes:
            if ftp_failures.get(ip, 0) > 0:
                anomalies.append({"ip": ip, "type": "FTP_COMPROMISE",
                                  "evidence": "Successful FTP login after repeated failures",
                                  "line": ""})
                _add_pattern("Account Compromise",
                             "Attacker succeeded in logging in after brute force attempts")

        # SSH brute force
        for ip, count in ssh_syn_count.items():
            if count >= SSH_BRUTE_FORCE_THRESHOLD:
                anomalies.append({"ip": ip, "type": "SSH_BRUTE_FORCE",
                                  "evidence": f"{count} connection attempts to SSH port 22",
                                  "line": ""})
                _add_pattern("SSH Brute Force",
                             "Repeated connection attempts against SSH service")

        return {
            "anomalies": anomalies,
            "attack_patterns": attack_patterns,
            "ip_requests": dict(ip_requests),
            "ip_failures": dict(ip_failures),
            "ftp_failures": dict(ftp_failures),
            "ftp_successes": dict(ftp_successes),
            "total_lines": len(lines),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — Extract & classify suspicious IPs (with role awareness)
    # ─────────────────────────────────────────────────────────────────────────

    def _step2_extract_ips(self, anomaly_data: dict) -> list[dict]:
        anomalies     = anomaly_data["anomalies"]
        ip_requests   = anomaly_data["ip_requests"]
        ftp_failures  = anomaly_data.get("ftp_failures", {})
        ftp_successes = anomaly_data.get("ftp_successes", {})

        ip_threats: dict = defaultdict(lambda: {
            "types": set(), "evidence": [], "request_count": 0, "role": "unknown"
        })

        for a in anomalies:
            ip = a["ip"]
            ip_threats[ip]["types"].add(a["type"])
            if a["evidence"]:
                ip_threats[ip]["evidence"].append(a["evidence"])

        # For HTTP traffic, count from ip_requests
        for ip, reqs in ip_requests.items():
            if ip in ip_threats:
                ip_threats[ip]["request_count"] = len(reqs)

        # For FTP attackers, set request_count from ftp_failures (login attempts)
        for ip, fail_count in ftp_failures.items():
            if ip in ip_threats:
                ip_threats[ip]["request_count"] = max(
                    ip_threats[ip]["request_count"], fail_count
                )

        # Assign roles based on threat types
        # IPs with attack-type anomalies = attacker
        # IPs with only TRAFFIC_SPIKE or PORT_SCAN without active attack types = suspicious
        ATTACKER_TYPES = {
            "FTP_BRUTE_FORCE", "FTP_COMPROMISE", "SSH_BRUTE_FORCE",
            "BRUTE_FORCE_HTTP", "SQL_INJECTION", "XSS_ATTEMPT",
        }
        for ip, data in ip_threats.items():
            if any(t in data["types"] for t in ATTACKER_TYPES):
                data["role"] = "attacker"
            elif "PORT_SCAN" in data["types"]:
                data["role"] = "attacker"
            else:
                data["role"] = "suspicious"

        suspicious = []
        for ip, data in ip_threats.items():
            is_private = any(ip.startswith(r) for r in PRIVATE_RANGES)
            types_list = list(data["types"])
            # Deduplicate evidence
            evidence = list(dict.fromkeys(data["evidence"]))
            suspicious.append({
                "ip": ip,
                "role": data["role"],
                "is_private": is_private,
                "threat_type": " + ".join(types_list),
                "reason": "; ".join(evidence) or "Multiple anomalous behaviours detected",
                "request_count": data["request_count"],
                "threat_types_list": types_list,
            })

        # Sort: attackers first, then by number of threat types
        suspicious.sort(key=lambda x: (
            0 if x["role"] == "attacker" else 1 if x["role"] == "suspicious" else 2,
            -len(x["threat_types_list"])
        ))
        return suspicious

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Threat Intel Enrichment
    # ─────────────────────────────────────────────────────────────────────────

    def _step3_threat_intel(self, suspicious_ips: list[dict]) -> list[dict]:
        enriched = []
        for ip_info in suspicious_ips:
            ip = ip_info["ip"]
            intel = {"ip": ip, "known_malicious": False,
                     "org": "Unknown", "reputation": "No data available"}

            for prefix, data in KNOWN_MALICIOUS_RANGES.items():
                if ip.startswith(prefix):
                    intel["known_malicious"] = True
                    intel["org"]             = data["org"]
                    intel["reputation"]      = data["reputation"]
                    break

            if any(ip.startswith(r) for r in PRIVATE_RANGES):
                intel["org"]        = "Internal Network"
                intel["reputation"] = (
                    "Internal — possible insider threat or compromised host"
                    if ip_info["role"] == "attacker"
                    else "Internal — server/service host"
                )

            enriched.append({**ip_info, "intel": intel})
        return enriched

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — RAG Context Retrieval
    # ─────────────────────────────────────────────────────────────────────────

    def _step4_rag_query(self, anomaly_data: dict,
                          suspicious_ips: list[dict]) -> tuple[str, list[str]]:
        all_types = []
        for ip in suspicious_ips:
            all_types.extend(ip.get("threat_types_list", []))

        attack_names = [p["name"] for p in anomaly_data.get("attack_patterns", [])]
        query = " ".join(dict.fromkeys(all_types + attack_names)) or "network attack"

        context = self.kb.get_context(query)
        titles  = self.kb.get_titles(query)
        return context, titles

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — Groq LLM Reasoning
    # ─────────────────────────────────────────────────────────────────────────

    def _step5_llm_analyze(self, log_text: str, anomaly_data: dict,
                            suspicious_ips: list[dict], rag_context: str) -> dict:
        ip_summary = json.dumps([{
            "ip":           ip["ip"],
            "role":         ip["role"],
            "threat_type":  ip["threat_type"],
            "reason":       ip["reason"],
            "request_count": ip["request_count"],
            "intel":        ip.get("intel", {}),
        } for ip in suspicious_ips[:6]], indent=2)

        patterns = json.dumps(
            [p["name"] for p in anomaly_data.get("attack_patterns", [])], indent=2
        )

        ftp_info = ""
        if anomaly_data.get("ftp_failures"):
            ftp_info = f"\nFTP login failures per IP: {dict(anomaly_data['ftp_failures'])}"
        if anomaly_data.get("ftp_successes"):
            ftp_info += f"\nFTP successful logins: {dict(anomaly_data['ftp_successes'])}"

        prompt = f"""You are a senior network security analyst. Analyze the threat data below and respond in strict JSON.

=== DETECTED ANOMALIES ===
Suspicious IPs (with roles — attacker vs server/victim):
{ip_summary}

Attack Patterns Detected:
{patterns}
{ftp_info}

Total log lines analyzed: {anomaly_data.get('total_lines', 0)}

=== SECURITY KNOWLEDGE BASE (RAG) ===
{rag_context}

=== RAW LOG SAMPLE ===
{log_text[:1500]}

Respond with ONLY valid JSON — no markdown fences, no preamble, no trailing text:
{{
  "threat_level": "HIGH|MEDIUM|LOW",
  "reasoning": "2–3 sentences: what attack is occurring, which IP is the attacker, which is the victim, and the risk level",
  "recommended_actions": [
    {{"priority": "HIGH",   "action": "immediate containment action"}},
    {{"priority": "HIGH",   "action": "second critical action"}},
    {{"priority": "MEDIUM", "action": "investigation or hardening action"}},
    {{"priority": "LOW",    "action": "long-term monitoring or prevention"}}
  ]
}}"""

        try:
            resp = requests.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {self.groq_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model":       self.groq_model,
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens":  1024,
                },
                timeout=30,
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()
            # Strip markdown fences if model disobeys
            raw = re.sub(r'^```(?:json)?\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)
            # Extract first JSON object
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if m:
                raw = m.group()
            return json.loads(raw)

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "?"
            user_msg = {
                400: "Groq rejected the request (400). The prompt may be too long or malformed.",
                401: "Groq API key is invalid or expired (401). Check your key in the sidebar.",
                429: "Groq rate limit reached (429). Wait a moment and try again.",
                500: "Groq server error (500). Try again shortly.",
            }.get(status_code, f"Groq API error (HTTP {status_code}).")
            return self._fallback_result(suspicious_ips, user_msg)

        except requests.exceptions.Timeout:
            return self._fallback_result(suspicious_ips,
                "Groq request timed out (>30 s). Check your connection and retry.")

        except json.JSONDecodeError:
            return self._fallback_result(suspicious_ips,
                "Groq returned a response that could not be parsed as JSON. Retry.")

        except Exception:
            return self._fallback_result(suspicious_ips,
                "Groq reasoning unavailable. Results are based on rule-based detection only.")

    def _fallback_result(self, suspicious_ips: list[dict], notice: str) -> dict:
        """Rule-based fallback when Groq is unavailable. Never leaks raw exceptions."""
        attackers = [ip for ip in suspicious_ips if ip["role"] == "attacker"]
        has_high = any(
            t in ip.get("threat_types_list", [])
            for ip in attackers
            for t in ["FTP_BRUTE_FORCE", "SSH_BRUTE_FORCE", "SQL_INJECTION",
                      "FTP_COMPROMISE", "XSS_ATTEMPT", "BRUTE_FORCE_HTTP"]
        )
        level = "HIGH" if (has_high and attackers) else ("MEDIUM" if suspicious_ips else "LOW")

        attacker_ips = ", ".join(ip["ip"] for ip in attackers) or "unknown"
        all_types    = list(dict.fromkeys(
            t for ip in suspicious_ips for t in ip.get("threat_types_list", [])
        ))

        reasoning = (
            f"Rule-based analysis identified {len(attackers)} attacker(s) ({attacker_ips}) "
            f"exhibiting: {', '.join(all_types)}. "
            f"AI reasoning was unavailable — {notice}"
        )

        return {
            "threat_level": level,
            "reasoning": reasoning,
            "recommended_actions": [
                {"priority": "HIGH",   "action": f"Block attacker IP(s) {attacker_ips} at firewall immediately"},
                {"priority": "HIGH",   "action": "Enable detailed logging and alerting on all affected services"},
                {"priority": "MEDIUM", "action": "Rotate credentials for all accounts on targeted services"},
                {"priority": "LOW",    "action": "Harden service configurations (disable plaintext protocols, enforce MFA)"},
            ],
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Main pipeline
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(self, log_text: str, on_step=None) -> dict:
        def step(idx: int, msg: str):
            if on_step:
                on_step(idx, msg)

        step(0, "Detecting anomalies in network traffic...")
        anomaly_data = self._step1_detect_anomalies(log_text)
        time.sleep(0.4)

        step(1, f"Extracting IP roles from {len(anomaly_data['anomalies'])} anomalies...")
        suspicious_ips = self._step2_extract_ips(anomaly_data)
        time.sleep(0.3)

        step(2, f"Enriching {len(suspicious_ips)} IPs with threat intelligence...")
        suspicious_ips = self._step3_threat_intel(suspicious_ips)
        time.sleep(0.4)

        step(3, "Retrieving relevant security knowledge via RAG...")
        rag_context, rag_titles = self._step4_rag_query(anomaly_data, suspicious_ips)
        time.sleep(0.3)

        step(4, f"Running {self.groq_model} reasoning...")
        llm_result = self._step5_llm_analyze(log_text, anomaly_data,
                                              suspicious_ips, rag_context)
        step(5, "Generating prioritised actions...")
        time.sleep(0.2)

        return {
            "threat_level":        llm_result.get("threat_level", "MEDIUM"),
            "suspicious_ips":      suspicious_ips,
            "attack_patterns":     anomaly_data.get("attack_patterns", []),
            "reasoning":           llm_result.get("reasoning", ""),
            "recommended_actions": llm_result.get("recommended_actions", []),
            "rag_context":         rag_titles,
            "stats": {
                "total_lines":          anomaly_data.get("total_lines", 0),
                "anomalies_detected":   len(anomaly_data.get("anomalies", [])),
                "suspicious_ips_count": len(suspicious_ips),
                "ftp_failures":         sum(anomaly_data.get("ftp_failures", {}).values()),
                "ftp_successes":        sum(anomaly_data.get("ftp_successes", {}).values()),
            },
        }