"""
RAG Knowledge Base using TF-IDF cosine similarity.
Covers HTTP, FTP, SSH, Telnet, and protocol-aware attack patterns.
"""

import re
import numpy as np

SECURITY_DOCS = [
    {
        "id": "ftp_brute_force",
        "title": "FTP Brute Force / Credential Attack",
        "content": """
        FTP brute force attacks repeatedly attempt login credentials against an FTP server.
        Protocol: FTP operates on TCP port 21 (control) and 20 (data).
        Key indicators in pcap/logs: Repeated USER + PASS command sequences from same IP.
        Failure response: FTP 530 "Login incorrect" — each failed attempt shows this code.
        Success response: FTP 230 "User logged in" — indicates successful compromise.
        Pattern: Attacker sends USER <name> then PASS <password> in loop, incrementing passwords.
        Sequential passwords (1, 2, 3... or dictionary words) are classic automated brute force.
        Initiator role: The IP sending USER/PASS commands is the ATTACKER; the responding server is the VICTIM.
        Tools used: Hydra, Medusa, Metasploit ftp_login module, custom scripts.
        Thresholds: 5+ failed logins (530) from one IP = brute force confirmed.
        Mitigation: Disable FTP entirely (use SFTP/FTPS), account lockout after 3 failures,
        firewall port 21 to trusted IPs only, strong passwords, fail2ban.
        """,
    },
    {
        "id": "ssh_brute_force",
        "title": "SSH Brute Force Attack",
        "content": """
        SSH brute force attacks target TCP port 22 with repeated authentication attempts.
        Key indicators: Many TCP connections to port 22 from same source IP in short time.
        Failed auth: Connection reset or disconnect after each failed attempt.
        Successful compromise: Sustained SSH session (large data transfer, long connection).
        Tools: Hydra, Medusa, Ncrack, THC-Hydra.
        Thresholds: 10+ connection attempts to port 22 from single IP within 60 seconds.
        Mitigation: Disable password auth (use key-based only), change default port,
        fail2ban, AllowUsers directive, rate limiting via iptables.
        """,
    },
    {
        "id": "credential_stuffing",
        "title": "Credential Stuffing and Password Spraying",
        "content": """
        Credential stuffing uses leaked username/password pairs from data breaches.
        Password spraying tries one common password across many accounts to avoid lockouts.
        FTP/SSH indicators: Same source trying many usernames, or one username with many passwords.
        HTTP indicators: POST /login with 401 responses in rapid succession.
        Difference from brute force: Credential stuffing uses real leaked credentials (higher success rate).
        Sequential numeric passwords (1,2,3...) = simple brute force (unsophisticated attacker).
        Dictionary attack: Uses wordlists (rockyou.txt, common passwords).
        Mitigation: MFA, credential breach monitoring (HaveIBeenPwned API), account lockout,
        CAPTCHA, anomaly-based detection on auth failure rates.
        """,
    },
    {
        "id": "brute_force_http",
        "title": "HTTP Brute Force Attack Patterns",
        "content": """
        HTTP brute force attacks target web login forms via repeated POST requests.
        Key indicators: Multiple 401/403 HTTP responses from the same IP within seconds.
        Threshold: More than 5 failed login attempts in 60 seconds from one IP.
        Common targets: /login, /admin, /wp-admin, /api/auth endpoints.
        Status codes: 401 Unauthorized, 403 Forbidden = failed auth.
        Success indicator: 200 or 302 redirect after a series of failures.
        Mitigation: Rate limiting, account lockout, CAPTCHA, IP blocking after threshold.
        Tools used by attackers: Hydra, Medusa, Burp Suite Intruder.
        """,
    },
    {
        "id": "ddos",
        "title": "DDoS and Traffic Spike Detection",
        "content": """
        Distributed Denial of Service attacks flood servers with traffic to cause outage.
        Key indicators: Unusually high request rate from single or multiple IPs simultaneously.
        Threshold: >100 requests/second from single IP, >1000 req/s total spike.
        Types: Volume-based (UDP flood), Protocol attacks (SYN flood), Application layer (HTTP flood).
        Mitigation: Rate limiting, CDN protection, IP blocking, traffic scrubbing services.
        Detection: Monitor requests per second, bandwidth utilization, connection count.
        DDoS differs from brute force: goal is availability disruption, not credential theft.
        """,
    },
    {
        "id": "port_scan",
        "title": "Port Scanning and Reconnaissance",
        "content": """
        Port scanning discovers open services before launching targeted attacks.
        Key indicators: Sequential SYN packets to many different ports from one source IP.
        Path scanning: Rapid GET requests to many different URL paths (/admin, /.env, /config).
        Patterns: Many 404 responses in rapid succession across different endpoints.
        Common scan targets: SSH (22), Telnet (23), FTP (21), HTTP (80), HTTPS (443), MySQL (3306).
        Threshold: 10+ unique ports or paths probed within 30 seconds = active scanning.
        Tools: Nmap, Masscan, ZMap, Gobuster (web path scanning).
        Mitigation: Firewall rules, fail2ban, honeypots, IDS/IPS systems.
        """,
    },
    {
        "id": "sql_injection",
        "title": "SQL Injection Detection",
        "content": """
        SQL injection attacks manipulate database queries through unsanitized input.
        Key indicators: SQL keywords in URL parameters or POST bodies.
        Common payloads: ' OR '1'='1, UNION SELECT, 1; DROP TABLE, ' AND 1=1--.
        HTTP status clues: 500 errors after SQL payloads indicate query execution errors.
        Blind SQLi: Boolean-based (no error shown) or time-based (SLEEP/BENCHMARK).
        Mitigation: Parameterized queries, WAF, input validation, least privilege DB accounts.
        Detection: Monitor for SQL keywords in query strings and POST bodies.
        """,
    },
    {
        "id": "xss",
        "title": "Cross-Site Scripting (XSS) Detection",
        "content": """
        XSS attacks inject malicious scripts into web responses viewed by other users.
        Key indicators: Script tags, javascript: URIs, event handlers in request parameters.
        Common payloads: <script>alert(1)</script>, onerror=alert, javascript:void.
        Types: Reflected XSS (parameter echoed back), Stored XSS (saved to DB), DOM-based.
        Mitigation: Content Security Policy headers, output encoding, input sanitization.
        Detection: WAF rules, monitor for HTML/JS tags in parameters.
        """,
    },
    {
        "id": "known_malicious_ips",
        "title": "Known Malicious IP Ranges and Threat Intel",
        "content": """
        Certain IP ranges are frequently associated with malicious scanning activity.
        Shodan scanner ranges: 45.33.x.x commonly appear in scan and brute force reports.
        Documentation ranges abused: 198.51.100.x, 203.0.113.x, 192.0.2.x (RFC 5737).
        Private ranges (RFC 1918): 10.x.x.x, 172.16-31.x.x, 192.168.x.x = internal network.
        Internal threats are insider attacks, compromised internal hosts, or lateral movement.
        Tor exit nodes: Often used for anonymized attacks — check exit node lists.
        Threat intel sources: AbuseIPDB, Shodan, VirusTotal, Emerging Threats, Spamhaus.
        """,
    },
    {
        "id": "incident_response",
        "title": "Incident Response Playbook",
        "content": """
        Standard incident response steps for confirmed network threats:
        1. CONTAIN: Immediately block confirmed malicious IPs via firewall/ACL.
        2. IDENTIFY: Determine attack vector, scope, and affected systems/accounts.
        3. ERADICATE: Remove malicious access, patch exploited vulnerabilities.
        4. RECOVER: Restore normal operations, reset compromised credentials.
        5. DOCUMENT: Log all findings for forensics, compliance, and post-mortem.
        Escalation: HIGH threats require immediate security team notification.
        FTP brute force: Disable FTP service if not required; rotate affected credentials.
        Tools: iptables, pfSense, CloudFlare, AWS WAF, fail2ban, Snort/Suricata.
        """,
    },
    {
        "id": "http_anomaly",
        "title": "HTTP Anomaly Detection",
        "content": """
        HTTP traffic anomalies signal potential web-layer attacks.
        Status code patterns: Spike in 4xx errors (scanning/brute force), 5xx (injection).
        User-agent anomalies: Bot signatures, missing user agents, scanner fingerprints.
        Request size: Unusually large POST bodies may indicate data injection or exfiltration.
        Timing patterns: Requests at perfectly regular intervals strongly suggest automation.
        Sensitive endpoint probing: /etc/passwd, /proc, /.git, /.env, /config, /backup.
        """,
    },
    {
        "id": "data_exfiltration",
        "title": "Data Exfiltration Detection",
        "content": """
        Data exfiltration involves unauthorized data transfer outside the network perimeter.
        Indicators: Unusually large outbound data volumes, DNS tunneling, HTTPS to unknown hosts.
        Detection: Monitor outbound traffic volume, unusual destination IPs/domains, off-hours transfers.
        Common exfil methods: HTTP POST to external servers, FTP upload, DNS tunneling, cloud storage abuse.
        After-hours activity: Large transfers outside business hours are highly suspicious.
        Mitigation: DLP (Data Loss Prevention), egress filtering, network monitoring, CASB.
        """,
    },
    {
        "id": "telnet_attack",
        "title": "Telnet Brute Force and Exploitation",
        "content": """
        Telnet (TCP port 23) is an unencrypted legacy protocol frequently targeted.
        Risk: All credentials and data transmitted in plaintext — trivial to sniff.
        Brute force indicators: Repeated TCP connections to port 23 from same source.
        Mirai botnet: Famous for Telnet brute force against IoT devices using default creds.
        Common default credentials targeted: admin/admin, root/root, root/toor, admin/1234.
        Mitigation: Disable Telnet entirely, use SSH instead, firewall port 23.
        """,
    },
]


class SecurityKnowledgeBase:
    """
    TF-IDF cosine similarity knowledge base for security threat retrieval.
    No external APIs or heavy dependencies — pure numpy.
    """

    def __init__(self):
        self.documents = SECURITY_DOCS
        self.vectors = None
        self.vocab: dict[str, int] = {}
        self._built = False

    # ── Tokenization & vectorization ─────────────────────────────────────────

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r'\b[a-z]{3,}\b', text.lower())

    def _build_vocab(self, texts: list[str]) -> dict[str, int]:
        vocab: dict[str, int] = {}
        for text in texts:
            for tok in self._tokenize(text):
                if tok not in vocab:
                    vocab[tok] = len(vocab)
        return vocab

    def _vectorize(self, text: str) -> np.ndarray:
        tokens = self._tokenize(text)
        vec = np.zeros(len(self.vocab))
        for tok in tokens:
            if tok in self.vocab:
                vec[self.vocab[tok]] += 1
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec

    # ── Build / query ─────────────────────────────────────────────────────────

    def build(self):
        if self._built:
            return
        texts = [d["content"] for d in self.documents]
        self.vocab = self._build_vocab(texts)
        self.vectors = np.array([self._vectorize(t) for t in texts])
        self._built = True

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        if not self._built:
            self.build()
        q_vec = self._vectorize(query)
        scores = self.vectors @ q_vec
        top_idx = np.argsort(scores)[::-1][:top_k]
        results = []
        for i in top_idx:
            if scores[i] > 0.01:
                doc = self.documents[i].copy()
                doc["score"] = float(scores[i])
                results.append(doc)
        return results

    def get_context(self, query: str, max_chars: int = 2500) -> str:
        docs = self.retrieve(query, top_k=4)
        parts, total = [], 0
        for doc in docs:
            chunk = f"[{doc['title']}]:\n{doc['content'].strip()}"
            if total + len(chunk) <= max_chars:
                parts.append(chunk)
                total += len(chunk)
        return "\n\n".join(parts)

    def get_titles(self, query: str) -> list[str]:
        docs = self.retrieve(query, top_k=3)
        return [f"📄 {d['title']} (score: {d['score']:.2f})" for d in docs]