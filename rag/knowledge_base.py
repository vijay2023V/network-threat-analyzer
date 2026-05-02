"""
RAG Knowledge Base using FAISS for security documents and attack patterns.
"""

import json
import numpy as np
import os
import pickle

# Security knowledge documents
SECURITY_DOCS = [
    {
        "id": "brute_force",
        "title": "Brute Force Attack Patterns",
        "content": """
        Brute force attacks involve repeated login attempts using automated tools.
        Key indicators: Multiple 401/403 HTTP responses from the same IP within seconds.
        Threshold: More than 5 failed login attempts in 60 seconds from one IP.
        Common targets: /login, /admin, /wp-admin, /api/auth endpoints.
        Mitigation: Rate limiting, account lockout, CAPTCHA, IP blocking after threshold.
        Tools used by attackers: Hydra, Medusa, Burp Suite Intruder.
        """
    },
    {
        "id": "ddos",
        "title": "DDoS and Traffic Spike Detection",
        "content": """
        Distributed Denial of Service attacks flood servers with traffic.
        Key indicators: Unusually high request rate from single or multiple IPs.
        Threshold: >100 requests/second from single IP, >1000 req/s total spike.
        Types: Volume-based, Protocol attacks, Application layer (HTTP flood).
        Mitigation: Rate limiting, CDN protection, IP blocking, traffic scrubbing.
        Detection: Monitor requests per second, bandwidth utilization, connection count.
        """
    },
    {
        "id": "port_scan",
        "title": "Port Scanning and Reconnaissance",
        "content": """
        Port scanning is used by attackers to discover open services.
        Key indicators: Sequential requests to multiple non-existent endpoints/paths.
        Patterns: 404 responses in rapid succession, probing for /admin, /.env, /config.
        Common scan targets: SSH (22), HTTP (80), HTTPS (443), MySQL (3306), Redis (6379).
        Tools: Nmap, Masscan, ZMap.
        Mitigation: Firewall rules, fail2ban, honeypots, IDS/IPS systems.
        """
    },
    {
        "id": "sql_injection",
        "title": "SQL Injection Detection",
        "content": """
        SQL injection attacks attempt to manipulate database queries.
        Key indicators: SQL keywords in URL parameters: SELECT, UNION, DROP, OR, AND.
        Common payloads: ' OR '1'='1, UNION SELECT, 1; DROP TABLE, ' AND 1=1--.
        HTTP status clues: 500 errors after SQL payloads (server error from bad query).
        Mitigation: Parameterized queries, WAF, input validation, least privilege DB accounts.
        Detection: Monitor for SQL keywords in query strings and POST bodies.
        """
    },
    {
        "id": "xss",
        "title": "Cross-Site Scripting (XSS) Detection",
        "content": """
        XSS attacks inject malicious scripts into web responses.
        Key indicators: Script tags, javascript: URIs, event handlers in parameters.
        Common payloads: <script>alert(1)</script>, onerror=alert, javascript:void.
        Types: Reflected XSS, Stored XSS, DOM-based XSS.
        Mitigation: Content Security Policy, output encoding, input sanitization.
        """
    },
    {
        "id": "known_malicious_ips",
        "title": "Known Malicious IP Ranges",
        "content": """
        Certain IP ranges are commonly associated with malicious activity.
        Tor exit nodes: Often used for anonymized attacks.
        Shodan ranges: 45.33.x.x, 198.51.100.x commonly appear in scan reports.
        Botnet ranges: 192.0.2.x (TEST-NET), 203.0.113.x documented attack sources.
        Cloud abuse ranges: Misconfigured cloud instances used for scanning.
        Threat intel sources: AbuseIPDB, Shodan, VirusTotal, Emerging Threats.
        """
    },
    {
        "id": "incident_response",
        "title": "Incident Response Playbook",
        "content": """
        Standard incident response steps for network threats:
        1. CONTAIN: Immediately block confirmed malicious IPs via firewall.
        2. IDENTIFY: Determine attack vector, scope, and affected systems.
        3. ERADICATE: Remove malicious access, patch vulnerabilities exploited.
        4. RECOVER: Restore normal operations, monitor for recurrence.
        5. DOCUMENT: Log all findings for forensics and compliance.
        Escalation: HIGH threats require immediate security team notification.
        Tools: pfSense, iptables, CloudFlare, AWS WAF, fail2ban.
        """
    },
    {
        "id": "http_anomaly",
        "title": "HTTP Anomaly Detection",
        "content": """
        HTTP traffic anomalies indicate potential attacks.
        Status code patterns: Spike in 4xx errors (scanning), 5xx errors (injection).
        User-agent anomalies: Bot user agents, missing user agents, scanner signatures.
        Request size: Unusually large POST bodies may indicate data exfiltration.
        Timing patterns: Requests at perfectly regular intervals suggest automation.
        Endpoint patterns: Accessing sensitive endpoints like /etc/passwd, /proc, /.git.
        """
    },
    {
        "id": "authentication_attacks",
        "title": "Authentication Attack Patterns",
        "content": """
        Authentication attacks target login systems to gain unauthorized access.
        Credential stuffing: Using leaked username/password pairs from breaches.
        Password spraying: Trying common passwords across many accounts.
        Account enumeration: Different responses for valid vs invalid usernames.
        Session hijacking: Stealing session tokens from network traffic.
        Indicators: Sequential failed logins, same password tried on many accounts.
        Mitigation: MFA, account lockout, CAPTCHA, monitoring failed auth rates.
        """
    },
    {
        "id": "data_exfiltration",
        "title": "Data Exfiltration Detection",
        "content": """
        Data exfiltration involves unauthorized data transfer outside the network.
        Indicators: Unusually large outbound data volumes, DNS tunneling, HTTPS to unknown hosts.
        Detection: Monitor outbound traffic volume, unusual destination IPs/domains.
        Common methods: HTTP POST to external servers, FTP, DNS tunneling, cloud storage.
        After-hours activity: Large transfers outside business hours are suspicious.
        Mitigation: DLP solutions, egress filtering, network monitoring, CASB.
        """
    }
]


class SecurityKnowledgeBase:
    """
    FAISS-based vector store for security knowledge.
    Uses TF-IDF-style embeddings (no external API needed) for retrieval.
    Falls back to keyword matching if numpy/faiss not available.
    """
    
    def __init__(self):
        self.documents = SECURITY_DOCS
        self.vectors = None
        self.vocab = {}
        self._built = False
    
    def _tokenize(self, text):
        """Simple tokenizer."""
        import re
        text = text.lower()
        tokens = re.findall(r'\b[a-z]{3,}\b', text)
        return tokens
    
    def _build_vocab(self, all_texts):
        """Build vocabulary from all documents."""
        vocab = {}
        for text in all_texts:
            for token in self._tokenize(text):
                if token not in vocab:
                    vocab[token] = len(vocab)
        return vocab
    
    def _vectorize(self, text):
        """TF-IDF-style vectorization."""
        tokens = self._tokenize(text)
        vec = np.zeros(len(self.vocab))
        for token in tokens:
            if token in self.vocab:
                vec[self.vocab[token]] += 1
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec
    
    def build(self):
        """Build the vector index."""
        if self._built:
            return
        
        all_texts = [doc["content"] for doc in self.documents]
        self.vocab = self._build_vocab(all_texts)
        
        self.vectors = np.array([
            self._vectorize(text) for text in all_texts
        ])
        self._built = True
    
    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        """Retrieve most relevant documents for a query."""
        if not self._built:
            self.build()
        
        query_vec = self._vectorize(query)
        
        # Cosine similarity
        scores = self.vectors @ query_vec
        top_indices = np.argsort(scores)[::-1][:top_k]
        
        results = []
        for idx in top_indices:
            if scores[idx] > 0.01:  # threshold
                doc = self.documents[idx].copy()
                doc["score"] = float(scores[idx])
                results.append(doc)
        
        return results
    
    def get_context(self, query: str, max_chars: int = 2000) -> str:
        """Get combined context string from retrieved documents."""
        docs = self.retrieve(query, top_k=3)
        context_parts = []
        total = 0
        for doc in docs:
            text = f"[{doc['title']}]: {doc['content'].strip()}"
            if total + len(text) <= max_chars:
                context_parts.append(text)
                total += len(text)
        return "\n\n".join(context_parts)
    
    def get_titles(self, query: str) -> list[str]:
        """Get titles of retrieved docs for display."""
        docs = self.retrieve(query, top_k=3)
        return [f"📄 {doc['title']} (score: {doc['score']:.2f})" for doc in docs]
