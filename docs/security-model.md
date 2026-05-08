# Security Model

VulnScope is intended for authorized testing only. It enforces scope, rate limits requests, uses timeouts, and ships safe payloads. It does not implement brute force, credential stuffing, destructive SQL payloads, file deletion, shell command execution, persistence, privilege escalation, or automated exploitation.

Secrets provided for authenticated scans are redacted from storage and reports. Findings are detection signals, not proof of exploitability.

