# ClavisVault Critical Alerts

This file is polled by the desktop app on every update check.

## Template for new alerts (add at top)

```yaml
id: "CVE-2026-0001"
version: "0.1.0"
critical: true
severity: "critical"
channel: "security"
dedupe_hours: 24
starts_at: "2026-02-24T00:00:00Z"
ends_at: "2026-12-31T23:59:59Z"
ack_until_version: "0.1.2"
ack_until_date: "2026-03-01T00:00:00Z"
message: "CRITICAL SECURITY UPDATE — update immediately. CVE-2026-XXXX fixed."

id: "release-note-001"
version: "0.1.0"
critical: false
severity: "low"
channel: "release"
dedupe_hours: 12
message: "Initial release — all good."
```
