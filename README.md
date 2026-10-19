# LogOps Intelligence
### Zero-Leak AI Incident Analytics Platform for Enterprise Infrastructure

**LogOps** is an enterprise-grade log ingestion, zero-leak redaction, local LLM diagnosis, and reverse rehydration platform. It allows SRE and DevOps teams to diagnose production incidents using modern LLMs without leaking sensitive customer PII, database passwords, internal IP topologies, or API credentials outside the enterprise trust boundary.

---

## 🔒 The Zero-Leak Guarantee

```
Enterprise Log Stream (WebLogic, Kafka, Apache, Windows, Jenkins)
                              │
                              ▼ [1. Ingest & Structural Parsing]
                      Raw Log Structure
                              │
                              ▼ [2. filtr Sanitization & In-Memory Vault]
          All IPs, users, credentials replaced with synthetic tokens
          (e.g., <IP_ADDRESS_1>, <BEA_USER_1>, <TOKEN_1>)
                              │
                              ▼ [3. Zero-Leak Local LLM Egress]
         Strictly Scrubbed Payload Forwarded to LLM (Ollama/DeepSeek)
                              │
                              ▼ [4. filtr Reverse Rehydration]
       AI diagnostic playbook restored with actual hostnames and targets
                              │
                              ▼ [5. Operational SRE Dashboard]
                  Instant, Actionable Remediation
```

1. **Ingest & Parse**: Structured parsers extract timestamp, event level, component, and stack traces.
2. **filtr Redaction**: The payload is sent to `filtr` (`POST /api/v1/sanitize`), registering sensitive entities in a memory vault and replacing them with deterministic cryptographic tokens.
3. **Local LLM Diagnosis**: The sanitized payload is diagnosed by an on-premise LLM (Ollama / DeepSeek / Mistral). The model **never sees real infrastructure identifiers**.
4. **filtr Rehydration**: The AI's diagnostic hypothesis and remediation playbook pass through `filtr` (`POST /api/v1/hydrate`), substituting tokens back to actual servers, users, and networks for operators to copy and execute.

---

## 🚀 Quick Start

### Option A: Standalone Node.js (Development / On-Prem)
```bash
# 1. Start filtr on port 8080 (in main maskr directory)
docker run -d -p 8080:8080 filtr-app

# 2. Run LogOps backend & dashboard on port 8888
cd logops/server
npm start
```
Access the dashboard at `http://localhost:8888`.
- **Default Username**: `admin`
- **Default Password**: `LogOps2026!`

### Option B: Docker Compose (Production Stack)
```bash
cd logops
docker compose up -d
```

---

## 🔌 Log Shipper Integration

LogOps provides an authenticated ingestion endpoint:
`POST http://<logops-host>:8888/api/ingest`
Header: `X-LogOps-Key: <your-api-key>`

### 1. Fluent Bit (`fluent-bit.conf`)
```ini
[INPUT]
    Name        tail
    Path        /var/log/weblogic/*.log
    Tag         weblogic.server

[OUTPUT]
    Name        http
    Match       weblogic.*
    Host        127.0.0.1
    Port        8888
    URI         /api/ingest
    Header      X-LogOps-Key logops_key_live_default_9f83a2
    Header      Content-Type application/json
    Format      json
```

### 2. Vector.dev (`vector.toml`)
```toml
[sources.kafka_logs]
type = "file"
include = ["/var/log/kafka/server.log"]

[sinks.logops_pipeline]
type = "http"
inputs = ["kafka_logs"]
uri = "http://127.0.0.1:8888/api/ingest"
method = "post"
headers.X-LogOps-Key = "logops_key_live_default_9f83a2"
encoding.codec = "json"
```

### 3. cURL CLI
```bash
curl -X POST http://localhost:8888/api/ingest \
  -H "X-LogOps-Key: logops_key_live_default_9f83a2" \
  -H "Content-Type: application/json" \
  -d '{
    "sourceType": "weblogic",
    "rawLogs": "####<Oct 13, 2026> <Error> <WebLogicServer> <BEA-000337> <[STUCK] ExecuteThread: 12 failed>"
  }'
```

### 4. PowerShell (Windows Event Logs)
```powershell
$Event = Get-WinEvent -LogName "Security" -MaxEvents 1
$Body = @{
    sourceType = "windows"
    rawLogs = $Event.Message
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8888/api/ingest" `
  -Method Post -Headers @{"X-LogOps-Key"="logops_key_live_default_9f83a2"} `
  -ContentType "application/json" -Body $Body
```

---

## 🛡️ Supported Enterprise Sources & Parsers
- **Oracle WebLogic Server**: Multiline BEA error format, stuck threads, JDBC pool exhaustion, transaction rollbacks.
- **Apache Kafka**: KRaft metadata quorum errors, partition leader election failures, consumer rebalances.
- **Apache HTTPD / Nginx**: Combined access logs, upstream gateway 502/504 errors, security scanner probes.
- **Windows Event Log**: Event 4625 (Logon Failures / Brute Force), Service Control Manager crashes (Event 7034).
- **Jenkins CI/CD**: Maven build failures, Surefire test crashes, Java JVM OutOfMemoryError heap space crashes.

---

## 📁 Repository Structure
```
logops/
├── dist/
│   └── index.html          # High-performance Tailwind + Lucide SPA dashboard
├── server/
│   ├── package.json        # Node server manifest
│   ├── server.js           # REST API, auth (PBKDF2), rate limiter & routing
│   ├── parsers.js          # Regex parsers for enterprise formats
│   ├── orchestrator.js     # 4-stage pipeline (filtr -> LLM -> filtr hydrate)
│   └── data/               # Persistent storage for users, API keys, reports
├── Dockerfile              # Container image for LogOps platform
├── docker-compose.yml      # Orchestration for logops, filtr, and ollama
└── README.md               # Complete platform documentation
```
