/**
 * LogOps Platform API Server
 * Enterprise Log Ingestion, Zero-Leak Redaction, Local LLM Diagnosis & SRE Dashboard
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { executeLogPipeline } = require('./orchestrator');
const elkConnector = require('./elkConnector');

const PORT = parseInt(process.env.PORT || process.env.LOGOPS_PORT || '8888', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// -----------------------------------------------------------------------------
// Data Persistence Helpers
// -----------------------------------------------------------------------------
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');

function readJsonFile(filePath, defaultValue) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch (err) {
    console.error(`Error reading ${filePath}:`, err.message);
  }
  return defaultValue;
}

function writeJsonFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`Error writing ${filePath}:`, err.message);
  }
}

// Ensure default admin user
let users = readJsonFile(USERS_FILE, []);
if (users.length === 0) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync('LogOps2026!', salt, 100000, 64, 'sha512').toString('hex');
  users = [{
    id: 'user_admin',
    username: 'admin',
    salt,
    hash,
    role: 'administrator',
    createdAt: new Date().toISOString()
  }];
  writeJsonFile(USERS_FILE, users);
}

// Ensure initial API key for log shippers
let apiKeys = readJsonFile(KEYS_FILE, []);
if (apiKeys.length === 0) {
  apiKeys = [{
    id: 'key_initial',
    name: 'Default Ingestion Gateway',
    key: 'logops_key_live_default_9f83a2',
    createdAt: new Date().toISOString(),
    lastUsedAt: null
  }];
  writeJsonFile(KEYS_FILE, apiKeys);
}

let reports = readJsonFile(REPORTS_FILE, []);

// Initialize ELK Community Edition Connector & Auto-Harvester
elkConnector.init(DATA_DIR, executeLogPipeline, (report) => {
  reports.unshift(report);
  if (reports.length > 100) reports = reports.slice(0, 100);
  writeJsonFile(REPORTS_FILE, reports);
});

const activeSessions = new Map(); // token -> user

// -----------------------------------------------------------------------------
// Authentication & Security Helpers
// -----------------------------------------------------------------------------
function generateSessionToken(user) {
  const token = 'sess_' + crypto.randomBytes(32).toString('hex');
  activeSessions.set(token, {
    userId: user.id,
    username: user.username,
    role: user.role,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  });
  return token;
}

function authenticateRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  const apiKeyHeader = req.headers['x-logops-key'] || req.headers['x-api-key'] || '';

  // 1. Check API Key
  if (apiKeyHeader) {
    const keyRecord = apiKeys.find(k => k.key === apiKeyHeader);
    if (keyRecord) {
      keyRecord.lastUsedAt = new Date().toISOString();
      writeJsonFile(KEYS_FILE, apiKeys);
      return { authorized: true, type: 'api_key', entity: keyRecord.name };
    }
  }

  // 2. Check Bearer Token
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const session = activeSessions.get(token);
    if (session && session.expiresAt > Date.now()) {
      return { authorized: true, type: 'session', user: session };
    }
  }

  return { authorized: false };
}

// -----------------------------------------------------------------------------
// HTTP Utilities
// -----------------------------------------------------------------------------
function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-LogOps-Key, X-API-Key',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  res.end(body);
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 20 * 1024 * 1024) { // 20 MB max
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({ rawText: body });
      }
    });
    req.on('error', reject);
  });
}

// -----------------------------------------------------------------------------
// 10 Realistic Enterprise Use Case Samples
// -----------------------------------------------------------------------------
const SAMPLE_LOGS = {
  weblogic: `####<Oct 19, 2026 2:15:20 PM UTC> <Error> <WebLogicServer> <prod-wls-01.corp.internal> <ManagedServer_2> <[ACTIVE] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <000000> <BEA-000337> <[STUCK] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)' has been busy for "680" seconds working on the request "HttpTrace", which is more than the configured time (StuckThreadMaxTime) of "600" seconds. Stack trace:
java.sql.SQLException: Connection pool "OracleFinDS" has reached MaxCapacity=100. Connection allocation timed out after 30000ms.
	at weblogic.jdbc.common.internal.ConnectionEnv.allocate(ConnectionEnv.java:312)
	at weblogic.jdbc.wrapper.PoolConnection.init(PoolConnection.java:88)
	Database endpoint: jdbc:oracle:thin:@10.100.40.15:1521/ORCLFIN with user=app_db_user password="SuperSecretPassword2026!">
####<Oct 19, 2026 2:15:35 PM UTC> <Warning> <JDBC> <prod-wls-01.corp.internal> <ManagedServer_2> <[ACTIVE] ExecuteThread: '2'> <<WLS Kernel>> <> <000000> <BEA-001153> <Forcibly releasing idle resource from pool "OracleFinDS" to relieve thread contention.>`,

  kafka: `[2026-10-19 14:22:01,892] ERROR [KafkaServer id=2] Fatal error during KafkaServer startup. Prepare to shutdown (kafka.server.KafkaServer)
org.apache.kafka.common.errors.ClusterAuthorizationException: Principal User:kafka_producer_client@finance.internal is not authorized to access topic: customer-payment-events with ApiKey: 3
[2026-10-19 14:22:03,104] WARN [GroupCoordinator 2]: Member telemetry-consumer-01_10.128.4.15 in group "payment-processors" has failed heartbeat (session.timeout.ms=10000). Triggering partition rebalance.
[2026-10-19 14:22:04,412] ERROR [ReplicaManager broker=2] Error shrink ISR for partition payment-transactions-0 from [1,2,3] to [1,3]. Broker 10.128.4.20 unreachable.`,

  apache: `[Sun Oct 19 14:15:20.892019 2026] [proxy:error] [pid 14208:tid 1399] [client 198.51.100.42:54210] AH00898: Error reading from remote server returned by /api/v2/checkout
[Sun Oct 19 14:15:20.893102 2026] [proxy_http:error] [pid 14208:tid 1399] (70007)The timeout specified has expired: [client 198.51.100.42:54210] AH01102: error reading status line from remote server 10.240.12.88:8080
[Sun Oct 19 14:15:21.011244 2026] [mpm_event:error] [pid 14199:tid 1402] AH00484: server reached MaxRequestWorkers setting, consider raising the MaxRequestWorkers setting
198.51.100.42 - john.doe@company.com [19/Oct/2026:14:15:22 +0000] "POST /api/v2/checkout HTTP/1.1" 504 182 "https://portal.company.com/cart" "Mozilla/5.0" Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123`,

  windows: `Event[0]:
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Date: 2026-10-19T14:30:12.000Z
Event ID: 4625
Level: Information
Keywords: Audit Failure
Computer: WIN-DC01.corp.internal
Description:
An account failed to log on.
Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		svc_jenkins_deployer@corp.internal
	Account Domain:		CORP
Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A
Network Information:
	Workstation Name:	WIN-HOST99
	Source Network Address:	192.168.10.85
	Source Port:		49820

Event[1]:
Log Name: System
Source: Service Control Manager
Date: 2026-10-19T14:31:00.000Z
Event ID: 7034
Level: Error
Computer: WIN-DC01.corp.internal
Description:
The Enterprise Sync Service service terminated unexpectedly. It has done this 1 time(s).`,

  jenkins: `Started by user admin_devops@corp.internal
Running in Durability level: MAX_SURVIVABILITY
[Pipeline] Start of Pipeline
[Pipeline] stage (Build & Test)
+ mvn clean package -DskipTests=false
[INFO] Scanning for projects...
[INFO] Building Enterprise Payment Gateway 4.1.0
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-surefire-plugin:3.0.0:test (default-test) on project billing-gateway:
[ERROR] Tests run: 214, Failures: 1, Errors: 0, Skipped: 0
[ERROR] ConnectionRefusedException: Failed to connect to Redis cache at 10.0.80.25:6379 with auth_token="redis_prod_auth_token_999"
[ERROR] java.lang.OutOfMemoryError: Java heap space
    at java.base/java.util.Arrays.copyOf(Arrays.java:3537)
Build user: builder_ci@corp.internal on node worker-aws-us-east-1a-10.2.14.99
ERROR: Build step failed with exit code 1
Finished: FAILURE`,

  kubernetes: `2026-10-19T14:35:10.120Z kubelet node-worker-pool-3 Pod payment-processing-service-7f89d4-x9z12 container checkout-worker terminated with exit code 137 (OOMKilled)
2026-10-19T14:35:11.450Z kubelet node-worker-pool-3 Readiness probe failed: HTTP probe failed with statuscode: 503 for pod payment-processing-service-7f89d4-x9z12 (10.244.3.44:8080)
2026-10-19T14:35:12.890Z kubelet node-worker-pool-3 Back-off restarting failed container checkout-worker in pod payment-processing-service-7f89d4-x9z12_prod-namespace(48e9c-12)
2026-10-19T14:35:15.002Z k8s-apiserver [audit] user="system:serviceaccount:prod:ingress-controller" ip="10.244.0.1" verb="get" uri="/api/v1/namespaces/prod/secrets/vault-api-jwt" code=403
2026-10-19T14:35:20.100Z kubelet Warning FailedScheduling pod/payment-processing-service-7f89d4-x9z12 0/8 nodes are available: 3 Insufficient memory, 5 node(s) had untolerated taint.`,

  postgres: `2026-10-19 14:40:12.019 UTC [14820] prod_billing_db app_user_prod 10.0.12.50(44120) FATAL: remaining connection slots are reserved for non-replication superuser connections
2026-10-19 14:40:12.891 UTC [14821] prod_billing_db app_user_prod 10.0.12.50(44122) ERROR: deadlock detected
2026-10-19 14:40:12.892 UTC [14821] prod_billing_db DETAIL: Process 14821 waits for ExclusiveLock on transaction 891240; blocked by process 14818.
Process 14818 waits for ShareLock on transaction 891241; blocked by process 14821.
2026-10-19 14:40:12.893 UTC [14821] prod_billing_db HINT: See server log for query details. Connection string: postgresql://admin_db:SecureDbPass2026!@10.0.12.50:5432/prod_billing_db
2026-10-19 14:40:13.104 UTC [14822] prod_billing_db STATEMENT: UPDATE customer_accounts SET balance = balance - 120.00 WHERE account_id = 'ACC-99824';`,

  aws: `2026-10-19T14:45:00.102Z 8f9b2c3d-12ab-4c5d-9e8f-123456789abc START RequestId: 8f9b2c3d-12ab-4c5d-9e8f-123456789abc Version: $LATEST
2026-10-19T14:45:02.341Z 8f9b2c3d-12ab-4c5d-9e8f-123456789abc [ERROR] ClientError: An error occurred (AccessDeniedException) when calling the Decrypt operation: The ciphertext refers to a customer master key that does not exist or you are not authorized to use.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE role_arn="arn:aws:iam::123456789012:role/lambda-payment-processor"
2026-10-19T14:45:30.104Z 8f9b2c3d-12ab-4c5d-9e8f-123456789abc Task timed out after 30.00 seconds
2026-10-19T14:45:30.105Z 8f9b2c3d-12ab-4c5d-9e8f-123456789abc END RequestId: 8f9b2c3d-12ab-4c5d-9e8f-123456789abc
REPORT RequestId: 8f9b2c3d-12ab-4c5d-9e8f-123456789abc Duration: 30000.00 ms Billed Duration: 30000 ms Memory Size: 1024 MB Max Memory Used: 248 MB`,

  redis: `1:M 19 Oct 2026 14:50:01.120 # OOM command not allowed when used memory > 'maxmemory' (current used: 4294967296 bytes, limit: 4294967296 bytes).
1:M 19 Oct 2026 14:50:01.440 * Client id=4981 addr=10.0.4.15:52190 name=api_cache_client age=140 idle=0 flags=N db=0 fd=18 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=40928 argv-mem=10 obl=0 oll=0 omem=0 tot-mem=61466 events=r cmd=set user=default
1:S 19 Oct 2026 14:50:05.890 * Connecting to MASTER 10.0.4.10:6379 with password="ProdRedisCachePassword2026!"
1:S 19 Oct 2026 14:50:05.892 # Error condition on socket for SYNC: Connection refused
1:X 19 Oct 2026 14:50:10.002 # +sdown master redis-prod-master 10.0.4.10 6379
1:X 19 Oct 2026 14:50:11.200 # +odown master redis-prod-master 10.0.4.10 6379 #quorum 2/2`,

  nginx: `2026/10/19 14:55:01 [error] 2891#2891: *14902 connect() failed (111: Connection refused) while connecting to upstream, client: 198.51.100.77, server: api.enterprise.internal, request: "POST /v1/transactions/authorize HTTP/1.1", upstream: "http://10.240.10.15:8443/v1/transactions/authorize", host: "api.enterprise.internal"
2026/10/19 14:55:02 [error] 2891#2891: *14903 SSL_do_handshake() failed (SSL: error:0A000086:SSL routines::certificate verify failed) while SSL handshaking to upstream, client: 198.51.100.77, server: api.enterprise.internal, upstream: "https://10.240.10.16:8443/v1/transactions/authorize"
2026/10/19 14:55:03 [error] 2891#2891: *14904 no live upstreams while connecting to upstream, client: 198.51.100.77, server: api.enterprise.internal, request: "POST /v1/transactions/authorize HTTP/1.1", upstream: "http://billing_cluster"`
};

// -----------------------------------------------------------------------------
// Request Dispatcher
// -----------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Handle CORS Pre-flight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-LogOps-Key, X-API-Key'
    });
    return res.end();
  }

  // 1. Healthcheck Endpoint
  if (pathname === '/healthz' || pathname === '/api/health') {
    return sendJson(res, 200, {
      status: 'UP',
      service: 'logops-intelligence-platform',
      version: '1.0.0',
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
  }

  // 2. Comprehensive Status & Engine Discovery Endpoint
  if (pathname === '/api/status' && method === 'GET') {
    const filtrUrl = process.env.FILTR_URL || 'http://127.0.0.1:8080';
    const llmUrl = process.env.LLM_URL || 'http://127.0.0.1:11434';
    const llmModel = process.env.LLM_MODEL || 'deepseek-r1';

    let filtrStatus = { live: false, url: filtrUrl, latencyMs: null, error: null };
    let llmStatus = { live: false, url: llmUrl, model: llmModel, latencyMs: null, error: null };

    // Ping filtr
    try {
      const fStart = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const fRes = await fetch(`${filtrUrl}/api/health`, { signal: controller.signal });
      clearTimeout(timeout);
      filtrStatus.latencyMs = Date.now() - fStart;
      filtrStatus.live = fRes.ok;
    } catch (err) {
      filtrStatus.error = err.message;
    }

    // Ping LLM
    try {
      const lStart = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const lRes = await fetch(`${llmUrl}/api/tags`, { signal: controller.signal });
      clearTimeout(timeout);
      llmStatus.latencyMs = Date.now() - lStart;
      llmStatus.live = lRes.ok;
    } catch (err) {
      llmStatus.error = err.message;
    }

    return sendJson(res, 200, {
      success: true,
      filtr: filtrStatus,
      llm: llmStatus,
      stats: {
        totalReports: reports.length,
        totalKeys: apiKeys.length,
        activeSessions: activeSessions.size
      }
    });
  }

  // 3. Authentication: Login
  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseJsonBody(req);
    const { username, password } = body;

    const user = users.find(u => u.username === username);
    if (!user) {
      return sendJson(res, 401, { success: false, error: 'Invalid username or password' });
    }

    const testHash = crypto.pbkdf2Sync(password || '', user.salt, 100000, 64, 'sha512').toString('hex');
    if (testHash !== user.hash) {
      return sendJson(res, 401, { success: false, error: 'Invalid username or password' });
    }

    const token = generateSessionToken(user);
    return sendJson(res, 200, {
      success: true,
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  }

  // 4. Authentication: Current User
  if (pathname === '/api/auth/me' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) {
      return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    }
    return sendJson(res, 200, { success: true, user: auth.user });
  }

  // 5. API Keys Management
  if (pathname === '/api/keys' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    return sendJson(res, 200, { success: true, keys: apiKeys });
  }

  if (pathname === '/api/keys' && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const body = await parseJsonBody(req);
    const newKey = {
      id: 'key_' + Date.now(),
      name: body.name || 'New Log Shipper',
      key: 'logops_live_' + crypto.randomBytes(16).toString('hex'),
      createdAt: new Date().toISOString(),
      lastUsedAt: null
    };
    apiKeys.push(newKey);
    writeJsonFile(KEYS_FILE, apiKeys);
    return sendJson(res, 201, { success: true, key: newKey });
  }

  if (pathname.startsWith('/api/keys/') && method === 'DELETE') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const keyId = pathname.replace('/api/keys/', '');
    apiKeys = apiKeys.filter(k => k.id !== keyId);
    writeJsonFile(KEYS_FILE, apiKeys);
    return sendJson(res, 200, { success: true, deletedId: keyId });
  }

  // 6. Sample Logs for 1-Click UI Testing
  if (pathname.startsWith('/api/samples/') && method === 'GET') {
    const srcType = pathname.replace('/api/samples/', '').toLowerCase();
    const sample = SAMPLE_LOGS[srcType] || SAMPLE_LOGS.weblogic;
    return sendJson(res, 200, { success: true, sourceType: srcType, sampleLogs: sample });
  }

  // 7. Ingest & Live Pipeline Run
  if ((pathname === '/api/pipeline/run' || pathname === '/api/ingest') && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) {
      return sendJson(res, 401, {
        error: 'Unauthorized. Provide Bearer session token or X-LogOps-Key header.'
      });
    }

    const body = await parseJsonBody(req);
    const rawLogs = body.logs || body.rawLogs || body.payload || body.text || '';
    const sourceType = body.sourceType || body.source || 'weblogic';

    if (!rawLogs.trim()) {
      return sendJson(res, 400, { error: 'Missing log text content.' });
    }

    try {
      const result = await executeLogPipeline({
        sourceType,
        rawLogs,
        filtrUrl: body.filtrUrl || process.env.FILTR_URL || 'http://127.0.0.1:8080',
        llmUrl: body.llmUrl || process.env.LLM_URL || 'http://127.0.0.1:11434',
        llmModel: body.llmModel || process.env.LLM_MODEL || 'deepseek-r1'
      });

      // Persist Report
      reports.unshift(result);
      if (reports.length > 100) reports = reports.slice(0, 100);
      writeJsonFile(REPORTS_FILE, reports);

      return sendJson(res, 200, { success: true, report: result });
    } catch (err) {
      console.error('Pipeline execution failed:', err);
      return sendJson(res, 500, { error: err.message || 'Pipeline processing error' });
    }
  }

  // 8. Incident Reports History & Export
  if (pathname === '/api/reports' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    return sendJson(res, 200, { success: true, reports });
  }

  if (pathname.startsWith('/api/reports/') && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const repSub = pathname.replace('/api/reports/', '');

    if (repSub.endsWith('/markdown')) {
      const repId = repSub.replace('/markdown', '');
      const report = reports.find(r => r.id === repId);
      if (!report) return sendJson(res, 404, { error: 'Report not found' });

      const diag = report.diagnostic || {};
      const actions = (diag.remediationSteps || diag.remediationActions || []).map((a, i) => `${i + 1}. ${a}`).join('\n');
      const md = `# [INCIDENT REPORT] ${diag.incidentTitle || 'Enterprise Incident'}\n\n` +
        `**Severity**: ${diag.severity || 'CRITICAL'}\n` +
        `**Source System**: ${report.sourceType}\n` +
        `**Incident ID**: ${report.id}\n` +
        `**Generated At**: ${report.createdAt}\n` +
        `**Entities Masked & Rehydrated**: ${report.stages?.sanitization?.redactedCount || (report.tokenLedger || []).length}\n\n` +
        `## 🔍 Root Cause Hypothesis\n${diag.rootCause || diag.rootCauseHypothesis || 'N/A'}\n\n` +
        `## 🛠️ Actionable SRE Remediation Playbook\n${actions}\n\n` +
        `## 🛡️ Zero-Leak Verification\n` +
        `- filtr Core Gateway Status: ${report.filtrEngineStatus}\n` +
        `- Local LLM Engine: ${report.llmEngineStatus}\n` +
        `- Tokens Restored: ${report.stages?.rehydration?.tokensRestored || 0}\n`;

      res.writeHead(200, {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="${report.id}.md"`
      });
      return res.end(md);
    }

    const report = reports.find(r => r.id === repSub);
    if (!report) return sendJson(res, 404, { error: 'Report not found' });
    return sendJson(res, 200, { success: true, report });
  }

  if (pathname.startsWith('/api/reports/') && method === 'DELETE') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const repId = pathname.replace('/api/reports/', '');
    reports = reports.filter(r => r.id !== repId);
    writeJsonFile(REPORTS_FILE, reports);
    return sendJson(res, 200, { success: true, deletedId: repId });
  }

  // ---------------------------------------------------------------------------
  // ELK Community Edition Integration Routes
  // ---------------------------------------------------------------------------
  if (pathname === '/api/elk/config' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    return sendJson(res, 200, { success: true, config: elkConnector.config });
  }

  if (pathname === '/api/elk/config' && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const body = await parseJsonBody(req);
    const updated = elkConnector.updateConfig(body);
    return sendJson(res, 200, { success: true, config: updated });
  }

  if (pathname === '/api/elk/test' && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const body = await parseJsonBody(req);
    const testResult = await elkConnector.testConnection(body);
    return sendJson(res, 200, testResult);
  }

  if (pathname === '/api/elk/harvest-now' && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    try {
      const harvestResult = await elkConnector.harvestNow();
      return sendJson(res, 200, { success: true, ...harvestResult });
    } catch (err) {
      return sendJson(res, 500, { success: false, error: err.message });
    }
  }

  if (pathname === '/api/elk/history' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    return sendJson(res, 200, { success: true, history: elkConnector.history });
  }

  if ((pathname === '/api/elk/forward' || pathname === '/api/ingest/elk') && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) {
      return sendJson(res, 401, { error: 'Unauthorized forwarder. Provide X-LogOps-Key or Bearer token.' });
    }
    const body = await parseJsonBody(req);
    try {
      const result = await elkConnector.processForwardedBatch(body);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { success: false, error: err.message });
    }
  }

  if (pathname === '/api/elk/logstash-config' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const primaryKey = apiKeys.length > 0 ? apiKeys[0].key : 'YOUR_LOGOPS_API_KEY';
    const configSnippet = elkConnector.getLogstashConfig(req.headers.host, primaryKey);
    return sendJson(res, 200, { success: true, config: configSnippet });
  }

  // 9. Serve Frontend Static Assets
  const publicDir = path.join(__dirname, '..', 'dist');
  let filePath = path.join(publicDir, pathname === '/' ? 'index.html' : pathname);

  if (!fs.existsSync(filePath)) {
    filePath = path.join(publicDir, 'index.html');
  }

  if (fs.existsSync(filePath)) {
    const ext = path.extname(filePath);
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png'
    };
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
    return fs.createReadStream(filePath).pipe(res);
  }

  // Fallback 404
  sendJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`==========================================================`);
  console.log(`  LogOps Intelligence Platform Server`);
  console.log(`  Listening on: http://${HOST}:${PORT}`);
  console.log(`  Default Admin: admin / LogOps2026!`);
  console.log(`  filtr Bridge: ${process.env.FILTR_URL || 'http://127.0.0.1:8080'}`);
  console.log(`==========================================================`);
});
