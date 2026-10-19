/**
 * LogOps Platform Backend Server
 * High-performance standalone service with authentication, API key validation,
 * zero-leak log pipeline orchestration, and report intelligence persistence.
 */

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { executeLogPipeline } = require('./orchestrator');
const elkConnector = require('./elkConnector');

const PORT = parseInt(process.env.PORT || '8888', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// -----------------------------------------------------------------------------
// Data Storage & In-Memory State
// -----------------------------------------------------------------------------
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');

function readJsonFile(file, fallback) {
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf-8'));
    }
  } catch {}
  return fallback;
}

function writeJsonFile(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error(`Failed to write ${file}:`, err);
  }
}

// Seed default admin user: admin / LogOps2026!
let users = readJsonFile(USERS_FILE, []);
if (users.length === 0) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync('LogOps2026!', salt, 10000, 64, 'sha256').toString('hex');
  users = [{
    id: 'usr_admin',
    username: 'admin',
    role: 'administrator',
    salt,
    hash,
    createdAt: new Date().toISOString()
  }];
  writeJsonFile(USERS_FILE, users);
}

// Seed default API Key for automated log shippers
let apiKeys = readJsonFile(KEYS_FILE, []);
if (apiKeys.length === 0) {
  apiKeys = [{
    id: 'key_default_shipper',
    name: 'Enterprise Fluent Bit / Vector Shipper',
    key: 'logops_live_' + crypto.randomBytes(16).toString('hex'),
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
// Realistic Sample Logs for 1-Click Testing
// -----------------------------------------------------------------------------
const SAMPLE_LOGS = {
  apache: `[Sun Oct 13 14:15:20.892019 2026] [proxy:error] [pid 14208:tid 1399] [client 198.51.100.42:54210] AH00898: Error reading from remote server returned by /api/v2/checkout
[Sun Oct 13 14:15:20.893102 2026] [proxy_http:error] [pid 14208:tid 1399] (70007)The timeout specified has expired: [client 198.51.100.42:54210] AH01102: error reading status line from remote server 10.240.12.88:8080
[Sun Oct 13 14:15:21.011244 2026] [mpm_event:error] [pid 14199:tid 1402] AH00484: server reached MaxRequestWorkers setting, consider raising the MaxRequestWorkers setting
198.51.100.42 - john.doe@company.com [13/Oct/2026:14:15:22 +0000] "POST /api/v2/checkout HTTP/1.1" 504 182 "https://portal.company.com/cart" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123`,

  weblogic: `####<Oct 13, 2026 2:15:20 PM UTC> <Error> <WebLogicServer> <prod-wls-01.corp.internal> <ManagedServer_2> <[ACTIVE] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <000000> <BEA-000337> <[STUCK] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)' has been busy for "680" seconds working on the request "HttpTrace", which is more than the configured time (StuckThreadMaxTime) of "600" seconds. Stack trace:
java.sql.SQLException: Connection pool "OracleFinDS" has reached MaxCapacity=100. Connection allocation timed out after 30000ms.
	at weblogic.jdbc.common.internal.ConnectionEnv.allocate(ConnectionEnv.java:312)
	at weblogic.jdbc.wrapper.PoolConnection.init(PoolConnection.java:88)
	Database endpoint: jdbc:oracle:thin:@10.100.40.15:1521/ORCLFIN with user=app_db_user password="SuperSecretPassword2026!">
####<Oct 13, 2026 2:15:35 PM UTC> <Warning> <JDBC> <prod-wls-01.corp.internal> <ManagedServer_2> <[ACTIVE] ExecuteThread: '2'> <<WLS Kernel>> <> <000000> <BEA-001153> <Forcibly releasing idle resource from pool "OracleFinDS" to relieve thread contention.>`,

  kafka: `[2026-10-13 14:22:01,892] ERROR [KafkaServer id=2] Fatal error during KafkaServer startup. Prepare to shutdown (kafka.server.KafkaServer)
org.apache.kafka.common.errors.ClusterAuthorizationException: Principal User:kafka_client_app is not authorized to access topic: customer-payment-events with ApiKey: 3
[2026-10-13 14:22:03,104] WARN [GroupCoordinator 2]: Member telemetry-consumer-01_10.128.4.15 in group "payment-processors" has failed heartbeat (session.timeout.ms=10000). Triggering partition rebalance.
[2026-10-13 14:22:04,412] ERROR [ReplicaManager broker=2] Error shrink ISR for partition payment-transactions-0 from [1,2,3] to [1,3]. Broker 10.128.4.20 unreachable.`,

  windows: `Event[0]:
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Date: 2026-10-13T14:30:12.000Z
Event ID: 4625
Level: Information
Keywords: Audit Failure
Computer: WIN-DC01.corp.internal
Description:
An account failed to log on.
Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		svc_jenkins_deployer
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
Date: 2026-10-13T14:31:00.000Z
Event ID: 7034
Level: Error
Computer: WIN-DC01.corp.internal
Description:
The Enterprise Sync Service service terminated unexpectedly. It has done this 1 time(s).`,

  jenkins: `Started by user admin
Running in Durability level: MAX_SURVIVABILITY
[Pipeline] Start of Pipeline
[Pipeline] stage
[Pipeline] { (Build & Deploy)
[Pipeline] sh
+ mvn clean package -DskipTests=false
[INFO] Scanning for projects...
[INFO] -----------------------< com.enterprise:cloud-service >-----------------------
[INFO] Building Enterprise Cloud Service 3.2.0
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-surefire-plugin:3.0.0:test (default-test) on project cloud-service:
[ERROR] There are test failures.
[ERROR] Tests run: 142, Failures: 1, Errors: 0, Skipped: 0
[ERROR] ConnectionRefusedException: Failed to connect to Redis cluster at 10.0.80.25:6379 with auth_token="redis_prod_auth_token_999"
[Pipeline] }
[Pipeline] // stage
[Pipeline] End of Pipeline
ERROR: Build step failed with exit code 1
Finished: FAILURE`
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

  // 1. Health Probe
  if (pathname === '/api/health' && method === 'GET') {
    return sendJson(res, 200, {
      status: 'UP',
      version: '1.0.0',
      uptimeSeconds: Math.floor(process.uptime()),
      reportsCount: reports.length,
      activeSessions: activeSessions.size,
      registeredApiKeys: apiKeys.length
    });
  }

  // 2. Authentication: Login
  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseJsonBody(req);
    const { username, password } = body;

    const user = users.find(u => u.username === username);
    if (!user) {
      return sendJson(res, 401, { success: false, error: 'Invalid credentials' });
    }

    const testHash = crypto.pbkdf2Sync(password || '', user.salt, 10000, 64, 'sha256').toString('hex');
    if (testHash !== user.hash) {
      return sendJson(res, 401, { success: false, error: 'Invalid credentials' });
    }

    const token = generateSessionToken(user);
    return sendJson(res, 200, {
      success: true,
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  }

  // 3. Authentication: Current User
  if (pathname === '/api/auth/me' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) {
      return sendJson(res, 401, { success: false, error: 'Unauthorized' });
    }
    return sendJson(res, 200, { success: true, user: auth.user });
  }

  // 4. API Keys Management
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

  // 5. Sample Logs for 1-Click UI Testing
  if (pathname.startsWith('/api/samples/') && method === 'GET') {
    const srcType = pathname.replace('/api/samples/', '').toLowerCase();
    const sample = SAMPLE_LOGS[srcType] || SAMPLE_LOGS.apache;
    return sendJson(res, 200, { success: true, sourceType: srcType, sampleLogs: sample });
  }

  // 6. Ingest & Live Pipeline Run
  if ((pathname === '/api/pipeline/run' || pathname === '/api/ingest') && method === 'POST') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) {
      return sendJson(res, 401, {
        error: 'Unauthorized. Provide Bearer session token or X-LogOps-Key header.'
      });
    }

    const body = await parseJsonBody(req);
    const rawLogs = body.logs || body.rawLogs || body.payload || body.text || '';
    const sourceType = body.sourceType || body.source || 'apache';

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

  // 7. Incident Reports History
  if (pathname === '/api/reports' && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    return sendJson(res, 200, { success: true, reports });
  }

  if (pathname.startsWith('/api/reports/') && method === 'GET') {
    const auth = authenticateRequest(req);
    if (!auth.authorized) return sendJson(res, 401, { error: 'Unauthorized' });
    const repId = pathname.replace('/api/reports/', '');
    const report = reports.find(r => r.id === repId);
    if (!report) return sendJson(res, 404, { error: 'Report not found' });
    return sendJson(res, 200, { success: true, report });
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

  // 8. Serve Frontend Static Assets
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
  console.log(`==========================================================`);
});
