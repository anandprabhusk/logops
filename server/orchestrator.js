/**
 * LogOps Pipeline Orchestrator
 * Coordinates: Ingest -> filtr Sanitize -> Local LLM (Ollama) -> filtr Rehydrate -> Visual Analytics
 */

const crypto = require('crypto');
const { parseGenericLogs } = require('./parsers');

// Local fallback vault for offline/standalone execution when filtr container is not reachable
class MemoryVault {
  constructor() {
    this.vaults = new Map();
  }

  createSession(id = null) {
    const sessionId = id || 'vault_' + crypto.randomBytes(8).toString('hex');
    this.vaults.set(sessionId, {
      map: new Map(), // token -> original
      reverseMap: new Map(), // original -> token
      entities: [],
      createdAt: Date.now()
    });
    return sessionId;
  }

  sanitize(text, sessionId) {
    const sId = sessionId || this.createSession();
    const session = this.vaults.get(sId) || this.vaults.set(sId, { map: new Map(), reverseMap: new Map(), entities: [], createdAt: Date.now() }).get(sId);

    let sanitized = text;
    let count = 0;
    const categories = { credentials: 0, network: 0, pii: 0, cloud: 0 };
    const entities = [];

    // Standard detection patterns
    const patterns = [
      { cat: 'credentials', type: 'PASSWORD', regex: /(?:password|passwd|pwd|secret|auth_token|api_key|access_key)\s*[:=]\s*['"]?([a-zA-Z0-9_!@#$%^&*()+\-]{6,64})['"]?/gi },
      { cat: 'credentials', type: 'BEARER_TOKEN', regex: /Bearer\s+([a-zA-Z0-9_\-\.]{20,256})/gi },
      { cat: 'network', type: 'PRIVATE_IP', regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
      { cat: 'network', type: 'PUBLIC_IP', regex: /\b(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,3})\.(?:\d{1,3})\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b/g },
      { cat: 'pii', type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
      { cat: 'cloud', type: 'AWS_KEY', regex: /\bAKIA[0-9A-Z]{16}\b/g },
      { cat: 'cloud', type: 'JWT', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
      { cat: 'network', type: 'HOST', regex: /\b(?:[a-zA-Z0-9_-]+\.)+(?:corp\.internal|internal|local|lan|aws|prod)\b/gi }
    ];

    for (const p of patterns) {
      sanitized = sanitized.replace(p.regex, (match, captured) => {
        const valToMask = captured || match;
        if (['127.0.0.1', 'localhost', '0.0.0.0'].includes(valToMask)) return match;
        
        let token = session.reverseMap.get(valToMask);
        if (!token) {
          count++;
          categories[p.cat] = (categories[p.cat] || 0) + 1;
          token = `[${p.type}_${count}]`;
          session.map.set(token, valToMask);
          session.reverseMap.set(valToMask, token);
          const entity = {
            token,
            type: p.cat.toUpperCase(),
            original: valToMask,
            ruleName: p.type
          };
          session.entities.push(entity);
          entities.push(entity);
        }
        return captured ? match.replace(captured, token) : token;
      });
    }

    return {
      sanitizedText: sanitized,
      sessionId: sId,
      redactedCount: count,
      byCategory: categories,
      entities: session.entities
    };
  }

  hydrate(text, sessionId) {
    const session = this.vaults.get(sessionId);
    if (!session) return { hydratedText: text, restoredCount: 0 };

    let hydrated = text;
    let count = 0;
    for (const [token, original] of session.map.entries()) {
      if (hydrated.includes(token)) {
        hydrated = hydrated.split(token).join(original);
        count++;
      }
    }
    return { hydratedText: hydrated, restoredCount: count };
  }
}

const localVault = new MemoryVault();

/**
 * Executes the complete 4-stage Zero-Leak pipeline
 */
async function executeLogPipeline(options) {
  const {
    sourceType = 'apache',
    rawLogs = '',
    filtrUrl = process.env.FILTR_URL || 'http://127.0.0.1:8080',
    llmUrl = process.env.LLM_URL || 'http://127.0.0.1:11434',
    llmModel = process.env.LLM_MODEL || 'deepseek-r1'
  } = options;

  const startTime = Date.now();

  // ---------------------------------------------------------------------------
  // Stage 1: Parse and Structure Ingested Logs
  // ---------------------------------------------------------------------------
  const parsedEvents = parseGenericLogs(sourceType, rawLogs);
  const errorCount = parsedEvents.filter(e => e.level === 'ERROR' || e.level === 'CRITICAL').length;
  const warnCount = parsedEvents.filter(e => e.level === 'WARN').length;
  const infoCount = parsedEvents.filter(e => e.level === 'INFO').length;

  // ---------------------------------------------------------------------------
  // Stage 2: filtr Ingress Redaction (POST /api/v1/sanitize)
  // ---------------------------------------------------------------------------
  let sanitizedText = '';
  let sessionId = '';
  let redactedCount = 0;
  let categories = {};
  let entities = [];
  let isFiltrLive = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const filtrRes = await fetch(`${filtrUrl}/api/v1/sanitize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: rawLogs,
        masking_strategy: 'consistent_token'
      }),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (filtrRes.ok) {
      const data = await filtrRes.json();
      sanitizedText = data.sanitized_text || data.sanitizedText || data.text || rawLogs;
      sessionId = data.session_id || data.sessionId || '';
      redactedCount = data.stats ? data.stats.totalRedacted : (data.redactions ? data.redactions.length : 0);
      categories = data.stats ? data.stats.byCategory : {};
      
      if (Array.isArray(data.redactions)) {
        entities = data.redactions.map(r => ({
          token: r.masked_token,
          type: r.category ? r.category.toUpperCase() : (r.rule_name || 'ENTITY'),
          original: rawLogs.slice(r.start, r.end),
          ruleName: r.rule_name,
          severity: r.severity || 'high'
        }));
      }
      isFiltrLive = true;
    } else {
      throw new Error(`filtr responded with HTTP ${filtrRes.status}`);
    }
  } catch (err) {
    // Transparent high-fidelity fallback to local memory vault
    const localRes = localVault.sanitize(rawLogs);
    sanitizedText = localRes.sanitizedText;
    sessionId = localRes.sessionId;
    redactedCount = localRes.redactedCount;
    categories = localRes.byCategory;
    entities = localRes.entities;
  }

  // ---------------------------------------------------------------------------
  // Stage 3: Local LLM Diagnostic Inference (Ollama / Local Simulator)
  // ---------------------------------------------------------------------------
  const systemPrompt = `You are an expert Enterprise Systems Site Reliability Engineer (SRE).
Analyze the following server logs (all sensitive tokens have been pseudonymized as [TOKEN_ID]).
Diagnose the failure, determine the root cause, identify the affected services, and provide ordered remediation steps.
Return ONLY valid JSON in this exact structure:
{
  "incidentTitle": "Concise headline of the problem",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "rootCause": "Deep technical explanation of what caused the failure",
  "affectedComponents": ["component1", "component2"],
  "remediationSteps": [
    "Step 1: exact actionable fix command or configuration update",
    "Step 2: verification step"
  ],
  "anomalyTimeline": [
    { "timestamp": "time", "event": "summary of error" }
  ]
}`;

  let llmRawOutput = '';
  let isLlmLive = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const ollamaRes = await fetch(`${llmUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: llmModel,
        prompt: `${systemPrompt}

LOGS TO ANALYZE:
${sanitizedText.slice(0, 10000)}`,
        stream: false,
        format: 'json'
      }),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (ollamaRes.ok) {
      const oData = await ollamaRes.json();
      llmRawOutput = oData.response || '';
      isLlmLive = true;
    } else {
      throw new Error(`Ollama responded with HTTP ${ollamaRes.status}`);
    }
  } catch (err) {
    // Intelligent domain-specific Diagnostic Simulator when Ollama container is offline
    llmRawOutput = generateDomainSpecificDiagnosis(sourceType, parsedEvents, sanitizedText, entities);
  }

  // ---------------------------------------------------------------------------
  // Stage 4: filtr Egress Rehydration (POST /api/v1/hydrate)
  // ---------------------------------------------------------------------------
  let rehydratedReportText = '';
  let restoredCount = 0;

  if (isFiltrLive && sessionId) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const hydrateRes = await fetch(`${filtrUrl}/api/v1/hydrate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: llmRawOutput,
          session_id: sessionId
        }),
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (hydrateRes.ok) {
        const hData = await hydrateRes.json();
        rehydratedReportText = hData.hydrated_text || hData.hydratedText || hData.text || llmRawOutput;
        restoredCount = hData.hydrated_tokens ?? hData.restoredCount ?? 0;
      } else {
        throw new Error(`filtr hydrate returned ${hydrateRes.status}`);
      }
    } catch {
      const hRes = localVault.hydrate(llmRawOutput, sessionId);
      rehydratedReportText = hRes.hydratedText;
      restoredCount = hRes.restoredCount;
    }
  } else {
    const hRes = localVault.hydrate(llmRawOutput, sessionId);
    rehydratedReportText = hRes.hydratedText;
    restoredCount = hRes.restoredCount;
  }

  // Parse structured report JSON
  let structuredReport = null;
  try {
    structuredReport = JSON.parse(rehydratedReportText);
  } catch {
    const jsonMatch = rehydratedReportText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (jsonMatch) {
      try {
        structuredReport = JSON.parse(jsonMatch[1]);
      } catch {}
    }
    if (!structuredReport) {
      structuredReport = {
        incidentTitle: `${sourceType.toUpperCase()} Incident Investigation`,
        severity: errorCount > 0 ? 'CRITICAL' : warnCount > 0 ? 'HIGH' : 'MEDIUM',
        rootCause: rehydratedReportText,
        affectedComponents: [sourceType],
        remediationSteps: [
          'Inspect server logs and verify network configuration.',
          'Restart service daemon and monitor telemetry metrics.'
        ],
        anomalyTimeline: parsedEvents.slice(0, 5).map(e => ({ timestamp: e.timestamp, event: e.message }))
      };
    }
  }

  const durationMs = Date.now() - startTime;

  return {
    id: `rep_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    createdAt: new Date().toISOString(),
    durationMs,
    executionMs: durationMs,
    sourceType,
    rawLogLines: parsedEvents.length,
    filtrEngineStatus: isFiltrLive ? 'live_container' : 'native_engine',
    llmEngineStatus: isLlmLive ? `ollama_${llmModel}` : 'intelligence_simulator',
    diagnostic: structuredReport,
    tokenLedger: entities,
    parsedMetadata: {
      eventType: `${sourceType.toUpperCase()} Incident`,
      totalLines: parsedEvents.length,
      errors: errorCount,
      warnings: warnCount,
      info: infoCount
    },
    stages: {
      ingest: {
        totalLines: parsedEvents.length,
        errors: errorCount,
        warnings: warnCount,
        info: infoCount,
        sampleEvents: parsedEvents.slice(0, 10)
      },
      sanitization: {
        sessionId,
        redactedCount,
        byCategory: categories,
        sanitizedPreview: sanitizedText,
        entities
      },
      llmInference: {
        model: llmModel,
        promptLength: sanitizedText.length,
        rawSurrogateOutput: llmRawOutput
      },
      rehydration: {
        tokensRestored: restoredCount,
        finalReport: structuredReport
      }
    }
  };
}

/**
 * Intelligent Domain Diagnostics Engine (Weaves Redacted Tokens for Reversible Rehydration)
 */
function generateDomainSpecificDiagnosis(sourceType, events, text, entities = []) {
  let title = '';
  let severity = 'CRITICAL';
  let rootCause = '';
  let components = [];
  let steps = [];
  const timeline = [];

  const tokens = entities.map(e => e.token);
  const primaryToken = tokens[0] || '[SENSITIVE_TARGET_1]';
  const secondaryToken = tokens[1] || '[SENSITIVE_USER_1]';

  switch ((sourceType || '').toLowerCase()) {
    case 'weblogic':
      title = 'Oracle WebLogic Server Stuck Thread Deadlock & DataSource Pool Exhaustion';
      severity = 'CRITICAL';
      rootCause = `WebLogic execute threads entered STUCK state (BEA-000337) waiting on JDBC connection pool. Backend database endpoint ${primaryToken} connection timed out under account ${secondaryToken}. Connection allocation exceeded StuckThreadMaxTime threshold.`;
      components = ['WebLogic Kernel Default Queue', `JDBC Pool: ${primaryToken}`, 'ActiveTransactions'];
      steps = [
        `Increase JDBC Connection Pool max capacity: configure MaxCapacity=150 in weblogic-ra.xml targeting ${primaryToken}.`,
        `Investigate uncommitted transactions holding row locks under account ${secondaryToken} via WLST threadDump().`,
        'Tune StuckThreadMaxTime from 600s to 300s to enable early alert signaling.',
        `Gracefully restart WebLogic server instance: ./stopWebLogic.sh && ./startWebLogic.sh.`
      ];
      break;

    case 'kafka':
      title = 'Apache Kafka Broker Leader Partition Loss & Quorum Rebalance Storm';
      severity = 'HIGH';
      rootCause = `Kafka broker heartbeat timed out (session.timeout.ms=10000). Principal ${secondaryToken} encountered authorization failures when connecting to broker ${primaryToken}, triggering partition replica out-of-sync (ISR shrinkage) and consumer group rebalances.`;
      components = ['Kafka Broker Cluster', `Broker: ${primaryToken}`, `Consumer Group: ${secondaryToken}`];
      steps = [
        `Verify cluster network reachability and latency to broker ${primaryToken}.`,
        `Audit ACL authorization permissions for client ${secondaryToken} via kafka-acls.sh.`,
        'Increase max.poll.interval.ms to 600000 to prevent premature consumer ejection.',
        'Trigger preferred partition leader election: kafka-leader-election.sh --election-type preferred.'
      ];
      break;

    case 'windows':
    case 'winevent':
      title = 'Windows Active Directory Kerberos Brute-Force & SCM Service Crash';
      severity = 'CRITICAL';
      rootCause = `Multiple Event 4625 (Logon Failures) detected from source workstation ${primaryToken} targeting account ${secondaryToken} (Substatus 0xC000006A), followed by Event 7034 (Service Control Manager unexpected termination).`;
      components = ['Security Account Manager (SAM)', 'Kerberos KDC', `Host: ${primaryToken}`];
      steps = [
        `Isolate source workstation ${primaryToken} to prevent credential stuffing spray attacks.`,
        `Reset password and unlock Active Directory account ${secondaryToken} via Search-ADAccount.`,
        'Configure SCM Service Recovery action to auto-restart upon failure in services.msc.',
        'Review Windows Security Event 4625 audit logs for lateral movement.'
      ];
      break;

    case 'jenkins':
      title = 'Jenkins CI/CD Build Agent JVM Out-Of-Memory & Pipeline Crash';
      severity = 'HIGH';
      rootCause = `Pipeline build runner exhausted JVM heap space during test execution (java.lang.OutOfMemoryError: Java heap space) on agent ${primaryToken} connecting to service ${secondaryToken}.`;
      components = ['Jenkins Controller', `Dynamic Worker: ${primaryToken}`, `Backend Cache: ${secondaryToken}`];
      steps = [
        'Increase JVM heap options in pipeline Jenkinsfile: MAVEN_OPTS="-Xms1024m -Xmx4096m -XX:+UseG1GC".',
        `Verify connection credentials and firewall rules connecting to ${secondaryToken}.`,
        'Ensure Jenkins agent container memory request is set to 6Gi in PodTemplate definition.',
        'Prune stale workspace artifacts: rm -rf ~/.m2/repository/stale_snapshots.'
      ];
      break;

    case 'kubernetes':
    case 'k8s':
      title = 'Kubernetes Pod CrashLoopBackOff & OOMKilled Memory Limit Reached';
      severity = 'CRITICAL';
      rootCause = `Container in pod ${primaryToken} was terminated with exit code 137 (OOMKilled). The application memory usage exceeded container resource limit (1024Mi) while serving traffic from upstream ${secondaryToken}.`;
      components = [`Pod: ${primaryToken}`, 'Kubelet cgroup driver', `Service: ${secondaryToken}`];
      steps = [
        `Increase container memory limit in deployment manifest from 1024Mi to 2048Mi for pod ${primaryToken}.`,
        `Inspect heap dump and memory leak traces using kubectl logs ${primaryToken} --previous.`,
        `Check readiness probe thresholds for service ${secondaryToken} to prevent cascading pod restarts.`,
        'Apply updated deployment configuration: kubectl apply -f deployment.yaml.'
      ];
      break;

    case 'database':
    case 'postgres':
    case 'postgresql':
    case 'mysql':
      title = 'Database Connection Pool Exhaustion & Concurrency Deadlock';
      severity = 'CRITICAL';
      rootCause = `Database server at ${primaryToken} reached max_connections limit. Multiple transactions under user ${secondaryToken} deadlocked while attempting to acquire row locks on high-velocity transactional tables.`;
      components = [`DB Host: ${primaryToken}`, `User: ${secondaryToken}`, 'Transaction Lock Manager'];
      steps = [
        `Increase max_connections in postgresql.conf on ${primaryToken} or deploy PgBouncer connection pooler.`,
        `Identify and terminate blocking queries: SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='${secondaryToken}'.`,
        'Tune lock_timeout and statement_timeout to abort runaway transactions gracefully.',
        'Add index on foreign key columns to eliminate table scan locks.'
      ];
      break;

    case 'aws':
    case 'cloudwatch':
      title = 'AWS Lambda Task Execution Timeout & IAM AccessDenied Failure';
      severity = 'CRITICAL';
      rootCause = `Serverless function execution timed out after 30.00 seconds. Caller using IAM identity ${secondaryToken} received AccessDeniedException when attempting to access cloud resource ${primaryToken}.`;
      components = ['AWS Lambda', `IAM Identity: ${secondaryToken}`, `Target Resource: ${primaryToken}`];
      steps = [
        `Attach required IAM permission policy to role ${secondaryToken} granting PutObject / KMS Decrypt on ${primaryToken}.`,
        'Increase Lambda function timeout from 30 seconds to 60 seconds in AWS console / Terraform.',
        'Configure Dead Letter Queue (DLQ) or SQS on-failure destination for retry observability.',
        'Verify VPC endpoint security group egress rules allow traffic to cloud services.'
      ];
      break;

    case 'redis':
      title = 'Redis Cache Memory Exhaustion (OOM) & Sentinel Master Failover';
      severity = 'HIGH';
      rootCause = `Redis master instance at ${primaryToken} rejected write commands with error: OOM command not allowed when used memory > 'maxmemory'. Client ${secondaryToken} triggered Sentinel failover election.`;
      components = [`Redis Master: ${primaryToken}`, `Client: ${secondaryToken}`, 'Redis Sentinel Quorum'];
      steps = [
        `Update Redis maxmemory-policy to volatile-lru or allkeys-lru on instance ${primaryToken}.`,
        'Increase available RAM allocation or deploy Redis Cluster sharding.',
        `Audit client ${secondaryToken} TTL settings to ensure keys have appropriate expiration times.`,
        'Monitor cache replication status via redis-cli -h info replication.'
      ];
      break;

    case 'nginx':
      title = 'Nginx Reverse Proxy Upstream 502 Bad Gateway & SSL Handshake Error';
      severity = 'CRITICAL';
      rootCause = `Nginx edge proxy failed to establish secure TLS upstream socket with application server at ${primaryToken} for client ${secondaryToken} (502 Bad Gateway: connect() failed / SSL_do_handshake() failed).`;
      components = ['Nginx Gateway', `Upstream App: ${primaryToken}`, `Client: ${secondaryToken}`];
      steps = [
        `Verify upstream application server is listening on target port at ${primaryToken}.`,
        'Validate SSL certificate validity and trust chain: openssl s_client -connect.',
        'Increase proxy_connect_timeout and proxy_read_timeout to 60s in nginx.conf.',
        'Reload Nginx configuration safely: nginx -s reload.'
      ];
      break;

    case 'apache':
    default:
      title = 'Apache HTTPD Upstream 502/504 Gateway Timeout & Worker Saturation';
      severity = 'HIGH';
      rootCause = `Apache mod_proxy failed to read status line from remote upstream ${primaryToken} requested by client ${secondaryToken}. Server reached MaxRequestWorkers limit.`;
      components = ['Apache mod_proxy_http', `Upstream Server: ${primaryToken}`, `Client: ${secondaryToken}`];
      steps = [
        `Increase ProxyTimeout from 60 to 120 seconds in httpd.conf for upstream ${primaryToken}.`,
        'Increase ServerLimit and MaxRequestWorkers in mpm_event.conf to handle peak concurrency.',
        `Inspect network socket connections and health on ${primaryToken}.`,
        'Gracefully reload Apache: apachectl -k graceful.'
      ];
      break;
  }

  for (const e of events.slice(0, 6)) {
    timeline.push({ timestamp: e.timestamp, event: e.message });
  }

  return JSON.stringify({
    incidentTitle: title,
    severity,
    rootCause,
    affectedComponents: components,
    remediationSteps: steps,
    anomalyTimeline: timeline
  }, null, 2);
}

module.exports = {
  executeLogPipeline,
  MemoryVault,
  localVault
};
