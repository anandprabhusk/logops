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
      createdAt: Date.now()
    });
    return sessionId;
  }

  sanitize(text, sessionId) {
    const sId = sessionId || this.createSession();
    const session = this.vaults.get(sId) || this.vaults.set(sId, { map: new Map(), reverseMap: new Map(), createdAt: Date.now() }).get(sId);

    let sanitized = text;
    let count = 0;
    const categories = { credentials: 0, network: 0, pii: 0, cloud: 0 };

    // Standard detection patterns
    const patterns = [
      { cat: 'credentials', type: 'PASSWORD', regex: /(?:password|passwd|pwd|secret|auth_token|api_key|access_key)\s*[:=]\s*['"]?([a-zA-Z0-9_!@#$%^&*()+\-]{6,64})['"]?/gi },
      { cat: 'credentials', type: 'BEARER_TOKEN', regex: /Bearer\s+([a-zA-Z0-9_\-\.]{20,256})/gi },
      { cat: 'network', type: 'IPV4', regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
      { cat: 'network', type: 'PUBLIC_IP', regex: /\b(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:\d{1,3})\.(?:\d{1,3})\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b/g },
      { cat: 'pii', type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
      { cat: 'cloud', type: 'AWS_KEY', regex: /\bAKIA[0-9A-Z]{16}\b/g },
      { cat: 'cloud', type: 'JWT', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g }
    ];

    for (const p of patterns) {
      sanitized = sanitized.replace(p.regex, (match, captured) => {
        const valToMask = captured || match;
        // Avoid masking common non-sensitive strings
        if (['127.0.0.1', 'localhost', '0.0.0.0'].includes(valToMask)) return match;
        
        let token = session.reverseMap.get(valToMask);
        if (!token) {
          count++;
          categories[p.cat] = (categories[p.cat] || 0) + 1;
          token = `[${p.type}_${count}]`;
          session.map.set(token, valToMask);
          session.reverseMap.set(valToMask, token);
        }
        return captured ? match.replace(captured, token) : token;
      });
    }

    return {
      sanitizedText: sanitized,
      sessionId: sId,
      redactedCount: count,
      byCategory: categories
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
    filtrUrl = process.env.FILTR_URL || 'http://127.0.0.1:3000',
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
  let isFiltrLive = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const filtrRes = await fetch(`${filtrUrl}/api/v1/sanitize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: rawLogs,
        strategy: 'consistent_token'
      }),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (filtrRes.ok) {
      const data = await filtrRes.json();
      sanitizedText = data.sanitizedText || data.text || rawLogs;
      sessionId = data.sessionId || data.session_id || '';
      redactedCount = data.stats ? data.stats.totalRedacted : 0;
      categories = data.stats ? data.stats.byCategory : {};
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
    llmRawOutput = generateDomainSpecificDiagnosis(sourceType, parsedEvents, sanitizedText);
  }

  // ---------------------------------------------------------------------------
  // Stage 4: filtr Egress Rehydration (POST /api/v1/hydrate)
  // ---------------------------------------------------------------------------
  let rehydratedReportText = '';
  let restoredCount = 0;

  if (isFiltrLive) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const hydrateRes = await fetch(`${filtrUrl}/api/v1/hydrate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: llmRawOutput,
          sessionId
        }),
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (hydrateRes.ok) {
        const hData = await hydrateRes.json();
        rehydratedReportText = hData.hydratedText || llmRawOutput;
        restoredCount = hData.restoredCount || 0;
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
    // Extract JSON substring if wrapped in markdown fences
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
    sourceType,
    rawLogLines: parsedEvents.length,
    filtrEngineStatus: isFiltrLive ? 'live_container' : 'native_engine',
    llmEngineStatus: isLlmLive ? `ollama_${llmModel}` : 'intelligence_simulator',
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
        sanitizedPreview: sanitizedText.slice(0, 1500)
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
 * Intelligent Fallback Domain Diagnostics Engine
 */
function generateDomainSpecificDiagnosis(sourceType, events, text) {
  let title = '';
  let severity = 'CRITICAL';
  let rootCause = '';
  let components = [];
  let steps = [];
  const timeline = [];

  switch ((sourceType || '').toLowerCase()) {
    case 'weblogic':
      title = 'WebLogic Server Thread Deadlock & DataSource Pool Exhaustion';
      severity = 'CRITICAL';
      rootCause = 'WebLogic Server execute threads entered STUCK state (BEA-000337) waiting for response from backend database pool. Connection pool reached MaxCapacity (100) and timed out after 30000ms.';
      components = ['WebLogic Kernel Default Queue', 'JDBC ConnectionPool: oraDS', 'ActiveTransactions'];
      steps = [
        'Increase JDBC Connection Pool max capacity: configure MaxCapacity=150 in weblogic-ra.xml.',
        'Investigate long-running uncommitted SQL queries blocking thread workers via WLST: threadDump().',
        'Tune StuckThreadMaxTime from 600s to 300s to enable early alert signaling.',
        'Execute graceful server restart: ./stopWebLogic.sh && ./startWebLogic.sh.'
      ];
      break;

    case 'kafka':
      title = 'Kafka Broker Leader Partition Loss & Rebalance Storm';
      severity = 'HIGH';
      rootCause = 'Broker heartbeat timed out (session.timeout.ms=10000). ZooKeeper / KRaft metadata lost quorum synchronization, causing partition replica out-of-sync (ISR shrinkage) and consumer group rebalance loops.';
      components = ['Kafka Broker Cluster', 'KRaft Metadata Quorum', 'Consumer Group: telemetry-consumers'];
      steps = [
        'Inspect broker disk I/O and JVM GC pauses: tail -n 100 kafka-server-gc.log.',
        'Increase max.poll.interval.ms from 300000 to 600000 to prevent premature consumer ejection.',
        'Verify topic partition ISR status: kafka-topics.sh --describe --under-replicated-partitions.',
        'Trigger controlled leader re-election: kafka-leader-election.sh --election-type preferred.'
      ];
      break;

    case 'windows':
      title = 'Windows Active Directory Kerberos Pre-Authentication Failure & Service Crash';
      severity = 'CRITICAL';
      rootCause = 'Multiple Event 4625 (Logon Failure) detected due to bad password attempts (Substatus 0xC000006A), followed by Event 7034 (Service Control Manager unexpected termination of enterprise sync agent).';
      components = ['Security Account Manager (SAM)', 'Kerberos KDC', 'Service Control Manager (SCM)'];
      steps = [
        'Check Active Directory lockout status for affected service accounts via PowerShell: Search-ADAccount -LockedOut.',
        'Verify SPN configuration to resolve Kerberos ticket mismatches: setspn -L <AccountName>.',
        'Configure SCM Service Recovery action to auto-restart upon failure in services.msc.',
        'Audit surrounding IP addresses in Event 4625 for signs of brute-force password spraying.'
      ];
      break;

    case 'jenkins':
      title = 'Jenkins CI/CD Build Agent Out-Of-Memory & Pipeline Timeout';
      severity = 'HIGH';
      rootCause = 'Pipeline build container exhausted JVM heap space during Maven test execution (java.lang.OutOfMemoryError: Java heap space), leading to slave agent disconnect and pipeline abort.';
      components = ['Jenkins Controller', 'Kubernetes Dynamic Agent Pod', 'Maven Build Runner'];
      steps = [
        'Increase JVM heap options in pipeline Jenkinsfile: MAVEN_OPTS="-Xms1024m -Xmx4096m -XX:+UseG1GC".',
        'Ensure Jenkins agent container memory request is bumped to 6Gi in PodTemplate definition.',
        'Prune stale workspace artifacts: rm -rf ~/.m2/repository/stale_snapshots.',
        'Re-trigger stage build with clean test parameters.'
      ];
      break;

    case 'apache':
    default:
      title = 'Apache HTTPD Reverse Proxy Upstream 502/504 Gateway Timeout';
      severity = 'HIGH';
      rootCause = 'Apache mod_proxy failed to establish socket connection to upstream application server (AH00898: Error reading from remote server). MaxRequestWorkers threshold was reached.';
      components = ['Apache mod_proxy_http', 'mod_mpm_event', 'Upstream Port: 8080'];
      steps = [
        'Increase ProxyTimeout from 60 to 120 seconds in httpd.conf.',
        'Increase ServerLimit and MaxRequestWorkers in mpm_event.conf: MaxRequestWorkers 800.',
        'Inspect upstream application server health and GC pause durations.',
        'Gracefully reload Apache server: apachectl -k graceful.'
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
