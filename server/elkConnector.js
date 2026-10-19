/**
 * LogOps ELK Community Edition Connector & Auto-Harvester
 * 
 * Provides:
 * 1. Pull Model: Scheduled & On-Demand Elasticsearch Community REST API Error Harvester
 * 2. Log Deduplication & Template Clustering (Drain-style token reducer)
 * 3. Push Model: High-Throughput Logstash / Filebeat HTTP Forwarding Ingestion
 * 4. Configuration Persistence & Historical Telemetry
 */

const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ElkConnector {
  constructor() {
    this.config = {
      enabled: false,
      elasticsearchUrl: 'http://127.0.0.1:9200',
      authType: 'none', // 'none' | 'basic' | 'apiKey'
      username: '',
      password: '',
      apiKey: '',
      indexPattern: 'filebeat-*,logstash-*,*-app-*',
      filterQuery: 'log.level:(ERROR OR FATAL OR CRITICAL) OR level:(ERROR OR FATAL) OR status:[500 TO 599]',
      intervalSeconds: 60,
      batchSize: 100,
      minErrorThreshold: 1,
      autoAnalyze: true,
      lastHarvestTimestamp: null,
      lastHarvestStatus: 'idle',
      lastLogCount: 0,
      lastIncidentId: null,
      lastError: null
    };

    this.timer = null;
    this.history = [];
    this.configFile = null;
    this.historyFile = null;
    this.executePipeline = null;
    this.onReportSaved = null;
    this.isHarvesting = false;
  }

  init(dataDir, executePipelineFn, onReportSavedFn) {
    this.configFile = path.join(dataDir, 'elk_config.json');
    this.historyFile = path.join(dataDir, 'elk_history.json');
    this.executePipeline = executePipelineFn;
    this.onReportSaved = onReportSavedFn;

    // Load persisted config
    try {
      if (fs.existsSync(this.configFile)) {
        const saved = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
        this.config = { ...this.config, ...saved };
      }
    } catch (err) {
      console.error('[ELK Connector] Failed to load config:', err.message);
    }

    // Load persisted history
    try {
      if (fs.existsSync(this.historyFile)) {
        this.history = JSON.parse(fs.readFileSync(this.historyFile, 'utf8'));
      }
    } catch {}

    if (this.config.enabled) {
      this.startPoller();
    }
  }

  saveConfig() {
    try {
      if (this.configFile) {
        fs.writeFileSync(this.configFile, JSON.stringify(this.config, null, 2), 'utf8');
      }
    } catch (err) {
      console.error('[ELK Connector] Failed to save config:', err.message);
    }
  }

  saveHistory(entry) {
    try {
      this.history.unshift(entry);
      if (this.history.length > 50) this.history = this.history.slice(0, 50);
      if (this.historyFile) {
        fs.writeFileSync(this.historyFile, JSON.stringify(this.history, null, 2), 'utf8');
      }
    } catch {}
  }

  updateConfig(newConfig) {
    const wasEnabled = this.config.enabled;
    const oldInterval = this.config.intervalSeconds;

    this.config = {
      ...this.config,
      ...newConfig,
      intervalSeconds: Math.max(10, parseInt(newConfig.intervalSeconds || this.config.intervalSeconds, 10))
    };

    this.saveConfig();

    if (this.config.enabled) {
      if (!wasEnabled || oldInterval !== this.config.intervalSeconds) {
        this.startPoller();
      }
    } else {
      this.stopPoller();
    }

    return this.config;
  }

  startPoller() {
    this.stopPoller();
    console.log(`[ELK Connector] Auto-Harvester activated (Polling every ${this.config.intervalSeconds}s)`);
    this.timer = setInterval(() => {
      this.harvestNow().catch(err => {
        console.error('[ELK Connector] Poller cycle error:', err.message);
      });
    }, this.config.intervalSeconds * 1000);
  }

  stopPoller() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      console.log('[ELK Connector] Auto-Harvester paused.');
    }
  }

  // ---------------------------------------------------------------------------
  // Low-level HTTP/HTTPS Request Helper
  // ---------------------------------------------------------------------------
  makeRequest(targetUrl, method, headers = {}, body = null, timeoutMs = 12000) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === 'https:';
      const client = isHttps ? https : http;

      const authHeaders = { ...headers };
      if (this.config.authType === 'basic' && this.config.username) {
        const creds = Buffer.from(`${this.config.username}:${this.config.password || ''}`).toString('base64');
        authHeaders['Authorization'] = `Basic ${creds}`;
      } else if (this.config.authType === 'apiKey' && this.config.apiKey) {
        authHeaders['Authorization'] = `ApiKey ${this.config.apiKey.trim()}`;
      }

      const reqOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + (parsed.search || ''),
        method: method.toUpperCase(),
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...authHeaders
        },
        timeout: timeoutMs,
        rejectUnauthorized: false // Allow self-signed internal enterprise certs
      };

      const req = client.request(reqOptions, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            json = data;
          }
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Connection to Elasticsearch (${targetUrl}) timed out after ${timeoutMs}ms`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (body) {
        req.write(typeof body === 'string' ? body : JSON.stringify(body));
      }
      req.end();
    });
  }

  // ---------------------------------------------------------------------------
  // Test Connection to Elasticsearch Cluster
  // ---------------------------------------------------------------------------
  async testConnection(testConfig = null) {
    const cfg = testConfig ? { ...this.config, ...testConfig } : this.config;
    const base = cfg.elasticsearchUrl.replace(/\/+$/, '');

    try {
      // 1. Ping cluster info (GET /)
      const rootRes = await this.makeRequest(base, 'GET');
      if (rootRes.status !== 200) {
        throw new Error(`Elasticsearch responded with HTTP ${rootRes.status}: ${JSON.stringify(rootRes.data)}`);
      }

      const clusterInfo = rootRes.data || {};
      const clusterName = clusterInfo.cluster_name || 'unknown';
      const version = clusterInfo.version?.number || 'unknown';
      const buildFlavor = clusterInfo.version?.build_flavor || 'default (oss/basic)';

      // 2. Test index search / count
      const indexPattern = encodeURIComponent(cfg.indexPattern);
      const countUrl = `${base}/${indexPattern}/_count`;
      let matchingErrors = 0;
      let countStatus = 'index_queried';

      try {
        const queryBody = {
          query: {
            query_string: {
              query: cfg.filterQuery || '*'
            }
          }
        };
        const countRes = await this.makeRequest(countUrl, 'POST', {}, queryBody);
        if (countRes.status === 200 && countRes.data?.count !== undefined) {
          matchingErrors = countRes.data.count;
        } else if (countRes.status === 404) {
          countStatus = 'index_not_found';
        }
      } catch (countErr) {
        countStatus = `count_failed: ${countErr.message}`;
      }

      return {
        success: true,
        clusterName,
        version,
        buildFlavor,
        matchingErrors,
        countStatus,
        message: `Successfully connected to Elasticsearch cluster "${clusterName}" (v${version})`
      };
    } catch (err) {
      return {
        success: false,
        error: err.message || 'Failed to reach Elasticsearch'
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Log Deduplication & Template Clustering (Token-Reducer)
  // ---------------------------------------------------------------------------
  clusterLogs(hits) {
    const clusters = new Map(); // signature -> { template, count, sample, events: [] }

    for (const hit of hits) {
      const src = hit._source || {};
      const msg = src.message || src.log?.message || src.error?.message || JSON.stringify(src);
      const level = (src.log?.level || src.level || src.status || 'ERROR').toString().toUpperCase();
      const timestamp = src['@timestamp'] || src.timestamp || new Date().toISOString();
      const service = src.service?.name || src.fields?.service || src.host?.hostname || 'enterprise-app';

      // Canonical signature generation: replace numbers, UUIDs, hex tokens, IPs
      const signature = msg
        .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '<UUID>')
        .replace(/\b0x[0-9a-fA-F]+\b/g, '<HEX>')
        .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<IP>')
        .replace(/\b\d{4,}\b/g, '<NUM>')
        .substring(0, 160)
        .trim();

      if (!clusters.has(signature)) {
        clusters.set(signature, {
          signature,
          level,
          service,
          count: 1,
          firstSeen: timestamp,
          lastSeen: timestamp,
          sample: msg,
          events: [{ timestamp, service, level, message: msg }]
        });
      } else {
        const c = clusters.get(signature);
        c.count++;
        c.lastSeen = timestamp;
        if (c.events.length < 5) {
          c.events.push({ timestamp, service, level, message: msg });
        }
      }
    }

    return Array.from(clusters.values()).sort((a, b) => b.count - a.count);
  }

  // ---------------------------------------------------------------------------
  // Execute Harvester Pull Cycle
  // ---------------------------------------------------------------------------
  async harvestNow() {
    if (this.isHarvesting) {
      return { status: 'busy', message: 'Harvester cycle is already in progress.' };
    }

    this.isHarvesting = true;
    const startTime = Date.now();
    const base = this.config.elasticsearchUrl.replace(/\/+$/, '');
    const indexPattern = encodeURIComponent(this.config.indexPattern);
    const searchUrl = `${base}/${indexPattern}/_search`;

    // Compute window: query from last harvest or past (interval * 2) seconds
    const lookbackSecs = this.config.intervalSeconds ? Math.max(30, this.config.intervalSeconds * 2) : 120;
    const gteTime = this.config.lastHarvestTimestamp 
      ? this.config.lastHarvestTimestamp 
      : `now-${lookbackSecs}s`;

    const searchPayload = {
      size: this.config.batchSize || 100,
      sort: [{ '@timestamp': { order: 'asc' } }],
      query: {
        bool: {
          filter: [
            { range: { '@timestamp': { gte: gteTime } } },
            { query_string: { query: this.config.filterQuery || '*' } }
          ]
        }
      }
    };

    try {
      const res = await this.makeRequest(searchUrl, 'POST', {}, searchPayload);
      if (res.status !== 200) {
        throw new Error(`Elasticsearch query returned HTTP ${res.status}: ${JSON.stringify(res.data)}`);
      }

      const hits = res.data?.hits?.hits || [];
      const totalCount = res.data?.hits?.total?.value ?? hits.length;
      const clusters = this.clusterLogs(hits);

      this.config.lastHarvestTimestamp = new Date().toISOString();
      this.config.lastHarvestStatus = 'success';
      this.config.lastLogCount = hits.length;
      this.config.lastError = null;

      let reportId = null;

      // Check if errors meet threshold for automated AI Zero-Leak incident diagnosis
      if (hits.length >= (this.config.minErrorThreshold || 1) && this.config.autoAnalyze && this.executePipeline) {
        console.log(`[ELK Connector] Detected ${hits.length} errors across ${clusters.length} clusters. Triggering Zero-Leak AI Incident Analysis...`);

        // Format raw aggregated logs with frequency weighting
        let rawLogStream = `=== ELK COMMUNITY EDITION HARVEST SUMMARY ===\n`;
        rawLogStream += `Timestamp Window: >= ${gteTime}\n`;
        rawLogStream += `Total Hits: ${hits.length} | Unique Signatures: ${clusters.length}\n\n`;

        for (const cl of clusters) {
          rawLogStream += `--- [CLUSTER] (Occurrences: ${cl.count}) Level: ${cl.level} Service: ${cl.service} ---\n`;
          rawLogStream += `Sample: ${cl.sample}\n`;
          for (const ev of cl.events.slice(0, 3)) {
            rawLogStream += `  [${ev.timestamp}] ${ev.message}\n`;
          }
          rawLogStream += `\n`;
        }

        const report = await this.executePipeline({
          sourceType: 'elk',
          rawLogs: rawLogStream
        });

        reportId = report.id;
        this.config.lastIncidentId = reportId;

        if (this.onReportSaved) {
          this.onReportSaved(report);
        }
      }

      const durationMs = Date.now() - startTime;
      const historyEntry = {
        timestamp: new Date().toISOString(),
        durationMs,
        hitsCount: hits.length,
        clustersCount: clusters.length,
        status: 'success',
        reportId
      };

      this.saveHistory(historyEntry);
      this.saveConfig();

      return {
        status: 'success',
        hitsCount: hits.length,
        clustersCount: clusters.length,
        durationMs,
        reportId
      };
    } catch (err) {
      this.config.lastHarvestStatus = 'error';
      this.config.lastError = err.message;
      this.saveConfig();

      const historyEntry = {
        timestamp: new Date().toISOString(),
        durationMs: Date.now() - startTime,
        hitsCount: 0,
        clustersCount: 0,
        status: 'error',
        error: err.message
      };
      this.saveHistory(historyEntry);

      throw err;
    } finally {
      this.isHarvesting = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Push Forwarding: Ingestion from Logstash / Filebeat / HTTP Webhook
  // ---------------------------------------------------------------------------
  async processForwardedBatch(payload) {
    let events = [];

    // Support array of events or single event
    if (Array.isArray(payload)) {
      events = payload;
    } else if (payload && Array.isArray(payload.events)) {
      events = payload.events;
    } else if (payload && Array.isArray(payload.logs)) {
      events = payload.logs;
    } else if (payload && payload.rawLogs) {
      events = [{ message: payload.rawLogs, level: payload.level || 'ERROR' }];
    } else if (payload && payload.message) {
      events = [payload];
    } else {
      events = [{ message: JSON.stringify(payload), level: 'ERROR' }];
    }

    const hits = events.map(e => ({
      _source: {
        '@timestamp': e['@timestamp'] || e.timestamp || new Date().toISOString(),
        message: e.message || e.log?.message || JSON.stringify(e),
        level: e.level || e.log?.level || 'ERROR',
        service: e.service || e.fields?.service || e.host?.name || 'logstash-shipper'
      }
    }));

    const clusters = this.clusterLogs(hits);

    let rawLogStream = `=== LOGSTASH / FORWARDED BATCH INGEST ===\n`;
    rawLogStream += `Batch Size: ${events.length} | Clusters: ${clusters.length}\n\n`;

    for (const cl of clusters) {
      rawLogStream += `--- [CLUSTER] (Occurrences: ${cl.count}) Level: ${cl.level} Service: ${cl.service} ---\n`;
      rawLogStream += `Sample: ${cl.sample}\n\n`;
    }

    let report = null;
    if (this.executePipeline) {
      report = await this.executePipeline({
        sourceType: 'elk',
        rawLogs: rawLogStream
      });
      if (this.onReportSaved) {
        this.onReportSaved(report);
      }
    }

    return {
      success: true,
      received: events.length,
      clusters: clusters.length,
      reportId: report?.id || null
    };
  }

  // ---------------------------------------------------------------------------
  // Generate Copy-Paste Logstash Configuration for ELK Community Edition
  // ---------------------------------------------------------------------------
  getLogstashConfig(serverHost, apiKey) {
    return `# ==============================================================================
# LogOps Forwarder Pipeline for ELK Community Edition
# Place in: /etc/logstash/conf.d/output-logops.conf
# ==============================================================================

filter {
  # Tag and enrich error logs prior to forwarding
  if [log][level] =~ /(?i)error|fatal|critical|severe/ or [level] =~ /(?i)error|fatal/ or [status] >= 500 {
    mutate {
      add_tag => [ "forward_to_logops" ]
    }
  }
}

output {
  # Standard Elasticsearch Output (Existing Pipeline)
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }

  # Zero-Leak LogOps Ingestion Output (Filtered high-severity anomalies only)
  if "forward_to_logops" in [tags] {
    http {
      url => "http://${serverHost || 'localhost:8888'}/api/elk/forward"
      http_method => "post"
      headers => {
        "X-LogOps-Key" => "${apiKey || 'YOUR_LOGOPS_API_KEY'}"
        "Content-Type" => "application/json"
      }
      format => "json"
      mapping => {
        "@timestamp" => "%{[@timestamp]}"
        "message"    => "%{[message]}"
        "level"      => "%{[log][level]}"
        "service"    => "%{[service][name]}"
        "host"       => "%{[host][hostname]}"
      }
      # Batch optimization
      automatic_retries => 3
      connect_timeout => 5
    }
  }
}
`;
  }
}

module.exports = new ElkConnector();
