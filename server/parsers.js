/**
 * LogOps Structural Log Parsers
 * Parses enterprise formats into normalized diagnostic events
 */

function parseApacheLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];
  
  for (const line of lines) {
    const errorMatch = line.match(/^\[([^\]]+)\]\s+\[(?:([a-zA-Z0-9_-]+):)?([a-zA-Z]+)\]\s+(?:\[pid\s+\d+:tid\s+\d+\]\s+)?(?:\[client\s+([^:\]]+)(?::\d+)?\]\s+)?(.*)$/);
    if (errorMatch) {
      events.push({
        source: 'apache',
        type: 'error',
        timestamp: errorMatch[1],
        level: (errorMatch[3] || 'error').toUpperCase(),
        clientIp: errorMatch[4] || 'internal',
        message: errorMatch[5] || line
      });
      continue;
    }

    const accessMatch = line.match(/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?\"\s+(\d{3})\s+(\S+)/);
    if (accessMatch) {
      const statusCode = parseInt(accessMatch[6], 10);
      events.push({
        source: 'apache',
        type: 'access',
        timestamp: accessMatch[3],
        level: statusCode >= 500 ? 'CRITICAL' : statusCode >= 400 ? 'WARN' : 'INFO',
        clientIp: accessMatch[1],
        method: accessMatch[4],
        path: accessMatch[5],
        statusCode,
        message: `${accessMatch[4]} ${accessMatch[5]} -> ${statusCode}`
      });
      continue;
    }

    events.push({
      source: 'apache',
      type: 'generic',
      timestamp: new Date().toISOString(),
      level: line.includes('error') || line.includes('AH') ? 'ERROR' : 'INFO',
      message: line
    });
  }

  return events;
}

function parseWebLogicLog(rawText) {
  const blocks = rawText.split(/(?=####<)/g).filter(b => b.trim().length > 0);
  const events = [];

  for (const block of blocks) {
    const headerMatch = block.match(/^####<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([^>]+)>\s+<([\s\S]*)/);
    if (headerMatch) {
      events.push({
        source: 'weblogic',
        timestamp: headerMatch[1],
        level: headerMatch[2].toUpperCase(),
        subsystem: headerMatch[3],
        host: headerMatch[4],
        serverName: headerMatch[5],
        thread: headerMatch[6],
        messageId: headerMatch[10],
        message: headerMatch[11].replace(/>\s*$/, '').trim()
      });
    } else {
      events.push({
        source: 'weblogic',
        timestamp: new Date().toISOString(),
        level: block.includes('BEA-') || block.includes('Exception') || block.includes('STUCK') ? 'CRITICAL' : 'INFO',
        message: block.trim()
      });
    }
  }

  return events;
}

function parseKafkaLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const match = line.match(/^\[([^\]]+)\]\s+([A-Z]+)\s+(?:\[([^\]]+)\])?\s+(.*)$/);
    if (match) {
      events.push({
        source: 'kafka',
        timestamp: match[1],
        level: match[2].toUpperCase(),
        component: match[3] || 'kafka-core',
        message: match[4]
      });
    } else {
      events.push({
        source: 'kafka',
        timestamp: new Date().toISOString(),
        level: line.includes('ERROR') ? 'ERROR' : line.includes('WARN') ? 'WARN' : 'INFO',
        message: line
      });
    }
  }

  return events;
}

function parseWindowsEventLog(rawText) {
  const events = [];

  try {
    const parsed = JSON.parse(rawText);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    for (const item of arr) {
      events.push({
        source: 'windows',
        timestamp: item.TimeCreated || item.timestamp || new Date().toISOString(),
        level: (item.LevelDisplayName || item.level || 'ERROR').toUpperCase(),
        eventId: item.EventID || item.Id || item.eventId || 'N/A',
        provider: item.ProviderName || item.channel || 'System',
        computer: item.Computer || item.host || 'DESKTOP-NODE',
        message: item.Message || item.description || JSON.stringify(item)
      });
    }
    return events;
  } catch {}

  const entries = rawText.split(/(?=Event\[\d+\]:|Log Name:|LogName:)/i).filter(e => e.trim().length > 0);
  for (const entry of entries) {
    const eventIdMatch = entry.match(/Event\s*ID:\s*(\d+)/i) || entry.match(/EventID:\s*(\d+)/i);
    const levelMatch = entry.match(/Level:\s*([a-zA-Z]+)/i);
    const dateMatch = entry.match(/Date:\s*([^\r\n]+)/i);
    const sourceMatch = entry.match(/Source:\s*([^\r\n]+)/i);

    events.push({
      source: 'windows',
      timestamp: dateMatch ? dateMatch[1].trim() : new Date().toISOString(),
      level: levelMatch ? levelMatch[1].toUpperCase() : 'ERROR',
      eventId: eventIdMatch ? eventIdMatch[1] : 'N/A',
      provider: sourceMatch ? sourceMatch[1].trim() : 'Security / System Auditing',
      message: entry.trim()
    });
  }

  return events;
}

function parseJenkinsLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const isError = line.includes('ERROR') || line.includes('FATAL') || line.includes('FAILURE') || line.includes('Exception');
    const isWarn = line.includes('WARNING') || line.includes('WARN');
    
    events.push({
      source: 'jenkins',
      timestamp: new Date().toISOString(),
      level: isError ? 'ERROR' : isWarn ? 'WARN' : 'INFO',
      message: line
    });
  }

  return events;
}

function parseKubernetesLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const isOOM = line.includes('OOMKilled') || line.includes('exit code 137') || line.includes('out of memory');
    const isCrash = line.includes('CrashLoopBackOff') || line.includes('Back-off restarting failed container');
    const isError = isOOM || isCrash || /error|fatal|exception|failed/i.test(line);
    const isWarn = /warning|warn|unhealthy|evict/i.test(line);

    events.push({
      source: 'kubernetes',
      timestamp: new Date().toISOString(),
      level: isOOM || isCrash ? 'CRITICAL' : isError ? 'ERROR' : isWarn ? 'WARN' : 'INFO',
      type: isOOM ? 'OOMKilled' : isCrash ? 'CrashLoopBackOff' : 'PodEvent',
      message: line
    });
  }

  return events;
}

function parseDatabaseLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const isDeadlock = /deadlock detected|lock wait timeout|deadlock found/i.test(line);
    const isPoolExhausted = /too many connections|connection pool exhausted|max_connections reached|FATAL:\s*remaining connection slots/i.test(line);
    const isError = isDeadlock || isPoolExhausted || /ERROR|FATAL|PANIC|Exception/i.test(line);
    const isWarn = /WARNING|WARN/i.test(line);

    events.push({
      source: 'database',
      timestamp: new Date().toISOString(),
      level: isDeadlock || isPoolExhausted ? 'CRITICAL' : isError ? 'ERROR' : isWarn ? 'WARN' : 'INFO',
      type: isDeadlock ? 'Deadlock' : isPoolExhausted ? 'PoolExhaustion' : 'DBLog',
      message: line
    });
  }

  return events;
}

function parseAwsLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const isAccessDenied = /AccessDenied|403 Forbidden|UnauthorizedOperation/i.test(line);
    const isTimeout = /Task timed out after|Endpoint request timed out|504 Gateway Timeout/i.test(line);
    const isError = isAccessDenied || isTimeout || /ERROR|FATAL|Exception|Failed/i.test(line);
    const isWarn = /WARN|WARNING/i.test(line);

    events.push({
      source: 'aws',
      timestamp: new Date().toISOString(),
      level: isAccessDenied ? 'CRITICAL' : isTimeout || isError ? 'ERROR' : isWarn ? 'WARN' : 'INFO',
      type: isAccessDenied ? 'IAM_AccessDenied' : isTimeout ? 'Lambda_Timeout' : 'CloudWatch',
      message: line
    });
  }

  return events;
}

function parseRedisLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const isOom = /OOM command not allowed|used memory > 'maxmemory'/i.test(line);
    const isFailover = /failover-end|failover-state-send-slave-reconf|sdown master/i.test(line);
    const isError = isOom || /ERROR|FATAL|WRONGPASS|NOAUTH/i.test(line);

    events.push({
      source: 'redis',
      timestamp: new Date().toISOString(),
      level: isOom ? 'CRITICAL' : isError ? 'ERROR' : isFailover ? 'WARN' : 'INFO',
      type: isOom ? 'OOM_Eviction' : isFailover ? 'Sentinel_Failover' : 'RedisEvent',
      message: line
    });
  }

  return events;
}

function parseNginxLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];

  for (const line of lines) {
    const is502 = /502 Bad Gateway|connect\(\) failed|upstream prematurely closed/i.test(line);
    const isSsl = /SSL_do_handshake\(\) failed|certificate verify failed/i.test(line);
    const isError = is502 || isSsl || /\[error\]|\[crit\]|\[alert\]/i.test(line);

    events.push({
      source: 'nginx',
      timestamp: new Date().toISOString(),
      level: is502 || isSsl ? 'CRITICAL' : isError ? 'ERROR' : 'INFO',
      type: is502 ? '502_Bad_Gateway' : isSsl ? 'SSL_Handshake_Fail' : 'NginxEvent',
      message: line
    });
  }

  return events;
}

function parseElkLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];
  for (const line of lines) {
    let parsedObj = null;
    if (line.trim().startsWith('{') && line.trim().endsWith('}')) {
      try {
        parsedObj = JSON.parse(line);
      } catch {}
    }

    if (parsedObj) {
      const msg = parsedObj.message || parsedObj.log?.message || JSON.stringify(parsedObj);
      const level = (parsedObj.log?.level || parsedObj.level || 'ERROR').toUpperCase();
      const ts = parsedObj['@timestamp'] || parsedObj.timestamp || new Date().toISOString();
      const service = parsedObj.service?.name || parsedObj.fields?.service || parsedObj.host?.name || 'elk-service';
      events.push({
        source: 'elk',
        type: 'log',
        timestamp: ts,
        level,
        service,
        message: msg
      });
      continue;
    }

    const isClusterHeader = line.includes('--- [CLUSTER]');
    const isSummary = line.includes('=== ELK COMMUNITY EDITION') || line.includes('=== LOGSTASH');
    const isError = /error|fatal|exception|crash|fail/i.test(line);

    events.push({
      source: 'elk',
      type: isClusterHeader ? 'cluster' : isSummary ? 'summary' : 'event',
      timestamp: new Date().toISOString(),
      level: isError ? 'ERROR' : 'INFO',
      message: line
    });
  }
  return events;
}

function parseGenericLogs(sourceType, rawText) {
  switch ((sourceType || '').toLowerCase()) {
    case 'apache':
      return parseApacheLog(rawText);
    case 'weblogic':
      return parseWebLogicLog(rawText);
    case 'kafka':
      return parseKafkaLog(rawText);
    case 'windows':
    case 'winevent':
      return parseWindowsEventLog(rawText);
    case 'elk':
      return parseElkLog(rawText);
    case 'jenkins':
      return parseJenkinsLog(rawText);
    case 'kubernetes':
    case 'k8s':
      return parseKubernetesLog(rawText);
    case 'database':
    case 'postgres':
    case 'postgresql':
    case 'mysql':
      return parseDatabaseLog(rawText);
    case 'aws':
    case 'cloudwatch':
      return parseAwsLog(rawText);
    case 'redis':
      return parseRedisLog(rawText);
    case 'nginx':
      return parseNginxLog(rawText);
    default:
      return rawText.trim().split(/\r?\n/).filter(Boolean).map(line => ({
        source: sourceType || 'generic',
        timestamp: new Date().toISOString(),
        level: line.includes('ERROR') ? 'ERROR' : line.includes('WARN') ? 'WARN' : 'INFO',
        message: line
      }));
  }
}

module.exports = {
  parseApacheLog,
  parseWebLogicLog,
  parseKafkaLog,
  parseWindowsEventLog,
  parseJenkinsLog,
  parseKubernetesLog,
  parseDatabaseLog,
  parseAwsLog,
  parseRedisLog,
  parseNginxLog,
  parseGenericLogs
};
