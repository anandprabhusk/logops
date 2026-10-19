/**
 * Specialized Log Parsers for Enterprise Systems
 * Supports: Apache HTTPD, Oracle WebLogic, Apache Kafka, Windows Event Logs, Jenkins CI/CD
 */

function parseApacheLog(rawText) {
  const lines = rawText.trim().split(/\r?\n/).filter(Boolean);
  const events = [];
  
  for (const line of lines) {
    // Check error log format: [timestamp] [module:level] [pid X:tid Y] [client IP:port] message
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

    // Check combined access log format: IP - - [date] "METHOD /path HTTP/1.1" STATUS BYTES "REFERER" "UA"
    const accessMatch = line.match(/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?"\s+(\d{3})\s+(\S+)/);
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
      level: 'INFO',
      message: line
    });
  }

  return events;
}

function parseWebLogicLog(rawText) {
  // WebLogic logs often multi-line format:
  // ####<Oct 13, 2026 2:15:20 PM UTC> <Error> <WebLogicServer> <host> <myserver> <[ACTIVE] ExecuteThread: '3' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <000000> <BEA-000337> <[STUCK] ExecuteThread: '1' for queue: 'weblogic.kernel.Default (self-tuning)' has been busy for "680" seconds...>
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
        level: block.includes('BEA-') ? 'ERROR' : 'INFO',
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
    // Format: [2026-10-13 14:22:01,892] ERROR [KafkaServer id=2] Fatal error during KafkaServer startup (kafka.server.KafkaServer)
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
        level: line.includes('ERROR') ? 'ERROR' : 'INFO',
        message: line
      });
    }
  }

  return events;
}

function parseWindowsEventLog(rawText) {
  const events = [];

  // Try JSON lines or array first
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

  // Text representation e.g. Event[0]: Log Name: System, Event ID: 7034, Level: Error
  const entries = rawText.split(/(?=Event\[\d+\]:|Log Name:)/i).filter(e => e.trim().length > 0);
  for (const entry of entries) {
    const eventIdMatch = entry.match(/Event ID:\s*(\d+)/i);
    const levelMatch = entry.match(/Level:\s*([a-zA-Z]+)/i);
    const dateMatch = entry.match(/Date:\s*([^\r\n]+)/i);
    const sourceMatch = entry.match(/Source:\s*([^\r\n]+)/i);

    events.push({
      source: 'windows',
      timestamp: dateMatch ? dateMatch[1].trim() : new Date().toISOString(),
      level: levelMatch ? levelMatch[1].toUpperCase() : 'ERROR',
      eventId: eventIdMatch ? eventIdMatch[1] : 'N/A',
      provider: sourceMatch ? sourceMatch[1].trim() : 'Service Control Manager',
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
  parseGenericLogs
};
