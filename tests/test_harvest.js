const http = require('http');

function post(url, data, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = JSON.stringify(data);
    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'POST',
      headers: headers
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function run() {
  console.log('Logging in...');
  const login = await post('http://127.0.0.1:8888/api/auth/login', { username: 'admin', password: 'LogOps2026!' });
  const token = login.data.token;
  console.log('Logged in successfully! Token:', token ? token.substring(0, 16) + '...' : 'NONE');

  console.log('\n=== 1. Testing /api/harvester/browse on ./sample_logs/apache ===');
  const browseRes = await post('http://127.0.0.1:8888/api/harvester/browse', { path: './sample_logs/apache' }, token);
  console.log('Status:', browseRes.status, 'Target:', browseRes.data.targetPath);
  if (browseRes.data.files) {
    browseRes.data.files.forEach(f => console.log('  ->', f.name, f.sizeFormatted, f.linesCount + ' lines', 'modified: ' + f.modifiedAt));
  }

  console.log('\n=== 2. Testing /api/harvester/preview on ./sample_logs/apache/error.log ===');
  const prevRes = await post('http://127.0.0.1:8888/api/harvester/preview', { filePath: './sample_logs/apache/error.log', lines: 3 }, token);
  console.log('Status:', prevRes.status, 'Total file lines:', prevRes.data.totalLines);
  console.log('Preview content:\n' + prevRes.data.preview);

  console.log('\n=== 3. Testing /api/harvester/ingest on ./sample_logs/apache (Automated Pipeline: Harvest -> filtr Redact -> LLM -> filtr Hydrate -> Incident Report) ===');
  const ingestRes = await post('http://127.0.0.1:8888/api/harvester/ingest', {
    path: './sample_logs/apache',
    sourceType: 'apache',
    tailLines: 40
  }, token);
  console.log('Status:', ingestRes.status);
  console.log('Harvest Summary:', JSON.stringify(ingestRes.data.harvestSummary, null, 2));
  const pipe = ingestRes.data.pipelineResult;
  if (pipe) {
    console.log('\n--- ZERO-LEAK PIPELINE VERIFICATION ---');
    console.log('Pipeline Success:', pipe.success);
    console.log('Parser Used:', pipe.parser);
    console.log('Filtr Redacted Tokens Count:', pipe.redaction ? pipe.redaction.tokensCount : 0);
    console.log('Filtr Redacted Tokens:', pipe.redaction ? pipe.redaction.tokens : []);
    console.log('Filtr Rehydrated Tokens Restored:', pipe.hydration ? pipe.hydration.tokensRestored : 0);
    console.log('\n--- SRE INCIDENT REPORT ---');
    console.log('Incident ID:', pipe.report ? pipe.report.incidentId : 'N/A');
    console.log('Severity:', pipe.report ? pipe.report.severity : 'N/A');
    console.log('Summary:', pipe.report ? pipe.report.summary : 'N/A');
    console.log('Root Cause Analysis:');
    if (pipe.report && pipe.report.rootCauseAnalysis) {
      pipe.report.rootCauseAnalysis.forEach(rc => console.log('  *', rc.hypothesis, '(Confidence:', rc.confidence + ')'));
    }
    console.log('Remediation Plan:');
    if (pipe.report && pipe.report.remediationPlan) {
      pipe.report.remediationPlan.slice(0, 3).forEach(rp => console.log('  *', rp.step, ':', rp.action));
    }
  } else {
    console.log('Raw output:', ingestRes);
  }
}

run().catch(console.error);
