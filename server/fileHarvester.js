/**
 * LogOps Server File & Directory Harvester
 * Automates discovering, reading, tailing, and watching server log paths (e.g. Apache, Nginx, K8s)
 */

const fs = require('fs');
const path = require('path');

class FileHarvester {
  constructor() {
    this.watchers = new Map(); // id -> watcher state
    this.fileOffsets = new Map(); // filePath -> last read byte offset
    this.watchersFile = null;
    this.executePipeline = null;
    this.onReportSaved = null;
  }

  init(dataDir, executePipelineFn, onReportSavedFn) {
    this.watchersFile = path.join(dataDir, 'watchers.json');
    this.executePipeline = executePipelineFn;
    this.onReportSaved = onReportSavedFn;

    // Load persisted watchers
    try {
      if (fs.existsSync(this.watchersFile)) {
        const saved = JSON.parse(fs.readFileSync(this.watchersFile, 'utf8'));
        if (Array.isArray(saved)) {
          for (const w of saved) {
            this.watchers.set(w.id, { ...w, timer: null });
            if (w.enabled) {
              this.startWatcher(w.id);
            }
          }
        }
      }
    } catch (e) {
      console.error('Error loading watchers:', e.message);
    }
  }

  resolvePath(inputPath) {
    if (!inputPath || typeof inputPath !== 'string') {
      return path.resolve(process.cwd(), 'sample_logs/apache');
    }
    const cleanPath = inputPath.trim();
    if (path.isAbsolute(cleanPath)) {
      return cleanPath;
    }
    return path.resolve(process.cwd(), cleanPath);
  }

  browse(targetPath, pattern = '*.log') {
    const resolved = this.resolvePath(targetPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Server path does not exist: ${resolved}`);
    }

    const stat = fs.statSync(resolved);
    const files = [];

    const globToRegex = (pat) => {
      if (!pat || pat === '*') return /.*/;
      const escaped = pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
      return new RegExp(`^${escaped}$`, 'i');
    };

    const regex = globToRegex(pattern);

    if (stat.isFile()) {
      const lineCount = this.countLines(resolved);
      files.push({
        name: path.basename(resolved),
        fullPath: resolved,
        size: stat.size,
        sizeFormatted: this.formatBytes(stat.size),
        mtime: stat.mtime.toISOString(),
        lineCount
      });
      return { path: path.dirname(resolved), isDirectory: false, files };
    }

    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile()) {
        if (regex.test(entry.name)) {
          const fullPath = path.join(resolved, entry.name);
          try {
            const fStat = fs.statSync(fullPath);
            const lineCount = this.countLines(fullPath);
            files.push({
              name: entry.name,
              fullPath,
              size: fStat.size,
              sizeFormatted: this.formatBytes(fStat.size),
              mtime: fStat.mtime.toISOString(),
              lineCount
            });
          } catch {}
        }
      }
    }

    // Sort by modified time descending (newest first)
    files.sort((a, b) => new Date(b.mtime) - new Date(a.mtime));

    return {
      path: resolved,
      isDirectory: true,
      files
    };
  }

  preview(filePath, tailLines = 50) {
    const resolved = this.resolvePath(filePath);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
      throw new Error(`File not found: ${resolved}`);
    }

    const content = fs.readFileSync(resolved, 'utf8');
    const allLines = content.split(/\r?\n/).filter(Boolean);
    const sliced = allLines.slice(-tailLines);

    return {
      filePath: resolved,
      fileName: path.basename(resolved),
      totalLines: allLines.length,
      previewLines: sliced,
      previewText: sliced.join('\n')
    };
  }

  readLogs(targetPath, options = {}) {
    const {
      pattern = '*.log',
      tailLines = 100,
      filterErrors = false
    } = options;

    const browseResult = this.browse(targetPath, pattern);
    if (browseResult.files.length === 0) {
      throw new Error(`No matching log files found in ${browseResult.path} (pattern: ${pattern})`);
    }

    let aggregatedLines = [];
    const filesProcessed = [];

    for (const f of browseResult.files) {
      try {
        const content = fs.readFileSync(f.fullPath, 'utf8');
        let lines = content.split(/\r?\n/).filter(Boolean);
        if (filterErrors) {
          lines = lines.filter(l => /error|warn|fatal|critical|fail|exception|stuck|timeout|oom/i.test(l));
        }
        const recent = lines.slice(-tailLines);
        aggregatedLines = aggregatedLines.concat(recent);
        filesProcessed.push({
          file: f.name,
          fullPath: f.fullPath,
          linesHarvested: recent.length
        });
      } catch (err) {
        console.error(`Failed reading ${f.fullPath}:`, err.message);
      }
    }

    return {
      path: browseResult.path,
      filesProcessed,
      totalLines: aggregatedLines.length,
      rawLogs: aggregatedLines.join('\n')
    };
  }

  countLines(filePath) {
    try {
      const buf = fs.readFileSync(filePath);
      let count = 0;
      for (let i = 0; i < buf.length; i++) {
        if (buf[i] === 10) count++;
      }
      return count || (buf.length > 0 ? 1 : 0);
    } catch {
      return 0;
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // ---------------------------------------------------------------------------
  // Continuous Directory Watcher Manager
  // ---------------------------------------------------------------------------
  getWatchers() {
    const list = [];
    for (const [id, w] of this.watchers.entries()) {
      list.push({
        id,
        name: w.name,
        path: w.path,
        pattern: w.pattern,
        sourceType: w.sourceType,
        intervalSeconds: w.intervalSeconds,
        enabled: w.enabled,
        lastCheckTimestamp: w.lastCheckTimestamp,
        lastHarvestStatus: w.lastHarvestStatus,
        lastErrorCount: w.lastErrorCount,
        lastIncidentId: w.lastIncidentId
      });
    }
    return list;
  }

  createWatcher(data) {
    const id = 'watch_' + Date.now();
    const watcher = {
      id,
      name: data.name || `Path Watcher (${path.basename(data.path || 'apache')})`,
      path: this.resolvePath(data.path || './sample_logs/apache'),
      pattern: data.pattern || '*.log',
      sourceType: data.sourceType || 'apache',
      intervalSeconds: parseInt(data.intervalSeconds || '60', 10),
      enabled: data.enabled !== false,
      lastCheckTimestamp: null,
      lastHarvestStatus: 'idle',
      lastErrorCount: 0,
      lastIncidentId: null,
      timer: null
    };

    this.watchers.set(id, watcher);
    this.saveWatchers();

    if (watcher.enabled) {
      this.startWatcher(id);
    }

    return watcher;
  }

  startWatcher(id) {
    const w = this.watchers.get(id);
    if (!w) return;
    if (w.timer) clearInterval(w.timer);

    w.enabled = true;
    w.timer = setInterval(() => this.pollWatcher(id), w.intervalSeconds * 1000);
    this.saveWatchers();
  }

  stopWatcher(id) {
    const w = this.watchers.get(id);
    if (!w) return;
    if (w.timer) {
      clearInterval(w.timer);
      w.timer = null;
    }
    w.enabled = false;
    this.saveWatchers();
  }

  deleteWatcher(id) {
    this.stopWatcher(id);
    this.watchers.delete(id);
    this.saveWatchers();
  }

  async pollWatcher(id) {
    const w = this.watchers.get(id);
    if (!w) return;

    try {
      w.lastCheckTimestamp = new Date().toISOString();
      const harvestRes = this.readLogs(w.path, {
        pattern: w.pattern,
        tailLines: 50,
        filterErrors: true
      });

      if (harvestRes.totalLines > 0 && this.executePipeline) {
        w.lastHarvestStatus = 'analyzing';
        w.lastErrorCount = harvestRes.totalLines;

        const report = await this.executePipeline({
          sourceType: w.sourceType,
          rawLogs: harvestRes.rawLogs
        });

        w.lastIncidentId = report.id;
        w.lastHarvestStatus = 'harvested_incident';

        if (this.onReportSaved) {
          this.onReportSaved(report);
        }
      } else {
        w.lastHarvestStatus = 'idle_no_errors';
      }
    } catch (err) {
      w.lastHarvestStatus = 'error: ' + err.message;
    }
    this.saveWatchers();
  }

  saveWatchers() {
    if (!this.watchersFile) return;
    try {
      const list = this.getWatchers();
      fs.writeFileSync(this.watchersFile, JSON.stringify(list, null, 2), 'utf8');
    } catch (err) {
      console.error('Error saving watchers:', err.message);
    }
  }
}

module.exports = new FileHarvester();
