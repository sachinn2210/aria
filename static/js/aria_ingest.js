/* ═══════════════════════════════════════════════════════════════════════════
   ARIA Ingestion Panel – aria_ingest.js
   Include in index.html after aria.js:
     <script src="/static/js/aria_ingest.js"></script>
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Tab switching ─────────────────────────────────────────────────────────────

function switchTab(name) {
  document.querySelectorAll('.ingest-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.ingest-body').forEach(d => d.style.display = 'none');
  document.querySelector(`[onclick="switchTab('${name}')"]`).classList.add('active');
  document.getElementById(`tab-${name}`).style.display = 'block';
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

let _proxyPollTimer = null;

async function proxyStart() {
  const target = document.getElementById('proxy-target').value.trim();
  const port   = parseInt(document.getElementById('proxy-port').value) || 8888;

  if (!target) {
    setStatus('ingest-status-msg', 'Enter a target URL first', 'error');
    return;
  }

  setStatus('ingest-status-msg', 'Starting proxy…', '');
  document.getElementById('proxy-start-btn').disabled = true;

  try {
    const r = await fetch('/api/proxy/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, port }),
    });
    const d = await r.json();

    if (d.ok) {
      setStatus('ingest-status-msg', `Proxying → ${d.target}`, 'success');
      document.getElementById('proxy-stop-btn').disabled = false;
      document.getElementById('proxy-start-btn').disabled = true;
      document.getElementById('proxy-log-feed').style.display = 'block';
      setBadge('ingest-proxy-badge', 'PROXY ON', 'HIGH');
      _proxyPollTimer = setInterval(pollProxyStatus, 3000);
    } else {
      setStatus('ingest-status-msg', `Error: ${d.error}`, 'error');
      document.getElementById('proxy-start-btn').disabled = false;
    }
  } catch (e) {
    setStatus('ingest-status-msg', `Failed: ${e}`, 'error');
    document.getElementById('proxy-start-btn').disabled = false;
  }
}

async function proxyStop() {
  await fetch('/api/proxy/stop', { method: 'POST' });
  document.getElementById('proxy-start-btn').disabled = false;
  document.getElementById('proxy-stop-btn').disabled = true;
  setBadge('ingest-proxy-badge', 'PROXY OFF', 'LOW');
  setStatus('ingest-status-msg', 'Proxy stopped', '');
  if (_proxyPollTimer) { clearInterval(_proxyPollTimer); _proxyPollTimer = null; }
}

async function pollProxyStatus() {
  try {
    const r = await fetch('/api/proxy/status');
    const d = await r.json();
    if (!d.running) {
      document.getElementById('proxy-start-btn').disabled = false;
      document.getElementById('proxy-stop-btn').disabled = true;
      setBadge('ingest-proxy-badge', 'PROXY OFF', 'LOW');
      clearInterval(_proxyPollTimer);
      return;
    }
    document.getElementById('proxy-stats').textContent =
      `${d.requests} req  ${d.errors} err`;
  } catch (_) {}
}

// Watch the SSE feed and mirror proxy lines into the mini-feed
let _proxyLineCount = 0;
(function wireProxyMirror() {
  // Re-use the global evtSrc declared in aria.js
  window.addEventListener('aria-sse-event', e => {
    const ev = e.detail;
    if (!ev.source || !ev.source.includes('proxy')) return;
    appendProxyLine(ev);
  });
})();

// The SSE handler in aria.js needs to dispatch a custom event so we can listen
// Patch it by overriding evtSrc.onmessage — done in a DOMContentLoaded hook
document.addEventListener('DOMContentLoaded', () => {
  // Small delay to let aria.js set up evtSrc first
  setTimeout(() => {
    if (typeof evtSrc !== 'undefined') {
      const original = evtSrc.onmessage;
      evtSrc.onmessage = function(e) {
        if (original) original.call(this, e);
        try {
          const ev = JSON.parse(e.data);
          if (ev.source && ev.source.includes('proxy')) appendProxyLine(ev);
        } catch (_) {}
      };
    }
  }, 500);
});

function appendProxyLine(ev) {
  const feed = document.getElementById('proxy-feed-lines');
  if (!feed) return;

  const ts     = (ev.timestamp || '').slice(11, 19);
  const ip     = ev.source_ip || '–';
  const path   = ev.extra?.path || ev.raw_log?.slice(0, 60) || '–';
  const status = ev.extra?.status || '–';
  const cls    = status >= 500 ? 's5xx' : status >= 400 ? 's4xx'
               : status >= 300 ? 's3xx' : 's2xx';

  const line = document.createElement('div');
  line.className = 'proxy-line';
  line.innerHTML = `
    <span class="pl-ts">${ts}</span>
    <span class="pl-ip">${ip}</span>
    <span class="pl-path">${escapeHtml(path)}</span>
    <span class="pl-code ${cls}">${status}</span>`;
  feed.prepend(line);
  if (feed.children.length > 80) feed.lastElementChild.remove();
  _proxyLineCount++;
}


// ── Paste Logs ────────────────────────────────────────────────────────────────

// Live format detection as user types
document.addEventListener('DOMContentLoaded', () => {
  const ta = document.getElementById('paste-text');
  if (ta) {
    ta.addEventListener('input', () => {
      const sample = ta.value.slice(0, 500);
      if (sample.length < 20) {
        document.getElementById('paste-format-hint').textContent = '';
        return;
      }
      detectFormatHint(sample);
    });
  }
});

async function detectFormatHint(sample) {
  // Client-side heuristic (no server round-trip needed for hint)
  const hint = document.getElementById('paste-format-hint');
  if (!hint) return;
  let fmt = 'unknown';
  if (/\b(sshd|sudo)\[\d+\]:/.test(sample))                  fmt = 'auth.log';
  else if (/"[A-Z]+ \S+ HTTP\/\d\.\d" \d{3}/.test(sample))  fmt = 'Apache/Nginx';
  else if (/EventID:\s*\d+/.test(sample))                     fmt = 'Windows Event Log';
  else if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(sample)) fmt = 'generic';
  hint.textContent = `Detected: ${fmt}`;
  hint.style.color = fmt === 'unknown' ? 'var(--dim)' : 'var(--green)';
}

async function pasteIngest() {
  const text   = document.getElementById('paste-text').value.trim();
  const source = document.getElementById('paste-source').value.trim() || 'paste';
  const result = document.getElementById('paste-result');

  if (!text) { result.textContent = 'Paste some log lines first'; result.className = 'ingest-error'; return; }

  result.textContent = 'Processing…';
  result.className   = '';

  try {
    const r = await fetch('/api/ingest/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, source }),
    });
    const d = await r.json();
    if (d.ok) {
      result.textContent = `✓ ${d.lines} lines ingested (${d.format})`;
      result.className   = 'ingest-success';
    } else {
      result.textContent = `✗ ${d.error}`;
      result.className   = 'ingest-error';
    }
  } catch(e) {
    result.textContent = `✗ ${e}`;
    result.className   = 'ingest-error';
  }
}

function loadSampleLogs() {
  const samples = [
    `May  6 14:22:01 server sshd[1234]: Failed password for root from 192.168.1.45 port 54321 ssh2`,
    `May  6 14:22:02 server sshd[1234]: Failed password for root from 192.168.1.45 port 54321 ssh2`,
    `May  6 14:22:03 server sshd[1234]: Failed password for root from 192.168.1.45 port 54321 ssh2`,
    `May  6 14:22:04 server sshd[1235]: Invalid user admin from 10.0.0.23 port 41234 ssh2`,
    `May  6 14:22:05 server sshd[1236]: Invalid user oracle from 45.55.200.1 port 39012 ssh2`,
    `May  6 14:22:06 server sshd[1237]: Accepted password for ubuntu from 192.168.1.1 port 22 ssh2`,
    `May  6 14:22:10 server sudo[9001]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash`,
    `203.0.113.12 - - [06/May/2025:14:22:15 +0000] "GET /wp-admin HTTP/1.1" 401 512 "-" "Mozilla/5.0"`,
    `45.55.200.1 - - [06/May/2025:14:22:18 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 0 "-" "curl/7.68"`,
    `91.108.4.1 - - [06/May/2025:14:22:20 +0000] "GET /.env HTTP/1.1" 404 0 "-" "python-requests/2.25.1"`,
    `1.2.3.4 - - [06/May/2025:14:22:22 +0000] "GET /api/users?id=1' OR 1=1-- HTTP/1.1" 500 0 "-" "sqlmap/1.5"`,
    `TimeCreated: 2025-05-06T14:22:30 EventID: 4625 Source: Security Account Name: Administrator Source Address: 198.51.100.7`,
    `TimeCreated: 2025-05-06T14:22:31 EventID: 4672 Source: Security Account Name: SYSTEM Source Address: 192.168.1.100`,
  ].join('\n');

  document.getElementById('paste-text').value = samples;
  detectFormatHint(samples.slice(0, 500));
}


// ── File Upload ───────────────────────────────────────────────────────────────

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) uploadFile(file);
}

async function uploadFile(file) {
  const source = document.getElementById('upload-source').value.trim() || file.name;
  const result = document.getElementById('upload-result');

  result.innerHTML = `<span style="color:var(--dim)">Uploading ${escapeHtml(file.name)}…</span>`;

  const fd = new FormData();
  fd.append('file', file);
  fd.append('source', source);

  try {
    const r = await fetch('/api/ingest/upload', { method: 'POST', body: fd });
    const d = await r.json();

    if (d.ok) {
      result.innerHTML = `
        <span class="ingest-success">
          ✓ ${d.lines} lines ingested from <strong>${escapeHtml(file.name)}</strong>
          &nbsp;·&nbsp; Format: ${d.format}
          &nbsp;·&nbsp; Saved to ${escapeHtml(d.saved_to || '–')}
        </span>`;
    } else {
      result.innerHTML = `<span class="ingest-error">✗ ${escapeHtml(d.error)}</span>`;
    }
  } catch(e) {
    result.innerHTML = `<span class="ingest-error">✗ ${e}</span>`;
  }
}


// ── Fetch from URL ────────────────────────────────────────────────────────────

async function fetchIngest() {
  const url    = document.getElementById('fetch-url').value.trim();
  const source = document.getElementById('fetch-source').value.trim() || 'remote';
  const result = document.getElementById('fetch-result');

  if (!url) { result.textContent = 'Enter a URL'; result.className = 'ingest-error'; return; }

  result.textContent = 'Fetching…';
  result.className   = '';

  try {
    const r = await fetch('/api/ingest/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, source }),
    });
    const d = await r.json();
    if (d.ok) {
      result.textContent = `✓ Fetched ${d.fetched} lines, processed ${d.processed} (${d.format})`;
      result.className   = 'ingest-success';
    } else {
      result.textContent = `✗ ${d.error}`;
      result.className   = 'ingest-error';
    }
  } catch(e) {
    result.textContent = `✗ ${e}`;
    result.className   = 'ingest-error';
  }
}


// ── Windows Event Logs ────────────────────────────────────────────────────────

async function windowsIngest() {
  const log    = document.getElementById('win-log').value;
  const max    = document.getElementById('win-max').value || 200;
  const result = document.getElementById('win-result');

  result.textContent = 'Reading…';
  result.className   = '';

  try {
    const r = await fetch(`/api/ingest/windows?log=${encodeURIComponent(log)}&max=${max}`);
    const d = await r.json();
    if (d.ok) {
      result.textContent = `✓ ${d.processed} events ingested from ${log}`;
      result.className   = 'ingest-success';
    } else {
      result.textContent = `✗ ${d.error}`;
      result.className   = 'ingest-error';
    }
  } catch(e) {
    result.textContent = `✗ ${e}`;
    result.className   = 'ingest-error';
  }
}


// ── Helpers ───────────────────────────────────────────────────────────────────

function setStatus(id, msg, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.color = type === 'error' ? 'var(--red)'
                 : type === 'success' ? 'var(--green)'
                 : 'var(--dim)';
}

function setBadge(id, text, level) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className   = `badge ${level}`;
}