/* ARIA – Dashboard JavaScript */

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toUTCString().slice(17, 25) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ── Chart.js defaults ─────────────────────────────────────────────────────────
Chart.defaults.color = '#4a6480';
Chart.defaults.borderColor = '#1a2d4a';

// ── Timeline Chart ────────────────────────────────────────────────────────────
const tlCtx = document.getElementById('timeline-chart').getContext('2d');
const tlChart = new Chart(tlCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Events/min',
      data: [],
      borderColor: '#00c8ff',
      backgroundColor: 'rgba(0,200,255,.08)',
      borderWidth: 2,
      fill: true,
      tension: 0.4,
      pointRadius: 2,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { maxTicksLimit: 8, font: { family: 'Share Tech Mono', size: 10 } } },
      y: { beginAtZero: true, ticks: { font: { family: 'Share Tech Mono', size: 10 } } }
    }
  }
});

// ── Severity Doughnut ─────────────────────────────────────────────────────────
const sevCtx = document.getElementById('sev-chart').getContext('2d');
const sevChart = new Chart(sevCtx, {
  type: 'doughnut',
  data: {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [0, 0, 0, 0],
      backgroundColor: ['#ff3b5c', '#ff8c00', '#f5c518', '#00e5a0'],
      borderWidth: 0,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: { font: { family: 'Share Tech Mono', size: 11 } }
      }
    },
    cutout: '68%',
  }
});

// ── Stats Refresh ─────────────────────────────────────────────────────────────
async function refreshStats() {
  try{
  const r = await fetch('/api/stats');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  document.getElementById('stat-critical').textContent = d.critical ?? 0;
  document.getElementById('stat-high').textContent     = d.high ?? 0;
  document.getElementById('stat-1h').textContent       = d.last_1h ?? 0;
  document.getElementById('stat-total').textContent    = d.total_alerts ?? 0;

  const score = d.avg_anomaly_score ?? 0;
  document.getElementById('gauge-val').textContent = score.toFixed(2);
  document.getElementById('gauge-needle').style.left = Math.min(score * 100, 100) + '%';
  const gv = document.getElementById('gauge-val');
  gv.style.color = score > .7 ? 'var(--red)' : score > .4 ? 'var(--orange)' : 'var(--green)';
}
catch (err) {
  console.error('[ARIA] Failed to refresh stats:', err);
}
}

async function refreshTimeline() {
  const r = await fetch('/api/timeline');
  const d = await r.json();
  tlChart.data.labels = d.map(x => x.bucket.slice(11, 16));
  tlChart.data.datasets[0].data = d.map(x => x.count);
  tlChart.update();
}

async function refreshSeverity() {
  const r = await fetch('/api/severity_breakdown');
  const d = await r.json();
  sevChart.data.datasets[0].data = [
    d.CRITICAL || 0, d.HIGH || 0, d.MEDIUM || 0, d.LOW || 0
  ];
  sevChart.update();
}

async function refreshTopIPs() {
  const r = await fetch('/api/top_ips');
  const d = await r.json();
  const el = document.getElementById('top-ips');
  if (!d.length) {
    el.innerHTML = '<span style="color:var(--dim)">No data yet</span>';
    return;
  }
  el.innerHTML = d.map((x, i) => `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
      <span style="color:var(--dim);min-width:16px;">${i + 1}.</span>
      <span style="color:var(--accent);flex:1;">${x.source_ip}</span>
      <span style="color:var(--dim);">${x.hit_count} hits</span>
      <span class="badge ${x.max_severity}">${x.max_severity}</span>
    </div>
  `).join('');
}

function refreshAll() {
  refreshStats();
  refreshTimeline();
  refreshSeverity();
  refreshTopIPs();
}

setInterval(refreshAll, 5000);
refreshAll();

// ── Alert Table ───────────────────────────────────────────────────────────────
let currentPage = 1;

async function loadAlerts(page = 1) {
  currentPage = page;
  const q   = document.getElementById('search-input').value;
  const sev = document.getElementById('sev-filter').value;
  const params = new URLSearchParams({ page, limit: 20, q, severity: sev });
  const r = await fetch('/api/alerts?' + params);
  const d = await r.json();

  const tbody = document.getElementById('alert-tbody');
  tbody.innerHTML = d.alerts.map(a => {
    const score = a.anomaly_score || 0;
    const pct   = Math.round(score * 100);
    const fillColor = score > .7 ? 'var(--red)' : score > .4 ? 'var(--orange)' : 'var(--green)';
    const ts = (a.timestamp || '').slice(0, 19).replace('T', ' ');
    return `
      <tr>
        <td style="color:var(--dim)">${a.id}</td>
        <td style="color:var(--dim)">${ts}</td>
<td style="color:var(--accent)">${escapeHtml(a.source_ip || '–')}</td>
<td>${escapeHtml(a.attack_type || '–')}</td>
<td style="color:var(--dim);font-size:10px;">${escapeHtml(a.mitre_tag || '–')}</td>
        <td>
          <div class="score-bar">
            <div class="score-fill" style="width:${pct}%;background:${fillColor};"></div>
          </div>
          <span style="font-size:10px;color:var(--dim)">${score.toFixed(2)}</span>
        </td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>
          ${a.llm_summary
            ? `<span style="font-size:15px;color:var(--dim)">${escapeHtml(a.llm_summary.slice(0, 60))}…</span>`
            : `<button class="btn-summary" onclick="openSummary(${a.id})">Generate</button>`
          }
        </td>
      </tr>`;
  }).join('') || `
    <tr>
      <td colspan="8" style="text-align:center;color:var(--dim);padding:30px;">
        No alerts yet — start demo_log_gen.py to generate traffic.
      </td>
    </tr>`;

  const total = d.total;
  const pages = Math.ceil(total / 20);
  document.getElementById('page-info').textContent = `Page ${page} of ${Math.max(pages, 1)}`;
  document.getElementById('total-info').textContent = `${total} total`;
  document.getElementById('btn-prev').disabled = page <= 1;
  document.getElementById('btn-next').disabled = page >= pages;
}

function prevPage() { loadAlerts(currentPage - 1); }
function nextPage() { loadAlerts(currentPage + 1); }

// Auto-refresh table every 8 seconds
setInterval(() => loadAlerts(currentPage), 8000);
loadAlerts(1);

// ── Live SSE Feed ─────────────────────────────────────────────────────────────
let feedCount = 0;
const feed = document.getElementById('live-feed');
const evtSrc = new EventSource('/stream');

evtSrc.onmessage = function (e) {
  const ev = JSON.parse(e.data);
  feedCount++;
  document.getElementById('feed-count').textContent = feedCount + ' events';

  const sev = (ev.severity || '').toLowerCase();
  const ts  = (ev.timestamp || '').slice(11, 19);
  const ip  = ev.source_ip || '0.0.0.0';
  const msg = ev.raw_log ? ev.raw_log.slice(0, 120) : (ev.attack_type || 'event');

  const line = document.createElement('div');
  line.className = `feed-line ${sev}`;
  line.innerHTML = `
    <span class="feed-ts">${ts}</span>
    <span class="feed-ip">${ip}</span>
    <span class="feed-msg">${escapeHtml(msg)}</span>`;

  feed.prepend(line);
  if (feed.children.length > 200) feed.lastElementChild.remove();
};

evtSrc.onerror = function () {
  console.warn('[ARIA] SSE connection lost, retrying...');
};

// ── Summary Modal ─────────────────────────────────────────────────────────────
async function openSummary(id) {
  document.getElementById('modal-text').textContent = 'Generating AI summary…';
  document.getElementById('modal-overlay').classList.add('open');
  try {
    const r = await fetch(`/api/alerts/${id}/summary`);
    const d = await r.json();
    document.getElementById('modal-text').textContent = d.summary || 'No summary available.';
    loadAlerts(currentPage);
  } catch {
    document.getElementById('modal-text').textContent = 'Error generating summary.';
  }
}

function closeModal(e) {
  if (!e || e.target === document.getElementById('modal-overlay')) {
    document.getElementById('modal-overlay').classList.remove('open');
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
