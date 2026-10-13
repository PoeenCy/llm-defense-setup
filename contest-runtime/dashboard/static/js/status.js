/* status.js — System Status panel (data from host_agent.py via /api/status). */
// ── Poll for system status (health_check.py --push) every 10s ──
async function pollStatus() {
  try {
    const resp = await fetch('/api/status');
    if (resp.ok) renderStatus(await resp.json());
  } catch(e) {}
}
function renderStatus(data) {
  const list = document.getElementById('status-list');
  const items = data.items || [];
  if (items.length === 0) {
    list.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text-dim);font-size:11px;">
      ${escHtml(data.note || 'No status data yet')}</div>`;
    document.getElementById('status-badge').textContent = '—';
    return;
  }
  const upCount = items.filter(i => i.status === 'up').length;
  document.getElementById('status-badge').textContent = `${upCount}/${items.length} UP`;
  document.getElementById('status-badge').className = `panel-badge ${upCount === items.length ? 'badge-green' : 'badge-red'}`;
  document.getElementById('status-staleness').textContent = data.stale
    ? '⚠ STALE — host_agent.py not running (re-run deploy-all.sh, or: python3 host_agent.py &)'
    : `updated ${Math.max(0, Math.round(Date.now()/1000 - data.checked_at))}s ago`;

  list.innerHTML = items.map(it => `
    <div class="service-row" style="flex:0 0 auto;min-width:220px;" title="${escHtml(it.detail || '')}">
      <div class="service-indicator ${it.status || 'unknown'}"></div>
      <div class="service-name">${escHtml(it.name || '?')}</div>
    </div>
  `).join('');
}
pollStatus();
setInterval(pollStatus, 10000);

