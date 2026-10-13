/* monitor.js — Monitor tab: live alert feed (WebSocket), stats, watchdog, ML hints. */
// ── WebSocket ─────────────────────────────────────────────────
function connect() {
  ws = new WebSocket(CONFIG.wsUrl);

  ws.onopen = () => {
    setConnStatus(true);
    showToast('Dashboard connected', 'success');
  };

  ws.onclose = () => {
    setConnStatus(false);
    setTimeout(connect, 3000); // auto-reconnect
  };

  ws.onerror = () => setConnStatus(false);

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      handleMessage(msg);
    } catch(e) { console.error('WS parse error', e); }
  };
}

function setConnStatus(connected) {
  document.getElementById('conn-dot').className = 'conn-dot' + (connected ? ' connected' : '');
  document.getElementById('conn-label').textContent = connected ? 'LIVE' : 'RECONNECTING...';
}

function handleMessage(msg) {
  if (msg.type === 'initial_state') {
    alertData = msg.alerts || [];
    hintData  = msg.hints  || [];
    watchdogData = msg.watchdog || {};

    if (msg.config) {
      document.getElementById('footer-vulnbox').textContent = `Vulnbox: ${msg.config.vulnbox_ip}`;
      document.getElementById('footer-monitor').textContent = `Monitor: ${msg.config.monitor_ip}`;
    }

    recalcStats();
    renderAlerts();
    renderHints();
    renderWatchdog();
    return;
  }

  // New alert/hint streamed in
  if (msg.channel === 'alerts_channel' || msg.source === 'detection' || msg.source === 'watchdog') {
    alertData.unshift(msg);
    if (alertData.length > 200) alertData.pop();
    updateStats(msg);
    renderAlerts();
    notifyNewAlert(msg);
  } else if (msg.channel === 'hints_channel' || msg.source === 'ml-fingerprint') {
    hintData.unshift(msg);
    if (hintData.length > 100) hintData.pop();
    stats.hints++;
    document.getElementById('stat-hints').textContent = stats.hints;
    document.getElementById('hints-badge').textContent = hintData.length;
    renderHints();
  }
}

// ── Stats ─────────────────────────────────────────────────────
function recalcStats() {
  stats = { flagOut:0, honeytoken:0, suricata:0, sla:0, hints:hintData.length };
  for (const a of alertData) { updateStats(a, false); }
  updateStatDisplay();
}

function updateStats(a, updateDisplay=true) {
  const t = (a.type || '').toLowerCase();
  if (t === 'flag-out' || t === 'flag_out') stats.flagOut++;
  else if (t === 'honeytoken' || t === 'honeytoken-out') stats.honeytoken++;
  else if (t === 'suricata') stats.suricata++;
  else if (t.startsWith('sla-')) stats.sla++;
  if (updateDisplay) updateStatDisplay();
}

function updateStatDisplay() {
  document.getElementById('stat-flag-out').textContent   = stats.flagOut;
  document.getElementById('stat-honeytoken').textContent = stats.honeytoken;
  document.getElementById('stat-suricata').textContent   = stats.suricata;
  document.getElementById('stat-sla').textContent        = stats.sla;
  document.getElementById('stat-hints').textContent      = stats.hints;
  document.getElementById('total-alert-badge').textContent = alertData.length;
}

// ── Alert rendering ───────────────────────────────────────────
function getPriority(a) {
  const t = (a.type || '').toLowerCase();
  if (t === 'flag-out' || t === 'flag_out' || t === 'honeytoken' || t === 'honeytoken-out' || t === 'os-watchdog') return 'critical';
  if (t === 'suricata' && (a.severity || 3) <= 1) return 'critical';
  if (t === 'suricata') return 'high';
  if (t === 'sla-down') return 'high';
  if (t === 'sla-slow') return 'medium';
  if (t === 'sla-restored' || t === 'flag-planted') return 'info';
  if (t === 'flag-echo') return 'low';
  if (t === 'bot-deviation-hint') return 'hint';
  if (a.confidence === 'HIGH') return 'high';
  if (a.confidence === 'MEDIUM') return 'medium';
  return 'low';
}

function getTypeClass(type) {
  const t = (type || '').toLowerCase();
  if (t === 'flag-out' || t === 'flag_out') return 'type-flag-out';
  if (t === 'honeytoken' || t === 'honeytoken-out') return 'type-honeytoken';
  if (t === 'suricata') return 'type-suricata';
  if (t === 'sla-down') return 'type-sla-down';
  if (t === 'sla-slow') return 'type-sla-slow';
  if (t === 'sla-restored') return 'type-sla-restored';
  if (t === 'bot-deviation-hint') return 'type-bot-hint';
  if (t === 'ioc-analysis') return 'type-ioc';
  return 'type-default';
}

function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('filter-' + f)?.classList.add('active');
  renderAlerts();
}

function renderAlerts() {
  const list = document.getElementById('alert-list');

  let filtered = alertData;
  if (currentFilter === 'critical') {
    filtered = alertData.filter(a => getPriority(a) === 'critical' || getPriority(a) === 'high');
  } else if (currentFilter === 'hints') {
    filtered = alertData.filter(a => getPriority(a) === 'hint');
  }

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="icon">📡</div>
        <p>No alerts yet.<br>Waiting for detection events...</p>
      </div>`;
    return;
  }

  // Sort: critical first, then by time
  const order = { critical:0, high:1, medium:2, low:3, hint:4, info:5 };
  const sorted = [...filtered].sort((a, b) => {
    const pa = order[getPriority(a)] ?? 99;
    const pb = order[getPriority(b)] ?? 99;
    if (pa !== pb) return pa - pb;
    return new Date(b.ts || 0) - new Date(a.ts || 0);
  });

  list.innerHTML = sorted.slice(0, 100).map((a, i) => {
    const prio = getPriority(a);
    const typeClass = getTypeClass(a.type);
    const ts = a.ts ? new Date(a.ts).toLocaleTimeString('en-US', {hour12:false}) : '?';
    const isNew = i === 0;
    return `
      <div class="alert-card prio-${prio} ${isNew && prio==='critical' ? 'new-critical' : ''}"
           onclick="showModal(${JSON.stringify(JSON.stringify(a)).replace(/'/g, "&#39;")})">
        <div class="alert-header">
          <span class="alert-type-badge ${typeClass}">${(a.type||'unknown').toUpperCase()}</span>
          <span class="alert-message">${escHtml(a.message || 'No message')}</span>
        </div>
        <div class="alert-meta">
          <span class="conf-${a.confidence || 'MEDIUM'}">${a.confidence || '?'}</span>
          ${a.src_ip ? `<span class="ip">${escHtml(a.src_ip)}</span>` : ''}
          ${a.dst_ip ? `<span>→ <span class="ip">${escHtml(a.dst_ip)}</span></span>` : ''}
          ${a.service ? `<span class="ip">${escHtml(a.service)}</span>` : ''}
          <span class="mon-flow" data-flowkey="${i}" onclick="event.stopPropagation()"></span>
          <span style="margin-left:auto;">${ts}</span>
        </div>
      </div>`;
  }).join('');
  monResolveFlows(sorted);
}

/* Flow id for the alert cards (same resolver the Events tab uses). Lazy +
   cached so the live feed doesn't hammer Tulip. */
const monFlowCache = new Map();
const monKey = a => [a.ts, a.src_ip, a.dst_ip, a.message].join('|');

function monFlowHtml(a, r) {
  const url = id => `${location.protocol}//${location.hostname}:${META.tulip_port || 3000}/flow/${id}`;
  if (a.flow_id) return `<a class="flowlink" href="${url(a.flow_id)}" target="_blank" onclick="event.stopPropagation()">✓ flow</a>`;
  if (!r || !r.flow_id) return '';
  return `<a class="flowlink ${r.exact ? '' : 'approx'}" href="${url(r.flow_id)}" target="_blank" title="${escHtml(r.why || '')}" onclick="event.stopPropagation()">${r.exact ? '✓' : '~'} flow</a>`;
}

async function monResolveFlows(sorted) {
  sorted.forEach((a, i) => {
    const c = a.flow_id ? null : monFlowCache.get(monKey(a));
    const span = document.querySelector(`.mon-flow[data-flowkey="${i}"]`);
    if (span && (a.flow_id || c)) span.innerHTML = monFlowHtml(a, c);
  });
  const todo = sorted.map((a, i) => i).filter(i => {
    const a = sorted[i];
    return !a.flow_id && !monFlowCache.get(monKey(a)) && (a.src_ip || a.dst_ip) &&
           !['sla-down', 'sla-slow', 'sla-restored', 'bot-deviation-hint'].includes(a.type);
  }).slice(0, 40);
  if (!todo.length) return;
  let res;
  try { res = await apiPost('/api/tulip/resolve', { events: todo.map(i => sorted[i]) }); } catch (e) { return; }
  if (!Array.isArray(res)) return;
  todo.forEach((i, k) => {
    if (res[k] && res[k].flow_id) monFlowCache.set(monKey(sorted[i]), res[k]);
    const span = document.querySelector(`.mon-flow[data-flowkey="${i}"]`);
    if (span) span.innerHTML = monFlowHtml(sorted[i], res[k]);
  });
}

// ── Watchdog rendering ────────────────────────────────────────
function renderWatchdog() {
  const list = document.getElementById('service-list');
  const entries = Object.values(watchdogData);

  if (entries.length === 0) {
    list.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text-dim);font-size:11px;">Polling vulnbox services...</div>`;
    return;
  }

  const upCount = entries.filter(e => e.state === 'up').length;
  document.getElementById('watchdog-badge').textContent = `${upCount}/${entries.length} UP`;
  document.getElementById('watchdog-badge').className = `panel-badge ${upCount === entries.length ? 'badge-green' : 'badge-red'}`;

  list.innerHTML = entries.map(s => `
    <div class="service-row">
      <div class="service-indicator ${s.state || 'unknown'}"></div>
      <div class="service-name">${escHtml(s.name || '?')}</div>
      <div class="service-port">:${s.port}</div>
      <div class="service-latency">${s.state === 'up' ? '✓ UP ' + s.latency_ms + 'ms'
        : s.state === 'down' ? '✗ DOWN' : s.state === 'slow' ? '! SLOW ' + (s.latency_ms || '') + 'ms'
        : '? ' + escHtml((s.state || 'unknown').toUpperCase())}</div>
    </div>
  `).join('');
}

// Update watchdog status from alerts
function updateWatchdogFromAlert(a) {
  if (!a.service) return;
  const key = `${a.service}:${a.port}`;
  if (a.type === 'sla-down')      watchdogData[key] = {...(watchdogData[key]||{}), name:a.service, port:a.port, state:'down', latency_ms:a.latency_ms||0};
  if (a.type === 'sla-slow')      watchdogData[key] = {...(watchdogData[key]||{}), name:a.service, port:a.port, state:'slow', latency_ms:a.latency_ms||0};
  if (a.type === 'sla-restored')  watchdogData[key] = {...(watchdogData[key]||{}), name:a.service, port:a.port, state:'up',   latency_ms:a.latency_ms||0};
  renderWatchdog();
}

// ── Hints rendering ────────────────────────────────────────────
function renderHints() {
  const list = document.getElementById('hint-list');
  document.getElementById('hints-badge').textContent = hintData.length;
  if (hintData.length === 0) {
    list.innerHTML = `<div style="padding:16px;text-align:center;color:var(--text-dim);font-size:11px;">Warming up fingerprinter... (~3 ticks)</div>`;
    return;
  }
  list.innerHTML = hintData.slice(0, 40).map(h => `
    <div class="hint-card">
      <div class="hint-label">🤖 BOT DEVIATION — tick ${h.tick || '?'}</div>
      <div class="hint-msg">${escHtml(h.message || '')}</div>
      <div class="hint-meta">
        ${h.src_ip ? `src: ${escHtml(h.src_ip)}` : ''}
        ${h.dst_port ? ` dst: :${h.dst_port}` : ''}
        ${h.dist_from_bot_cluster ? ` dist: ${h.dist_from_bot_cluster}` : ''}
      </div>
    </div>
  `).join('');
}

// ── Poll for watchdog status every 5s ─────────────────────────
async function pollWatchdog() {
  try {
    const resp = await fetch('/api/watchdog');
    if (resp.ok) {
      watchdogData = await resp.json();
      renderWatchdog();
    }
  } catch(e) {}
}
setInterval(pollWatchdog, 5000);

// ── Poll for recent alerts if WS disconnected ──────────────────
async function pollAlerts() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  try {
    const [ar, hr] = await Promise.all([
      fetch('/api/alerts?n=50').then(r=>r.json()).catch(()=>[]),
      fetch('/api/hints?n=30').then(r=>r.json()).catch(()=>[]),
    ]);
    alertData = ar;
    hintData  = hr;
    recalcStats();
    renderAlerts();
    renderHints();
  } catch(e) {}
}
setInterval(pollAlerts, 8000);

