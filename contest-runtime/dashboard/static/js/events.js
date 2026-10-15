/* events.js — EVENTS tab: unified, searchable event log. */

let evRows = [];
// Survives auto-refresh (so rows don't flicker back to "…") but otherwise
// grows by one entry per event for the whole session -- over an 8h contest
// that's real browser memory, not theoretical. Capped via capMap() (core.js).
const evFlowCache = new Map();
const EV_FLOW_CACHE_MAX = 2000;
const evKey = e => [e.ts, e.src_ip, e.dst_ip, e.message].join('|');

function evQuery() {
  return new URLSearchParams({
    q: $('ev-q').value, source: $('ev-source').value, severity: $('ev-sev').value,
  }).toString();
}

async function loadEvents() {
  const qs = evQuery();
  $('ev-export').href = '/api/events.log?' + qs;
  try { evRows = await apiGet('/api/events?limit=500&' + qs); } catch (e) { evRows = []; }
  evRows.forEach(e => { const c = evFlowCache.get(evKey(e)); if (c) e._flow = c; });
  $('ev-count').textContent = `${evRows.length} events`;
  const body = $('ev-body');
  if (!evRows.length) {
    body.innerHTML = `<tr><td colspan="7" class="er-empty">No events match.</td></tr>`;
    return;
  }
  body.innerHTML = evRows.map((e, i) => {
    const flow = `${escHtml(e.src_ip || '-')} → ${escHtml(e.dst_ip || '-')}${e.dst_port ? ':' + escHtml(String(e.dst_port)) : ''}`;
    return `<tr>
      <td>${escHtml((e.ts || '').slice(0, 19).replace('T', ' '))}</td>
      <td><span class="sev sev-${e.severity}">${e.severity}</span></td>
      <td>${escHtml(e.source)}<br><span style="color:var(--text-dim)">${escHtml(e.type)}</span></td>
      <td>${flow}</td>
      <td id="evf-${i}">${flowCell(e)}</td>
      <td class="msg">${escHtml(e.message)}</td>
      <td style="white-space:nowrap;">
        <button class="er-btn-sm" data-act="detail" data-i="${i}">Detail</button>
        ${e.type === 'os-watchdog' ? `<button class="er-btn-sm" data-act="oswd-allow" data-i="${i}" title="Mark this exact alert (not the whole type) as known-good -- e.g. the organizer's checker legitimately SSHing in -- so it stops repeating">✓ Known-good</button>` : `
        <button class="er-btn-sm" data-act="rule" data-i="${i}">Make rule</button>
        <button class="er-btn-sm" data-act="alert" data-i="${i}" title="Suricata only -- never blocks anything, always safe">Alert</button>
        <button class="er-btn-sm danger" data-act="block" data-i="${i}" title="ctf_proxy -- auto-loads the flow, picks the narrowest safe match, uploads a real block. Refuses on a bare path with no parameter.">Block</button>`}
      </td>
    </tr>`;
  }).join('');
  evResolveVisible();
}

/* ── Tulip flow behind each event ───────────────────────────── */
function tulipUrl(id) {
  return `${location.protocol}//${location.hostname}:${META.tulip_port || 3000}/flow/${id}`;
}

function flowCell(e) {
  const r = e._flow;
  if (e.flow_id) return `<a class="flowlink" href="${tulipUrl(e.flow_id)}" target="_blank" title="${escHtml(e.flow_id)}">✓ …${escHtml(e.flow_id.slice(-12))}</a>`;
  if (!r) return (e.src_ip || e.dst_ip) ? '<span style="color:var(--text-dim)">…</span>' : '<span style="color:var(--text-dim)">—</span>';
  if (!r.flow_id) return `<span style="color:var(--text-dim)" title="${escHtml(r.why || '')}">— none</span>`;
  return `<a class="flowlink ${r.exact ? '' : 'approx'}" href="${tulipUrl(r.flow_id)}" target="_blank"
            title="${escHtml(r.flow_id + ' — ' + r.why)}">${r.exact ? '✓' : '~'} …${escHtml(r.flow_id.slice(-12))}</a>`;
}

/* Ask the backend to find the flow for every visible row that has IPs. */
async function evResolveVisible() {
  const rows = evRows;
  const todo = rows.map((e, i) => i).filter(i => !rows[i].flow_id && !rows[i]._flow && (rows[i].src_ip || rows[i].dst_ip));
  for (let off = 0; off < todo.length; off += 100) {
    const idx = todo.slice(off, off + 100);
    let res;
    try { res = await apiPost('/api/tulip/resolve', { events: idx.map(i => rows[i]) }); } catch (e) { return; }
    if (rows !== evRows || !Array.isArray(res)) return;      // table was reloaded meanwhile
    idx.forEach((i, k) => {
      rows[i]._flow = res[k];
      if (res[k] && res[k].flow_id) { evFlowCache.set(evKey(rows[i]), res[k]); capMap(evFlowCache, EV_FLOW_CACHE_MAX); }
      const cell = $('evf-' + i);
      if (cell) cell.innerHTML = flowCell(rows[i]);
    });
  }
}

/* Flow for one event: its own id, the already-resolved one, or ask now. */
async function flowForEvent(e) {
  if (e.flow_id) return { flow_id: e.flow_id, exact: true, why: 'event carries its flow id' };
  if (e._flow) return e._flow;
  if (!e.src_ip && !e.dst_ip) return { flow_id: null, why: 'event has no IP/time to search by' };
  try { e._flow = (await apiPost('/api/tulip/resolve', { events: [e] }))[0]; } catch (err) { return { flow_id: null, why: String(err) }; }
  if (e._flow && e._flow.flow_id) { evFlowCache.set(evKey(e), e._flow); capMap(evFlowCache, EV_FLOW_CACHE_MAX); }
  return e._flow;
}

async function quickAlertClicked(btn, e) {
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = '...';
  let res;
  try { res = await quickAlertFromEvent(e); } catch (err) { res = { ok: false, msg: 'Error: ' + err }; }
  btn.disabled = false; btn.textContent = old;
  showToast(res.msg, res.ok ? 'success' : 'critical');
  showTab('rules');
  if (!res.ok) rulesPrefillFromEvent(e);
}

async function quickBlockClicked(btn, e) {
  if (!confirm('Auto-load the flow, pick the narrowest safe match, build & upload a ctf_proxy block rule NOW (real block, no further confirmation)?\n\nToo broad a match (a bare path with no parameter) gets REFUSED instead of auto-applied -- open the RULES tab to pick by hand in that case.')) return;
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = '...';
  let res;
  try { res = await quickBlockFromEvent(e); } catch (err) { res = { ok: false, msg: 'Error: ' + err }; }
  btn.disabled = false; btn.textContent = old;
  showToast(res.msg, res.ok ? 'success' : 'critical');
  if (res.ok) showTab('rules');   // let them see exactly what got uploaded
  else { showTab('rules'); rulesPrefillFromEvent(e); }   // refused -- land them on the manual builder instead
}

/* A one-time baseline diff can't tell "the checker legitimately SSH'd in"
   from "an attacker did" -- both just look like "not in baseline" to it.
   This marks the EXACT (alert_type, detail text) a human just looked at and
   recognized as known-good, so os-watchdog-agent.sh stops re-reporting that
   specific thing every CHECK_INTERVAL. Any different/new alert still fires. */
async function markOswdKnownGood(e) {
  const alertType = (e.raw && e.raw.alert_type) || '';
  const suggested = (e.raw && e.raw.detail) || e.message || '';
  if (!alertType) { showToast('No alert_type on this event -- cannot allowlist it', 'critical'); return; }
  const pattern = prompt(
    `Mark "${alertType}" alerts matching this text as known-good (e.g. the organizer's checker) -- edit down to just the stable/recurring part if this exact text won't repeat verbatim:`,
    suggested
  );
  if (pattern === null) return;
  if (!pattern.trim()) { showToast('Empty pattern -- not added', 'critical'); return; }
  const d = await apiPost('/api/oswatchdog/allow', { alert_type: alertType, pattern: pattern.trim() });
  showToast(d.ok ? `✓ Allowlisted [${alertType}]` : '✗ ' + d.output, d.ok ? 'success' : 'critical');
}

function initEvents() {
  $('ev-search').onclick = loadEvents;
  $('ev-q').addEventListener('keydown', ev => { if (ev.key === 'Enter') loadEvents(); });
  $('ev-source').onchange = loadEvents;
  $('ev-sev').onchange = loadEvents;
  $('ev-body').addEventListener('click', ev => {
    const b = ev.target.closest('button[data-act]');
    if (!b) return;
    const e = evRows[+b.dataset.i];
    if (b.dataset.act === 'detail') showModal(JSON.stringify({ ...e.raw, ts: e.ts }));
    if (b.dataset.act === 'rule') { showTab('rules'); rulesPrefillFromEvent(e); }
    if (b.dataset.act === 'alert') quickAlertClicked(b, e);
    if (b.dataset.act === 'block') quickBlockClicked(b, e);
    if (b.dataset.act === 'oswd-allow') markOswdKnownGood(e);
  });
  setInterval(() => {
    if (currentTab === 'events' && $('ev-auto').checked) loadEvents();
  }, 15000);
}
