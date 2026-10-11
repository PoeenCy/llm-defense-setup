/* events.js — EVENTS tab: unified, searchable event log. */

let evRows = [];
const evFlowCache = new Map();   // survives auto-refresh, so rows don't flicker back to "…"
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
        <button class="er-btn-sm" data-act="llm" data-i="${i}">Ask LLM</button>
        <button class="er-btn-sm" data-act="rule" data-i="${i}">Make rule</button>
        <button class="er-btn-sm danger" data-act="quickblock" data-i="${i}" title="tự tải flow, tự chọn chuỗi hẹp nhất, build &amp; upload ctf_proxy ngay">⚡ Chặn ngay</button>
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
      if (res[k] && res[k].flow_id) evFlowCache.set(evKey(rows[i]), res[k]);
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
  if (e._flow && e._flow.flow_id) evFlowCache.set(evKey(e), e._flow);
  return e._flow;
}

async function evAskLLM(e) {
  $('modal-title').textContent = `LLM analysis — ${e.type} @ ${(e.ts || '').slice(0, 19)}`;
  $('modal-body').textContent = '⏳ Finding the Tulip flow for this event...';
  $('modal-overlay').classList.add('open');
  const f = e.type === 'flow' ? { flow_id: e.flow_id } : await flowForEvent(e);
  const body = f.flow_id ? { flow_id: f.flow_id } : {};
  if (e.raw) body.log_snippet = JSON.stringify(e.raw);
  if (!body.flow_id && !body.log_snippet) { $('modal-body').textContent = '✗ Nothing to analyze.'; return; }
  $('modal-body').textContent = (f.flow_id
      ? `✓ Using flow ${f.flow_id} (${f.why}).`
      : `! No Tulip flow found (${f.why}). The model only sees the alert line — weak evidence.`) +
    '\n\n⏳ Asking IOC Brain (model loads on demand, ~30-120s)...\n\nLLM output is a hint, not a verdict — verify before acting.';
  $('modal-title').textContent = `LLM analysis — ${e.type} @ ${(e.ts || '').slice(0, 19)}`;
  $('modal-body').textContent = '⏳ Asking IOC Brain (model loads on demand, ~15-60s)...\n\nLLM output is a hint, not a verdict — verify before acting.';
  $('modal-overlay').classList.add('open');
  try {
    $('modal-body').textContent = JSON.stringify(await apiPost('/api/analyze', body), null, 2);
  } catch (err) {
    $('modal-body').textContent = 'Request failed: ' + err;
  }
}

async function quickBlockClicked(btn, e) {
  if (!confirm('Tự tải flow, tự chọn chuỗi hẹp nhất, build & upload rule ctf_proxy NGAY (chặn thật, không hỏi lại)?\n\nNếu quá rộng (chặn cả path trần không có tham số) sẽ bị TỪ CHỐI thay vì tự áp — khi đó mở tab RULES để chọn tay.')) return;
  const old = btn.textContent;
  btn.disabled = true; btn.textContent = '⏳...';
  let res;
  try { res = await quickBlockFromEvent(e); } catch (err) { res = { ok: false, msg: 'Lỗi: ' + err }; }
  btn.disabled = false; btn.textContent = old;
  showToast(res.msg, res.ok ? 'success' : 'critical');
  if (res.ok) showTab('rules');   // let them see exactly what got uploaded
  else { showTab('rules'); rulesPrefillFromEvent(e); }   // refused -- land them on the manual builder instead
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
    if (b.dataset.act === 'llm') evAskLLM(e);
    if (b.dataset.act === 'rule') { showTab('rules'); rulesPrefillFromEvent(e); }
    if (b.dataset.act === 'quickblock') quickBlockClicked(b, e);
  });
  setInterval(() => {
    if (currentTab === 'events' && $('ev-auto').checked) loadEvents();
  }, 15000);
}
