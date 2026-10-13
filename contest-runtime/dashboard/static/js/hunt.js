/* hunt.js — HUNT tab: query events + Tulip flows to reconstruct an attack. */

function huBody() {
  const toISO = id => { const v = $(id).value; return v ? new Date(v).toISOString() : ''; };
  return {
    ip: $('hu-ip').value.trim(), port: $('hu-port').value.trim(),
    since: toISO('hu-since'), until: toISO('hu-until'),
    text: $('hu-text').value, regex: $('hu-regex').checked,
  };
}

function huFlowLink(id) {
  return `${location.protocol}//${location.hostname}:${META.tulip_port || 3000}/flow/${id}`;
}

async function huSearch() {
  $('hu-summary').textContent = '⏳ Searching events and Tulip flows...';
  let d;
  try { d = await apiPost('/api/hunt', huBody()); } catch (e) { $('hu-summary').textContent = '✗ ' + e; return; }
  if (d.error) { $('hu-summary').textContent = '✗ ' + d.error; return; }
  const s = d.summary;
  $('hu-summary').textContent =
    `${s.events} event(s), ${s.flows} flow(s)` + (s.flows_shown < s.flows ? ` (showing ${s.flows_shown})` : '') +
    `\nFirst seen: ${(s.first_seen || '—').slice(0, 19)}   Last seen: ${(s.last_seen || '—').slice(0, 19)}` +
    `\nEvent types: ${s.event_types.map(([t, n]) => `${t}×${n}`).join('  ') || '—'}` +
    `\nTop clients (by flow count): ${s.top_clients.map(([ip, n]) => `${ip}×${n}`).join('  ') || '—'}` +
    (d.flow_error ? `\n⚠ ${d.flow_error}` : '');

  $('hu-ev-n').textContent = d.events.length;
  $('hu-ev').innerHTML = d.events.length ? d.events.map((e, i) => `<tr>
      <td>${escHtml((e.ts_packet || e.ts || '').slice(0, 19).replace('T', ' '))}</td>
      <td><span class="sev sev-${e.severity}">${e.severity}</span></td>
      <td>${escHtml(e.type)}</td>
      <td>${escHtml(e.src_ip || '-')} → ${escHtml(e.dst_ip || '-')}</td>
      <td class="msg">${escHtml(e.message)}</td>
      <td><button class="er-btn-sm" data-hu-ev="${i}">Make rule</button></td></tr>`).join('')
    : '<tr><td colspan="6" class="er-empty">No events match.</td></tr>';
  huEvents = d.events;

  $('hu-fl-n').textContent = d.flows.length;
  $('hu-fl').innerHTML = d.flows.length ? d.flows.map(f => `<tr>
      <td>${escHtml((f.time || '').slice(0, 19).replace('T', ' '))}</td>
      <td>${escHtml(f.src)} → ${escHtml(f.dst)}</td>
      <td>${escHtml((f.tags || []).join(', '))}</td>
      <td><a class="flowlink" href="${huFlowLink(f.id)}" target="_blank">open</a>
          <button class="er-btn-sm" data-hu-fl="${escHtml(f.id)}">Make rule</button></td></tr>`).join('')
    : '<tr><td colspan="4" class="er-empty">No flows match.</td></tr>';
}

let huEvents = [];
function initHunt() {
  $('hu-go').onclick = huSearch;
  $('hu-text').addEventListener('keydown', e => { if (e.key === 'Enter') huSearch(); });
  document.querySelectorAll('#tab-hunt [data-range]').forEach(b => b.onclick = () => {
    const mins = +b.dataset.range;
    const fmt = d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
    $('hu-until').value = mins ? fmt(new Date()) : '';
    $('hu-since').value = mins ? fmt(new Date(Date.now() - mins * 60000)) : '';
    huSearch();
  });
  $('hu-ev').addEventListener('click', e => {
    const b = e.target.closest('[data-hu-ev]'); if (!b) return;
    showTab('rules'); rulesPrefillFromEvent(huEvents[+b.dataset.huEv]);
  });
  $('hu-fl').addEventListener('click', e => {
    const b = e.target.closest('[data-hu-fl]'); if (!b) return;
    showTab('rules'); loadFlow(b.dataset.huFl);
  });
}
