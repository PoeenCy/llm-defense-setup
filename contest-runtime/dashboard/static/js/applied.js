/* applied.js — APPLIED tab: what rules are live, where, and how often they fired. */

const BUILTIN_WHAT = {
  'flag-out': 'detection: a flag left a service (open the flow to judge checker vs theft)',
  'flag-planted': 'detection: a flag was stored into a service (usually the checker)',
  'flag-echo': 'detection: a store response repeated its own flag',
  'honeytoken-out': 'detection: a decoy honeytoken left a service',
  'honeytoken': 'detection: the honeytoken endpoint was hit',
  'proxy-blocked': 'detection: ctf_proxy blocked a request',
  'sla-down': 'watchdog: a service stopped answering', 'sla-slow': 'watchdog: a service got slow',
  'sla-restored': 'watchdog: a service recovered', 'os-watchdog': 'OS watchdog agent on the vulnbox',
  'bot-deviation-hint': 'ML: a client looked unlike the checker',
};

async function loadApplied(withProxy) {
  $('ap-where').textContent = '⏳ Loading...';
  let d;
  try { d = await apiGet('/api/applied' + (withProxy ? '?proxy=1' : '')); } catch (e) { $('ap-where').textContent = '✗ ' + e; return; }
  const cps = d.ctfproxy || [];
  const cpSummary = cps.length ? cps.map(cp =>
    `  [${cp.service}] ` + (cp.loaded ? `${cp.methods.length} rule(s), ${cp.paused ? 'PAUSED' : 'filtering'}`
      : cp.error ? `not loaded (${cp.error})` : 'press "Load rule list from vulnbox"') + `\n    → ${cp.location}`
  ).join('\n') : '  (no TCP service in services.json)';
  $('ap-where').textContent =
    `SURICATA (alert): ${d.suricata.active} active` + (d.suricata.disabled ? `, ${d.suricata.disabled} disabled` : '') +
    `\n  → ${d.suricata.location}` +
    `\n\nCTF_PROXY (block):\n${cpSummary}` +
    `\n\nCounts from the ${d.window}.`;

  const anyLoaded = cps.some(cp => cp.loaded);
  const allPaused = cps.length && cps.every(cp => cp.paused === true);
  $('ap-cp-state').className = 'state ' + (allPaused ? 'state-paused' : anyLoaded ? 'state-running' : 'state-unknown');
  $('ap-cp-state').textContent = allPaused ? 'PAUSED' : anyLoaded ? (cps.length > 1 ? `${cps.length} SERVICES` : 'FILTERING') : '';
  const rows = cps.flatMap(cp => cp.methods.map(m => ({ ...m, service: cp.service })));
  $('ap-cp').innerHTML = rows.length ? rows.map(m => `<tr>
      <td>${escHtml(m.service)}</td>
      <td><b>${escHtml(m.name)}</b></td><td>${m.hits}</td>
      <td>${escHtml((m.last_hit || '—').slice(0, 19))}</td>
      <td>${escHtml(m.top_sources.join(', ') || '—')}</td>
      <td><button class="er-btn-sm danger" data-ap-cp-del="${escHtml(m.name)}" data-ap-cp-service="${escHtml(m.service)}" title="remove this rule now">✗ Xóa</button></td></tr>`).join('')
    : `<tr><td colspan="6" class="er-empty">${anyLoaded ? 'No ctf_proxy block rules defined.' : 'Not loaded — click “Load rule list from vulnbox”. Blocks seen in traffic still appear once they happen.'}</td></tr>`;

  apSuRules = d.suricata.rules;
  renderApSu();
  $('ap-su-n').textContent = `${d.suricata.active} active`;

  $('ap-bi').innerHTML = (d.builtin.length ? d.builtin : []).map(b => `<tr>
      <td>${escHtml(b.type)}</td><td>${b.count}</td>
      <td class="msg">${escHtml(BUILTIN_WHAT[b.type] || '')}</td></tr>`).join('')
    || '<tr><td colspan="3" class="er-empty">No events yet.</td></tr>';
}

let apSuRules = [];
function renderApSu() {
  const only = $('ap-only-hit').checked;
  const rows = apSuRules.filter(r => !only || r.hits > 0);
  $('ap-su').innerHTML = rows.length ? rows.map(r => `<tr>
      <td>${escHtml(r.sid || '?')}</td>
      <td class="msg">${escHtml(r.msg)}${r.action !== 'alert' ? ` <b>[${escHtml(r.action)}]</b>` : ''}</td>
      <td>${r.hits}</td>
      <td>${escHtml((r.last_hit || '—').slice(0, 19))}</td>
      <td>${escHtml(r.top_sources.join(', ') || '—')}</td>
      <td>${r.sid ? `<button class="er-btn-sm" data-ap-sid="${escHtml(r.sid)}">Edit</button>
        <button class="er-btn-sm danger" data-ap-su-del="${escHtml(r.sid)}" title="remove this rule now">✗ Xóa</button>` : ''}</td></tr>`).join('')
    : '<tr><td colspan="6" class="er-empty">No rules match.</td></tr>';
}

function initApplied() {
  $('ap-refresh').onclick = () => loadApplied(false);
  $('ap-cp-load').onclick = () => loadApplied(true);
  $('ap-only-hit').onchange = renderApSu;
  $('ap-su').addEventListener('click', e => {
    const delBtn = e.target.closest('[data-ap-su-del]');
    if (delBtn) { deleteApSu(delBtn); return; }
    const b = e.target.closest('[data-ap-sid]'); if (!b) return;
    showTab('rules');
    (async () => { if (!$('rs-text').value) await rsReload(); rulesShowSid(b.dataset.apSid); })();
  });
  $('ap-cp').addEventListener('click', e => {
    const b = e.target.closest('[data-ap-cp-del]'); if (!b) return;
    deleteApCp(b);
  });
}

async function deleteApSu(btn) {
  const sid = btn.dataset.apSuDel;
  if (!confirm(`Xóa rule Suricata sid ${sid}? Sẽ test cú pháp + backup trước khi áp lại, có thể Rollback nếu cần.`)) return;
  btn.disabled = true; btn.textContent = '⏳';
  const d = await apiPost('/api/rules/suricata/delete', { sid });
  if (!d.ok) { alert('✗ Xóa thất bại:\n' + d.output); btn.disabled = false; btn.textContent = '✗ Xóa'; return; }
  await loadApplied(false);
}

async function deleteApCp(btn) {
  const name = btn.dataset.apCpDel;
  const service = btn.dataset.apCpService;
  if (!confirm(`Xóa rule ctf_proxy "${name}" (service ${service})? Sẽ kiểm tra cú pháp + backup trước khi upload lại, có thể Rollback nếu cần.`)) return;
  btn.disabled = true; btn.textContent = '⏳';
  const d = await apiPost('/api/rules/ctfproxy/delete', { name, service });
  if (!d.ok) { alert('✗ Xóa thất bại:\n' + d.output); btn.disabled = false; btn.textContent = '✗ Xóa'; return; }
  await loadApplied(true);
}
