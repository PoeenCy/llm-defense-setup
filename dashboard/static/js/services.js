/* services.js — SERVICES tab: state of every component + start/stop/restart. */

const OP_LABEL = {
  start: 'Start', stop: 'Stop', restart: 'Restart',
  pause_filter: 'Pause filtering', resume_filter: 'Resume filtering', uninstall: 'Uninstall (emergency)',
};
const OP_CONFIRM = {
  stop: s => `Stop ${s.label}?\n\n${s.note || ''}`,
  restart: s => `Restart ${s.label}?`,
  pause_filter: () => 'Pause ctf_proxy filtering? Every blocking rule turns off; traffic keeps flowing. Your rules are kept.',
  uninstall: () => 'EMERGENCY: take ctf_proxy out of the traffic path and give the port back to the original service?\n\n' +
    'Causes a few seconds of downtime. Use only if ctf_proxy itself is broken (e.g. the service is DOWN because of it).',
};
let svcLoading = false;

async function loadServices() {
  if (svcLoading) return;
  svcLoading = true;
  try {
    const d = await apiGet('/api/services');
    if (!d.ok) { $('sv-body').innerHTML = `<tr><td colspan="4" class="er-empty">✗ ${escHtml(d.output || 'failed')}</td></tr>`; return; }
    let group = '';
    $('sv-body').innerHTML = d.items.map(s => {
      const head = s.group !== group ? `<tr class="svc-group"><td colspan="4">${escHtml((group = s.group).toUpperCase())}</td></tr>` : '';
      const btns = s.protected
        ? '<span class="help" style="padding:0;">protected — use a terminal</span>'
        : s.ops.filter(op => !(op === 'start' && s.state === 'running') && !(op === 'stop' && s.state === 'stopped')
                          && !(op === 'pause_filter' && s.state === 'paused') && !(op === 'resume_filter' && s.state === 'running'))
            .map(op => `<button class="btn ${op === 'stop' || op === 'uninstall' ? 'danger' : ''}" data-svc="${s.id}" data-op="${op}">${OP_LABEL[op] || op}</button>`).join(' ');
      return head + `<tr>
        <td><b>${escHtml(s.label)}</b><br><span style="color:var(--text-dim)">${escHtml(s.note || '')}</span></td>
        <td><span class="state state-${escHtml(s.state)}">${escHtml(s.state.toUpperCase())}</span></td>
        <td class="msg">${escHtml(s.detail || '')}</td>
        <td style="white-space:nowrap;">${btns}</td>
      </tr>`;
    }).join('');
  } finally {
    svcLoading = false;
  }
}

async function fwLoad() {
  const d = await apiGet('/api/firewall');
  if (!d.ok) { $('fw-body').innerHTML = `<tr><td colspan="2" class="er-empty">✗ ${escHtml(d.output || 'failed')}</td></tr>`; return; }
  $('fw-body').innerHTML = (d.blocked && d.blocked.length)
    ? d.blocked.map(ip => `<tr><td>${escHtml(ip)}</td><td><button class="er-btn-sm" data-fw-un="${escHtml(ip)}">Unblock</button></td></tr>`).join('')
    : '<tr><td colspan="2" class="er-empty">Không có IP nào bị chặn.</td></tr>';
}

function fwDo(op, ip) {
  if (!ip) { $('fw-out').textContent = 'Nhập IP trước.'; return; }
  if (op === 'block' && !confirm(`Chặn ${ip} trên firewall vulnbox? Nếu đây là IP checker sẽ MẤT SLA.`)) return;
  withBusy($(op === 'block' ? 'fw-block' : 'fw-unblock'), 'fw-out', `${op} ${ip}...`, async out => {
    const d = await apiPost('/api/firewall/' + op, { ip });
    showResult(out, d);
    showToast(`${op} ${ip}: ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
    await fwLoad();
  });
}

function initServices() {
  $('fw-refresh').onclick = fwLoad;
  $('fw-block').onclick = () => fwDo('block', $('fw-ip').value.trim());
  $('fw-unblock').onclick = () => fwDo('unblock', $('fw-ip').value.trim());
  $('fw-body').addEventListener('click', ev => {
    const b = ev.target.closest('[data-fw-un]'); if (b) fwDo('unblock', b.dataset.fwUn);
  });
  $('sv-refresh').onclick = loadServices;
  $('sv-body').addEventListener('click', ev => {
    const b = ev.target.closest('button[data-op]');
    if (!b) return;
    const op = b.dataset.op;
    const label = b.closest('tr').querySelector('b').textContent;
    const ask = OP_CONFIRM[op];
    if (ask && !confirm(ask({ label, note: b.closest('tr').querySelector('span').textContent }))) return;
    withBusy(b, 'sv-out', `${OP_LABEL[op]}: ${label}...`, async out => {
      const d = await apiPost(`/api/services/${b.dataset.svc}/${op}`);
      showResult(out, d);
      showToast(`${label}: ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
      await loadServices();
    });
  });
  setInterval(() => { if (currentTab === 'services') loadServices(); }, 20000);
}
