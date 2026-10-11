/* config.js — CONFIG tab: edit services.json with validation, backup, re-deploy. */

const QUICK_FIELDS = [
  ['team_id', 'Team id'],
  ['vulnbox.ip', 'Vulnbox IP'],
  ['vulnbox.capture_ssh_alias', 'Capture SSH alias'],
  ['services.0.name', 'Service name'],
  ['services.0.port', 'Service public port', 'int'],
  ['flag.regex', 'Flag regex'],
  ['flag.submit_url', 'Flag submit URL'],
  ['monitor_host.bind_ip', 'Dashboard bind IP'],
  ['ctf_proxy.insertion.mode', 'ctf_proxy mode', ['disabled', 'docker-compose']],
  ['ctf_proxy.insertion.remote_ssh_alias', 'ctf_proxy SSH alias'],
  ['ctf_proxy.insertion.remote_compose_file', 'Target compose file'],
  ['ctf_proxy.insertion.remote_compose_service', 'Target compose service'],
  ['ctf_proxy.insertion.remote_network_name', 'Target docker network'],
  ['retention.pcap_keep_minutes', 'Keep pcaps (minutes)', 'int'],
  ['retention.pcap_max_gb', 'Max pcap storage (GB)', 'int'],
  ['retention.min_free_gb', 'Always keep free (GB)', 'int'],
];

function getPath(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function setPath(obj, path, val) {
  const keys = path.split('.');
  let o = obj;
  keys.slice(0, -1).forEach(k => { if (o[k] == null) o[k] = {}; o = o[k]; });
  o[keys[keys.length - 1]] = val;
}

function renderQuick() {
  let cfg;
  try { cfg = JSON.parse($('cg-text').value); }
  catch (e) { $('qc-form').innerHTML = `<span class="help" style="grid-column:1/3;">JSON on the right is invalid (${escHtml(e.message)}) — fix it there first.</span>`; return; }
  $('qc-form').innerHTML = QUICK_FIELDS.map(([path, label, kind]) => {
    const v = getPath(cfg, path);
    const input = Array.isArray(kind)
      ? `<select class="sel" data-path="${path}">${kind.map(k => `<option ${k === v ? 'selected' : ''}>${k}</option>`).join('')}</select>`
      : `<input class="inp" data-path="${path}" data-kind="${kind || ''}" value="${escHtml(v == null ? '' : String(v))}">`;
    return `<label title="${path}">${escHtml(label)}</label>${input}`;
  }).join('');
}

function quickChanged(ev) {
  const el = ev.target;
  if (!el.dataset.path) return;
  let cfg;
  try { cfg = JSON.parse($('cg-text').value); } catch (e) { return; }
  let val = el.value;
  if (el.dataset.kind === 'int') { val = parseInt(val, 10); if (Number.isNaN(val)) return; }
  setPath(cfg, el.dataset.path, val);
  $('cg-text').value = JSON.stringify(cfg, null, 2) + '\n';
  $('cg-out').textContent = 'Edited (not saved). Validate, then "Save & apply".';
}

async function loadConfigText() {
  const d = await apiGet('/api/config');
  $('cg-text').value = d.text || '';
  renderQuick();
}

function initConfig() {
  $('qc-form').addEventListener('change', quickChanged);
  $('cg-text').addEventListener('change', renderQuick);
  $('cg-reload').onclick = () => { loadConfigText(); $('cg-out').textContent = 'Reloaded from disk.'; };
  $('cg-validate').onclick = e => withBusy(e.target, 'cg-out', 'Validating...', async out => {
    showResult(out, await apiPost('/api/config/validate', { text: $('cg-text').value }));
  });
  $('cg-save').onclick = e => withBusy(e.target, 'cg-out', 'Validating & saving...', async out => {
    showResult(out, await apiPost('/api/config', { text: $('cg-text').value, restart: false }));
  });
  $('cg-apply').onclick = e => {
    if (!confirm('Save services.json and re-deploy? Containers whose settings changed restart; the page may disconnect for 1-2 minutes.')) return;
    withBusy(e.target, 'cg-out', 'Validating, saving, starting re-deploy...', async out => {
      showResult(out, await apiPost('/api/config', { text: $('cg-text').value, restart: true }));
    });
  };
  $('cg-rollback').onclick = e => {
    if (!confirm('Restore the previous services.json? (not re-deployed until you press Save & apply)')) return;
    withBusy(e.target, 'cg-out', 'Rolling back...', async out => {
      const d = await apiPost('/api/config/rollback');
      showResult(out, d);
      if (d.text) { $('cg-text').value = d.text; renderQuick(); }
    });
  };
  $('cg-log').onclick = e => withBusy(e.target, 'cg-out', 'Fetching log...', async out => {
    const d = await apiGet('/api/config/redeploy-log');
    out.textContent = (d.done ? '✓ Re-deploy finished.\n\n' : '') + (d.output || '');
  });
}
