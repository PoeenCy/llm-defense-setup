/* flagtrace-chains.js — P2.4b in the profile view: which group this chain
   belongs to, and which of its steps differ from what the checker sends.

   A group is chains with the same shape: same steps, same endpoints, same
   field names, whatever the values were. It says the chains look alike, never
   that they exploit the same bug. A suspicious step is a lead, and how much
   checker traffic it was weighed against is always shown with it.

   Loaded after flagtrace.js, which calls ftRenderChain() when a result is
   rendered. Same escaping rules: escHtml everywhere, double-quoted attributes. */

const FT_VERDICT = {
  same_in_all: ['fixed in every chain', 'the attacker sends this value verbatim, so a script keeps it'],
  differs_each_time: ['new in every chain', 'made up or handed out per run, so a script cannot hard-code it'],
  mixed: ['repeats across chains', 'some chains share a value, others do not'],
  single_chain: ['only this chain', 'no other chain of the group sent this field'],
};
const FT_FINDING = {
  endpoint_unseen: 'endpoint the checker never calls',
  field_unseen: 'field the checker never sends here',
  content_type_unseen: 'content type the checker never sends here',
  length: 'longer than anything the checker sends',
  charset: 'characters the checker never sends',
};

function ftFieldLabel(f) {
  return `#${f.position} ${f.field}`;
}

/* ── suspicious steps ───────────────────────────────────────── */
function ftRenderSuspects(run, pos) {
  const s = run.suspects || {}, body = $('ft-suspects'), sum = $('ft-suspects-summary');
  if (!s.state || s.state === 'not_computed') {
    sum.textContent = 'Not computed for this result. Re-analyse to compare its steps with the checker baseline.';
    body.innerHTML = `<tr><td colspan="4" class="er-empty">—</td></tr>`;
    return;
  }
  const b = s.baseline || {};
  if (s.state === 'no_baseline') {
    sum.innerHTML = `<b>No checker baseline for this service.</b> ${escHtml(s.note || '')} — nothing is called
      normal or abnormal here. The baseline is built from the checker's own requests, so it needs
      <code>game.checker_ips</code> to be right and the checker to have run.`;
    body.innerHTML = `<tr><td colspan="4" class="er-empty">Nothing compared.</td></tr>`;
    return;
  }
  const thin = (b.service_samples || 0) < (s.min_samples || 0);
  sum.innerHTML = `${s.steps_flagged} of ${run.steps.length} step(s) differ · ${s.strong} strong · ${s.weak} weak
    ${s.raw_skipped ? ` · ${s.raw_skipped} raw TCP step(s) not compared (no request line to compare)` : ''}
    <br>Baseline: ${b.endpoints ?? 0} endpoint(s), ${b.service_samples ?? 0} checker value(s)
    ${b.window_end_tick != null ? `up to tick ${escHtml(String(b.window_end_tick))}` : ''}.
    ${thin ? `<span class="ft-warnline">Fewer than ${s.min_samples} samples: findings are weak and prove nothing on their own.</span>` : ''}`;
  if (!s.steps.length) {
    body.innerHTML = `<tr><td colspan="4" class="er-empty">No step differs from the checker baseline.</td></tr>`;
    return;
  }
  body.innerHTML = s.steps.map(st => {
    const step = run.steps.find(x => x.transaction_id === st.transaction_id) || {};
    const m = step.summary || {};
    const findings = st.findings.map(f => `<div>${escHtml(FT_FINDING[f.kind] || f.kind)}
      ${f.field ? `<code>${escHtml(ftLocation(f.field))}</code>` : ''}
      <span class="ft-dim">${escHtml(f.detail || '')}</span>
      ${f.strength === 'weak' ? '<span class="ft-chip ft-warn">weak</span>' : ''}</div>`).join('');
    const samples = st.findings.map(f => (f.baseline || {}).samples).filter(n => n != null);
    return `<tr class="ft-row" data-tx="${escHtml(st.transaction_id)}">
      <td>${pos[st.transaction_id] ?? '?'}</td>
      <td class="msg">${escHtml(m.method || m.proto || '')} ${escHtml(m.path || '')}</td>
      <td>${st.strength === 'strong' ? '<span class="ft-chip ft-flag">strong</span>' : '<span class="ft-chip ft-warn">weak</span>'}
          ${samples.length ? `<span class="ft-dim">vs ${Math.max(...samples)} checker value(s)</span>` : ''}</td>
      <td class="msg">${findings}</td>
    </tr>`;
  }).join('');
  // Mark the same steps in the Timeline, without rebuilding its rows.
  const marked = new Set(s.steps.filter(x => x.strength === 'strong').map(x => x.transaction_id));
  document.querySelectorAll('#ft-steps tr[data-tx]').forEach(tr => {
    if (!marked.has(tr.dataset.tx) || tr.querySelector('.ft-suspect-mark')) return;
    const cell = tr.children[3];
    if (cell) cell.insertAdjacentHTML('beforeend',
      ' <span class="ft-chip ft-flag ft-suspect-mark" title="Differs from what the checker sends; see the table below">differs</span>');
  });
}

/* ── the group this chain belongs to ────────────────────────── */
function ftRenderGroupLine(run) {
  const g = run.grouping || {}, line = $('ft-chain-group');
  const details = $('ft-group-details');
  if (!g.state || g.state === 'not_computed') {
    line.innerHTML = '<span class="ft-dim">Chain group not computed for this result.</span>';
    details.hidden = true;
    return null;
  }
  const now = g.now || {};
  const many = (now.profiles || 0) > 1;
  line.innerHTML = `<b>Chain shape</b> <code>${escHtml(g.description || '')}</code>
    · seen in <b>${now.profiles ?? 1}</b> flag-out(s) from <b>${now.sources ?? 1}</b> source(s)
    <span class="ft-dim">(same steps and field names, whatever the values were — not proof they exploit the same bug)</span>`;
  details.hidden = !many;
  $('ft-group-n').textContent = now.profiles ?? 1;
  return many ? g.group_id : null;
}

async function ftLoadGroupDetail(groupId) {
  const body = $('ft-group-body');
  body.innerHTML = '<div class="ft-dim">Loading...</div>';
  let d;
  try { d = await apiGet('/api/flagtrace/chain-groups/' + groupId); } catch (e) { d = { error: String(e) }; }
  if (d.error) { body.innerHTML = `<div class="er-empty">${escHtml(d.error)}</div>`; return; }
  const sources = d.sources.map(s => `<span class="ft-chip">${escHtml(s.source_key)} ×${s.profiles}</span>`).join(' ');
  const fields = (d.fields || []).map(f => {
    const [label, why] = FT_VERDICT[f.verdict] || [f.verdict, ''];
    const roles = Object.entries(f.roles || {}).map(([r, n]) => `${r} ${n}`).join(' · ');
    return `<tr><td>${escHtml(ftFieldLabel(f))}</td>
      <td>${f.sent_by}/${f.chains}</td>
      <td>${f.distinct}${f.distinct_capped ? '+' : ''}</td>
      <td title="${escHtml(why)}">${escHtml(label)}</td>
      <td class="msg"><code>${escHtml(f.samples.join(' · '))}</code></td>
      <td class="ft-dim">${escHtml(roles)}</td></tr>`;
  }).join('');
  const members = d.members.map(m => `<tr class="ft-row" data-trace="${escHtml(m.trace_id)}">
      <td>${ftTime(m.ts_request)}</td><td>${escHtml(m.source_key)}</td>
      <td>t${escHtml(String(m.tick ?? '?'))}</td>
      <td>${ftStateBadge(m.display_state)}</td>
      <td>${m.suspect ? `<span class="ft-chip ${m.suspect === 'strong' ? 'ft-flag' : 'ft-warn'}">${escHtml(m.suspect)}</span>` : '<span class="ft-dim">—</span>'}</td>
    </tr>`).join('');
  body.innerHTML = `<div class="help">Sources: ${sources}</div>
    <div class="ft-subtitle">How each field varies across ${d.fields_chains} chain(s) of this group — what one chain alone cannot tell</div>
    <div class="er-table-wrap"><table class="er-table">
      <thead><tr><th>Step · field</th><th>Sent by</th><th>Distinct</th><th>Across chains</th><th>Examples</th><th>Role per chain</th></tr></thead>
      <tbody>${fields || '<tr><td colspan="6" class="er-empty">No comparable fields.</td></tr>'}</tbody></table></div>
    <div class="ft-subtitle">Flag-outs in this group — click one to open it</div>
    <div class="er-table-wrap"><table class="er-table">
      <thead><tr><th>Request time (UTC)</th><th>Source</th><th>Tick</th><th>State</th><th>Differs</th></tr></thead>
      <tbody id="ft-group-members">${members}</tbody></table></div>
    ${d.next_offset != null ? `<div class="ft-dim">Showing ${d.members.length} of ${d.profiles}.</div>` : ''}`;
}

function ftRenderChain(run, pos) {
  if (!run) {
    $('ft-chain-group').textContent = '';
    $('ft-suspects-summary').textContent = '';
    $('ft-suspects').innerHTML = '';
    $('ft-group-details').hidden = true;
    return;
  }
  ftRenderSuspects(run, pos || {});
  const groupId = ftRenderGroupLine(run);
  const details = $('ft-group-details');
  if (groupId && details.open) ftLoadGroupDetail(groupId);
  details.dataset.group = groupId || '';
}

function initFlagtraceChains() {
  const details = $('ft-group-details');
  details.addEventListener('toggle', () => {
    if (details.open && details.dataset.group) ftLoadGroupDetail(details.dataset.group);
  });
  $('ft-group-body').addEventListener('click', e => {
    const row = e.target.closest('tr[data-trace]');
    if (row) ftOpen(row.dataset.trace, null, true);
  });
  $('ft-suspects').addEventListener('click', e => {
    const row = e.target.closest('tr[data-tx]');
    if (row) ftShowEvidence([{ tx: row.dataset.tx, label: 'Step that differs from the checker baseline' }]);
  });
}
