/* flagtrace.js — FLAG TRACE tab: one profile per transaction whose response
   carried a flag, its analysis history, and the evidence behind each link.

   Everything shown here comes from captured traffic, i.e. from attackers.
   Table cells go through escHtml with double-quoted attributes only, and
   payload bytes are put on the page as text nodes, never as HTML. */

const FT = {
  items: [], cursor: null, pages: 0,
  trace: null, detail: null, runs: [], run: null, runId: null,
  pinnedRun: null,   // an older result the user chose; polling must not move off it
  timer: null, active: false, view: [],
  decoder: null,
};
const FT_POLL_MS = 5000;
const FT_HEX = /^[0-9a-f]{64}$/;

/* ── formatting ─────────────────────────────────────────────── */
function ftTime(us) {
  if (us === null || us === undefined) return '—';
  const d = new Date(Math.floor(us / 1000));
  return d.toISOString().replace('T', ' ').slice(0, 23);
}

function ftDelta(us, anchorUs) {
  if (us === null || us === undefined || anchorUs === null || anchorUs === undefined) return '—';
  const s = (us - anchorUs) / 1e6;
  if (s === 0) return '0';
  return (s > 0 ? '+' : '') + (Math.abs(s) < 10 ? s.toFixed(3) : s.toFixed(1)) + 's';
}

const FT_STATES = {
  linked:    ['state-running',  'linked'],
  partial:   ['state-degraded', 'partial'],
  seed_only: ['state-unknown',  'anchor only'],
  pending:   ['state-unknown',  'pending'],
  running:   ['state-degraded', 'running'],
  failed:    ['state-stopped',  'failed'],
};
function ftStateBadge(state) {
  const [cls, label] = FT_STATES[state] || ['state-unknown', state || '—'];
  return `<span class="state ${cls}">${escHtml(label)}</span>`;
}

const FT_ROLES = { anchor: '⚑ anchor', data_linked: '⇄ data-linked' };
function ftRole(role) {
  return `<span class="ft-role ft-role-${escHtml(role)}">${escHtml(FT_ROLES[role] || role)}</span>`;
}

const FT_VALUE_ROLES = { linked: '⇠ linked', generated: '✎ generated', target: '◎ target', unknown: '? unknown' };
function ftValueRole(role) {
  return `<span class="ft-vrole ft-vrole-${escHtml(role)}">${escHtml(FT_VALUE_ROLES[role] || role)}</span>`;
}

function ftLocation(loc) {
  if (!Array.isArray(loc)) return '—';
  const [side, cat, ...rest] = loc;
  if (cat === 'body' && rest.length >= 2 && typeof rest[0] === 'number') return `${side} body @${rest[0]}..${rest[1]}`;
  return `${side} ${cat} ${rest.map(x => typeof x === 'number' ? `#${x}` : x).join(' ')}`;
}

function ftChips(list, cls) {
  return (list || []).map(q => `<span class="ft-chip ${cls || ''}">${escHtml(q)}</span>`).join(' ');
}

/* ── list ───────────────────────────────────────────────────── */
function ftFilters() {
  const p = new URLSearchParams();
  const src = $('ft-source').value.trim(), svc = $('ft-service').value.trim(), st = $('ft-state').value;
  if (src) p.set('source_key', src);
  if (svc) p.set('service', svc);
  if (st) p.set('state', st);
  return p;
}

async function ftLoadList(more) {
  if (FT.grouped) return ftLoadGroups(more);   // flagtrace-groups.js
  const p = ftFilters();
  p.set('limit', '50');
  if (more && FT.cursor) p.set('cursor', FT.cursor);
  let d;
  try { d = await apiGet('/api/flagtrace/traces?' + p.toString()); } catch (e) { d = { error: String(e) }; }
  if (d.error) {
    $('ft-list').innerHTML = `<tr><td colspan="7" class="er-empty">${escHtml(d.error)}</td></tr>`;
    $('ft-count').textContent = '—';
    $('ft-more').hidden = true;
    return;
  }
  FT.items = more ? FT.items.concat(d.items) : d.items;
  FT.pages = more ? FT.pages + 1 : 1;
  FT.cursor = d.next_cursor;
  $('ft-count').textContent = `${d.total} profiles`;
  $('ft-more').hidden = !d.next_cursor;
  ftRenderList();
}

function ftRenderList() {
  const body = $('ft-list');
  if (!FT.items.length) {
    body.innerHTML = `<tr><td colspan="7" class="er-empty">No flag-out profiles yet. Profiles appear once Flag-trace ingest sees a response carrying a flag.</td></tr>`;
    return;
  }
  body.innerHTML = FT.items.map(it => {
    const run = it.latest_run;
    // The flow only: the flag-out plus the steps a value links to it.
    let links;
    if (!run) {
      links = '<span class="ft-dim">not analysed yet</span>';
    } else {
      links = run.linked_count
        ? `${run.step_count} steps · ${run.edge_count} links`
        : '<span class="ft-dim">1 step, no earlier step linked</span>';
    }
    const warn = run && run.warning_count ? ` <span class="ft-chip ft-warn" title="warnings">! ${run.warning_count}</span>` : '';
    return `<tr class="ft-row${it.trace_id === FT.trace ? ' ft-sel' : ''}" data-trace="${escHtml(it.trace_id)}">
      <td>${ftTime(it.ts_request)}</td>
      <td>${escHtml(it.source_key)}</td>
      <td>${escHtml(it.service)} · t${escHtml(String(it.tick ?? '?'))}</td>
      <td class="msg">${escHtml(it.method || it.proto || '')} ${escHtml(it.path || '')}</td>
      <td>${it.flag_count}</td>
      <td>${ftStateBadge(it.display_state)}</td>
      <td>${links}${warn}</td>
    </tr>`;
  }).join('');
}

/* ── worker status ──────────────────────────────────────────── */
async function ftLoadStatus() {
  let d;
  try { d = await apiGet('/api/flagtrace/trace-status'); } catch (e) { d = { error: String(e) }; }
  const el = $('ft-worker');
  if (d.error) {
    el.className = 'state state-unknown';
    el.textContent = 'unavailable';
    el.title = d.error;
    return;
  }
  const cls = { running: 'state-running', degraded: 'state-degraded', no_worker: 'state-stopped', disabled: 'state-disabled' }[d.state] || 'state-unknown';
  el.className = 'state ' + cls;
  const b = d.backlog || {}, j = b.jobs || {};
  el.textContent = `worker ${d.state.replace('_', ' ')}`;
  el.title = `waiting dispatch ${b.pending_dispatch ?? 0} · pending ${j.pending ?? 0} · running ${j.running ?? 0} · failed ${j.failed ?? 0}`;
  $('ft-backlog').textContent = el.title;
}

/* ── ingest decoder mode ────────────────────────────────────── */
const FT_DECODER_HELP = {
  full: 'every body is decoded',
  gated: 'only bodies that look encoded are decoded, as detection does',
  off: 'no decoding: a flag that only shows after decoding is not seen, so that flag-out gets no profile',
};

async function ftLoadDecoder(force) {
  let d;
  try { d = await apiGet('/api/flagtrace/decoder'); } catch (e) { d = { error: String(e) }; }
  FT.decoder = d;
  const sel = $('ft-decoder'), st = $('ft-decoder-state');
  if (d.error || !FT_DECODER_HELP[d.mode]) {
    sel.disabled = true;
    st.className = 'state state-unknown';
    st.textContent = 'decoder unavailable';
    st.title = d.error || '';
    return;
  }
  sel.disabled = false;
  // Polling must not flip the list while someone is choosing in it.
  if (force || document.activeElement !== sel) sel.value = d.mode;
  const set = d.source !== 'config';
  const since = set && d.since ? ' since ' + new Date(d.since * 1000).toLocaleTimeString() : '';
  st.className = 'state ' + { full: 'state-running', gated: 'state-degraded', off: 'state-stopped' }[d.mode];
  st.textContent = 'decoder ' + (d.mode === 'full' ? 'full' : d.mode.toUpperCase()) + since;
  const parts = [FT_DECODER_HELP[d.mode],
    set ? 'set from the dashboard, kept across restarts' : 'from services.json',
    'config default ' + d.default];
  if (d.last_file_mode && d.last_file_mode !== d.mode) parts.push(`last capture read as ${d.last_file_mode}; the new mode applies from the next capture`);
  if (d.searched !== undefined) parts.push(`since ingest start: ${d.searched} searched, ${d.cache_hits} reused, ${d.skipped_gated} skipped (gated), ${d.skipped_off} skipped (off)`);
  st.title = parts.join(' · ');
  $('ft-decoder-reset').hidden = !set;
}

async function ftSetDecoder(mode) {
  const sel = $('ft-decoder');
  if (mode === 'off' && !confirm('Turn the ingest decoder OFF?\n\nFlags that only appear after decoding (base64, gzip, xor...) will not be found in captures read from now on, and those flag-outs get no profile. The setting stays after a restart until you change it back.')) {
    ftLoadDecoder(true);
    return;
  }
  // Not withBusy's button: setting a select's text would remove its options.
  sel.disabled = true;
  await withBusy($('ft-decoder-reset'), 'ft-decoder-out', 'Saving...', async out => {
    const r = await fetch('/api/flagtrace/decoder', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }),
    });
    const d = await r.json();
    out.textContent = r.ok
      ? `✓ decoder ${d.mode}${mode === 'default' ? ' (config default)' : ''}; applies from the next capture`
      : '✗ ' + (d.error || r.status);
  });
  await ftLoadDecoder(true);
}

/* ── one profile ────────────────────────────────────────────── */
async function ftOpen(traceId, runId, push) {
  if (!FT_HEX.test(traceId || '')) return;
  const changed = FT.trace !== traceId;
  FT.trace = traceId;
  if (changed) FT.pinnedRun = null;
  if (runId) FT.pinnedRun = runId;
  if (push) {
    const hash = '#flagtrace/' + traceId + (runId ? '/' + runId : '');
    if (location.hash !== hash) history.pushState(null, '', hash);
  }
  document.querySelectorAll('#ft-list tr.ft-row').forEach(r => r.classList.toggle('ft-sel', r.dataset.trace === traceId));
  $('ft-detail').hidden = false;
  if (changed) {
    $('ft-steps').innerHTML = `<tr><td colspan="8" class="er-empty">Loading...</td></tr>`;
    $('ft-edges').innerHTML = '';
    $('ft-values').innerHTML = '';
    $('ft-values-summary').textContent = '';
    $('ft-scripts').innerHTML = '';
    $('ft-scripts-summary').textContent = '';
    $('ft-script-preview').hidden = true;
    $('ft-evidence').replaceChildren();
    $('ft-retrace-out').textContent = '';
  }
  const [detail, runs] = await Promise.all([
    apiGet(`/api/flagtrace/traces/${traceId}`).catch(e => ({ error: String(e) })),
    apiGet(`/api/flagtrace/traces/${traceId}/runs?limit=50`).catch(e => ({ error: String(e) })),
  ]);
  if (FT.trace !== traceId) return;          // another profile was opened meanwhile
  if (detail.error) {
    $('ft-title').textContent = 'Profile not found';
    $('ft-summary').textContent = detail.error;
    $('ft-steps').innerHTML = '';
    return;
  }
  FT.detail = detail;
  FT.runs = runs.items || [];
  ftRenderHeader();
  const pinned = FT.pinnedRun && FT.runs.some(r => r.run_id === FT.pinnedRun) ? FT.pinnedRun : null;
  const want = pinned || (detail.latest_run ? detail.latest_run.run_id : null);
  if (want && (changed || want !== FT.runId || !FT.run)) await ftLoadRun(want);
  else if (!want) ftRenderNoRun();
}

function ftRenderHeader() {
  const d = FT.detail, a = d.anchor;
  $('ft-title').textContent = `${a.source_key} → ${a.service} · ${a.method || a.proto} ${a.path || ''}`;
  const sel = $('ft-runs');
  sel.innerHTML = FT.runs.length
    ? FT.runs.map(r => `<option value="${escHtml(r.run_id)}">#${r.request_sequence} · ${escHtml((FT_STATES[r.state] || [0, r.state])[1])} · ${escHtml(new Date(r.created * 1000).toISOString().slice(11, 19))}${r.is_latest ? ' (latest)' : ''}</option>`).join('')
    : '<option value="">no result yet</option>';
  if (FT.runId) sel.value = FT.runId;
  $('ft-retrace').disabled = !d.trace_enabled;
  $('ft-retrace').title = d.trace_enabled ? 'Queue a new analysis of the data stored now; earlier results stay in the history.'
    : 'Trace worker is disabled in config (flagtrace.trace.enabled).';
  const newest = d.jobs && d.jobs[0];
  let pending = '';
  if (newest && newest.status !== 'done' && (!d.latest_run || newest.request_sequence > d.latest_run.request_sequence)) {
    pending = ` · request #${newest.request_sequence}: ${ftStateBadge(newest.status)}` +
      (newest.error ? ` <span class="ft-dim">${escHtml(newest.error)}</span>` : '');
  }
  $('ft-head').innerHTML = `
    <div><b>Anchor</b> ${ftTime(a.ts_request)} UTC · tick ${escHtml(String(a.tick ?? '?'))} ·
      ${escHtml(a.method || a.proto)} ${escHtml(a.path || '')} → ${escHtml(String(a.status ?? '—'))} ·
      source <b>${escHtml(a.source_key)}</b>${a.team_id ? ` (team ${escHtml(a.team_id)})` : ''}${pending}</div>
    <div><b>Flags in response</b> ${ftChips(a.flags_found, 'ft-flag')} ${a.quality.length ? ' · <b>capture quality</b> ' + ftChips(a.quality, 'ft-warn') : ''}</div>`;
}

function ftRenderNoRun() {
  FT.run = null; FT.runId = null;
  $('ft-summary').innerHTML = `<b>No analysis result yet.</b> The profile exists; linking has not run. ` +
    `Waiting, running and failed requests are shown above.`;
  $('ft-steps').innerHTML = `<tr><td colspan="8" class="er-empty">Only the anchor is known so far.</td></tr>`;
  ftRenderChain(null);
  $('ft-edges').innerHTML = '';
  $('ft-values').innerHTML = '';
  $('ft-values-summary').textContent = '';
  $('ft-scripts').innerHTML = '';
  $('ft-scripts-summary').textContent = '';
  $('ft-script-preview').hidden = true;
  $('ft-coverage').replaceChildren();
  ftShowEvidence([{ tx: FT.detail.anchor.transaction_id, label: 'Anchor' }]);
}

async function ftLoadRun(runId) {
  const traceId = FT.trace;
  const run = await apiGet(`/api/flagtrace/traces/${traceId}/runs/${runId}`).catch(e => ({ error: String(e) }));
  if (FT.trace !== traceId) return;
  if (run.error) { $('ft-summary').textContent = run.error; return; }
  FT.run = run; FT.runId = runId;
  $('ft-runs').value = runId;
  ftRenderRun();
}

function ftRenderRun() {
  const run = FT.run, a = run.anchor || {};
  const anchorTs = a.ts_request;
  // Numbered as shown. Results from older engines also stored nearby
  // "context" steps; the API leaves those out, so stored positions have gaps.
  const pos = Object.fromEntries(run.steps.map((s, i) => [s.transaction_id, i + 1]));
  const note = {
    linked: 'Linking ran to completion on the data stored at the time. That is not proof the exploit was found or reproduced.',
    partial: 'Linking stopped at a limit; links beyond it were not searched. See coverage below.',
    seed_only: 'Only the anchor was stored; value linking was not computed for this result.',
  }[run.state] || '';
  const chain = ((run.scripts || {}).artifacts || []).find(a => a.kind === 'chain');
  const chainCopy = run.state === 'linked' && chain
    ? `<button class="btn ft-chain-copy" data-artifact="${escHtml(chain.artifact_id)}"
         title="Copy the generated whole-chain Python script; this does not send traffic">Copy chain</button>
       ${chain.support === 'supported' ? '' : ftScriptBadge(chain.support)}`
    : '';
  $('ft-summary').innerHTML = `<span class="ft-result-actions">${ftStateBadge(run.state)}${chainCopy}</span> result #${run.request_sequence}
    (${escHtml(run.trigger_key || '')}) · engine ${escHtml(run.engine_version)} ·
    snapshot ${escHtml(new Date(run.snapshot_wall * 1000).toISOString().replace('T', ' ').slice(0, 19))} UTC ·
    ${run.duration_ms ?? '?'} ms${run.is_latest ? '' : ' · <b>older result</b>'}<br>${escHtml(note)}
    ${run.warnings.map(w => `<div class="ft-warnline">! ${escHtml(w)}</div>`).join('')}`;

  const requestArtifacts = new Map((((run.scripts || {}).artifacts) || [])
    .filter(a => a.kind === 'request' && a.transaction_id)
    .map(a => [a.transaction_id, a]));
  $('ft-steps').innerHTML = run.steps.map(s => {
    const m = s.summary || {};
    const artifact = requestArtifacts.get(s.transaction_id);
    return `<tr class="ft-row" data-tx="${escHtml(s.transaction_id)}">
      <td>${pos[s.transaction_id]}</td>
      <td>${ftDelta(m.ts_request, anchorTs)}</td>
      <td>${ftRole(s.role)}</td>
      <td class="msg">${escHtml(m.method || m.proto || '')} ${escHtml(m.path || '')} → ${escHtml(String(m.status ?? '—'))}${m.flag_out ? ' <span class="ft-chip ft-flag">flag</span>' : ''}${ftChips(s.quality, 'ft-warn')}</td>
      <td title="${escHtml(m.conn_id || '')}">${escHtml((m.conn_id || '').slice(0, 8))}:${escHtml(String(m.seq_in_conn ?? ''))}</td>
      <td>${ftChips(s.reasons)}</td>
      <td class="ft-tulip"><span class="ft-dim">…</span></td>
      <td>${artifact ? `<button class="btn ft-step-copy" data-artifact="${escHtml(artifact.artifact_id)}"
        title="Copy Python for request #${pos[s.transaction_id]}; this does not send traffic">Copy</button>` : '<span class="ft-dim">—</span>'}</td>
    </tr>`;
  }).join('') + (run.steps_truncated ? `<tr><td colspan="8" class="er-empty">More steps exist than are shown.</td></tr>` : '');

  $('ft-edges').innerHTML = run.edges.length ? run.edges.map((e, i) => `<tr class="ft-row" data-edge="${i}">
      <td>#${pos[e.src_transaction_id] ?? '?'} <span class="ft-dim">${escHtml(ftLocation(e.src_location))}</span></td>
      <td>#${pos[e.dst_transaction_id] ?? '?'} <span class="ft-dim">${escHtml(ftLocation(e.dst_location))}</span></td>
      <td>${e.kind === 'response_to_request' ? 'response → request' : 'reused from request'}</td>
      <td class="msg"><code>${escHtml(e.value_preview)}</code>${e.value_length > 64 ? ` <span class="ft-dim">(${e.value_length} chars)</span>` : ''}</td>
      <td>${e.ambiguous ? '<span class="ft-chip ft-warn">ambiguous</span> ' : ''}${e.alternatives.length ? `<span class="ft-dim">${e.alternatives.length} other source(s)</span>` : ''}</td>
      <td class="msg ft-dim">${escHtml(e.note || '')}</td>
    </tr>`).join('')
    : `<tr><td colspan="6" class="er-empty">${run.state === 'seed_only' ? 'Linking not computed for this result.' : 'No value links found in scope.'}</td></tr>`;

  ftRenderValues(run, pos);
  ftRenderScripts(run);
  ftRenderCoverage(run);
  ftRenderChain(run, pos);   // flagtrace-chains.js: group and suspicious steps
  ftRenderTulip(run);        // flagtrace-tulip.js: link each step to its Tulip flow
  // Keep the evidence pane on a step of this run if it still is one.
  if (!FT.view.length || !FT.view.every(v => pos[v.tx])) ftShowEvidence([{ tx: a.transaction_id, label: 'Anchor' }]);
}

/* Why a value has its role, in one line. Positions are the timeline's. */
function ftValueWhy(role, ev, pos) {
  ev = ev || {};
  const at = x => x ? `#${pos[x.transaction_id] ?? '?'} ${ftLocation(x.location)}` : '?';
  if (role === 'linked') return `response of ${at(ev.from)}` + (ev.also_matches_flag_id ? ' · also a flag ID' : '');
  if (role === 'generated') return ev.first_sent ? `first sent here, reused ${(ev.reused_by || []).length}×` : `first sent in ${at(ev.first_sent_in)}`;
  if (role === 'target') {
    const ticks = [...new Set((ev.flag_ids || []).map(f => f.tick))].join(', ');
    return `flag ID (${ev.basis || '?'}${ticks !== '' ? `, tick ${ticks}` : ''}${ev.short ? ', short' : ''})`;
  }
  if (role === 'unknown') return `no source: ${ev.reason || '?'}`;
  return '';
}

function ftRenderValues(run, pos) {
  const vr = run.value_roles || {}, body = $('ft-values'), sum = $('ft-values-summary');
  if (!vr.state || vr.state === 'not_computed') {
    sum.textContent = 'Value roles were not computed for this result (it predates them). Re-analyse to compute them.';
    body.innerHTML = '';
    return;
  }
  const f = vr.flag_ids || {}, c = vr.counts || {};
  const counts = ['target', 'linked', 'generated', 'unknown', 'constant'].map(r => `${escHtml(r)} ${c[r] ?? 0}`).join(' · ');
  const skipped = (vr.steps_not_classified || []).map(s => `#${pos[s.transaction_id] ?? '?'} (${s.reason || '?'}${s.partly ? ', partly' : ''})`);
  sum.innerHTML = `${vr.state === 'partial' ? ftStateBadge('partial') + ' ' : ''}${counts}<br>
    Flag IDs: <b>${escHtml(f.status || '?')}</b> · service ${escHtml(f.service || '?')} · owner ${escHtml(f.owner_team_id || 'any team')}
    · ${f.records_in_scope ?? 0} record(s) in scope ${escHtml(JSON.stringify(f.sources || {}))}
    · validity ${f.validity_ticks ? escHtml(String(f.validity_ticks)) + ' tick(s)' : 'not configured'}
    ${(f.leaked_flag_puts || []).length ? ` · leaked flag stored at tick ${escHtml(f.leaked_flag_puts.map(p => p.tick).join(', '))}` : ''}
    ${(f.notes || []).map(n => `<div class="ft-warnline">! ${escHtml(n)}</div>`).join('')}
    ${(f.refused || []).map(r => `<div class="ft-warnline">! <code>${escHtml(r.value_preview)}</code> is a flag ID but was refused: ${escHtml(r.reasons.join(', '))}</div>`).join('')}
    ${skipped.length ? `<div class="ft-warnline">! steps not (fully) classified: ${escHtml(skipped.join(', '))}</div>` : ''}`;
  const values = vr.values || [];
  body.innerHTML = values.length ? values.map((v, i) => {
    let what = v.var ? `<code>${escHtml(v.var)}</code>` : '';
    if (v.template) what = `<code>${escHtml(v.template)}</code>${v.transform.length ? ` <span class="ft-dim">then ${escHtml(v.transform.join(', '))}</span>` : ''}`;
    if (v.unresolved) what += ` <span class="ft-chip ft-warn">${escHtml(v.unresolved)}</span>`;
    const why = v.parts.length
      ? v.parts.map(p => `${escHtml(p.var)}: ${escHtml(ftValueWhy(p.role, p.evidence, pos))}`).join('<br>')
      : escHtml(ftValueWhy(v.role, v.evidence, pos));
    return `<tr class="ft-row" data-value="${i}">
      <td>#${pos[v.transaction_id] ?? '?'}</td>
      <td class="ft-dim">${escHtml(ftLocation(v.location))}</td>
      <td>${ftValueRole(v.role)}${v.session_cookie ? ' <span class="ft-chip">session</span>' : ''}${v.ambiguous ? ' <span class="ft-chip ft-warn">ambiguous</span>' : ''}</td>
      <td class="msg">${what}</td>
      <td class="msg"><code>${escHtml(v.value_preview)}</code>${v.value_length > 64 ? ` <span class="ft-dim">(${v.value_length} chars)</span>` : ''}</td>
      <td class="msg ft-dim">${why}</td>
    </tr>`;
  }).join('') + (vr.values_listed_truncated || vr.values_truncated ? `<tr><td colspan="6" class="er-empty">More values exist than are shown.</td></tr>` : '')
    : `<tr><td colspan="6" class="er-empty">Every value is a constant: a replay would send this chain verbatim.</td></tr>`;
}

function ftScriptBadge(value) {
  const cls = value === 'supported' || value === 'reproduced' ? '' : 'ft-warn';
  return `<span class="ft-chip ${cls}">${escHtml(value || '—')}</span>`;
}

function ftRenderScripts(run) {
  const scripts = run.scripts || {}, body = $('ft-scripts'), sum = $('ft-scripts-summary');
  $('ft-script-preview').hidden = true;
  if (!scripts.state || scripts.state === 'not_computed') {
    sum.textContent = 'Scripts were not computed for this result. Re-analyse to create immutable artifacts with the current exporter.';
    body.innerHTML = '';
    return;
  }
  sum.innerHTML = `Exporter <code>${escHtml(scripts.exporter_version)}</code> · overall ${ftScriptBadge(scripts.support)} · ` +
    `<b>supported does not mean reproduced</b>. Copying never sends traffic.`;
  body.innerHTML = (scripts.artifacts || []).map((a, i) => {
    const label = a.kind === 'chain' ? 'Whole HTTP chain' : `Request #${a.position}`;
    const verification = (a.verification || {}).status || 'not_run';
    return `<tr class="ft-row" data-script="${i}"><td>${escHtml(label)}<br><span class="ft-dim">${escHtml(a.filename)} · ${a.size} bytes</span></td>
      <td>${ftScriptBadge(a.support)}</td><td>${ftScriptBadge(verification)}</td>
      <td class="msg ft-dim">${escHtml((a.warnings || []).join(' · ') || 'none')}</td>
      <td><button class="btn ft-script-copy" data-artifact="${escHtml(a.artifact_id)}">Copy</button>
          <button class="btn ft-script-download" data-artifact="${escHtml(a.artifact_id)}">Download</button></td></tr>`;
  }).join('') || '<tr><td colspan="5" class="er-empty">No artifacts were stored.</td></tr>';
}

async function ftFetchScript(artifactId) {
  if (!FT.trace || !FT.runId || !FT_HEX.test(artifactId || '')) throw new Error('invalid artifact');
  const d = await apiGet(`/api/flagtrace/traces/${FT.trace}/runs/${FT.runId}/scripts/${artifactId}`);
  if (d.error) throw new Error(d.error);
  return d;
}

async function ftCopyText(content) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(content);
      return;
    } catch (_) { /* HTTP/local browser policies may deny the modern API. */ }
  }
  const area = document.createElement('textarea');
  area.value = content; area.style.position = 'fixed'; area.style.opacity = '0';
  document.body.append(area); area.select();
  const copied = document.execCommand('copy');
  area.remove();
  if (!copied) throw new Error('clipboard unavailable');
}

async function ftScriptAction(button, download, showPreview = true) {
  const old = button.textContent;
  const help = button.dataset.help || button.title;
  button.dataset.help = help;
  button.disabled = true; button.textContent = 'Loading…';
  try {
    const artifact = await ftFetchScript(button.dataset.artifact);
    if (showPreview) {
      const preview = $('ft-script-preview');
      preview.textContent = artifact.content;
      preview.hidden = false;
    }
    if (download) {
      const url = URL.createObjectURL(new Blob([artifact.content], { type: 'text/x-python;charset=utf-8' }));
      const a = document.createElement('a'); a.href = url; a.download = artifact.filename; a.click();
      URL.revokeObjectURL(url);
    } else {
      await ftCopyText(artifact.content);
    }
    button.title = help;
    button.textContent = download ? 'Downloaded' : 'Copied';
  } catch (e) {
    button.textContent = 'Failed'; button.title = String(e);
  } finally {
    setTimeout(() => { button.disabled = false; button.textContent = old; }, 1200);
  }
}

function ftRenderCoverage(run) {
  const c = run.coverage || {}, box = $('ft-coverage');
  const counters = c.counters || {}, gaps = c.ingest_gaps || {};
  const lines = [
    `Scope: ${JSON.stringify(c.scope || {})}`,
    `Window: ${ftTime(c.window_start_us)} → ${ftTime(c.window_end_us)} UTC (never after the anchor request)`,
    `Limits hit while linking: ${(c.limits_hit || []).join(', ') || 'none'}`,
    `Rows read ${counters.rows_read ?? '?'} / ${counters.row_budget ?? '?'} · tokens considered ${counters.tokens_considered ?? '?'} · candidates ${counters.candidates_examined ?? '?'}`,
    `Skipped as noise: ${JSON.stringify(counters.tokens_skipped || {})}`,
    `Capture gaps in this game: rejected ${gaps.rejected_files ?? 0} · failed ${gaps.error_files ?? 0} · late ${gaps.late_files ?? 0}`,
  ];
  const pre = document.createElement('pre');
  pre.className = 'out';
  pre.textContent = lines.join('\n');
  const table = document.createElement('table');
  table.className = 'er-table';
  table.innerHTML = `<thead><tr><th>Value</th><th>Where</th><th>Why no source</th></tr></thead><tbody>${
    (c.unexplained || []).map(u => `<tr><td class="msg"><code>${escHtml(u.value_preview)}</code></td>
      <td>${escHtml(ftLocation(u.location))}</td><td>${escHtml(u.reason)}</td></tr>`).join('')
    || '<tr><td colspan="3" class="er-empty">Every considered value was explained.</td></tr>'}</tbody>`;
  box.replaceChildren(pre, table);
  $('ft-unexplained-n').textContent = String((c.unexplained || []).length);
}

/* ── evidence ───────────────────────────────────────────────── */
function ftBytes(b64) {
  const bin = atob(b64 || '');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function ftText(bytes) {
  return new TextDecoder('utf-8').decode(bytes).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '·');
}

/* Payload as text nodes, with byte ranges wrapped in <mark>. Ranges are
   offsets into this representation only; they are never applied to another
   one (decoded offsets do not map onto raw wire bytes). */
function ftPayload(bytes, ranges) {
  const pre = document.createElement('pre');
  pre.className = 'flowview ft-payload';
  let at = 0;
  ranges.filter(r => r.start < bytes.length).sort((x, y) => x.start - y.start).forEach(r => {
    const start = Math.max(r.start, at), end = Math.min(r.end, bytes.length);
    if (end <= start) return;
    if (start > at) pre.append(document.createTextNode(ftText(bytes.subarray(at, start))));
    const mark = document.createElement('mark');
    mark.className = r.cls;
    mark.title = r.title;
    mark.textContent = ftText(bytes.subarray(start, end));
    pre.append(mark);
    at = end;
  });
  if (at < bytes.length) pre.append(document.createTextNode(ftText(bytes.subarray(at))));
  return pre;
}

async function ftShowEvidence(view) {
  FT.view = view;
  const box = $('ft-evidence');
  box.replaceChildren();
  const run = FT.runId ? `?run_id=${FT.runId}` : '';
  const results = await Promise.all(view.map(v =>
    apiGet(`/api/flagtrace/transactions/${v.tx}/evidence${run}`).catch(e => ({ error: String(e) }))));
  if (FT.view !== view) return;
  document.querySelectorAll('#ft-steps tr.ft-row').forEach(r =>
    r.classList.toggle('ft-sel', view.some(v => v.tx === r.dataset.tx)));
  results.forEach((ev, i) => box.append(ftEvidenceCard(view[i], ev)));
}

function ftEvidenceCard(v, ev) {
  const card = document.createElement('div');
  card.className = 'ft-card';
  if (ev.error) {
    card.textContent = `${v.label}: ${ev.error}`;
    return card;
  }
  const t = ev.transaction;
  const head = document.createElement('div');
  head.className = 'ft-card-head';
  head.innerHTML = `<b>${escHtml(v.label)}</b> ${escHtml(t.method || t.proto || '')} ${escHtml(t.path || '')} → ${escHtml(String(t.status ?? '—'))}
    · ${ftTime(t.ts_request)} UTC · ${escHtml(t.src_ip)}:${t.src_port} → ${escHtml(t.dst_ip)}:${t.dst_port}
    ${ev.flags_found.length ? '<br>flags ' + ftChips(ev.flags_found, 'ft-flag') : ''}
    ${ev.quality.length ? '<br>quality ' + ftChips(ev.quality, 'ft-warn') : ''}
    ${ev.response.available ? '' : '<br><span class="ft-chip ft-warn">no response captured</span>'}`;
  card.append(head);

  // Every typed value of this transaction; the edge's token is highlighted.
  const fields = document.createElement('table');
  fields.className = 'er-table';
  fields.innerHTML = `<thead><tr><th>Field (typed location)</th><th>Value</th></tr></thead><tbody>${
    ev.tokens.filter(k => !k.parent_id || k.id === v.token).map(k => `<tr class="${k.id === v.token ? 'ft-hl-row' : ''}">
      <td>${escHtml(ftLocation(k.location))}</td><td class="msg"><code>${escHtml(k.value)}</code></td></tr>`).join('')
    || '<tr><td colspan="2" class="er-empty">No values extracted.</td></tr>'}</tbody>`;
  const fieldsBox = document.createElement('details');
  fieldsBox.open = !!v.token;
  fieldsBox.innerHTML = `<summary>Values (${ev.tokens_total}${ev.tokens_truncated ? ', first ' + ev.tokens.length + ' shown' : ''})</summary>`;
  fieldsBox.append(fields);
  card.append(fieldsBox);

  const token = ev.tokens.find(k => k.id === v.token);
  ev.representations.forEach(rep => {
    const ranges = [];
    if (token && token.representation_id === rep.id && Array.isArray(token.span)) {
      ranges.push({ start: token.span[0], end: token.span[1], cls: 'ft-mark-token', title: 'linked value' });
    }
    ev.sightings.filter(s => s.representation_id === rep.id)
      .forEach(s => ranges.push({ start: s.start, end: s.end, cls: 'ft-mark-flag', title: 'flag' }));
    const box = document.createElement('details');
    // Header/cookie/path values have no byte span: say which bytes hold the
    // value instead of pretending to mark a position in them.
    const holdsToken = !!(token && token.representation_id === rep.id);
    box.open = ranges.length > 0 || holdsToken || (rep.kind === 'raw' && rep.side === 'req') ||
      (rep.kind === 'body' && rep.side === 'resp' && !v.token);
    const cut = [];
    if (rep.storage_truncated) cut.push(`stored ${rep.stored_size} of ${rep.original_size} bytes`);
    if (rep.api_truncated) cut.push('display limit reached');
    const summary = document.createElement('summary');
    summary.textContent = `${rep.side === 'req' ? 'Request' : 'Response'} · ${rep.kind}` +
      (rep.transform.length ? ` (${rep.transform.join(' → ')})` : '') + ` · ${rep.original_size} bytes` +
      (cut.length ? ` · ${cut.join(', ')}` : '') +
      (ranges.length ? ' · highlighted' : holdsToken ? ' · holds the linked value (see Values)' : '');
    box.append(summary, ftPayload(ftBytes(rep.data_base64), ranges));
    card.append(box);
  });
  return card;
}

/* ── actions ────────────────────────────────────────────────── */
async function ftRetrace(btn) {
  if (!FT.trace) return;
  // One key per click: a resent request returns the same job instead of a new one.
  const key = 'ui-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  await withBusy(btn, 'ft-retrace-out', 'Queueing...', async out => {
    const r = await fetch(`/api/flagtrace/traces/${FT.trace}/retrace`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idempotency_key: key }),
    });
    const d = await r.json();
    out.textContent = r.ok
      ? `✓ Request #${d.request_sequence} queued. The current result stays visible until the new one is committed.`
      : '✗ ' + (d.error || r.status);
    FT.pinnedRun = null;
    await ftOpen(FT.trace, null, false);
  });
}

/* ── routing and polling ────────────────────────────────────── */
function ftRoute(sub) {
  const [trace, run] = (sub || '').split('/');
  if (!FT_HEX.test(trace || '')) return;
  const pinned = FT_HEX.test(run || '') ? run : null;
  // The address decides: a link without a run ID means the latest result,
  // also when going back from an older one.
  if (trace === FT.trace) FT.pinnedRun = pinned;
  ftOpen(trace, pinned, false);
}

function ftTick() {
  if (!FT.active || document.visibilityState !== 'visible' || !$('ft-auto').checked) return;
  ftLoadStatus();
  ftLoadDecoder();
  if (FT.pages <= 1) ftLoadList(false);
  const d = FT.detail;
  const busy = d && d.jobs && d.jobs[0] && ['pending', 'running'].includes(d.jobs[0].status);
  if (FT.trace && busy) ftOpen(FT.trace, null, false);
}

function ftShow(sub) {
  FT.active = true;
  if (!FT.timer) FT.timer = setInterval(ftTick, FT_POLL_MS);
  ftLoadStatus();
  ftLoadDecoder();
  ftLoadList(false);
  ftRoute(sub);
}

function ftHide() {
  FT.active = false;
  clearInterval(FT.timer);
  FT.timer = null;
}

function initFlagtrace() {
  initFlagtraceGroups();
  initFlagtraceChains();
  $('ft-search').onclick = () => ftLoadList(false);
  $('ft-more').onclick = () => ftLoadList(true);
  $('ft-retrace').onclick = e => ftRetrace(e.currentTarget);
  $('ft-decoder').onchange = e => ftSetDecoder(e.target.value);
  $('ft-decoder-reset').onclick = () => ftSetDecoder('default');
  $('ft-runs').onchange = e => {
    if (!e.target.value) return;
    const latest = FT.detail && FT.detail.latest_run && FT.detail.latest_run.run_id === e.target.value;
    FT.pinnedRun = latest ? null : e.target.value;
    history.pushState(null, '', `#flagtrace/${FT.trace}` + (latest ? '' : `/${e.target.value}`));
    ftLoadRun(e.target.value);
  };
  ['ft-source', 'ft-service'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key === 'Enter') ftLoadList(false); }));
  $('ft-state').onchange = () => ftLoadList(false);
  $('ft-list').onclick = e => {
    if (ftGroupClick(e)) return;
    const row = e.target.closest('tr[data-trace]');
    if (row) ftOpen(row.dataset.trace, null, true);
  };
  $('ft-steps').onclick = e => {
    const copy = e.target.closest('.ft-step-copy');
    if (copy) {
      e.stopPropagation();
      ftScriptAction(copy, false, false);
      return;
    }
    const row = e.target.closest('tr[data-tx]');
    if (row) ftShowEvidence([{ tx: row.dataset.tx, label: 'Step' }]);
  };
  $('ft-edges').onclick = e => {
    const row = e.target.closest('tr[data-edge]');
    if (!row || !FT.run) return;
    const edge = FT.run.edges[+row.dataset.edge];
    document.querySelectorAll('#ft-edges tr.ft-row').forEach(r => r.classList.toggle('ft-sel', r === row));
    ftShowEvidence([
      { tx: edge.src_transaction_id, token: edge.src_token_id,
        label: edge.kind === 'response_to_request' ? 'Source (response carried it)' : 'Source (first request using it)' },
      { tx: edge.dst_transaction_id, token: edge.dst_token_id, label: 'Destination (request used it)' },
    ]);
  };
  $('ft-values').onclick = e => {
    const row = e.target.closest('tr[data-value]');
    if (!row || !FT.run) return;
    const v = (FT.run.value_roles.values || [])[+row.dataset.value], ev = v.evidence || {};
    document.querySelectorAll('#ft-values tr.ft-row').forEach(r => r.classList.toggle('ft-sel', r === row));
    const view = [{ tx: v.transaction_id, token: v.token_id, label: `Value (${v.role})` }];
    if (v.role === 'linked' && ev.from) view.unshift({ tx: ev.from.transaction_id, label: 'Source (response carried it)' });
    if (v.role === 'generated' && ev.first_sent_in) view.unshift({ tx: ev.first_sent_in.transaction_id, label: 'First sent here' });
    ftShowEvidence(view);
  };
  $('ft-summary').onclick = e => {
    const copy = e.target.closest('.ft-chain-copy');
    if (copy) ftScriptAction(copy, false, false);
  };
  $('ft-scripts').onclick = e => {
    const copy = e.target.closest('.ft-script-copy');
    const download = e.target.closest('.ft-script-download');
    if (copy) ftScriptAction(copy, false);
    if (download) ftScriptAction(download, true);
  };
  document.addEventListener('visibilitychange', ftTick);
}
