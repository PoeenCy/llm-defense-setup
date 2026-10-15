/* flagtrace-groups.js — FLAG TRACE list with identical flag-outs shown once.

   An attacker replaying one request reads the same flag over and over; each
   read is its own profile. Grouped, the list shows one row per source,
   service, flag(s) and anchor request, with ×N to open the repeats. Nothing
   is merged on the server: every member keeps its own analysis.

   Loaded after flagtrace.js, whose list functions hand over to these when
   FT.grouped is on. Same escaping rules as flagtrace.js: cells go through
   escHtml with double-quoted attributes only. */

FT.grouped = true;
FT.groups = [];
FT.offset = null;
FT.expanded = new Map();   // group_id → { items, next_offset, error }
try { FT.grouped = localStorage.getItem('ft-grouped') !== '0'; } catch (e) { /* storage unavailable */ }

function ftGroupResult(run) {
  if (!run) return '<span class="ft-dim">not analysed yet</span>';
  const links = run.linked_count
    ? `${run.step_count} steps · ${run.edge_count} links`
    : '<span class="ft-dim">1 step, no earlier step linked</span>';
  const warn = run.warning_count ? ` <span class="ft-chip ft-warn" title="warnings">! ${run.warning_count}</span>` : '';
  return links + warn;
}

async function ftLoadGroups(more) {
  const p = ftFilters();
  p.set('limit', '50');
  if (more && FT.offset != null) p.set('offset', String(FT.offset));
  let d;
  try { d = await apiGet('/api/flagtrace/trace-groups?' + p.toString()); } catch (e) { d = { error: String(e) }; }
  if (d.error) {
    $('ft-list').innerHTML = `<tr><td colspan="7" class="er-empty">${escHtml(d.error)}</td></tr>`;
    $('ft-count').textContent = '—';
    $('ft-more').hidden = true;
    return;
  }
  FT.groups = more ? FT.groups.concat(d.items) : d.items;
  FT.pages = more ? FT.pages + 1 : 1;
  FT.offset = d.next_offset;
  $('ft-count').textContent = `${d.total_groups} flag-outs · ${d.total_profiles} profiles`;
  $('ft-more').hidden = d.next_offset == null;
  // Opened groups stay open across refreshes; their repeats are re-read.
  const live = new Set(FT.groups.map(g => g.group_id));
  for (const id of [...FT.expanded.keys()]) if (!live.has(id)) FT.expanded.delete(id);
  await Promise.all([...FT.expanded.keys()].map(id => ftLoadMembers(id, false, false)));
  ftRenderGroups();
}

async function ftLoadMembers(groupId, more, render = true) {
  const g = FT.groups.find(x => x.group_id === groupId);
  if (!g) return;
  const prev = FT.expanded.get(groupId);
  const p = ftFilters();
  p.set('limit', '100');
  if (more && prev && prev.next_offset != null) p.set('offset', String(prev.next_offset));
  let d;
  try { d = await apiGet(`/api/flagtrace/trace-groups/${g.shown.trace_id}/members?` + p.toString()); } catch (e) { d = { error: String(e) }; }
  FT.expanded.set(groupId, d.error
    ? { items: prev ? prev.items : [], next_offset: null, error: d.error }
    : { items: more && prev ? prev.items.concat(d.items) : d.items, next_offset: d.next_offset });
  if (render) ftRenderGroups();
}

function ftRenderGroups() {
  const body = $('ft-list');
  if (!FT.groups.length) {
    body.innerHTML = `<tr><td colspan="7" class="er-empty">No flag-out profiles yet. Profiles appear once Flag-trace ingest sees a response carrying a flag.</td></tr>`;
    return;
  }
  body.innerHTML = FT.groups.map(g => {
    const it = g.shown, open = FT.expanded.get(g.group_id);
    const ticks = g.tick_min === g.tick_max ? `t${g.tick_min ?? '?'}` : `t${g.tick_min}–t${g.tick_max}`;
    const states = Object.entries(g.states || {});
    const mixed = states.length > 1
      ? ` <span class="ft-dim">${escHtml(states.map(([s, n]) => `${n} ${s.replace('_', ' ')}`).join(' · '))}</span>` : '';
    const differ = g.results.length > 1
      ? ` <span class="ft-chip ft-warn" title="Not every repeat linked the same steps; the row shows the one that linked the most. Open ×${g.count} to compare.">results differ</span>` : '';
    const dup = g.count > 1
      ? ` <button class="ft-chip ft-dup" data-expand="${escHtml(g.group_id)}" title="Same source, service, flag and request seen ${g.count} times (first ${escHtml(ftTime(g.first_ts))}). Click to list them.">${open ? '▾' : '▸'} ×${g.count}</button>` : '';
    const sel = FT.trace && (it.trace_id === FT.trace || (open && open.items.some(m => m.trace_id === FT.trace)));
    let html = `<tr class="ft-row${sel ? ' ft-sel' : ''}" data-trace="${escHtml(it.trace_id)}">
      <td>${ftTime(g.last_ts)}${dup}</td>
      <td>${escHtml(it.source_key)}</td>
      <td>${escHtml(it.service)} · ${escHtml(ticks)}</td>
      <td class="msg">${escHtml(it.method || it.proto || '')} ${escHtml(it.path || '')}</td>
      <td>${it.flag_count}</td>
      <td>${ftStateBadge(it.display_state)}${mixed}</td>
      <td>${ftGroupResult(it.latest_run)}${differ}</td>
    </tr>`;
    if (open) html += ftRenderMembers(g, open);
    return html;
  }).join('');
}

function ftRenderMembers(g, open) {
  const rows = open.items.map(m => `<tr class="ft-row ft-member${m.trace_id === FT.trace ? ' ft-sel' : ''}" data-trace="${escHtml(m.trace_id)}">
      <td>↳ ${ftTime(m.ts_request)}</td><td></td>
      <td>t${escHtml(String(m.tick ?? '?'))}</td><td></td><td></td>
      <td>${ftStateBadge(m.display_state)}</td>
      <td>${ftGroupResult(m.latest_run)}</td>
    </tr>`).join('');
  const tail = open.error
    ? `<tr class="ft-member"><td colspan="7" class="er-empty">${escHtml(open.error)}</td></tr>`
    : open.next_offset != null
      ? `<tr class="ft-member"><td colspan="7"><button class="btn" data-members-more="${escHtml(g.group_id)}">More repeats of this flag-out</button></td></tr>`
      : '';
  return rows + tail;
}

/* Clicks on ×N and "more" are taken before the row's own click opens a profile. */
function ftGroupClick(e) {
  const exp = e.target.closest('[data-expand]');
  if (exp) {
    if (FT.expanded.has(exp.dataset.expand)) {
      FT.expanded.delete(exp.dataset.expand);
      ftRenderGroups();
    } else {
      ftLoadMembers(exp.dataset.expand, false);
    }
    return true;
  }
  const more = e.target.closest('[data-members-more]');
  if (more) {
    ftLoadMembers(more.dataset.membersMore, true);
    return true;
  }
  return false;
}

function ftSetGrouped(on) {
  FT.grouped = on;
  try { localStorage.setItem('ft-grouped', on ? '1' : '0'); } catch (e) { /* storage unavailable */ }
  const head = $('ft-list').closest('table').querySelector('thead th');
  if (head) head.textContent = on ? 'Last seen (UTC)' : 'Request time (UTC)';
  FT.cursor = null;
  FT.offset = null;
  ftLoadList(false);
}

function initFlagtraceGroups() {
  const box = $('ft-group');
  box.checked = FT.grouped;
  box.onchange = () => ftSetGrouped(box.checked);
  const head = $('ft-list').closest('table').querySelector('thead th');
  if (head && FT.grouped) head.textContent = 'Last seen (UTC)';
}
