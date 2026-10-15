/* flagtrace-tulip.js — the Tulip column of the Timeline.

   Each step of a trace is one captured exchange, so it is also one flow in
   Tulip. This column links to it, for looking at the raw bytes, the tags and
   the neighbouring traffic that Flag-trace deliberately leaves out.

   No flow ID is stored with the result: the match is made here, at display
   time, by the same `/api/tulip/resolve` the Events and Monitor tabs use
   (time window plus IPs/ports, plus the flag text on the anchor). The answer
   says whether it matched exactly, and a match that is only the closest flow
   in time is shown as such rather than as a fact.

   Loaded after flagtrace.js, which calls ftRenderTulip() when a result is
   rendered. Same escaping rules: escHtml everywhere, double-quoted attributes. */

const FT_TULIP = new Map();   // transaction_id → resolve result, per page load
const FT_TULIP_BATCH = 100;   // the resolve endpoint takes at most this many
// Resolving asks Tulip once per step. When Tulip is down each of those waits
// for a connection to time out, so give up rather than leave the column
// spinning: the timeline itself does not depend on Tulip being reachable.
const FT_TULIP_TIMEOUT_MS = 20000;

function ftTulipUrl(id) {
  return `${location.protocol}//${location.hostname}:${META.tulip_port || 3000}/flow/${id}`;
}

function ftTulipIso(us) {
  return (us === null || us === undefined) ? null : new Date(Math.floor(us / 1000)).toISOString();
}

function ftTulipEvent(step) {
  const n = step.network || {}, m = step.summary || {};
  const ts = ftTulipIso(n.ts_request ?? m.ts_request);
  if (!ts || !(n.src_ip || n.dst_ip)) return null;
  const flags = m.flags_found || [];
  const event = { ts_packet: ts, src_ip: n.src_ip, dst_ip: n.dst_ip, src_port: n.src_port, dst_port: n.dst_port };
  // Only the anchor carries a flag; it makes the match much more certain.
  if (m.flag_out && flags.length) event.flag = flags[0];
  return event;
}

function ftTulipCell(result) {
  if (!result) return '<span class="ft-dim">…</span>';
  if (result.unresolvable) return `<span class="ft-dim" title="${escHtml(result.why)}">—</span>`;
  if (!result.flow_id) return `<span class="ft-dim" title="${escHtml(result.why || '')}">none</span>`;
  const label = result.exact ? '✓' : '~';
  const title = `${result.flow_id} — ${result.why || ''}`;
  return `<a class="flowlink ${result.exact ? '' : 'approx'}" target="_blank" rel="noopener"
            href="${escHtml(ftTulipUrl(result.flow_id))}" title="${escHtml(title)}"
            >${label} …${escHtml(result.flow_id.slice(-12))}</a>`;
}

function ftTulipPaint() {
  document.querySelectorAll('#ft-steps tr[data-tx]').forEach(row => {
    const cell = row.querySelector('td.ft-tulip');
    if (cell) cell.innerHTML = ftTulipCell(FT_TULIP.get(row.dataset.tx));
  });
}

async function ftRenderTulip(run) {
  const steps = (run && run.steps) || [];
  const todo = [];
  for (const step of steps) {
    if (FT_TULIP.has(step.transaction_id)) continue;
    const event = ftTulipEvent(step);
    if (!event) {
      FT_TULIP.set(step.transaction_id, {
        unresolvable: true,
        why: 'this step has no address or packet time to search Tulip by',
      });
      continue;
    }
    todo.push({ tx: step.transaction_id, event });
  }
  ftTulipPaint();
  if (!todo.length) return;
  const batch = todo.slice(0, FT_TULIP_BATCH);
  let results;
  const control = new AbortController();
  const giveUp = setTimeout(() => control.abort(), FT_TULIP_TIMEOUT_MS);
  try {
    const response = await fetch('/api/tulip/resolve', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: batch.map(x => x.event) }), signal: control.signal,
    });
    results = await response.json();
  } catch (e) {
    const why = control.signal.aborted
      ? `Tulip did not answer within ${FT_TULIP_TIMEOUT_MS / 1000}s; it may be down or still importing`
      : 'Tulip unavailable: ' + e;
    results = batch.map(() => ({ flow_id: null, why }));
  } finally {
    clearTimeout(giveUp);
  }
  if (!Array.isArray(results)) return;
  const retry = [];
  batch.forEach((x, i) => {
    const r = results[i] || { flow_id: null, why: 'Tulip gave no answer for this step' };
    FT_TULIP.set(x.tx, r);
    // A miss can become a hit once the capture finishes importing, so it is
    // shown but not remembered; the next render asks again.
    if (!r.flow_id) retry.push(x.tx);
  });
  ftTulipPaint();
  retry.forEach(tx => FT_TULIP.delete(tx));
}
