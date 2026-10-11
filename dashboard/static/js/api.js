/* api.js — small helpers every tab uses. */

const META = { services: [], tulip_port: 3000 };

async function apiGet(url) {
  const r = await fetch(url);
  return r.json();
}

async function apiPost(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  return r.json();
}

/* Run an async action with the button disabled and a status line in `outId`.
   Every long action in the UI goes through this, so a slow host action can't
   be double-submitted. */
async function withBusy(btn, outId, label, fn) {
  const out = outId ? document.getElementById(outId) : null;
  const old = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = label || 'Working...'; }
  if (out) out.textContent = '⏳ ' + (label || 'Working...');
  try {
    return await fn(out);
  } catch (e) {
    if (out) out.textContent = '✗ Request failed: ' + e;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = old; }
  }
}

function showResult(out, d) {
  if (!out) return;
  out.textContent = (d.ok ? '✓ ' : '✗ ') + (d.output || JSON.stringify(d, null, 2));
}

function $(id) { return document.getElementById(id); }
