/* rules.js — RULES tab: flow → selection → rule builders → test on traffic → apply. */

const HTTP_REQ_BUFFERS = ['http.uri', 'http.request_body', 'http.header', 'http.cookie', 'http.user_agent',
                          'http.method', 'http.host', 'http.uri.raw', 'http.request_line'];
const HTTP_RESP_BUFFERS = ['http.response_body', 'http.stat_code', 'http.response_line'];
let flowMessages = [];
let currentBuilder = 'sur';
let cpNameTouched = false;   // true once the user types into cp-name by hand

/* ── Step 1: the attack ─────────────────────────────────────── */
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

/* opts.highlight: text to mark (e.g. the stolen flag) so you see where it left. */
async function loadFlow(id, opts = {}) {
  id = (id || $('fl-id').value).trim();
  const m = id.match(UUID_RE);              // accepts a pasted Tulip URL too
  if (!m) { $('fl-view').textContent = '✗ Paste a Tulip flow id or a Tulip flow URL (…/flow/<id>).'; return false; }
  id = m[0];
  $('fl-id').value = id;
  $('fl-view').textContent = '⏳ loading flow from Tulip...';
  $('fl-picks').innerHTML = '';
  const d = await apiGet('/api/tulip/flow/' + encodeURIComponent(id));
  if (d.error) { $('fl-view').textContent = '✗ ' + d.error; flowMessages = []; return false; }
  flowMessages = d.messages || [];
  $('fl-meta').textContent = `${d.src} → ${d.dst}  ·  ${(d.time || '').slice(0, 19)}  ·  tags: ${(d.tags || []).join(', ')}`;
  const hl = opts.highlight;
  $('fl-view').innerHTML = flowMessages.map((m, i) => {
    let html = escHtml(m.text);
    if (hl) html = html.split(escHtml(hl)).join(`<mark>${escHtml(hl)}</mark>`);
    return `<span class="dir ${m.direction}"></span><span data-msg="${i}">${html}</span>`;
  }).join('\n');
  const mark = $('fl-view').querySelector('mark');
  if (mark) mark.scrollIntoView({ block: 'center' });
  renderPicks();
  const dst = (d.dst || '').split(':').pop();
  if (dst && [...$('su-port').options].some(o => o.value === dst)) $('su-port').value = dst;
  return true;
}

/* Split a client message into the parts a rule can target. Each pick knows
   its location, so the builder gets the narrowest buffer/target directly. */
function requestPicks() {
  const picks = [];
  const add = (kind, value, loc) => {
    if (!value || value.length < 2 || picks.some(p => p.value === value && p.loc.where === loc.where)) return;
    picks.push({ kind, value: value.slice(0, 300), loc: { direction: 'client', ...loc } });
  };
  flowMessages.filter(m => m.direction === 'client').forEach(m => {
    // several requests can share one keep-alive connection
    m.text.split(/(?=^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP\/)/m).forEach(req => {
      const lm = req.match(/^([A-Z]+) (\S+) HTTP\/[\d.]+/);
      if (!lm) { add('raw', req.trim().slice(0, 120), { where: 'raw' }); return; }
      const [path, query] = lm[2].split(/\?(.*)/s);
      add('path', path, { where: 'uri' });
      (query || '').split('&').forEach(kv => {
        const [k, v] = kv.split(/=(.*)/s);
        if (v) add(`?${k}=`, v, { where: 'uri', param: k });
      });
      const sep = req.search(/\r?\n\r?\n/);
      const head = sep >= 0 ? req.slice(0, sep) : req;
      const body = sep >= 0 ? req.slice(sep).replace(/^\s+/, '') : '';
      head.split(/\r?\n/).slice(1).forEach(line => {
        const hm = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
        if (!hm) return;
        const name = hm[1].toLowerCase();
        if (name === 'cookie') hm[2].split(/;\s*/).forEach(c => add('cookie', c, { where: 'header', header: 'Cookie' }));
        else if (name === 'user-agent' || name.startsWith('x-') || name === 'authorization' || name === 'referer')
          add(hm[1], hm[2], { where: 'header', header: hm[1] });
      });
      if (!body) return;
      let parsed = false;
      if (/^[\[{]/.test(body)) {
        try {
          const j = JSON.parse(body);
          Object.entries(Array.isArray(j) ? {} : j).forEach(([k, v]) => {
            if (typeof v === 'string' || typeof v === 'number') add(`body ${k}`, String(v), { where: 'body', param: k });
          });
          parsed = true;
        } catch (e) { /* not JSON */ }
      }
      const bm = head.match(/boundary=("?)([^";\r\n]+)\1/i);
      if (bm) {                                   // file upload: one pick per part
        body.split('--' + bm[2]).forEach(part => {
          const nm = (part.match(/name="([^"]*)"/) || [])[1];
          if (!nm) return;
          const fn = (part.match(/filename="([^"]*)"/) || [])[1];
          if (fn) add(`file ${nm}`, fn, { where: 'body' });   // multipart: match on raw body, params aren't parsed
          const content = part.split(/\r?\n\r?\n/).slice(1).join('\n\n').trim();
          if (content) add(`part ${nm}`, content.slice(0, 120), { where: 'body' });
        });
        parsed = true;
      }
      if (!parsed && /^[^=&\s]+=[^\n]*$/.test(body.split('\n')[0])) {
        body.split('\n')[0].split('&').forEach(kv => {
          const [k, v] = kv.split(/=(.*)/s);
          if (v) add(`body ${k}=`, v, { where: 'body', param: k });
        });
        parsed = true;
      }
      if (!parsed) add('body', body.slice(0, 120), { where: 'body' });
    });
  });
  return picks.slice(0, 40);
}

let flowPicks = [];
function renderPicks() {
  flowPicks = requestPicks();
  $('fl-picks').innerHTML = flowPicks.length
    ? flowPicks.map((p, i) => `<button class="pick" data-pick="${i}" title="${escHtml(p.value)}"><i>${escHtml(p.kind)}</i>${escHtml(p.value.slice(0, 60))}</button>`).join('')
    : '<span class="help" style="padding:0;">(no HTTP request found — select text manually)</span>';
}

/* Guess WHERE in the request the selected text lives, so the builder can
   target the narrowest buffer (narrow rule = less chance of hitting the checker). */
function locateSelection(sel) {
  const node = window.getSelection().anchorNode;
  const span = node && (node.nodeType === 3 ? node.parentElement : node).closest('[data-msg]');
  const msg = span ? flowMessages[+span.dataset.msg] : flowMessages.find(m => m.text.includes(sel));
  if (!msg) return { where: 'raw' };
  const text = msg.text;
  const idx = text.indexOf(sel);
  const headEnd = text.indexOf('\r\n\r\n') >= 0 ? text.indexOf('\r\n\r\n') : text.indexOf('\n\n');
  const firstLineEnd = text.search(/\r?\n/);
  const res = { direction: msg.direction };
  if (idx >= 0 && firstLineEnd > 0 && idx < firstLineEnd) {
    res.where = 'uri';
    const qm = text.slice(0, firstLineEnd).match(new RegExp('[?&]([^=&\\s]+)=[^&\\s]*' + sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    if (qm) res.param = qm[1];
  } else if (idx >= 0 && headEnd > 0 && idx > headEnd) {
    res.where = 'body';
    const body = text.slice(headEnd).trim();
    const esc = sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const fm = body.match(new RegExp('(?:^|&)([^=&]+)=[^&]*' + esc)) || body.match(new RegExp('"([^"]+)"\\s*:\\s*"?[^"]*' + esc));
    if (fm) res.param = decodeURIComponent(fm[1]);
  } else if (idx >= 0) {
    res.where = 'header';
    const line = text.slice(text.lastIndexOf('\n', idx) + 1, text.indexOf('\n', idx) >= 0 ? text.indexOf('\n', idx) : undefined);
    const hm = line.match(/^([A-Za-z0-9-]+):/);
    if (hm) res.header = hm[1];
  } else {
    res.where = 'raw';
  }
  return res;
}

function useSelection() {
  const sel = window.getSelection().toString();
  if (!sel) { $('fl-meta').textContent = 'Select some text in the flow first (or click a Quick pick).'; return; }
  applyPick(sel, locateSelection(sel));
}

/* Put a value + its location into whichever builder is open. */
function applyPick(sel, loc) {
  if (currentBuilder === 'sur') {
    const server = loc.direction === 'server';
    $('su-proto').value = 'http';
    $('su-dir').value = server ? 'to_client' : 'to_server';
    let buf = server ? 'http.response_body'
      : loc.where === 'uri' ? 'http.uri'
      : loc.where === 'body' ? 'http.request_body'
      : loc.header && loc.header.toLowerCase() === 'user-agent' ? 'http.user_agent'
      : loc.header && loc.header.toLowerCase() === 'cookie' ? 'http.cookie'
      : loc.where === 'header' ? 'http.header' : 'http.uri';
    const rows = $('su-matches').querySelectorAll('.match-row');
    const empty = [...rows].find(r => !r.querySelector('.m-val').value);
    if (empty) { empty.querySelector('.m-buf').value = buf; empty.querySelector('.m-val').value = sel; }
    else addMatchRow(buf, 'contains', sel);
    if (!$('su-msg').value) $('su-msg').value = `CUSTOM ${server ? 'response' : 'request'} contains ${sel.slice(0, 40)}`;
  } else {
    if (loc.direction === 'server') { $('cp-out').textContent = 'ctf_proxy rules here filter REQUESTS — pick text from the client → server part.'; return; }
    let target, pname, bareEndpoint = false;
    if (loc.param) { target = 'param'; pname = loc.param; }
    else if (loc.where === 'header' && loc.header) { target = 'header'; pname = loc.header; }
    else if (loc.where === 'uri') { target = 'path'; bareEndpoint = true; }
    else if (loc.where === 'body') { target = 'body'; }
    else { target = 'raw'; }
    // Raw-TCP service: no parsed url/path/param/header exists server-side,
    // only the raw bytes -- collapse whatever the flow viewer guessed back
    // to "raw" instead of letting an invalid target reach Build and error.
    if (cpIsRawService() && target !== 'raw') { target = 'raw'; pname = undefined; }

    // First pick fills the primary condition; every pick after that becomes
    // another AND'd condition in the "extra" list below (same pattern as the
    // Suricata builder's "+ condition" rows) -- combining several distinctive
    // parts of the request is what actually keeps a BLOCKING rule from also
    // matching the checker, instead of overwriting the previous pick.
    if (!$('cp-value').value) {
      $('cp-target').value = target;
      if (pname) $('cp-pname').value = pname;
      $('cp-value').value = sel;
      if (!cpNameTouched) $('cp-name').value = (loc.param || loc.where || 'rule') + '_' + sel.replace(/\W+/g, '_').slice(0, 16);
      cpTargetChanged();
    } else {
      const rows = $('cp-extra').querySelectorAll('.match-row');
      const empty = [...rows].find(r => !r.querySelector('.cpm-val').value);
      if (empty) {
        empty.querySelector('.cpm-target').value = target;
        if (pname) empty.querySelector('.cpm-name').value = pname;
        empty.querySelector('.cpm-val').value = sel;
        empty._syncName();
      } else {
        cpAddMatchRow(target, pname, 'contains', sel);
      }
    }
    // The exact mistake that took down /image-sharing/ earlier: picking the
    // bare PATH (no query param, no body) blocks the whole endpoint, which
    // the checker usually also calls for legitimate reasons. Warn loudly
    // right here instead of letting it ship silently.
    $('cp-out').textContent = bareEndpoint
      ? `⚠ Bạn đang chọn PATH ("${sel}") — rule này sẽ chặn CẢ endpoint này, không chỉ phần độc hại.\n` +
        'Nếu endpoint còn dùng cho việc hợp lệ (checker/người dùng thật), hãy chọn lại THAM SỐ hoặc nội dung body của payload tấn công thay vì path, hoặc thêm điều kiện (+ condition) để thu hẹp lại. ' +
        'Chỉ giữ "the URL path" làm điều kiện DUY NHẤT nếu bạn chắc endpoint này không có traffic hợp lệ nào.'
      : '';
  }
  $('fl-meta').textContent = `Selection placed into the ${currentBuilder === 'sur' ? 'Suricata' : 'ctf_proxy'} builder (detected location: ${loc.where}${loc.param ? ', param ' + loc.param : ''}${loc.header ? ', header ' + loc.header : ''}).`;
}

/* ── Step 2a: Suricata builder ──────────────────────────────── */
function bufferOptions(selected) {
  const proto = $('su-proto').value;
  const list = proto === 'http'
    ? ($('su-dir').value === 'to_client' ? HTTP_RESP_BUFFERS : HTTP_REQ_BUFFERS)
    : ['payload'];
  return list.map(b => `<option ${b === selected ? 'selected' : ''}>${b}</option>`).join('');
}

function addMatchRow(buf, mode, value) {
  const row = document.createElement('div');
  row.className = 'match-row';
  row.innerHTML = `
    <select class="sel m-buf">${bufferOptions(buf)}</select>
    <select class="sel m-mode"><option value="contains">contains</option><option value="regex">regex</option></select>
    <input class="inp m-val" placeholder="value">
    <span style="white-space:nowrap;">
      <label class="chk"><input type="checkbox" class="m-nocase"> nocase</label>
      <label class="chk"><input type="checkbox" class="m-neg"> NOT</label>
      <label class="chk"><input type="checkbox" class="m-hex"> hex</label>
      <button class="er-btn-sm m-del" title="remove">✗</button>
    </span>`;
  row.querySelector('.m-mode').value = mode || 'contains';
  row.querySelector('.m-val').value = value || '';
  row.querySelector('.m-del').onclick = () => row.remove();
  $('su-matches').appendChild(row);
}

function refreshBufferSelects() {
  $('su-matches').querySelectorAll('.m-buf').forEach(s => { s.innerHTML = bufferOptions(s.value); });
}

function suSpec() {
  return {
    msg: $('su-msg').value, proto: $('su-proto').value, direction: $('su-dir').value,
    port: $('su-port').value || null, src_ip: $('su-src').value,
    matches: [...$('su-matches').querySelectorAll('.match-row')].map(r => ({
      buffer: r.querySelector('.m-buf').value, mode: r.querySelector('.m-mode').value,
      value: r.querySelector('.m-val').value, nocase: r.querySelector('.m-nocase').checked,
      negate: r.querySelector('.m-neg').checked, hex: r.querySelector('.m-hex').checked,
    })),
  };
}

async function suBuild(btn) {
  await withBusy(btn, 'su-out', 'Generating...', async out => {
    const d = await apiPost('/api/rules/suricata/build', suSpec());
    if (d.errors && d.errors.length) { out.textContent = '✗ Fix these first:\n- ' + d.errors.join('\n- '); return; }
    $('su-rule').value = d.rule;
    out.textContent = '✓ Rule generated (sid ' + d.sid + '). Next: Test on recent traffic, then Add to ruleset.' +
      (d.warnings.length ? '\n\n⚠ ' + d.warnings.join('\n⚠ ') : '');
  });
}

function renderReplay(d) {
  if (!d.ok) return '✗ ' + d.output;
  let s = '✓ ' + d.output + '\n';
  if (!d.total) return s + '\nNo matches. Either the attack is not in these pcaps (replay more files / check the flow time), or the rule is too narrow.';
  s += '\nPer rule:\n' + Object.entries(d.by_sid).map(([sid, v]) => `  sid ${sid}: ${v.count} × ${v.signature}`).join('\n');
  s += '\n\nSource IPs that triggered it:\n  ' + (d.distinct_sources || []).join(', ');
  s += '\n\n⚠ If the checker bot / other legitimate clients are in that list, the rule is too broad to use for BLOCKING.';
  s += '\n\nFirst matches:\n' + d.samples.slice(0, 15).map(m => `  ${(m.ts || '').slice(0, 19)}  ${m.src} → ${m.dst}  [${m.sid}]`).join('\n');
  return s;
}

async function suTest(btn, rulesText, outId) {
  if (!rulesText.trim()) { $(outId).textContent = 'Nothing to test — generate or write a rule first.'; return; }
  await withBusy(btn, outId, 'Replaying traffic (can take a minute)...', async out => {
    const d = await apiPost('/api/rules/suricata/test-traffic', { rules: rulesText, files: +$('su-files').value || 40 });
    out.textContent = renderReplay(d);
  });
}

function suAddToRuleset() {
  const rule = $('su-rule').value.trim();
  if (!rule) { $('su-out').textContent = 'Generate a rule first.'; return; }
  const ta = $('rs-text');
  if (ta.value.includes(rule)) { $('su-out').textContent = 'Already in the ruleset below.'; return; }
  ta.value = ta.value.replace(/\s*$/, '\n') + `# added ${new Date().toISOString().slice(0, 19)} from rule builder\n${rule}\n`;
  ta.scrollTop = ta.scrollHeight;
  rsRenderFromText();
  $('su-out').textContent = '✓ Added to the ruleset table/editor below (3a) -- see it marked "not applied yet". Press "Test syntax & Apply" there to make it live.';
}

/* ── Step 2b: ctf_proxy builder ─────────────────────────────── */
function cpTargetChanged() {
  const t = $('cp-target').value;
  const show = t === 'param' || t === 'header';
  $('cp-pname').style.display = show ? '' : 'none';
  $('cp-pname-l').style.display = show ? '' : 'none';
  $('cp-pname-l').textContent = t === 'header' ? 'Header name' : 'Parameter name';
}

/* The currently-picked service in panel 3b decides what the builder can even
   offer: a raw TCP service (no HTTP parsing) only ever has bytes to match on
   -- url/path/param/header/method targets don't exist for it server-side
   (rulegen/ctfproxy.py rejects them). Restricting the dropdowns here means
   that error can never actually happen -- the invalid options simply aren't
   there to pick, instead of being generated and then rejected after Build. */
function cpIsRawService() {
  const info = cfServices.find(s => s.name === cfSvc());
  return !!(info && !info.http);
}

function cpRestrictTargetSelect(sel, raw) {
  [...sel.options].forEach(o => { o.hidden = raw && o.value !== 'raw'; });
  if (raw && sel.value !== 'raw') sel.value = 'raw';
}

function cpApplyServiceConstraints() {
  const raw = cpIsRawService();
  cpRestrictTargetSelect($('cp-target'), raw);
  cpTargetChanged();
  document.querySelectorAll('#cp-extra .cpm-target').forEach(sel => {
    cpRestrictTargetSelect(sel, raw);
    sel.dispatchEvent(new Event('change'));
  });
  $('cp-http-only').style.display = raw ? 'none' : '';
  $('cp-raw-note').hidden = !raw;
  if (raw) $('cp-raw-note-svc').textContent = cfSvc();
}

/* Extra AND'd conditions beyond the primary one (mirrors Suricata's
   "+ condition" match-row pattern) -- combining several distinctive parts
   of the request (e.g. path AND body payload) is what keeps a BLOCKING
   rule from also matching the checker. Backend hard-refuses target=header
   with header_name user-agent/x-forwarded-for on ANY row, primary or extra
   -- those are shared between attacker and checker too often to block on. */
function cpAddMatchRow(target, name, mode, value, nocase) {
  const row = document.createElement('div');
  row.className = 'match-row';
  row.innerHTML = `
    <select class="sel cpm-target">
      <option value="param">a parameter</option>
      <option value="body">the raw body</option>
      <option value="path">the URL path</option>
      <option value="url">the full URL</option>
      <option value="query_string">the query string</option>
      <option value="header">a header</option>
      <option value="method">the HTTP method</option>
      <option value="raw">the whole raw request</option>
    </select>
    <input class="inp cpm-name" placeholder="parameter name" style="width:120px;display:none;">
    <select class="sel cpm-mode"><option value="contains">contains</option><option value="equals">equals</option><option value="regex">regex</option></select>
    <input class="inp cpm-val" placeholder="value">
    <span style="white-space:nowrap;">
      <label class="chk"><input type="checkbox" class="cpm-nocase"> nocase</label>
      <button class="er-btn-sm cpm-del" title="remove">✗</button>
    </span>`;
  const targetSel = row.querySelector('.cpm-target');
  const nameInput = row.querySelector('.cpm-name');
  const syncName = () => {
    const show = targetSel.value === 'param' || targetSel.value === 'header';
    nameInput.style.display = show ? '' : 'none';
    nameInput.placeholder = targetSel.value === 'header' ? 'header name' : 'parameter name';
  };
  targetSel.value = target || 'body';
  nameInput.value = name || '';
  row.querySelector('.cpm-mode').value = mode || 'contains';
  row.querySelector('.cpm-val').value = value || '';
  row.querySelector('.cpm-nocase').checked = !!nocase;
  targetSel.onchange = syncName;
  row._syncName = syncName;
  syncName();
  row.querySelector('.cpm-del').onclick = () => row.remove();
  $('cp-extra').appendChild(row);
  cpRestrictTargetSelect(targetSel, cpIsRawService());
  syncName();
  return row;
}

function cpSpec() {
  const t = $('cp-target').value;
  return {
    name: $('cp-name').value, target: t, mode: $('cp-mode').value, value: $('cp-value').value,
    nocase: $('cp-nocase').checked, only_method: $('cp-meth').value, only_path_contains: $('cp-path').value,
    param_name: t === 'param' ? $('cp-pname').value : '', header_name: t === 'header' ? $('cp-pname').value : '',
    extra: [...$('cp-extra').querySelectorAll('.match-row')].map(r => {
      const et = r.querySelector('.cpm-target').value;
      const ename = r.querySelector('.cpm-name').value;
      return {
        target: et, mode: r.querySelector('.cpm-mode').value, value: r.querySelector('.cpm-val').value,
        nocase: r.querySelector('.cpm-nocase').checked,
        param_name: et === 'param' ? ename : '', header_name: et === 'header' ? ename : '',
      };
    }),
  };
}

async function cpBuild(btn) {
  await withBusy(btn, 'cp-out', 'Generating...', async out => {
    if (!$('cf-text').value.trim()) {
      out.textContent = '⏳ Loading the current filter from the vulnbox first...';
      const ok = await cfLoad();
      if (!ok) { out.textContent = '✗ Could not load the current ctf_proxy filter (see 3b). Is ctf_proxy installed and the vulnbox reachable?'; return; }
    }
    const spec = cpSpec();
    const d = await apiPost('/api/rules/ctfproxy/build', { spec, source: $('cf-text').value, service: cfSvc() });
    if (d.errors && d.errors.length) { out.textContent = '✗ Fix these first:\n- ' + d.errors.join('\n- '); return; }
    $('cf-text').value = d.source;
    cfRenderFromText();
    // That name is now spent (used for the method just inserted) -- clear it
    // so the next pick starts a fresh auto-name instead of reusing this one.
    $('cp-name').value = '';
    cpNameTouched = false;
    out.textContent = `✓ Method ${d.name}() inserted into the filter (3b). NOT uploaded yet — review it, then "Check & Upload".\n` +
      'Tip: test the same pattern as a Suricata rule first ("Test on recent traffic") to see if the checker would be blocked.\n\n' +
      d.code + (d.warnings.length ? '\n⚠ ' + d.warnings.join('\n⚠ ') : '');
  });
}

/* ── Step 3: live rulesets ──────────────────────────────────────────────
   The table is ALWAYS re-derived from whatever is currently in #rs-text --
   never a separate source of truth. That's deliberate: #rs-text is the one
   place "Add to ruleset", the rule library, and hand-editing all write to,
   and all of those are drafts until "Test syntax & Apply" actually uploads
   them. If the table only refreshed from the server, adding a draft rule
   would make it vanish from view until Apply -- confusing, looks like the
   add silently failed. So: every row is tagged live (confirmed on disk, as
   of the last successful reload/apply) or draft (only in the textarea so
   far) and gets different actions accordingly. ── */
let rsLiveSids = new Set();   // sids confirmed present after the last reload/apply
let rsAddedMap = {};          // sid -> ISO timestamp, from the server

function rsFormatAdded(iso) {
  if (!iso) return '<span style="color:var(--text-dim)">-</span>';
  // "2026-10-13T15:01:31+00:00" -> "10-13 15:01" (no year clutter; this tool
  // only ever runs within one contest day).
  const m = iso.match(/(\d{2})-(\d{2})T(\d{2}:\d{2})/);
  return m ? `${m[1]}-${m[2]} ${m[3]}` : escHtml(iso.slice(0, 16));
}

function rsParseLocal(text) {
  const rows = [];
  let n = 0;
  for (const raw of (text || '').split('\n')) {
    const s = raw.trim();
    if (!s || s.startsWith('#')) continue;
    n++;
    const sidM = s.match(/sid\s*:\s*(\d+)/);
    const msgM = s.match(/msg\s*:\s*"((?:[^"\\]|\\.)*)"/);
    const sid = sidM ? sidM[1] : null;
    rows.push({ n, sid, msg: msgM ? msgM[1] : s.slice(0, 80), line: s,
                added: sid ? (rsAddedMap[sid] || null) : null,
                live: sid ? rsLiveSids.has(sid) : false });
  }
  return rows;
}

function rsRenderRows(parsed) {
  rsLastParsed = parsed || [];
  if (!parsed || !parsed.length) {
    $('rs-rows').innerHTML = '<tr><td colspan="5" class="er-empty">No active rules.</td></tr>';
    return;
  }
  $('rs-rows').innerHTML = parsed.map(r => {
    const added = r.live ? rsFormatAdded(r.added) : '<span style="color:var(--accent-cyan)">not applied yet</span>';
    const actions = !r.sid ? ''
      : r.live ? `<button class="er-btn-sm" data-rs-edit="${r.n}">Edit</button> <button class="er-btn-sm danger" data-rs-del="${escHtml(r.sid)}">Delete</button>`
      : `<button class="er-btn-sm" data-rs-remove="${r.n}" title="Removes this draft line from the editor -- it was never applied, so there is nothing live to delete">Remove draft</button>`;
    return `<tr data-rs-n="${r.n}">
      <td>${r.n}</td>
      <td>${escHtml(r.sid || '-')}</td>
      <td class="msg" title="${escHtml(r.line)}">${escHtml(r.msg)}</td>
      <td style="white-space:nowrap;">${added}</td>
      <td style="white-space:nowrap;">${actions}</td>
    </tr>`;
  }).join('');
}

let rsLastParsed = [];
function rsRenderFromText() { rsRenderRows(rsParseLocal($('rs-text').value)); }

async function rsReload() {
  const d = await apiGet('/api/rules/suricata');
  $('rs-text').value = d.rules || '';
  $('rs-out').textContent = d.note ? '✗ ' + d.note : '';
  rsLiveSids = new Set();
  rsAddedMap = {};
  (d.parsed || []).forEach(r => { if (r.sid) { rsLiveSids.add(r.sid); if (r.added) rsAddedMap[r.sid] = r.added; } });
  rsRenderFromText();
}

async function rsDeleteSid(sid) {
  if (!confirm(`Delete Suricata rule sid ${sid}? This re-applies the ruleset without it (tested + backed up, same as any other apply).`)) return;
  const d = await apiPost('/api/rules/suricata/delete', { sid });
  $('rs-out').textContent = d.ok ? `✓ Deleted sid ${sid}.` : '✗ ' + d.output;
  showToast(`Delete sid ${sid}: ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
  await rsReload();
}

function rsRemoveDraft(n) {
  const row = rsLastParsed.find(r => r.n === n);
  if (!row) return;
  const lines = $('rs-text').value.split('\n');
  const idx = lines.findIndex(l => l.trim() === row.line);
  if (idx >= 0) lines.splice(idx, 1);
  $('rs-text').value = lines.join('\n');
  rsRenderFromText();
}

function rsStartEdit(n) {
  const row = rsLastParsed.find(r => r.n === n);
  const tr = $('rs-rows').querySelector(`tr[data-rs-n="${n}"]`);
  if (!row || !tr) return;
  const cells = tr.querySelectorAll('td');
  cells[2].innerHTML = `<textarea class="code" id="rs-edit-${n}" style="width:100%;min-height:60px;" spellcheck="false">${escHtml(row.line)}</textarea>`;
  cells[4].innerHTML = `<button class="er-btn-sm primary" data-rs-save="${n}">Save</button> <button class="er-btn-sm" data-rs-cancel="${n}">Cancel</button>`;
}

async function rsSaveEdit(n) {
  const row = rsLastParsed.find(r => r.n === n);
  const ta = $(`rs-edit-${n}`);
  if (!row || !ta) return;
  const newLine = ta.value.trim();
  if (!newLine) { alert('Rule text cannot be empty -- use Delete instead.'); return; }
  const full = $('rs-text').value;
  if (!full.includes(row.line)) {
    $('rs-out').textContent = '✗ Could not find the original line to replace (the ruleset changed under you) -- Reload from disk and try again.';
    rsRenderFromText();
    return;
  }
  $('rs-text').value = full.replace(row.line, newLine);
  const d = await apiPost('/api/rules/suricata', { rules: $('rs-text').value });
  $('rs-out').textContent = d.ok ? `✓ sid ${row.sid} updated and live.` : '✗ ' + d.output;
  showToast(`Edit sid ${row.sid}: ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
  await rsReload();
}

/* Same always-re-derive-from-the-editor approach as the Suricata table above
   (see the comment on rsLiveSids/rsParseLocal) -- #cf-text is what Add-method,
   quick-block and hand-editing all write to, so the table has to reflect
   whatever is in there right now, not just what the server last confirmed. */
let cfLiveNames = new Set();   // method names confirmed uploaded as of the last reload/apply
let cfAddedMap = {};           // name -> ISO timestamp, from the server
let cfLastParsed = [];

function cfParseLocal(text) {
  const rows = [];
  const defRe = /^ {4}def (\w+)\(self[^\n]*\n/gm;
  const defs = [];
  let m;
  while ((m = defRe.exec(text || ''))) defs.push({ name: m[1], start: m.index });
  let n = 0;
  for (let i = 0; i < defs.length; i++) {
    const { name, start } = defs[i];
    if (name === 'execute' || name.startsWith('_')) continue;
    const end = i + 1 < defs.length ? defs[i + 1].start : (text || '').length;
    const code = (text || '').slice(start, end);
    const trimmed = code.replace(/\s+$/, '');
    const trailing = code.slice(trimmed.length) || '\n';
    const docM = trimmed.match(/"""([\s\S]*?)"""/);
    const desc = docM ? docM[1].split(' [generated')[0].trim() : name;
    n++;
    rows.push({ n, name, desc, code, trimmed, trailing,
                added: cfAddedMap[name] || null, live: cfLiveNames.has(name) });
  }
  return rows;
}

function cfRenderRows(parsed) {
  cfLastParsed = parsed || [];
  if (!parsed || !parsed.length) {
    $('cf-rows').innerHTML = '<tr><td colspan="5" class="er-empty">No rule methods in the filter.</td></tr>';
    return;
  }
  $('cf-rows').innerHTML = parsed.map(r => {
    const added = r.live ? rsFormatAdded(r.added) : '<span style="color:var(--accent-cyan)">not applied yet</span>';
    const actions = r.live
      ? `<button class="er-btn-sm" data-cf-edit="${r.n}">Edit</button> <button class="er-btn-sm danger" data-cf-del="${escHtml(r.name)}">Delete</button>`
      : `<button class="er-btn-sm" data-cf-remove="${r.n}" title="Removes this draft method from the editor -- it was never uploaded, so there is nothing live to delete">Remove draft</button>`;
    return `<tr data-cf-n="${r.n}">
      <td>${r.n}</td>
      <td>${escHtml(r.name)}()</td>
      <td class="msg" title="${escHtml(r.name)}()">${escHtml(r.desc)}</td>
      <td style="white-space:nowrap;">${added}</td>
      <td style="white-space:nowrap;">${actions}</td>
    </tr>`;
  }).join('');
}

function cfRenderFromText() { cfRenderRows(cfParseLocal($('cf-text').value)); }

/* One ctf_proxy deployment fronts every TCP service in services.json -- the
   dropdown picks which one 3b is looking at. UDP services never appear here
   (ctf_proxy can't proxy them; use the SERVICES tab's content-based firewall
   block instead). */
let cfServices = [];
function cfSvc() { return $('cf-service').value || ''; }

async function cfLoadServices() {
  const d = await apiGet('/api/rules/ctfproxy/services');
  cfServices = (d && d.services) || [];
  const cur = $('cf-service').value;
  $('cf-service').innerHTML = cfServices.length
    ? cfServices.map(s => `<option value="${escHtml(s.name)}">${escHtml(s.name)}${s.http ? '' : ' (raw TCP)'}</option>`).join('')
    : '<option value="">(no TCP service configured)</option>';
  if (cur && cfServices.some(s => s.name === cur)) $('cf-service').value = cur;
  cpApplyServiceConstraints();
}

async function cfLoad() {
  if (!cfServices.length) await cfLoadServices();
  const d = await apiGet('/api/rules/ctfproxy?service=' + encodeURIComponent(cfSvc()));
  if (!d.ok) { $('cf-out').textContent = '✗ ' + d.output; $('cp-state').className = 'state'; $('cp-state').textContent = ''; return false; }
  $('cf-text').value = d.source;
  $('cf-path').textContent = d.path;
  $('cp-state').className = 'state ' + (d.paused ? 'state-paused' : 'state-running');
  $('cp-state').textContent = d.paused ? 'PAUSED' : 'FILTERING';
  $('cf-out').textContent = d.paused ? '! Filtering is PAUSED (Services tab). Uploads are saved and take effect on Resume.' : '';
  cfLiveNames = new Set();
  cfAddedMap = {};
  (d.parsed || []).forEach(r => { cfLiveNames.add(r.name); if (r.added) cfAddedMap[r.name] = r.added; });
  cfRenderFromText();
  return true;
}

async function cfDeleteMethod(name) {
  if (!confirm(`Delete ctf_proxy rule ${name}()? This re-uploads the filter without it (tested + backed up, same as any other upload).`)) return;
  const d = await apiPost('/api/rules/ctfproxy/delete', { name, service: cfSvc() });
  $('cf-out').textContent = d.ok ? `✓ Deleted ${name}().` : '✗ ' + d.output;
  showToast(`Delete ${name}(): ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
  await cfLoad();
}

function cfRemoveDraft(n) {
  const row = cfLastParsed.find(r => r.n === n);
  if (!row) return;
  const full = $('cf-text').value;
  if (!full.includes(row.code)) { cfRenderFromText(); return; }
  $('cf-text').value = full.replace(row.code, '');
  cfRenderFromText();
}

function cfStartEdit(n) {
  const row = cfLastParsed.find(r => r.n === n);
  const tr = $('cf-rows').querySelector(`tr[data-cf-n="${n}"]`);
  if (!row || !tr) return;
  const cells = tr.querySelectorAll('td');
  cells[2].innerHTML = `<textarea class="code" id="cf-edit-${n}" style="width:100%;min-height:140px;" spellcheck="false">${escHtml(row.trimmed)}</textarea>`;
  cells[4].innerHTML = `<button class="er-btn-sm primary" data-cf-save="${n}">Save</button> <button class="er-btn-sm" data-cf-cancel="${n}">Cancel</button>`;
}

async function cfSaveEdit(n) {
  const row = cfLastParsed.find(r => r.n === n);
  const ta = $(`cf-edit-${n}`);
  if (!row || !ta) return;
  const newBody = ta.value.replace(/\s+$/, '');
  if (!newBody.trim()) { alert('Method body cannot be empty -- use Delete instead.'); return; }
  const full = $('cf-text').value;
  if (!full.includes(row.code)) {
    $('cf-out').textContent = '✗ Could not find the original method to replace (the filter changed under you) -- Load from vulnbox and try again.';
    cfRenderFromText();
    return;
  }
  $('cf-text').value = full.replace(row.code, newBody + row.trailing);
  const d = await apiPost('/api/rules/ctfproxy', { source: $('cf-text').value, service: cfSvc() });
  $('cf-out').textContent = d.ok ? `✓ ${row.name}() updated and uploaded.` : '✗ ' + d.output;
  showToast(`Edit ${row.name}(): ${d.ok ? 'done' : 'FAILED'}`, d.ok ? 'success' : 'critical');
  await cfLoad();
}

async function rulesPrefillFromEvent(e) {
  const raw = e.raw || {};
  const flag = raw.flag || ((raw.message || '').match(/(?:outbound|service): (\S+)/) || [])[1];
  $('fl-context').innerHTML = `<b>From event:</b> ${escHtml(e.type)} · ${escHtml(e.src_ip || '?')} → ${escHtml(e.dst_ip || '?')}` +
    `${e.dst_port ? ':' + escHtml(String(e.dst_port)) : ''} · ${escHtml((raw.ts_packet || e.ts || '').slice(0, 19))}<br>${escHtml((e.message || '').slice(0, 160))}`;
  $('fl-cands').innerHTML = '';
  if (!$('su-msg').value) $('su-msg').value = `CUSTOM ${e.type}: ${(e.message || '').slice(0, 60)}`;
  if (e.dst_port && [...$('su-port').options].some(o => o.value === String(e.dst_port))) $('su-port').value = String(e.dst_port);
  const sid = e.sid || ((e.message || '').match(/^\[(\d+)\]/) || [])[1];
  if (e.type === 'suricata' && sid) { if (!$('rs-text').value) await rsReload(); rulesShowSid(sid); }

  $('fl-view').textContent = '⏳ Finding the Tulip flow for this event...';
  const f = await flowForEvent(e);
  if (!f.flow_id) {
    $('fl-view').textContent = `✗ No Tulip flow found: ${f.why}.\n\nOpen Tulip (🌷 button at the top), filter by ${e.src_ip || ''} ${e.dst_ip || ''} around ` +
      `${(raw.ts_packet || e.ts || '').slice(11, 19)} UTC, copy the flow URL and paste it in the box above.`;
    return;
  }
  await loadFlow(f.flow_id, { highlight: flag });
  const others = (f.candidates || []).filter(c => c.id !== f.flow_id);
  $('fl-cands').innerHTML = (f.exact ? `<div class="cands">✓ ${escHtml(f.why)}.` : `<div class="cands">! ${escHtml(f.why)}.`) +
    (flag ? ' The flag is <mark>marked</mark>; the request that got it is the CLIENT → SERVER part above it.' : '') +
    (others.length ? '<br>Other possible flows: ' + others.map(c =>
      `<button class="er-btn-sm" data-cand="${escHtml(c.id)}" title="${escHtml(c.id)}">${escHtml(c.src)} → ${escHtml(c.dst)} ${escHtml((c.time || '').slice(11, 19))}${(c.tags || []).includes('flag-out') ? ' [flag-out]' : ''}</button>`).join('') : '') + '</div>';
  $('fl-cands').querySelectorAll('[data-cand]').forEach(b => b.onclick = () => loadFlow(b.dataset.cand, { highlight: flag }));
}

/* One-click from EVENTS: load the flow, auto-pick the narrowest safe
   candidate (body/param over bare URL -- a bare path/URL gets REFUSED here,
   not auto-applied, because blocking a whole path can take the legit
   endpoint down with it; that exact mistake is what this guards against),
   build the ctf_proxy rule and upload it in one shot. Returns a short status
   string for the caller to show -- never throws. */
/* Suricata only ALERTS -- it can never break the service -- so it's safe to
   auto-apply even on a bare path/URL pick that ctf_proxy must refuse. */
async function quickApplySuricata(best) {
  currentBuilder = 'sur';
  applyPick(best.value, best.loc);
  if (!$('su-msg').value) $('su-msg').value = `AUTO quickblock: ${best.kind} ${best.value.slice(0, 40)}`;
  const d = await apiPost('/api/rules/suricata/build', suSpec());
  if (d.errors && d.errors.length) return { ok: false, msg: '✗ Suricata: ' + d.errors.join('; ') };
  if (!$('rs-text').value) await rsReload();
  const ta = $('rs-text');
  if (!ta.value.includes(d.rule)) {
    ta.value = ta.value.replace(/\s*$/, '\n') + `# auto-added ${new Date().toISOString().slice(0, 19)} from event quickblock\n${d.rule}\n`;
  }
  const ap = await apiPost('/api/rules/suricata', { rules: ta.value });
  if (ap.ok) await rsReload(); else rsRenderFromText();
  return { ok: ap.ok, msg: ap.ok ? `✓ Suricata sid ${d.sid} is now alerting.` : '✗ Suricata apply: ' + ap.output };
}

/* Shared by the Alert and Block quick-actions: load the flow, auto-pick the
   narrowest safe candidate (prefer the leaked flag > a body/param value > a
   query param > bare path/raw). Returns {best} or {error}. */
async function _pickBestForEvent(e) {
  currentBuilder = 'cp';
  await rulesPrefillFromEvent(e);
  const picks = flowPicks;
  if (!picks.length) return { error: 'No HTTP request found in this flow -- nothing to act on automatically. Open the RULES tab to pick by hand.' };
  const flag = (e.raw && e.raw.flag) || '';
  const score = p => (flag && p.value.includes(flag) ? 100 : 0) + (p.loc.where === 'body' ? 50 : p.loc.where === 'uri' && p.loc.param ? 40 : p.loc.where === 'header' ? 20 : 0) + Math.min(p.value.length, 30);
  const best = [...picks].sort((a, b) => score(b) - score(a))[0];
  if (best.value.length < 4) {
    return { error: `Match found is too short ("${best.value}") -- too likely to hit normal traffic. Open the RULES tab to pick by hand.` };
  }
  return { best };
}

/* Alert-only quick action: Suricata never blocks anything, so this is always
   safe to auto-apply, even on a bare path/URL pick. */
async function quickAlertFromEvent(e) {
  const { best, error } = await _pickBestForEvent(e);
  if (error) return { ok: false, msg: error };
  const res = await quickApplySuricata(best);
  return { ok: res.ok, msg: `${res.msg}\nSee/undo in the APPLIED tab.` };
}

/* Block-only quick action: ctf_proxy. Refused when the only pick is a bare
   path/URL with no param -- same lesson as the /image-sharing/ incident:
   blocking a whole endpoint by path risks blocking the checker too. */
async function quickBlockFromEvent(e) {
  const { best, error } = await _pickBestForEvent(e);
  if (error) return { ok: false, msg: error };

  let cpRes;
  if (best.loc.where === 'uri' && !best.loc.param) {
    cpRes = { ok: false, msg: `ctf_proxy: only a bare URL/path ("${best.value}") with no specific parameter -- NOT auto-blocking (would likely block the checker too, like the /image-sharing/ incident). Open the RULES tab to pick the exact malicious parameter/content and block by hand.` };
  } else {
    currentBuilder = 'cp';
    applyPick(best.value, best.loc);
    await cpBuild({ disabled: false, textContent: '' });   // withBusy only needs .disabled/.textContent; builder writes into cf-text
    const errOut = $('cp-out').textContent;
    if (errOut.startsWith('✗') || errOut.startsWith('⚠')) {
      cpRes = { ok: false, msg: 'ctf_proxy: ' + errOut };
    } else {
      // Targets whichever service is picked in 3b's dropdown -- a quick-action
      // from EVENTS doesn't know which service the event's port maps to, so
      // make sure the right one is selected there first in a multi-service setup.
      const d = await apiPost('/api/rules/ctfproxy', { source: $('cf-text').value, service: cfSvc() });
      if (d.ok) await cfLoad(); else cfRenderFromText();
      cpRes = { ok: d.ok, msg: d.ok ? `✓ ctf_proxy (${cfSvc()}) now blocking on "${best.value.slice(0, 60)}".` : '✗ ctf_proxy: ' + d.output };
    }
  }
  return { ok: cpRes.ok, msg: `${cpRes.msg}\nSee/undo in the APPLIED tab.` };
}


/* A Suricata alert: tuning usually means editing the rule that fired. */
function rulesShowSid(sid) {
  const ta = $('rs-text');
  const pos = ta.value.search(new RegExp('sid\\s*:\\s*' + sid + '\\s*;'));
  if (pos < 0) { $('rs-out').textContent = `Alert came from sid ${sid} — not in the custom ruleset below (it is a built-in/ET rule).`; return; }
  const start = ta.value.lastIndexOf('\n', pos) + 1;
  const end = ta.value.indexOf('\n', pos);
  ta.focus();
  ta.setSelectionRange(start, end < 0 ? ta.value.length : end);
  $('rs-out').textContent = `Alert came from sid ${sid} — that rule is selected in the editor. Edit/narrow it, then Test syntax & Apply.`;
}

/* ── Rule library ───────────────────────────────────────────── */
async function libLoadList() {
  const d = await apiGet('/api/rules/library');
  const files = d.files || [];
  $('lib-file').innerHTML =
    files.map(f => `<option value="${escHtml(f.file)}">${escHtml(f.file)} — ${f.count} rules</option>`).join('') +
    '<option value="__all__">— ALL files (' + files.reduce((n, f) => n + f.count, 0) + ' rules, nặng) —</option>';
  if (files.length) $('lib-file').value = files[0].file;   // don't auto-load 3000+ rules
  await libShow();
}

async function libShow() {
  const v = $('lib-file').value;
  const names = v === '__all__' ? [...$('lib-file').options].slice(1).map(o => o.value) : [v];
  const texts = await Promise.all(names.map(n => apiGet('/api/rules/library/' + encodeURIComponent(n)).then(d => d.text || '')));
  $('lib-text').value = texts.join('\n');
  $('lib-info').textContent = 'folder: rules-library/suricata/';
}

/* Append library rules whose sid is not already in the editor. */
function libMerge() {
  const have = new Set(($('rs-text').value.match(/sid\s*:\s*\d+/g) || []).map(x => x.replace(/\D/g, '')));
  const fresh = $('lib-text').value.split('\n').filter(l => {
    const m = l.match(/^\s*alert\b.*sid\s*:\s*(\d+)/);
    return m && !have.has(m[1]);
  });
  if (fresh.length) {
    $('rs-text').value = $('rs-text').value.replace(/\s*$/, '\n') +
      `# added ${new Date().toISOString().slice(0, 19)} from rule library (${$('lib-file').value})\n` + fresh.join('\n') + '\n';
    rsRenderFromText();
  }
  return fresh.length;
}

function rulesApplyMeta() {
  const cur = $('su-port').value;
  $('su-port').innerHTML = '<option value="">any port</option>' +
    META.services.map(s => `<option value="${s.port}">${s.port} (${escHtml(s.name)})</option>`).join('');
  $('su-port').value = cur || (META.services.length ? String(META.services[0].port) : '');
}

function initRules() {
  rulesApplyMeta();
  addMatchRow('http.uri', 'contains', '');
  cpTargetChanged();

  document.querySelectorAll('[data-builder]').forEach(b => b.onclick = () => {
    currentBuilder = b.dataset.builder;
    $('bd-sur').hidden = currentBuilder !== 'sur';
    $('bd-cp').hidden = currentBuilder !== 'cp';
    $('bt-sur').classList.toggle('active', currentBuilder === 'sur');
    $('bt-cp').classList.toggle('active', currentBuilder === 'cp');
  });
  const manualLoad = () => { $('fl-context').textContent = ''; $('fl-cands').innerHTML = ''; loadFlow(); };
  $('fl-load').onclick = manualLoad;
  $('fl-id').addEventListener('keydown', e => { if (e.key === 'Enter') manualLoad(); });
  $('fl-use').onclick = useSelection;
  $('fl-picks').addEventListener('click', ev => {
    const b = ev.target.closest('[data-pick]');
    if (b) { const p = flowPicks[+b.dataset.pick]; applyPick(p.value, p.loc); }
  });
  $('su-proto').onchange = refreshBufferSelects;
  $('su-dir').onchange = refreshBufferSelects;
  $('su-addmatch').onclick = () => addMatchRow();
  $('su-build').onclick = e => suBuild(e.target);
  $('su-test').onclick = e => suTest(e.target, $('su-rule').value, 'su-out');
  $('su-add').onclick = suAddToRuleset;
  $('cp-del-shown').onclick = async e => {
    const name = e.target.dataset.name;
    if (!name || !confirm(`Bỏ rule "${name}" vừa chèn? Nếu đã bấm "Check & Upload" rồi thì xóa thật trên vulnbox; nếu chưa thì chỉ nạp lại filter gốc.`)) return;
    e.target.disabled = true;
    await apiPost('/api/rules/ctfproxy/delete', { name, service: cfSvc() });   // no-op (ok:false, ignored) if it was never uploaded
    await cfLoad();                                          // either way, reload what's actually live now
    e.target.hidden = true; e.target.disabled = false;
  };
  $('cp-target').onchange = cpTargetChanged;
  $('cp-addmatch').onclick = () => cpAddMatchRow();
  $('cp-build').onclick = e => cpBuild(e.target);
  // After a successful build the name field holds the just-generated method's
  // real name -- starting a fresh pick/build cycle should auto-name again
  // unless the user types their own, so clear the "touched" flag there too.
  $('cp-name').addEventListener('input', () => { cpNameTouched = $('cp-name').value.trim() !== ''; });

  $('rs-reload').onclick = rsReload;
  $('rs-rows').addEventListener('click', ev => {
    let b = ev.target.closest('[data-rs-del]'); if (b) { rsDeleteSid(b.dataset.rsDel); return; }
    b = ev.target.closest('[data-rs-edit]'); if (b) { rsStartEdit(+b.dataset.rsEdit); return; }
    b = ev.target.closest('[data-rs-save]'); if (b) { rsSaveEdit(+b.dataset.rsSave); return; }
    b = ev.target.closest('[data-rs-cancel]'); if (b) { rsRenderFromText(); return; }
    b = ev.target.closest('[data-rs-remove]'); if (b) { rsRemoveDraft(+b.dataset.rsRemove); return; }
  });
  // Keep the table in sync with hand-edits in the raw textarea too (Reload
  // from disk already happens below for every server round-trip).
  $('rs-text').addEventListener('input', rsRenderFromText);
  $('lib-file').onchange = libShow;
  $('lib-test').onclick = e => suTest(e.target, $('lib-text').value, 'lib-out');
  $('lib-add').onclick = async () => {
    if (!$('rs-text').value) await rsReload();
    const n = libMerge();
    $('lib-out').textContent = n ? `✓ ${n} rule(s) added to the ruleset editor (3a). NOT live yet — press "Test syntax & Apply" there.`
                                 : 'All rules of this file are already in the ruleset.';
  };
  $('lib-apply').onclick = e => {
    if ($('lib-file').value === '__all__' && !confirm('Áp TẤT CẢ hơn 3000 rule vào Suricata? Rất nhiều — nên chọn từng file. Vẫn tiếp tục?')) return;
    withBusy(e.target, 'lib-out', 'Adding & applying...', async out => {
    await rsReload();                        // start from what is live, not from unsaved edits
    const n = libMerge();
    if (!n) { out.textContent = 'All rules of this file are already live.'; return; }
    const d = await apiPost('/api/rules/suricata', { rules: $('rs-text').value });
    showResult(out, d);
    out.textContent = (d.ok ? `✓ ${n} rule(s) added and live.\n\n` : `✗ Not applied (live ruleset unchanged).\n\n`) + out.textContent;
    showToast(d.ok ? `Library: ${n} rules live` : 'Library apply rejected — see output', d.ok ? 'success' : 'critical');
    if (d.ok) await rsReload(); else rsRenderFromText();
  });
  };
  $('rs-test').onclick = e => suTest(e.target, $('rs-text').value, 'rs-out');
  $('rs-apply').onclick = e => withBusy(e.target, 'rs-out', 'Testing syntax & applying...', async out => {
    const d = await apiPost('/api/rules/suricata', { rules: $('rs-text').value });
    showResult(out, d);
    showToast(d.ok ? 'Suricata rules applied' : 'Rules rejected — see output', d.ok ? 'success' : 'critical');
    if (d.ok) await rsReload(); else rsRenderFromText();
  });
  $('rs-rollback').onclick = e => {
    if (!confirm('Restore the previous Suricata ruleset?')) return;
    withBusy(e.target, 'rs-out', 'Rolling back...', async out => {
      const d = await apiPost('/api/rules/suricata/rollback');
      showResult(out, d);
      await rsReload();   // re-fetch from disk rather than trust d.rules, so timestamps/live-set stay accurate
    });
  };
  cfLoadServices();   // local config read, no SSH -- safe to do unconditionally at page load
  $('cf-service').onchange = () => withBusy({ disabled: false, textContent: '' }, 'cf-out', 'Loading from vulnbox...', async () => { await cfLoad(); cpApplyServiceConstraints(); });
  $('cf-load').onclick = e => withBusy(e.target, 'cf-out', 'Loading from vulnbox...', async () => { await cfLoad(); });
  $('cf-apply').onclick = e => {
    if (!confirm('Upload this filter to ctf_proxy? Rules start BLOCKING immediately (unless filtering is paused).')) return;
    withBusy(e.target, 'cf-out', 'Checking & uploading...', async out => {
      const d = await apiPost('/api/rules/ctfproxy', { source: $('cf-text').value, service: cfSvc() });
      showResult(out, d);
      showToast(d.ok ? 'ctf_proxy filter uploaded' : 'Upload rejected — see output', d.ok ? 'success' : 'critical');
      if (d.ok) await cfLoad(); else cfRenderFromText();
    });
  };
  $('cf-rollback').onclick = e => {
    if (!confirm('Restore the previous ctf_proxy filter?')) return;
    withBusy(e.target, 'cf-out', 'Rolling back...', async out => {
      const d = await apiPost('/api/rules/ctfproxy/rollback', { service: cfSvc() });
      showResult(out, d);
      await cfLoad();   // re-fetch from disk rather than trust d.source, so timestamps/live-set stay accurate
    });
  };
  $('cf-rows').addEventListener('click', ev => {
    let b = ev.target.closest('[data-cf-del]'); if (b) { cfDeleteMethod(b.dataset.cfDel); return; }
    b = ev.target.closest('[data-cf-edit]'); if (b) { cfStartEdit(+b.dataset.cfEdit); return; }
    b = ev.target.closest('[data-cf-save]'); if (b) { cfSaveEdit(+b.dataset.cfSave); return; }
    b = ev.target.closest('[data-cf-cancel]'); if (b) { cfRenderFromText(); return; }
    b = ev.target.closest('[data-cf-remove]'); if (b) { cfRemoveDraft(+b.dataset.cfRemove); return; }
  });
  // Keep the table in sync with hand-edits in the raw textarea too.
  $('cf-text').addEventListener('input', cfRenderFromText);
}
