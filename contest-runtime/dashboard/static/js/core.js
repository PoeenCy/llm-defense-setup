/* core.js — shared state, clock, modal, toast, escHtml. Loaded first. */
/* ════════════════════════════════════════════════════════════
   CTF Monitor Hub — Dashboard Logic
════════════════════════════════════════════════════════════ */

const CONFIG = {
  wsUrl: `ws://${location.host}/ws`,
  tulipUrl: null,
};

let ws = null;
let alertData = [];
let hintData  = [];
let watchdogData = {};
let stats = { flagOut:0, honeytoken:0, suricata:0, sla:0, hints:0, iocs:0 };
let currentFilter = 'all';
let startTime = Date.now();

// A dashboard tab is meant to stay open for an entire multi-hour contest.
// Any Map that only ever grows (never evicts) over that span is a real
// browser-memory leak, not a theoretical one -- this caps one at `max`
// entries, dropping the OLDEST first (Map preserves insertion order, so the
// first key in iteration order is always the oldest). Call after every
// `.set()` on a cache that's meant to survive across refreshes/reconnects
// but has no natural size bound of its own (e.g. a per-event flow-lookup
// cache that otherwise grows by one entry per event for the whole session).
function capMap(map, max) {
  while (map.size > max) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

// ── Clock & uptime ────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toLocaleTimeString('en-US', {hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});

  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  const h = Math.floor(elapsed/3600).toString().padStart(2,'0');
  const m = Math.floor((elapsed%3600)/60).toString().padStart(2,'0');
  document.getElementById('stat-uptime').textContent = `${h}:${m}`;
}
setInterval(updateClock, 1000);
updateClock();


// ── Modal ──────────────────────────────────────────────────────
function showModal(jsonStr) {
  const a = JSON.parse(jsonStr);
  document.getElementById('modal-title').textContent = `${(a.type||'Alert').toUpperCase()} — ${a.ts ? new Date(a.ts).toLocaleString() : 'Unknown time'}`;
  document.getElementById('modal-body').textContent = JSON.stringify(a, null, 2);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(e) {
  if (!e || e.target.id === 'modal-overlay' || e.target.className === 'modal-close') {
    document.getElementById('modal-overlay').classList.remove('open');
  }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal({}); });

// ── Toast notifications ────────────────────────────────────────
// sticky: stays on screen until clicked (instead of auto-dismissing after
// ~3s) -- for data actually leaving a service (flag-out/honeytoken-out),
// where a glance-and-it's-gone toast is too easy to miss.
// Sticky toasts (flag-out/honeytoken-out -- see notifyNewAlert) only leave
// the DOM when clicked. Over an 8h contest with many such events, an
// un-clicked pile grows forever -- both a real memory/DOM-node leak and, in
// practice, a wall of stacked toasts burying the screen. Capped at the N
// MOST RECENT: a new one past the cap evicts the single oldest sticky toast,
// never a regular (already self-removing) one.
const MAX_STICKY_TOASTS = 8;

function showToast(msg, type = 'info', sticky = false) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  if (sticky) {
    toast.dataset.sticky = '1';
    toast.style.cursor = 'pointer';
    toast.title = 'Click to dismiss';
    toast.textContent = msg;
    toast.onclick = () => toast.remove();
    const existing = container.querySelectorAll('[data-sticky="1"]');
    if (existing.length >= MAX_STICKY_TOASTS) existing[0].remove();
  } else {
    toast.textContent = msg;
    setTimeout(() => toast.remove(), 3200);
  }
  container.appendChild(toast);
  return toast;
}

// ── Audible alarm for attacks ──────────────────────────────────
// WebAudio beep, no sound file needed. Gated by the 🔊 toggle (saved per
// browser) and normally throttled so a burst of alerts can't become a beep
// storm -- except when bypassThrottle is set (flag-out/honeytoken-out: data
// actually left a service, rare enough that every one of them deserves its
// own beep even if several land in the same couple of seconds).
let _lastBeep = 0;
function soundOn() {
  try { return localStorage.getItem('ctf_sound') !== 'off'; } catch (e) { return true; }
}
function playAlarm(urgent, bypassThrottle = false) {
  if (!urgent && !soundOn()) return;
  const now = Date.now();
  if (!urgent && !bypassThrottle && now - _lastBeep < 2500) return;   // throttle
  _lastBeep = now;
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    const ctx = window.__ac || (window.__ac = new AC());
    if (ctx.state === 'suspended') ctx.resume();
    const t0 = ctx.currentTime;
    [880, 0, 880].forEach((f, i) => {               // two short beeps
      if (!f) return;
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = 'square'; o.frequency.value = f;
      const t = t0 + i * 0.18;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.25, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.15);
      o.connect(g); g.connect(ctx.destination);
      o.start(t); o.stop(t + 0.16);
    });
  } catch (e) { /* audio not available */ }
}

// Data actually leaving a service -- the one thing worth being louder about
// than everything else, short of auto-blocking (which we deliberately don't
// do -- see quickBlockFromEvent's comments in rules.js). No new rule is ever
// created automatically; this only makes sure a human can't miss it.
const EXFIL_TYPES = new Set(['flag-out', 'flag_out', 'honeytoken-out', 'honeytoken']);

function notifyNewAlert(a) {
  const prio = getPriority(a);
  const isExfil = EXFIL_TYPES.has(a.type || '');
  if (isExfil) {
    showToast(`🚨 DATA LEFT A SERVICE: ${(a.message||'').slice(0,80)}`, 'critical', true);
    playAlarm(false, true);
    try {
      if (Notification.permission === 'granted') {
        const n = new Notification('🚨 Flag/honeytoken left a service', { body: a.message, requireInteraction: true });
        n.onclick = () => window.focus();
      }
    } catch (e) { /* no Notification API */ }
  } else if (prio === 'critical') {
    showToast(`🚨 CRITICAL: ${(a.message||'').slice(0,60)}`, 'critical');
    playAlarm(false);
    try {
      if (Notification.permission === 'granted') new Notification('🚨 CTF ALERT', { body: a.message });
    } catch (e) { /* no Notification API */ }
  } else if (prio === 'high') {
    showToast(`⚠️ ${(a.message||'').slice(0,60)}`, 'critical');
  }

  // Update watchdog from SLA alerts
  if ((a.type||'').startsWith('sla-')) updateWatchdogFromAlert(a);
}

// ── Notifications permission ───────────────────────────────────
try { if (Notification.permission === 'default') Notification.requestPermission(); } catch (e) {}

// Sound toggle (persisted) + test button, wired once the DOM is ready.
function initSound() {
  const t = document.getElementById('snd-toggle');
  if (t) {
    t.checked = soundOn();
    t.onchange = () => { try { localStorage.setItem('ctf_sound', t.checked ? 'on' : 'off'); } catch (e) {} if (t.checked) playAlarm(true); };
  }
  const b = document.getElementById('snd-test');
  if (b) b.onclick = () => playAlarm(true);
}

// ── Util ──────────────────────────────────────────────────────
function escHtml(s) {
  if (typeof s !== 'string') return String(s || '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

