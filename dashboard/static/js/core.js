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
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3200);
}

// ── Audible alarm for attacks ──────────────────────────────────
// WebAudio beep, no sound file needed. Gated by the 🔊 toggle (saved per
// browser) and throttled so a burst of alerts can't become a beep storm.
let _lastBeep = 0;
function soundOn() {
  try { return localStorage.getItem('ctf_sound') !== 'off'; } catch (e) { return true; }
}
function playAlarm(urgent) {
  if (!urgent && !soundOn()) return;
  const now = Date.now();
  if (!urgent && now - _lastBeep < 2500) return;   // throttle
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

function notifyNewAlert(a) {
  const prio = getPriority(a);
  if (prio === 'critical') {
    showToast(`🚨 CRITICAL: ${(a.message||'').slice(0,60)}`, 'critical');
    playAlarm(false);
    // Optional: browser notification (works even if the tab isn't focused)
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

