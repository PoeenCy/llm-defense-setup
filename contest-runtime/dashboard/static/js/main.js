/* main.js — tab routing + bootstrap. Loaded last. */

let currentTab = 'monitor';
const TAB_LOADED = {};
const TAB_FIRST_OPEN = {
  events: () => loadEvents(),
  rules: () => { rsReload(); libLoadList(); },
  hunt: () => {},
  applied: () => loadApplied(false),
  services: () => loadServices(),
  config: () => loadConfigText(),
};

function showTab(name) {
  if (!document.getElementById('tab-' + name)) name = 'monitor';
  currentTab = name;
  document.querySelectorAll('.tab').forEach(t => { t.hidden = t.id !== 'tab-' + name; });
  document.querySelectorAll('#tabnav button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  if (!TAB_LOADED[name] && TAB_FIRST_OPEN[name]) { TAB_LOADED[name] = true; TAB_FIRST_OPEN[name](); }
}

async function loadMeta() {
  try {
    Object.assign(META, await apiGet('/api/meta'));
  } catch (e) { /* page still works with defaults */ }
  $('team-id').textContent = `Team: ${META.team_id || '?'} | Vulnbox: ${META.vulnbox_ip || '?'}`;
  // Built from how YOU reached this page, so it works for localhost and for a
  // teammate on the LAN alike (Tulip binds the same address as the dashboard).
  $('tulip-link').href = `${location.protocol}//${location.hostname}:${META.tulip_port || 3000}/`;
  $('footer-vulnbox').textContent = `Vulnbox: ${META.vulnbox_ip || '—'}`;
  $('footer-monitor').textContent = `Monitor: ${META.monitor_ip || '—'}`;
}

(function bootstrap() {
  // Tabs and handlers first, synchronously: the page must be usable even if
  // an API call is slow or the host agent is down.
  document.querySelectorAll('#tabnav button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
  window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
  initEvents();
  initRules();
  initServices();
  initConfig();
  initSound();
  initHunt();
  initApplied();
  showTab(location.hash.slice(1) || 'monitor');
  connect();
  pollWatchdog();
  loadMeta().then(rulesApplyMeta);
})();
