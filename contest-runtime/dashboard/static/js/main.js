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

// Tabs that need to know when they are shown or left, e.g. to stop polling,
// and that take a sub-route after the tab name: #flagtrace/<trace>/<run>.
const TAB_HOOKS = {
  flagtrace: { show: sub => ftShow(sub), hide: () => ftHide() },
};

function showTab(route) {
  const [first, ...rest] = String(route || '').split('/');
  const name = document.getElementById('tab-' + first) ? first : 'monitor';
  const sub = name === first && TAB_HOOKS[name] ? rest.join('/') : '';
  const previous = currentTab;
  currentTab = name;
  document.querySelectorAll('.tab').forEach(t => { t.hidden = t.id !== 'tab-' + name; });
  document.querySelectorAll('#tabnav button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  const hash = '#' + name + (sub ? '/' + sub : '');
  if (location.hash !== hash) history.replaceState(null, '', hash);
  if (!TAB_LOADED[name] && TAB_FIRST_OPEN[name]) { TAB_LOADED[name] = true; TAB_FIRST_OPEN[name](); }
  if (previous !== name && TAB_HOOKS[previous]) TAB_HOOKS[previous].hide();
  if (TAB_HOOKS[name]) TAB_HOOKS[name].show(sub);
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
  initFlagtrace();
  showTab(location.hash.slice(1) || 'monitor');
  connect();
  pollWatchdog();
  loadMeta().then(rulesApplyMeta);
})();
