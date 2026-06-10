// ══════════════════════════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════════════════════════
let token     = localStorage.getItem('ss_token') || '';
let username  = localStorage.getItem('ss_user')  || '';
let allLeaks  = [];
let curFilter = 'all';

// ══════════════════════════════════════════════════════════════
//  BOOT
// ══════════════════════════════════════════════════════════════
window.addEventListener('DOMContentLoaded', () => {
  if (token) { showDash(); loadDash(); }
  else        { showLoginPage(); }

  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    const lf = document.getElementById('login-form');
    const rf = document.getElementById('reg-form');
    const si = document.getElementById('scan-input');
    if (document.activeElement === si) { doScan(); return; }
    if (lf && lf.style.display !== 'none') doLogin();
    else if (rf && rf.style.display !== 'none') doRegister();
  });
});

// ══════════════════════════════════════════════════════════════
//  PAGE SWITCHES
// ══════════════════════════════════════════════════════════════
function showLoginPage() {
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('dash-page').style.display  = 'none';
}
function showDash() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('dash-page').style.display  = 'block';
  document.getElementById('uname-el').textContent     = username;
}
function showReg() {
  document.getElementById('login-form').style.display = 'none';
  document.getElementById('reg-form').style.display   = 'block';
  clearMsg();
}
function showLogin() {
  document.getElementById('reg-form').style.display   = 'none';
  document.getElementById('login-form').style.display = 'block';
  clearMsg();
}

// ══════════════════════════════════════════════════════════════
//  AUTH MESSAGES
// ══════════════════════════════════════════════════════════════
function showMsg(text, type) {
  const el = document.getElementById('auth-msg');
  el.textContent   = text;
  el.className     = 'auth-msg ' + type;
  el.style.display = 'block';
}
function clearMsg() {
  document.getElementById('auth-msg').style.display = 'none';
}

// ══════════════════════════════════════════════════════════════
//  REGISTER
// ══════════════════════════════════════════════════════════════
async function doRegister() {
  const u = document.getElementById('r-user').value.trim();
  const p = document.getElementById('r-pass').value;
  if (!u || !p) { showMsg('Please fill in all fields.', 'err'); return; }

  const btn = document.getElementById('reg-btn');
  btn.disabled = true; btn.textContent = 'Creating…';

  try {
    const res  = await fetch('/api/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u,password:p}) });
    const data = await res.json();
    if (!res.ok) { showMsg(data.error, 'err'); return; }
    showMsg('Account created! Signing you in…', 'ok');
    document.getElementById('l-user').value = u;
    document.getElementById('l-pass').value = p;
    setTimeout(doLogin, 800);
  } catch {
    showMsg('Cannot reach server. Make sure node server.js is running.', 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Create Account';
  }
}

// ══════════════════════════════════════════════════════════════
//  LOGIN
// ══════════════════════════════════════════════════════════════
async function doLogin() {
  const u = document.getElementById('l-user').value.trim();
  const p = document.getElementById('l-pass').value;
  if (!u || !p) { showMsg('Please enter username and password.', 'err'); return; }

  const btn = document.getElementById('login-btn');
  btn.disabled = true; btn.textContent = 'Signing in…';

  try {
    const res  = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u,password:p}) });
    const data = await res.json();
    if (!res.ok) { showMsg(data.error, 'err'); return; }
    token    = data.token;
    username = data.username;
    localStorage.setItem('ss_token', token);
    localStorage.setItem('ss_user',  username);
    showDash();
    loadDash();
  } catch {
    showMsg('Cannot reach server. Make sure node server.js is running.', 'err');
  } finally {
    btn.disabled = false; btn.textContent = 'Sign In';
  }
}

// ══════════════════════════════════════════════════════════════
//  LOGOUT
// ══════════════════════════════════════════════════════════════
async function doLogout() {
  try { await apiFetch('/api/logout', 'POST'); } catch {}
  token = ''; username = '';
  localStorage.removeItem('ss_token');
  localStorage.removeItem('ss_user');
  showLoginPage();
}

// ══════════════════════════════════════════════════════════════
//  API HELPER
// ══════════════════════════════════════════════════════════════
async function apiFetch(url, method, body) {
  const opts = { method: method || 'GET', headers: {'Content-Type':'application/json','x-auth-token':token} };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (res.status === 401) {
    token = ''; username = '';
    localStorage.removeItem('ss_token'); localStorage.removeItem('ss_user');
    showLoginPage();
    throw new Error('session_expired');
  }
  return res.json();
}

// ══════════════════════════════════════════════════════════════
//  SCAN
// ══════════════════════════════════════════════════════════════
async function doScan() {
  const target = document.getElementById('scan-input').value.trim();
  if (!target) {
    showScanResult('Please enter a folder path or GitHub URL first.', 'error');
    return;
  }

  const btn = document.getElementById('scan-btn');
  btn.disabled = true; btn.textContent = 'Scanning…';

  const isGitHub = target.includes('github.com');
  showScanResult(
    isGitHub
      ? '⏳ Cloning GitHub repository and scanning… this may take 10-30 seconds.'
      : '⏳ Scanning folder for secrets…',
    'loading'
  );

  try {
    const data = await apiFetch('/api/scan', 'POST', { target });
    if (data.error) {
      showScanResult('❌ ' + data.error, 'error');
      return;
    }
    showScanResult('✅ ' + data.message, 'success');
    await loadDash();
  } catch (e) {
    if (e.message !== 'session_expired')
      showScanResult('❌ Could not connect to server.', 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Scan Now';
  }
}

function showScanResult(msg, type) {
  const el = document.getElementById('scan-result');
  el.textContent   = msg;
  el.className     = 'scan-result ' + type;
  el.style.display = 'block';
}

// ══════════════════════════════════════════════════════════════
//  LOAD DASHBOARD
// ══════════════════════════════════════════════════════════════
async function loadDash() {
  try {
    const [leakData, statData] = await Promise.all([apiFetch('/api/leaks'), apiFetch('/api/stats')]);
    allLeaks = leakData.leaks || [];
    renderLeaks();
    renderStats(statData);
  } catch (e) {
    if (e.message !== 'session_expired') console.error(e);
  }
}

// ══════════════════════════════════════════════════════════════
//  RENDER STATS
// ══════════════════════════════════════════════════════════════
function renderStats(s) {
  setText('st-total', s.total    || 0);
  setText('st-crit',  s.critical || 0);
  setText('st-high',  s.high     || 0);
  setText('st-med',   s.medium   || 0);
  setText('st-fixed', s.fixed    || 0);
  setText('st-pend',  s.pending  || 0);
  const g = document.getElementById('grade-el');
  g.textContent = s.grade || '–';
  g.className   = 'grade-circle g' + (s.grade || '');
}

// ══════════════════════════════════════════════════════════════
//  RENDER LEAKS
// ══════════════════════════════════════════════════════════════
function renderLeaks() {
  const list  = document.getElementById('leaks-list');
  const empty = document.getElementById('empty-msg');

  let show = allLeaks;
  if (['critical','high','medium'].includes(curFilter))
    show = allLeaks.filter(l => l.severity === curFilter);
  else if (['pending','fixed','ignored'].includes(curFilter))
    show = allLeaks.filter(l => l.status === curFilter);

  if (allLeaks.length === 0) { empty.style.display = 'block'; list.innerHTML = ''; return; }
  empty.style.display = 'none';

  if (show.length === 0) {
    list.innerHTML = '<div style="padding:32px;text-align:center;color:#4a5568">No leaks match this filter.</div>';
    return;
  }

  list.innerHTML = show.map(l => {
    const fixBtn    = l.status !== 'fixed'   ? `<button class="act-btn act-fix"    onclick="setStatus('${l.id}','fixed')">Mark Fixed</button>`   : '';
    const ignoreBtn = l.status !== 'ignored' ? `<button class="act-btn act-ignore" onclick="setStatus('${l.id}','ignored')">Ignore</button>`      : '';
    const reopenBtn = (l.status === 'fixed' || l.status === 'ignored') ? `<button class="act-btn act-reopen" onclick="setStatus('${l.id}','pending')">Reopen</button>` : '';
    return `
<div class="leak-card sev-${l.severity} status-${l.status}">
  <div class="lc-head">
    <span class="lc-type">${esc(l.type)}</span>
    <span class="badge badge-${l.severity}">${l.severity}</span>
    <span class="badge badge-${l.status}">${l.status}</span>
  </div>
  <div class="lc-meta">📄 ${esc(l.file)} &middot; Line ${l.line} &middot; ${fmtDate(l.detectedAt)}</div>
  <div class="lc-match">${esc(l.match)}</div>
  <div class="lc-actions">
    <button class="act-btn act-guide"  onclick="openModal('${l.id}')">View Fix Guide</button>
    ${fixBtn}${ignoreBtn}${reopenBtn}
    <button class="act-btn act-delete" onclick="deleteLeak('${l.id}')">Delete</button>
  </div>
</div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
//  STATUS / DELETE / CLEAR
// ══════════════════════════════════════════════════════════════
async function setStatus(id, status) {
  try {
    await apiFetch('/api/leak/' + id, 'PATCH', { status });
    const l = allLeaks.find(x => x.id === id);
    if (l) l.status = status;
    renderLeaks();
    renderStats(await apiFetch('/api/stats'));
  } catch (e) { if (e.message !== 'session_expired') alert('Error updating.'); }
}

async function deleteLeak(id) {
  if (!confirm('Permanently delete this leak?')) return;
  try {
    await apiFetch('/api/leak/' + id, 'DELETE');
    allLeaks = allLeaks.filter(l => l.id !== id);
    renderLeaks();
    renderStats(await apiFetch('/api/stats'));
  } catch (e) { if (e.message !== 'session_expired') alert('Error deleting.'); }
}

async function clearAll() {
  if (!confirm('Delete ALL results permanently? Cannot be undone.')) return;
  try {
    await apiFetch('/api/leaks/clear', 'DELETE');
    allLeaks = [];
    renderLeaks();
    renderStats(await apiFetch('/api/stats'));
  } catch (e) { if (e.message !== 'session_expired') alert('Error clearing.'); }
}

// ══════════════════════════════════════════════════════════════
//  FILTER
// ══════════════════════════════════════════════════════════════
function setFilter(btn) {
  curFilter = btn.getAttribute('data-f');
  document.querySelectorAll('.fbtn[data-f]').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  renderLeaks();
}

// ══════════════════════════════════════════════════════════════
//  MODAL
// ══════════════════════════════════════════════════════════════
function openModal(id) {
  const l = allLeaks.find(x => x.id === id);
  if (!l) return;
  document.getElementById('m-title').textContent = l.type;
  document.getElementById('m-badge').innerHTML   = `<span class="badge badge-${l.severity}">${l.severity}</span>`;
  document.getElementById('m-what').textContent  = l.what || 'Sensitive credential found in source code.';
  document.getElementById('m-meta').textContent  = `File: ${l.file}  |  Line: ${l.line}  |  Found: ${fmtDate(l.detectedAt)}`;
  const steps = Array.isArray(l.fixSteps) && l.fixSteps.length
    ? l.fixSteps
    : ['Rotate or revoke this credential in the service dashboard immediately.','Remove the hardcoded value from your source code.','Store it in .env and add .env to .gitignore.'];
  document.getElementById('m-steps').innerHTML = steps.map(s => `<li>${esc(s)}</li>`).join('');
  document.getElementById('modal-bg').style.display = 'flex';
}
function closeModal() { document.getElementById('modal-bg').style.display = 'none'; }
function bgClose(e)   { if (e.target === document.getElementById('modal-bg')) closeModal(); }

// ══════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function esc(s) { return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtDate(iso) { try { const d=new Date(iso); return d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}); } catch { return ''; } }