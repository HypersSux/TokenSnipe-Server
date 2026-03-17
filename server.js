// ET Sniper — License Server v2
// Features: HWID lock, expiry dates, admin dashboard

const express = require('express');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY  = process.env.ADMIN_KEY;

if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET not set'); process.exit(1); }
if (!ADMIN_KEY)  { console.error('FATAL: ADMIN_KEY not set');  process.exit(1); }

// ── KEYS DB ───────────────────────────────────────────────────────────────
const KEYS_FILE = path.join(__dirname, 'keys.json');
function loadKeys() {
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); }
  catch { return {}; }
}
function saveKeys(k) { fs.writeFileSync(KEYS_FILE, JSON.stringify(k, null, 2)); }

// ── MIDDLEWARE ────────────────────────────────────────────────────────────
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-et-token, x-hwid, x-admin-key');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Rate limiter
const rlMap = new Map();
function rateLimit(key, max) {
  const now = Date.now();
  const e   = rlMap.get(key) || { count: 0, reset: now + 60000 };
  if (now > e.reset) { e.count = 0; e.reset = now + 60000; }
  e.count++; rlMap.set(key, e);
  return e.count > max;
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const k = req.headers['x-admin-key'] || req.query.ak;
  if (k !== ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
}

function requireToken(req, res, next) {
  const token = req.headers['x-et-token'];
  const hwid  = req.headers['x-hwid'];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const keys    = loadKeys();
    const entry   = keys[payload.key];
    if (!entry || entry.active === false)
      return res.status(401).json({ error: 'Key revoked' });
    if (entry.expiresAt && new Date() > new Date(entry.expiresAt))
      return res.status(401).json({ error: 'Key expired' });
    if (entry.hwid && entry.hwid !== hwid)
      return res.status(401).json({ error: 'HWID mismatch' });
    req.keyPayload = payload;
    next();
  } catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ── PUBLIC ROUTES ─────────────────────────────────────────────────────────

app.post('/validate', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ valid: false, error: 'Missing fields' });

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (rateLimit(ip, 5)) return res.status(429).json({ valid: false, error: 'Too many attempts. Wait a minute.' });

  const keys  = loadKeys();
  const entry = keys[key];

  if (!entry || entry.active === false)
    return res.json({ valid: false, error: 'Invalid or revoked key' });

  if (entry.expiresAt && new Date() > new Date(entry.expiresAt))
    return res.json({ valid: false, error: 'Key has expired' });

  // HWID lock — lock on first use, reject mismatches after
  if (!entry.hwid) {
    entry.hwid      = hwid;
    entry.lockedAt  = new Date().toISOString();
  } else if (entry.hwid !== hwid) {
    return res.json({ valid: false, error: 'Key is locked to another device' });
  }

  entry.lastUsed    = new Date().toISOString();
  entry.activations = (entry.activations || 0) + 1;
  saveKeys(keys);

  const token = jwt.sign({ key, hwid }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ valid: true, token });
});

app.get('/heartbeat', requireToken, (req, res) => res.json({ ok: true }));

// ── ADMIN API ─────────────────────────────────────────────────────────────

app.get('/admin/keys', requireAdmin, (req, res) => res.json(loadKeys()));

app.post('/admin/keys/create', requireAdmin, (req, res) => {
  const { note, days } = req.body;
  const key       = 'ET-' + crypto.randomBytes(8).toString('hex').toUpperCase();
  const keys      = loadKeys();
  const expiresAt = days && days !== 'lifetime'
    ? new Date(Date.now() + parseInt(days) * 86400000).toISOString()
    : null;
  keys[key] = {
    active: true,
    created: new Date().toISOString(),
    note: note || '',
    days: days || 'lifetime',
    expiresAt,
    activations: 0,
    hwid: null,
    lastUsed: null,
  };
  saveKeys(keys);
  res.json({ key, expiresAt });
});

app.post('/admin/keys/revoke', requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: 'Not found' });
  keys[key].active = false;
  saveKeys(keys);
  res.json({ ok: true });
});

app.post('/admin/keys/reactivate', requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: 'Not found' });
  keys[key].active = true;
  saveKeys(keys);
  res.json({ ok: true });
});

app.post('/admin/keys/reset-hwid', requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: 'Not found' });
  keys[key].hwid     = null;
  keys[key].lockedAt = null;
  saveKeys(keys);
  res.json({ ok: true });
});

app.post('/admin/keys/delete', requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: 'Not found' });
  delete keys[key];
  saveKeys(keys);
  res.json({ ok: true });
});

// ── ADMIN DASHBOARD ───────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:;");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ET Sniper Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#07090f;--surf:#0e1420;--card:#131c2e;--border:rgba(59,130,246,0.15);--blue:#3b82f6;--blt:#60a5fa;--t1:#f1f5f9;--t2:#94a3b8;--t3:#475569;--green:#10b981;--red:#ef4444;--gold:#f59e0b;--purple:#a78bfa}
body{background:var(--bg);color:var(--t1);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}
#login{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-box{background:var(--surf);border:1px solid var(--border);border-radius:16px;padding:36px;width:100%;max-width:360px;display:flex;flex-direction:column;gap:16px;text-align:center}
.login-box h1{font-size:20px;font-weight:700}
input,select{width:100%;padding:9px 13px;background:var(--card);border:1px solid var(--border);border-radius:8px;color:var(--t1);font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
input:focus{border-color:rgba(59,130,246,0.5)}
select option{background:var(--card)}
#app{display:none;flex-direction:column;min-height:100vh}
.topbar{background:var(--surf);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.topbar h1{font-size:15px;font-weight:700}
.topbar-badge{font-size:10px;padding:2px 8px;background:rgba(59,130,246,.1);border:1px solid var(--border);border-radius:20px;color:var(--blt);margin-left:10px}
.main{padding:20px 24px;display:flex;flex-direction:column;gap:16px;max-width:1200px;margin:0 auto;width:100%}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.stat-val{font-size:26px;font-weight:700;margin-bottom:2px}
.stat-label{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em}
.create-card{background:var(--surf);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.create-card h2{font-size:11px;font-weight:700;margin-bottom:12px;color:var(--t3);text-transform:uppercase;letter-spacing:.08em}
.create-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:10px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.field input,.field select{min-width:160px}
.keys-card{background:var(--surf);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.keys-header{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.keys-header h2{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.08em}
.search{padding:6px 12px;background:var(--card);border:1px solid var(--border);border-radius:7px;color:var(--t1);font-size:12px;font-family:inherit;outline:none;width:220px}
table{width:100%;border-collapse:collapse}
th{padding:8px 12px;text-align:left;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid rgba(59,130,246,0.05);font-size:12px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(59,130,246,0.03)}
.key-mono{font-family:monospace;font-size:12px;color:var(--blt);font-weight:600;cursor:pointer}
.key-mono:hover{color:#93c5fd}
.badge{display:inline-flex;align-items:center;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}
.badge.active{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.25);color:var(--green)}
.badge.revoked{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:var(--red)}
.badge.expired{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);color:var(--gold)}
.badge.locked{background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);color:var(--purple)}
.badge.free{background:rgba(100,116,139,.1);border:1px solid rgba(100,116,139,.2);color:var(--t3)}
.actions{display:flex;gap:4px;flex-wrap:wrap}
button{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;font-family:inherit;cursor:pointer;border:1px solid;transition:all .15s;white-space:nowrap}
.btn-primary{padding:9px 20px;background:linear-gradient(135deg,#1e40af,#3b82f6);border-color:rgba(59,130,246,.5);color:#fff;font-size:12px;border-radius:8px}
.btn-primary:hover{opacity:.9}
.btn-revoke{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.3);color:#f87171}
.btn-revoke:hover{background:rgba(239,68,68,.2)}
.btn-activate{background:rgba(16,185,129,.08);border-color:rgba(16,185,129,.3);color:var(--green)}
.btn-activate:hover{background:rgba(16,185,129,.2)}
.btn-hwid{background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.3);color:var(--purple)}
.btn-hwid:hover{background:rgba(167,139,250,.2)}
.btn-delete{background:rgba(239,68,68,.04);border-color:rgba(100,116,139,.2);color:var(--t3)}
.btn-delete:hover{background:rgba(239,68,68,.15);color:#f87171}
.btn-logout{background:transparent;border-color:var(--border);color:var(--t3)}
.btn-logout:hover{border-color:rgba(239,68,68,.3);color:#f87171}
.filter-tabs{display:flex;gap:4px}
.ftab{background:transparent;border:1px solid var(--border);color:var(--t3);border-radius:20px;padding:3px 12px;font-size:11px}
.ftab.on{background:rgba(59,130,246,.1);border-color:rgba(59,130,246,.3);color:var(--blt)}
.note-col{color:var(--t2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.expiry-ok{color:var(--green)}
.expiry-soon{color:var(--gold)}
.expiry-exp{color:var(--red)}
.expiry-never{color:var(--t3)}
.new-key-box{margin-top:12px;padding:10px 14px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);border-radius:8px;display:none}
.new-key-box p{font-size:10px;color:var(--t3);margin-bottom:4px}
.new-key-val{font-family:monospace;font-size:15px;color:var(--green);font-weight:700;cursor:pointer}
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;background:var(--card);border:1px solid var(--border);border-radius:10px;font-size:12px;font-weight:600;z-index:100;animation:tin .2s ease;pointer-events:none}
.toast.ok{border-color:rgba(16,185,129,.4);color:var(--green)}
.toast.err{border-color:rgba(239,68,68,.4);color:var(--red)}
@keyframes tin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.empty-row td{text-align:center;padding:32px;color:var(--t3)}
</style>
</head>
<body>

<div id="login">
  <div class="login-box">
    <div>
      <div style="font-size:32px;margin-bottom:8px">🔑</div>
      <h1>ET Sniper Admin</h1>
      <p style="color:var(--t3);font-size:12px;margin-top:6px">Enter your admin key to continue</p>
    </div>
    <input id="ak" type="password" placeholder="Admin key..." />
    <button class="btn-primary" onclick="doLogin()">Login</button>
    <div id="lerr" style="color:var(--red);font-size:11px;min-height:14px"></div>
  </div>
</div>

<div id="app">
  <div class="topbar">
    <div style="display:flex;align-items:center">
      <h1>ET Sniper — Key Manager</h1>
      <span class="topbar-badge" id="total-badge">0 keys</span>
    </div>
    <button class="btn-logout" onclick="logout()">Logout</button>
  </div>

  <div class="main">
    <div class="stats">
      <div class="stat"><div class="stat-val" id="s-total" style="color:var(--blt)">0</div><div class="stat-label">Total Keys</div></div>
      <div class="stat"><div class="stat-val" id="s-active" style="color:var(--green)">0</div><div class="stat-label">Active</div></div>
      <div class="stat"><div class="stat-val" id="s-revoked" style="color:var(--red)">0</div><div class="stat-label">Revoked</div></div>
      <div class="stat"><div class="stat-val" id="s-expired" style="color:var(--gold)">0</div><div class="stat-label">Expired</div></div>
      <div class="stat"><div class="stat-val" id="s-uses" style="color:var(--purple)">0</div><div class="stat-label">Total Uses</div></div>
    </div>

    <div class="create-card">
      <h2>Generate New Key</h2>
      <div class="create-row">
        <div class="field">
          <label>Note / Username</label>
          <input id="c-note" type="text" placeholder="e.g. Discord user xyz" />
        </div>
        <div class="field">
          <label>Duration</label>
          <select id="c-days">
            <option value="1">1 day</option>
            <option value="3">3 days</option>
            <option value="7">7 days</option>
            <option value="14">14 days</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="180">6 months</option>
            <option value="365">1 year</option>
            <option value="lifetime" selected>Lifetime</option>
          </select>
        </div>
        <button class="btn-primary" onclick="createKey()">+ Generate Key</button>
      </div>
      <div class="new-key-box" id="new-key-box">
        <p>New key created — click to copy:</p>
        <div class="new-key-val" id="new-key-val" onclick="copyText(this.textContent)"></div>
      </div>
    </div>

    <div class="keys-card">
      <div class="keys-header">
        <h2>All Keys</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <div class="filter-tabs">
            <button class="ftab on" onclick="setFilter('all',this)">All</button>
            <button class="ftab" onclick="setFilter('active',this)">Active</button>
            <button class="ftab" onclick="setFilter('revoked',this)">Revoked</button>
            <button class="ftab" onclick="setFilter('expired',this)">Expired</button>
          </div>
          <input class="search" type="text" id="search" placeholder="Search key or note..." oninput="renderTable()" />
        </div>
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Key</th><th>Note</th><th>Status</th><th>HWID</th><th>Expires</th><th>Uses</th><th>Last Used</th><th>Actions</th>
            </tr>
          </thead>
          <tbody id="keys-body"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
let adminKey='',keysData={},filterMode='all';

function doLogin(){
  adminKey=document.getElementById('ak').value.trim();
  if(!adminKey)return;
  fetchKeys().then(ok=>{
    if(ok){
      document.getElementById('login').style.display='none';
      document.getElementById('app').style.display='flex';
    }else{
      document.getElementById('lerr').textContent='Invalid admin key.';
    }
  });
}
document.getElementById('ak').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});

function logout(){
  adminKey='';keysData={};
  document.getElementById('login').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('ak').value='';
}

async function api(path,method='GET',body=null){
  const opts={method,headers:{'x-admin-key':adminKey,'Content-Type':'application/json'}};
  if(body)opts.body=JSON.stringify(body);
  const res=await fetch(path,opts);
  return res.json();
}

async function fetchKeys(){
  try{
    const data=await api('/admin/keys');
    if(data.error)return false;
    keysData=data;renderTable();updateStats();return true;
  }catch{return false;}
}

function updateStats(){
  const vals=Object.values(keysData),now=new Date();
  document.getElementById('s-total').textContent=vals.length;
  document.getElementById('s-active').textContent=vals.filter(k=>k.active&&(!k.expiresAt||new Date(k.expiresAt)>now)).length;
  document.getElementById('s-revoked').textContent=vals.filter(k=>!k.active).length;
  document.getElementById('s-expired').textContent=vals.filter(k=>k.active&&k.expiresAt&&new Date(k.expiresAt)<=now).length;
  document.getElementById('s-uses').textContent=vals.reduce((a,k)=>a+(k.activations||0),0);
  document.getElementById('total-badge').textContent=vals.length+' keys';
}

function setFilter(mode,el){
  filterMode=mode;
  document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('on'));
  el.classList.add('on');renderTable();
}

function getStatus(k){
  const now=new Date();
  if(!k.active)return'revoked';
  if(k.expiresAt&&new Date(k.expiresAt)<=now)return'expired';
  return'active';
}

function fmtExpiry(k){
  if(!k.expiresAt)return'<span class="expiry-never">Lifetime</span>';
  const now=new Date(),exp=new Date(k.expiresAt),diff=exp-now,days=Math.ceil(diff/86400000),str=exp.toLocaleDateString();
  if(diff<=0)return'<span class="expiry-exp">'+str+' (expired)</span>';
  if(days<=3)return'<span class="expiry-soon">'+str+' ('+days+'d left)</span>';
  return'<span class="expiry-ok">'+str+'</span>';
}

function fmtDate(d){
  if(!d)return'<span style="color:var(--t3)">Never</span>';
  return new Date(d).toLocaleDateString()+' '+new Date(d).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
}

function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

function renderTable(){
  const search=document.getElementById('search').value.toLowerCase();
  const body=document.getElementById('keys-body');
  let entries=Object.entries(keysData);
  entries=entries.filter(([k,v])=>{
    const st=getStatus(v);
    if(filterMode!=='all'&&st!==filterMode)return false;
    if(search&&!k.toLowerCase().includes(search)&&!(v.note||'').toLowerCase().includes(search))return false;
    return true;
  });
  entries.sort((a,b)=>new Date(b[1].created)-new Date(a[1].created));
  if(!entries.length){body.innerHTML='<tr class="empty-row"><td colspan="8">No keys found</td></tr>';return;}
  body.innerHTML=entries.map(([k,v])=>{
    const st=getStatus(v);
    const hwidBadge=v.hwid?'<span class="badge locked">Locked</span>':'<span class="badge free">Free</span>';
    let actions='';
    if(st==='revoked'){
      actions='<button class="btn-activate" onclick="reactivate(\''+k+'\')">Reactivate</button>'
              +'<button class="btn-delete" onclick="del(\''+k+'\')">Delete</button>';
    }else{
      actions='<button class="btn-revoke" onclick="revoke(\''+k+'\')">Revoke</button>'
              +(v.hwid?'<button class="btn-hwid" onclick="resetHwid(\''+k+'\')">Reset HWID</button>':'')
              +'<button class="btn-delete" onclick="del(\''+k+'\')">Delete</button>';
    }
    return'<tr>'
      +'<td><span class="key-mono" onclick="copyText(\''+k+'\')" title="Click to copy">'+k+'</span></td>'
      +'<td><span class="note-col" title="'+esc(v.note||'')+'">'+esc(v.note||'—')+'</span></td>'
      +'<td><span class="badge '+st+'">'+st.charAt(0).toUpperCase()+st.slice(1)+'</span></td>'
      +'<td>'+hwidBadge+'</td>'
      +'<td>'+fmtExpiry(v)+'</td>'
      +'<td style="color:var(--purple)">'+(v.activations||0)+'</td>'
      +'<td style="color:var(--t3);font-size:11px">'+fmtDate(v.lastUsed)+'</td>'
      +'<td><div class="actions">'+actions+'</div></td>'
      +'</tr>';
  }).join('');
}

async function createKey(){
  const note=document.getElementById('c-note').value.trim();
  const days=document.getElementById('c-days').value;
  const data=await api('/admin/keys/create','POST',{note,days});
  if(data.key){
    document.getElementById('new-key-box').style.display='block';
    document.getElementById('new-key-val').textContent=data.key;
    copyText(data.key);
    toast('Key created + copied!','ok');
    await fetchKeys();
  }else toast('Error creating key','err');
}

async function revoke(key){
  if(!confirm('Revoke '+key+'?\\nUser will be kicked within 5 minutes.'))return;
  const data=await api('/admin/keys/revoke','POST',{key});
  if(data.ok){toast('Key revoked','ok');await fetchKeys();}else toast('Error','err');
}

async function reactivate(key){
  const data=await api('/admin/keys/reactivate','POST',{key});
  if(data.ok){toast('Key reactivated','ok');await fetchKeys();}else toast('Error','err');
}

async function resetHwid(key){
  if(!confirm('Reset HWID for '+key+'?\\nKey can be used on a new device.'))return;
  const data=await api('/admin/keys/reset-hwid','POST',{key});
  if(data.ok){toast('HWID reset','ok');await fetchKeys();}else toast('Error','err');
}

async function del(key){
  if(!confirm('Permanently DELETE '+key+'? Cannot be undone.'))return;
  const data=await api('/admin/keys/delete','POST',{key});
  if(data.ok){toast('Key deleted','ok');await fetchKeys();}else toast('Error','err');
}

function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('Copied: '+t,'ok'));}

let tTimer;
function toast(msg,type='ok'){
  const el=document.createElement('div');
  el.className='toast '+type;el.textContent=msg;
  document.body.appendChild(el);
  clearTimeout(tTimer);tTimer=setTimeout(()=>el.remove(),2800);
}

setInterval(()=>{if(adminKey)fetchKeys();},30000);
</script>
</body>
</html>`);
});

app.listen(PORT, () => console.log('ET Sniper server running on port', PORT));
