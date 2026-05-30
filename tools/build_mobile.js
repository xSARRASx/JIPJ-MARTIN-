#!/usr/bin/env node
/* Génère coffre-mobile.html : un fichier UNIQUE, tout en un,
   qui contient HTML + CSS + JS + données chiffrées.
   Marche sur iPhone (Files -> Safari), Mac, n'importe quel ordi. */

const fs = require('fs');

const data = fs.readFileSync('data.enc.json', 'utf8');
const blob = JSON.parse(data);
const dataB64 = Buffer.from(data, 'utf8').toString('base64');

const html = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1, user-scalable=no" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<meta name="apple-mobile-web-app-title" content="Coffre" />
<meta name="theme-color" content="#0a0e1a" />
<meta name="robots" content="noindex, nofollow" />
<title>Coffre — Martin</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80'%3E%F0%9F%94%90%3C/text%3E%3C/svg%3E" />
<link rel="apple-touch-icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%230a0e1a'/%3E%3Ctext y='75' x='50' text-anchor='middle' font-size='60'%3E%F0%9F%94%90%3C/text%3E%3C/svg%3E" />
<style>
*,*::before,*::after{box-sizing:border-box}*{margin:0;padding:0}[hidden]{display:none!important}
html,body{height:100%;overscroll-behavior:none;-webkit-tap-highlight-color:transparent}
body{font:15px/1.4 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif;
  background:radial-gradient(ellipse 100% 60% at 20% 0%,#1a1438 0%,transparent 60%),
             radial-gradient(ellipse 100% 60% at 100% 100%,#0a2840 0%,transparent 55%),#07091a;
  color:#e8ecf4;-webkit-font-smoothing:antialiased;padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)}
button,input{font:inherit;color:inherit;background:none;border:0;outline:0}
button{cursor:pointer}
input{-webkit-appearance:none;appearance:none}
/* lock screen */
.lock{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:24px;background:inherit}
.lock-card{width:100%;max-width:380px;text-align:center}
.lock-emoji{font-size:54px;line-height:1;margin-bottom:14px}
.lock h1{font-size:28px;font-weight:700;letter-spacing:-.02em}
.lock-sub{color:#8b95a8;margin:6px 0 28px;font-size:14px}
.field{position:relative;margin-bottom:14px}
.field input{width:100%;padding:16px 50px 16px 18px;border-radius:14px;background:#141b2d;
  border:1px solid #2a3552;font-size:16px;color:#fff;text-align:center}
.field input:focus{border-color:#7c5cff;background:#171f36}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:40px;height:40px;
  display:flex;align-items:center;justify-content:center;color:#8b95a8;border-radius:10px}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;
  width:100%;padding:16px;border-radius:14px;font-weight:600;font-size:16px;
  background:linear-gradient(135deg,#7c5cff 0%,#00d4ff 100%);color:#fff;
  box-shadow:0 8px 24px -8px rgba(124,92,255,.6)}
.btn:active{transform:translateY(1px)}
.btn[disabled]{opacity:.6}
.err{color:#ff7585;font-size:13px;margin-top:10px;min-height:18px}
.lock-foot{color:#5d6779;font-size:12px;margin-top:24px}
/* app shell */
.app{display:flex;flex-direction:column;height:100vh;height:100dvh}
.topbar{padding:14px 16px 8px;border-bottom:1px solid rgba(255,255,255,.05);background:rgba(7,9,26,.85);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);position:sticky;top:0;z-index:10}
.tabs{display:flex;gap:4px;padding:3px;background:rgba(7,9,26,.5);border-radius:11px;margin-bottom:10px}
.tab{flex:1;padding:8px;border-radius:8px;font-weight:600;font-size:13px;color:#8b95a8;
  transition:background .15s,color .15s}
.tab.active{background:linear-gradient(135deg,#7c5cff 0%,#00d4ff 100%);color:#fff;
  box-shadow:0 4px 12px -4px rgba(124,92,255,.6)}
.search{position:relative}
.search input{width:100%;padding:11px 16px 11px 40px;background:#141b2d;border:1px solid #2a3552;
  border-radius:11px;font-size:15px;color:#fff}
.search::before{content:"🔎";position:absolute;left:14px;top:50%;transform:translateY(-50%);
  font-size:14px;opacity:.6}
.cats{display:flex;gap:6px;padding:10px 16px 4px;overflow-x:auto;-webkit-overflow-scrolling:touch;
  scrollbar-width:none;background:rgba(7,9,26,.55)}
.cats::-webkit-scrollbar{display:none}
.cat{flex-shrink:0;padding:7px 13px;border-radius:18px;background:#141b2d;border:1px solid #2a3552;
  font-size:13px;font-weight:500;color:#cfd6e8;white-space:nowrap}
.cat.active{background:linear-gradient(135deg,#7c5cff,#00d4ff);color:#fff;border-color:transparent}
.cat-n{opacity:.7;margin-left:6px;font-size:11px}
/* content */
.scroll{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch}
.list{padding:10px 14px 30px}
.empty{padding:60px 30px;text-align:center;color:#8b95a8}
.empty-i{font-size:46px;margin-bottom:10px}
.empty h2{color:#fff;font-size:18px;margin-bottom:6px}
.card{background:linear-gradient(180deg,rgba(22,28,46,.85),rgba(18,23,39,.85));
  border:1px solid rgba(255,255,255,.05);border-radius:14px;margin-bottom:8px;overflow:hidden}
.card-head{display:flex;align-items:center;gap:12px;padding:13px 14px;width:100%;text-align:left}
.card-ico{width:38px;height:38px;display:flex;align-items:center;justify-content:center;
  background:rgba(124,92,255,.15);border-radius:10px;font-size:20px;flex-shrink:0}
.card-txt{flex:1;min-width:0}
.card-name{font-weight:600;font-size:15px;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card-sub{color:#8b95a8;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px}
.chev{color:#5d6779;transition:transform .2s;flex-shrink:0}
.card.open .chev{transform:rotate(180deg)}
.card-body{display:none;padding:0 12px 12px;border-top:1px solid rgba(255,255,255,.05);padding-top:10px;margin-top:2px}
.card.open .card-body{display:block;animation:fadeIn .2s}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.row{background:rgba(7,9,26,.6);border-radius:10px;padding:10px 12px;margin-bottom:6px}
.row-lab{font-size:10px;font-weight:700;letter-spacing:.06em;color:#8b95a8;text-transform:uppercase;margin-bottom:4px}
.row-val{display:flex;align-items:center;gap:8px}
.row-val .v{flex:1;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:13.5px;
  word-break:break-all;color:#e8ecf4;line-height:1.4}
.row-val.multi .v{white-space:pre-wrap}
.mini{padding:6px 10px;border-radius:8px;background:rgba(124,92,255,.18);color:#cfb6ff;
  font-size:11.5px;font-weight:600;flex-shrink:0}
.mini:active{background:rgba(124,92,255,.3)}
.mini.icon{padding:6px 8px}
/* planning */
.plan-head{padding:16px 16px 8px}
.plan-title{font-size:22px;font-weight:700;letter-spacing:-.02em}
.daily{margin:12px 0 4px;padding:11px 13px;background:linear-gradient(135deg,rgba(124,92,255,.14),rgba(0,212,255,.06));
  border:1px solid rgba(124,92,255,.22);border-radius:13px}
.daily-lab{font-size:10.5px;font-weight:700;letter-spacing:.06em;color:#b8c3e0;text-transform:uppercase;margin-bottom:7px}
.daily-tags{display:flex;flex-wrap:wrap;gap:6px}
.daily-tag{font-size:12px;padding:4px 10px;background:rgba(255,255,255,.06);border-radius:14px}
.days{padding:8px 14px 30px}
.day{background:linear-gradient(180deg,rgba(22,28,46,.85),rgba(18,23,39,.85));
  border:1px solid rgba(255,255,255,.05);border-top:3px solid var(--c,#7c5cff);
  border-radius:14px;padding:13px 15px 14px;margin-bottom:10px}
.day-name{font-weight:700;font-size:13.5px;color:#fff;text-transform:uppercase;letter-spacing:.04em;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.day-name::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--c,#7c5cff);box-shadow:0 0 8px var(--c,#7c5cff)}
.day-tasks{list-style:none;display:flex;flex-direction:column;gap:6px}
.task{display:flex;gap:9px;padding:8px 10px;background:rgba(7,9,26,.55);border-radius:9px;font-size:13px;line-height:1.35}
.task-i{flex-shrink:0;font-size:14px}
/* lock btn */
.lock-btn{position:fixed;bottom:max(14px,env(safe-area-inset-bottom));right:14px;z-index:20;
  width:48px;height:48px;border-radius:50%;background:rgba(20,27,45,.95);border:1px solid #2a3552;
  display:flex;align-items:center;justify-content:center;font-size:18px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.lock-btn:active{background:#2a3552}
/* toast */
.toast{position:fixed;bottom:max(80px,env(safe-area-inset-bottom));left:50%;transform:translateX(-50%);
  padding:11px 18px;border-radius:11px;background:rgba(0,200,150,.95);color:#fff;font-weight:600;font-size:14px;
  z-index:100;box-shadow:0 10px 30px -10px rgba(0,0,0,.6);animation:up .2s}
.toast.err{background:rgba(255,90,108,.95)}
@keyframes up{from{transform:translate(-50%,12px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
</style>
</head>
<body>

<div id="lock" class="lock">
  <div class="lock-card">
    <div class="lock-emoji">🔐</div>
    <h1>Coffre</h1>
    <p class="lock-sub">Entre ton mot de passe maître</p>
    <form id="unlock">
      <div class="field">
        <input id="mp" type="password" placeholder="Mot de passe maître"
               autocomplete="current-password" required autocapitalize="off" autocorrect="off" />
        <button type="button" class="eye" id="eye" aria-label="Afficher">👁</button>
      </div>
      <button type="submit" class="btn" id="unlockBtn">Déverrouiller</button>
      <p id="err" class="err"></p>
    </form>
    <p class="lock-foot">🔒 Chiffré · hors-ligne · sur ce téléphone</p>
  </div>
</div>

<div id="app" class="app" hidden>
  <div class="topbar">
    <div class="tabs">
      <button class="tab active" data-tab="vault">🔐 Coffre</button>
      <button class="tab" data-tab="plan">📅 Planning</button>
    </div>
    <div class="search" id="searchWrap"><input id="search" type="search"
      placeholder="Rechercher…" autocomplete="off" autocapitalize="off" /></div>
  </div>
  <div id="cats" class="cats"></div>
  <div class="scroll" id="scroll">
    <div id="vaultView" class="list"></div>
    <div id="planView" hidden></div>
  </div>
</div>

<button id="lockBtn" class="lock-btn" hidden aria-label="Verrouiller">🔒</button>

<script>
// Données chiffrées (base64 du JSON {salt,iv,iterations,data})
const VAULT_DATA = "${dataB64}";

const $ = s => document.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();
const b64d = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
const esc = s => String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

let vault=null, view="vault", cat="all", q="", lockTimer=null;
const blob = JSON.parse(atob(VAULT_DATA));

async function unlock(pw){
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:b64d(blob.salt), iterations:blob.iterations||250000, hash:"SHA-256"},
    baseKey, {name:"AES-GCM", length:256}, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({name:"AES-GCM", iv:b64d(blob.iv)}, key, b64d(blob.data));
  return JSON.parse(dec.decode(plain));
}

function toast(msg, type){
  const t=document.createElement("div");
  t.className="toast"+(type==="err"?" err":"");
  t.textContent=msg; document.body.appendChild(t);
  setTimeout(()=>t.remove(),1600);
}
async function copy(text){
  try{ await navigator.clipboard.writeText(text); toast("Copié ✓"); }
  catch{
    const ta=document.createElement("textarea");
    ta.value=text; ta.style.cssText="position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand("copy"); toast("Copié ✓"); }
    catch{ toast("Impossible de copier","err"); }
    ta.remove();
  }
}
function bumpLock(){
  if(lockTimer) clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, 15*60*1000);
}
function lock(){
  vault=null;
  $("#app").hidden=true;
  $("#lockBtn").hidden=true;
  $("#lock").hidden=false;
  $("#mp").value=""; $("#err").textContent="";
  if(lockTimer){ clearTimeout(lockTimer); lockTimer=null; }
  setTimeout(()=>$("#mp").focus(),100);
}

$("#eye").onclick = () => {
  const i=$("#mp"); i.type = i.type==="password"?"text":"password";
};
$("#lockBtn").onclick = lock;
document.querySelectorAll(".tab").forEach(b=>{
  b.onclick = () => { view=b.dataset.tab; renderApp(); bumpLock(); };
});
$("#search").addEventListener("input", e=>{ q=e.target.value; renderVault(); bumpLock(); });
document.addEventListener("touchstart", bumpLock, {passive:true});
document.addEventListener("click", bumpLock);

$("#unlock").addEventListener("submit", async e=>{
  e.preventDefault();
  const btn=$("#unlockBtn"); btn.disabled=true; btn.textContent="Déchiffrement…";
  $("#err").textContent="";
  try{
    vault = await unlock($("#mp").value);
    $("#lock").hidden=true;
    $("#app").hidden=false;
    $("#lockBtn").hidden=false;
    renderApp(); bumpLock();
  }catch(err){
    $("#err").textContent="Mot de passe incorrect.";
    $("#mp").select();
  }finally{
    btn.disabled=false; btn.textContent="Déverrouiller";
  }
});

function renderApp(){
  document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t.dataset.tab===view));
  const isVault = view==="vault";
  $("#vaultView").hidden = !isVault;
  $("#planView").hidden = isVault;
  $("#cats").hidden = !isVault;
  $("#searchWrap").hidden = !isVault;
  if(isVault){ renderCats(); renderVault(); }
  else renderPlanning();
}

function renderCats(){
  const counts={}; vault.entries.forEach(e=>counts[e.category]=(counts[e.category]||0)+1);
  const items = [{id:"all", name:"Tout", icon:"📁", n:vault.entries.length}];
  vault.categories.forEach(c=>{ if(counts[c.id]) items.push({...c, n:counts[c.id]}); });
  $("#cats").innerHTML = items.map(c=>
    \`<button class="cat \${c.id===cat?"active":""}" data-cat="\${c.id}">\${c.icon||""} \${esc(c.name)}<span class="cat-n">\${c.n}</span></button>\`
  ).join("");
  document.querySelectorAll(".cat").forEach(b=>{
    b.onclick = () => { cat=b.dataset.cat; renderCats(); renderVault(); bumpLock(); };
  });
}

function renderVault(){
  const ql=q.trim().toLowerCase();
  let list = vault.entries;
  if(cat!=="all") list = list.filter(e=>e.category===cat);
  if(ql) list = list.filter(e=>["name","username","email","url","notes","category"].some(k=>String(e[k]||"").toLowerCase().includes(ql)));
  list = list.slice().sort((a,b)=>(a.name||"").localeCompare(b.name||"","fr",{sensitivity:"base"}));
  const catsMap = Object.fromEntries(vault.categories.map(c=>[c.id,c]));
  if(!list.length){
    $("#vaultView").innerHTML = '<div class="empty"><div class="empty-i">🔍</div><h2>Aucun résultat</h2><p>Essaie un autre terme.</p></div>';
    return;
  }
  $("#vaultView").innerHTML = list.map(e=>{
    const ic = e.icon || (catsMap[e.category]||{}).icon || "🔑";
    const sub = e.email || e.username || e.url || "";
    return \`<div class="card" data-id="\${esc(e.id||e.name)}">
      <button class="card-head"><div class="card-ico">\${ic}</div>
        <div class="card-txt"><div class="card-name">\${esc(e.name||"")}</div>
        <div class="card-sub">\${esc(sub)}</div></div>
        <span class="chev">▼</span></button>
      <div class="card-body" data-body></div></div>\`;
  }).join("");
  document.querySelectorAll(".card").forEach(card=>{
    card.querySelector(".card-head").onclick = () => {
      const open = card.classList.contains("open");
      document.querySelectorAll(".card.open").forEach(c=>{ c.classList.remove("open"); c.querySelector("[data-body]").innerHTML=""; });
      if(!open){
        const e = list.find(x=>(x.id||x.name)===card.dataset.id);
        card.querySelector("[data-body]").innerHTML = entryBody(e);
        card.classList.add("open");
        bindRows(card, e);
      }
      bumpLock();
    };
  });
}

function entryBody(e){
  const rows=[];
  if(e.email)    rows.push({lab:"Email",       v:e.email,    secret:false});
  if(e.username) rows.push({lab:"Identifiant", v:e.username, secret:false});
  if(e.password) rows.push({lab:"Mot de passe",v:e.password, secret:true});
  if(e.url)      rows.push({lab:"Lien",        v:e.url,      secret:false, link:true});
  (e.extra||[]).forEach(x=>rows.push({lab:x.label, v:x.value, secret:!!x.secret, multi:!!x.multiline}));
  if(e.notes)    rows.push({lab:"Notes",       v:e.notes,    secret:false, multi:true});
  return rows.map((r,i)=>{
    const dot = r.secret ? "•".repeat(Math.min(14,r.v.length)) : esc(r.v);
    return \`<div class="row">
      <div class="row-lab">\${esc(r.lab)}</div>
      <div class="row-val \${r.multi?"multi":""}">
        <div class="v" data-i="\${i}" data-secret="\${r.secret?1:0}">\${r.secret?dot:(r.link?\`<a href="\${esc(r.v)}" target="_blank" rel="noopener" style="color:#9ad4ff;text-decoration:none">\${esc(r.v)}</a>\`:esc(r.v))}</div>
        \${r.secret?'<button class="mini icon" data-act="show" data-i="'+i+'" aria-label="Afficher">👁</button>':''}
        <button class="mini" data-act="copy" data-i="\${i}">Copier</button>
      </div></div>\`;
  }).join("");
}

function bindRows(card, e){
  const rows=[];
  if(e.email)    rows.push({v:e.email,    secret:false});
  if(e.username) rows.push({v:e.username, secret:false});
  if(e.password) rows.push({v:e.password, secret:true});
  if(e.url)      rows.push({v:e.url,      secret:false});
  (e.extra||[]).forEach(x=>rows.push({v:x.value, secret:!!x.secret}));
  if(e.notes)    rows.push({v:e.notes,    secret:false});
  card.querySelectorAll("[data-act]").forEach(btn=>{
    btn.onclick = (ev) => {
      ev.stopPropagation();
      const i = +btn.dataset.i;
      if(btn.dataset.act==="copy"){ copy(rows[i].v); }
      else{
        const target = card.querySelector('.v[data-i="'+i+'"]');
        const isShown = btn.textContent.includes("Mas") || btn.getAttribute("data-shown")==="1";
        if(isShown){
          target.innerHTML = "•".repeat(Math.min(14,rows[i].v.length));
          btn.textContent="👁"; btn.setAttribute("data-shown","0");
        }else{
          target.textContent = rows[i].v;
          btn.textContent="🙈"; btn.setAttribute("data-shown","1");
        }
      }
      bumpLock();
    };
  });
}

function renderPlanning(){
  const p = vault.planning;
  if(!p){ $("#planView").innerHTML = '<div class="empty"><div class="empty-i">📅</div><h2>Pas de planning</h2></div>'; return; }
  const daily = (p.daily||[]).map(d=>\`<span class="daily-tag">\${d.icon||""} \${esc(d.label)}</span>\`).join("");
  const days = (p.days||[]).map(d=>{
    const safe = /^#[0-9a-fA-F]{3,8}$/.test(d.color||"") ? d.color : "#7c5cff";
    const tasks = (d.tasks||[]).map(t=>\`<li class="task"><span class="task-i">\${t.icon||"•"}</span><span>\${esc(t.label)}</span></li>\`).join("");
    return \`<div class="day" style="--c:\${safe}"><div class="day-name">\${esc(d.name)}</div><ul class="day-tasks">\${tasks||'<li class="task" style="justify-content:center;color:#5d6779">—</li>'}</ul></div>\`;
  }).join("");
  $("#planView").innerHTML = \`
    <div class="plan-head">
      <div class="plan-title">📅 \${esc(p.title||"Planning")}</div>
      \${daily?\`<div class="daily"><div class="daily-lab">🔁 Tous les jours</div><div class="daily-tags">\${daily}</div></div>\`:""}
    </div>
    <div class="days">\${days}</div>\`;
}

setTimeout(()=>$("#mp").focus(),200);
</script>
</body>
</html>
`;

fs.writeFileSync('coffre-mobile.html', html, 'utf8');
const kb = (Buffer.byteLength(html)/1024).toFixed(0);
console.log(`coffre-mobile.html généré (${kb} Ko) — tout en un, hors-ligne.`);
