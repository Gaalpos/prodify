const K='daybook.md.v1';
/* In the desktop app, FS mirrors the Markdown files in ~/Prodify and settings live in a
   config file; boot.js loads both into window.BOOT. In a plain browser everything stays in localStorage. */
const TAURI=window.__TAURI__&&window.__TAURI__.core,BOOT=window.BOOT||{};
let FS={},DISK={},LOCKED=!!BOOT.error,SQ=Promise.resolve();
const fail=m=>{const t=$('toast');t.textContent=m;t.hidden=false;clearTimeout(toast.t)};
// Writes run one after another, so an older save can never land after a newer one.
const queue=(f,what)=>{SQ=SQ.then(f).then(()=>{const t=$('toast');if(t.textContent.startsWith('Could not save'))t.hidden=true}).catch(e=>fail('Could not save '+what+': '+e))};
const store={get:k=>{if(TAURI)return BOOT.kv&&k in BOOT.kv?BOOT.kv[k]:null;try{return localStorage.getItem(k)}catch(e){return null}},
 set:(k,v)=>{if(!TAURI){try{if(v==null)localStorage.removeItem(k);else localStorage.setItem(k,v)}catch(e){}return}if(LOCKED)return;queue(()=>TAURI.invoke('kv_set',{key:k,value:v}),'settings')}};
/* ---------- users ----------
   Several people can use Prodify on one computer. Each user has their own data folder (in the browser preview, their
   own storage) and their own settings, and can have their own account and encryption. The list of users is kept in
   the app's settings, outside any data folder: [{id, name, dir, main}]. The first user ("main") keeps the original
   settings key; the others' settings and preview storage get "@<id>" added. Switching user reopens Prodify. */
let USERS=[];try{USERS=JSON.parse(store.get('prodify.users')||'[]')||[]}catch(e){}
const ME=(TAURI?USERS.find(u=>u.dir===BOOT.dir):USERS.find(u=>u.id===store.get('prodify.user')))||USERS.find(u=>u.main&&!TAURI&&!store.get('prodify.user'))||null;
const USUF=ME&&!ME.main?'@'+ME.id:'';
// "Who's using Prodify?" when it opens (with two or more users), unless this start is a switch to another user.
let WHO=false;try{WHO=USERS.length>1&&store.get('prodify.ask')!=='0'&&!sessionStorage.getItem('prodify.switched');sessionStorage.removeItem('prodify.switched')}catch(e){}
/* ---------- local account and encryption ----------
   An account is prodify-account.md in the data folder (so other devices syncing the folder can unlock it too). It holds
   the name, whether data is encrypted, and a random 256-bit data key sealed twice with AES-256-GCM: with a key derived
   from the password (PBKDF2-SHA256, 600,000 rounds) and with one derived from the recovery key. With encryption on,
   every other file is written as "PRODIFY-ENCRYPTED v1" + base64(iv + ciphertext), and attachments start with the
   bytes "PRDENC1\n"; FS always holds plain text. DISK is the plain text of what is on disk and RAW what is literally
   there; NEEDW lists files to rewrite (encryption turned on or off, or a file from another device in the other form). */
const ACCK='prodify-account.md',CENC='PRODIFY-ENCRYPTED v1',CMAG=[80,82,68,69,78,67,49,10];
let ACCT=null,DK=null,DKRAW=null,ACCREADY=true,RAW={},NEEDW=new Set(),BOOTRAW=null,LSRAW={};
/* App storage (Settings → Data and backups) keeps the files in a database inside the app instead of the Markdown
   folder. With encryption on there, file names are hidden too: each file is stored as "enc/<keyed hash of its name>"
   and its real name travels inside the encrypted text (first line). DISKK maps a file to the name it's stored under. */
const STORE_DB=!!(TAURI&&BOOT.storage==='db');let DISKK={},NHK=null;
async function nameHash(k){if(!NHK){const d=await crypto.subtle.digest('SHA-256',new Uint8Array([...new TextEncoder().encode('prodify-names:'),...DKRAW]));NHK=await crypto.subtle.importKey('raw',d,{name:'HMAC',hash:'SHA-256'},false,['sign'])}
 return [...new Uint8Array(await crypto.subtle.sign('HMAC',NHK,new TextEncoder().encode(k))).slice(0,16)].map(b=>b.toString(16).padStart(2,'0')).join('')}
const hideNames=k=>STORE_DB&&encOn()&&k!==ACCK;
const diskKey=async k=>hideNames(k)?'enc/'+await nameHash(k):k;
const u8b64=u=>{let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s)},b64u8=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const isEncT=t=>typeof t==='string'&&t.startsWith(CENC+'\n'),isEncB=u=>!!u&&u.length>8&&CMAG.every((x,i)=>u[i]===x);
const aesKey=raw=>crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
async function kdf(secret,salt,iterations){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt:b64u8(salt),iterations,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function sealB(key,bytes){const iv=crypto.getRandomValues(new Uint8Array(12)),ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,bytes)),o=new Uint8Array(12+ct.length);o.set(iv);o.set(ct,12);return o}
async function openB(key,u){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:u.slice(0,12)},key,u.slice(12)))}
async function encText(t){return CENC+'\n'+u8b64(await sealB(DK,new TextEncoder().encode(t))).replace(/.{1,76}/g,'$&\n')}
async function decText(t){return new TextDecoder().decode(await openB(DK,b64u8(t.slice(CENC.length+1).replace(/\s+/g,''))))}
async function encBytes(u){const x=await sealB(DK,u),o=new Uint8Array(8+x.length);o.set(CMAG);o.set(x,8);return o}
const decBytes=u=>openB(DK,u.subarray(8));
const encOn=()=>!!(ACCT&&ACCT.enc&&DK);
// What a file looks like on disk: encrypted when the account encrypts (never the account file itself).
const encFile=(k,t)=>encOn()&&k!==ACCK?encText(hideNames(k)?k+'\n'+t:t):t;
function accParse(t){if(typeof t!=='string')return null;const g=k=>{const m=t.match(new RegExp('^'+k+':[ \\t]*(.*)$','m'));return m?m[1].trim():''};if(g('prodify-account')!=='1')return null;
 return{name:g('name'),enc:g('encrypted')==='true',iter:+g('iterations')||600000,salt:g('salt'),key:g('key'),riter:+g('recovery-iterations')||100000,rsalt:g('recovery-salt'),rkey:g('recovery-key'),created:g('created'),kid:g('key-id')}}
const accText=a=>`---\nprodify-account: 1\nname: ${String(a.name||'').replace(/\s+/g,' ').trim()}\nencrypted: ${!!a.enc}\nkdf: PBKDF2-SHA256, AES-256-GCM\niterations: ${a.iter}\nsalt: ${a.salt}\nkey: ${a.key}\nrecovery-iterations: ${a.riter}\nrecovery-salt: ${a.rsalt}\nrecovery-key: ${a.rkey}\n${a.kid?`key-id: ${a.kid}\n`:''}created: ${a.created}\n---\n# Prodify account\n\nThis file lets Prodify open your data. It holds your account name and your data key, locked with your password and with your recovery key (neither is stored here). Keep it in this folder and in your backups: without it ${a.enc?'your encrypted files can’t be opened':'Prodify won’t ask for your password'}.\n`;
// Recovery keys: 20 random bytes as 32 letters and digits in groups of four.
const recNew=()=>{const A='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',r=crypto.getRandomValues(new Uint8Array(32));return [...r].map(x=>A[x%32]).join('').match(/.{4}/g).join('-')};
const recNorm=s=>String(s||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
const randB64=n=>u8b64(crypto.getRandomValues(new Uint8Array(n)));
async function accSeal(a,pw,rk){a.salt=randB64(16);a.key=u8b64(await sealB(await kdf(pw,a.salt,a.iter),DKRAW));if(rk){a.rsalt=randB64(16);a.rkey=u8b64(await sealB(await kdf(recNorm(rk),a.rsalt,a.riter),DKRAW))}}
// The data key from the password (or, with rec, the recovery key); null when it's wrong.
// A fingerprint of the data key (reveals nothing about it): tells whether two devices or a cloud use the same account.
async function keyId(){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array([...new TextEncoder().encode('prodify-key-id:'),...DKRAW])))].slice(0,8).map(b=>b.toString(16).padStart(2,'0')).join('')}
async function accKey(secret,rec,acct){const a=acct||ACCT;try{return await openB(await kdf(rec?recNorm(secret):secret,rec?a.rsalt:a.salt,rec?a.riter:a.iter),b64u8(rec?a.rkey:a.key))}catch(e){return null}}
// Plain text for each file read from disk; files whose disk form doesn't match the account get rewritten.
async function rawToPlain(raw){const out={};
 if(raw[ACCK]!==RAW[ACCK]){const a=accParse(raw[ACCK]);if(a)ACCT=a;else if(ACCT&&RAW[ACCK]&&!raw[ACCK])ACCT=null}// account changed (or removed) on another device
 for(const k in raw){const r=raw[k];if(r===RAW[k]&&k in DISK){out[k]=DISK[k];continue}
  if(isEncT(r)){if(!DK){if(k in DISK)out[k]=DISK[k];continue}try{out[k]=await decText(r)}catch(e){if(k in DISK)out[k]=DISK[k];continue}}else out[k]=r;
  RAW[k]=r;if(ACCT&&k!==ACCK&&isEncT(r)!==!!ACCT.enc)NEEDW.add(k)}
 for(const k in RAW)if(!(k in raw))delete RAW[k];return out}
// In the browser preview the "disk" is one localStorage entry holding every file as written.
if(TAURI)FS={...(BOOT.files||{})};else{try{LSRAW=JSON.parse(localStorage.getItem(K+USUF)||'{}')}catch(e){}FS={...LSRAW}}
DISK={...FS};RAW={...FS};ACCT=accParse(FS[ACCK]);
// With an account, nothing is shown (or saved) until it's unlocked; then accLoad fills FS with the decrypted files.
if(ACCT){ACCREADY=false;BOOTRAW={...FS};FS={[ACCK]:FS[ACCK]};DISK={...FS}}
// Only files that changed since the last save are written; files removed from FS are deleted.
const save=()=>{if(LOCKED||!ACCREADY)return;
 queue(async()=>{const plain={},gone=Object.keys(DISK).filter(k=>!(k in FS));for(const k in FS)if(FS[k]!==DISK[k]||NEEDW.has(k))plain[k]=FS[k];
  if(!gone.length&&!Object.keys(plain).length)return;
  // written under the name it's stored as; a file whose stored name changes (names hidden or shown) loses its old copy
  const write={},remove=gone.map(k=>DISKK[k]||k),dks={};
  for(const k in plain){const dk=await diskKey(k);dks[k]=dk;write[dk]=await encFile(k,plain[k]);if(DISKK[k]&&DISKK[k]!==dk)remove.push(DISKK[k])}
  if(TAURI)await TAURI.invoke('sync_files',{write,remove});else{remove.forEach(k=>delete LSRAW[k]);Object.assign(LSRAW,write);localStorage.setItem(K+USUF,JSON.stringify(LSRAW))}
  gone.forEach(k=>{delete DISK[k];delete RAW[k];delete DISKK[k]});Object.assign(DISK,plain);for(const k in plain){RAW[k]=write[dks[k]];DISKK[k]=dks[k];NEEDW.delete(k)}if(typeof mirSoon==='function')mirSoon();if(typeof cloudSoon==='function')cloudSoon()},'your files')};
const HERE=TAURI?'in your Prodify folder':'in this browser';
const DEF={searchLow:true,homeFixed:false,pageWidth:'wide',zoom:100,calView:'month',theme:'system',palette:'classic',accent:'teal',font:'jetbrains',size:16,week:1,time:'24',name:'',prompts:true,focus:[],confirmTask:true,confirmNote:true,confirmProject:true,confirmQuestion:true,navLayout:'cards',cmdKeys:{},propTypes:{created:'date'},defaultTpl:'',notesView:'panel',notesSort:'date',newNoteFocus:'title',noteOpen:'view',jInNotes:true,catView:'covers',catSort:'alpha',navCounts:true,lang:'en',scrollbars:false,navAuto:false,cardColors:'soft',homeCols:3,healthCols:2,shineColor:'status',iconStyle:'symbols',shine:true,icons:{},syms:{},tabOrder:[],tabOff:[],navWide:[],homeOrder:[],homeOff:[],intAi:true,intRem:true,intNotif:true,calTasks:true,calJournal:true,calNotes:true,calHabits:true,calProjects:true,start:'today'};
let CFG={...DEF};
try{Object.assign(CFG,JSON.parse(store.get('daybook.settings.v1'+USUF)||'{}'))}catch(e){}
// Category covers became the default view; switch an old Tiles default over once.
// JetBrains Mono became the default font; switch an old Default choice over once.
if(!CFG.fontJB){if(CFG.font==='default')CFG.font='jetbrains';CFG.fontJB=1}
// The search bar above the phone tab bar became the default; switch existing settings over once.
if(!CFG.sbLowDef){CFG.searchLow=true;CFG.sbLowDef=1}
if(!CFG.catCovers){if(CFG.catView==='tiles')CFG.catView='covers';CFG.catCovers=1}
if(CFG.start==='questions')CFG.start='journal'; // Questions is now part of Journal
const saveCfg=()=>store.set('daybook.settings.v1'+USUF,JSON.stringify(CFG));
const DN=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
const ACC={teal:['#1f6f78','#d9ecee','#5cb8c2','#1f3a3f'],indigo:['#4a55b8','#e0e3f6','#9aa5f0','#2a2f55'],plum:['#8a4a8f','#efdff1','#d29bd6','#47294a'],forest:['#2f7a4a','#dcefe2','#7fcf9c','#1f3d2b'],amber:['#a35f12','#f6e8d2','#e6b05c','#47341a'],rose:['#b0405c','#f7dfe5','#ec8fa6','#4a2530']};
const FONTS={serif:'Literata,Georgia,serif',sans:'Figtree,system-ui,sans-serif',mono:'ui-monospace,"DejaVu Sans Mono",Menlo,monospace',jetbrains:'"JetBrains Mono",ui-monospace,monospace'};
/* Themes: each has a light and a dark palette; Settings' Mode picks which one shows (System follows the OS).
   acc:'full' takes accent and its tint from ACC; acc:'ac' takes only the accent, keeping the theme's own grays. */
const THEMES={
 classic:{name:'Classic',acc:'full',
  light:{bg:'#f2f4f3',sf:'#ffffff',ink:'#1d2733',mut:'#5d6b78',line:'#dbe1e0',am:'#b9791f',pl:'#7a4e7e'},
  dark:{bg:'#141a20',sf:'#1c242c',ink:'#e6ecef',mut:'#9aa8b3',line:'#2c3742',am:'#e0a850',pl:'#c496c8'}},
 // OLED uses a grouped settings look: pure black (or light gray) page, lighter rounded sections, no borders.
 oled:{name:'OLED',acc:'ac',
  light:{bg:'#f2f2f7',sf:'#ffffff',fld:'#f2f2f7',ink:'#000000',mut:'#6c6c70',line:'#e5e5ea',acs:'#e5e5ea',am:'#a86b12',pl:'#6e4a8a'},
  dark:{bg:'#000000',sf:'#1c1c1e',fld:'#2c2c2e',ink:'#ffffff',mut:'#98989f',line:'#38383a',acs:'#2c2c2e',am:'#e0a850',pl:'#c496c8'}},
 notepad:{name:'Notepad',
  light:{bg:'#fff6d8',sf:'#fffcef',ink:'#3b2a12',mut:'#7a6440',line:'#efdcaa',ac:'#a9530a',onac:'#ffffff',acs:'#fde4bf',am:'#b9790e',pl:'#a0522d'},
  dark:{bg:'#1d180e',sf:'#282114',ink:'#f6ead0',mut:'#c2ad85',line:'#3e3322',ac:'#f5a524',onac:'#1d180e',acs:'#4a3618',am:'#f5c04a',pl:'#e08a5a'}},
 forest:{name:'Forest',
  light:{bg:'#eef3ec',sf:'#fafcf8',ink:'#1d2b20',mut:'#56695a',line:'#d3dfd1',ac:'#2f7a4a',onac:'#ffffff',acs:'#d6ebdc',am:'#a0752a',pl:'#6b5b95'},
  dark:{bg:'#0e1912',sf:'#15231a',ink:'#e3efe5',mut:'#93ab98',line:'#24382a',ac:'#6cc48b',onac:'#0e1912',acs:'#1f3d2a',am:'#d9b45a',pl:'#b39ddb'}},
 aqua:{name:'Aqua',
  light:{bg:'#edf5fb',sf:'#ffffff',ink:'#12263a',mut:'#4f6a82',line:'#d2e2ef',ac:'#1f6fb8',onac:'#ffffff',acs:'#d6e8f7',am:'#b9791f',pl:'#7a4e9e'},
  dark:{bg:'#0a1521',sf:'#111f2e',ink:'#e2eef8',mut:'#8fa7bd',line:'#1f3347',ac:'#5aa9e6',onac:'#0a1521',acs:'#173452',am:'#e0a850',pl:'#b79be0'}},
 princess:{name:'Princess',
  light:{bg:'#fdf0f5',sf:'#fffafc',ink:'#3a1a2b',mut:'#85607a',line:'#f3d3e1',ac:'#c92a76',onac:'#ffffff',acs:'#fadbe9',am:'#c97a2b',pl:'#9b59b6'},
  dark:{bg:'#1d0f17',sf:'#291521',ink:'#f9e4ee',mut:'#c99ab3',line:'#412536',ac:'#f472b6',onac:'#1d0f17',acs:'#4a1f36',am:'#e8b05a',pl:'#d8a6f0'}}};
const themeVars=(t,dark)=>{const v={...t[dark?'dark':'light']},a=ACC[CFG.accent]||ACC.teal;
 if(t.acc){v.ac=a[dark?2:0];v.onac=dark?'#14181c':'#ffffff';if(t.acc==='full')v.acs=a[dark?3:1]}
 return Object.entries(v).map(([k,x])=>`--${k}:${x}`).join(';')};
/* Custom themes: CFG.customThemes = [{id, name, light:{…}, dark:{…}}], added to THEMES as "c-<id>". Each can be exported
   as a .prodify-theme.json file and imported again (here or on another computer). */
const TCOLS=[['bg','Background'],['sf','Cards'],['ink','Text'],['mut','Secondary text'],['line','Lines'],['ac','Accent'],['acs','Accent tint'],['am','Events'],['pl','Journal']];
function themesSync(){Object.keys(THEMES).filter(k=>k.startsWith('c-')).forEach(k=>delete THEMES[k]);(CFG.customThemes||[]).forEach(t=>{THEMES['c-'+t.id]={name:t.name,custom:true,light:{...t.light,onac:onColor(t.light.ac)},dark:{...t.dark,onac:onColor(t.dark.ac)}}})}
const onColor=hex=>{const m=String(hex||'').match(/^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/i);if(!m)return '#ffffff';const[r,g,b]=m.slice(1).map(x=>parseInt(x,16));return (r*299+g*587+b*114)/1000>150?'#14181c':'#ffffff'};
// The colors a theme shows (accent filled in from the accent setting for built-in themes that use it).
const themeColors=(id,dark)=>{const t=THEMES[id]||THEMES.classic,v={...t[dark?'dark':'light']},a=ACC[CFG.accent]||ACC.teal;if(t.acc){v.ac=a[dark?2:0];if(t.acc==='full'||!v.acs)v.acs=v.acs||a[dark?3:1]}
 const o={};TCOLS.forEach(([k])=>{o[k]=/^#[0-9a-f]{6}$/i.test(v[k]||'')?v[k]:k==='acs'?(dark?'#2c2c2e':'#e5e5ea'):dark?'#888888':'#666666'});return o};
let THD=null,thSide='light';
const themeEditor=()=>{const e=THD,c=e[thSide],pv=k=>c[k];
 return `<section class="thed"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${e.id&&(CFG.customThemes||[]).some(x=>x.id===e.id)?'Edit theme':'New theme'}</h2>${seg('thSide',[['light','Light'],['dark','Dark']],thSide).replace(/data-act="set" data-s="thSide"/g,'data-act="thSide"')}</div>
<input id="thname" value="${esc(e.name)}" placeholder="Theme name" aria-label="Theme name" autocomplete="off" style="max-width:320px">
<div class="thgrid">${TCOLS.map(([k,l])=>`<label class="thcol"><input type="color" data-thc="${k}" value="${c[k]}" aria-label="${l}"><span>${l}</span><code>${c[k]}</code></label>`).join('')}</div>
<div class="thprev" style="background:${pv('bg')};color:${pv('ink')}"><div class="thpc" style="background:${pv('sf')};border-color:${pv('line')}"><b>Preview</b><span style="color:${pv('mut')}">Secondary text and details</span><span class="thpb" style="background:${pv('ac')};color:${onColor(pv('ac'))}">Button</span><span class="thpt" style="background:${pv('acs')}">Selected</span><span><i style="background:${pv('am')}"></i><i style="background:${pv('pl')}"></i></span></div></div>
<div class="row" style="margin-top:14px"><button class="b tick" data-act="thSave" aria-label="Save theme" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="thCancel">Cancel</button><button class="g" data-act="thCopy">Copy ${thSide==='light'?'Light to Dark':'Dark to Light'}</button>${(CFG.customThemes||[]).some(x=>x.id===e.id)?`<span style="flex:1"></span><button class="x" data-act="thDel">${armed==='th:'+e.id?'Click again to delete':'Delete theme'}</button>`:''}</div></section>`};
const themeGrid=()=>{const cur=THEMES[CFG.palette];
 return `<div class="tgrid">${Object.keys(THEMES).map(themeCard).join('')}<button class="tcard tnew" data-act="thNew" title="Create a theme from the current one"><span class="tprev">${lineIco('M12 5v14M5 12h14')}</span><span class="tname">New theme</span></button></div>
<div class="row" style="margin:10px 0 0">${cur&&cur.custom?`<button class="g" data-act="thEdit">Edit “${esc(cur.name)}”</button><button class="g" data-act="thExport">Export theme</button>`:''}<button class="g" data-act="thImport">Import theme</button></div>${THD?themeEditor():''}`};
// Keeps the editor's typed name and picked colors (the color inputs update THD live, see below).
const thSync=()=>{if(!THD)return;const n=$('thname');if(n)THD.name=n.value};
document.addEventListener('input',e=>{const k=e.target.dataset&&e.target.dataset.thc;if(!k||!THD)return;THD[thSide][k]=e.target.value;const c=e.target.parentElement.querySelector('code');if(c)c.textContent=e.target.value;
 const pv=document.querySelector('.thprev');if(pv){const tmp=document.createElement('div');thSync();tmp.innerHTML=themeEditor();const np=tmp.querySelector('.thprev');if(np)pv.replaceWith(np)}});
// One preview card per theme: light half on the left, dark half on the right.
themesSync();
const themeCard=id=>{const t=THEMES[id],a=ACC[CFG.accent]||ACC.teal,half=dark=>{const v=t[dark?'dark':'light'],ac=t.acc?a[dark?2:0]:v.ac;
  return `<span class="tp" style="background:${v.bg}"><i style="background:${v.sf};border-color:${v.line}"><em style="background:${v.ink}"></em><em style="background:${v.mut};width:60%"></em></i><b style="background:${ac}"></b></span>`};
 return `<button class="tcard ${CFG.palette===id?'on':''}" data-act="set" data-s="palette" data-val="${id}" aria-pressed="${CFG.palette===id}"><span class="tprev">${half(0)}${half(1)}</span><span class="tname">${t.name}</span></button>`};
/* Zoom (Settings → Appearance → Zoom, Ctrl + / Ctrl − / Ctrl 0): the desktop app zooms the whole window natively;
   the browser version uses CSS zoom. */
const ZOOMS=[80,90,100,110,125,150];
function applyZoom(){const z=(ZOOMS.includes(+CFG.zoom)?+CFG.zoom:100)/100,wv=window.__TAURI__&&window.__TAURI__.webview;
 if(wv&&wv.getCurrentWebview){document.documentElement.style.zoom='';wv.getCurrentWebview().setZoom(z).catch(()=>{document.documentElement.style.zoom=z===1?'':String(z)})}
 else document.documentElement.style.zoom=z===1?'':String(z)}
// CSS zoom scales fixed positions too; screen coordinates are divided by it before being used as left/top.
const cz=()=>parseFloat(document.documentElement.style.zoom)||1;
function zoomStep(d){const i=ZOOMS.indexOf(ZOOMS.includes(+CFG.zoom)?+CFG.zoom:100),n=d===0?100:ZOOMS[Math.max(0,Math.min(ZOOMS.length-1,i+d))];if(n===+CFG.zoom&&d)return;CFG.zoom=n;saveCfg();applyZoom();if(view==='settings')render();toast(`Zoom ${n}%`)}
document.addEventListener('keydown',e=>{if(!(e.ctrlKey||e.metaKey)||e.altKey)return;const k=e.key;if(k==='='||k==='+'){e.preventDefault();zoomStep(1)}else if(k==='-'||k==='_'){e.preventDefault();zoomStep(-1)}else if(k==='0'){e.preventDefault();zoomStep(0)}});
function apply(){applyZoom();document.body.classList.toggle('shine',CFG.shine!==false);document.body.classList.toggle('shine-plain',CFG.shineColor==='white');document.body.classList.toggle('vivid',CFG.cardColors==='vibrant');document.documentElement.classList.toggle('noscroll',!CFG.scrollbars);document.documentElement.lang=CFG.lang==='es'?'es':'en';setTimeout(()=>{if(CFG.lang==='es')i18nRun(document.body);else i18nRestore(document.body)});
 const r=document.documentElement,a=ACC[CFG.accent]||ACC.teal,ap=document.getElementById('app');if(ap){ap.className='nav-'+(CFG.navLayout||'side')+(CFG.navAuto&&CFG.navLayout!=='top'?' navauto':'');ap.classList.remove('navshow')}navWidth();
 CFG.theme==='system'?r.removeAttribute('data-theme'):r.setAttribute('data-theme',CFG.theme);r.dataset.style=['accent','colorful','mono','material'].includes(CFG.uiStyle)?CFG.uiStyle:'default';r.dataset.pal=THEMES[CFG.palette]?CFG.palette:'classic';
 const t=THEMES[CFG.palette]||THEMES.classic,dk=themeVars(t,1);
 document.getElementById('sty').textContent=`:root{${themeVars(t,0)}}@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){${dk};color-scheme:dark}}:root[data-theme="dark"]{${dk};color-scheme:dark}${fontCSS()}body{font-size:${CFG.size}px}`}
// Default keeps the original mix (Figtree interface, Literata writing). Any other choice sets the font for the whole app;
// the Markdown editor and code stay monospace unless the chosen font is itself monospace.
const fontCSS=()=>{const f=FONTS[CFG.font];if(!f)return '';const mono=CFG.font==='mono'||CFG.font==='jetbrains';
 return `body,body *:not(code):not(.mono){font-family:${f}!important}`+(mono?`.mono,code{font-family:${f}!important}`:'')};
const clock=()=>{const d=new Date(),h=d.getHours();return CFG.time==='12'?`${h%12||12}:${pad(d.getMinutes())} ${h<12?'AM':'PM'}`:`${pad(h)}:${pad(d.getMinutes())}`};
const pad=n=>String(n).padStart(2,'0');
const iso=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const TD=()=>iso(new Date());
const hm=(c)=>{const d=new Date();return pad(d.getHours())+c+pad(d.getMinutes())};
const pd=s=>{const[a,b,c]=s.split('-').map(Number);return new Date(a,b-1,c)};
const LOC=()=>CFG.lang==='es'?'es-ES':'en-US';
const fmt=(s,o)=>pd(s).toLocaleDateString(LOC(),o||{weekday:'short',month:'short',day:'numeric'});
const LONG={weekday:'long',month:'long',day:'numeric'};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $=id=>document.getElementById(id);
const MOOD=[['Low','--m1'],['Down','--m2'],['Okay','--m3'],['Good','--m4'],['Great','--m5']];
const PROMPTS=["What gave you energy today, and what drained it?","What’s one thing you’re avoiding, and why?","When did you feel most like yourself this week?","What would you tell a friend who was in your position?","What are you proud of that nobody has noticed?","Which of your habits is helping you right now? Which isn’t?","What did you say yes to that you wish you’d declined?","What does a good day look like for you, in detail?","Who left you feeling better after you talked to them?","What are you curious about lately?","What’s a belief you held a year ago that you’ve changed your mind on?","What do you need more of, and less of?"];

/* ---------- Markdown storage: FS maps file paths to Markdown text ---------- */
const jp=d=>`journal/${d}.md`;
/* Journal entries: each one is its own file in journal/entries/ ("YYYY-MM-DD HH-MM.md"), made from the
   "Journal entry" template, with created, time, mood (1–5), location and categories as properties.
   Older day files (journal/YYYY-MM-DD.md, one "## time" section per entry) keep working alongside. */
const JE='journal/entries/',JTPL='templates/Journal entry.md';
const isJE=k=>String(k||'').startsWith(JE);
const isDayK=k=>/^journal\/\d{4}-\d{2}-\d{2}\.md$/.test(k);
const dayKeys=()=>Object.keys(FS).filter(isDayK).sort().reverse();
const entKeys=()=>Object.keys(FS).filter(isJE).sort().reverse();
function jeRead(k){const n=readNote(FS[k]),f=n.fm,m=k.match(/(\d{4}-\d{2}-\d{2}) (\d{2})-(\d{2})/);
 return{k,date:/^\d{4}-\d{2}-\d{2}/.test(f.created||'')?String(f.created).slice(0,10):m?m[1]:TD(),time:String(f.time||(m?m[2]+':'+m[3]:'')),mood:/^[1-5]$/.test(String(f.mood))?+f.mood:0,loc:String(f.location||''),cats:f.categories||[],emos:Array.isArray(f.emotions)?f.emotions.map(String):f.emotions?[String(f.emotions)]:[],body:n.body}}
const entOn=d=>entKeys().map(jeRead).filter(e=>e.date===d);
/* Mood check-ins: journal/moods.md, one per line: "- 2026-10-23 11:58: 4 · Grateful, Tired" (level 1–5, then emotions).
   A day's mood is the average of its check-ins, its journal entries' moods and an older day-file mood. */
const moodsRead=()=>(FS['journal/moods.md']||'').split('\n').map(l=>l.match(/^- (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}): ([1-5])(?: · (.+))?$/)).filter(Boolean).map((m,i)=>({i,d:m[1],t:m[2],m:+m[3],emos:m[4]?m[4].split(',').map(x=>x.trim()).filter(Boolean):[]}));
const moodsWrite=l=>{FS['journal/moods.md']='# Mood check-ins\n\n'+l.slice().sort((a,b)=>(a.d+a.t).localeCompare(b.d+b.t)).map(x=>`- ${x.d} ${x.t}: ${x.m}${x.emos.length?' · '+x.emos.join(', '):''}`).join('\n')+(l.length?'\n':'')};
const getMood=d=>{const m=(FS[jp(d)]||'').match(/^mood:\s*(\d)/m),ms=[...(m?[+m[1]]:[]),...entOn(d).map(e=>e.mood).filter(Boolean),...(FS['journal/moods.md']?moodsRead().filter(x=>x.d===d).map(x=>x.m):[])];return ms.length?Math.round(ms.reduce((a,b)=>a+b,0)/ms.length):0};
const setMood=(d,n)=>{let s=FS[jp(d)]||'';
 if(!s.startsWith('---'))s=`---\ndate: ${d}\nmood: ${n}\n---\n\n`+s;
 else if(/^mood:/m.test(s))s=s.replace(/^mood:.*$/m,'mood: '+n);
 else s=s.replace(/^(date:.*)$/m,'$1\nmood: '+n);
 FS[jp(d)]=s};
const addEntry=(d,p,t,time)=>{const s=FS[jp(d)]||`---\ndate: ${d}\n---\n`;
 FS[jp(d)]=s.replace(/\n+$/,'')+`\n\n## ${time||clock()}${p?' — '+p:''}\n\n${t.trim()}\n`};
const TRE=/^- \[([ xX])\] (.*?)(?: \(due: (\d{4}-\d{2}-\d{2})\))?(?: \(remind: (\d{4}-\d{2}-\d{2} \d{2}:\d{2})\))?(?: \(project: ([^)]+)\))?(?: \(list: ([^)]+)\))?(?: \(added: (\d{4}-\d{2}-\d{2})\))?(?: \(done: (\d{4}-\d{2}-\d{2})\))?(?: \(status: (doing)\))?(?: \(repeat: (daily|weekdays|weekly|monthly|yearly)\))?(?: \(priority: (high|medium|low)\))?\s*$/,ERE=/^- (\d{4}-\d{2}-\d{2}): (.*)$/;
const SRE=/^\s+- \[([ xX])\] (.*?)\s*$/;
function parseTasks(s){const out=[];for(const l of s.split('\n')){const m=l.match(TRE);
 if(m)out.push({i:out.length,done:m[1]!==' ',title:m[2],due:m[3]||'',rem:m[4]||'',proj:m[5]||'',list:m[6]||'',added:m[7]||'',doneOn:m[8]||'',doing:m[9]==='doing',rep:m[10]||'',pri:m[11]||'',subs:[]});
 else{const x=l.match(SRE);if(x&&out.length)out[out.length-1].subs.push({done:x[1]!==' ',title:x[2]})}}return out}
const tasks=()=>parseTasks(FS['tasks.md']||'');
/* Recurring tasks: "(repeat: daily|weekdays|weekly|monthly|yearly)". Checking one off adds the next one (same title,
   list, project, priority, subtasks unticked) with the due date (and reminder) moved on. */
const REPL={daily:'Every day',weekdays:'Weekdays',weekly:'Every week',monthly:'Every month',yearly:'Every year'};
function repNext(d,r){let x=pd(d);if(r==='daily')x.setDate(x.getDate()+1);else if(r==='weekdays'){do{x.setDate(x.getDate()+1)}while(x.getDay()===0||x.getDay()===6)}else if(r==='weekly')x.setDate(x.getDate()+7);else if(r==='monthly')x.setMonth(x.getMonth()+1);else x.setFullYear(x.getFullYear()+1);return iso(x)}
/* Natural-language task entry: "Call mom friday 6pm !high #family +launch every week" → due date, reminder, priority,
   list (#name), project (+name) and repeat; the rest is the title. English and Spanish words work. */
const DOW3={sun:0,dom:0,mon:1,lun:1,tue:2,mar:2,wed:3,mie:3,thu:4,jue:4,fri:5,vie:5,sat:6,sab:6};
function nlTask(raw){let t=' '+String(raw).trim()+' ',due='',time='',rp='',pri='',list='',proj='';const td=TD();
 t=t.replace(/\s!(high|alta|medium|media|low|baja|1|2|3|!{0,2})(?=\s)/i,(m,p)=>{p=p.toLowerCase();pri=/^(high|alta|1|!!)$/.test(p)?'high':/^(medium|media|2|!)$/.test(p)?'medium':/^(low|baja|3)$/.test(p)?'low':'high';return ' '});
 t=t.replace(/\s(every\s+weekday|weekdays|entre\s+semana|every\s+day|daily|cada\s+d[ií]a|a\s+diario|every\s+week|weekly|cada\s+semana|semanal(?:mente)?|every\s+month|monthly|cada\s+mes|mensual(?:mente)?|every\s+year|yearly|cada\s+a[ñn]o|anual(?:mente)?)(?=\s)/i,(m,r)=>{r=fold(r);rp=/weekday|entre/.test(r)?'weekdays':/day|daily|dia|diario/.test(r)?'daily':/week|seman/.test(r)?'weekly':/month|mes|mensual/.test(r)?'monthly':'yearly';return ' '});
 t=t.replace(/\s(?:at\s+|a\s+las\s+)?(\d{1,2})(?::(\d{2}))?\s?(am|pm)?(?=\s)/i,(m,h,mi,ap)=>{if(!mi&&!ap)return m;h=+h;if(ap){ap=ap.toLowerCase();if(ap==='pm'&&h<12)h+=12;if(ap==='am'&&h===12)h=0}if(h>23||(mi&&+mi>59))return m;time=pad(h)+':'+(mi||'00');return ' '});
 t=t.replace(/\s(today|hoy|tomorrow|ma[ñn]ana|next\s+week|la\s+semana\s+que\s+viene|in\s+(\d+)\s+days?|en\s+(\d+)\s+d[ií]as|(\d{4}-\d{2}-\d{2})|(?:next\s+|this\s+|on\s+|el\s+)?(sun(?:day)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|domingo|lunes|martes|mi[eé]rcoles|jueves|viernes|s[aá]bado))(?=\s)/i,(m,w,n1,n2,iso2,dw)=>{if(due)return m;const x=fold(w);
   if(/^(today|hoy)$/.test(x))due=td;else if(/^(tomorrow|manana)$/.test(x))due=dAdd(td,1);else if(/week|semana/.test(x))due=dAdd(td,7);else if(n1||n2)due=dAdd(td,+(n1||n2));else if(iso2)due=iso2;
   else if(dw){const n=DOW3[fold(dw).slice(0,3)];if(n===undefined)return m;due=dAdd(td,(n-pd(td).getDay()+7)%7)}return ' '});
 t=t.replace(/\s#([^\s#]+)/g,(m,n)=>{const l=userLists().find(x=>fold(x.name).replace(/\s+/g,'')===fold(n));if(l&&!list){list=l.id;return ' '}return m});
 t=t.replace(/\s\+([^\s+]+)/g,(m,n)=>{const p=projects().find(x=>fold(x.name).replace(/\s+/g,'').startsWith(fold(n)));if(p&&!proj){proj=p.id;return ' '}return m});
 if(time&&!due)due=time<=hm(':')?dAdd(td,1):td;if(rp&&!due)due=td;if(rp==='weekdays')while([0,6].includes(pd(due).getDay()))due=dAdd(due,1);
 const title=t.replace(/\s+/g,' ').trim()||String(raw).trim();return{title,due,rem:time?`${due} ${time}`:'',list,proj,rep:rp,pri}}
const nlSummary=n=>[n.due?(n.due===TD()?'Today':n.due===dAdd(TD(),1)?'Tomorrow':fmt(n.due)):'',n.rem?tf(n.rem.slice(11)):'',n.pri?{high:'High priority',medium:'Medium priority',low:'Low priority'}[n.pri]:'',n.rep?REPL[n.rep]:'',n.list?getList(n.list).name:'',n.proj?pname(n.proj):''].filter(Boolean).join(' · ');
// A live hint under task inputs showing what was understood.
document.addEventListener('input',e=>{const el=e.target;if(!(el.id==='tt'||el.id==='ptt'||(el.dataset&&el.dataset.tca!==undefined)))return;const n=nlTask(el.value),sm=el.value.trim()?nlSummary(n):'';
 const host=el.closest('.rnline,.row')||el.parentElement;let h=host.parentElement.querySelector(':scope > .nlhint');if(!sm){if(h)h.remove();return}
 if(!h){h=document.createElement('div');h.className='nlhint meta';host.insertAdjacentElement('afterend',h)}h.textContent='→ '+n.title+' · '+sm});
const putTasks=ts=>{FS['tasks.md']='# Tasks\n\n'+ts.map(t=>`- [${t.done?'x':' '}] ${t.title}${t.due?` (due: ${t.due})`:''}${t.rem?` (remind: ${t.rem})`:''}${t.proj?` (project: ${t.proj})`:''}${t.list?` (list: ${t.list})`:''}${t.added?` (added: ${t.added})`:''}${t.done&&t.doneOn?` (done: ${t.doneOn})`:''}${!t.done&&t.doing?' (status: doing)':''}${t.rep?` (repeat: ${t.rep})`:''}${t.pri?` (priority: ${t.pri})`:''}\n`+(t.subs||[]).map(s=>`  - [${s.done?'x':' '}] ${s.title}\n`).join('')).join('')};
// Events: "- 2026-10-22: Title" (all day) or "- 2026-10-22: 09:00-10:30 Title" (timed; the end time is optional).
const ETM=/^(\d{1,2}:\d{2})(?:\s*[-–]\s*(\d{1,2}:\d{2}))?\s+(.+)$/,h5=x=>x?x.padStart(5,'0'):'';
// Weekly repeats can skip weeks and pick weekdays: "(repeat: every 2 weeks on mon,tue,wed,thu,fri)" (rotating shifts).
const WKD=['sun','mon','tue','wed','thu','fri','sat'],WKN=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
const repStr=e=>e.rep==='weekly'&&((e.every||1)>1||(e.days||[]).length)?`${(e.every||1)>1?`every ${e.every} weeks`:'weekly'}${(e.days||[]).length?' on '+[...e.days].sort((a,b)=>((a+6)%7)-((b+6)%7)).map(x=>WKD[x]).join(','):''}`:e.rep;
const events=()=>(FS['events.md']||'').split('\n').map(l=>l.match(ERE)).filter(Boolean).map((m,i)=>{let txt=m[2],rp='';let ev=1,dy=[];const r=txt.match(/\s\(repeat: (daily|weekly|monthly|yearly|every (\d+) weeks)(?: on ([a-z,]+))?\)$/);if(r){rp=r[2]?'weekly':r[1];ev=r[2]?Math.max(1,+r[2]):1;dy=r[3]?r[3].split(',').map(x=>WKD.indexOf(x)).filter(x=>x>=0):[];txt=txt.slice(0,-r[0].length)}const t=txt.match(ETM);return{i,date:m[1],start:t?h5(t[1]):'',end:t&&t[2]?h5(t[2]):'',title:t?t[3]:txt,rep:rp,every:ev,days:dy}});
/* Repeating events ("(repeat: weekly)" after the title) and birthdays (birthdays.md: "- 05-12: Ana (1990)") show on every
   matching day: evOn(E, day) is the list for a day. Birthdays come through as all-day events with i = -1. */
const evHits=(e,d)=>{if(e.date===d)return true;if(!e.rep||d<e.date)return false;const a=pd(e.date),b=pd(d);
 if(e.rep==='weekly'){const dy=e.days||[];if(dy.length?!dy.includes(b.getDay()):a.getDay()!==b.getDay())return false;
  // weeks counted from the week the event starts in (weeks start on the day set in Settings)
  const wk=Math.round((pd(weekStart(d))-pd(weekStart(e.date)))/6048e5);return wk%(e.every||1)===0}
 return e.rep==='daily'||(e.rep==='monthly'&&a.getDate()===b.getDate())||(e.rep==='yearly'&&a.getDate()===b.getDate()&&a.getMonth()===b.getMonth())};
const bdays=()=>(FS['birthdays.md']||'').split('\n').map(l=>l.match(/^- (\d{2})-(\d{2}): (.+?)(?: \((\d{4})\))?\s*$/)).filter(Boolean).map((m,i)=>({i,m:m[1],d:m[2],name:m[3].trim(),y:m[4]||''}));
const bdWrite=l=>{FS['birthdays.md']='# Birthdays\n\n'+l.slice().sort((a,b)=>(a.m+a.d).localeCompare(b.m+b.d)).map(x=>`- ${x.m}-${x.d}: ${x.name}${x.y?` (${x.y})`:''}`).join('\n')+(l.length?'\n':'')};
const bdOn=d=>bdays().filter(b=>d.slice(5)===`${b.m}-${b.d}`).map(b=>({i:-1,bday:true,date:d,start:'',end:'',rep:'',title:`🎂 ${b.name}${b.y?` turns ${+d.slice(0,4)-+b.y}`:''}`}));
const evOn=(E,d)=>[...bdOn(d),...E.filter(e=>evHits(e,d))];
const putEvents=es=>{FS['events.md']='# Events\n\n'+es.filter(e=>!e.bday).map(e=>`- ${e.date}: ${e.start?e.start+(e.end?'-'+e.end:'')+' ':''}${e.title}${e.rep?` (repeat: ${repStr(e)})`:''}\n`).join('')};
const tf=x=>{if(!x)return '';const[h,m]=x.split(':').map(Number);return CFG.time==='12'?`${h%12||12}${m?':'+pad(m):''} ${h<12?'AM':'PM'}`:x};
/* Time boxes follow Settings → Time format (the browser's own time box follows the system locale instead):
   timeField(id, "HH:MM") is hour and minute menus (plus AM/PM in 12-hour mode) writing "HH:MM" into a hidden input with
   that id; dtField(id, "YYYY-MM-DDTHH:MM") adds a date box in front and writes "YYYY-MM-DDTHH:MM". Empty means no time. */
function timeField(id,val,label){const t=/^\d{1,2}:\d{2}$/.test(val||'')?h5(val):'',H=t?+t.slice(0,2):null,M=t?+t.slice(3):null,tw=CFG.time==='12';
 const hs=tw?[12,1,2,3,4,5,6,7,8,9,10,11]:[...Array(24).keys()],hsel=H===null?'':tw?(H%12||12):H;
 return `<span class="tfield" data-tfield="${id}" role="group" aria-label="${esc(label||'Time')}"><select data-tfp="h" aria-label="Hour"><option value="">--</option>${hs.map(h=>`<option value="${h}" ${String(hsel)===String(h)?'selected':''}>${tw?h:pad(h)}</option>`).join('')}</select><span class="tfsep">:</span><select data-tfp="m" aria-label="Minutes"><option value="">--</option>${[...Array(60).keys()].map(m=>`<option value="${m}" ${M===m?'selected':''}>${pad(m)}</option>`).join('')}</select>${tw?`<select data-tfp="ap" aria-label="AM or PM"><option value="AM" ${H!==null&&H<12?'selected':''}>AM</option><option value="PM" ${H!==null&&H>=12?'selected':''}>PM</option></select>`:''}<input type="hidden" id="${id}" value="${t}"></span>`}
function dtField(id,val,label){const m=String(val||'').match(/^(\d{4}-\d{2}-\d{2})[T ](\d{1,2}:\d{2})/);return `<span class="dtfield" data-dtfield="${id}"><input type="date" data-dtd value="${m?m[1]:''}" aria-label="${esc(label||'Date')}">${timeField(id+'-t',m?m[2]:'',label)}<input type="hidden" id="${id}" value="${m?m[1]+'T'+h5(m[2]):''}"></span>`}
document.addEventListener('change',e=>{const t=e.target,f=t.closest&&t.closest('.tfield');
 if(f){const g=k=>{const x=f.querySelector(`[data-tfp="${k}"]`);return x?x.value:''},hidden=f.querySelector('input[type=hidden]');let h=g('h'),m=g('m');
  if(h===''&&t.dataset.tfp==='m'&&m!==''){h=CFG.time==='12'?'12':'9';f.querySelector('[data-tfp="h"]').value=h}if(m===''&&h!==''){m='0';f.querySelector('[data-tfp="m"]').value='0'}
  let H=h===''?null:+h;if(H!==null&&CFG.time==='12'){H=H%12+(g('ap')==='PM'?12:0)}hidden.value=H===null?'':`${pad(H)}:${pad(+m)}`}
 const d=t.closest&&t.closest('.dtfield');if(d){const dd=d.querySelector('[data-dtd]').value,tt=d.querySelector('.tfield input[type=hidden]').value;let tm=tt;
  if(dd&&!tm){tm='09:00';const tf2=d.querySelector('.tfield');tf2.querySelector('input[type=hidden]').value=tm;tf2.querySelector('[data-tfp="h"]').value=CFG.time==='12'?'9':'9';tf2.querySelector('[data-tfp="m"]').value='0';const ap=tf2.querySelector('[data-tfp="ap"]');if(ap)ap.value='AM'}
  d.querySelector(':scope>input[type=hidden]').value=dd?dd+'T'+tm:''}},true);
const evTime=e=>e.start?tf(e.start)+(e.end?'–'+tf(e.end):''):'';
const mins=x=>{const[h,m]=x.split(':').map(Number);return h*60+(m||0)},hhmm=n=>`${pad(Math.floor(n/60)%24)}:${pad(n%60)}`;
const evSort=(a,b)=>(a.start||'').localeCompare(b.start||'')||a.i-b.i;
(function migrate(){if(Object.keys(FS).length)return;let o;try{o=JSON.parse(localStorage.getItem('daybook.v1')||'null')}catch(e){}
 if(!o)return;
 (o.notes||[]).forEach(n=>FS[`notes/${n.date}-${n.id}.md`]=`# ${n.title||'Untitled'}\n\n${n.body}\n`);
 (o.journal||[]).forEach(j=>addEntry(j.date,j.prompt,j.text,'00:00'));
 Object.entries(o.moods||{}).forEach(([d,m])=>setMood(d,m));
 if((o.tasks||[]).length)putTasks(o.tasks.map(t=>({done:t.done,title:t.title,due:t.due})));
 if((o.events||[]).length)putEvents(o.events);
 save()})();

/* ---------- tiny Markdown renderer ---------- */
/* ---------- photos ----------
   Photos are resized to at most 2048 px (JPEG) and stored as files in ~/Prodify/attachments/; entries link them with
   standard Markdown, ![](../attachments/<name>.jpg), so Obsidian shows them too. In a plain browser (no folder to
   write to) the image data lives in IndexedDB instead. Consecutive photo lines render as one photo mosaic. */
const IMGRE=/^!\[[^\]]*\]\((?:\.\.\/)*attachments\/([^)\s]+)\)\s*$/;
const IDB=(()=>{let p;const db=()=>p||(p=new Promise((ok,no)=>{const r=indexedDB.open('prodify-attachments',1);r.onupgradeneeded=()=>r.result.createObjectStore('f');r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)}));
 const tx=(mode,f)=>db().then(d=>new Promise((ok,no)=>{const t=d.transaction('f',mode),r=f(t.objectStore('f'));t.oncomplete=()=>ok(r&&r.result);t.onerror=()=>no(t.error)}));
 return{put:(k,v)=>tx('readwrite',st=>st.put(v,USUF+k)),get:k=>tx('readonly',st=>st.get(USUF+k))}})();// each user's own keys
const ATTURL={};
const blob64=b=>new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok(String(r.result).split(',')[1]||'');r.onerror=()=>no(r.error);r.readAsDataURL(b)});
// Attachment bytes as stored (attRead/attWrite) and as plain bytes (attPlain decrypts encrypted ones).
const ATTMIME={jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',webp:'image/webp',gif:'image/gif',pdf:'application/pdf'};
const attMime=n=>ATTMIME[String(n).split('.').pop().toLowerCase()]||'application/octet-stream';
async function attRead(name){if(TAURI)return b64u8(await TAURI.invoke('read_attachment',{name}));const b=await IDB.get(name);return b?new Uint8Array(await new Response(b).arrayBuffer()):null}
const attWrite=(name,u)=>TAURI?TAURI.invoke('save_attachment',{name,data:u8b64(u)}):IDB.put(name,new Blob([u],{type:attMime(name)}));
async function attPlain(name){const u=await attRead(name);return u&&isEncB(u)?decBytes(u):u}
const saveAtt=async(name,blob)=>encOn()?attWrite(name,await encBytes(new Uint8Array(await blob.arrayBuffer()))):TAURI?TAURI.invoke('save_attachment',{name,data:await blob64(blob)}):IDB.put(name,blob);
// With an account, attachments may be encrypted, so they're read, decrypted and shown from memory.
const attURL=name=>ATTURL[name]?Promise.resolve(ATTURL[name]):ACCT||STORE_DB?attPlain(name).then(u=>u?(ATTURL[name]=URL.createObjectURL(new Blob([u],{type:attMime(name)}))):'').catch(()=>''):TAURI?Promise.resolve(ATTURL[name]=TAURI.convertFileSrc((BOOT.dir||'')+'/attachments/'+name)):IDB.get(name).then(b=>b?(ATTURL[name]=URL.createObjectURL(b)):'');
// Fills in <img data-att> after each render (file paths in the app, IndexedDB blobs in a browser).
/* Storage cards as a masonry grid: rows are 4 px tall and each card spans as many as its height needs, so cards of
   different heights pack tightly while keeping their left-to-right order. Cards re-measure when an image loads or the
   window resizes. */
const stRO=typeof ResizeObserver!=='undefined'?new ResizeObserver(es=>es.forEach(e=>stSpan(e.target))):null;
function stSpan(c){if(!c.isConnected)return;const h=c.offsetHeight;c.style.gridRowEnd='span '+Math.max(1,Math.ceil((h+14)/4))}
function stMasonry(){document.querySelectorAll('.stcards>.stcard').forEach(c=>{stSpan(c);if(stRO)stRO.observe(c)})}
/* Confirmation pop-up: askConfirm({title, text, ok, att}) resolves true (Delete button or Enter) or false (Cancel, Esc
   or a click outside). att shows a stored image as a thumbnail. */
function askConfirm({title,text='',ok='Delete',att=''}){return new Promise(res=>{closeCtx();let o=$('cfm');if(o)o.remove();o=document.createElement('div');o.id='cfm';o.className='cfm';
 o.innerHTML=`<div class="cfmbox" role="alertdialog" aria-modal="true" aria-labelledby="cfmt"${text?' aria-describedby="cfmd"':''}>${att?`<img class="cfmimg" data-att="${esc(att)}" alt="">`:''}<h2 id="cfmt">${esc(title)}</h2>${text?`<p class="meta" id="cfmd">${esc(text)}</p>`:''}<div class="cfmbtns"><button class="g" data-cfm="0">Cancel</button><button class="b cfmok" data-cfm="1">${esc(ok)}</button></div></div>`;
 document.body.appendChild(o);if(att)hydrateImgs();if(CFG.lang==='es')i18nRun(o);
 const done=v=>{o.remove();document.removeEventListener('keydown',kd,true);res(v)},kd=e=>{if(e.key==='Escape'||e.key==='Enter'){e.preventDefault();e.stopPropagation();done(e.key==='Enter')}};
 document.addEventListener('keydown',kd,true);o.addEventListener('click',e=>{e.stopPropagation();const b=e.target.closest('[data-cfm]');if(b)done(b.dataset.cfm==='1');else if(e.target===o)done(false)});o.querySelector('.cfmok').focus()})}
const stKindName=k=>k==='links'?'link':k==='images'?'image':'PDF';
async function stConfirmDel(kind,i){const x=stRead(kind)[i];if(!x)return;
 if(!await askConfirm({title:`Delete this ${stKindName(kind)}?`,text:`“${x.title||host(x.url)}” will be removed from Storage. This can’t be undone.`,att:kind==='images'?x.att:''}))return;
 const l=stRead(kind),j=l.findIndex(y=>y.url===x.url&&y.d===x.d);if(j<0)return;l.splice(j,1);stWrite(kind,l);if(stPrev===x.att)stPrev=null;save();render();toast(kind==='links'?'Link deleted':kind==='images'?'Image deleted':'PDF deleted')}
/* Trash (Notes → Trash): deleting a note, archived note, sticky note or template moves it to trash/ with "deleted: <date>"
   and "from: <old path>" in its front matter. It can be restored to where it was, or deleted for good; anything older
   than 30 days is removed automatically (at startup and whenever the Trash tab opens). */
const TRASH_DAYS=30,trashable=k=>/^(notes|archive|templates)\//.test(k);
function noteTrash(k){const n=readNote(FS[k]);n.fm={...n.fm,deleted:TD(),from:k};const base='trash/'+k.replace(/^[^/]+\//,'').slice(0,-3);let tk=base+'.md',i=2;while(FS[tk])tk=`${base} ${i++}.md`;FS[tk]=writeNote(n);delete FS[k];return tk}
function noteRestore(tk){const n=readNote(FS[tk]),from=/^(notes|archive|templates)\/.+\.md$/.test(String(n.fm.from||''))?String(n.fm.from):'notes/'+tk.slice(6);delete n.fm.deleted;delete n.fm.from;
 let k=from,i=2;while(FS[k])k=from.slice(0,-3)+' '+(i++)+'.md';FS[k]=writeNote(n);delete FS[tk];return k}
const trashLeft=tk=>{const d=String(readNote(FS[tk]).fm.deleted||'').slice(0,10);return /^\d{4}-\d{2}-\d{2}$/.test(d)?Math.max(0,TRASH_DAYS-Math.round((pd(TD())-pd(d))/864e5)):TRASH_DAYS};
function trashPurge(){let n=0;keys('trash/').forEach(k=>{if(trashLeft(k)<=0){delete FS[k];n++}});if(n)save();return n}
// Deleting a note (or a journal day's free text): the confirmation pop-up (when "Confirm before deleting a note" is on),
// saying so when the note is also pinned on the Home board; it then leaves the board too.
async function noteDel(k){if(!FS[k])return;const B=HB(),onB=!!B.items['note:'+k],jd=k.startsWith('journal/');
 if(trashable(k)){const tt=wlPlain(noteTitle(k));if(CFG.confirmNote!==false&&!await askConfirm({title:'Move to Trash?',text:`“${tt}” will be moved to Trash, where you can restore it for ${TRASH_DAYS} days.${onB?' It will also be removed from your Home board.':''}`,ok:'Move to Trash'}))return;
  const tk=noteTrash(k);if(onB){delete B.items['note:'+k];saveCfg()}if(edN===k){edN=null;ND=null}expd.delete(k);armed=null;save();render();
  toastAct(onB?'Moved to Trash and removed from the board':'Moved to Trash',[['Undo',()=>{if(FS[tk]){noteRestore(tk);save();render()}}]]);return}
 if(CFG.confirmNote!==false&&!await askConfirm({title:isJE(k)?'Delete this journal entry?':jd?'Delete this journal day?':k.startsWith('templates/')?'Delete this template?':'Delete this note?',text:`“${wlPlain(noteTitle(k))}” will be deleted.${onB?' It’s also on your Home board and will be removed from there.':''} This can’t be undone.`}))return;
 if(jd){const p=FS[k].split(/\n(?=## )/),qk=p.slice(1).filter(isQ);if(qk.length)FS[k]=[p[0],...qk].join('\n').replace(/\n*$/,'\n');else delete FS[k]}else delete FS[k];
 if(onB){delete B.items['note:'+k];saveCfg()}if(edN===k){edN=null;ND=null}expd.delete(k);armed=null;save();render();toast(onB?'Note deleted and removed from the board':'Note deleted')}
async function colConfirmDel(k){if(!FS[k])return;const it=colRead(k);
 if(!await askConfirm({title:'Delete this item?',text:`“${it.title}” and its notes, rating and status will be deleted. This can’t be undone.`,ok:'Delete'}))return;
 delete FS[k];if(colSel===k){colSel=null;CD=null}armed=null;save();render();toast('Deleted from collections')}
function hydrateImgs(){document.querySelectorAll('img[data-att]:not([src])').forEach(img=>attURL(img.dataset.att).then(u=>{if(u)img.src=u;else img.closest('.mimg')&&img.closest('.mimg').classList.add('missing')}).catch(()=>{}))}
const attName=()=>`${TD()}-${Date.now().toString(36)}${Math.random().toString(36).slice(2,6)}.jpg`;
async function prepImage(file){const bmp=await createImageBitmap(file,{imageOrientation:'from-image'}),k=Math.min(1,2048/Math.max(bmp.width,bmp.height)),c=document.createElement('canvas');
 c.width=Math.round(bmp.width*k);c.height=Math.round(bmp.height*k);const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.drawImage(bmp,0,0,c.width,c.height);
 return new Promise((ok,no)=>c.toBlob(b=>b?ok(b):no(new Error('encode')),'image/jpeg',.85))}
// Layouts: 1 full, 2 side by side, 3 big + two stacked, 4 big + two stacked + tall, 5+ big + four (last shows +N).
const mosaic=ns=>{const n=ns.length,show=ns.slice(0,5),extra=n-show.length,set=esc(ns.join('|'));
 return `<div class="mosaic m${show.length}">${show.map((x,i)=>`<button class="mimg" data-act="lightbox" data-att="${esc(x)}" data-set="${set}" aria-label="Open photo ${i+1} of ${n}"><img data-att="${esc(x)}" alt="" loading="lazy">${extra&&i===show.length-1?`<span class="more">+${extra}</span>`:''}</button>`).join('')}</div>`};
// Photos chosen for the entry being written, kept in memory until "Save to journal".
let JIMG=[];
async function addPhotos(files){let n=0;for(const f of files){if(!f.type.startsWith('image/'))continue;try{const blob=await prepImage(f);JIMG.push({name:attName(),blob,url:URL.createObjectURL(blob)});n++}catch(e){toast('Could not read '+(f.name||'that image'))}}if(n)redraw()}
// Full-size viewer: arrows or ‹ › step through the entry's photos, Escape or clicking outside closes.
let LB=null;
function lbShow(){let o=$('lbox');if(!LB){if(o)o.remove();return}
 if(!o){o=document.createElement('div');o.id='lbox';o.className='lbox';o.setAttribute('role','dialog');o.setAttribute('aria-modal','true');o.setAttribute('aria-label','Photo');document.body.appendChild(o)}
 const n=LB.set.length;o.innerHTML=`<img data-att="${esc(LB.set[LB.i])}" alt="Photo ${LB.i+1} of ${n}">${n>1?`<span class="lbn">${LB.i+1} / ${n}</span><button class="circ lbp" data-lb="-1" aria-label="Previous photo">‹</button><button class="circ lbx" data-lb="1" aria-label="Next photo">›</button>`:''}<button class="circ lbc" data-lb="close" aria-label="Close">×</button>`;
 hydrateImgs();o.querySelector('.lbc').focus()}
const lbMove=d=>{if(!LB)return;LB.i=(LB.i+d+LB.set.length)%LB.set.length;lbShow()};
document.addEventListener('click',e=>{const o=$('lbox');if(!o||!o.contains(e.target))return;e.stopPropagation();const b=e.target.closest('[data-lb]');
 if(b&&b.dataset.lb!=='close')lbMove(+b.dataset.lb);else if(b||e.target===o){LB=null;lbShow()}},true);
document.addEventListener('keydown',e=>{if(!LB)return;if(e.key==='Escape'){LB=null;lbShow()}else if(e.key==='ArrowRight')lbMove(1);else if(e.key==='ArrowLeft')lbMove(-1);else return;e.preventDefault();e.stopPropagation()},true);
document.addEventListener('paste',e=>{if(e.target.id!=='jt')return;const fs=[...(e.clipboardData&&e.clipboardData.files||[])].filter(f=>f.type.startsWith('image/'));if(fs.length){e.preventDefault();addPhotos(fs)}});
// Inline Markdown: `code` (kept as is), [links](https://…) and bare URLs, **bold**, *italic* / _italic_, ~~strike~~, ==highlight==.
const mdA=(u,t)=>`<a class="mdlink" href="${u}" data-act="olink" data-v="${u}" title="${u}">${t}</a>`;
/* Wiki links: [[Title]] or [[Title|shown text]] become capsules that open a note, journal entry, project, collection
   item or task list with that name; a missing one offers to create the note. Renaming a note updates its links. */
let WLC=null;
/* Navigation history: every move to another page or item (not a sidebar jump) remembers where you were. A page's back
   button (or one "‹ name" button on top when the page has none) returns there, scroll position included. */
let NAVH=[],navSig=null,navSnap=null,navSkip=false;
const navState=()=>({view,colSel,curP,curList,selCat,wkSel,exSel,edN:view==='notes'?edN:null,nmode,hv,stTab,jtab,colQuotes,setg:view==='settings'?SETG:null,y:window.scrollY});
const navSigOf=x=>[x.view,x.colSel,x.curP,x.curList,x.view==='notes'?x.selCat:'',x.wkSel,x.exSel,x.edN,x.view==='notes'?x.nmode:'',x.view==='health'?x.hv:'',x.colQuotes,x.setg||''].join('|');
function navTrack(){const st=navState(),sg=navSigOf(st);if(view==='today'&&navSnap&&navSnap.view!=='today'&&NAVH.length&&NAVH[NAVH.length-1].view==='today'){NAVH=[];navSkip=true}if(navSig!==null&&sg!==navSig&&!navSkip&&navSnap){NAVH.push(navSnap);if(NAVH.length>40)NAVH.shift()}navSkip=false;navSig=sg;navSnap=st}
window.addEventListener('scroll',()=>{if(navSnap&&navSigOf(navState())===navSig)navSnap.y=window.scrollY},{passive:true});
function navLabel(x){if(!x)return 'Back';if(x.view==='today')return 'Home';if(x.view==='collections'&&x.colSel&&FS[x.colSel])return colRead(x.colSel).title;if(x.view==='collections'&&x.colQuotes)return 'Quotes';
 if(x.view==='notes'&&x.edN&&FS[x.edN])return wlPlain(noteTitle(x.edN));if(x.view==='notes'&&x.selCat)return x.selCat;if(x.view==='projects'&&x.curP&&FS['projects/'+x.curP+'.md'])return getP(x.curP).name;
 if(x.view==='settings'&&x.setg){const g=SETGROUPS.find(y=>y[0]===x.setg);if(g)return g[1]}if(x.view==='tasks'&&x.curList)return getList(x.curList).name;if(x.view==='health'&&x.exSel)return x.exSel;if(x.view==='health'&&x.hv&&x.hv!=='overview')return({gym:'Gym',meditation:'Meditation',body:'Body'})[x.hv]||'Health';return (TABS.find(t=>t[0]===x.view)||[0,'Back'])[1]}
// A section's main page (no list, project, note, category… open): its back button always goes Home.
const secRoot=()=>({collections:!colSel&&!colQuotes,projects:!curP,tasks:!curList,notes:!edN&&!selCat,health:!wkSel&&!exSel&&(!hv||hv==='overview'),settings:!SETG})[view]??true;
function navBack(){const x=NAVH.pop();if(!x)return false;if(x.view==='today')NAVH=[];flushNote&&flushNote();navSkip=true;view=x.view;colSel=x.colSel;CD=null;curP=x.curP;edP=false;curList=x.curList;edL=false;selCat=x.selCat;wkSel=x.wkSel;WK=null;exSel=x.exSel;
 if(x.view==='notes'){edN=x.edN;ND=null;nmode=x.nmode;if(edN){nViewK=edN;nView=true}}hv=x.hv;stTab=x.stTab;jtab=x.jtab;colQuotes=x.colQuotes;SETG=x.setg||null;hq='';render();window.scrollTo(0,x.y||0);return true}
// The note a link was opened from: the destination's back button (and a "‹ Note" button on top) return to it.
let wlFrom=null;
// A back button: the usual round ‹, or "‹ Note name" when this page was opened from a link in a note.
const backBtn=(act,lab,tt)=>NAVH.length?`<button class="circ backnote" data-act="navBack" aria-label="Back to ${esc(navLabel(NAVH[NAVH.length-1]))}" title="Back">${lineIco('M15 5l-7 7 7 7')}<span data-notr>${esc(navLabel(NAVH[NAVH.length-1]))}</span></button>`:`<button class="circ" data-act="${act}" aria-label="${lab}" title="${tt}">${lineIco('M15 5l-7 7 7 7')}</button>`;
function wlReturn(){const f=wlFrom;wlFrom=null;if(!f||!FS[f.k])return;view='notes';nmode=f.nmode||'notes';edN=f.k;ND=null;nViewK=f.k;nView=f.nView!==false;window.scrollTo(0,0)}
const wlIndex=()=>{if(WLC&&Date.now()-WLC.t<1500)return WLC.m;const m=new Map(),add=(n,o)=>{const f=fold(String(n||'').trim());if(f&&!m.has(f))m.set(f,{...o,name:String(n).trim()})};
 [...keys('notes/'),...(secOn('journal')?entKeys():[])].forEach(k=>add(noteTitle(k),{kind:isJE(k)?'journal':'note',k}));
 if(secOn('projects'))projects().forEach(p=>add(p.name,{kind:'project',k:p.id}));
 if(secOn('collections'))colKeys().forEach(k=>add(colRead(k).title,{kind:'col',k}));
 if(secOn('tasks'))allLists().forEach(l=>add(l.name,{kind:'list',k:l.id}));
 WLC={t:Date.now(),m};return m};
const WLICO={note:['note','📝'],journal:['notebook','📓'],project:['folder','📁'],col:['books','📚'],list:['list-bullets','📋']};
const unesc=t=>t.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&amp;/g,'&');
const wlCap=(raw,alias)=>{const t=unesc(raw).trim(),x=wlIndex().get(fold(t)),lab=esc(alias?unesc(alias).trim():t);
 if(!x)return `<button class="wl missing" data-act="wlNew" data-v="${esc(t)}" title="Create a note called “${esc(t)}”"><span class="wli">${lineIco('M12 5v14M5 12h14')}</span><span class="wlt">${lab}</span></button>`;
 let[ic,em]=WLICO[x.kind];if(x.kind==='col'&&FS[x.k]){const t=ctype(colRead(x.k).type);ic=t.sym;em=t.emoji}return `<button class="wl wl-${x.kind}" data-act="wlGo" data-kind="${x.kind}" data-v="${esc(x.k)}" title="Open ${esc(x.name)}"><span class="wli">${symbols()?sym(ic):em}</span><span class="wlt">${lab}</span></button>`};
const il=s=>{const codes=[],wls=[];s=esc(s).replace(/`([^`]+)`/g,(_,c)=>{codes.push(c);return `\u0000${codes.length-1}\u0000`}).replace(/\[\[([^\]|\n]+)(?:\|([^\]\n]+))?\]\]/g,(_,t,a)=>{wls.push(wlCap(t,a));return `\u0001${wls.length-1}\u0001`});
 s=s.replace(/\[([^\]]+)\]\(((?:https?:\/\/|mailto:)[^)\s]+)\)/g,(_,t,u)=>mdA(u,t)).replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g,(_,p,u)=>p+mdA(u,u))
  .replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/(^|[^*\w])\*([^*\s][^*]*?)\*(?!\*)/g,'$1<i>$2</i>').replace(/(^|[^\w])_([^_\s][^_]*?)_(?!\w)/g,'$1<i>$2</i>')
  .replace(/~~(.+?)~~/g,'<s>$1</s>').replace(/==(.+?)==/g,'<mark>$1</mark>');
 return s.replace(/\u0000(\d+)\u0000/g,(_,i)=>`<code>${codes[+i]}</code>`).replace(/\u0001(\d+)\u0001/g,(_,i)=>wls[+i])};
function md(src){src=src.replace(/^---\n[\s\S]*?\n---\n?/,'');let h='',lt='',m,imgs=[],code=null;
 const cl=()=>{if(lt){h+=`</${lt}>`;lt=''}},fl=()=>{if(imgs.length){h+=mosaic(imgs);imgs=[]}},open=t=>{if(lt!==t){cl();h+=`<${t}>`;lt=t}};
 for(const l of src.split('\n')){
  if(code!==null){if(/^```/.test(l)){h+=`<pre class="mdcode"><code>${esc(code.join('\n'))}</code></pre>`;code=null}else code.push(l);continue}
  if(/^```/.test(l)){fl();cl();code=[];continue}
  if(m=l.match(IMGRE)){cl();imgs.push(m[1]);continue}
  if(!l.trim()&&imgs.length)continue;fl();
  if(m=l.match(LOCRE)){cl();h+=`<p class="jloc">${sym('map-pin')}<span>${il(m[1])}</span></p>`}
  else if(m=l.match(/^(#{1,6}) (.*)/)){cl();const n=Math.min(m[1].length,3)+2;h+=`<h${n}>${il(m[2])}</h${n}>`}
  else if(/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(l)){cl();h+='<hr>'}
  else if(m=l.match(/^>\s?(.*)/)){open('blockquote');h+=m[1].trim()?`<p>${il(m[1])}</p>`:''}
  else if(m=l.match(/^\s*[-*+] (?:\[([ xX])\] )?(.*)/)){open('ul');h+=`<li${m[1]?' class="c"':''}>${m[1]?(m[1]===' '?'☐ ':'☑ '):''}${il(m[2])}</li>`}
  else if(m=l.match(/^\s*\d+[.)] (.*)/)){open('ol');h+=`<li>${il(m[1])}</li>`}
  else if(!l.trim())cl();
  else{cl();h+=`<p>${il(l)}</p>`}}
 if(code!==null)h+=`<pre class="mdcode"><code>${esc(code.join('\n'))}</code></pre>`;
 fl();cl();return h}

/* ---------- zip export (stored, no compression) ---------- */
const CT=(()=>{const t=[];for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
const crc=b=>{let c=-1;for(const x of b)c=CT[(c^x)&255]^(c>>>8);return(c^-1)>>>0};
function zip(files){const enc=new TextEncoder(),parts=[],cen=[];let off=0;const names=Object.keys(files);
 for(const n of names){const nb=enc.encode(n),d=enc.encode(files[n]),c=crc(d);
  const h=new DataView(new ArrayBuffer(30));h.setUint32(0,0x04034b50,true);h.setUint16(4,20,true);h.setUint16(6,0x0800,true);h.setUint16(12,33,true);h.setUint32(14,c,true);h.setUint32(18,d.length,true);h.setUint32(22,d.length,true);h.setUint16(26,nb.length,true);
  parts.push(h.buffer,nb,d);
  const e=new DataView(new ArrayBuffer(46));e.setUint32(0,0x02014b50,true);e.setUint16(4,20,true);e.setUint16(6,20,true);e.setUint16(8,0x0800,true);e.setUint16(14,33,true);e.setUint32(16,c,true);e.setUint32(20,d.length,true);e.setUint32(24,d.length,true);e.setUint16(28,nb.length,true);e.setUint32(42,off,true);
  cen.push(e.buffer,nb);off+=30+nb.length+d.length}
 const cs=cen.reduce((a,b)=>a+b.byteLength,0),z=new DataView(new ArrayBuffer(22));
 z.setUint32(0,0x06054b50,true);z.setUint16(8,names.length,true);z.setUint16(10,names.length,true);z.setUint32(12,cs,true);z.setUint32(16,off,true);
 return new Blob([...parts,...cen,z.buffer],{type:'application/zip'})}

/* ---------- state, helpers ---------- */
let curQ=null,qBusy=false,qf='all',qs='',SAMPLE=null,edT=null,ansQ=null,curP=null,edP=false,edS=null,addSubT=null,expd=new Set(),hday=TD(),edH=null,HD=freshHD(),homeEdit=false,icoPick=null;
let view=CFG.start||'today',pi=Math.floor(Math.random()*PROMPTS.length),cm=new Date(),sel=TD(),q='',edN=null,edJ=null,armed=null,DL=null;
cm.setDate(1);
if(TAURI)DL={save:async({filename,data})=>{const b=data instanceof Blob?data:new Blob([data]);
 const b64=await new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok(String(r.result).split(',')[1]||'');r.onerror=()=>no(r.error);r.readAsDataURL(b)});
 if(!await TAURI.invoke('save_download',{name:filename,data:b64}))throw{code:'declined'}}};
const TABS=[['today','Home'],['notes','Notes'],['journal','Journal'],['tasks','Tasks'],['projects','Projects'],['habits','Habits'],['health','Health'],['collections','Collections'],['calendar','Calendar'],['insights','Insights'],['files','Storage'],['music','Music'],['settings','Settings']];
const keys=p=>Object.keys(FS).filter(k=>k.startsWith(p)).sort().reverse();
const toast=m=>{const t=$('toast');t.classList.remove('withact');t.textContent=m;t.hidden=false;clearTimeout(toast.t);toast.t=setTimeout(()=>t.hidden=true,3500)};
// A toast with buttons (e.g. Open, Undo); each button runs its function and closes the toast.
const toastAct=(m,acts)=>{const t=$('toast');t.classList.add('withact');t.innerHTML=`<span>${esc(m)}</span>${acts.map((a,i)=>`<button class="tact" data-ti="${i}">${esc(a[0])}</button>`).join('')}`;t.hidden=false;
 t.querySelectorAll('.tact').forEach(b=>b.onclick=()=>{t.hidden=true;acts[+b.dataset.ti][1]()});clearTimeout(toast.t);toast.t=setTimeout(()=>t.hidden=true,7000)};
async function dl(name,data){
 if(DL){try{await DL.save({filename:name,data});toast('Saved '+name)}catch(e){if(e.code!=='declined')toast('Could not save: '+(e.message||e.code||e))}}
 else{const a=document.createElement('a');a.href=URL.createObjectURL(data instanceof Blob?data:new Blob([data]));a.download=name;a.click()}}
const plain=k=>FS[k].replace(/^---[\s\S]*?---\n/,'').split('\n').filter(l=>l.trim()&&!l.startsWith('#')).join(' ');
// Home "How are you feeling?": pick a level, add emotions, save a check-in for this moment; today's check-ins are listed.
let MC=null;
const mcRow=x=>`<div class="mcrow"><span class="meta mct">${tf(x.t)}</span><span class="dot" style="background:var(${MOOD[x.m-1][1]})"></span><b>${MOOD[x.m-1][0]}</b>${x.emos.length?`<span class="meta mce">${x.emos.map(esc).join(', ')}</span>`:''}<button class="cx rbtn mcdel" data-act="mcDel" data-i="${x.i}" aria-label="Delete check-in" title="Delete">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`;
function moodCard(){const t=TD(),today=moodsRead().filter(x=>x.d===t).reverse();
 const lv=`<div class="moods">${MOOD.map((m,i)=>`<button data-act="mcPick" data-n="${i+1}" class="${MC&&MC.m===i+1?'on':''}" aria-pressed="${!!(MC&&MC.m===i+1)}"><span class="dot" style="background:var(${m[1]})"></span>${m[0]}</button>`).join('')}</div>`;
 const pick=MC?`<div class="mcemo"><span class="meta">What are you feeling? <span class="meta">(optional)</span></span>${emoChips(MC.emos,'mcEmo')}<div class="row" style="margin:10px 0 0"><button class="b tick" data-act="mcSave" aria-label="Save check-in" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="mcCancel">Cancel</button></div></div>`:'';
 const list=today.length?`<div class="mclist">${today.map(mcRow).join('')}</div>`:'';
 return `${lv}${pick}${list}`}
const moodBtns=()=>`<div class="moods">${MOOD.map((m,i)=>`<button data-act="mood" data-n="${i+1}" class="${getMood(TD())===i+1?'on':''}"><span class="dot" style="background:var(${m[1]})"></span>${m[0]}</button>`).join('')}</div>`;
// Places used in earlier entries ("📍 Place" lines), most recent first, for the location suggestions.
const LOCRE=/^📍\s*(.+?)\s*$/;
const places=()=>{const out=[];entKeys().forEach(k=>{const l=jeRead(k).loc;if(l&&!out.includes(l))out.push(l)});dayKeys().forEach(k=>FS[k].split('\n').reverse().forEach(l=>{const m=l.match(LOCRE);if(m&&!out.includes(m[1]))out.push(m[1])}));return out.slice(0,50)};
/* Emotions on journal entries ("emotions: [Grateful, Tired]" in the entry's front matter): several can be picked
   with the mood when writing, and changed while editing. */
const EMOS=[['Happy','pos'],['Grateful','pos'],['Calm','pos'],['Excited','pos'],['Proud','pos'],['Loved','pos'],['Hopeful','pos'],['Content','pos'],['Motivated','pos'],['Relaxed','pos'],
 ['Anxious','neg'],['Stressed','neg'],['Sad','neg'],['Angry','neg'],['Tired','neg'],['Lonely','neg'],['Frustrated','neg'],['Overwhelmed','neg'],['Bored','neg'],['Worried','neg']];
let JEMO=[],emoOpen=false;
const emoKind=x=>(EMOS.find(e=>e[0]===x)||[0,'pos'])[1];
const emoChips=(sel,act,k)=>`<div class="emos">${EMOS.map(([x,kd])=>`<button class="emo ${kd} ${sel.includes(x)?'on':''}" data-act="${act}" data-v="${x}"${k?` data-k="${esc(k)}"`:''} aria-pressed="${sel.includes(x)}">${x}</button>`).join('')}</div>`;
const emoPick=inJ=>inJ||emoOpen||JEMO.length?`<div class="emowrap"><span class="meta">What are you feeling?${JEMO.length?` <b>${JEMO.length}</b>`:''}</span>${emoChips(JEMO,'jeEmo')}</div>`:`<button class="x emoadd" data-act="emoOpenT">+ Add emotions</button>`;
const emoRead=l=>l.length?`<div class="emos ro">${l.map(x=>`<span class="emo ${emoKind(x)} on">${esc(x)}</span>`).join('')}</div>`:'';
const jMoodPick=lab=>`<div class="jmood">${lab?'<span class="meta">How do you feel right now?</span>':''}<div class="moods seg">${MOOD.map((m,i)=>`<button data-act="jmSet" data-n="${i+1}" class="${JM===i+1?'on':''}" aria-pressed="${JM===i+1}"><span class="dot" style="background:var(${m[1]})"></span>${m[0]}</button>`).join('')}</div></div>`;
/* "How are you feeling?" (Home, Journal → Emotions and New entry): a mood level, emotions once a level is picked,
   and optional writing. Without text, Save only logs a mood check-in (journal/moods.md); with text it also
   saves a journal entry with the same mood and emotions. mode: none = Home, 1 = Journal New entry, 2 = Emotions tab. */
const writeBox=mode=>{const inJ=mode===1,today=mode?[]:moodsRead().filter(x=>x.d===TD()).reverse();return `<section${inJ?' class="jnew"':' class="feelbox"'}><h2>${inJ?'New entry':'How are you feeling?'}</h2>${jMoodPick(inJ)}${JM||JEMO.length?`<div class="emowrap"><span class="meta">What are you feeling? <span class="meta">(optional)</span>${JEMO.length?` <b>${JEMO.length}</b>`:''}</span>${emoChips(JEMO,'jeEmo')}</div>`:''}${moodQ(JM)}<textarea id="jt" placeholder="${inJ?'Start anywhere. You can paste photos here too.':'Write about it (optional). Adds a journal entry. You can paste photos too.'}"></textarea>${JIMG.length?`<div class="jpend">${JIMG.map((x,i)=>`<span class="jth"><img src="${x.url}" alt="Photo ${i+1}"><button class="cx" data-act="jimgDel" data-i="${i}" aria-label="Remove photo ${i+1}">×</button></span>`).join('')}</div>`:''}${jCatPick('new',JC)}<label class="jlocin">${sym('map-pin')}<input id="jloc" placeholder="Add location" list="dl-places" autocomplete="off" aria-label="Location"></label><datalist id="dl-places">${places().map(x=>`<option value="${esc(x)}">`).join('')}</datalist><div class="row"><button class="b" data-act="saveJ">Save</button><button class="g" data-act="addImg">Add photos</button>${inJ?'<span style="flex:1"></span><button class="g" data-act="jNewCancel">Cancel</button>':''}</div>${today.length?`<div class="mclist">${today.map(mcRow).join('')}</div>`:''}</section>`};
const qBox=()=>`<section><h2>Today’s question</h2><p class="q">${curQ?esc(curQ):qBusy?'Thinking of a question…':'No question right now. Ask for a new one.'}</p>${curQ&&qBusy?'<p class="meta">Finding a new question…</p>':''}${curQ&&!qBusy?`<textarea id="qa0" placeholder="Your answer is saved in Journal → Questions."></textarea>`:''}<div class="row">${curQ&&!qBusy?`<button class="b" data-act="saveQ" data-k="${esc(curQ)}" data-t="qa0">Save answer</button>`:''}<button class="g" data-act="newQ" ${qBusy?'disabled':''}>${SAMPLE&&CFG.intAi?'New question from AI':'New question'}</button></div></section>`;
const isQ=s=>/^## [^—\n]*— .+/.test(s);
const freeText=k=>{const p=FS[k].split(/\n(?=## )/),f=p.slice(1).filter(x=>!isQ(x));return f.length?[p[0],...f].join('\n'):null};
// A task outside the Tasks section (Home, search, projects, calendar) uses the same checklist-style row,
// tinted with its list's color (or the accent color when it has no list).
const taskRow=t=>`<div class="rhost" style="--tc:${t.list&&FS[listKey(t.list)]?vivid(getList(t.list).color):'var(--ac)'}">${remRow(t)}</div>`;
const fileBtns=k=>{const e=esc(k);return `${k[0]==='n'?`<button class="x" data-act="pin" data-k="${e}">${isPinned(k)?'Unpin':'Pin'}</button>`:''}<button class="x" data-act="edit${k[0]==='n'?'N':'J'}" data-k="${e}">Edit</button><button class="x" data-act="delF" data-k="${e}">${armed===k?'Click again to delete':'Delete'}</button>`};

/* ---------- reflection questions: never repeated, answered or not ---------- */
const nq=s=>s.toLowerCase().replace(/[^\p{L}\p{N} ]/gu,'').replace(/\s+/g,' ').trim();
const qLines=()=>(FS['questions.md']||'').split('\n').map(l=>l.match(ERE)).filter(Boolean).map(m=>({d:m[1],q:m[2]}));
function answers(){const out={};
 Object.keys(FS).filter(isDayK).sort().forEach(k=>{const d=k.slice(8,-3);
  FS[k].split(/\n(?=## )/).forEach(sec=>{const m=sec.match(/^## [^—\n]*— (.+)\n+([\s\S]*)$/);
   if(m){const n=nq(m[1]);(out[n]=out[n]||{q:m[1].trim(),a:[]}).a.push({d,t:m[2].trim()})}})});
 return out}
function allQ(){const ans=answers(),seen={},list=[];
 const add=(q,d)=>{const n=nq(q);if(!seen[n]){seen[n]=1;list.push({q,d,i:list.length,a:(ans[n]||{a:[]}).a})}};
 qLines().forEach(x=>add(x.q,x.d));
 Object.values(ans).forEach(v=>add(v.q,v.a[0].d));
 return list.sort((a,b)=>a.d<b.d?1:a.d>b.d?-1:b.i-a.i)}
const DRE=/^- ~~(\d{4}-\d{2}-\d{2}): (.*)~~\s*$/;
const delLines=()=>(FS['questions.md']||'').split('\n').map(l=>l.match(DRE)).filter(Boolean).map(m=>({d:m[1],q:m[2]}));
const used=()=>new Set(allQ().concat(delLines()).map(x=>nq(x.q)));
function deleteQ(q){const n=nq(q),it=allQ().find(x=>nq(x.q)===n),d=it?it.d:TD();
 Object.keys(FS).filter(isDayK).forEach(k=>{const parts=FS[k].split(/\n(?=## )/);
  const keep=parts.filter((s,i)=>{if(i===0)return true;const m=s.match(/^## [^—\n]*— (.+)/);return !(m&&nq(m[1])===n)});
  if(keep.length!==parts.length){if(keep.length<2&&!/^mood:/m.test(keep[0]))delete FS[k];else FS[k]=keep.join('\n').replace(/\n*$/,'\n')}});
 const lines=(FS['questions.md']||'# Questions\n\n').split('\n').filter(l=>{const m=l.match(ERE);return !(m&&nq(m[2])===n)});
 FS['questions.md']=lines.join('\n').replace(/\n+$/,'')+`\n- ~~${d}: ${q}~~\n`;
 if(curQ&&nq(curQ)===n)curQ=null}
function issue(q){FS['questions.md']=(FS['questions.md']||'# Questions\n\n').replace(/\n+$/,'')+`\n- ${TD()}: ${q}\n`;curQ=q}
function bankQ(){const u=used(),f=PROMPTS.filter(p=>!u.has(nq(p)));return f.length?f[Math.floor(Math.random()*f.length)]:null}
// Topics for new AI questions: [id, label, what it means for the question]. Several can be chosen; none = anything.
const QTOPICS=[['friends','Friends','friendships and the people you choose to spend time with'],['family','Family','family, parents, siblings and relatives'],['partner','Partner','a romantic partner, dating and love'],['self','Self-image','how you see yourself, self-esteem and self-worth'],
 ['emotions','Emotions','feelings, moods and what triggers them'],['stress','Stress','stress, anxiety, pressure and what calms you'],['fears','Fears','fears, worries and what holds you back'],['gratitude','Gratitude','gratitude and the good things in your life'],
 ['work','Work','your job, colleagues and daily work'],['career','Career','career direction, ambition and professional goals'],['money','Money','money, spending, saving and security'],['learning','Learning','learning, curiosity and skills'],
 ['health','Health','physical health, sleep, food and exercise'],['habits','Habits','habits, routines and discipline'],['rest','Rest','rest, free time and recharging'],['hobbies','Hobbies','hobbies, play and things you enjoy'],['creativity','Creativity','creativity, ideas and making things'],
 ['values','Values','your values, principles and what matters most'],['purpose','Purpose','meaning, purpose and the bigger picture'],['growth','Growth','personal growth and who you are becoming'],['goals','Goals','goals, plans and the future'],['past','Memories','memories, the past and what shaped you'],['home','Home','home, where you live and your surroundings'],['spirit','Spirituality','spirituality, faith and inner peace']];
// The chosen topic ids (older versions stored a single focus string).
const qTopics=()=>{const f=CFG.focus;const a=Array.isArray(f)?f:f&&f!=='any'?[f==='relationships'?'friends':f]:[];return a.filter(x=>QTOPICS.some(t=>t[0]===x))};
const topicPick=()=>{const tp=qTopics();return `<div class="moods multi qtopics"><button data-act="qtopic" data-val="" class="${tp.length?'':'on'}" aria-pressed="${!tp.length}">Anything</button>${QTOPICS.map(([id,l])=>`<button data-act="qtopic" data-val="${id}" class="${tp.includes(id)?'on':''}" aria-pressed="${tp.includes(id)}">${l}</button>`).join('')}</div>`};
/* AI (Claude). Inside Claude's web app it uses the built-in connection (SAMPLE); in the desktop app it uses the person's
   own Anthropic API key (Settings → Integrations), sent from the app's backend. */
const AIMODELS=[['claude-haiku-5-5','Haiku 5.5 · fast'],['claude-sonnet-5-5','Sonnet 5.5 · balanced'],['claude-opus-5-5','Opus 5.5 · best']];
const aiFn=()=>SAMPLE||(TAURI&&(CFG.aiKey||'').trim()?p=>TAURI.invoke('ai_complete',{key:CFG.aiKey,model:CFG.aiModel||'claude-haiku-5-5',prompt:p,system:null,maxTokens:1500}).then(text=>({text})):null);
async function aiQ(){const SMP=aiFn();if(!SMP||!CFG.intAi)return null;const list=allQ().concat(delLines()).slice(0,150).map(x=>'- '+x.q).join('\n'),u=used();
 // one of the chosen topics at random, so new questions rotate through them (none chosen = anything)
 const tp=qTopics(),pick=tp.length?QTOPICS.find(x=>x[0]===tp[Math.floor(Math.random()*tp.length)]):null,focus=pick?` Focus on this area of life: ${pick[2]}.`:'';
 for(let t=0;t<2;t++){
  const r=await SMP(`Write one new journaling question that helps someone understand themselves better${CFG.lang==='es'?', written in Spanish (Spain)':''}. One question only, under 25 words, plain and warm, no preamble, no quotes, no numbering.${focus} It must differ in both topic and wording from every question already asked:\n${list||'(none yet)'}\n\nReply with the question only.`,{modelTier:'quick',cache:false});
  const q=(r.text||'').trim().split('\n')[0].replace(/^\d+[.)]\s+/,'').replace(/^[-*\s"“]+|["”\s]+$/g,'');
  if(q.length>8&&q.length<200&&!u.has(nq(q)))return q}
 return null}
function keepRender(){const t=$('jt'),v=t&&t.value;render();const n=$('jt');if(n&&v)n.value=v}
async function newQ(){if(qBusy)return;qBusy=true;keepRender();let q=null;
 try{q=await aiQ()}catch(e){}
 if(!q){q=bankQ();if(q&&CFG.intAi)toast(aiFn()?'AI didn’t give a usable question, so I used a built-in one.':'AI isn’t available here, so I used a built-in question.')}
 qBusy=false;if(q)issue(q);else toast('No unused built-in questions left. Try again when AI is available.');
 save();keepRender()}

/* ---------- task reminders ---------- */
let FIRED=[];try{FIRED=JSON.parse(store.get('daybook.fired')||'[]')}catch(e){}
const saveFired=()=>store.set('daybook.fired',JSON.stringify(FIRED.slice(-300)));
const rkey=t=>t.rem+'|'+t.title,NOTIFIED=new Set();
const stamp=d=>iso(d)+' '+pad(d.getHours())+':'+pad(d.getMinutes());
const dueRem=()=>{const n=stamp(new Date());return tasks().filter(t=>!t.done&&t.rem&&t.rem<=n&&!FIRED.includes(rkey(t)))};
const NS=()=>TAURI?'granted':window.Notification?Notification.permission:'unsupported';
// Birthday reminders: once a day, a notification for tomorrow's birthdays (and today's).
function bdRemind(){const t=TD();if(CFG.bdNotified===t||!FS['birthdays.md'])return;const tm=dAdd(t,1),tod=bdays().filter(b=>`${b.m}-${b.d}`===t.slice(5)),tom=bdays().filter(b=>`${b.m}-${b.d}`===tm.slice(5));CFG.bdNotified=t;saveCfg();
 if(tom.length){const m='Tomorrow: '+tom.map(b=>b.name).join(', ');notify('Birthday tomorrow',m,{key:'bd:'+t+':tom',ico:'cake',go:{view:'calendar'}});toast('🎂 '+m)}if(tod.length){const m='Today: '+tod.map(b=>b.name).join(', ');notify('Birthday today',m,{key:'bd:'+t,ico:'cake',go:{view:'calendar'}});toast('🎂 '+m)}}
const notifyOS=(title,body)=>{if(TAURI)return TAURI.invoke('notify',{title,body}).catch(()=>{});try{if(window.Notification&&Notification.permission==='granted')new Notification(title,{body})}catch(e){}};
// Every notification also goes to the bell panel (see the notification center below).
const notify=(title,body,o)=>{nAdd(title,body,o);return notifyOS(title,body)};
/* Notification center: a bell at the top right with the unread count, and a panel that slides in from the right with
   "Today" (due tasks, upcoming events, birthdays, habits left) and the notification history (CFG.notifs, newest 60;
   o.key avoids repeats, o.go = {view, …} opens the right page, o.ico picks the icon). */
let NP=false,npFresh=new Set();
function nAdd(title,body,o={}){const l=CFG.notifs||[];if(o.key&&l.some(x=>x.key===o.key))return;
 l.unshift({id:Date.now().toString(36)+Math.random().toString(36).slice(2,5),at:Date.now(),title:String(title||''),body:String(body||''),ico:o.ico||'bell',go:o.go||null,key:o.key||'',read:false});
 CFG.notifs=l.slice(0,60);saveCfg();nBell();if(NP)npShow()}
const nUnread=()=>(CFG.notifs||[]).filter(x=>!x.read).length;
const nAgo=ms=>{const m=Math.round((Date.now()-ms)/60000);return m<1?'Just now':m<60?`${m} min ago`:m<1440?`${Math.round(m/60)} h ago`:fmt(iso(new Date(ms)))};
function nBell(){let b=$('nbell');if(PWLOCK||ONB){if(b)b.remove();return}if(!b){b=document.createElement('button');b.id='nbell';b.className='circ nbell';b.dataset.act='npToggle';document.body.appendChild(b)}
 const n=nUnread();b.setAttribute('aria-label',n?`Notifications, ${n} unread`:'Notifications');b.title='Notifications';b.setAttribute('aria-expanded',String(NP));b.classList.toggle('on',NP);
 b.innerHTML=`${uiIco(n?'bell-ringing':'bell','🔔')}${n?`<span class="nbadge">${n>9?'9+':n}</span>`:''}`;nbPlace()}
// The bell lines up with each page's own header buttons: same top, 8 px after the content's right edge (the page keeps
// that space free on wide windows).
function nbPlace(){const b=$('nbell'),m=$('main');if(!b||!m)return;if(innerWidth<=760){b.style.left='';b.style.top='';return}
 const r=m.getBoundingClientRect(),cs=getComputedStyle(m),pr=parseFloat(cs.paddingRight)||0,pt=parseFloat(cs.paddingTop)||0;
 b.style.left=Math.round(r.right-pr+8)+'px';b.style.top=Math.round(r.top+window.scrollY+pt)+'px'}
window.addEventListener('resize',()=>nbPlace());
// "Today": what needs attention now, computed from tasks, events, birthdays and habits.
function npToday(){const t=TD(),out=[],nowM=new Date().getHours()*60+new Date().getMinutes();
 if(secOn('tasks')){const due=tasks().filter(x=>!x.done&&x.due&&x.due<=t).sort((a,b)=>a.due.localeCompare(b.due));if(due.length)out.push({ico:'check-square',title:`${due.length} task${due.length===1?'':'s'} due`,body:due.slice(0,4).map(x=>x.title+(x.due<t?' (overdue)':'')).join(' · ')+(due.length>4?' …':''),go:{view:'tasks',list:'today'}})}
 if(secOn('calendar')){const E=events(),up=[...evOn(E,t).filter(e=>!e.bday&&(!e.start||mins(e.start)>=nowM-30)).map(e=>({e,d:t})),...evOn(E,dAdd(t,1)).filter(e=>!e.bday).map(e=>({e,d:dAdd(t,1)}))];
  if(up.length)out.push({ico:'calendar-dots',title:'Coming up',body:up.slice(0,4).map(({e,d})=>`${d===t?'Today':'Tomorrow'}${e.start?' '+tf(e.start):''} · ${e.title}`).join('\n'),go:{view:'calendar'}});
  const bd=bdOn(t).concat(bdOn(dAdd(t,1)).map(x=>({...x,tom:true})));if(bd.length)out.push({ico:'cake',title:'Birthdays',body:bd.map(x=>(x.tom?'Tomorrow: ':'Today: ')+x.title.replace(/^🎂 /,'')).join(' · '),go:{view:'calendar'}})}
 if(secOn('habits')){const left=habits().filter(h=>h.period!=='weekly'&&h.pol==='good'&&h.log[t]===undefined);if(left.length)out.push({ico:'repeat',title:`${left.length} habit${left.length===1?'':'s'} left today`,body:left.slice(0,5).map(h=>h.name).join(' · '),go:{view:'habits'}})}
 return out}
function npShow(){let o=$('npanel');if(!NP){if(o){o.classList.remove('open');setTimeout(()=>{if(!NP&&o.parentNode)o.remove()},220)}nBell();return}
 if(!o){o=document.createElement('aside');o.id='npanel';o.className='ncenter';o.setAttribute('role','dialog');o.setAttribute('aria-label','Notifications');document.body.appendChild(o);requestAnimationFrame(()=>o.classList.add('open'))}
 const T=npToday(),L=CFG.notifs||[],item=(x,i,hist)=>`<div class="nitem ${hist&&npFresh.has(x.id)?'new':''}"><button class="nmain" data-act="npGo" data-k="${hist?esc(x.id):''}" data-i="${i}" data-h="${hist?1:0}"><span class="nico">${uiIco(x.ico||'bell','🔔')}</span><span class="ntx"><b data-notr>${esc(x.title)}</b>${x.body?`<span class="meta" data-notr>${esc(x.body).replace(/\n/g,'<br>')}</span>`:''}${hist?`<span class="meta nwhen">${nAgo(x.at)}</span>`:''}</span></button>${hist?`<button class="cx ndel" data-act="npDel" data-k="${esc(x.id)}" aria-label="Remove" title="Remove">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</div>`;
 o.innerHTML=`<div class="nphead"><h2>Notifications</h2><button class="cx" data-act="npToggle" aria-label="Close" title="Close (Esc)">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
<div class="npbody"><p class="meta lab0 nplab">Today</p>${T.length?T.map((x,i)=>item(x,i,false)).join(''):'<p class="meta npempty">Nothing needs your attention right now.</p>'}
<div class="nplab2"><p class="meta lab0 nplab">Earlier</p>${L.length?`<button class="x" data-act="npClear">Clear all</button>`:''}</div>${L.length?L.map((x,i)=>item(x,i,true)).join(''):'<p class="meta npempty">No notifications yet. Reminders, timers, alarms, birthdays and finished sessions show up here.</p>'}</div>`;
 if(CFG.lang==='es')i18nRun(o);nBell()}
function npToggle(on){NP=on===undefined?!NP:on;if(NP){npFresh=new Set((CFG.notifs||[]).filter(x=>!x.read).map(x=>x.id));(CFG.notifs||[]).forEach(x=>x.read=true);saveCfg()}npShow()}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&NP){npToggle(false)}});
document.addEventListener('pointerdown',e=>{if(NP&&!(e.target.closest&&e.target.closest('#npanel,#nbell,#ctx,.cfm')))npToggle(false)});
function showRem(){const d=CFG.intRem===false||!secOn('tasks')?[]:dueRem(),el=$('rem');
 d.forEach(t=>{if(!NOTIFIED.has(rkey(t))){NOTIFIED.add(rkey(t));nAdd('Reminder',t.title,{key:'rem:'+rkey(t),ico:'bell-ringing',go:{view:'tasks',list:'today'}});try{if(CFG.intNotif&&NS()==='granted')notifyOS('Prodify reminder',t.title)}catch(e){}}});
 const html=d.map(t=>`<div class="rm"><div><b>${esc(t.title)}</b><span class="meta">Reminder for ${fmt(t.rem.slice(0,10))}, ${tf(t.rem.slice(11))}</span></div><div class="row" style="margin:0"><button class="b" data-act="rDone" data-i="${t.i}">Done</button><button class="g" data-act="rSnz" data-i="${t.i}">Snooze 10 min</button><button class="g" data-act="rOk" data-i="${t.i}">Dismiss</button></div></div>`).join('');
 el.hidden=!d.length;if(el.dataset.h!==html){el.innerHTML=html;el.dataset.h=html}}
const editRow=t=>`<div class="item"><div class="t"><input id="etit" value="${esc(t.title)}" aria-label="Task title"><div class="row"><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:200px">Due <input id="etd" type="date" value="${t.due}"></label><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:240px">Remind me ${dtField('etr',t.rem,'Remind me')}</label><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:200px">Project <select id="epj">${projOpts(t.proj)}</select></label><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:200px">List <select id="elst">${listOpts(t.list)}</select></label><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:200px">Repeat <select id="erep"><option value="">Never</option>${Object.entries(REPL).map(([k,l])=>`<option value="${k}" ${t.rep===k?'selected':''}>${l}</option>`).join('')}</select></label><label class="meta" style="display:flex;gap:8px;align-items:center;flex:1;min-width:200px">Priority <select id="epri"><option value="">None</option>${[['high','High'],['medium','Medium'],['low','Low']].map(([k,l])=>`<option value="${k}" ${t.pri===k?'selected':''}>${l}</option>`).join('')}</select></label></div><div class="row"><button class="b" data-act="saveT" data-i="${t.i}">Save</button><button class="g" data-act="cancel">Cancel</button></div></div></div>`;

/* ---------- projects: projects/<id>.md, tasks tagged "(project: id)", notes listed under "## Notes" ---------- */
/* Note files are named "<Title> <YYYY-MM-DD>.md": the title (or the first line of text, else "Untitled") and the
   created date. Characters that break file names or Obsidian links are left out; a clash gets " 2", " 3"… */
const safeName=t=>String(t).replace(/[\/\\:*?"<>|#^\[\]\u0000-\u001f]/g,' ').replace(/\s+/g,' ').trim().replace(/^\.+/,'').slice(0,80).trim()||'Untitled';
function noteKeyFor(dir,title,date,cur){const base=`${dir}${safeName(title)} ${date}`;let k=base+'.md',n=2;while(FS[k]&&k!==cur)k=`${base} ${n++}.md`;return k}
const nameTitle=(title,body)=>String(title||'').trim()||(String(body||'').split('\n').find(l=>l.trim())||'').replace(/^#+\s*/,'').trim();
const createdOf=(fm,fallback)=>/^\d{4}-\d{2}-\d{2}/.test(fm.created||'')?String(fm.created).slice(0,10):fallback||TD();
// Moves a note to a new file name, keeping project links, the open editor and expanded cards pointing at it.
function renameNote(old,nk){if(old===nk||!FS[old])return old;FS[nk]=FS[old];delete FS[old];keys(histDir(old)).forEach(h=>{FS[histDir(nk)+h.slice(histDir(old).length)]=FS[h];delete FS[h]});
 projects().forEach(p=>{const i=p.notes.indexOf(old);if(i>=0){p.notes[i]=nk;putP(p)}});
 if(expd.has(old)){expd.delete(old);expd.add(nk)}if(edN===old)edN=nk;return nk}
const slug=s=>s.toLowerCase().replace(/[^\p{L}\p{N}]+/gu,'-').replace(/^-+|-+$/g,'')||'project';
function parseP(k){const s=FS[k]||'',g=n=>{const m=s.match(new RegExp('^'+n+': (.*)$','m'));return m?m[1].trim():''};
 const body=s.replace(/^---[\s\S]*?---\n?/,''),i=body.indexOf('## Notes'),id=k.slice(9,-3);
 return {id,key:k,name:g('name')||id,status:g('status')||'active',created:g('created')||TD(),color:g('color'),symbol:g('symbol'),emoji:g('emoji'),desc:(i<0?body:body.slice(0,i)).trim(),
  notes:i<0?[]:body.slice(i).split('\n').map(l=>l.match(/^- ((?:notes|archive)\/.+\.md)\s*$/)).filter(Boolean).map(m=>m[1]),
  ms:(mi=>mi<0?[]:body.slice(mi).split('\n').map(l=>l.match(/^- \[([ xX])\] (\d{4}-\d{2}-\d{2}): (.+)$/)).filter(Boolean).map(m=>({done:m[1]!==' ',d:m[2],t:m[3].trim()})))(body.indexOf('## Milestones')),
  files:(fi=>fi<0?[]:body.slice(fi).split('\n').map(l=>l.match(/^- (!?)\[([^\]]*)\]\(([^)\s]+)\)\s*$/)).filter(Boolean).map(m=>{const att=(m[3].match(/attachments\/([^)\s]+)$/)||[])[1]||'';return{k:m[1]?'images':att&&/\.pdf$/i.test(att)?'pdfs':'links',title:m[2],url:att?'':m[3],att}}))(body.indexOf('## Files'))}}
const getP=id=>parseP('projects/'+id+'.md');
// The New project form: its icon (picker id 'newproj') and typed name survive re-renders while picking.
let PN={symbol:'',emoji:'',name:''};
const pIcon=p=>symbols()?sym(p.symbol&&SYM[p.symbol]?p.symbol:'folder-simple'):esc(p.emoji||'📁');
const projects=()=>Object.keys(FS).filter(k=>k.startsWith('projects/')).sort().map(parseP);
const putP=p=>{FS['projects/'+p.id+'.md']=`---\nname: ${p.name}\nstatus: ${p.status}\ncreated: ${p.created}\n${p.color?`color: ${p.color}\n`:''}${p.symbol?`symbol: ${p.symbol}\n`:''}${p.emoji?`emoji: ${p.emoji}\n`:''}---\n\n${p.desc?p.desc+'\n\n':''}## Notes\n\n${p.notes.map(n=>`- ${n}`).join('\n')}${p.notes.length?'\n':''}${(p.ms||[]).length?`\n## Milestones\n\n${p.ms.slice().sort((a,b)=>a.d.localeCompare(b.d)).map(m=>`- [${m.done?'x':' '}] ${m.d}: ${m.t}`).join('\n')}\n`:''}${(p.files||[]).length?`\n## Files\n\n${p.files.map(f=>`- ${f.k==='images'?'!':''}[${String(f.title||'').replace(/[\[\]\n]/g,' ').trim()}](${f.att?'../attachments/'+f.att:f.url})`).join('\n')}\n`:''}`};
const pname=id=>FS['projects/'+id+'.md']?getP(id).name:id;
const projOpts=sel=>'<option value="">No project</option>'+projects().map(p=>`<option value="${esc(p.id)}" ${p.id===sel?'selected':''}>${esc(p.name)}</option>`).join('');

const DEFICO={health:'❤️',collections:'📚',today:'🏠',notes:'📝',journal:'📓',tasks:'✅',projects:'📁',habits:'🔁',calendar:'📅',insights:'📊',files:'🗂️',music:'🎵',settings:'⚙️'};
// Card colors: "soft" uses each color as is; "vibrant" makes it more saturated and brighter (tiles, side cards).
function vivid(hex){if(CFG.cardColors!=='vibrant'||!/^#[0-9a-f]{6}$/i.test(hex))return hex;let[r,g,b]=[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255);
 const mx=Math.max(r,g,b),mn=Math.min(r,g,b),d=mx-mn;let h=0,l=(mx+mn)/2,sat=d?d/(1-Math.abs(2*l-1)):0;
 if(d)h=mx===r?((g-b)/d)%6:mx===g?(b-r)/d+2:(r-g)/d+4;h*=60;if(h<0)h+=360;
 sat=Math.min(1,sat*1.5+.18);l=Math.min(.6,Math.max(.46,l*1.06));
 const c=(1-Math.abs(2*l-1))*sat,x=c*(1-Math.abs((h/60)%2-1)),m=l-c/2,[R,G,B]=h<60?[c,x,0]:h<120?[x,c,0]:h<180?[0,c,x]:h<240?[0,x,c]:h<300?[x,0,c]:[c,0,x];
 return '#'+[R,G,B].map(v=>Math.round((v+m)*255).toString(16).padStart(2,'0')).join('')}
// A section's card color: the one picked (right-click a side card) or its default.
const secColor=id=>(CFG.navColors||{})[id]||NAVC[id]||'#7a8794';
const NAVC={health:'#e0566f',collections:'#b0794a',today:'#5b9bd5',notes:'#d4a43a',journal:'#9a5fa0',tasks:'#5fa57f',projects:'#6f7fb0',habits:'#d4605a',calendar:'#3f9aa5',insights:'#9a7fd0',files:'#7a8794',music:'#c9629b',settings:'#6b7280'};
const EMOJIS=['🏠','📝','📓','📔','❓','💭','✅','📌','📁','🗂️','🎯','🔁','💪','🌱','📅','🗓️','📊','📈','⚙️','🔧','💡','⭐','❤️','🔥','🌙','☀️','🧠','🧘','📚','🎨','🎵','✈️','💼','🏃','🍎','☕','🔒','🔔','📎','🧩','🚀','🌟'];
const ico=id=>id==='newlist'?(LD&&LD.emoji)||'':id==='catedit'?(catEd&&catEd.emoji)||'':id.startsWith('habit:')?getH(id.slice(6)).emoji||'':id.startsWith('list:')?getList(id.slice(5)).emoji||'':id==='newproj'?PN.emoji||'':id.startsWith('proj:')?getP(id.slice(5)).emoji||'':CFG.icons&&id in CFG.icons?CFG.icons[id]:(DEFICO[id]||'');
/* Symbol icons (see icons.js): an alternative to emoji, chosen in Settings → Appearance. */
const DEFSYM={health:'heartbeat',collections:'books',today:'house',notes:'note',journal:'notebook',tasks:'check-square',projects:'folder',habits:'repeat',calendar:'calendar-blank',insights:'chart-bar',files:'files',music:'music-notes',settings:'gear'};
const symName=id=>id==='newlist'?(LD&&LD.symbol)||'':id==='catedit'?(catEd&&catEd.sym)||'':id.startsWith('habit:')?getH(id.slice(6)).symbol||'':id.startsWith('list:')?getList(id.slice(5)).symbol||'':id==='newproj'?PN.symbol||'':id.startsWith('proj:')?getP(id.slice(5)).symbol||'':CFG.syms&&id in CFG.syms?CFG.syms[id]:(DEFSYM[id]||'');
// Saves a picked icon: kind 'emoji' or 'symbol'; val null restores the default.
function setIcon(id,kind,val){if(id.startsWith('habit:')){const x=getH(id.slice(6));x[kind]=val===null?'':val;putH(x);return}
 if(id==='catedit'&&catEd){catEd[kind==='symbol'?'sym':'emoji']=val===null?{symbol:'folder',emoji:'📁'}[kind]:val;return}
 if(id==='newlist'&&LD){LD[kind]=val===null?{symbol:'list-bullets',emoji:'📋'}[kind]:val;return}
 if(id==='newproj'){PN[kind]=val===null?'':val;return}
 if(id.startsWith('proj:')){const p=getP(id.slice(5));p[kind]=val===null?'':val;putP(p);return}
 if(id.startsWith('list:')){const lid=id.slice(5),l=getList(lid),d=LDEF[lid]||{symbol:'list-bullets',emoji:'📋'};l[kind]=val===null?d[kind]:val;putList(l);return}
 const key=kind==='emoji'?'icons':'syms',o={...CFG[key]};if(val===null)delete o[id];else o[id]=val;CFG[key]=o;saveCfg()}
// An interface icon: the Phosphor symbol, or the emoji when Settings → Section icons is set to Emoji.
const uiIco=(n,e)=>symbols()?sym(n):e;
const sym=n=>SYM[n]?`<svg class="sym" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true">${SYM[n]}</svg>`:'';
const symbols=()=>CFG.iconStyle==='symbols';
const icoHTML=id=>symbols()?sym(symName(id)):esc(ico(id));
function navCount(id){const t=TD();switch(id){
 case 'notes':return keys('notes/').length;
 case 'journal':return dayKeys().reduce((n,k)=>n+FS[k].split(/\n(?=## )/).slice(1).filter(s=>!isQ(s)).length,0)+entKeys().length;
 case 'tasks':return tasks().filter(x=>!x.done).length;
 case 'projects':return projects().filter(p=>p.status!=='done').length;
 case 'habits':return habits().length;
 case 'calendar':return events().filter(e=>e.date>=t).length;
 case 'collections':return colKeys().length;
 case 'health':{const ws=weekStart(t);return workouts().filter(d=>d>=ws).length}
 default:return ''}}
function renderNav(){const icons=CFG.navLayout==='icons'||CFG.navLayout==='grid',cards=CFG.navLayout==='cards'||icons;
 $('nav').innerHTML=`<div class="logo"><span>Prodify</span>${CFG.navLayout!=='top'?`<button class="navpin ${CFG.navAuto?'on':''}" data-act="navAuto" aria-pressed="${!!CFG.navAuto}" title="Auto-hide sidebar: ${CFG.navAuto?'on':'off'} (Ctrl+B)" aria-label="Auto-hide sidebar">${sym('sidebar-simple')}</button>`:''}</div>`+visTabs().map(t=>{const e=ico(t[0]),c=cards&&CFG.navCounts!==false&&!(CFG.navNoCount||[]).includes(t[0])?navCount(t[0]):'';
  return `<button data-act="nav" data-v="${t[0]}" data-dnd="tab" data-id="${t[0]}" title="${icons?esc(t[1]):'Drag to reorder'}" aria-label="${esc(t[1])}" class="navb ${view===t[0]?'on':''} ${cards&&!icons&&(CFG.navWide||[]).includes(t[0])?'wide':''}" style="--tc:${vivid(secColor(t[0]))}"><span class="ni">${icoHTML(t[0])}</span><span class="nl">${esc(t[1])}</span>${c!==''&&!(icons&&!+c)?`<span class="nc" aria-label="${c} items">${c}</span>`:''}</button>`}).join('')}
// Phone tab bar (shown instead of the sidebar on narrow windows): Home, three sections you pick, and More,
// a sheet with every other section. "Edit" in that sheet picks the three (CFG.mobTabs).
let mSheet=null;// null, 'more' or 'edit'
const mPicks=()=>{const ok=visTabs().map(t=>t[0]).filter(id=>id!=='today');const own=(CFG.mobTabs||['tasks','notes','calendar']).filter(id=>ok.includes(id)).slice(0,3);if(mSheet==='edit')return own;
 for(const id of ok){if(own.length>=3)break;if(!own.includes(id)&&id!=='settings')own.push(id)}return own.slice(0,3)};
const mLab=id=>(TABS.find(t=>t[0]===id)||[0,id])[1];
function renderMTabs(){let bar=$('mtabs');if(!bar){bar=document.createElement('div');bar.id='mtabs';bar.className='mtabs';bar.setAttribute('role','navigation');bar.setAttribute('aria-label','Sections');document.body.appendChild(bar)}
 document.body.classList.toggle('sblow',!!CFG.searchLow&&view==='today');
 const ids=['today',...mPicks()],more=!ids.includes(view)||mSheet;
 bar.innerHTML=ids.map(id=>`<button data-act="nav" data-v="${id}" ${id!=='today'?`data-dnd="mtab" data-id="${id}"`:''} class="${view===id&&!mSheet?'on':''}" style="--tc:${vivid(secColor(id))}" aria-current="${view===id?'page':'false'}"><span class="ni">${icoHTML(id)}</span><span class="nl">${esc(id==='today'?'Home':mLab(id))}</span></button>`).join('')
  +`<button data-act="mMore" class="${more?'on':''}" aria-expanded="${!!mSheet}"><span class="ni">${lineIco('M5 12h.01M12 12h.01M19 12h.01')}</span><span class="nl">More</span></button>`;
 let sh=$('msheet');document.body.classList.toggle('msopen',!!mSheet);if(!mSheet){if(sh)sh.remove();return}
 if(!sh){sh=document.createElement('div');sh.id='msheet';sh.className='msheet';document.body.appendChild(sh)}
 const edit=mSheet==='edit',pk=mPicks(),list=visTabs().map(t=>t[0]).filter(id=>id!=='today'&&(edit||!pk.includes(id)));
 // Update the open sheet in place: rebuilding it would replay its slide-up animation on every tap.
 const inner=`<div class="mshead"><h2>${edit?'Tab bar':'More'}</h2>${edit?`<span class="meta">${pk.length}/3 picked</span><button class="b" data-act="mEditDone">Done</button>`:`<button class="g" data-act="mEdit">Edit tab bar</button>`}</div>
${edit?'<p class="meta" style="margin:0 0 10px">Pick 3 sections to keep next to Home. Drag them in the tab bar below to change their order.</p>':''}<div class="msgrid">${list.map(id=>{const on=pk.includes(id);return `<button data-act="${edit?'mPick':'nav'}" data-v="${id}" class="${edit&&on?'on':''} ${!edit&&view===id?'cur':''}" style="--tc:${vivid(secColor(id))}" ${edit?`aria-pressed="${on}"`:''}><span class="ni">${icoHTML(id)}</span><span class="nl">${esc(mLab(id))}</span>${edit?`<span class="mschk">${on?lineIco('M5 12.5l4.5 4.5L19 7'):''}</span>`:''}</button>`}).join('')}</div>`;
 const pn=sh.querySelector('.mspanel');if(pn){pn.innerHTML=inner;pn.setAttribute('aria-label',edit?'Edit tab bar':'More sections')}
 else sh.innerHTML=`<div class="msback" data-act="mClose"></div><div class="mspanel" role="dialog" aria-label="${edit?'Edit tab bar':'More sections'}">${inner}</div>`}
const secOn=id=>!(CFG.tabOff||[]).includes(id);
const cOn=(sec,k)=>secOn(sec)&&CFG[k]!==false;
const tabList=()=>{const all=TABS.map(t=>t[0]),o=(CFG.tabOrder||[]).filter(i=>all.includes(i)),ex=all.filter(i=>!o.includes(i)),si=o.indexOf('settings'),ids=si>=0?[...o.slice(0,si),...ex,...o.slice(si)]:[...o,...ex];return ids.map(id=>TABS.find(t=>t[0]===id))};
const visTabs=()=>tabList().filter(t=>t[0]==='settings'||secOn(t[0]));
// With nothing in progress, Home suggests one of the "Want to" items (a different one each day; Another picks again).
let colSug=0;
const colSuggest=()=>{const ws=colKeys().map(colRead).filter(x=>x.status==='want');if(!ws.length)return '<p class="empty">Nothing in progress. Set a collection item to Reading, Watching or Playing.</p>';
 const day=Math.floor(pd(TD()).getTime()/864e5),x=ws.sort((a,b)=>(a.added||'').localeCompare(b.added||'')||alpha(a.title,b.title))[(day+colSug)%ws.length],t=ctype(x.type);
 const verb={book:'Start reading',movie:'Start watching',series:'Start watching',anime:'Start watching',game:'Start playing'}[x.type]||'Start';
 return `<p class="meta csnone">Nothing in progress right now.</p><div class="csugg"><span class="cstag">Suggestion</span><div class="csmini">${colMini(x)}</div><div class="cstext"><span class="meta csfrom">From your ${esc(statLabel(x.type,'want'))} list</span><b data-notr>${esc(x.title)}</b><span class="meta">${esc([t.label,x.creator,x.year].filter(Boolean).join(' · '))}</span>
<div class="row" style="margin:10px 0 0"><button class="b" data-act="col:sugStart" data-k="${esc(x.k)}" title="${esc('Set to '+statLabel(x.type,'doing'))}">${verb}</button>${ws.length>1?`<button class="g" data-act="col:sugNext" title="Suggest something else">${lineIco('M4 12a8 8 0 1 0 2.5-5.8M4 4v4h4')}Another</button>`:`<button class="g" data-act="ipAddT" title="Find something else in your collections or online">${lineIco('M4 12a8 8 0 1 0 2.5-5.8M4 4v4h4')}Another</button>`}</div></div></div>`};
/* Home → In progress: + opens a finder over your collections; picking an item sets it to Reading / Watching / Playing.
   "Search online" opens Collections → Add with the same words. */
let ipAdd=false,ipQ='';
function ipFinder(){const q=fold(ipQ.trim()),its=colKeys().map(colRead).filter(it=>it.status!=='doing'&&(!q||fold([it.title,it.creator,it.year].join(' ')).includes(q))).sort((a,b)=>(a.status==='want'?0:1)-(b.status==='want'?0:1)||(b.added||'').localeCompare(a.added||'')).slice(0,6);
 return `<div class="ipfind"><span class="sbox"><input id="ipq" value="${esc(ipQ)}" placeholder="Find in your collections…" autocomplete="off" aria-label="Find in your collections">${ipQ?`<button class="sclr" data-act="sclr" data-for="ipq" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span>
${its.length?`<div class="iplist">${its.map(it=>`<button class="ipitem" data-act="ipStart" data-k="${esc(it.k)}"><span class="qcov">${cimg(it)}</span><span class="cnt"><b data-notr>${esc(it.title)}</b><span class="meta">${esc([ctype(it.type).one,it.creator,statLabel(it.type,it.status)].filter(Boolean).join(' · '))}</span></span><span class="ipgo">${esc(statLabel(it.type,'doing'))}</span></button>`).join('')}</div>`:`<p class="meta" style="margin:6px 2px">${q?'Nothing in your collections matches.':'Your collections are empty.'}</p>`}
${ipQ.trim()?`<button class="g ipweb" data-act="ipWeb">${lineIco('M10.5 3a7.5 7.5 0 1 0 4.6 13.4l4.2 4.2M10.5 3a7.5 7.5 0 0 1 0 15')}Search online for “${esc(ipQ.trim())}”</button>`:''}</div>`}
const colMini=x=>`<button class="mini" data-act="col:open" data-k="${esc(x.k)}" data-colk="${esc(x.k)}" title="${esc(x.title)}"><span class="mcov">${cimg(x)}<span class="cfav ${x.fav?'on':''}" data-act="col:fav" data-k="${esc(x.k)}" role="button" tabindex="0" aria-pressed="${x.fav}" aria-label="${x.fav?'Remove from favorites':'Add to favorites'}" title="${x.fav?'Remove from favorites':'Add to favorites'}">${heartIco(x.fav)}</span><span class="cbadge s-${x.status}">${esc(statLabel(x.type,x.status))}</span></span><b>${esc(x.title)}</b><span class="meta">${esc(colMeta(x)||ctype(x.type).label)}</span></button>`;
const HOME_DEF=[['focus','Focus session','tasks'],['weather','Time & weather',''],['sounds','Sounds',''],['mood','How are you feeling?',''],['question','Today’s question','journal'],['tasks','Tasks','tasks'],['habits','Habits today','habits'],['coming','Coming up','calendar'],['projects','Projects','projects'],['notes','Notes','notes'],['week','This week','insights'],['collections','In progress','collections'],['recap','Daily recap',''],['timers','Timers & alarms',''],['body','Body','health'],['readlater','Read later','files'],['otd','On this day','journal'],['meditate','Meditation','health'],['shortcuts','Shortcuts','']];
/* Custom Home cards built from Collections (CFG.colCards): a type, a status, favorites only, a sort order and how
   many covers to show. Each one is a Home card "cc:<id>" that can be moved, hidden, edited or deleted like the others. */
const CCSORT=[['added','Recently added'],['rating','Rating'],['title','Title'],['year','Year'],['started','Recently started']];
const ccDefTitle=c=>{const es=CFG.lang==='es'&&typeof I18N_ES!=='undefined',tr=x=>es&&I18N_ES[x]||x,t=tr(c.type&&c.type!=='all'?ctype(c.type).label:'Collections'),st=c.status?tr(c.type&&c.type!=='all'?statLabel(c.type,c.status):CSTATL[CSTAT.indexOf(c.status)]):'';return [c.fav?(es?'Favoritos: '+t:'Favorite '+t.toLowerCase()):t,st].filter(Boolean).join(' · ')};
const ccTitle=c=>(c.title||'').trim()||ccDefTitle(c);
/* Home card colors: each card follows its section's color (tinting it in the Colorful style); a color picked from the
   card's right-click menu or Customize → Color (CFG.homeColors[id]) tints that card in every style. */
const hcSec=id=>id.startsWith('cc:')?'collections':id.startsWith('tc:')?'tasks':((homeDefs().find(x=>x[0]===id)||[])[2]||'journal');
const hcOwn=id=>(CFG.homeColors||{})[id]||'',hcColor=id=>hcOwn(id)||secColor(hcSec(id));
const homeCtx=()=>{const id=ctxK.slice(3),own=hcOwn(id),col=hcColor(id);
 return `<p class="ctxlab">Card color</p><div class="ctxsw">${LCOLORS.map(c=>`<button class="lsw ${own===c?'on':''}" data-ctx="hccol" data-v="${c}" style="background:${c}" aria-label="Color ${c}" aria-pressed="${own===c}"></button>`).join('')}${swCustom(own&&!LCOLORS.includes(own)?own:'',`data-homecolor="${esc(id)}"`,'lsw')}</div>${own?'<button role="menuitem" data-ctx="hcreset">Default color</button>':''}<hr class="ctxhr"><button role="menuitem" data-ctx="hcedit">Customize Home…</button><button role="menuitem" data-ctx="hchide">Hide this card</button>`};
// A Home card's opening tag: its color (--cc) and classes added to whatever style/class it already has.
const hcAttrs=(a,id)=>{const c=hcColor(id),cl=[homeEdit?'dragcard':'',hcOwn(id)?'hcolored':''].filter(Boolean).join(' ');
 a=/style="/.test(a)?a.replace('style="',`style="--cc:${c};`):a+` style="--cc:${c}"`;if(cl)a=/class="/.test(a)?a.replace('class="',`class="${cl} `):a+` class="${cl}"`;return a};
// Shortcuts card (Home): the sections as square tiles, like the Grid sidebar. Edit picks which ones show (CFG.homeShort)
// and lets you drag them into order.
let shEdit=false;
const shAll=()=>visTabs().map(t=>t[0]).filter(id=>id!=='today');
const shPicks=()=>{const ok=shAll();return CFG.homeShort?CFG.homeShort.filter(id=>ok.includes(id)):ok};
function shortCard(){const pk=shPicks(),ids=shEdit?[...pk,...shAll().filter(id=>!pk.includes(id))]:pk,cnt=CFG.navCounts!==false;
 return `<section class="shcard"><div class="head" style="margin:0 0 10px"><h2 class="h2i" style="margin:0">${uiIco('squares-four','▦')}Shortcuts</h2><button class="${shEdit?'b':'x'}" data-act="shEdit" aria-pressed="${shEdit}">${shEdit?'Done':'Edit'}</button></div>
${shEdit?'<p class="meta" style="margin:-4px 0 10px">Tap to show or hide a section. Drag to change the order.</p>':''}${ids.length?`<div class="shgrid">${ids.map(id=>{const on=pk.includes(id),c=cnt&&!shEdit?navCount(id):'',lab=(TABS.find(t=>t[0]===id)||[0,id])[1];
  return `<button class="shtile ${shEdit&&!on?'off':''}" ${shEdit?`data-act="shPick" aria-pressed="${on}"`:`data-act="nav"`} data-v="${id}" ${on?`data-dnd="short" data-id="${id}"`:''} style="--tc:${vivid(secColor(id))}" title="${esc(lab)}"><span class="shico">${icoHTML(id)}${c!==''&&+c?`<span class="shnc">${c}</span>`:''}${shEdit?`<span class="mschk">${on?lineIco('M5 12.5l4.5 4.5L19 7'):''}</span>`:''}</span><span class="shl">${esc(lab)}</span></button>`}).join('')}</div>`:'<p class="empty">No shortcuts. Click Edit to pick some.</p>'}</section>`}
const homeDefs=()=>[...HOME_DEF,...(CFG.colCards||[]).map(c=>['cc:'+c.id,ccTitle(c),'collections']),...(CFG.taskCards||[]).map(c=>['tc:'+c.id,tcTitle(c),'tasks'])];
// The collection card editor: ccEd = {id (null for a new card), title, type, status, fav, sort, limit}.
let ccEd=null;
const ccPanel=()=>tcEd?tcPanel():!ccEd?(secOn('collections')||secOn('tasks')?`<div class="row" style="margin:0 0 14px">${secOn('tasks')?`<button class="g" data-act="tcNew">${lineIco('M12 5v14M5 12h14')}Task list card</button>`:''}${secOn('collections')?`<button class="g" data-act="ccNew">${lineIco('M12 5v14M5 12h14')}Collection card</button>`:''}<span class="meta">Add cards that show a task list or collection items, with your own filters.</span></div>`:'')
 :(e=>{const sl=e.type&&e.type!=='all'?ctype(e.type).st:CSTATL,n=ccItems(e).length,segc=(f,o)=>`<div class="moods seg">${o.map(([v,l])=>`<button data-act="ccSet" data-f="${f}" data-val="${v}" class="${String(e[f]||'')===String(v)?'on':''}" aria-pressed="${String(e[f]||'')===String(v)}">${l}</button>`).join('')}</div>`;
 return `<section class="cced"><div class="head" style="margin:0 0 6px"><h2 style="margin:0">${e.id?'Edit collection card':'New collection card'}</h2><span class="meta">${n} item${n===1?'':'s'} match</span></div>
${L('Title')}<input id="ccTitle" value="${esc(e.title||'')}" placeholder="${esc(ccDefTitle(e))}" autocomplete="off" style="max-width:420px">
${L('Type')}${segc('type',[['all','All'],...ctypesOrdered().map(t=>[t.id,t.label])])}
${L('Status')}${segc('status',[['','Any'],...CSTAT.map((x,i)=>[x,sl[i]])])}
<div class="swrow" style="max-width:420px"><span>Favorites only</span>${swBtn(!!e.fav,'data-act="ccSet" data-f="fav" data-val="'+(e.fav?'':'1')+'"','Favorites only')}</div>
${L('Sort by')}${segc('sort',CCSORT)}
${L('Show up to')}${segc('limit',[['4','4'],['8','8'],['12','12'],['24','24']])}
<div class="row" style="margin-top:16px"><button class="b tick" data-act="ccSave" aria-label="Save card" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="ccCancel">Cancel</button>${e.id?`<span style="flex:1"></span><button class="x" data-act="ccDel">${armed==='cc:'+e.id?'Click again to delete':'Delete card'}</button>`:''}</div></section>`})(ccEd);
// Task list cards: CFG.taskCards = [{id, title, list, when, done, add, sort, limit}]. tcEd is the open editor.
let tcEd=null;
const TCWHEN=[['any','Any date'],['overdue','Overdue'],['today','Today'],['week','Next 7 days'],['nodate','No date']],
 TCSORT=[['due','Due date'],['added','Recently added'],['title','Title'],['manual','Manual']];
const tcDefTitle=c=>{const es=CFG.lang==='es'&&typeof I18N_ES!=='undefined',tr=x=>es&&I18N_ES[x]||x,l=FS[listKey(c.list)]||LDEF[c.list]?getList(c.list).name:'Tasks',w=c.when&&c.when!=='any'?tr((TCWHEN.find(x=>x[0]===c.when)||[])[1]||''):'';
 return [SMART.includes(c.list)?tr(l):l,w].filter(Boolean).join(' · ')};
const tcTitle=c=>(c.title||'').trim()||tcDefTitle(c);
function tcItems(c){const t=TD(),wk=dAdd(t,7);let ts=listTasks(c.list||'all',tasks());
 if(c.list!=='completed'&&!c.done)ts=ts.filter(x=>!x.done);
 const due=x=>x.due||(x.rem?x.rem.slice(0,10):'');
 if(c.when==='overdue')ts=ts.filter(x=>due(x)&&due(x)<t);
 else if(c.when==='today')ts=ts.filter(x=>due(x)&&due(x)<=t);
 else if(c.when==='week')ts=ts.filter(x=>due(x)&&due(x)<=wk);
 else if(c.when==='nodate')ts=ts.filter(x=>!due(x));
 const s=c.sort||'due';
 if(s==='due')ts.sort((a,b)=>(due(a)||'9999').localeCompare(due(b)||'9999')||a.i-b.i);
 else if(s==='added')ts.sort((a,b)=>(b.added||'').localeCompare(a.added||'')||b.i-a.i);
 else if(s==='title')ts.sort((a,b)=>alpha(a.title,b.title));
 return ts.sort((a,b)=>a.done-b.done)}
const tcPanel=()=>{const e=tcEd,n=tcItems(e).length,segc=(f,o)=>`<div class="moods seg">${o.map(([v,l])=>`<button data-act="tcSet" data-f="${f}" data-val="${esc(v)}" class="${String(e[f]||'')===String(v)?'on':''}" aria-pressed="${String(e[f]||'')===String(v)}">${l}</button>`).join('')}</div>`;
 return `<section class="cced"><div class="head" style="margin:0 0 6px"><h2 style="margin:0">${e.id?'Edit task list card':'New task list card'}</h2><span class="meta">${n} task${n===1?'':'s'} match</span></div>
${L('Title')}<input id="tcTitle" value="${esc(e.title||'')}" placeholder="${esc(tcDefTitle(e))}" autocomplete="off" style="max-width:420px">
${L('List')}<div class="moods seg tclists">${allLists().map(l=>`<button data-act="tcSet" data-f="list" data-val="${esc(l.id)}" class="${e.list===l.id?'on':''}" aria-pressed="${e.list===l.id}"><i class="tcdot" style="background:${vivid(l.color)}"></i>${SMART.includes(l.id)?esc(l.name):`<span data-notr>${esc(l.name)}</span>`}</button>`).join('')}</div>
${L('Due')}${segc('when',TCWHEN)}
${L('Sort by')}${segc('sort',TCSORT)}
${L('Show up to')}${segc('limit',[['3','3'],['6','6'],['10','10'],['20','20']])}
<div class="swrow" style="max-width:420px"><span>Show completed tasks</span>${swBtn(e.list==='completed'||!!e.done,'data-act="tcSet" data-f="done" data-val="'+(e.done?'':'1')+'"'+(e.list==='completed'?' disabled':''),'Show completed tasks')}</div>
<div class="swrow" style="max-width:420px"><span>Quick add field</span>${swBtn(e.list!=='completed'&&e.add!==false,'data-act="tcSet" data-f="add" data-val="'+(e.add!==false?'':'1')+'"'+(e.list==='completed'?' disabled':''),'Quick add field')}</div>
<div class="row" style="margin-top:16px"><button class="b tick" data-act="tcSave" aria-label="Save card" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="tcCancel">Cancel</button>${e.id?`<span style="flex:1"></span><button class="x" data-act="tcDel">${armed==='tc:'+e.id?'Click again to delete':'Delete card'}</button>`:''}</div></section>`};
function ccItems(c){const by={added:(a,b)=>(b.added||'').localeCompare(a.added||''),rating:(a,b)=>b.rating-a.rating,title:(a,b)=>alpha(a.title,b.title),year:(a,b)=>(+b.year||0)-(+a.year||0),started:(a,b)=>(b.started||'').localeCompare(a.started||'')}[c.sort||'added'];
 return colKeys().map(colRead).filter(x=>(!c.type||c.type==='all'||x.type===c.type)&&(!c.status||x.status===c.status)&&(!c.fav||x.fav)).sort((a,b)=>by(a,b)||alpha(a.title,b.title))}
/* Timers & alarms (Home card). Timers: CFG.timers = [{id, label, total (s), end (ms, while running), left (s, while paused)}].
   Alarms: CFG.alarms = [{id, time "07:30", label, days [0–6] (none = once), on, last (the day it last rang)}].
   They ring while Prodify is open: a chime, a notification and a toast. */
let tmTab='timers';
const tmLeft=t=>t.end?Math.max(0,Math.ceil((t.end-Date.now())/1000)):(t.left??t.total);
const tmName=t=>t.label||(t.total%60?tmFmt(t.total):t.total/60+' min')+' timer';
const tmFmt=n=>{const h=Math.floor(n/3600),m=Math.floor(n%3600/60),x=n%60;return h?`${h}:${pad(m)}:${pad(x)}`:`${m}:${pad(x)}`};
function chime(n=3){try{const ac=new (window.AudioContext||window.webkitAudioContext)();for(let i=0;i<n;i++){const o=ac.createOscillator(),g=ac.createGain(),t0=ac.currentTime+i*.45;o.frequency.value=i%2?660:880;g.gain.setValueAtTime(.0001,t0);g.gain.exponentialRampToValueAtTime(.2,t0+.03);g.gain.exponentialRampToValueAtTime(.0001,t0+.4);o.connect(g);g.connect(ac.destination);o.start(t0);o.stop(t0+.42)}}catch(e){}}
function tmCard(){const ts=CFG.timers||[],as=(CFG.alarms||[]).slice().sort((a,b)=>a.time.localeCompare(b.time)),x=lineIco('M6 6l12 12M18 6L6 18');
 const seg=`<div class="moods seg">${[['timers','Timers'],['alarms','Alarms']].map(([v,l])=>`<button data-act="tmTab" data-val="${v}" class="${tmTab===v?'on':''}" aria-pressed="${tmTab===v}">${l}${v==='timers'&&ts.some(t=>t.end)?' •':''}</button>`).join('')}</div>`;
 const body=tmTab==='timers'?`<p class="meta tmlab0">Quick start · minutes</p><div class="tmpre">${[1,5,10,15,25,45].map(m=>`<button data-act="tmStart" data-val="${m}" title="Start a ${m} min timer">${m}</button>`).join('')}</div>
<div class="row tmnew"><span class="tmico">${lineIco('M12 8v5l3 2M9 2h6M12 4a9 9 0 1 0 0 18 9 9 0 0 0 0-18')}</span><input id="tmmin" inputmode="decimal" placeholder="min" aria-label="Minutes"><input id="tmlab" placeholder="Label (optional)" aria-label="Timer label" autocomplete="off"><button class="b tick" data-act="tmStart" aria-label="Start timer" title="Start timer">${lineIco('M8 5.5v13l10.5-6.5z')}</button></div>
${ts.map(t=>{const l=tmLeft(t),pct=t.total?100-l/t.total*100:0;return `<div class="tmrow ${t.end?'run':''} ${!l?'fin':''}"><span class="rpring" style="--p:${pct}%" data-tmring="${t.id}"></span><span class="t"><b data-tm="${t.id}">${tmFmt(l)}</b><span class="meta" data-notr>${esc(tmName(t))}</span></span>${l?`<button class="cx" data-act="tmPause" data-val="${t.id}" aria-label="${t.end?'Pause':'Resume'}" title="${t.end?'Pause':'Resume'}">${t.end?lineIco('M8 5v14M16 5v14'):lineIco('M8 5.5v13l10.5-6.5z')}</button>`:`<button class="cx" data-act="tmAgain" data-val="${t.id}" title="Start again">${lineIco('M4 12a8 8 0 1 0 2.5-5.8M4 4v4h4')}</button>`}<button class="cx" data-act="tmDel" data-val="${t.id}" aria-label="Remove timer" title="Remove">${x}</button></div>`}).join('')}`
 :`<div class="row tmnew"><span class="tmico">${lineIco('M12 9v4l2 2M5 3L2 6M19 3l3 3M12 5a8 8 0 1 0 0 16 8 8 0 0 0 0-16')}</span>${timeField('altime','','Alarm time')}<input id="allab" placeholder="Label (optional)" aria-label="Alarm label" autocomplete="off"><button class="b tick" data-act="alAdd" aria-label="Add alarm" title="Add alarm">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>
${as.map(a=>`<div class="tmrow al ${a.on?'':'off'}"><span class="t"><b>${tf(a.time)}</b><span class="meta"><span data-notr>${esc(a.label||'Alarm')}</span> · ${alDays(a)}</span><span class="aldays">${[1,2,3,4,5,6,0].map(dw=>`<button class="${(a.days||[]).includes(dw)?'on':''}" data-act="alDay" data-val="${a.id}" data-d="${dw}" title="${DN[dw]}">${DN[dw][0]}</button>`).join('')}</span></span>${swBtn(a.on,`data-act="alTog" data-val="${a.id}"`,'Alarm on')}<button class="cx" data-act="alDel" data-val="${a.id}" aria-label="Delete alarm" title="Delete">${x}</button></div>`).join('')||'<p class="empty">No alarms. They ring while Prodify is open.</p>'}`;
 return `<section class="tmcard"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Timers &amp; alarms</h2>${seg}</div>${body}</section>`}
const alDays=a=>{const d=a.days||[];return !d.length?'Once':d.length===7?'Every day':d.length===5&&[1,2,3,4,5].every(x=>d.includes(x))?'Weekdays':d.length===2&&d.includes(0)&&d.includes(6)?'Weekends':[1,2,3,4,5,6,0].filter(x=>d.includes(x)).map(x=>DN[x]).join(', ')};
// Every second: update the timers on screen, ring the ones that end, and ring alarms at their minute.
setInterval(()=>{const ts=CFG.timers||[];let ch=false;
 ts.forEach(t=>{if(!t.end)return;const l=tmLeft(t);const el=document.querySelector(`[data-tm="${t.id}"]`);if(el)el.textContent=tmFmt(l);const rg=document.querySelector(`[data-tmring="${t.id}"]`);if(rg)rg.style.setProperty('--p',(100-l/t.total*100)+'%');
  if(!l){t.end=null;t.left=0;ch=true;chime(4);const lab=tmName(t);notify('Timer done',lab,{ico:'timer'});toast('⏰ '+lab+' · done')}});
 const n=new Date(),hhm=pad(n.getHours())+':'+pad(n.getMinutes()),td=TD();
 (CFG.alarms||[]).forEach(a=>{if(!a.on||a.time!==hhm||a.last===td)return;if((a.days||[]).length&&!a.days.includes(n.getDay()))return;a.last=td;if(!(a.days||[]).length)a.on=false;ch=true;chime(6);notify('Alarm · '+tf(a.time),a.label||'Alarm',{ico:'alarm'});toast('⏰ '+(a.label||'Alarm')+' · '+tf(a.time))});
 if(ch){saveCfg();if(view==='today'&&!document.activeElement.matches('input,textarea'))render()}},1000);
/* Focus session (Home): up to 3 tasks picked for the day (CFG.prio = {d, ids}), pinned above the cards with a big check.
   Focus mode (CFG.prioMode) hides the other cards until the three are done. Tasks are matched by title + date added. */
let prioPick=false,prioSel=[];
const tKey=t=>t.title+'|'+(t.added||'');
const prioToday=()=>CFG.prio&&CFG.prio.d===TD()?CFG.prio.ids:[];
/* Focus sessions: turning on focus mode starts a stopwatch (CFG.focusRun = {at, acc, paused}: kept in settings so it
   survives a restart). Exiting focus mode, End, or finishing every focus task ends it and logs it in focus.md:
     - 2026-10-24 09:10: 45 min · 2/3 tasks · Pay rent, Call Ana
   Sessions under a minute are not logged. Insights → Focus reads the log. */
const fsMs=()=>{const r=CFG.focusRun;return r?(r.acc||0)+(r.paused?0:Date.now()-r.at):0};
const fsClock=ms=>{const s=Math.floor(ms/1000),h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?`${h}:${pad(m)}:${pad(s%60)}`:`${pad(m)}:${pad(s%60)}`};
const fsStart=()=>{CFG.focusRun={at:Date.now(),acc:0,paused:false,d:TD(),t:hm(':')}};
const focusLog=()=>(FS['focus.md']||'').split('\n').map(l=>l.match(/^- (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}): (\d+) min(?: · (\d+)\/(\d+) tasks?)?(?: · (.+))?$/)).filter(Boolean).map(m=>({d:m[1],t:m[2],min:+m[3],done:+(m[4]||0),of:+(m[5]||0),titles:m[6]||''}));
function fsEnd(why){const r=CFG.focusRun;if(!r)return;const ms=fsMs(),min=Math.round(ms/60000);CFG.focusRun=null;CFG.prioMode=false;
 // Finished tasks leave the card so the next session starts fresh; unfinished ones stay picked.
 const T=tasks(),items=prioToday().map(id=>T.find(t=>tKey(t)===id)).filter(Boolean),dn=items.filter(t=>t.done);if(dn.length)CFG.prio={d:TD(),ids:items.filter(t=>!t.done).map(tKey)};saveCfg();
 if(min<1){toast('Focus ended · less than a minute, not logged');return}
 const line=`- ${r.d||TD()} ${r.t||hm(':')}: ${min} min${items.length?` · ${dn.length}/${items.length} task${items.length===1?'':'s'}`:''}${dn.length?' · '+dn.map(t=>t.title.replace(/\n/g,' ')).join(', '):''}`;
 FS['focus.md']=(FS['focus.md']||'# Focus sessions\n\n')+line+'\n';save();nAdd(why==='done'?'Focus done':'Focus session logged',`${fmtMin(min)}${items.length?` · ${dn.length}/${items.length} tasks`:''}`,{ico:'target',go:{view:'insights'}});toast(`${why==='done'?'Focus done':'Focus session ended'} · ${fmtMin(min)} logged`)}
const fmtMin=m=>m>=60?`${Math.floor(m/60)} h${m%60?' '+m%60+' min':''}`:`${m} min`;
setInterval(()=>{const c=$('fclock');if(c&&CFG.focusRun)c.textContent=fsClock(fsMs())},1000);
function focusBar(){if(!secOn('tasks'))return '';const T=tasks(),open=T.filter(t=>!t.done),items=prioToday().map(id=>T.find(t=>tKey(t)===id)).filter(Boolean);
 if(CFG.focusRun&&items.length&&items.every(t=>t.done)){fsEnd('done');return focusBar()}
 if(prioPick)return `<section class="focuscard"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">Pick tasks for this session</h2><span class="meta">${prioSel.length}/3</span></div>
${open.length?`<div class="prioopts">${open.slice(0,40).map(t=>{const k=tKey(t),on=prioSel.includes(k);return `<button class="pfopt ${on?'on':''}" data-act="prioTog" data-k="${esc(k)}" aria-pressed="${on}" ${!on&&prioSel.length>=3?'disabled':''}><span class="cnt"><b data-notr>${esc(t.title)}</b>${t.due?`<span class="meta">${remDue(t)}</span>`:''}</span><span class="pfchk">${on?lineIco('M5 12.5l4.5 4.5L19 7'):''}</span></button>`}).join('')}</div>`:'<p class="empty">No open tasks to pick from.</p>'}
<div class="row" style="margin-top:10px"><button class="b tick" data-act="prioSave" aria-label="Save focus" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="prioCancel">Cancel</button></div></section>`;
 if(!items.length)return `<section class="focuscard fempty"><div class="head" style="margin:0 0 6px"><h2 style="margin:0"><span class="fico">${lineIco('M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8')}</span>Focus session</h2></div><p class="meta" style="margin:0 0 10px">${open.length?'Pick up to 3 tasks to work on, then start the timer.':'No open tasks. Add some to start a focus session.'}</p>${open.length?'<button class="g" data-act="prioPickT">Pick tasks</button>':''}</section>`;
 const dn=items.filter(t=>t.done).length,all=dn===items.length;
 return `<section class="focuscard ${all?'alldone':''}"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">${all?'Focus done 🎉':'Focus session'} <span class="meta">${dn}/${items.length}</span></h2><span class="row" style="margin:0;gap:6px">${CFG.focusRun?`<span class="ftimer ${CFG.focusRun.paused?'paused':''}" title="Time in this focus session">${lineIco('M12 8v4l2.5 2.5M9 2h6M12 5a8 8 0 1 0 0 16 8 8 0 0 0 0-16z')}<b id="fclock">${fsClock(fsMs())}</b></span><button class="cx rbtn" data-act="fsPause" aria-label="${CFG.focusRun.paused?'Resume':'Pause'}" title="${CFG.focusRun.paused?'Resume':'Pause'}">${lineIco(CFG.focusRun.paused?'M8 5.5v13l10.5-6.5z':'M8 5v14M16 5v14')}</button>`:''}<button class="g fmode ${CFG.prioMode?'on':''}" data-act="prioMode" aria-pressed="${!!CFG.prioMode}" title="${CFG.prioMode?'End the session and log its time':'Hide the other cards and time this session'}">${CFG.prioMode?'End focus':'Start focus'}</button><button class="cx rbtn" data-act="prioPickT" aria-label="Edit focus" title="Edit">${lineIco('M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4')}</button></span></div>
${items.map(t=>`<div class="frow ${t.done?'done':''}"><button class="fchk ${t.done?'on':''}" data-act="tog" data-i="${t.i}" role="checkbox" aria-checked="${t.done}" aria-label="${t.done?'Mark as not done':'Mark as done'}">${t.done?lineIco('M5 12.5l4.5 4.5L19 7'):''}</button><span class="ft" data-notr>${esc(t.title)}</span>${t.due?remDue(t):''}</div>`).join('')}</section>`}
// Focus mode: the focus card sits in the middle of the space left below the search bar.
function fmFit(){const w=document.querySelector('.fmfocus');if(!w)return;const z=cz();w.style.minHeight=Math.max(0,(innerHeight-w.getBoundingClientRect().top-24)/z)+'px'}
window.addEventListener('resize',fmFit);
const focusHides=()=>{if(!CFG.prioMode||!secOn('tasks'))return false;const T=tasks(),items=prioToday().map(id=>T.find(t=>tKey(t)===id)).filter(Boolean);return items.length>0&&items.some(t=>!t.done)};
/* Quick capture: a floating + on every page. One box saves a task, note, event, link or journal line; Auto guesses the
   type (a link → Storage, "tomorrow 18:00 …" → event, several lines → note, otherwise a task). */
let QC=null;
function qcGuess(t){t=t.trim();if(!t)return 'task';if(stUrl(t))return 'link';if(/\n/.test(t)||t.length>140)return 'note';if(/^(today|tomorrow|hoy|mañana|\d{4}-\d{2}-\d{2})\s+\d{1,2}:\d{2}/i.test(t))return 'event';return 'task'}
const QCT=[['auto','Auto'],['task','Task'],['note','Note'],['event','Event'],['link','Link'],['journal','Journal']];
const qcOk=k=>({task:'tasks',note:'notes',event:'calendar',link:'files',journal:'journal'})[k];
// Each type has its own form, built like that type's form elsewhere in the app; Auto keeps one box that guesses.
// QC = {type, text (Auto box), f: {title, body, due, list, date, start, end, url, mood}}.
const QCWILL={task:'a task',note:'a note',event:'an event',link:'a link in Storage',journal:'a journal entry'};
// Reads what is typed in the open form back into QC, so switching type or re-drawing keeps it.
function qcSync(){if(!QC)return;const f=QC.f||(QC.f={}),g=id=>{const e=$(id);return e?e.value:null};
 if(g('qctext')!==null)QC.text=g('qctext');[['qct','title'],['qcb','body'],['qcd','due'],['qcl','list'],['qced','date'],['qces','start'],['qcee','end'],['qcu','url'],['qcj','body']].forEach(([id,k])=>{const v=g(id);if(v!==null)f[k]=v})}
// The main text moves between forms: the Auto box fills the new form, and a form's title/link/text goes back to Auto.
function qcCarry(from,to){const f=QC.f||(QC.f={});
 const main=from==='auto'?(QC.text||''):from==='link'?(f.url||''):from==='journal'||from==='note'?[f.title,f.body].filter(Boolean).join('\n'):(f.title||'');
 if(to==='auto'){QC.text=main;return}
 if(to==='note'){const l=main.split('\n');f.title=l[0].slice(0,80);f.body=l.slice(1).join('\n').trim()||(l[0].length>80?main:'');return}
 if(to==='journal'){f.title='';f.body=main;return}
 if(to==='link'){f.url=main.trim();return}
 if(to==='event'){const[d,rest]=cmdDate(main.replace(/\n/g,' ')),x=rest.match(ETM);f.date=d||f.date||TD();if(x){f.start=h5(x[1]);f.end=x[2]?h5(x[2]):'';f.title=x[3]}else f.title=rest||main;return}
 f.title=main.replace(/\n/g,' ')}
function qcForm(g){const f=QC.f||{},e=v=>esc(v||'');
 if(g==='task')return `<div class="qcform qctask"><div class="rrow rnew"><span class="rchk ghost" aria-hidden="true"></span><div class="rt"><input id="qct" class="rin" value="${e(f.title)}" placeholder="New task" aria-label="New task"></div></div>
<div class="qcrow"><label class="meta lab">Due<input id="qcd" type="date" value="${e(f.due)}"></label>${userLists().length?`<label class="meta lab">List<select id="qcl">${listOpts(f.list||'')}</select></label>`:''}</div></div>`;
 if(g==='note')return `<div class="qcform qcnote"><input id="qct" class="ntitle" value="${e(f.title)}" placeholder="Untitled" aria-label="Note title"><textarea id="qcb" class="md" rows="4" placeholder="Write your note…" aria-label="Note">${e(f.body)}</textarea></div>`;
 if(g==='event')return `<div class="qcform qcevent"><input id="qct" value="${e(f.title)}" placeholder="Event title" autocomplete="off" aria-label="Event title">
<div class="evrow"><label class="meta lab">Date<input type="date" id="qced" value="${e(f.date||TD())}"></label><label class="meta lab">Starts${timeField('qces',f.start||'','Starts')}</label><label class="meta lab">Ends${timeField('qcee',f.end||'','Ends')}</label></div></div>`;
 if(g==='link'){const u=stUrl((f.url||'').trim())||stUrl('https://'+(f.url||'').trim());return `<div class="qcform qclink"><label class="qclin">${sym('link-simple')}<input id="qcu" value="${e(f.url)}" placeholder="Paste a link (https://…)" autocomplete="off" aria-label="Link"></label><div class="qclprev">${u?`${stFavicon({url:u})}<span class="meta">${esc(host(u))}</span>`:'<span class="meta">Saved to Storage → Links, with its title and preview.</span>'}</div></div>`}
 if(g==='journal')return `<div class="qcform qcjournal"><div class="moods seg">${MOOD.map((m,i)=>`<button data-act="qcMood" data-n="${i+1}" class="${f.mood===i+1?'on':''}" aria-pressed="${f.mood===i+1}"><span class="dot" style="background:var(${m[1]})"></span>${m[0]}</button>`).join('')}</div><textarea id="qcj" rows="4" placeholder="Start anywhere." aria-label="Journal entry">${e(f.body)}</textarea></div>`;
 return `<textarea id="qctext" rows="3" placeholder="A task, a thought, a link, or “tomorrow 18:00 Dinner”…">${esc(QC.text)}</textarea>`}
function qcShow(){let o=$('qcap');if(!QC){if(o)o.remove();return}
 if(!o){o=document.createElement('div');o.id='qcap';o.className='qcap';o.setAttribute('role','dialog');o.setAttribute('aria-label','Quick capture');document.body.appendChild(o)}
 const g=QC.type==='auto'?qcGuess(QC.text):QC.type,tps=QCT.filter(([k])=>k==='auto'||secOn(qcOk(k)));
 o.dataset.type=QC.type;o.style.setProperty('--qk',vivid(secColor(qcOk(g))));
 o.innerHTML=`<div class="qchead"><b>Quick capture</b><button class="cx" data-act="qcClose" aria-label="Close" title="Close (Esc)">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
<div class="moods seg qctypes">${tps.map(([k,l])=>`<button data-act="qcType" data-val="${k}" class="${QC.type===k?'on':''}" aria-pressed="${QC.type===k}">${l}</button>`).join('')}</div>
${qcForm(QC.type)}
<div class="qcfoot"><span class="meta qcwill">Saves as ${QCWILL[g]}</span><button class="b tick" data-act="qcSave" aria-label="Save" title="Save (Enter)">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>`;
 setTimeout(()=>{const t=o.querySelector('#qctext,#qct,#qcu,#qcj');if(t&&!o.contains(document.activeElement)){t.focus();if(t.setSelectionRange)t.setSelectionRange(t.value.length,t.value.length)}})}
function qcSave(){qcSync();const f=QC.f||{},g=QC.type==='auto'?qcGuess(QC.text||''):QC.type;
 if(QC.type==='auto'){const raw=(QC.text||'').trim();if(!raw){toast('Type something first');return}QC.f={};qcCarry('auto',g)}
 const F=QC.f,tt=(F.title||'').trim();
 if(g==='link'){const r=(F.url||'').trim(),u=stUrl(r)||stUrl('https://'+r);if(!u){toast(r?'That doesn’t look like a link':'Paste a link first');return}stAddLink(u)}
 else if(g==='note'){const body=(F.body||'').trim();if(!tt&&!body){toast('Type something first');return}const ttl=tt||'Untitled',k=noteKeyFor('notes/',ttl,TD());FS[k]=`---\ncreated: ${TD()}\n---\n# ${ttl}\n\n${body}\n`;toast('Note saved')}
 else if(g==='event'){if(!tt){toast('Give the event a title');return}const d=F.date||TD();putEvents(events().concat([{date:d,start:F.start||'',end:F.end||'',title:tt}]));toast('Event saved · '+fmt(d))}
 else if(g==='journal'){const t=(F.body||'').trim(),m=+F.mood||0,now=hm(':');if(!t&&!m){toast('Pick how you feel, or write something');return}
  if(m)moodsWrite([...moodsRead(),{d:TD(),t:now,m,emos:[]}]);
  // jeNew reads the Journal form's mood, emotions and categories: borrow them for this entry, then put them back.
  if(t){const keep=[JM,JEMO,JC];JM=m;JEMO=[];JC=[];jeNew(t,'');[JM,JEMO,JC]=keep;toast('Saved to your journal')}else toast(`Mood logged · ${tf(now)}`)}
 else{if(!tt){toast('Type something first');return}const n=nlTask(tt);putTasks(tasks().concat([{done:false,title:n.title,due:F.due||n.due,rem:n.rem,proj:n.proj,list:F.list||n.list,rep:n.rep,pri:n.pri,added:TD()}]));toast('Task added'+(nlSummary(n)?' · '+nlSummary(n):''))}
 QC=null;qcShow();save();render()}
document.addEventListener('input',e=>{if(!QC||!e.target.closest||!e.target.closest('#qcap'))return;qcSync();
 if(e.target.id==='qctext'){const w=document.querySelector('.qcwill'),g=qcGuess(QC.text);if(w)w.textContent='Saves as '+QCWILL[g];$('qcap').style.setProperty('--qk',vivid(secColor(qcOk(g))))}
 if(e.target.id==='qcu'){const p=document.querySelector('.qclprev'),u=stUrl(QC.f.url.trim())||stUrl('https://'+QC.f.url.trim());if(p)p.innerHTML=u?`${stFavicon({url:u})}<span class="meta">${esc(host(u))}</span>`:'<span class="meta">Saved to Storage → Links, with its title and preview.</span>'}});
// Enter saves from one-line fields and the Auto box (Shift+Enter for a new line); note and journal text keep Enter for new lines.
document.addEventListener('keydown',e=>{if(!QC||!e.target.closest||!e.target.closest('#qcap'))return;
 if(e.key==='Escape'){e.preventDefault();QC=null;qcShow();return}
 if(e.key==='Enter'&&!e.shiftKey&&(e.target.id==='qctext'||(e.target.tagName==='INPUT'&&e.target.type!=='date'))){e.preventDefault();qcSave()}});
function qcButton(){let b=$('qcbtn');if(!b){b=document.createElement('button');b.id='qcbtn';b.className='qcbtn';b.dataset.act='qcOpen';b.setAttribute('aria-label','Quick capture');b.title='Quick capture';b.innerHTML=lineIco('M12 5v14M5 12h14');document.body.appendChild(b)}
 b.hidden=!!document.querySelector('#main .fab')||!!ONB||PWLOCK}
/* Daily recap (Home card): what a day added up to: mood, tasks finished, habits, workout, meditation, journal,
   notes, events and collection progress. ‹ › step through earlier days. */
let recapD=null;
function recapCard(){const t=TD(),d=recapD&&recapD<=t?recapD:t,T=tasks(),on=secOn,tiles=[],lines=[];
 const tile=(ic,em,n,l,c)=>tiles.push(`<div class="rctile" style="--rc:${c}"><span class="rcico">${symbols()?sym(ic):em}</span><b>${n}</b><span class="meta">${l}</span></div>`);
 const m=on('journal')&&getMood(d);if(m)tile('smiley','🙂',MOOD[Math.round(m)-1][0],'Mood','var('+MOOD[Math.round(m)-1][1]+')');
 if(on('tasks')){const dn=T.filter(x=>x.done&&x.doneOn===d),late=d<t?T.filter(x=>!x.done&&x.due===d):[];if(dn.length)tile('check-circle','✅',dn.length,'Task'+(dn.length===1?'':'s')+' done','#4a8fd9');
  if(dn.length)lines.push(`<p class="rcl"><b>Done:</b> <span data-notr>${dn.slice(0,5).map(x=>esc(x.title)).join(', ')}</span>${dn.length>5?` <span class="meta">+${dn.length-5}</span>`:''}</p>`);
  if(late.length)lines.push(`<p class="rcl"><b>Still open:</b> <span data-notr>${late.slice(0,4).map(x=>esc(x.title)).join(', ')}</span></p>`)}
 if(on('habits')){const hs=habits().filter(h=>h.period!=='weekly'&&(!h.created||h.created<=d));if(hs.length){const ok=hs.filter(h=>hOk(h,d)).length;tile('repeat','🔁',`${ok}/${hs.length}`,'Habits','#5fa57f')}}
 if(on('health')){const w=wkRead(d);if(w&&w.ex.length){const v=volume(w);tile('barbell','🏋️',w.ex.length,'Exercise'+(w.ex.length===1?'':'s'),'#4f9d7c');lines.push(`<p class="rcl"><b>Workout:</b> <span data-notr>${esc([w.routine&&(w.routine+(w.day&&w.day!==w.routine?' · '+w.day:'')),w.ex.map(e=>e.name).slice(0,4).join(', ')].filter(Boolean).join(' — '))}</span>${v?` <span class="meta">· ${v.toLocaleString(LOC())} kg</span>`:''}</p>`)}
  const mt=medTotal(d);if(mt)tile('flower-lotus','🧘',medFmt(mt),'Meditation','#8a7fd0')}
 if(on('health')){const bd=bodyRead().find(x=>x.d===d);if(bd&&bd.sleep!=null)tile('moon','🌙',bd.sleep+' h','Sleep','#8a7fd0');if(bd&&bd.weight!=null)tile('person','🧍',bd.weight+' kg','Weight','#4a8fd9')}
 if(on('projects')){const ms=projects().flatMap(p=>(p.ms||[]).filter(m=>m.done&&m.d===d).map(m=>m.t+' ('+p.name+')'));if(ms.length)lines.push(`<p class="rcl"><b>Milestones:</b> <span data-notr>${ms.map(esc).join(', ')}</span></p>`)}
 if(on('journal')){const n=entOn(d).length+((FS[jp(d)]||'').split(/\n(?=## )/).length-1);if(n)tile('notebook','📓',n,'Journal entr'+(n===1?'y':'ies'),'#9a5fa0')}
 if(on('notes')){const nk=keys('notes/').filter(k=>noteDate(k)===d&&!isJE(k));if(nk.length){tile('note','📝',nk.length,'Note'+(nk.length===1?'':'s'),'#d4a43a');lines.push(`<p class="rcl"><b>Notes:</b> ${nk.slice(0,4).map(k=>`<button class="clink" data-act="openN" data-k="${esc(k)}" data-notr>${esc(wlPlain(noteTitle(k)))}</button>`).join(', ')}</p>`)}}
 if(on('calendar')){const ev=evOn(events(),d).sort(evSort);if(ev.length){tile('calendar-blank','📅',ev.length,'Event'+(ev.length===1?'':'s'),'#e0a33f');lines.push(`<p class="rcl"><b>Events:</b> <span data-notr>${ev.slice(0,4).map(e=>esc((e.start?tf(e.start)+' ':'')+e.title)).join(', ')}</span></p>`)}}
 if(on('collections')){const cs=colKeys().map(colRead),fin=cs.filter(x=>x.finished===d),st=cs.filter(x=>x.started===d&&x.finished!==d);
  if(fin.length)lines.push(`<p class="rcl"><b>Finished:</b> <span data-notr>${fin.map(x=>esc(x.title)).join(', ')}</span></p>`);if(st.length)lines.push(`<p class="rcl"><b>Started:</b> <span data-notr>${st.map(x=>esc(x.title)).join(', ')}</span></p>`)}
 const lab=d===t?'Today':d===dAdd(t,-1)?'Yesterday':fmt(d,{weekday:'short',month:'short',day:'numeric'});
 return `<section class="recap"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Daily recap</h2><span class="rcnav"><button class="cx" data-act="recapNav" data-val="-1" aria-label="Previous day" title="Previous day">${lineIco('M15 5l-7 7 7 7')}</button><span class="meta">${lab}</span><button class="cx" data-act="recapNav" data-val="1" ${d>=t?'disabled':''} aria-label="Next day" title="Next day">${lineIco('M9 5l7 7-7 7')}</button></span></div>
${tiles.length?`<div class="rctiles">${tiles.join('')}</div>${lines.join('')}`:`<p class="empty">${d===t?'Nothing logged yet today. Finish a task, check in your mood or log a habit and it shows up here.':'Nothing was logged on this day.'}</p>`}</section>`}
const homeList=()=>{const all=homeDefs().map(x=>x[0]),o=(CFG.homeOrder||[]).filter(i=>all.includes(i));if(!o.includes('focus')&&o.length)o.unshift('focus');return [...o,...all.filter(i=>!o.includes(i))]};
const homeSec=id=>(homeDefs().find(x=>x[0]===id)||[])[2];
// Drag groups: 'tab' sections, 'home' cards, 'lpin' pinned task lists, 'lrow' the other task lists.
const listOrder=g=>allLists().filter(l=>(l.pinned==='true')===(g==='lpin')).map(l=>l.id);
const orderOf=g=>g==='short'?shPicks():g==='mtab'?mPicks():g==='ctile'?ctypesOrdered().map(t=>t.id):g==='tab'?tabList().map(t=>t[0]):g==='home'?homeList():g==='col'?colKeys().map(colRead).sort(colSortFn()).map(i=>i.k):listOrder(g);
const setOrder=(g,a)=>{if(g==='mtab'){CFG.mobTabs=a;saveCfg();return}if(g==='short'){CFG.homeShort=a;saveCfg();return}if(g==='ctile'){CFG.colTypeOrder=a;saveCfg();return}
 if(g==='col'){colSaveOrder(a);return}
 if(g==='lpin'||g==='lrow'){const other=listOrder(g==='lpin'?'lrow':'lpin');
  // renumber every list (pinned first) and write only the ones whose position changed
  (g==='lpin'?[...a,...other]:[...other,...a]).forEach((id,i)=>{const l=getList(id);if(String(l.order)!==String(i+1)){l.order=String(i+1);putList(l)}});save();return}
 if(g==='tab')CFG.tabOrder=a;else CFG.homeOrder=a;saveCfg()};
function moveItem(g,from,to){const o=orderOf(g),fi=o.indexOf(from),ti0=o.indexOf(to);if(fi<0||ti0<0||from===to)return;
 const a=o.filter(x=>x!==from),ti=a.indexOf(to);a.splice(fi<ti0?ti+1:ti,0,from);setOrder(g,a);redraw()}
const dndRow=(g,id,label,on,locked,note)=>{const e=g==='tab'?ico(id):'';return `<div class="drow" data-dnd="${g}" data-id="${id}"><span class="grip" aria-hidden="true">⠿</span>${g==='tab'?`<button class="x ico" data-act="icoPick" data-id="${id}" aria-label="Choose icon for ${esc(label)}" title="Choose icon">${icoHTML(id)||'＋'}</button>`:''}<span class="dl">${esc(label)}${note?` <span class="meta">${note}</span>`:''}</span>${g==='tab'?(w=>`<div class="moods seg sm" role="group" aria-label="Card width in the Cards layout" title="Card width in the Cards layout">${[['1','1 col',!w],['2','2 col',w]].map(([v,l,on])=>`<button data-act="wideSet" data-id="${id}" data-val="${v}" class="${on?'on':''}" aria-pressed="${on}">${l}</button>`).join('')}</div>`)((CFG.navWide||[]).includes(id)):''}${locked?'<span class="meta" style="min-width:56px;text-align:center">Always on</span>':swBtn(on,`data-act="tgl" data-g="${g}" data-id="${id}"`,label)}</div>`+(g==='tab'&&icoPick===id?picker(id,e):'')};
/* Icon picker: category tabs and search over every emoji (emojis.js) or symbol (icons.js). */
let pcat=0,pq='';
const ECATS=()=>[['Suggested',EMOJIS.map(m=>[m,''])],...EMOJICAT];
// Emojis newer than the system's emoji font draw as an empty box (or as several emojis side by side);
// those are hidden from the picker. Only emojis added in Emoji 14.0 or later are checked.
const emojiOK=(()=>{let x,ref,tofu;const cache={};
 const draw=e=>{x.clearRect(0,0,32,32);x.fillText(e,0,0);return x.getImageData(0,0,32,32).data};
 return e=>{if(e in cache)return cache[e];
  if(!x){const c=document.createElement('canvas');c.width=c.height=32;x=c.getContext('2d',{willReadFrequently:true});x.font='24px sans-serif';x.textBaseline='top';ref=x.measureText('😀').width;tofu=draw('\u{3FFFD}').join()}
  const d=draw(e);let col=false;for(let i=0;i<d.length;i+=4)if(d[i+3]>40&&(Math.abs(d[i]-d[i+1])>24||Math.abs(d[i+1]-d[i+2])>24)){col=true;break}
  return cache[e]=x.measureText(e).width<ref*1.5&&(col||d.join()!==tofu)}})();
function pickGrid(id){const q=nq(pq);
 if(symbols()){const names=q?Object.keys(SYM).filter(n=>nq(n.replace(/-/g,' ')+' '+(SYMTAGS[n]||'')).includes(q)):(SYMCAT[pcat]||SYMCAT[0])[1];
  return names.slice(0,q?400:undefined).map(n=>{const t=n.replace(/-/g,' ');return `<button data-act="setSym" data-id="${id}" data-val="${n}" class="${symName(id)===n?'on':''}" aria-label="${t}" title="${t}">${sym(n)}</button>`}).join('')||'<p class="empty">No icons match.</p>'}
 const cats=ECATS(),list=q?cats.slice(1).flatMap(c=>c[1]).filter(m=>nq(m[1]).includes(q)):(cats[pcat]||cats[0])[1];
 return list.filter(m=>!m[2]||emojiOK(m[0])).slice(0,q?400:undefined).map(m=>`<button data-act="setIco" data-id="${id}" data-val="${m[0]}" class="${ico(id)===m[0]?'on':''}"${m[1]?` title="${esc(m[1])}" aria-label="${esc(m[1])}"`:''}>${m[0]}</button>`).join('')||'<p class="empty">No emojis match.</p>'}
const picker=(id,e)=>{const s=symbols(),cats=s?SYMCAT:ECATS(),what=s?'icons':'emojis';
 return `<div class="epick ${s?'sympick':''}"><input data-pq="${id}" placeholder="Search ${what}" value="${esc(pq)}" aria-label="Search ${what}">
<div class="pcats">${cats.map((c,i)=>`<button data-act="pcat" data-val="${i}" class="${!pq&&pcat===i?'on':''}">${c[0]}</button>`).join('')}</div>
<div id="pgrid" class="pgrid">${pickGrid(id)}</div>
<div class="row" style="margin:6px 0 0;width:100%">${s?`<button class="g" data-act="setSym" data-id="${id}" data-val="">No icon</button><button class="g" data-act="symDef" data-id="${id}">Default</button><span style="flex:1"></span><button class="b" data-act="icoDone">Done</button>`:`<input data-ico="${id}" placeholder="Type or paste an emoji" value="${esc(e)}" maxlength="12" style="max-width:220px" aria-label="Custom emoji"><button class="g" data-act="setIco" data-id="${id}" data-val="">No emoji</button><button class="g" data-act="icoDef" data-id="${id}">Default</button><span style="flex:1"></span><button class="b" data-act="icoDone">Done</button>`}</div></div>`};
/* Note properties, stored the way Obsidian stores them: YAML front matter between --- lines at the top of the file.
   Lists are written as "key:" followed by "  - item" lines, an empty property as a bare "key:",
   and categories as "[[Name]]" links. Template placeholders such as {{date}} are written unquoted. */
const LISTP=['tags','categories','aliases'];
const unq=v=>{v=v.trim();if(/^".*"$/.test(v)){try{return JSON.parse(v)}catch(e){return v.slice(1,-1)}}if(/^'.*'$/.test(v))return v.slice(1,-1).replace(/''/g,"'");return v};
function parseFM(s){const m=s.match(/^---\n(?:([\s\S]*?)\n)?---[ \t]*(?:\n|$)/);if(!m)return{fm:{},body:s};
 const fm={};let cur=null;
 for(const l of (m[1]||'').split('\n')){let x;
  if(cur&&(x=l.match(/^\s*-(?:\s+(.*))?$/))){if(!Array.isArray(fm[cur]))fm[cur]=[];if(x[1]&&x[1].trim())fm[cur].push(unq(x[1]))}
  else if(x=l.match(/^([^\s#:-][^:]*):(?:\s+(.*))?$/)){cur=x[1].trim();const v=(x[2]||'').trim();
   if(v===''||v==='null'||v==='~')fm[cur]=null;
   else if(/^\[.*\]$/.test(v)&&!/^\[\[.*\]\]$/.test(v)){fm[cur]=v.slice(1,-1).split(',').map(unq).filter(Boolean);cur=null}
   else{fm[cur]=unq(v);cur=null}}}
 return{fm,body:s.slice(m[0].length)}}
const catName=c=>String(c).replace(/^\[\[|\]\]$/g,'').split('|')[0].trim();
function readNote(s){const {fm,body}=parseFM(s||''),o={};
 for(const [k,v] of Object.entries(fm))o[k]=LISTP.includes(k)?(Array.isArray(v)?v:v==null||v===''?[]:[v]).map(String):v==null?'':v;
 if(o.categories)o.categories=o.categories.map(catName).filter(Boolean);
 return{fm:o,body}}
const yv=v=>{v=String(v);if(v===''||/^\{\{[^{}]+\}\}$/.test(v)||/^(true|false)$/.test(v))return v;
 return /^[\[\]{}"'!&*>|%@`#,?:-]|: | #|^\s|\s$|^(null|~|yes|no)$/i.test(v)?JSON.stringify(v):v};
function writeNote(n){const fm={...n.fm};if(fm.categories)fm.categories=fm.categories.map(c=>`[[${c}]]`);
 const ks=Object.keys(fm);if(!ks.length)return n.body;
 return '---\n'+ks.map(k=>{const v=fm[k];if(Array.isArray(v))return v.length?`${k}:\n`+v.map(x=>`  - ${yv(x)}`).join('\n'):`${k}:`;const y=yv(v);return y===''?`${k}:`:`${k}: ${y}`}).join('\n')+'\n---\n'+n.body}
const isPinned=k=>{const v=readNote(FS[k]).fm.pinned;return v===true||v==='true'};
const setPinned=(k,on)=>{const n=readNote(FS[k]);if(on)n.fm.pinned='true';else delete n.fm.pinned;FS[k]=writeNote(n)};
const stripFM=s=>parseFM(s).body;
const availW=()=>{const w=window.innerWidth,sw=CFG.navLayout==='top'||CFG.navAuto?0:navW();return w-(w>760?sw:0)-2*Math.min(48,Math.max(16,w*.04))};
const ncols=()=>Math.max(1,Math.min(5,Math.floor((availW()+16)/316)||1));
function redraw(){const ids=['jt','jloc','qa0','tt','nb'],vs=ids.map(i=>$(i)&&$(i).value);render();ids.forEach((i,x)=>{if(vs[x]&&$(i))$(i).value=vs[x]})}
// Stacks the cards of .hgrid into columns with no gaps (Home, Health overview). want is the chosen number of columns;
// narrow windows get fewer so a column never gets thinner than about 260px.
// Home columns: 2, 3 or 4, or Auto (the default): 4 when Home is at least 1750 px wide (a full-screen 2K monitor), else 3.
const homeColsCfg=()=>[2,3,4].includes(+CFG.homeCols)?+CFG.homeCols:'auto';
function layoutHome(want){const g=document.querySelector&&document.querySelector('.hgrid');if(!g||!g.children.length)return;if(want==='auto')want=g.clientWidth>=1750?4:3;
 // never more columns than cards, so a few cards still span the full width
 // columns: the chosen number, fewer on narrow screens (one full-width column below 700px); with only a few cards no more columns than cards,
 // but always at least two when there is room, so a single card takes at most half the width
 const cards=[...g.children].filter(c=>!c.hidden),fit=g.clientWidth<700?1:Math.max(1,Math.min(want||3,Math.floor((g.clientWidth+16)/276))),n=Math.max(1,Math.min(fit,Math.max(cards.length,2))),cw=(g.clientWidth-16*(n-1))/n;
 cards.forEach(c=>{c.style.flex='none';c.style.width=cw+'px'});
 const hts=cards.map(c=>c.offsetHeight),cols=Array.from({length:n},()=>{const el=document.createElement('div');el.className='hcol';return{el,h:0}});
 // Keep cards in their column (CFG.homeFixed): each card goes to the column it was dropped in (CFG.homeColOf, clamped to
 // the column count); cards without one take the shortest column once and keep it.
 const fixed=CFG.homeFixed&&n>1&&view==='today'&&!boardMode();let fx=false;const map=CFG.homeColOf||{};
 cards.forEach((c,i)=>{const id=c.dataset.id;let col;if(fixed){let ci=map[id];if(!(ci>=0)){ci=cols.indexOf(cols.reduce((a,b)=>b.h<a.h?b:a));map[id]=ci;fx=true}col=cols[Math.min(n-1,ci)]}else col=i<n?cols[i]:cols.reduce((a,b)=>b.h<a.h?b:a);
  c.style.flex='';c.style.width='';col.el.className='hcol';col.el.appendChild(c);col.h+=hts[i]+16});
 g.classList.toggle('hfixed',!!fixed);if(fx){CFG.homeColOf=map;saveCfg()}
 g.append(...cols.map(c=>c.el))}
const ncKey=()=>ncols()+'|'+Math.floor((availW()+16)/276)+'|'+(availW()>=700)+'|'+(availW()>=1750);
let lastNC=ncKey();
if(window.addEventListener)window.addEventListener('resize',()=>{const n=ncKey();if(n!==lastNC){lastNC=n;if(view==='notes'||view==='today'||view==='health')redraw()}});
const card=k=>`<section class="ncard ${isPinned(k)?'pin':''}" data-note="${esc(k)}"><div class="md ${expd.has(k)?'open':''}" data-act="expN" data-k="${esc(k)}">${md(FS[k])}</div>${noteChips(k)}<div class="row">${fileBtns(k)}</div></section>`;
const board=ks=>{const n=ncols(),cols=Array.from({length:n},()=>[]);ks.forEach((k,i)=>cols[i%n].push(card(k)));return `<div class="notes">${cols.map(c=>`<div class="ncol">${c.join('')}</div>`).join('')}</div>`};
const noteBoards=ks=>{if(!ks.length)return `<section><p class="empty">${q?'No notes match your search.':'No notes yet. Write your first one above.'}</p></section>`;
 const p=ks.filter(isPinned),o=ks.filter(k=>!isPinned(k));
 return (p.length?'<h2 style="margin:0 0 10px">Pinned</h2>'+board(p)+(o.length?'<h2 style="margin:20px 0 10px">Others</h2>':''):'')+(o.length?board(o):'')};
const subRow=(t,s,j)=>edS===t.i+'.'+j
 ?`<div class="sub sjoin"><input id="esn" value="${esc(s.title)}" aria-label="Subtask"><button class="b tick" data-act="saveS" data-i="${t.i}" data-j="${j}" aria-label="Save subtask" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="x scx" data-act="cancel" aria-label="Cancel" title="Cancel">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`
 :`<div class="sub srow ${s.done?'done':''}"><button class="rchk sm" data-act="togS" data-i="${t.i}" data-j="${j}" role="checkbox" aria-checked="${!!s.done}" aria-label="${s.done?'Mark subtask as not done':'Mark subtask as done'}"></button><span class="tt">${esc(s.title)}</span><span class="sact"><button class="x" data-act="editS" data-i="${t.i}" data-j="${j}">Edit</button><button class="x" data-act="delS" data-i="${t.i}" data-j="${j}">Delete</button></span></div>`;
const V={};
/* ---------- Home search and commands ----------
   Typing searches everything; only groups with matches are shown. Matching ignores case and accents and needs every word.
   Text starting with "/" is a command: /n note, /t task, /e event, /p project (Enter runs it). */
let hq='';
const fold=s=>String(s).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
const hWords=(t=hq)=>fold(t).split(/\s+/).filter(Boolean);
const hMatch=(...parts)=>{const t=fold(parts.join(' ')),w=hWords();return w.length>0&&w.every(x=>t.includes(x))};
// Highlights matches the same way search finds them (ignoring case and accents): fold each character, remember where it came from.
const hl=(s,w=hWords())=>{s=String(s);if(!w.length)return esc(s);let f='';const at=[],on=new Array(s.length).fill(false);
 for(let i=0;i<s.length;i++)for(const ch of fold(s[i])){f+=ch;at.push(i)}
 w.forEach(x=>{for(let p=f.indexOf(x);p>=0;p=f.indexOf(x,p+1))for(let j=p;j<p+x.length;j++)on[at[j]]=true});
 let h='',m=false;for(let i=0;i<s.length;i++){if(on[i]!==m){h+=m?'</mark>':'<mark>';m=on[i]}h+=esc(s[i])}return h+(m?'</mark>':'')};
// The first line of a text that contains a search word, shortened.
const hSnip=text=>{const w=hWords(),l=String(text).split('\n').map(x=>x.replace(/^#+\s*|^[-*]\s+/,'').trim()).filter(Boolean);const f=l.find(x=>w.some(y=>fold(x).includes(y)))||l[0]||'';return f.length>110?f.slice(0,110)+'…':f};
const sres=(attrs,title,meta)=>`<button class="sres" ${attrs}><b>${hl(title)}</b>${meta?`<span class="meta">${meta}</span>`:''}</button>`;
const sgroup=(title,n,items,more)=>`<section class="sgroup"><div class="head" style="margin:0 0 6px"><h2 style="margin:0">${title} <span class="meta">${n}</span></h2>${more||''}</div>${items}</section>`;
// Settings that can be found by search and changed in place: [label, extra words, control].
// A found setting: switches sit beside their label, other controls below it.
// Settings that belong to a section disappear (page and search) while that section is off.
const SETSEC={'Calendar view':'calendar','Note categories view':'notes','Category page layout':'notes','Storage layout':'files','Storage sort':'files','Gym rest timer':'health','Show journal entries in Notes':['notes','journal'],'Shine on hover':'collections','Shine color':'collections','Collections fields':'collections','Collections API keys':'collections','Home columns':'today','Health overview columns':'health',
 'Notes layout':'notes','Notes sort':'notes','Open notes in':'notes','New notes start typing in':'notes','Confirm before deleting a note':'notes','Daily reflection question':'journal','AI question topics':'journal','AI-generated questions':'journal',
 'Time format':'journal','Confirm before deleting a question':'journal','Confirm before deleting a task':'tasks','In-app reminder banner':'tasks','Desktop notifications for reminders':'tasks','Confirm before deleting a project':'projects',
 'Calendar shows tasks and reminders':['calendar','tasks'],'Calendar shows journal, mood and questions':['calendar','journal'],'Calendar shows notes':['calendar','notes'],'Calendar shows habits':['calendar','habits'],'Calendar shows projects':['calendar','projects']};
const setOk=x=>{const q=SETSEC[x[0]];return !q||[].concat(q).every(secOn)};
const setRow=(x,w)=>{const c=x[2]();if(x[3]==='raw')return `<div class="setrow">${c}</div>`;return c.startsWith('<button class="sw')?`<div class="setrow swrow"><span>${hl(x[0],w)}</span>${c}</div>`:`<div class="setrow"><p class="meta setlab">${hl(x[0],w)}</p>${c}</div>`};
const onOff=k=>tog(k,!!CFG[k]);
const SETS=()=>[
 ['Theme','color color palette appearance classic oled notepad forest aqua princess custom new theme create edit import export colors editor json',()=>themeGrid()],
 ['Design style','appearance style black gray grey monochrome mono grayscale dark accent filled buttons colorful colourful color vibrant tinted material android google shapes buttons fields rounded look prodify',()=>seg('uiStyle',[['default','Prodify'],['accent','Accent'],['colorful','Colorful'],['mono','Black & gray'],['material','Material']],['accent','colorful','mono','material'].includes(CFG.uiStyle)?CFG.uiStyle:'default')],
 ['Mode','dark light system appearance night theme',()=>seg('theme',[['system','System'],['light','Light'],['dark','Dark']],CFG.theme)],
 ...((THEMES[CFG.palette]||THEMES.classic).acc?[['Accent color','color appearance',()=>`<div class="moods">${Object.entries(ACC).map(([k,a])=>`<button data-act="set" data-s="accent" data-val="${k}" class="${CFG.accent===k?'on':''}"><span class="dot" style="background:${a[0]}"></span>${k[0].toUpperCase()+k.slice(1)}</button>`).join('')}</div>`]]:[]),
 ['Font','typeface writing serif sans mono jetbrains appearance',()=>seg('font',[['jetbrains','JetBrains Mono'],['default','Classic'],['serif','Serif'],['sans','Sans'],['mono','Mono']],CFG.font)],
 ['Text size','font bigger smaller zoom appearance',()=>seg('size',[[14,'Small'],[16,'Medium'],[18,'Large']],CFG.size)],
 ['Zoom','zoom scale bigger smaller magnify interface size percent appearance',()=>seg('zoom',ZOOMS.map(z=>[z,z+'%']),ZOOMS.includes(+CFG.zoom)?+CFG.zoom:100)],
 ['Page width','page width wide full narrow margins space sides layout content appearance',()=>seg('pageWidth',[['comfortable','Comfortable'],['wide','Wide'],['full','Full']],{comfortable:1,wide:1,full:1}[CFG.pageWidth]?CFG.pageWidth:'wide')],
 ['Shine on hover','plastic light gloss effect animation tilt appearance hover collections covers storage cards images',()=>tog('shine',CFG.shine!==false)],
 ['Shine color','shine color color status white tint light collections covers appearance',()=>seg('shineColor',[['status','By status'],['white','White']],CFG.shineColor||'status')],
 ['Section icons','emoji symbols appearance',()=>seg('iconStyle',[['emoji','Emoji'],['symbols','Symbols']],CFG.iconStyle)],
 ['Auto-hide sidebar','compact mode zen hover hide sidebar menu navigation collapse',()=>tog('navAuto',!!CFG.navAuto)],
 ['Show scrollbars','scroll bar hide scrolling appearance',()=>tog('scrollbars',!!CFG.scrollbars)],
 ['Language','language idioma english spanish español ingles',()=>seg('lang',[['en','English'],['es','Español']],CFG.lang==='es'?'es':'en')],
 ['Card colors','color color vibrant vivid soft muted bright saturated tiles side cards appearance',()=>seg('cardColors',[['soft','Soft'],['vibrant','Vibrant']],CFG.cardColors==='vibrant'?'vibrant':'soft')],
 ['Home layout','home layout board whiteboard free floating canvas columns sticky notes pinned messages images',()=>seg('homeLayout',[['columns','Columns'],['board','Board']],CFG.homeLayout==='board'?'board':'columns')],
 ['Home columns','layout cards grid width dashboard auto 2 3 4',()=>seg('homeCols',[['auto','Auto'],[2,'2'],[3,'3'],[4,'4']],homeColsCfg())],
 ['Health overview columns','layout cards grid width health 2 3 4',()=>seg('healthCols',[[2,'2'],[3,'3'],[4,'4']],+CFG.healthCols||2)],
 ['Show item counts on cards','numbers count badge sidebar cards navigation appearance',()=>tog('navCounts',CFG.navCounts!==false)],
 ['Navigation layout','sidebar top bar cards icons only compact rail menu appearance',()=>seg('navLayout',[['side','Sidebar'],['top','Top bar'],['cards','Cards'],['grid','Icon grid'],['icons','Icons']],CFG.navLayout)],
 ['Week starts on','calendar monday sunday saturday',()=>seg('week',[[1,'Monday'],[0,'Sunday'],[6,'Saturday']],CFG.week)],
 ['Time format','clock 12 24 hour am pm time format journal events reminders alarms',()=>seg('time',[['24','24-hour · 15:30'],['12','12-hour · 3:30 PM']],CFG.time==='12'?'12':'24')],
 ['Collections fields','metadata properties platform downloaded store device netflix steam fields per type collections',colFieldSettings],
 ['Collections API keys','tmdb rawg movies games books series anime key',colSettings],
 ['Commands','slash / shortcuts keywords words note task event project',cmdSettings],
 ['Storage folder','files location directory data save path disk vault app storage database markdown sqlite private inside',()=>(STORE_DB?'':storageBody())+storeModeBody(),'raw'],
 ['Weather city','weather city location town forecast temperature home card time clock',()=>wxSettings()],
 ['Your name','greeting',()=>`<input id="sname" value="${esc(CFG.name)}" placeholder="Optional" style="max-width:260px">`],
 ['Daily reflection question','journal prompt home',()=>onOff('prompts')],
 ['AI question topics','journal questions topic focus friends family partner work money health emotions values growth',topicPick],
 ['Open Prodify on','start startup page home',()=>seg('start',visTabs().filter(t=>t[0]!=='settings').map(t=>[t[0],t[1]]),CFG.start)],
 ['Notes layout','cards panel list notes',()=>seg('notesView',[['cards','Cards'],['panel','Panel']],CFG.notesView)],
 ['Notes sort','order alphabetical date notes',()=>seg('notesSort',[['date','Date created'],['alpha','Alphabetical']],CFG.notesSort)],
 ['Open notes in','view edit mode read notes default',()=>seg('noteOpen',[['edit','Edit mode'],['view','View mode']],CFG.noteOpen||'view')],
 ['Show journal entries in Notes','journal entries notes list mix combine',()=>tog('jInNotes',CFG.jInNotes!==false)],
 ['New notes start typing in','title text cursor notes',()=>seg('newNoteFocus',[['title','Title'],['body','Text']],CFG.newNoteFocus)],
 ['Confirm before deleting a task','delete ask tasks',()=>onOff('confirmTask')],
 ['Confirm before deleting a note','delete ask notes',()=>onOff('confirmNote')],
 ['Confirm before deleting a project','delete ask projects',()=>onOff('confirmProject')],
 ['Confirm before deleting a question','delete ask journal',()=>onOff('confirmQuestion')],
 ['AI-generated questions','claude journal integrations',()=>onOff('intAi')],
 ...(TAURI?[['AI connection','anthropic api key claude model haiku sonnet opus ai artificial intelligence integrations summarize categories tasks test connection',aiKeyBody,'raw']]:[]),
 ['Account and encryption','account local encryption encrypt decrypt privacy lock password recovery key security protect pin passcode hide ctrl+l idle auto lock unlock',()=>accSettings().replace(/^<section class="accsec"><h2>[^<]*<\/h2>/,'').replace(/<\/section>[\s\S]*$/,''),'raw'],
 ['Calendar view','calendar month week day layout default',()=>seg('calView',[['month','Month'],['week','Week'],['day','Day']],['month','week','day'].includes(CFG.calView)?CFG.calView:'month')],
 ['Note categories view','categories covers tiles list notes layout',()=>seg('catView',[['covers','Covers'],['tiles','Tiles'],['list','List']],['tiles','list'].includes(CFG.catView)?CFG.catView:'covers')],
 ['Category page layout','category notes grid list cards layout',()=>seg('catNotes',[['grid','Grid'],['list','List']],CFG.catNotes==='list'?'list':'grid')],
 ['Storage layout','storage links images pdfs cards list view layout files',()=>`<div class="pseg" role="group">${[['list','List'],['cards','Cards']].map(([v,l])=>`<button data-act="stViewSet" data-val="${v}" class="${(CFG.stView||'list')===v?'on':''}">${l}</button>`).join('')}</div>`],
 ['Storage sort','storage order newest oldest alphabetical a-z type links images pdfs',()=>`<div class="pseg" role="group">${STSORT.map(([v,l])=>`<button data-act="stSortSet" data-val="${v}" class="${(CFG.stSort||'new')===v?'on':''}">${l}</button>`).join('')}</div>`],
 ['Gym rest timer','rest timer seconds sets workout gym health countdown break',()=>`<div class="moods seg">${[['0','Off'],['60','1 min'],['90','1:30'],['120','2 min'],['180','3 min']].map(([v,l])=>`<button data-act="hl:rest" data-val="${v}" class="${String(CFG.rest??90)===v?'on':''}">${l}</button>`).join('')}</div>`],
 ['Add a Home card','home cards new collection card task list card custom dashboard filters',()=>`<div class="row" style="margin:0">${secOn('tasks')?'<button class="g" data-act="tcNew">+ Task list card</button>':''}${secOn('collections')?'<button class="g" data-act="ccNew">+ Collection card</button>':''}</div>`],
 ['In-app reminder banner','reminders tasks integrations',()=>onOff('intRem')],
 ['Desktop notifications for reminders','notification reminders tasks integrations',()=>onOff('intNotif')],
 ['Calendar shows tasks and reminders','calendar tasks',()=>onOff('calTasks')],
 ['Calendar shows journal, mood and questions','calendar journal',()=>onOff('calJournal')],
 ['Calendar shows notes','calendar notes',()=>onOff('calNotes')],
 ['Calendar shows habits','calendar habits',()=>onOff('calHabits')],
 ['Calendar shows projects','calendar projects',()=>onOff('calProjects')],
 // Sections and Home cards show the same row as on the Settings page (icon, 1 col / 2 col, on/off), without the drag handle.
 ...tabList().map(t=>[`${t[1]} section`,'show hide sections sidebar nav icon emoji symbol width wide column 1 col 2 col cards layout',()=>plainRow(dndRow('tab',t[0],t[1]+' section',secOn(t[0]),t[0]==='settings')),'raw']),
 ...homeList().map(id=>{const x=homeDefs().find(y=>y[0]===id);return[`${x[1]} card`,'home cards dashboard show hide',()=>plainRow(dndRow('home',id,x[1]+' (Home card)',!homeOff().includes(id),false,x[2]&&!secOn(x[2])?'· its section is off':'')),'raw']}),
 ['Backups','backup restore daily automatic copy safety snapshot export',()=>backupSettings().replace(/^<section><h2>Backups<\/h2>/,'').replace(/<\/section>$/,''),'raw'],
 ['Keyboard shortcuts','keyboard shortcuts keys hotkeys go to quick capture help',()=>`<button class="g" data-act="kbOpen">Show keyboard shortcuts</button>`],
 ['Run setup again','setup onboarding welcome tour start features choose sections wizard',()=>`<button class="g" data-act="onbStart">Run setup again</button>`],
 ['Users','users people profiles family switch user multi multiple accounts add remove who is using',()=>usersSettings().replace(/^<section class="usersec"><h2>Users<\/h2>/,'').replace(/<\/section>$/,''),'raw'],
 ...(TAURI?[['Backup folder','backup folder mirror copy second drive usb external disk',()=>mirSection().replace(/^<section><h2>Backup folder<\/h2>/,'').replace(/<\/section>$/,''),'raw']]:[]),
 ['Search bar above the tab bar on phones','search bar bottom phone mobile thumb reach home',()=>tog('searchLow',!!CFG.searchLow)],
 ['Keep Home cards in the column you put them','home cards columns fixed flow order drag move',()=>tog('homeFixed',!!CFG.homeFixed)],
 ...(innerWidth<=760?[['Phone tab bar','phone mobile tab bar bottom icons navigation more pick reorder sections',()=>'<button class="g" data-act="mEditOpen">Edit tab bar</button>','raw']]:[]),
 ['Reset','reset settings erase delete wipe all data defaults',()=>`<div class="row" style="margin:0"><button class="g" data-act="resetCfg">Reset settings</button><button class="g" data-act="wipe">${armed==='wipe'?'Click again to erase everything':'Erase all notes, journal and tasks'}</button></div>`]];
const plainRow=h=>h.replace(/ data-dnd="[^"]*"/,'').replace(/<span class="grip"[^>]*>⠿<\/span>/,'');
function homeResults(){if(hq.startsWith('/'))return cmdHelp();const G=[hqSaveRow()],lim=5,more=(n,act)=>n>lim?`<button class="x" ${act}>See all ${n}</button>`:'';
 const on=secOn,nk=on('notes')?keys('notes/').filter(k=>hMatch(FS[k])):[];
 if(nk.length)G.push(sgroup('Notes',nk.length,nk.slice(0,lim).map(k=>{const f=readNote(FS[k]).fm,d=noteDate(k);return sres(`data-act="openNote" data-k="${esc(k)}"`,noteTitle(k),[d?fmt(d):'',...(f.categories||[]),...(f.tags||[]).map(x=>'#'+x),hl(hSnip(stripFM(FS[k]).replace(/^\s*#[^\n]*\n?/,'')))].filter(Boolean).join(' · '))}).join(''),more(nk.length,'data-act="notesSearch"')));
 const ts=!on('tasks')?[]:tasks().filter(t=>hMatch(t.title,(t.subs||[]).map(x=>x.title).join(' '))).sort((a,b)=>a.done-b.done);
 if(ts.length)G.push(sgroup('Tasks',ts.length,ts.slice(0,lim).map(taskRow).join(''),more(ts.length,'data-act="listGo" data-val="all"')));
 const ls=on('tasks')?allLists().filter(l=>hMatch(l.name)):[];
 if(ls.length)G.push(sgroup('Task lists',ls.length,ls.map(l=>sres(`data-act="listGo" data-val="${esc(l.id)}"`,l.name,`${lOpen(l,tasks())} open`)).join('')));
 const ps=on('projects')?projects().filter(p=>hMatch(p.name,p.desc)):[];
 if(ps.length)G.push(sgroup('Projects',ps.length,ps.slice(0,lim).map(p=>sres(`data-act="openPj" data-k="${esc(p.id)}"`,p.name,(p.status==='done'?'Complete':'Active')+(p.desc?' · '+hl(hSnip(p.desc)):''))).join('')));
 const hs=on('habits')?habits().filter(x=>hMatch(x.name,x.unit)):[];
 if(hs.length)G.push(sgroup('Habits',hs.length,hs.slice(0,lim).map(x=>habitItem(x,TD())).join('')));
 const es=on('calendar')?events().filter(e=>hMatch(e.title)):[];
 if(es.length)G.push(sgroup('Events',es.length,es.slice(-lim).reverse().map(e=>sres(`data-act="evGo" data-d="${e.date}"`,e.title,fmt(e.date,LONG))).join('')));
 const jk=!on('journal')?[]:[...entKeys().filter(k=>hMatch(jeRead(k).body,jeRead(k).loc)),...dayKeys().filter(k=>{const f=freeText(k);return f!==null&&hMatch(f)})];
 if(jk.length)G.push(sgroup('Journal',jk.length,jk.slice(0,lim).map(k=>isJE(k)?(e=>sres(`data-act="jGo"`,`${fmt(e.date,LONG)}${e.time?' · '+e.time:''}`,hl(hSnip(e.body))))(jeRead(k)):sres(`data-act="jGo"`,fmt(k.slice(8,-3),LONG),hl(hSnip(freeText(k).replace(/^---[\s\S]*?---\n/,'').replace(/^## .*$/gm,''))))).join('')));
 const qs2=!on('journal')?[]:allQ().filter(x=>hMatch(x.q,x.a.map(y=>y.t).join(' ')));
 if(qs2.length)G.push(sgroup('Questions',qs2.length,qs2.slice(0,lim).map(x=>sres(`data-act="qGo"`,x.q,x.a.length?hl(hSnip(x.a.map(y=>y.t).join('\n'))):'Not answered yet')).join(''),more(qs2.length,'data-act="qGo"')));
 const cs=on('notes')?[...propIndex('categories').values()].filter(c=>hMatch(c.name)):[],tg=on('notes')?[...propIndex('tags').values()].filter(t=>hMatch(t.name)):[];
 if(cs.length||tg.length)G.push(sgroup('Categories and tags',cs.length+tg.length,`<div class="nchips">${cs.map(c=>`<button class="clink" data-act="openCat" data-v="${esc(c.name)}">${hl(c.name)}</button>`).join('')}${tg.map(t=>`<button class="chip tagc clink" data-act="tagGo" data-v="${esc(t.name)}">${hl(t.name)}</button>`).join('')}</div>`));
 const tp=on('notes')?keys('templates/').filter(k=>hMatch(tplName(k))):[];
 if(tp.length)G.push(sgroup('Templates',tp.length,tp.map(k=>sres(`data-act="tplGo" data-k="${esc(k)}"`,tplName(k),'Template')).join('')));
 const ci=!on('collections')?[]:colKeys().map(colRead).filter(it=>hMatch(it.title,it.creator,it.year,it.genres.join(' ')));
 if(ci.length)G.push(sgroup('Collections',ci.length,ci.slice(0,lim).map(it=>sres(`data-act="col:open" data-k="${esc(it.k)}"`,it.title,esc([ctype(it.type).one,colMeta(it),statLabel(it.type,it.status)].filter(Boolean).join(' · ')))).join(''),more(ci.length,'data-act="nav" data-v="collections"')));
 // Storage: saved links, images and PDFs (opening them like in Storage).
 if(on('files')){const sl=[...stRead('links'),...stRead('images'),...stRead('pdfs')].filter(x=>hMatch(x.title,x.k==='links'?x.url+' '+x.desc:'',x.k==='links'?'link':x.k==='pdfs'?'pdf':'image')),set=esc(stRead('images').map(x=>x.att).join('|'));
  const si=sl.filter(x=>x.k==='images'),so=sl.filter(x=>x.k!=='images');
  if(sl.length)G.push(sgroup('Storage',sl.length,(si.length?`<div class="srimgs">${si.slice(0,8).map(x=>`<button class="srimg" ${stOpenAttr(x,set)}><span class="srimgc"><img data-att="${esc(x.att)}" alt="" loading="lazy"></span><b>${hl(x.title||'Image')}</b><span class="meta">${fmt(x.d,{month:'short',day:'numeric'})}</span></button>`).join('')}</div>`:'')+so.slice(0,lim).map(x=>`<button class="sres sresi" ${stOpenAttr(x,set)}>${x.k==='pdfs'?'<span class="stpdf">PDF</span>':stFavicon(x)}<span class="srt"><b>${hl(x.title)}</b><span class="meta">${esc([x.k==='links'?'Link · '+host(x.url):'PDF',fmt(x.d)].join(' · '))}</span></span></button>`).join(''),more(sl.length,'data-act="goSub" data-v="files" data-sub="all"')))}
 // Gym: workouts (by date, routine or exercise), routines and logged exercises.
 if(on('health')){const wk=workouts().map(d=>wkRead(d)).filter(w=>w&&hMatch(fmt(w.d,LONG),w.d,w.routine,w.day,w.notes,w.ex.map(e=>e.name).join(' '),'workout gym')),rt=routines().filter(r=>hMatch(r.name,r.days.map(d=>d.name+' '+d.ex.map(e=>e.name).join(' ')).join(' '),'routine')),ex=exStats().filter(x=>hMatch(x.name,'exercise'));
  if(wk.length)G.push(sgroup('Workouts',wk.length,wk.slice(0,lim).map(w=>sres(`data-act="hl:open" data-val="${w.d}"`,fmt(w.d,LONG),esc([w.routine&&(w.routine+(w.day&&w.day!==w.routine?' · '+w.day:'')),w.ex.map(e=>e.name).slice(0,4).join(', ')].filter(Boolean).join(' — ')))).join(''),more(wk.length,'data-act="goSub" data-v="health" data-sub="gym"')));
  if(rt.length)G.push(sgroup('Routines',rt.length,rt.map(r=>sres(`data-act="goSub" data-v="health" data-sub="gym"`,r.name,esc(r.days.map(d=>d.name).join(' · ')))).join('')));
  if(ex.length)G.push(sgroup('Exercises',ex.length,ex.slice(0,lim).map(x=>sres(`data-act="hl:ex" data-val="${esc(x.name)}"`,x.name,esc([x.days+' session'+(x.days===1?'':'s'),x.best?`best ${x.best.kg} kg × ${x.best.reps}`:''].filter(Boolean).join(' · ')))).join('')))}
 // Alarms and timers by their label.
 const al=[...(CFG.alarms||[]).filter(a=>hMatch(a.label||'alarm',a.time,'alarm')).map(a=>sres(`data-act="goSub" data-v="today" data-sub="alarms"`,a.label||'Alarm',esc(tf(a.time)+' · '+alDays(a)+(a.on?'':' · off')))),...(CFG.timers||[]).filter(t=>hMatch(tmName(t),'timer')).map(t=>sres(`data-act="goSub" data-v="today" data-sub="timers"`,tmName(t),tmFmt(tmLeft(t))+(t.end?' left':'')))];
 if(al.length)G.push(sgroup('Timers and alarms',al.length,al.join('')));
 // Go to: sections and their pages (Gym, Categories, Links…), by name.
 const GO=[...visTabs().map(t=>[t[0],'',t[1]]),['health','gym','Gym','Health'],['health','meditation','Meditation','Health'],['notes','categories','Categories','Notes'],['notes','tags','Tags','Notes'],['notes','templates','Templates','Notes'],['notes','archive','Archived','Notes'],
  ['journal','questions','Questions','Journal'],['files','links','Links','Storage'],['files','images','Images','Storage'],['files','pdfs','PDFs','Storage'],['files','files','Files','Storage'],['calendar','week','Week view','Calendar'],['calendar','day','Day view','Calendar']].filter(([v])=>on(v)||v==='settings');
 const go=GO.filter(([v,sb,l,p])=>hMatch(l,p||'',v,sb));
 if(go.length)G.unshift(sgroup('Go to',go.length,`<div class="gorow">${go.slice(0,8).map(([v,sb,l,p])=>`<button class="g" data-act="goSub" data-v="${v}" data-sub="${sb}">${p?`<span class="meta">${p} ›</span>`:''}${l}</button>`).join('')}</div>`));
 const st=SETS().filter(setOk).filter(x=>hMatch(x[0],x[1]));
 if(st.length)G.push(sgroup('Settings',st.length,st.map(x=>setRow(x)).join(''),'<button class="x" data-act="nav" data-v="settings">All settings</button>'));
 return G.join('')||`<section><p class="empty">Nothing found for “${esc(hq.trim())}”. Type / to see commands.</p></section>`}
/* Commands typed after "/" on Home. Each one has an id, default words (changeable in Settings → Commands), a label,
   a usage hint and plan(arg), which returns {say, go}: say is shown in the / menu before Enter ("Adds task …"),
   go performs it. Without go, say explains what's missing and Enter just shows it. */
const cmdDate=arg=>{const m=arg.match(/^(today|tomorrow|hoy|mañana|\d{4}-\d{2}-\d{2})(?:\s+|$)([\s\S]*)$/i);if(!m)return['',arg];const w=m[1].toLowerCase();return[w==='today'||w==='hoy'?TD():w==='tomorrow'||w==='mañana'?dAdd(TD(),1):w,m[2].trim()]};
// Best match by name: exact, then starts with, then contains (ignoring case and accents).
const pickBy=(items,name,q)=>{const f=fold(q).trim();if(!f)return null;return items.find(x=>fold(name(x))===f)||items.find(x=>fold(name(x)).startsWith(f))||items.find(x=>fold(name(x)).includes(f))||null};
// "Name rest": the longest item name the text starts with, else the first word as a partial name.
function nameThen(items,name,arg){const fa=fold(arg);const full=items.slice().sort((a,b)=>name(b).length-name(a).length).find(x=>{const f=fold(name(x));return fa===f||fa.startsWith(f+' ')});
 if(full)return{item:full,rest:arg.slice(name(full).length).trim()};const w=arg.split(/\s+/)[0];return{item:pickBy(items,name,w),rest:arg.slice(w.length).trim(),word:w}}
const wordsMatch=(text,q)=>{const t=fold(text);return fold(q).split(/\s+/).filter(Boolean).every(w=>t.includes(w))};
const openView=(v,f)=>{view=v;if(f)f();render();window.scrollTo(0,0)};
const focusId=id=>{const el=$(id);if(el)el.focus()};
const done_=msg=>{save();render();if(msg)toast(msg);return true};
const CMDS=[
 {id:'n',words:['n','note'],label:'New note',usage:'Title',plan:a=>({say:a?`Creates note “${esc(a)}”`:'Opens a new note',go:()=>{view='notes';nmode='notes';edN=null;ND=null;tplSel=null;addProp=false;
  if(a){draft();ND.title=a;commitHist();persistNote()}save();render();window.scrollTo(0,0);a?focusId('nb'):focusNew();return true}})},
 {id:'t',words:['t','task'],label:'New task',usage:'[today|tomorrow|2026-10-25] Title',plan:a=>{const[d,t]=cmdDate(a);
  return t?{say:`Adds task “${esc(t)}”${d?' due '+fmt(d):''}`,go:()=>{putTasks(tasks().concat([{done:false,title:t,due:d,rem:'',proj:'',list:'',added:TD()}]));return done_(`Task added${d?' · due '+fmt(d):''}`)}}
   :{say:'Opens your tasks',go:()=>{openView('tasks',()=>{curList='all';edL=false});focusId('tt');return true}}}},
 {id:'e',words:['e','event'],label:'New event',usage:'[today|tomorrow|2026-10-25] Title',plan:a=>{const[d,t]=cmdDate(a),day=d||TD();
  return t?{say:`Adds event “${esc(t)}” on ${fmt(day)}`,go:()=>{putEvents(events().concat([{date:day,title:t}]));return done_('Event added · '+fmt(day))}}
   :{say:'Opens the calendar',go:()=>{openView('calendar',()=>{sel=TD()});focusId('et');return true}}}},
 {id:'p',words:['p','project'],label:'New project',usage:'Name',plan:a=>a?{say:`Creates project “${esc(a)}”`,go:()=>{let id=slug(a),c=2;while(FS['projects/'+id+'.md'])id=slug(a)+'-'+c++;
  putP({id,name:a,status:'active',created:TD(),desc:'',notes:[]});curP=id;view='projects';return done_()}}:{say:'Opens your projects',go:()=>{openView('projects',()=>{curP=null});focusId('pnm');return true}}},
 // "/j @Place: text", or "@Place text" for a one-word place.
 {id:'j',words:['j','journal'],label:'Journal entry',usage:'[@Place:] Text',plan:a=>{const m=a.match(/^@([^:]+):\s*([\s\S]*)$/)||a.match(/^@(\S+)\s*([\s\S]*)$/),loc=m?m[1].trim():'',t=m?m[2].trim():a;
  return t?{say:`Adds a journal entry${loc?' at '+esc(loc):''}: “${esc(t.length>60?t.slice(0,60)+'…':t)}”`,go:()=>{addEntry(TD(),'',[loc?'📍 '+loc:'',t].filter(Boolean).join('\n\n'));return done_('Saved to journal')}}
   :{say:'Opens your journal',go:()=>{openView('journal',()=>{jtab='entries'});focusId('jt');return true}}}},
 {id:'m',words:['m','mood'],label:'Mood today',usage:'low | down | okay | good | great (or 1–5)',plan:a=>{if(!a)return{say:'Opens Home to pick a mood',go:()=>{openView('today');return true}};
  const n=/^[1-5]$/.test(a)?+a:(MOOD.findIndex(x=>fold(x[0]).startsWith(fold(a)))+1)||(fold(a)==='ok'?3:0);
  return n?{say:`Sets today’s mood to ${MOOD[n-1][0]}`,go:()=>{setMood(TD(),n);return done_('Mood · '+MOOD[n-1][0])}}:{say:'Type low, down, okay, good or great (or 1–5)'}}},
 {id:'h',words:['h','habit'],label:'Log a habit',usage:'Habit [yes | no | number]',plan:a=>{if(!a)return{say:'Opens your habits',go:()=>{openView('habits',()=>{hday=TD()});return true}};
  const {item:x,rest,word}=nameThen(habits(),h=>h.name,a);if(!x)return{say:`No habit called “${esc(word||a)}”`};let val;
  if(x.kind==='yesno'){const r=fold(rest);val=!r||/^(y|yes|si|done|1|ok)$/.test(r)?'yes':/^(n|no|0)$/.test(r)?'no':null;if(!val)return{say:`Type yes or no for ${esc(x.name)}`}}
  else{const n=parseFloat(rest.replace(',','.'));if(isNaN(n))return{say:`Add a number for ${esc(x.name)}${x.unit?' ('+esc(x.unit)+')':''}`};val=String(n)}
  return{say:`Logs ${esc(x.name)}: ${esc(val)}${x.kind==='number'&&x.unit?' '+esc(x.unit):''} for today`,go:()=>{x.log[TD()]=val;putH(x);return done_(`${x.name} logged`)}}}},
 // "/r [date] 18:30 Title" (also 6pm / 6:30pm); without a date, a time already past means tomorrow.
 {id:'r',words:['r','remind'],label:'Task with a reminder',usage:'[today|tomorrow|2026-10-25] 18:30 Title',plan:a=>{if(!a)return{say:'Opens your tasks with the reminder field',go:()=>{tDet=true;openView('tasks',()=>{curList='all';edL=false});focusId('tt');return true}};
  const[d,rest]=cmdDate(a),m=rest.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?(?:\s+|$)([\s\S]*)$/i);if(!m||(!m[2]&&!m[3]))return{say:'Add a time, e.g. /'+cmdWords(CMDS.find(c=>c.id==='r'))[0]+' 18:30 Call mum'};
  let h=+m[1],mi=+(m[2]||0);if(m[3]){const pm=m[3].toLowerCase()==='pm';if(h===12)h=0;if(pm)h+=12}if(h>23||mi>59)return{say:'That time doesn’t look right'};const t=m[4].trim();if(!t)return{say:'Add what to be reminded about'};
  const tm=pad(h)+':'+pad(mi);let day=d||TD();if(!d&&`${day} ${tm}`<stamp(new Date()))day=dAdd(day,1);
  return{say:`Adds “${esc(t)}” with a reminder ${fmt(day)} at ${tm}`,go:()=>{putTasks(tasks().concat([{done:false,title:t,due:day,rem:`${day} ${tm}`,proj:'',list:'',added:TD()}]));return done_(`Reminder set · ${fmt(day)} ${tm}`)}}}},
 {id:'l',words:['l','list'],label:'Add to a list',usage:'List Title',plan:a=>{if(!a)return{say:'Opens your task lists',go:()=>{openView('tasks',()=>{curList=null});return true}};
  const {item:l,rest,word}=nameThen(userLists(),x=>x.name,a);if(!l)return{say:`No list called “${esc(word||a)}”`};
  return rest?{say:`Adds “${esc(rest)}” to ${esc(l.name)}`,go:()=>{putTasks(tasks().concat([{done:false,title:rest,due:'',rem:'',proj:'',list:l.id,added:TD()}]));return done_('Added to '+l.name)}}
   :{say:`Opens ${esc(l.name)}`,go:()=>{openView('tasks',()=>{curList=l.id;edL=false});return true}}}},
 {id:'q',words:['q','question'],label:'Answer today’s question',usage:'Your answer',plan:a=>{if(!a||!curQ)return{say:curQ?`Opens “${esc(curQ)}”`:'Opens your questions',go:()=>{openView('journal',()=>{jtab='questions'});focusId('qa0');return true}};
  const q=curQ;return{say:`Answers “${esc(q)}”`,go:()=>{addEntry(TD(),q,a);curQ=null;save();newQ();toast('Saved to Questions');return true}}}},
 {id:'d',words:['d','done'],label:'Check off a task',usage:'Part of a task’s name',plan:a=>{if(!a)return{say:'Opens your tasks',go:()=>{openView('tasks',()=>{curList='all'});return true}};
  const ms=tasks().filter(t=>!t.done&&wordsMatch(t.title,a)).sort((x,y)=>(x.due||'9')<(y.due||'9')?-1:1);if(!ms.length)return{say:`No open task matches “${esc(a)}”`};
  return{say:`Checks off “${esc(ms[0].title)}”${ms.length>1?` (${ms.length-1} more match${ms.length>2?'es':''})`:''}`,go:()=>{const ts=tasks(),t=ts[ms[0].i];t.done=true;t.doneOn=TD();putTasks(ts);return done_('Done · '+t.title)}}}},
 {id:'tpl',words:['tpl','template'],label:'Note from a template',usage:'Template [Title]',plan:a=>{const ks=keys('templates/');if(!a)return{say:'Opens your templates',go:()=>{openView('notes',()=>{nmode='templates';edN=null;ND=null});return true}};
  const {item:k,rest,word}=nameThen(ks,tplName,a);if(!k)return{say:`No template called “${esc(word||a)}”`};
  return{say:`New ${esc(tplName(k))} note${rest?` “${esc(rest)}”`:''}`,go:()=>{view='notes';nmode='notes';edN=null;ND=null;tplSel=k;addProp=false;if(rest){draft();ND.title=rest;commitHist();persistNote()}save();render();window.scrollTo(0,0);rest?focusId('nb'):focusNew();return true}}}},
 // Sections, Notes views, task lists and projects.
 {id:'go',words:['go','open'],label:'Go to',usage:'Section, list or project',plan:a=>{const T=[...visTabs().map(t=>({n:t[1],go:()=>openView(t[0])})),
   ...(secOn('notes')?[['categories','Categories'],['tags','Tags'],['templates','Templates'],['archive','Archived notes']]:[]).map(([m,n])=>({n,go:()=>openView('notes',()=>{nmode=m;selCat=null;edN=null;ND=null})})),
   ...(secOn('tasks')?allLists():[]).map(l=>({n:l.name,go:()=>openView('tasks',()=>{curList=l.id;edL=false})})),...(secOn('projects')?projects():[]).map(p=>({n:p.name,go:()=>openView('projects',()=>{curP=p.id})}))];
  if(!a)return{say:'Type a section, list or project'};const x=pickBy(T,t=>t.n,a);return x?{say:`Opens ${esc(x.n)}`,go:()=>{x.go();return true}}:{say:`Nothing called “${esc(a)}”`}}},
 {id:'tag',words:['tag','tags'],label:'Notes with a tag',usage:'Tag',plan:a=>{const x=a&&pickBy([...propIndex('tags').values()],t=>t.name,a.replace(/^#/,''));
  return !a?{say:'Opens your tags',go:()=>{openView('notes',()=>{nmode='tags'});return true}}:x?{say:`Shows notes tagged ${esc(x.name)}`,go:()=>{openView('notes',()=>{nmode='notes';tagF=x.name;edN=null;ND=null});return true}}:{say:`No tag called “${esc(a)}”`}}},
 {id:'cat',words:['cat','category'],label:'Open a category',usage:'Category',plan:a=>{const x=a&&pickBy([...propIndex('categories').values()],c=>c.name,a);
  return !a?{say:'Opens your categories',go:()=>{openView('notes',()=>{nmode='categories';selCat=null});return true}}:x?{say:`Opens ${esc(x.name)}`,go:()=>{openView('notes',()=>{nmode='categories';selCat=x.name});return true}}:{say:`No category called “${esc(a)}”`}}},
 {id:'theme',words:['theme','mode'],label:'Theme or light / dark',usage:Object.values(THEMES).map(t=>t.name).join(' | ')+' | dark | light | system',plan:a=>{
  const modes={dark:'dark',light:'light',system:'system',oscuro:'dark',claro:'light'},md=modes[fold(a)],th=a&&pickBy(Object.keys(THEMES),k=>THEMES[k].name,a);
  if(md)return{say:md==='system'?'Follows the system light / dark setting':`Switches to ${md} mode`,go:()=>{CFG.theme=md;saveCfg();apply();render();return true}};
  return th?{say:`Switches to the ${THEMES[th].name} theme`,go:()=>{CFG.palette=th;saveCfg();apply();render();return true}}:{say:'Type a theme name, or dark, light or system'}}},
 {id:'archive',words:['archive'],label:'Archive a note',usage:'Part of a note’s title',plan:a=>{if(!a)return{say:'Opens archived notes',go:()=>{openView('notes',()=>{nmode='archive'});return true}};
  const ms=byDate(keys('notes/').filter(k=>wordsMatch(noteTitle(k),a)));if(!ms.length)return{say:`No note title matches “${esc(a)}”`};
  return{say:`Archives “${esc(noteTitle(ms[0]))}”${ms.length>1?` (${ms.length-1} more match)`:''}`,go:()=>{const t=noteTitle(ms[0]);archiveNote(ms[0]);return done_('Archived · '+t)}}}}];
const cmdWords=c=>{const w=(CFG.cmdKeys||{})[c.id];return Array.isArray(w)&&w.length?w:c.words};
const cmdUsage=c=>`/${cmdWords(c)[0]} ${c.usage}`;
const cmdTry=()=>CMDS.slice(0,4).map(c=>'/'+cmdWords(c)[0]).join(', ');
// The section each command belongs to; a command is off when its section is off.
const CMDSEC={n:'notes',t:'tasks',e:'calendar',p:'projects',j:'journal',h:'habits',r:'tasks',l:'tasks',q:'journal',d:'tasks',tpl:'notes',tag:'notes',cat:'notes',archive:'notes'};
const cmdOn=c=>!CMDSEC[c.id]||secOn(CMDSEC[c.id]);
const cmdOf=raw=>{const m=raw.match(/^\/(\S*)\s*([\s\S]*)$/);if(!m)return null;const w=m[1].toLowerCase(),c=CMDS.filter(cmdOn).find(x=>cmdWords(x).includes(w));return c?{c,arg:m[2].trim()}:{c:null,w,arg:m[2].trim()}};
// Turns what was typed in Settings into a word list: lower case, no "/", split on commas or spaces, no repeats.
const parseWords=v=>[...new Set(String(v).toLowerCase().split(/[\s,]+/).map(x=>x.replace(/^\/+/,'')).filter(Boolean))];
const cmdSettings=()=>`<p class="meta" style="margin:0 0 10px">What you type after / on Home for each command. Separate several words with commas.</p>${CMDS.filter(cmdOn).map(c=>`<div class="cmdset"><label for="cmd-${c.id}"><b>${c.label}</b><span class="meta">${esc(cmdUsage(c))}</span></label><input id="cmd-${c.id}" data-cmd="${c.id}" value="${esc(cmdWords(c).join(', '))}" autocomplete="off" spellcheck="false"><span class="meta cmderr" id="cmderr-${c.id}" role="alert"></span></div>`).join('')}<div class="row"><button class="x" data-act="cmdReset">Restore default words</button></div>`;
function cmdHelp(){const x=cmdOf(hq),show=CMDS.filter(cmdOn).filter(c=>!x||x.c?(!x.c||c===x.c):cmdWords(c).some(w=>w.startsWith(x.w)));
 return `<section class="sgroup"><h2>Commands</h2>${show.map(c=>{const p=x&&x.c===c&&hq.match(/^\/\S+\s/)?c.plan(x.arg):null;
  return `<button class="sres cmdrow" data-act="cmdPick" data-val="${c.id}"><kbd>/${esc(cmdWords(c)[0])}</kbd><span><b>${c.label}</b><span class="meta ${p&&!p.go?'cmdwarn':''}">${p?(p.go?'Enter: ':'')+p.say:esc(cmdUsage(c))}</span></span></button>`}).join('')||`<p class="empty">No command matches. Try ${esc(cmdTry())}.</p>`}</section>`}
function runCmd(){const x=cmdOf(hq.trim());if(!x||!x.c)return false;const p=x.c.plan(x.arg);if(!p.go){const d=document.createElement('div');d.innerHTML=p.say;toast(d.textContent);return true}
 hq='';p.go();return true}
const searchBar=()=>`<div class="hsearch">${sym('magnifying-glass')}<input id="hq" value="${esc(hq)}" placeholder="Search everything, or type / for a command" autocomplete="off" spellcheck="false" aria-label="Search or command">${hq?`<button class="sclr hqclr" data-act="sclr" data-for="hq" aria-label="Clear search" title="Clear (Esc)">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:'<kbd title="Ctrl+K from anywhere">Ctrl K</kbd>'}</div>${hqTray()}`;
/* Time & weather (Home card). The city is set in Settings → General: it is looked up once with Open-Meteo's geocoding
   (CFG.weather = {name, admin, country, lat, lon}); the forecast comes from Open-Meteo (no account or key) and is kept
   for 20 minutes. Units: CFG.tempUnit 'c' or 'f'. */
let WX=null,wxBusy=false,wxErr='';
const WXC=[[[0],'Clear','sun','moon'],[[1],'Mostly clear','sun','moon'],[[2],'Partly cloudy','cloud-sun','cloud-moon'],[[3],'Cloudy','cloud','cloud'],[[45,48],'Fog','cloud-fog','cloud-fog'],
 [[51,53,55,56,57],'Drizzle','cloud-rain','cloud-rain'],[[61,63,65,66,67,80,81,82],'Rain','cloud-rain','cloud-rain'],[[71,73,75,77,85,86],'Snow','cloud-snow','cloud-snow'],[[95,96,99],'Thunderstorm','cloud-lightning','cloud-lightning']];
const wxInfo=(c,day=1)=>{const w=WXC.find(x=>x[0].includes(+c))||WXC[3];return {label:w[1],ico:day?w[2]:w[3]}};
const wxDeg=v=>v==null?'–':Math.round(CFG.tempUnit==='f'?v*9/5+32:v)+'°';
async function wxLoad(force){const c=CFG.weather;if(!c||wxBusy)return;if(!force&&WX&&WX.lat===c.lat&&WX.lon===c.lon&&Date.now()-WX.at<20*60000)return;wxBusy=true;wxErr='';
 try{const u=`https://api.open-meteo.com/v1/forecast?latitude=${c.lat}&longitude=${c.lon}&current=temperature_2m,apparent_temperature,weather_code,is_day,wind_speed_10m,relative_humidity_2m&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max&timezone=auto&forecast_days=4`;
  const r=await fetch(u);if(!r.ok)throw new Error(r.status);const j=await r.json();WX={lat:c.lat,lon:c.lon,at:Date.now(),cur:j.current,daily:j.daily,tz:j.timezone}}
 catch(e){wxErr='Couldn’t load the weather. Check your connection.'}wxBusy=false;if(view==='today')rerenderKeep()}
async function wxFind(q){q=q.trim();if(!q){CFG.weather=null;WX=null;saveCfg();render();return}
 try{const r=await fetch(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(q)}&count=1&language=${CFG.lang==='es'?'es':'en'}&format=json`),j=await r.json(),g=j.results&&j.results[0];
  if(!g){toast(`No city found for “${q}”`);return}CFG.weather={name:g.name,admin:g.admin1||'',country:g.country||'',lat:+g.latitude.toFixed(3),lon:+g.longitude.toFixed(3)};WX=null;saveCfg();toast(`Weather city: ${g.name}${g.country?', '+g.country:''}`);render();wxLoad(true)}
 catch(e){toast('Couldn’t look up that city. Check your connection.')}}
const clockNow=()=>{const d=new Date();return tf(pad(d.getHours())+':'+pad(d.getMinutes()))};
function wxCard(){const c=CFG.weather,d=new Date();if(c)wxLoad();
 const clock=`<div class="wxclock"><b id="hclock">${clockNow()}</b><span class="meta">${fmt(TD(),{weekday:'long',month:'long',day:'numeric'})}</span></div>`;
 if(!c)return `<section class="wxcard">${clock}<div class="wxset"><span class="meta">Add your city to see the weather here.</span><button class="g" data-act="wxSet">Set city</button></div></section>`;
 const W=WX&&WX.lat===c.lat&&WX.lon===c.lon?WX:null;
 if(!W)return `<section class="wxcard">${clock}<p class="meta wxload">${wxErr?esc(wxErr)+' <button class="x" data-act="wxRetry">Try again</button>':'Loading the weather…'}</p></section>`;
 const cu=W.cur,i=wxInfo(cu.weather_code,cu.is_day),dl=W.daily;
 return `<section class="wxcard">${clock}<div class="wxnow"><span class="wxico">${sym(i.ico)}</span><div class="wxtemp"><b>${wxDeg(cu.temperature_2m)}</b><span>${i.label}</span></div><div class="wxmeta meta"><span data-notr>${sym('map-pin')}${esc(c.name)}</span><span>Feels like ${wxDeg(cu.apparent_temperature)}</span><span>High ${wxDeg(dl.temperature_2m_max[0])} · Low ${wxDeg(dl.temperature_2m_min[0])}</span></div></div>
<div class="wxdays">${[1,2,3].map(k=>{const di=wxInfo(dl.weather_code[k]);return `<div title="${di.label}"><span class="meta">${DN[pd(dl.time[k]).getDay()]}</span>${sym(di.ico)}<b>${wxDeg(dl.temperature_2m_max[k])}</b><span class="meta">${wxDeg(dl.temperature_2m_min[k])}</span>${dl.precipitation_probability_max&&dl.precipitation_probability_max[k]>=30?`<span class="wxrain">${dl.precipitation_probability_max[k]}%</span>`:''}</div>`}).join('')}</div></section>`}
document.addEventListener('keydown',e=>{if(e.target&&e.target.id==='wcity'&&e.key==='Enter'){e.preventDefault();wxFind(e.target.value)}});
setInterval(()=>{const c=$('hclock');if(c){const n=clockNow();if(c.textContent!==n)c.textContent=n}if(view==='today'&&CFG.weather&&WX&&Date.now()-WX.at>20*60000&&!document.hidden)wxLoad()},1000);
/* Home Board (Settings → Home layout, or the board button on Home): instead of columns, cards float anywhere on a
   whiteboard and can be dragged and resized, next to sticky notes, pinned messages and images from Storage.
   - Positions live in CFG.homeBoard = {items: {bid: {x, y, w, h, z, ...}}, z} (bid: card:<id>, note:<key>, msg:<id>, img:<uid>).
   - Sticky notes are ordinary notes in notes/ with "sticky: true" and "color:" in their front matter.
   - Pinned messages are kept in board.md:  - m-abc123: Ship it by Friday   (line breaks written as \n).
   Narrow windows (under 700 px) fall back to columns. */
const HB=()=>{if(!CFG.homeBoard||!CFG.homeBoard.items)CFG.homeBoard={items:{},z:1};return CFG.homeBoard};
const boardMode=()=>CFG.homeLayout==='board'&&availW()>=700;
// Columns and Board each have their own set of cards: hidden cards are CFG.homeOff in columns and CFG.boardOff on the board.
const homeOffKey=()=>boardMode()?'boardOff':'homeOff',homeOff=()=>boardMode()&&Array.isArray(CFG.boardOff)?CFG.boardOff:(CFG.homeOff||[]);
const STC={yellow:'#fde68a',lemon:'#fef08a',orange:'#fed7aa',peach:'#fecaca',pink:'#fbcfe8',rose:'#fecdd3',purple:'#ddd6fe',lavender:'#e9d5ff',blue:'#bfdbfe',sky:'#bae6fd',mint:'#a7f3d0',green:'#bbf7d0',lime:'#d9f99d',sand:'#e7e5e4',white:'#f8fafc'};
// A sticky note's color: a named pastel, or any custom "#rrggbb"; dark colors get light text.
const stcOf=c=>STC[c]||(/^#[0-9a-f]{6}$/i.test(c||'')?c:STC.yellow);
const stcInk=hex=>{const n=parseInt(hex.slice(1),16),L=(.299*(n>>16&255)+.587*(n>>8&255)+.114*(n&255))/255;return L<.55?'#f8fafc':'#2a2a24'};
const boardMsgs=()=>{const o={};(FS['board.md']||'').split('\n').forEach(l=>{const m=l.match(/^- (m-[a-z0-9]+): (.*)$/);if(m)o[m[1]]=m[2].replace(/\\n/g,'\n')});return o};
const boardMsgsWrite=o=>{FS['board.md']='# Board messages\n\n'+Object.entries(o).map(([k,v])=>`- ${k}: ${String(v).replace(/\r?\n/g,'\\n')}`).join('\n')+(Object.keys(o).length?'\n':'')};
let hbDirty=false;
function hbView(shown,wrap){const B=HB(),it=B.items,sty=p=>`left:${Math.max(0,p.x)}px;top:${Math.max(0,p.y)}px;width:${p.w}px;${p.fh?`height:${p.fh}px;`:''}z-index:${p.z||1}`,fx=p=>p.fh?' fixh':'';
 const bottom=Math.max(0,...Object.values(it).map(p=>(p.y||0)+(p.h||240)));let auto=0;
 const pos=(bid,def)=>{if(!it[bid]){it[bid]={...def,z:++B.z};hbDirty=true}return it[bid]};
 const grip=`<span class="bres" aria-hidden="true" title="Drag to resize · double-click to fit the content"></span>`;
 const cards=shown.map(id=>{const p=pos('card:'+id,{x:(auto%3)*384,y:bottom+24+Math.floor(auto++/3)*340,w:360});return `<div class="bitem bcard${fx(p)}" data-bid="card:${esc(id)}" style="${sty(p)}">${wrap(id)}${grip}</div>`});
 const msgs=boardMsgs(),extra=Object.entries(it).filter(([b])=>!b.startsWith('card:')).map(([b,p])=>{
  if(b.startsWith('note:')){const k=b.slice(5);if(!FS[k]){delete it[b];hbDirty=true;return ''}const n=readNote(FS[k]),c=stcOf(n.fm.color);
   return `<div class="bitem bnote${fx(p)}" data-bid="${esc(b)}" style="${sty(p)};--sc:${c};--sink:${stcInk(c)}"><div class="sticky"><span class="bgrip" title="Drag to move"></span><textarea data-sticky="${esc(k)}" placeholder="Write something…" aria-label="Sticky note">${esc(n.body.replace(/^\n+/,''))}</textarea></div>${grip}</div>`}
  if(b.startsWith('msg:')){const id=b.slice(4);if(msgs[id]===undefined){delete it[b];hbDirty=true;return ''}
   return `<div class="bitem bmsg${fx(p)}" data-bid="${esc(b)}" style="${sty(p)}"><div class="pinmsg"><span class="bgrip bpin" title="Drag to move">${uiIco('push-pin','📌')}</span><textarea data-bmsg="${id}" placeholder="Type a message…" aria-label="Pinned message" rows="1">${esc(msgs[id])}</textarea></div><button class="cx bdel" data-act="hbDel" data-val="${esc(b)}" aria-label="Remove" title="${b.startsWith('msg:')?'Delete message':'Remove from board'}">${lineIco('M6 6l12 12M18 6L6 18')}</button>${grip}</div>`}
  if(b.startsWith('img:')&&p.att)return `<div class="bitem bimg${fx(p)}" data-bid="${esc(b)}" style="${sty(p)}"><img data-att="${esc(p.att)}" alt="" draggable="false"><button class="cx bdel" data-act="hbDel" data-val="${esc(b)}" aria-label="Remove" title="${b.startsWith('msg:')?'Delete message':'Remove from board'}">${lineIco('M6 6l12 12M18 6L6 18')}</button>${grip}</div>`;
  delete it[b];hbDirty=true;return ''});
 if(hbDirty){hbDirty=false;setTimeout(saveCfg)}
 return `${hbTools()}<div class="hboard" id="hboard">${cards.join('')}${extra.join('')}</div>`}
const hbTools=()=>`<div class="hbtools"><button class="g" data-act="hbAdd" data-val="pick">${lineIco('M5 4h14v10l-6 6H5zM13 20v-6h6')}Sticky note</button><button class="g" data-act="hbAdd" data-val="msg">${uiIco('push-pin','📌')}Message</button><button class="g" data-act="hbAdd" data-val="img">${uiIco('image','🖼️')}Image</button><span class="meta hbhint">Drag cards by any empty spot, resize from the corner. Right-click a note, message or image for options.</span><span style="flex:1"></span><button class="x" data-act="homeLayout" data-val="columns">Back to columns</button></div>`;
/* A card resized on the board scales everything inside it: the content is laid out narrower or wider and zoomed so it
   fills the box as large as it fits (between 50% and 300%). Cards that were never resized stay at normal size. */
function hbScale(it){if(!it||!it.classList.contains('bcard'))return;const sec=it.querySelector(':scope>section'),p=HB().items[it.dataset.bid];if(!sec||!p)return;
 const set=v=>{sec.style.zoom=v;sec.style.setProperty('width',(p.w/v)+'px','important')};
 if(!p.fh){sec.style.zoom='';sec.style.removeProperty('width');return}
 const z=cz(),fits=v=>{set(v);return sec.getBoundingClientRect().height/z<=p.fh+1};let lo=.5,hi=Math.min(3,p.w/240);if(hi<lo)hi=lo;
 if(fits(hi)){set(hi);return}for(let i=0;i<9;i++){const m=(lo+hi)/2;if(fits(m))lo=m;else hi=m}set(lo)}
// After rendering: the board grows to fit its items, and notes and messages grow with their text.
function hbFit(){const b=$('hboard');if(!b)return;b.querySelectorAll('.bcard').forEach(hbScale);b.querySelectorAll('.bitem:not(.fixh) textarea[data-sticky],.bitem:not(.fixh) textarea[data-bmsg]').forEach(t=>{t.style.height='auto';t.style.height=t.scrollHeight+'px'});
 let h=0;b.querySelectorAll('.bitem').forEach(el=>{h=Math.max(h,el.offsetTop+el.offsetHeight)});b.style.height=Math.max(h+60,420)+'px'}
// Where a new board item goes: near the top of what is on screen.
function hbSpot(w){const b=$('hboard'),B=HB(),n=Object.keys(B.items).length;let y=40;if(b){const r=b.getBoundingClientRect();y=Math.max(0,(-r.top)/cz()+90)}return{x:24+(n%6)*28,y:y+(n%6)*20,w,z:++B.z}}
function hbAdd(kind,att){const B=HB();
 if(kind==='note'){const k=noteKeyFor('notes/','Sticky note',TD());FS[k]=writeNote({fm:{created:TD(),sticky:'true',color:'yellow'},body:''});B.items['note:'+k]=hbSpot(220);save();saveCfg();render();setTimeout(()=>{const t=document.querySelector(`[data-sticky="${CSS.escape(k)}"]`);if(t)t.focus()},30);toast('Sticky note added · it’s saved in Notes');return}
 if(kind==='msg'){const id='m-'+Date.now().toString(36),o=boardMsgs();o[id]='';boardMsgsWrite(o);B.items['msg:'+id]=hbSpot(300);save();saveCfg();render();setTimeout(()=>{const t=document.querySelector(`[data-bmsg="${id}"]`);if(t)t.focus()},30);return}
 if(kind==='img'&&att){B.items['img:'+Date.now().toString(36)]={...hbSpot(260),att};saveCfg();render();return}
 if(kind==='img')hbPickImg();if(kind==='pick')hbPickNote()}
// Sticky note button: start a new sticky note, or pin an existing note (searchable; notes already on the board are marked).
function hbPickNote(){const B=HB(),on=k=>!!B.items['note:'+k],ks=sortNotes(keys('notes/')).slice(0,400);let o=$('bpick');if(o)o.remove();o=document.createElement('div');o.id='bpick';o.className='cfm';
 o.innerHTML=`<div class="cfmbox bpickbox" role="dialog" aria-modal="true" aria-label="Add a note"><h2>Add a note to the board</h2><button class="b bpnew" data-bnew="1">${lineIco('M12 5v14M5 12h14')}New sticky note</button>
<span class="sbox bpsearch"><input id="bpq" placeholder="Search your notes" autocomplete="off" aria-label="Search your notes"></span><div class="bpnotes">${ks.map(k=>{const d=noteDate(k),l=noteLines(k);return `<button class="bpnote" data-bnote="${esc(k)}" data-txt="${esc((noteTitle(k)+' '+l.join(' ')).toLowerCase().slice(0,600))}" ${on(k)?'disabled':''}><b data-notr>${esc(wlPlain(noteTitle(k)))}</b><span class="meta" data-notr>${on(k)?'On the board':[d?fmt(d):'',esc((l[1]||'').slice(0,80))].filter(Boolean).join(' · ')}</span></button>`}).join('')||'<p class="meta">No notes yet.</p>'}</div>
<div class="cfmbtns"><button class="g" data-bclose="1">Cancel</button></div></div>`;
 document.body.appendChild(o);if(CFG.lang==='es')i18nRun(o);const close=()=>{o.remove();document.removeEventListener('keydown',kd,true)},kd=e=>{if(e.key==='Escape'){e.preventDefault();e.stopPropagation();close()}};document.addEventListener('keydown',kd,true);
 const qi=o.querySelector('#bpq');qi.focus();qi.addEventListener('input',()=>{const v=qi.value.trim().toLowerCase();o.querySelectorAll('[data-bnote]').forEach(b=>b.hidden=!!v&&!b.dataset.txt.includes(v))});
 o.addEventListener('click',e=>{e.stopPropagation();if(e.target.closest('[data-bnew]')){close();hbAdd('note');return}const b=e.target.closest('[data-bnote]');if(b&&!b.disabled){close();B.items['note:'+b.dataset.bnote]=hbSpot(240);saveCfg();render();toast('Note added to the board · edits save to the note');return}if(e.target===o||e.target.closest('[data-bclose]'))close()})}
function hbPickImg(){const l=stRead('images');if(!l.length){toast('No images in Storage yet. Add some there first.');return}let o=$('bpick');if(o)o.remove();o=document.createElement('div');o.id='bpick';o.className='cfm';
 o.innerHTML=`<div class="cfmbox bpickbox" role="dialog" aria-modal="true" aria-label="Add an image"><h2>Add an image from Storage</h2><div class="bpickgrid">${l.map(x=>`<button data-batt="${esc(x.att)}" title="${esc(x.title)}"><img data-att="${esc(x.att)}" alt="${esc(x.title)}"></button>`).join('')}</div><div class="cfmbtns"><button class="g" data-bclose="1">Cancel</button></div></div>`;
 document.body.appendChild(o);hydrateImgs();if(CFG.lang==='es')i18nRun(o);const close=()=>{o.remove();document.removeEventListener('keydown',kd,true)},kd=e=>{if(e.key==='Escape'){e.preventDefault();e.stopPropagation();close()}};document.addEventListener('keydown',kd,true);
 o.addEventListener('click',e=>{e.stopPropagation();const b=e.target.closest('[data-batt]');if(b){close();hbAdd('img',b.dataset.batt);return}if(e.target===o||e.target.closest('[data-bclose]'))close()})}
// Saving what is typed in sticky notes and messages (half a second after typing stops; no re-render).
let hbT=null;
document.addEventListener('input',e=>{const t=e.target;if(!t.dataset)return;
 if(t.dataset.sticky!==undefined){const k=t.dataset.sticky;if(!FS[k])return;const n=readNote(FS[k]);FS[k]=writeNote({fm:n.fm,body:t.value});if(!t.closest('.fixh')){t.style.height='auto';t.style.height=t.scrollHeight+'px'}clearTimeout(hbT);hbT=setTimeout(()=>{save();hbFit()},500)}
 else if(t.dataset.bmsg!==undefined){const o=boardMsgs();o[t.dataset.bmsg]=t.value;boardMsgsWrite(o);if(!t.closest('.fixh')){t.style.height='auto';t.style.height=t.scrollHeight+'px'}clearTimeout(hbT);hbT=setTimeout(()=>{save();hbFit()},500)}});
// Moving and resizing board items with the pointer (small moves count as clicks).
let hbD=null;
document.addEventListener('pointerdown',e=>{if(e.button!==0)return;const it=e.target.closest&&e.target.closest('#hboard .bitem');if(!it)return;const B=HB(),bid=it.dataset.bid,p=B.items[bid];if(!p)return;
 const res=e.target.closest('.bres'),grip=e.target.closest('.bgrip');
 if(!res&&!grip&&e.target.closest('input,textarea,select,button,a,[data-act],[role="button"],[contenteditable="true"],.sclr'))return;
 p.z=++B.z;it.style.zIndex=p.z;hbD={it,bid,p,res:!!res,x:e.clientX,y:e.clientY,ox:p.x,oy:p.y,ow:p.w,oh:it.offsetHeight,on:false};if(res||grip)e.preventDefault()});
document.addEventListener('pointermove',e=>{if(!hbD)return;const dx=(e.clientX-hbD.x)/cz(),dy=(e.clientY-hbD.y)/cz();if(!hbD.on){if(Math.hypot(dx,dy)<5)return;hbD.on=true;document.body.classList.add('hbmoving');hbD.it.classList.add('moving')}
 const b=$('hboard'),bw=b?b.clientWidth:2000;
 if(hbD.res){const k=hbD.bid.split(':')[0],mw={card:240,img:80,note:140,msg:160}[k]||120,mh={card:120,img:60,note:100,msg:50}[k]||60;
  hbD.p.w=Math.round(Math.max(mw,Math.min(bw-hbD.p.x,hbD.ow+dx)));hbD.p.fh=Math.round(Math.max(mh,hbD.oh+dy));hbD.it.style.width=hbD.p.w+'px';hbD.it.style.height=hbD.p.fh+'px';hbD.it.classList.add('fixh');hbD.it.querySelectorAll('textarea').forEach(t=>{t.style.height=''});hbScale(hbD.it)}
 else{hbD.p.x=Math.round(Math.max(0,Math.min(bw-60,hbD.ox+dx)));hbD.p.y=Math.round(Math.max(0,hbD.oy+dy));hbD.it.style.left=hbD.p.x+'px';hbD.it.style.top=hbD.p.y+'px'}
 if(b){const need=hbD.it.offsetTop+hbD.it.offsetHeight+60;if(need>b.offsetHeight)b.style.height=need+'px'}});
document.addEventListener('pointerup',()=>{if(!hbD)return;const d=hbD;hbD=null;if(!d.on){saveCfg();return}document.body.classList.remove('hbmoving');d.it.classList.remove('moving');
 const sn=v=>Math.round(v/8)*8;if(d.res){d.p.w=sn(d.p.w);d.p.fh=sn(d.p.fh);d.it.style.height=d.p.fh+'px';hbScale(d.it)}else{d.p.x=sn(d.p.x);d.p.y=sn(d.p.y);d.it.style.left=d.p.x+'px';d.it.style.top=d.p.y+'px'}d.it.style.width=d.p.w+'px';d.p.h=d.it.offsetHeight;saveCfg();hbFit();
 const stop=ev=>{ev.stopPropagation();ev.preventDefault()};document.addEventListener('click',stop,{capture:true,once:true});setTimeout(()=>document.removeEventListener('click',stop,{capture:true}),50)});
document.addEventListener('dblclick',e=>{const rz=e.target.closest&&e.target.closest('#hboard .bres');if(rz){const it=rz.closest('.bitem'),p=HB().items[it.dataset.bid];if(p){delete p.fh;saveCfg();render()}return}
 const bx=e.target.closest&&e.target.closest('#hboard .bimg'),im=bx&&bx.querySelector('img');if(im){LB={set:[im.dataset.att],i:0};lbShow()}});
// Switching layouts: going to the board keeps every card where it was in the columns.
/* First visit to the Board: only Time & weather, Tasks and How are you feeling? (falling back to other useful cards when
   a section is off), scattered at random spots so it's clear cards can go anywhere. The rest wait in Customize. */
function hbFirst(){const B=HB(),g=document.querySelector('.hgrid'),W=Math.max(900,g?g.clientWidth:1100),avail=id=>homeDefs().some(x=>x[0]===id)&&(!homeSec(id)||secOn(homeSec(id)));
 const pick=['weather','tasks','mood','focus','habits','question','sounds'].filter(avail).slice(0,3),r=(a,b)=>Math.round(a+Math.random()*(b-a));
 CFG.boardOff=homeList().filter(id=>!pick.includes(id));const cw=Math.min(380,Math.round(W/3.4)),slots=[[.02,.1],[.36,.44],[.68,.74]].sort(()=>Math.random()-.5);
 pick.forEach((id,i)=>{const [a,b]=slots[i];B.items['card:'+id]={x:Math.min(W-cw-8,r(W*a,W*b)),y:r(16,170),w:cw,z:++B.z}});toast('Drag cards anywhere on the board. Bring back others from Customize Home')}
function homeLayoutSet(v){if((v==='board')===boardMode()&&CFG.homeLayout===(v==='board'?'board':'columns'))return;if(v==='board'&&!Array.isArray(CFG.boardOff)&&!Object.keys(HB().items).some(k=>k.startsWith('card:'))){hbFirst();CFG.homeLayout='board';homeEdit=false;saveCfg();render();return}
 if(v==='board'){const g=document.querySelector('.hgrid'),B=HB();if(g){const gr=g.getBoundingClientRect(),z=cz();g.querySelectorAll('section[data-dnd="home"]').forEach(sec=>{const id=sec.dataset.id,r=sec.getBoundingClientRect();if(!B.items['card:'+id])B.items['card:'+id]={x:Math.round((r.left-gr.left)/z),y:Math.round((r.top-gr.top)/z),w:Math.round(r.width/z),h:Math.round(r.height/z),z:1}})}}
 if(v==='board'&&!Array.isArray(CFG.boardOff))CFG.boardOff=[...(CFG.homeOff||[])];
 CFG.homeLayout=v==='board'?'board':'columns';homeEdit=false;saveCfg();render();toast(v==='board'?'Board layout · drag cards anywhere':'Column layout')}
// Right-click on a sticky note, message or image on the board.
const hbCtx=()=>{const bid=ctxK.slice(3),p=HB().items[bid];if(!p)return '';
 if(bid.startsWith('note:')){const k=bid.slice(5),c=FS[k]?readNote(FS[k]).fm.color||'yellow':'yellow',own=!STC[c]&&/^#[0-9a-f]{6}$/i.test(c)?c:'';return `<p class="ctxlab">Color</p><div class="ctxsw ctxsw8">${Object.entries(STC).map(([n,v])=>`<button class="lsw ${c===n?'on':''}" data-ctx="bnc" data-v="${n}" style="background:${v}" aria-label="${n}" aria-pressed="${c===n}"></button>`).join('')}${swCustom(own,`data-stickycolor="${esc(k)}"`,'lsw')}</div><button role="menuitem" data-ctx="bnopen">Open in Notes</button><hr class="ctxhr"><button role="menuitem" data-ctx="bremove">Remove from board</button><button role="menuitem" class="danger" data-ctx="bndel">Move to Trash…</button>`}
 if(bid.startsWith('img:'))return `<button role="menuitem" data-ctx="bimgview">View image</button><hr class="ctxhr"><button role="menuitem" class="danger" data-ctx="bremove">Remove from board</button>`;
 return `<button role="menuitem" class="danger" data-ctx="bremove">Delete message</button>`};
async function hbCtxAct(bid,a,v){const B=HB(),p=B.items[bid];closeCtx();if(!p)return;
 if(a==='bnc'){const k=bid.slice(5);if(FS[k]){const n=readNote(FS[k]);n.fm.color=v;FS[k]=writeNote(n);save();render()}return}
 if(a==='bnopen'){view='notes';nmode='notes';edN=bid.slice(5);ND=null;render();window.scrollTo(0,0);return}
 if(a==='bimgview'){LB={set:[p.att],i:0};lbShow();return}
 if(a==='bndel'){noteDel(bid.slice(5));return}
 if(a==='bremove'){if(bid.startsWith('msg:')){const o=boardMsgs();delete o[bid.slice(4)];boardMsgsWrite(o);save()}delete B.items[bid];saveCfg();render();toast(bid.startsWith('note:')?'Removed from the board · the note stays in Notes':bid.startsWith('msg:')?'Message deleted':'Image removed from the board')}}
/* Sounds (Home card), needs an internet connection:
   - Ambient: real field recordings streamed from Freesound. All are public domain (CC0); the high-quality MP3 previews
     loop, and they mix, each with its own volume (CFG.sounds = {rain: 0..1, …}).
   - Music: SomaFM, listener-supported radio, one station at a time (CFG.radio, CFG.radioVol) with what's playing now.
   CFG.sndVol is the master volume. Playback keeps going on other pages. */
const SNDS=[['rain','Rain','cloud-rain','🌧️','833/833924_15636277','bassimat'],['waves','Ocean waves','waves','🌊','615/615246_6371307','Fenodyrie'],
 ['wind','Wind','wind','💨','849/849302_10711943','Sandy-Ogilvie'],['fire','Fireplace','campfire','🔥','734/734248_2391840','yfjesse'],
 ['stream','Stream','drop','💧','722/722875_15675477','IceVFX'],['birds','Birds','bird','🐦','121/121965_78482','nfsgit'],
 ['thunder','Thunderstorm','cloud-lightning','⛈️','817/817640_664439','iscence'],['cafe','Café','coffee','☕','689/689957_2800886','Matias44']];
const STATIONS=[['fluid','Fluid','Instrumental hip-hop and lofi beats'],['groovesalad','Groove Salad','Chilled ambient and downtempo'],['dronezone','Drone Zone','Atmospheric ambient textures'],
 ['deepspaceone','Deep Space One','Deep ambient and space music'],['bossa','Bossa Beyond','Laid-back bossa nova'],['sonicuniverse','Sonic Universe','Eclectic, modern jazz']];
const SND={on:false,a:{},radio:null,ri:0,now:'',nowT:null,err:{}};
const sndVol=id=>Math.max(0,Math.min(1,+((CFG.sounds||{})[id]||0)));
const sndMaster=()=>CFG.sndVol==null?.8:+CFG.sndVol,curve=v=>Math.pow(v,1.6);
const sndUrl=id=>{const x=SNDS.find(s=>s[0]===id);return `https://cdn.freesound.org/previews/${x[4]}-hq.mp3`};
function sndErr(id,msg){SND.err[id]=msg;sndPaint()}
function sndStart(id){if(SND.a[id])return;const a=new Audio(sndUrl(id));a.loop=true;a.preload='auto';a.volume=0;SND.a[id]=a;delete SND.err[id];
 a.addEventListener('playing',()=>{delete SND.err[id];sndFade(a,curve(sndVol(id))*curve(sndMaster()));sndPaint()});
 a.addEventListener('error',()=>{sndErr(id,'Couldn’t load. Check your connection.');delete SND.a[id]});
 a.play().catch(()=>{});sndPaint()}
// Short volume fades so nothing starts or stops abruptly.
function sndFade(a,to,ms=600,done){clearInterval(a._f);const from=a.volume,st=Date.now();a._f=setInterval(()=>{const k=Math.min(1,(Date.now()-st)/ms);a.volume=Math.max(0,Math.min(1,from+(to-from)*k));if(k>=1){clearInterval(a._f);if(done)done()}},40)}
function sndStop(id){const a=SND.a[id];if(!a)return;delete SND.a[id];sndFade(a,0,500,()=>{a.pause();a.removeAttribute('src');a.load()})}
function sndLevel(id){if(!SND.on)return;const v=sndVol(id);if(v<=0){sndStop(id);return}const a=SND.a[id];if(!a){sndStart(id);return}clearInterval(a._f);a.volume=Math.min(1,curve(v)*curve(sndMaster()))}
// Radio: tries SomaFM's mirrors in turn if one fails.
const RMIR=['ice2','ice5','ice6'];
function radioStart(){const id=CFG.radio;radioStop(true);if(!id)return;SND.ri=0;const go=()=>{const a=new Audio(`https://${RMIR[SND.ri]}.somafm.com/${id}-128-mp3`);a.preload='none';a.volume=0;SND.radio=a;delete SND.err.radio;
  a.addEventListener('playing',()=>{delete SND.err.radio;sndFade(a,curve(CFG.radioVol==null?.6:+CFG.radioVol)*curve(sndMaster()),800);sndPaint()});
  a.addEventListener('error',()=>{if(SND.radio!==a)return;if(++SND.ri<RMIR.length)go();else{SND.radio=null;sndErr('radio','Couldn’t reach the station. Check your connection.')}});a.play().catch(()=>{})};go();radioNow();sndPaint()}
function radioStop(quick){const a=SND.radio;SND.radio=null;clearTimeout(SND.nowT);SND.now='';if(a)sndFade(a,0,quick?150:500,()=>{a.pause();a.removeAttribute('src');a.load()})}
// What's playing now on the station (refreshed every 30 seconds while it plays).
async function radioNow(){clearTimeout(SND.nowT);const id=CFG.radio;if(!SND.on||!id)return;try{const j=await (await fetch(`https://api.somafm.com/songs/${id}.json`)).json(),x=j.songs&&j.songs[0];SND.now=x?[x.artist,x.title].filter(Boolean).join(' – '):''}catch(e){SND.now=''}sndPaint();SND.nowT=setTimeout(radioNow,30000)}
function sndPlay(on){if(on){if(!SNDS.some(([id])=>sndVol(id)>0)&&!CFG.radio){CFG.sounds={...(CFG.sounds||{}),rain:.5};saveCfg()}SND.on=true;SNDS.forEach(([id])=>{if(sndVol(id)>0)sndStart(id)});if(CFG.radio)radioStart()}
 else{SND.on=false;Object.keys(SND.a).forEach(sndStop);radioStop()}sndPaint()}
function sndMasterSet(v){CFG.sndVol=v;sndSave();Object.entries(SND.a).forEach(([id,a])=>{clearInterval(a._f);a.volume=Math.min(1,curve(sndVol(id))*curve(v))});if(SND.radio){clearInterval(SND.radio._f);SND.radio.volume=Math.min(1,curve(CFG.radioVol==null?.6:+CFG.radioVol)*curve(v))}}
// Updates the card in place (no re-render) so sliders keep working while dragging.
function sndPaint(){mpPaint();document.querySelectorAll('.sndwrap').forEach(sndPaint1);if(CFG.radio&&SND.on)document.querySelectorAll('.mhsub').forEach(x=>x.textContent=SND.err.radio||SND.now||'')}
function sndPaint1(c){c.classList.toggle('playing',SND.on);const b=c.querySelector('[data-act="sndToggle"]');if(b){b.innerHTML=lineIco(SND.on?'M8 5v14M16 5v14':'M8 5.5v13l10.5-6.5z');b.setAttribute('aria-label',SND.on?'Pause sounds':'Play sounds');b.title=SND.on?'Pause':'Play'}
 c.querySelectorAll('[data-sndt]').forEach(t=>{const id=t.dataset.sndt,v=sndVol(id),a=SND.a[id];t.classList.toggle('on',v>0);t.classList.toggle('loading',!!(SND.on&&v>0&&(!a||a.paused||a.readyState<3)&&!SND.err[id]));t.classList.toggle('err',!!SND.err[id]);t.title=SND.err[id]||'';const r=t.querySelector('input');if(r&&document.activeElement!==r)r.value=Math.round(v*100);const bt=t.querySelector('.sndb');if(bt)bt.setAttribute('aria-pressed',String(v>0))});
 c.querySelectorAll('[data-station]').forEach(x=>{const on=CFG.radio===x.dataset.station;x.classList.toggle('on',on);x.setAttribute('aria-pressed',String(on))});
 const n=c.querySelector('.radnow');if(n)n.textContent=SND.err.radio||(CFG.radio&&SND.on?(SND.now?'Now playing: '+SND.now:(SND.radio&&!SND.radio.paused?'':'Connecting…')):'')}
const sndCard=()=>`<section class="sndcard sndwrap ${SND.on?'playing':''}"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Sounds</h2><span class="row" style="margin:0;gap:8px"><label class="sndmaster" title="Volume">${uiIco('speaker-high','🔊')}<input type="range" min="0" max="100" value="${Math.round(sndMaster()*100)}" data-sndm aria-label="Volume"></label><button class="sndplay" data-act="sndToggle" aria-label="${SND.on?'Pause sounds':'Play sounds'}" title="${SND.on?'Pause':'Play'}">${lineIco(SND.on?'M8 5v14M16 5v14':'M8 5.5v13l10.5-6.5z')}</button></span></div>
<p class="meta lab0 sndlab">Ambient</p><div class="sndgrid">${SNDS.map(([id,l,ic,em,,by])=>{const v=sndVol(id);return `<div class="sndt ${v>0?'on':''}" data-sndt="${id}"><button class="sndb" data-act="sndPick" data-val="${id}" aria-pressed="${v>0}" title="Recording by ${esc(by)} on Freesound (public domain)">${uiIco(ic,em)}<span>${l}</span></button><input type="range" min="0" max="100" value="${Math.round(v*100)}" data-snd="${id}" aria-label="${l} volume"></div>`}).join('')}</div>
<div class="radhead"><p class="meta lab0 sndlab">Music · radio</p><label class="sndmaster" title="Music volume">${uiIco('music-notes','🎵')}<input type="range" min="0" max="100" value="${Math.round((CFG.radioVol==null?.6:+CFG.radioVol)*100)}" data-radvol aria-label="Music volume"></label></div>
<div class="radlist">${STATIONS.map(([id,l,d])=>`<button class="radst ${CFG.radio===id?'on':''}" data-station="${id}" data-act="radPick" data-val="${id}" aria-pressed="${CFG.radio===id}" title="${esc(d)}"><b>${l}</b><span>${d}</span></button>`).join('')}</div><p class="meta radnow" data-notr></p>
<p class="meta sndhint">Needs an internet connection. Ambient recordings are public domain, from <a href="https://freesound.org" data-act="olink" data-v="https://freesound.org">Freesound</a>. Music by <a href="https://somafm.com" data-act="olink" data-v="https://somafm.com">SomaFM</a>, listener-supported radio: <a href="https://somafm.com/support/" data-act="olink" data-v="https://somafm.com/support/">support them</a>.</p></section>`;
let sndSaveT=null;const sndSave=()=>{clearTimeout(sndSaveT);sndSaveT=setTimeout(saveCfg,400)};
document.addEventListener('input',e=>{const t=e.target;if(!t.dataset)return;
 if(t.dataset.snd!==undefined){const id=t.dataset.snd;CFG.sounds={...(CFG.sounds||{}),[id]:t.value/100};sndSave();if(!SND.on&&t.value>0)sndPlay(true);else sndLevel(id);sndPaint();return}
 if(t.dataset.sndm!==undefined){sndMasterSet(t.value/100);return}
 if(t.dataset.radvol!==undefined){CFG.radioVol=t.value/100;sndSave();if(SND.radio){clearInterval(SND.radio._f);SND.radio.volume=Math.min(1,curve(CFG.radioVol)*curve(sndMaster()))}}});
/* Music section: what's playing, SomaFM stations as cards with their artwork, and the ambient mixer (same controls
   as the Home Sounds card, kept in sync by sndPaint). */
// Station logos (256 px) as listed in SomaFM's channels.json.
const START={fluid:'fluid256.jpg',groovesalad:'groovesalad256.png',dronezone:'dronezone256.png',deepspaceone:'deepspaceone256.png',bossa:'bossa256.jpg',sonicuniverse:'sonicuniverse256.png'};
const stArt=id=>`https://api.somafm.com/logos/256/${START[id]||id+'256.png'}`;
const mpNow=()=>{const st=STATIONS.find(x=>x[0]===CFG.radio),amb=SNDS.filter(([id])=>sndVol(id)>0).map(x=>x[1]);
 return{st,amb,title:st?st[1]:amb.length?'Ambient':'',sub:st?(SND.err.radio||(SND.on?(SND.now||'Connecting…'):'SomaFM')):amb.join(' · ')}};
V.music=()=>{const n=mpNow();
 const hero=`<section class="mhero sndwrap ${SND.on?'playing':''}"><span class="mhart">${n.st?`<img src="${stArt(n.st[0])}" alt="">`:uiIco('music-notes','🎵')}</span><div class="mhtxt"><span class="meta">${SND.on?'Now playing':n.title?'Paused':'Nothing playing'}</span><b data-notr>${esc(n.title||'Pick a station or a sound')}</b><span class="meta mhsub" data-notr>${esc(n.st?(SND.on?(SND.now||''):'SomaFM'):n.amb.join(' · '))}</span>${n.st&&n.amb.length?`<span class="meta" data-notr>+ ${esc(n.amb.join(' · '))}</span>`:''}</div>
<div class="mhctl"><label class="sndmaster" title="Volume">${uiIco('speaker-high','🔊')}<input type="range" min="0" max="100" value="${Math.round(sndMaster()*100)}" data-sndm aria-label="Volume"></label><button class="sndplay mhplay" data-act="sndToggle" aria-label="${SND.on?'Pause':'Play'}" title="${SND.on?'Pause':'Play'}">${lineIco(SND.on?'M8 5v14M16 5v14':'M8 5.5v13l10.5-6.5z')}</button></div></section>`;
 const radio=`<section class="sndwrap"><div class="radhead"><h2 style="margin:0">Radio</h2><label class="sndmaster" title="Music volume">${uiIco('music-notes','🎵')}<input type="range" min="0" max="100" value="${Math.round((CFG.radioVol==null?.6:+CFG.radioVol)*100)}" data-radvol aria-label="Music volume"></label></div>
<div class="mstations">${STATIONS.map(([id,l,d])=>`<button class="mst radst ${CFG.radio===id?'on':''}" data-station="${id}" data-act="radPick" data-val="${id}" aria-pressed="${CFG.radio===id}"><img src="${stArt(id)}" alt="" loading="lazy"><span><b>${l}</b><span>${d}</span></span><span class="mstbadge">${CFG.radio===id?(SND.on?'Playing':'Selected'):'Play'}</span></button>`).join('')}</div><p class="meta radnow" data-notr></p></section>`;
 const amb=`<section class="sndwrap"><h2>Ambient sounds</h2><p class="meta" style="margin:-4px 0 12px">Mix as many as you like, each with its own volume. They play together with the radio.</p><div class="sndgrid mgrid">${SNDS.map(([id,l,ic,em,,by])=>{const v=sndVol(id);return `<div class="sndt ${v>0?'on':''}" data-sndt="${id}"><button class="sndb" data-act="sndPick" data-val="${id}" aria-pressed="${v>0}" title="Recording by ${esc(by)} on Freesound (public domain)">${uiIco(ic,em)}<span>${l}</span></button><input type="range" min="0" max="100" value="${Math.round(v*100)}" data-snd="${id}" aria-label="${l} volume"></div>`}).join('')}</div></section>`;
 return `<h1>Music</h1><p class="sub">Radio and ambient sounds that keep playing while you use the rest of the app. Control them from the mini player.</p>${hero}${radio}${amb}
<p class="meta sndhint">Needs an internet connection. Ambient recordings are public domain, from <a href="https://freesound.org" data-act="olink" data-v="https://freesound.org">Freesound</a>. Music by <a href="https://somafm.com" data-act="olink" data-v="https://somafm.com">SomaFM</a>, listener-supported radio: <a href="https://somafm.com/support/" data-act="olink" data-v="https://somafm.com/support/">support them</a>.</p>`};
/* Mini player: pinned to the bottom of the sidebar (or the bottom of the screen with the top bar or on phones) while a
   station or sound is chosen. Play/pause, what's playing, and a click on the title opens Music. */
function mpPaint(){let m=$('mplayer');const n=mpNow(),show=!!n.title&&secOn('music')&&!PWLOCK&&!ONB;
 if(!show){if(m)m.remove();document.body.classList.remove('mpon');return}
 if(!m){m=document.createElement('div');m.id='mplayer';m.className='mplayer';document.body.appendChild(m)}
 document.body.classList.add('mpon');m.classList.toggle('playing',SND.on);
 const art=n.st?`<img src="${stArt(n.st[0])}" alt="">`:uiIco((SNDS.find(x=>x[1]===n.amb[0])||[])[2]||'music-notes','🎵');
 m.innerHTML=`<button class="mpart" data-act="nav" data-v="music" title="Open Music" aria-label="Open Music">${art}</button><button class="mptxt" data-act="nav" data-v="music" title="Open Music"><b data-notr>${esc(n.title)}</b><span data-notr>${esc(n.sub||'')}</span></button><button class="mpbtn" data-act="sndToggle" aria-label="${SND.on?'Pause':'Play'}" title="${SND.on?'Pause':'Play'}">${lineIco(SND.on?'M8 5v14M16 5v14':'M8 5.5v13l10.5-6.5z')}</button>`;
 if(CFG.lang==='es')i18nRun(m);mpPlace()}
// Follows the sidebar: its width in the side layouts, a small floating bar otherwise.
function mpPlace(){const m=$('mplayer'),nav=$('nav');if(!m||!nav)return;const r=nav.getBoundingClientRect(),side=CFG.navLayout!=='top'&&innerWidth>760&&r.height>innerHeight*.6&&r.width<innerWidth*.5;
 m.classList.toggle('mpside',side);if(side&&r.width>0&&!(CFG.navAuto&&r.left<-10)){m.style.left=(r.left+10)+'px';m.style.width=Math.max(150,r.width-20)+'px';m.style.display=''}else if(side){m.style.display='none'}else{m.style.left='';m.style.width='';m.style.display=''}}
window.addEventListener('resize',()=>mpPlace());
/* Home greeting: one of the 10 for this hour (greetings.js). Each hour has its own shuffled order of its 10 greetings,
   and every day moves 3 places along it: the message stays put for the hour, differs from the one shown at the same
   hour the day before, and all 10 come round within 10 days. */
const greetHash=x=>{let h=2166136261;for(const c of x){h^=c.charCodeAt(0);h=Math.imul(h,16777619)}return h>>>0};
function greetPick(){const d=new Date(),hr=d.getHours(),t=TD(),L=(typeof GREET!=='undefined'&&GREET[CFG.lang==='es'?'es':'en'])||null;
 if(!L)return (hr<12?'Good morning':hr<18?'Good afternoon':'Good evening')+(CFG.name?', '+CFG.name:'');
 const ord=[...Array(10).keys()].sort((x,z)=>greetHash(hr+':'+x)-greetHash(hr+':'+z)),day=Math.round(pd(t).getTime()/864e5);
 return L[hr][ord[(day*3)%10]].replace('{n}',CFG.name?', '+CFG.name:'')}
V.today=()=>{const t=TD(),hr=new Date().getHours(),g=greetPick(),T=secOn('tasks')?tasks():[],E=events(),
 open=T.filter(x=>!x.done).sort((a,b)=>(a.due||'9')<(b.due||'9')?-1:1),dueN=open.filter(x=>x.due&&x.due<=t).length,
 dot=c=>`<span class="dot" style="background:var(${c});margin-top:6px"></span>`,
 card=(title,link,body)=>`<section><div class="head" style="margin:0 0 8px"><h2 style="margin:0">${title}</h2>${link?`<button class="x" data-act="nav" data-v="${link}">View all</button>`:''}</div>${body}</section>`,C={};
 C.mood=writeBox();
 C.weather=wxCard();
 C.shortcuts=shortCard();
 C.sounds=sndCard();
 C.question=qBox();
 C.tasks=card(`Tasks · ${dueN} due`,'tasks',`<div class="row" style="margin:0 0 8px"><input id="tt" placeholder="Add a task" aria-label="Add a task"><button class="b tick" data-act="addT" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>${open.slice(0,6).map(taskRow).join('')||'<p class="empty">No open tasks.</p>'}${open.length>6?`<p class="meta" style="margin:8px 0 0">+${open.length-6} more</p>`:''}`);
 const hs=habits();
 C.habits=card('Habits today','habits',chainStrip(t,1)+hs.map(x=>habitItem(x,t)).join('')||'<p class="empty">No habits yet. Add one in Habits.</p>');
 // tasks have their own Home card, so Coming up lists them only when that card is hidden (no duplicates)
 const tasksOnHome=secOn('tasks')&&!homeOff().includes('tasks');
 const up=[0,1,2,3,4,5,6].map(i=>dAdd(t,i)).map(d=>({d,items:[...evOn(E,d).sort(evSort).map(e=>['--am',(e.start?evTime(e)+' · ':'')+e.title]),...(tasksOnHome?[]:open.filter(x=>x.due===d).map(x=>['--ac',x.title])),...(tasksOnHome?[]:open.filter(x=>x.rem&&x.rem.slice(0,10)===d&&x.due!==d).map(x=>['--ac',x.title+' · reminder '+tf(x.rem.slice(11))]))]})).filter(x=>x.items.length);
 C.coming=card('Coming up','calendar',up.map(x=>`<p class="meta" style="margin:10px 0 2px;font-weight:700">${x.d===t?'Today':x.d===dAdd(t,1)?'Tomorrow':fmt(x.d)}</p>`+x.items.map(([c,s])=>`<div class="item" style="padding:4px 0;border:0">${dot(c)}<div class="t">${esc(s)}</div></div>`).join('')).join('')||'<p class="empty">Nothing scheduled in the next 7 days.</p>');
 const ps=projects().filter(p=>p.status!=='done').slice(0,5),AT=tasks();
 C.projects=card('Projects','projects',ps.map(p=>{const ts=AT.filter(x=>x.proj===p.id),dn=ts.filter(x=>x.done).length;
  return `<div class="item" style="display:block"><div class="head" style="margin:0"><b>${esc(p.name)}</b><button class="x" data-act="openPj" data-k="${esc(p.id)}">Open</button></div><div class="bar"><i style="width:${ts.length?Math.round(dn/ts.length*100):0}%;background:${vivid(pColor(p))}"></i></div><span class="meta">${ts.length-dn} open · ${dn} done · ${p.notes.filter(k=>FS[k]&&!isArch(k)).length} notes</span>${(m=>m?`<span class="meta hcms">${lineIco('M5 21V4M5 4h11l-2 4 2 4H5')}<span><span data-notr>${esc(m.t)}</span> · ${(dd2=>dd2===0?'today':dd2>0?`in ${dd2} day${dd2===1?'':'s'}`:`${-dd2} day${dd2===-1?'':'s'} late`)(Math.round((pd(m.d)-pd(t))/864e5))}</span></span>`:'')((p.ms||[]).filter(x=>!x.done).sort((a,b)=>a.d.localeCompare(b.d))[0])}</div>`}).join('')||'<p class="empty">No active projects.</p>');
 const nk=byDate(keys('notes/')),nn=[...nk.filter(isPinned),...nk.filter(k=>!isPinned(k))].slice(0,4);
 C.notes=card('Notes','notes',`<button class="g hcdaily" data-act="dailyGo" data-d="${t}">${symbols()?sym('calendar-check'):'📅'}${dailyKey(t)?'Open today’s note':'Start today’s note'}</button>`+nn.map(k=>{const l=noteLines(k).map(wlPlain);return `<div class="item" style="display:block"><div class="head" style="margin:0"><b>${esc((l[0]||'Untitled').replace(/^#+\s*/,''))}</b><button class="x" data-act="openN" data-k="${esc(k)}">Open</button></div>${l.length>1?`<p class="meta" style="margin:2px 0 0">${esc(l.slice(1).join(' ').slice(0,90))}</p>`:''}</div>`}).join('')||'<p class="empty">No notes yet.</p>');
 const mv=[6,5,4,3,2,1,0].map(i=>getMood(dAdd(t,-i))),mm=mv.filter(Boolean),wk=dAdd(t,-6);
 const st=jStreak();
 // Collection items being read, watched or played, as small covers.
 const ip=colKeys().map(colRead).filter(x=>x.status==='doing').sort((a,b)=>(b.started||'').localeCompare(a.started||'')||alpha(a.title,b.title));
 C.collections=`<section><div class="head" style="margin:0 0 8px"><h2 style="margin:0">In progress</h2><span class="row" style="margin:0;gap:6px"><button class="cx rbtn ${ipAdd?'on':''}" data-act="ipAddT" aria-label="Add something you’re reading, watching or playing" title="Add to In progress">${lineIco(ipAdd?'M6 6l12 12M18 6L6 18':'M12 5v14M5 12h14')}</button><button class="x" data-act="col:inprog">View all</button></span></div>${ipAdd?ipFinder():''}${ip.length?`<div class="minis">${ip.slice(0,8).map(colMini).join('')}</div>${ip.length>8?`<p class="meta" style="margin:8px 0 0">+${ip.length-8} more</p>`:''}`:colSuggest()}${colGoalMini()}</section>`;
 (CFG.colCards||[]).forEach(c=>{const its=ccItems(c),n=+c.limit||8;C['cc:'+c.id]=`<section><div class="head" style="margin:0 0 8px"><h2 style="margin:0" data-notr>${esc(ccTitle(c))}</h2><button class="x" data-act="ccView" data-id="${esc(c.id)}">View all</button></div>${its.length?`<div class="minis">${its.slice(0,n).map(colMini).join('')}</div>${its.length>n?`<p class="meta" style="margin:8px 0 0">+${its.length-n} more</p>`:''}`:'<p class="empty">Nothing here yet.</p>'}</section>`});
 (CFG.taskCards||[]).forEach(c=>{const its=tcItems(c),n=+c.limit||6,l=getList(c.list||'all'),sv=curList;curList=c.list;
  const add=c.add!==false&&c.list!=='completed'?`<div class="row" style="margin:0 0 8px"><input data-tca="${esc(c.id)}" placeholder="Add a task" aria-label="Add a task to ${esc(l.name)}"><button class="b tick" data-act="tcAdd" data-id="${esc(c.id)}" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>`:'';
  C['tc:'+c.id]=`<section style="--tc:${vivid(l.color)}"><div class="head" style="margin:0 0 8px"><h2 style="margin:0" class="tchead"><span class="lri" style="background:${vivid(l.color)}">${lIcon(l)}</span><span data-notr>${esc(tcTitle(c))}</span></h2><button class="x" data-act="tcView" data-id="${esc(c.id)}">View all</button></div>${add}${its.slice(0,n).map(taskRow).join('')||`<p class="empty">${c.when&&c.when!=='any'?'No tasks match.':'No open tasks.'}</p>`}${its.length>n?`<p class="meta" style="margin:8px 0 0">+${its.length-n} more</p>`:''}</section>`;curList=sv});
 C.focus=focusBar()||'<section><h2>Focus session</h2><p class="empty">Turn on Tasks to pick daily priorities.</p></section>';
 C.recap=recapCard();
 C.timers=tmCard();
 C.meditate=(()=>{const busy=MT.run||MT.left<MT.dur,dm=Math.round(MT.dur/60),ws=weekStart(t);return `<section class="medcard"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">Meditation</h2><button class="x" data-act="goSub" data-v="health" data-sub="meditation">View all</button></div><div class="medstats"><div><b>${medFmt(medTotal(t))}</b><span class="meta">today</span></div><div><b>${medStreak()}</b><span class="meta">day streak</span></div><div><b>${medFmt(medDays().filter(d=>d>=ws).reduce((a,d)=>a+medTotal(d),0))}</b><span class="meta">this week</span></div></div>${busy?`<div class="row" style="margin:10px 0 0"><button class="b medgo" data-act="medFsOpen">${lineIco('M8 5.5v13l10.5-6.5z')}${MT.run?'Back to session':'Resume'} · ${mClock(MT.left)}</button></div>`:`<p class="meta tmlab0 medlab0">Length · minutes</p><div class="medpick">${[3,5,10,15,20,30].map(m=>`<button data-act="medDur" data-val="${m}" class="${dm===m?'on':''}" aria-pressed="${dm===m}">${m}</button>`).join('')}</div><button class="b medgo" data-act="medFsStart">${lineIco('M8 5.5v13l10.5-6.5z')}Start ${dm} min</button>`}</section>`})();
 C.otd=onThisDay()||'<section><h2>On this day</h2><p class="empty">Nothing written 1 month, 6 months or 1 year ago today yet. Keep journaling and memories show up here.</p></section>';
 C.readlater=(()=>{const l=stRead('links').filter(x=>x.later);return `<section><div class="head" style="margin:0 0 8px"><h2 class="h2i" style="margin:0">${uiIco('bookmark-simple','🔖')}Read later <span class="meta">${l.length}</span></h2>${l.length?`<button class="x" data-act="goSub" data-v="files" data-sub="links" data-later="1">View all</button>`:''}</div>${l.length?l.slice(0,5).map(x=>`<div class="rlrow">${stFavicon(x)}<button class="rlt" data-act="stOpen" data-val="${esc(x.url)}" title="${esc(x.url)}"><b data-notr>${esc(x.title)}</b><span class="meta" data-notr>${esc(host(x.url))}</span></button><button class="cx rbtn" data-act="rlDone" data-val="${esc(x.url)}" aria-label="Mark as read" title="Mark as read">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>`).join(''):'<p class="empty">Nothing to read. Right-click a link in Storage and choose Read later.</p>'}</section>`})();
 C.body=(()=>{const l=bodyRead(),td2=l.find(x=>x.d===t)||{},last=k=>[...l].reverse().find(x=>x[k]!=null);return `<section><div class="head" style="margin:0 0 8px"><h2 style="margin:0">Body</h2><button class="x" data-act="goSub" data-v="health" data-sub="body">Log</button></div><div class="bodymini">${BODYF.map(([k,lab,u,col])=>{const x=last(k),vals=l.slice(-14).map(y=>y[k]!=null?y[k]:null);return `<div style="--bc:${col}"><span class="meta">${lab}${td2[k]!=null?' · today':''}</span><b>${x?+x[k].toFixed(1):'–'} <small>${u}</small></b>${vals.filter(v=>v!=null).length>1?spark(vals,col,120,28):''}</div>`}).join('')}</div></section>`})();
 C.week=card('This week','insights',`<div class="hs" style="margin-top:0">${mv.map(m=>`<span class="hd" ${m?`style="background:var(${MOOD[m-1][1]})"`:''}></span>`).join('')}</div><div class="stats"><div><b>${mm.length?(mm.reduce((a,b)=>a+b,0)/mm.length).toFixed(1):'–'}</b><span class="meta">Avg mood</span></div><div><b>${st}</b><span class="meta">Journal streak</span></div><div><b>${AT.filter(x=>x.done&&x.doneOn>=wk).length}</b><span class="meta">Tasks done</span></div><div><b>${Math.max(0,...hs.map(x=>hStats(x).streak))}</b><span class="meta">Best habit streak</span></div></div>`);
 const avail=id=>(!homeSec(id)||secOn(homeSec(id)))&&(id!=='question'||CFG.prompts),
  shown=homeList().filter(id=>avail(id)&&!homeOff().includes(id)),
  hidden=homeList().filter(id=>avail(id)&&homeOff().includes(id)),lab=id=>homeDefs().find(x=>x[0]===id)[1],
  wrap=id=>C[id].replace(/^<section([^>]*)>/,(m,a)=>`<section${hcAttrs(a,id)} data-dnd="home" data-id="${id}">`+(homeEdit?`<div class="hbar"><span class="meta">⠿ Drag to move</span><span><button class="x hccol" data-act="hcColor" data-id="${esc(id)}" title="Card color"><span class="dot" style="background:${hcColor(id)}"></span>Color</button>${id.startsWith('cc:')||id.startsWith('tc:')?`<button class="x" data-act="${id[0]}cEdit" data-id="${esc(id.slice(3))}">Edit</button>`:''}<button class="x" data-act="tgl" data-g="home" data-id="${id}">Hide</button></span></div>`:''));
 return `<div class="head" style="margin:0 0 4px;align-items:flex-start"><div><h1 data-notr>${esc(g)}</h1><p class="sub">${fmt(t,{weekday:'long',month:'long',day:'numeric'})}</p></div><span class="row" style="margin:0;gap:8px">${availW()>=700?`<div class="moods seg hlay" role="group" aria-label="Home layout">${[['columns','Columns','M4 4h7v16H4zM13 4h7v16h-7z','Cards in columns'],['board','Board','M4 4h7v9H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 15h7v5H4z','Put cards, notes and images anywhere']].map(([v,l,ic,tt])=>{const on=(boardMode()?'board':'columns')===v;return `<button data-act="homeLayout" data-val="${v}" class="${on?'on':''}" aria-pressed="${on}" title="${tt}">${lineIco(ic)}${l}</button>`}).join('')}</div>`:''}<button class="circ${homeEdit?' on':''}" data-act="homeEdit" aria-pressed="${homeEdit}" aria-label="${homeEdit?'Done':'Customize Home'}" title="${homeEdit?'Done':'Customize Home'}">${homeEdit?lineIco('M5 12.5l4.5 4.5L19 7'):lineIco('M4 7h9M19 7h1M4 17h1M11 17h9M14 7a2 2 0 1 0 4 0a2 2 0 1 0-4 0M5 17a2 2 0 1 0 4 0a2 2 0 1 0-4 0')}</button></span></div>
${searchBar()}${hq.trim()?`<div id="hres" class="hres">${homeResults()}</div>`:`${homeEdit&&!boardMode()?`<div class="hfixrow">${swRow('Keep cards in the column you put them','homeFixed',!!CFG.homeFixed)}</div>`:''}${homeEdit?ccPanel():''}${homeEdit&&hidden.length?`<p class="meta" style="margin:0 0 6px">Hidden cards. Click to bring one back:</p><div class="moods seg" style="margin-bottom:14px">${hidden.map(id=>`<button data-act="tgl" data-g="home" data-id="${id}">+ ${lab(id)}</button>`).join('')}</div>`:''}
${!homeEdit&&focusHides()?`<div class="fmfocus">${wrap('focus')}<p class="meta fmhint">Focus mode is on. The other cards come back when your focus tasks are done.</p></div>`:(boardMode()?hbView(shown,wrap):`<div class="hgrid">${shown.map(wrap).join('')||'<p class="empty">All cards are hidden. Click Customize to bring some back.</p>'}</div>`)}`}`};
/* Notes: "cards" shows a grid of notes; "panel" shows a vertical list with the open note beside it.
   Either can be sorted by date created (newest first) or alphabetically by title. */
/* Archive: archiving moves notes/<name>.md to archive/<name>.md (and back), keeping project links pointing at it. */
/* Notes has five views: notes, categories, tags, templates and archived notes. */
let nmode='notes',selCat=null,tagF=null,ND=null,tplSel=null,addProp=false,pendingFocus=null,npT='text',npNameDraft='';
const isArch=k=>k.startsWith('archive/');
function archiveNote(k){const base=k.replace(/^[^/]+\//,'').slice(0,-3),dir=isArch(k)?'notes/':'archive/';let nk=dir+base+'.md',n=2;
 while(FS[nk])nk=dir+base+'-'+n+++'.md';
 FS[nk]=FS[k];delete FS[k];projects().forEach(p=>{const i=p.notes.indexOf(k);if(i>=0){p.notes[i]=nk;putP(p)}});
 if(edN===k)edN=null;return nk}
const isTplKey=k=>k.startsWith('templates/');
const tplName=k=>k.slice(10,-3);
// Notes without a first line show their creation time, like Obsidian's default note names ("2026-10-20 00.52").
const noteTitle=k=>{if(isJE(k)&&FS[k]){const e=jeRead(k),h=(e.body.match(/^#\s+(.+)$/m)||[])[1];return h||`Journal · ${fmt(e.date)}${e.time?' '+e.time:''}`}const l=noteLines(k)[0];if(l)return l.replace(/^#+\s*/,'');const m=k.match(/(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})/);return m?`${m[1]} ${m[2]}.${m[3]}`:k.replace(/^[^/]+\//,'').slice(0,-3).replace(/ \d{4}-\d{2}-\d{2}( \d+)?$/,'')};
// The created property, else a date in the file name.
const noteDate=k=>{const c=FS[k]&&readNote(FS[k]).fm.created;if(/^\d{4}-\d{2}-\d{2}/.test(c||''))return String(c).slice(0,10);return (k.match(/(\d{4}-\d{2}-\d{2})/)||[])[1]||''};
const byDate=ks=>ks.slice().sort((a,b)=>noteDate(b).localeCompare(noteDate(a))||alpha(noteTitle(a),noteTitle(b)));
const alpha=(a,b)=>a.localeCompare(b,undefined,{sensitivity:'base',numeric:true});
const sortNotes=ks=>CFG.notesSort==='alpha'?ks.slice().sort((a,b)=>alpha(noteTitle(a),noteTitle(b))):byDate(ks);
// Categories and tags across all notes (not archived ones), grouped ignoring upper/lower case.
// Base note categories, always offered even before any note uses them: [name, symbol, emoji].
const BASECATS=[['Article','article','📰'],['Blog','pen-nib','📝'],['Books','books','📚'],['Brain Dump','brain','🧠'],['Chess','horse','♟️'],['Collections','stack','🗂️'],['CS50','graduation-cap','🎓'],['Empty category','folder-simple-dashed','📁'],['Finances','wallet','💰'],['Gaming','game-controller','🎮'],['Gym','barbell','🏋️'],['Health','heartbeat','❤️'],['Hobbies','palette','🎨'],['Homelab','hard-drives','🖥️'],['Ideas','lightbulb','💡'],['Inbox','tray','📥'],['Item','package','📦'],['Journaling','notebook','📓'],['Links','link','🔗'],['Linux','terminal-window','🐧'],['Makes me grow','plant','🌱'],['Music','music-notes','🎵'],['People','users','👥'],['Podcast','microphone','🎙️'],['Programming','code','💻'],['Quillpad notes','feather','🪶'],['Review','star','⭐'],['Storage','database','🗄️'],['Tech','cpu','🔌'],['Tech I own','devices','📱'],['Templates','copy','📋'],['Video','video-camera','🎬'],['Youtube Videos - Gaalpos','play-circle','▶️']];
// Saved categories (CFG.cats: {name, sym, emoji}) start as BASECATS; they can be created, edited and deleted.
// Journal categories are a separate set (CFG.jcats), used the same way on the journal's day files.
const JBASECATS=[['Gratitude','hands-praying','🙏'],['Work','briefcase','💼'],['Family','users-three','👨‍👩‍👧'],['Friends','users','👥'],['Love','heart','❤️'],['Health','heartbeat','🩺'],['Fitness','barbell','🏋️'],['Mood','smiley','🙂'],['Stress','cloud-lightning','⛈️'],['Dreams','moon-stars','🌙'],
 ['Ideas','lightbulb','💡'],['Goals','target','🎯'],['Reflection','sparkle','✨'],['Travel','airplane','✈️'],['Learning','graduation-cap','🎓'],['Money','wallet','💰'],['Hobbies','palette','🎨'],['Food','fork-knife','🍽️'],['Home','house','🏠'],['Memories','camera','📷'],['Spirituality','flower-lotus','🪷']];
function catList(sc='notes'){const k=sc==='journal'?'jcats':'cats',b=sc==='journal'?JBASECATS:BASECATS;if(!Array.isArray(CFG[k]))CFG[k]=b.map(([name,sym,emoji])=>({name,sym,emoji}));
 // base categories added in later versions reach existing setups once (a deleted one is not brought back)
 if(sc==='journal'&&!(CFG.jcatsAdded||[]).includes('Spirituality')){if(!CFG[k].some(x=>x.name.toLowerCase()==='spirituality'))CFG[k].push({name:'Spirituality',sym:'flower-lotus',emoji:'🪷'});CFG.jcatsAdded=[...(CFG.jcatsAdded||[]),'Spirituality'];saveCfg()}
 return CFG[k]}
const catFiles=sc=>sc==='journal'?keys('journal/'):keys('notes/');
const catBase=(c,sc)=>{const f=String(c).toLowerCase();return catList(sc).find(b=>b.name.toLowerCase()===f)};
const catIco=(c,sc)=>{const b=catBase(c,sc);return symbols()?sym(b&&b.sym||'folder'):esc(b&&b.emoji||'📁')};
// All categories: the saved ones plus any used in notes, with the notes in each.
const allCats=(sc='notes')=>{const ix=sc==='journal'?propIndexOf(keys('journal/'),'categories'):propIndex('categories');for(const b of catList(sc))if(!ix.has(b.name.toLowerCase()))ix.set(b.name.toLowerCase(),{name:b.name,keys:[]});return ix};
// Renames (to) or removes (to null) a category in every note and template.
function catRewrite(from,to,sc='notes'){const f=from.toLowerCase();for(const k of sc==='journal'?keys('journal/'):[...keys('notes/'),...keys('templates/')]){const n=readNote(FS[k]),c=n.fm.categories;
 if(!Array.isArray(c)||!c.some(x=>x.toLowerCase()===f))continue;n.fm.categories=to?[...new Set(c.map(x=>x.toLowerCase()===f?to:x))]:c.filter(x=>x.toLowerCase()!==f);FS[k]=writeNote(n)}ND=null}
function catDelete(name,sc='notes'){const f=name.toLowerCase();CFG[sc==='journal'?'jcats':'cats']=catList(sc).filter(x=>x.name.toLowerCase()!==f);saveCfg();catRewrite(name,null,sc);if(sc==='journal'){if(jCatF&&jCatF.toLowerCase()===f)jCatF=null}else if(selCat&&selCat.toLowerCase()===f)selCat=null;if(catEd&&catEd.orig&&catEd.orig.toLowerCase()===f)catEd=null}
// The category editor (new or existing): catEd = {orig, name, sym, emoji}.
let catEd=null;
function catSave(){const e=catEd,sc=e.sc||'notes',name=e.name.trim().replace(/[\[\]|]/g,'').trim();if(!name){toast('Give the category a name');return false}
 const low=name.toLowerCase(),same=e.orig&&e.orig.toLowerCase()===low;if(!same&&allCats(sc).has(low)){toast(`“${name}” already exists`);return false}
 const l=catList(sc),i=e.orig?l.findIndex(x=>x.name.toLowerCase()===e.orig.toLowerCase()):-1,ent={name,sym:e.sym||'folder',emoji:e.emoji||'📁'};
 if(i>=0)l[i]=ent;else l.push(ent);CFG[sc==='journal'?'jcats':'cats']=[...l];saveCfg();
 if(e.orig&&e.orig!==name){catRewrite(e.orig,name,sc);if(sc==='journal'){if(jCatF&&jCatF.toLowerCase()===e.orig.toLowerCase())jCatF=name}else if(selCat&&selCat.toLowerCase()===e.orig.toLowerCase())selCat=name}
 catEd=null;return true}
const catEditor=()=>{const e=catEd;return `<section class="cated"><h2>${e.orig?'Edit category':'New category'}</h2>
<div class="row" style="margin:0;align-items:center"><button class="cathi catico" data-act="icoPick" data-id="catedit" aria-label="Choose icon" title="Choose icon">${symbols()?sym(e.sym||'folder'):esc(e.emoji||'📁')}</button><input id="catname" value="${esc(e.name)}" placeholder="Category name" aria-label="Category name" autocomplete="off" style="flex:1"><button class="b" data-act="catSave">${e.orig?'Save':'Create category'}</button><button class="g" data-act="catCancel">Cancel</button></div>
${(c=>c&&c.keys.length?`<p class="meta" style="margin:8px 0 0">Renaming updates the ${c.keys.length} ${e.sc==='journal'?'day':'note'}(s) in this category.</p>`:'')(e.orig&&allCats(e.sc).get(e.orig.toLowerCase()))}
${icoPick==='catedit'?picker('catedit',e.emoji||''):''}</section>`};
// A category as a neutral tile (like the Collections tiles, without color); count is optional.
const catTile=(name,n,small,sc,on)=>`<button class="ntab cattile ${small?'sm':''} ${on?'on':''}" data-act="${sc==='journal'?'jCat':'openCat'}" data-v="${esc(name)}" data-cat="${esc(name)}"${sc==='journal'?' data-csc="journal"':''}${on!==undefined?` aria-pressed="${!!on}"`:''}><span class="nti">${catIco(name,sc)}</span><span class="ntl">${esc(name)}</span>${n===undefined?'':`<span class="ntc">${n}</span>`}</button>`;
function propIndexOf(ks,p){const m=new Map();for(const k of ks)for(const c of readNote(FS[k]).fm[p]||[]){const id=c.toLowerCase();if(!m.has(id))m.set(id,{name:c,keys:[]});m.get(id).keys.push(k)}return m}
function propIndex(p){const m=new Map();for(const k of keys('notes/'))for(const c of readNote(FS[k]).fm[p]||[]){const id=c.toLowerCase();if(!m.has(id))m.set(id,{name:c,keys:[]});m.get(id).keys.push(k)}return m}
// Notes views, shown as small tiles in the same style as the section cards: [id, label, symbol, emoji, color, count].
const nmodes=()=>[['notes','Notes','note','📝','#d4a43a',keys('notes/').length],['categories','Categories','squares-four','🗂️','#6f7fb0',allCats().size],
 ['tags','Tags','tag','🏷️','#5fa57f',propIndex('tags').size],['templates','Templates','copy','📋','#9a7fd0',keys('templates/').length],['archive','Archived','archive','📦','#7a8794',keys('archive/').length],['trash','Trash','trash','🗑️','#a07870',keys('trash/').length]];
// Tile bar used by Notes, Journal and Collections. items: [id, label, symbol, emoji, color, count]; act is the click action;
// with dnd, tiles other than "all" can be dragged to reorder (drag group dnd).
const tileBar=(act,cur,items,dnd)=>`<div class="ntabs" role="tablist">${items.map(([v,t,ic,em,c,n])=>`<button class="ntab ${cur===v?'on':''}" role="tab" aria-selected="${cur===v}" data-act="${act}" data-val="${v}" style="--tc:${vivid(c)}"${dnd&&v!=='all'?` data-dnd="${dnd}" data-id="${v}" title="Drag to reorder"`:''}><span class="nti">${symbols()?sym(ic):em}</span><span class="ntl">${t}</span><span class="ntc">${n}</span></button>`).join('')}</div>`;
const notesBar=()=>tileBar('nmode',nmode,nmodes());

/* The note being edited is held as a draft (ND) so property changes survive re-renders until Save.
   New notes start from the chosen template, or the default template, with {{date}} and {{time}} filled in. */
function fromTpl(k){if(!k||!FS[k])return{k:null,fm:{created:TD()},body:'',tpl:''};
 const n=readNote(FS[k]),sub=v=>String(v).replace(/\{\{date\}\}/g,TD()).replace(/\{\{time\}\}/g,hm(':')).replace(/\{\{title\}\}/g,'');
 const fm={};for(const [p,v] of Object.entries(n.fm))fm[p]=Array.isArray(v)?v.map(sub):sub(v);return{k:null,fm,body:sub(n.body),tpl:k}}
// The title field edits the note's first "# " heading; the text box holds everything after it.
const splitTitle=n=>{const m=n.body.match(/^\s*#[ \t]+(.*)(?:\n|$)/);if(m){n.title=m[1].trim();n.body=n.body.slice(m[0].length).replace(/^\n+/,'')}else n.title='';return n};
const joinTitle=n=>{const t=(n.title||'').trim();return t?`# ${t}\n\n${n.body}`:n.body};
const draft=()=>{if(!ND||ND.k!==(edN||null)){ND=splitTitle(edN?{k:edN,...readNote(FS[edN])}:fromTpl(tplSel===null?CFG.defaultTpl:tplSel));
 if(!edN&&view==='notes'&&nmode==='categories'&&selCat){const c=(allCats().get(selCat.toLowerCase())||{name:selCat}).name,cur=ND.fm.categories||[];if(!cur.some(x=>x.toLowerCase()===c.toLowerCase()))ND.fm={...ND.fm,categories:[...cur,c]}}
 HIST={stack:[snap()],i:0}}return ND};
/* Autosave and undo/redo for the note editor.
   Every change is saved on its own: typing ~0.6 s after the last keystroke, clicks (chips, properties) straight away.
   A new note gets its file on the first change, so opening "New note" and leaving creates nothing.
   HIST holds snapshots of title, text and properties; typing is grouped into one step per pause. */
let HIST={stack:[],i:0},noteTimer=null;
const snap=()=>JSON.stringify({t:ND.title||'',b:ND.body,f:ND.fm});
function commitHist(){if(!ND)return;const x=snap();if(x===HIST.stack[HIST.i])return;HIST.stack=HIST.stack.slice(0,HIST.i+1);HIST.stack.push(x);if(HIST.stack.length>200)HIST.stack.shift();HIST.i=HIST.stack.length-1;histBtns()}
// Keeps the toolbar's undo / redo buttons enabled only when there is something to undo or redo.
const histBtns=()=>{const u=document.querySelector('.mdbar [data-act="undoN"]'),r=document.querySelector('.mdbar [data-act="redoN"]');if(u)u.disabled=!(HIST.i>0);if(r)r.disabled=!(HIST.i<HIST.stack.length-1)};
// After a note is renamed, links to its old title point to the new one ([[Old]] and [[Old|text]]).
function wlRename(ot,nt,self){if(!ot||!nt||fold(ot)===fold(nt))return;const re=new RegExp('\\[\\[\\s*'+ot.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*(\\|[^\\]\\n]*)?\\]\\]','gi');
 [...keys('notes/'),...entKeys()].forEach(k=>{if(k===self||!FS[k])return;const o=FS[k],n=o.replace(re,(_,a)=>`[[${nt}${a||''}]]`);if(n!==o)FS[k]=n});WLC=null}
/* Version history: before a note is overwritten, its previous text is kept as history/<note path>/<YYYY-MM-DD HH-MM>.md
   (at most one version per 10 minutes, the newest 40 per note). History panel: compare any version and restore it. */
const histDir=k=>'history/'+k.replace(/\.md$/,'')+'/';
const histKeys=k=>keys(histDir(k)).sort().reverse();
function histSnap(k,prev){if(!k||!prev||isTplKey(k))return;const ks=histKeys(k),last=ks[0],now=new Date(),st=`${TD()} ${pad(now.getHours())}-${pad(now.getMinutes())}`;
 if(last&&FS[last]===prev)return;if(last){const m=last.match(/(\d{4}-\d{2}-\d{2}) (\d{2})-(\d{2})\.md$/);if(m&&Date.now()-new Date(`${m[1]}T${m[2]}:${m[3]}`).getTime()<10*60000)return}
 FS[histDir(k)+st+'.md']=prev;histKeys(k).slice(40).forEach(x=>delete FS[x])}
// A simple line diff (longest common subsequence) for comparing versions.
function lineDiff(a,b){const A=a.split('\n'),B=b.split('\n'),n=A.length,m=B.length;if(n*m>250000)return[...A.map(t=>['-',t]),...B.map(t=>['+',t])];
 const L=Array.from({length:n+1},()=>new Uint16Array(m+1));for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)L[i][j]=A[i]===B[j]?L[i+1][j+1]+1:Math.max(L[i+1][j],L[i][j+1]);
 const out=[];let i=0,j=0;while(i<n&&j<m){if(A[i]===B[j]){out.push(['=',A[i]]);i++;j++}else if(L[i+1][j]>=L[i][j+1])out.push(['-',A[i++]]);else out.push(['+',B[j++]])}while(i<n)out.push(['-',A[i++]]);while(j<m)out.push(['+',B[j++]]);return out}
let histOpen=false,histSel=null;
function histPanel(k){if(!histOpen||!k)return '';const ks=histKeys(k);
 const lab=x=>{const m=x.match(/(\d{4}-\d{2}-\d{2}) (\d{2})-(\d{2})\.md$/);return m?`${m[1]===TD()?'Today':m[1]===dAdd(TD(),-1)?'Yesterday':fmt(m[1])}, ${tf(m[2]+':'+m[3])}`:x};
 const sel=histSel&&FS[histSel]?histSel:ks[0],cur=stripFM(FS[k]),d=sel?lineDiff(stripFM(FS[sel]),cur):[],add=d.filter(x=>x[0]==='+').length,del=d.filter(x=>x[0]==='-').length;
 return `<div class="histpanel"><div class="aihead"><b>${lineIco('M12 7v5l3 2M3.5 12a8.5 8.5 0 1 0 2.5-6M3 4v4h4')} Version history</b><button class="cx" data-act="histT" aria-label="Close" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
${ks.length?`<div class="histlist">${ks.map(x=>`<button class="${x===sel?'on':''}" data-act="histSel" data-k="${esc(x)}">${lab(x)}</button>`).join('')}</div>
<p class="meta" style="margin:8px 0 6px">Changes from ${lab(sel)} to now: <span class="hadd">+${add}</span> <span class="hdel">−${del}</span> lines</p>
<div class="histdiff">${d.filter((x,i)=>x[0]!=='='||(d[i-1]&&d[i-1][0]!=='=')||(d[i+1]&&d[i+1][0]!=='=')).map(x=>`<div class="hl-${x[0]==='+'?'add':x[0]==='-'?'del':'same'}"><span>${x[0]==='='?' ':x[0]}</span>${esc(x[1])||'&nbsp;'}</div>`).join('')||'<p class="meta">No differences.</p>'}</div>
<div class="row"><button class="g" data-act="histRestore" data-k="${esc(sel)}">Restore this version</button></div>`:'<p class="meta">No earlier versions yet. Versions are kept as you edit (one every 10 minutes at most).</p>'}</div>`}
/* Daily note: one note per day (front matter "daily: YYYY-MM-DD"), made from the "Daily note" template, with buttons to
   the previous and next day's note. */
const dailyKey=d=>keys('notes/').find(k=>String(readNote(FS[k]).fm.daily||'')===d);
const DAILYTPL='templates/Daily note.md';
function dailyOpen(d){let k=dailyKey(d);if(!k){if(!FS[DAILYTPL])FS[DAILYTPL]=writeNote({fm:{categories:[],tags:['daily']},body:'## Plan\n\n- \n\n## Notes\n\n## Done today\n'});
  const tp=fromTpl(DAILYTPL),ttl=fmt(d,{weekday:'long',month:'long',day:'numeric',year:'numeric'});k=noteKeyFor('notes/',ttl,d);FS[k]=writeNote({fm:{...tp.fm,created:d,daily:d},body:`# ${ttl}\n\n${tp.body.trim()}\n`});save()}
 view='notes';nmode='notes';edN=k;ND=null;nViewK=k;nView=true;histOpen=false;window.scrollTo(0,0)}
const dailyNav=n=>{const d=String(n.fm.daily||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(d))return '';const p=dAdd(d,-1),x=dAdd(d,1);
 return `<div class="dailynav"><button class="g" data-act="dailyGo" data-d="${p}">${lineIco('M15 5l-7 7 7 7')}${dailyKey(p)?fmt(p,{weekday:'short',day:'numeric'}):'Yesterday'}</button><span class="meta">Daily note</span><button class="g" data-act="dailyGo" data-d="${x}">${dailyKey(x)?fmt(x,{weekday:'short',day:'numeric'}):'Tomorrow'}${lineIco('M9 5l7 7-7 7')}</button></div>`};
function persistNote(){if(!ND)return false;if(!ND.k&&HIST.stack.length<2&&snap()===HIST.stack[0])return false;let changed=false;
 if((!ND.k||!isTplKey(ND.k))&&!isJE(ND.k)){const dir=ND.k&&isArch(ND.k)?'archive/':'notes/',want=noteKeyFor(dir,nameTitle(ND.title,ND.body),createdOf(ND.fm,ND.k&&noteDate(ND.k)),ND.k);
  if(!ND.k){ND.k=want;edN=want;if(nViewK===null)nViewK=want}else if(want!==ND.k){const ot=noteTitle(ND.k);renameNote(ND.k,want);wlRename(ot,(ND.title||'').trim()||noteTitle(want),want);if(nViewK===ND.k)nViewK=want;ND.k=want;edN=want;changed=true}}
 let out=writeNote({fm:ND.fm,body:joinTitle(ND)});if(!out.endsWith('\n'))out+='\n';if(FS[ND.k]===out){if(changed)save();return changed}histSnap(ND.k,FS[ND.k]);FS[ND.k]=out;save();return true}
const noteStatus=()=>{const el=$('nstat');if(el)el.textContent=ND&&ND.k?'Saved':''};
// Re-render without losing the caret: remember the focused field and its selection, then put them back.
function rerenderKeep(){const a=document.activeElement,ds=(a&&a.dataset)||{},sel=a&&a.id?'#'+CSS.escape(a.id):ds.np!==undefined?`[data-np="${CSS.escape(ds.np)}"]`:ds.npadd!==undefined?`[data-npadd="${CSS.escape(ds.npadd)}"]`:null;
 let st=null;try{if(a&&a.setSelectionRange)st=[a.selectionStart,a.selectionEnd,a.scrollTop]}catch(e){}const typed=ds.npadd!==undefined?a.value:null,y=window.scrollY;
 render();window.scrollTo(0,y);const b=sel&&document.querySelector(sel);if(b){b.focus();if(typed!==null)b.value=typed;if(st&&st[0]!=null){try{b.setSelectionRange(st[0],st[1])}catch(e){}b.scrollTop=st[2]}}}
function flushNote(){if(!noteTimer)return;clearTimeout(noteTimer);noteTimer=null;commitHist();persistNote()}
// kind 'type': wait for a pause; kind 'now': save immediately (the caller re-renders).
function noteChanged(kind){if(kind==='now'){clearTimeout(noteTimer);noteTimer=null;commitHist();persistNote();return}
 clearTimeout(noteTimer);noteTimer=setTimeout(()=>{noteTimer=null;commitHist();const wasNew=!ND.k;if(persistNote()&&view==='notes'&&(wasNew||CFG.notesView==='panel'||nmode!=='templates'))rerenderKeep();else noteStatus()},600);
 const el=$('nstat');if(el)el.textContent='Saving…'}
function undoNote(dir){flushNote();if(!ND)return;commitHist();const j=HIST.i+dir;if(j<0||j>=HIST.stack.length)return;HIST.i=j;
 const x=JSON.parse(HIST.stack[j]);ND.title=x.t;ND.body=x.b;ND.fm=x.f;persistNote()}
window.addEventListener('blur',flushNote);document.addEventListener('visibilitychange',()=>{if(document.hidden)flushNote()});window.addEventListener('beforeunload',flushNote);
const PICON={tags:'tag',categories:'list-bullets',list:'list-bullets',text:'text-align-left',number:'hash',checkbox:'check-square',date:'calendar-blank'};
// Property types work like Obsidian's: chosen when a property is added, remembered by name, otherwise guessed from the value.
const ptype=(k,v)=>k==='tags'||k==='categories'?k:(CFG.propTypes||{})[k]||(Array.isArray(v)?'list':/^(true|false)$/.test(v)?'checkbox':/^\d{4}-\d{2}-\d{2}$/.test(v)?'date':v!==''&&!isNaN(+v)?'number':'text');
const propRow=(k,v,tpl)=>{const t=ptype(k,v),e=esc(k);let val;
 if(t==='tags'||t==='categories'||t==='list'){const items=Array.isArray(v)?v:(v?[v]:[]);
  val=items.map((x,i)=>{const del=`<button class="cx" data-act="npDel" data-p="${e}" data-i="${i}" aria-label="Remove ${esc(x)}">×</button>`;
   return t==='categories'?`<span class="catedit">${catTile(x,undefined,1,isJE(edN)?'journal':undefined)}${del}</span>`
    :t==='tags'?`<span class="chip tagc"><button class="clink" data-act="tagGo" data-v="${esc(x)}">${esc(x)}</button>${del}</span>`:`<span class="chip">${esc(x)}${del}</span>`}).join('')
   +`<input class="pinp" data-npadd="${e}" placeholder="${items.length?(t==='categories'?'Add category':t==='tags'?'Add tag':''):(t==='categories'?'Add a category':t==='tags'?'Add a tag':'Empty')}" autocomplete="off" aria-label="Add to ${e}"${t==='categories'||t==='tags'?' aria-autocomplete="list"':''}>`}
 else if(t==='checkbox')val=`<input type="checkbox" data-np="${e}" ${String(v)==='true'?'checked':''} aria-label="${e}">`;
 else if(t==='date'&&!tpl&&(!v||/^\d{4}-\d{2}-\d{2}$/.test(v)))val=`<input type="date" class="pinp" data-np="${e}" value="${esc(v)}" aria-label="${e}">`;
 else val=`<input class="pinp" data-np="${e}" value="${esc(v)}"${t==='number'?' inputmode="decimal"':''} placeholder="Empty" aria-label="${e}">`;
 return `<div class="prow"><span class="pname">${sym(PICON[t])}<span title="${e}">${e}</span><button class="cx prm" data-act="npRm" data-p="${e}" aria-label="Remove property ${e}" title="Remove property">×</button></span><span class="pval">${val}</span></div>`};
const propsPanel=()=>{const n=draft(),tpl=isTplKey(n.k||'');
 return `<div class="props"><h3 class="ptitle">Properties</h3>${Object.entries(n.fm).filter(([k])=>k!=='pinned').map(([k,v])=>propRow(k,v,tpl)).join('')}
${addProp?`<div class="prow"><span class="pname"><input id="npName" class="pinp" value="${esc(npNameDraft)}" placeholder="Property name" list="dl-pnames" aria-label="Property name"></span><span class="pval"><div class="moods seg">${['text','list','number','checkbox','date'].map(t=>`<button type="button" data-act="npType" data-val="${t}" class="${npT===t?'on':''}" aria-pressed="${npT===t}">${t[0].toUpperCase()+t.slice(1)}</button>`).join('')}</div><button class="g" data-act="npAdd">Add</button><button class="x" data-act="npCancel">Cancel</button></span></div>`:`<button class="x padd" data-act="npNew">+ Add property</button>`}</div>`};
const dataLists=()=>{const names=new Set(Object.keys(CFG.propTypes||{}));[...keys('notes/'),...keys('templates/')].forEach(k=>Object.keys(readNote(FS[k]).fm).forEach(x=>names.add(x)));
 const opts=a=>a.map(x=>`<option value="${esc(x)}">`).join('');
 return `<datalist id="dl-tags">${opts([...propIndex('tags').values()].map(x=>x.name))}</datalist><datalist id="dl-categories">${opts([...allCats().values()].map(x=>x.name).sort(alpha))}</datalist><datalist id="dl-pnames">${opts([...names].filter(x=>x!=='pinned'))}</datalist>`};
/* ---------- Formatting toolbar for the note text ----------
   Buttons (and Ctrl+B / Ctrl+I / Ctrl+K) wrap the selection or prefix its lines with Markdown. Edits go through
   insertText so the note's autosave and the editor's own undo keep working. Enter continues lists and checklists. */
// Toolbar icons: letter glyphs for text styles, thin line drawings (24×24, 2px strokes) for the rest.
const mdSvg=(d,extra='')=>`<svg class="mdi" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d.split('|').map(x=>`<path d="${x}"/>`).join('')}${extra}</svg>`;
const MDI={
 heading:'<span class="mdg mdh">H</span>',bold:'<span class="mdg mdb">B</span>',italic:'<span class="mdg mdit">I</span>',strike:'<span class="mdg mds">S</span>',
 mark:mdSvg('M15 5l4 4-8.5 8.5H6.5v-4z|M13 7l4 4','<path d="M4 21h16" stroke="#e8b923" stroke-width="2.6"/>'),
 bullets:mdSvg('M10 6h10|M10 12h10|M10 18h10','<circle cx="5" cy="6" r="1.4" fill="currentColor" stroke="none"/><circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="5" cy="18" r="1.4" fill="currentColor" stroke="none"/>'),
 numbers:mdSvg('M10 6h10|M10 12h10|M10 18h10|M4 4.5l1.5-1v5|M3.6 13.2c.3-.8 2.6-1 2.6.4 0 1.1-2.6 1.9-2.6 3h2.8'),
 check:mdSvg('M3.5 4.5h5v5h-5z|M4.8 7.1l1.2 1.2 1.9-2.2|M3.5 14.5h5v5h-5z|M12 7h8.5|M12 17h8.5'),
 quote:mdSvg('M5 18c2-1 3.2-3 3.2-5.5V8H4v4.5h4.2|M14 18c2-1 3.2-3 3.2-5.5V8H13v4.5h4.2'),
 link:mdSvg('M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1|M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1'),
 code:mdSvg('M8 7l-5 5 5 5|M16 7l5 5-5 5|M13.5 4.5l-3 15'),
 codeblock:mdSvg('M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z|M9 10l-2 2 2 2|M15 10l2 2-2 2'),
 rule:mdSvg('M3 12h18','<path d="M7 7h10M7 17h10" opacity=".35"/>'),
 undo:mdSvg('M9 14L4 9l5-5|M4 9h10.5a5.5 5.5 0 0 1 0 11H11'),
 redo:mdSvg('M15 14l5-5-5-5|M20 9H9.5a5.5 5.5 0 0 0 0 11H13')};
const MDBAR=[[['heading','Heading (cycles H1–H3)'],['bold','Bold (Ctrl+B)'],['italic','Italic (Ctrl+I)'],['strike','Strikethrough (Ctrl+Shift+X)'],['mark','Highlight']],
 [['bullets','Bulleted list'],['numbers','Numbered list'],['check','Checklist'],['quote','Quote']],
 [['link','Link (Ctrl+K)'],['code','Inline code'],['codeblock','Code block'],['rule','Divider']]];
const mdBar=()=>`<div class="mdbar" role="toolbar" aria-label="Formatting"><span class="mdgrp"><button type="button" data-act="undoN" title="Undo (Ctrl+Z)" aria-label="Undo" ${HIST.i>0?'':'disabled'}>${MDI.undo}</button><button type="button" data-act="redoN" title="Redo (Ctrl+Shift+Z)" aria-label="Redo" ${HIST.i<HIST.stack.length-1?'':'disabled'}>${MDI.redo}</button></span>${MDBAR.map(g=>`<span class="mdgrp">${g.map(([id,t])=>`<button type="button" data-md="${id}" title="${t}" aria-label="${t.replace(/ \(.*\)$/,'')}">${MDI[id]}</button>`).join('')}</span>`).join('')}</div>`;
function mdPut(ta,start,end,text,s0,s1){ta.focus();ta.setSelectionRange(start,end);let ok=false;try{ok=document.execCommand('insertText',false,text)}catch(e){}
 if(!ok||ta.value.slice(start,start+text.length)!==text){ta.setRangeText(text,start,end,'end');ta.dispatchEvent(new Event('input',{bubbles:true}))}
 ta.setSelectionRange(start+s0,start+(s1==null?s0:s1))}
// Wraps the selection in a marker (or removes it when it is already wrapped); with no selection, places the cursor inside.
function mdWrap(ta,a,b=a){const v=ta.value,s0=ta.selectionStart,s1=ta.selectionEnd,sel=v.slice(s0,s1);
 if(v.slice(s0-a.length,s0)===a&&v.slice(s1,s1+b.length)===b){mdPut(ta,s0-a.length,s1+b.length,sel,0,sel.length);return}
 if(sel.startsWith(a)&&sel.endsWith(b)&&sel.length>=a.length+b.length){const inner=sel.slice(a.length,sel.length-b.length);mdPut(ta,s0,s1,inner,0,inner.length);return}
 mdPut(ta,s0,s1,a+sel+b,a.length,a.length+sel.length)}
// Adds or removes a prefix on every selected line (numbered lists count up).
function mdLines(ta,kind){const v=ta.value,ls=v.lastIndexOf('\n',ta.selectionStart-1)+1;let le=v.indexOf('\n',ta.selectionEnd);if(le<0)le=v.length;
 const lines=v.slice(ls,le).split('\n'),RX={bullets:/^\s*[-*+] (?!\[[ xX]\] )/,numbers:/^\s*\d+[.)] /,check:/^\s*[-*+] \[[ xX]\] /,quote:/^>\s?/},rx=RX[kind];
 const all=lines.filter(l=>l.trim()).every(l=>rx.test(l));
 const strip=l=>l.replace(/^\s*([-*+] \[[ xX]\] |[-*+] |\d+[.)] |>\s?)/,'');
 const out=lines.map((l,i)=>all?strip(l):(!l.trim()&&lines.length>1?l:(kind==='bullets'?'- ':kind==='numbers'?(i+1)+'. ':kind==='check'?'- [ ] ':'> ')+strip(l))).join('\n');
 mdPut(ta,ls,le,out,out.length)}
function mdHeading(ta){const v=ta.value,ls=v.lastIndexOf('\n',ta.selectionStart-1)+1;let le=v.indexOf('\n',ls);if(le<0)le=v.length;
 const line=v.slice(ls,le),m=line.match(/^(#{1,6}) /),n=m?m[1].length:0,text=line.replace(/^#{1,6} /,''),next=n>=3?'':'#'.repeat(n+1)+' ';mdPut(ta,ls,le,next+text,(next+text).length)}
function mdLink(ta){const v=ta.value,s0=ta.selectionStart,s1=ta.selectionEnd,sel=v.slice(s0,s1);
 if(/^(https?:\/\/|mailto:)\S+$/.test(sel)){mdPut(ta,s0,s1,`[](${sel})`,1);return}
 const t=sel||'link text',txt=`[${t}](https://)`;mdPut(ta,s0,s1,txt,t.length+3,t.length+11)}
function mdDo(id){const ta=$('nb');if(!ta)return;
 if(id==='bold')mdWrap(ta,'**');else if(id==='italic')mdWrap(ta,'*');else if(id==='strike')mdWrap(ta,'~~');else if(id==='mark')mdWrap(ta,'==');else if(id==='code')mdWrap(ta,'`');
 else if(id==='heading')mdHeading(ta);else if(id==='link')mdLink(ta);else if(['bullets','numbers','check','quote'].includes(id))mdLines(ta,id);
 else if(id==='codeblock'){const s0=ta.selectionStart,s1=ta.selectionEnd,sel=ta.value.slice(s0,s1),pre=s0&&ta.value[s0-1]!=='\n'?'\n':'';mdPut(ta,s0,s1,`${pre}\`\`\`\n${sel}\n\`\`\`\n`,pre.length+4,pre.length+4+sel.length)}
 else if(id==='rule'){const s0=ta.selectionStart,pre=s0&&ta.value[s0-1]!=='\n'?'\n':'';mdPut(ta,s0,ta.selectionEnd,`${pre}\n---\n\n`,pre.length+6)}}
document.addEventListener('mousedown',e=>{const b=e.target.closest&&e.target.closest('[data-md]');if(b)e.preventDefault()});
document.addEventListener('click',e=>{const b=e.target.closest&&e.target.closest('[data-md]');if(b){e.preventDefault();e.stopPropagation();mdDo(b.dataset.md)}},true);
document.addEventListener('keydown',e=>{if(e.target.id!=='nb')return;const k=e.key.toLowerCase(),mod=(e.ctrlKey||e.metaKey)&&!e.altKey;
 if(mod&&!e.shiftKey&&(k==='b'||k==='i'||k==='k')){e.preventDefault();e.stopImmediatePropagation();mdDo(k==='b'?'bold':k==='i'?'italic':'link');return}
 if(mod&&e.shiftKey&&k==='x'){e.preventDefault();mdDo('strike');return}
 // Enter continues a list item; Enter on an empty item ends the list
 if(e.key==='Enter'&&!e.shiftKey&&!mod&&e.target.selectionStart===e.target.selectionEnd){const ta=e.target,v=ta.value,p=ta.selectionStart,ls=v.lastIndexOf('\n',p-1)+1,line=v.slice(ls,p);
  const m=line.match(/^(\s*)([-*+] \[[ xX]\] |[-*+] |(\d+)([.)]) |> )(.*)$/);if(!m)return;e.preventDefault();
  if(!m[5].trim()){mdPut(ta,ls,p,m[1],m[1].length);return}
  const next=m[3]?`${+m[3]+1}${m[4]} `:m[2].replace(/\[[xX]\]/,'[ ]');mdPut(ta,p,p,'\n'+m[1]+next,1+m[1].length+next.length)}},true);
/* View and edit modes. View renders the note (title, properties, Markdown) read-only; Edit is the editor.
   An existing note opens in the mode chosen in Settings → Notes; new notes always start in Edit. Ctrl+E switches. */
let nView=false,nViewK=undefined;
const propView=(k,v)=>{const t=ptype(k,v),items=Array.isArray(v)?v:(v===''||v==null?[]:[v]);if(!items.length)return '';
 const val=t==='categories'?`<div class="cattiles">${items.map(x=>catTile(x,undefined,1,isJE(edN)?'journal':undefined)).join('')}</div>`
  :t==='tags'?items.map(x=>`<button class="chip tagc clink" data-act="tagGo" data-v="${esc(x)}">${esc(x)}</button>`).join('')
  :t==='checkbox'?(String(v)==='true'?'Yes':'No'):t==='date'&&/^\d{4}-\d{2}-\d{2}$/.test(v)?esc(fmt(v,{year:'numeric',month:'long',day:'numeric'})):items.map(esc).join(', ');
 return `<div class="prow"><span class="pname">${sym(PICON[t])}<span title="${esc(k)}">${esc(k)}</span></span><span class="pval">${val}</span></div>`};
const modeSeg=()=>`<div class="moods seg nmodes" role="group" aria-label="Note mode"><button data-act="nMode" data-val="view" class="${nView?'on':''}" aria-pressed="${nView}" title="View (Ctrl+E)">${sym('eye')}View</button><button data-act="nMode" data-val="edit" class="${nView?'':'on'}" aria-pressed="${!nView}" title="Edit (Ctrl+E)">${sym('pencil-simple')}Edit</button></div>`;
// Typing [[ in a note or journal entry opens a menu of things to link; ↑ ↓ choose, Enter or Tab inserts, Esc closes.
let WLS=null;
function caretXY(ta){const m=document.createElement('div'),cs=getComputedStyle(ta);['font','fontSize','fontFamily','lineHeight','letterSpacing','padding','border','boxSizing','whiteSpace','wordWrap','width'].forEach(p=>m.style[p]=cs[p]);
 m.style.position='absolute';m.style.visibility='hidden';m.style.whiteSpace='pre-wrap';m.style.wordWrap='break-word';m.style.top='0';m.style.left='-9999px';m.textContent=ta.value.slice(0,ta.selectionStart);const sp=document.createElement('span');sp.textContent='\u200b';m.appendChild(sp);document.body.appendChild(m);
 const r=ta.getBoundingClientRect(),x=r.left+sp.offsetLeft-ta.scrollLeft,y=r.top+sp.offsetTop-ta.scrollTop+parseFloat(cs.lineHeight||'20');m.remove();return{x,y}}
function wlShow(ta){const q=ta.value.slice(0,ta.selectionStart).match(/\[\[([^\]\n|]{0,60})$/);if(!q){wlHide();return}
 const f=fold(q[1].trim()),self=edN&&noteTitle(edN),items=[...wlIndex().values()].filter(x=>(!f||fold(x.name).includes(f))&&x.name!==self).sort((a,b)=>(fold(b.name).startsWith(f)-fold(a.name).startsWith(f))||alpha(a.name,b.name)).slice(0,8);
 if(q[1].trim()&&!items.some(x=>fold(x.name)===f))items.push({kind:'new',name:q[1].trim()});if(!items.length){wlHide();return}
 let el=$('wlsug');if(!el){el=document.createElement('div');el.id='wlsug';el.className='wlsug';el.setAttribute('role','listbox');document.body.appendChild(el)}
 WLS={ta,items,i:Math.min(WLS&&WLS.ta===ta?WLS.i:0,items.length-1),start:ta.selectionStart-q[1].length};
 el.innerHTML=items.map((x,i)=>`<button class="${i===WLS.i?'on':''}" data-wli="${i}" role="option" aria-selected="${i===WLS.i}">${x.kind==='new'?`${lineIco('M12 5v14M5 12h14')}<span>New note “${esc(x.name)}”</span>`:`${symbols()?sym(WLICO[x.kind][0]):WLICO[x.kind][1]}<span>${esc(x.name)}</span><em>${{note:'Note',journal:'Journal',project:'Project',col:'Collection',list:'List'}[x.kind]}</em>`}</button>`).join('');
 const p=caretXY(ta);el.style.left=Math.min(p.x,innerWidth-300)+'px';el.style.top=Math.min(p.y+4,innerHeight-40)+'px'}
function wlHide(){WLS=null;const el=$('wlsug');if(el)el.remove()}
function wlPick(i){if(!WLS)return;const x=WLS.items[i],ta=WLS.ta,st=WLS.start-2,end=ta.selectionStart,after=ta.value.slice(end).startsWith(']]')?2:0,ins=`[[${x.name}]]`;
 ta.value=ta.value.slice(0,st)+ins+ta.value.slice(end+after);ta.setSelectionRange(st+ins.length,st+ins.length);wlHide();ta.focus();ta.dispatchEvent(new Event('input',{bubbles:true}))}
document.addEventListener('input',e=>{if(e.target.id==='nb'||e.target.id==='jt'||(e.target.dataset&&e.target.dataset.jeb!==undefined))wlShow(e.target)});
document.addEventListener('keydown',e=>{if(!WLS)return;if(e.target!==WLS.ta){if(e.target.id&&WLS.ta.id===e.target.id&&!WLS.ta.isConnected)WLS.ta=e.target;else return}const n=WLS.items.length;
 if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();e.stopImmediatePropagation();WLS.i=(WLS.i+(e.key==='ArrowDown'?1:-1)+n)%n;wlShow(WLS.ta)}
 else if(e.key==='Enter'||e.key==='Tab'){e.preventDefault();e.stopImmediatePropagation();wlPick(WLS.i)}else if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();wlHide()}},true);
document.addEventListener('pointerdown',e=>{const b=e.target.closest&&e.target.closest('#wlsug [data-wli]');if(b){e.preventDefault();wlPick(+b.dataset.wli);return}if(WLS&&!e.target.closest('#wlsug'))wlHide()},true);
/* Password lock: CFG.lock = {salt, hash, idle (minutes, 0 = only at start)}. The password is kept only as a
   PBKDF2-SHA-256 hash. It hides the app until the password is typed; it does not encrypt the files on disk. */
let PWLOCK=!!(CFG.lock&&CFG.lock.hash)||!!ACCT,lockBusy=false,lockLast=Date.now(),lockSet=false;
const b64=buf=>btoa(String.fromCharCode(...new Uint8Array(buf))),unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function lockHash(pw,salt){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',salt:unb64(salt),iterations:210000,hash:'SHA-256'},k,256))}
const lockCheck=async pw=>!!(CFG.lock&&pw&&await lockHash(pw,CFG.lock.salt)===CFG.lock.hash);
const lockOn=()=>!!(ACCT||(CFG.lock&&CFG.lock.hash)),lockIdleMin=()=>ACCT?+CFG.accIdle||0:+((CFG.lock||{}).idle)||0;
/* Account actions. The first unlock decrypts every file into FS (accLoad); later unlocks (after Lock now or idle) only
   check the password, since the data key is still in memory. */
let lockRec=false,ACCUI=null,ACCRK='',accBusy=false,accEncOn=true,accViaRec=false;
async function accLoad(raw){const plain={},bad=[],r2={};DISKK={};NHK=null;
 for(const dk in raw){const r=raw[dk];let k=dk,t=r;
  if(isEncT(r)){try{t=await decText(r)}catch(e){bad.push(dk);continue}if(dk.startsWith('enc/')){const i=t.indexOf('\n');k=t.slice(0,i);t=t.slice(i+1)}}
  plain[k]=t;r2[k]=r;DISKK[k]=dk}
 for(const k in FS)delete FS[k];Object.assign(FS,plain);for(const k in DISK)delete DISK[k];Object.assign(DISK,plain);RAW=r2;
 // rewritten when stored the wrong way for the account: encrypted or not, and (in app storage) name hidden or not
 NEEDW=new Set(Object.keys(plain).filter(k=>k!==ACCK&&(isEncT(r2[k])!==!!ACCT.enc||(STORE_DB&&DISKK[k].startsWith('enc/')!==!!ACCT.enc))));ACCREADY=true;BOOTRAW=null;
 if(bad.length)toast(`${bad.length} file${bad.length===1?'':'s'} couldn’t be decrypted and ${bad.length===1?'was':'were'} left as ${bad.length===1?'it is':'they are'}`)}
async function accUnlock(secret,rec){const k=await accKey(secret,rec);if(!k)return false;
 if(!ACCREADY){DKRAW=k;DK=await aesKey(k);await accLoad(BOOTRAW);accAfterLoad()}return true}
// What startup does with the files, run again once they're decrypted.
function accAfterLoad(){cloudSoon(1500);if(ACCT&&!ACCT.kid&&DKRAW)keyId().then(k=>{ACCT.kid=k;FS[ACCK]=accText(ACCT);save()});try{trashPurge()}catch(e){}try{if(CFG.prompts){const u=allQ().find(x=>!x.a.length);if(u)curQ=u.q}}catch(e){}if(NEEDW.size)save();setTimeout(()=>{try{bkAuto()}catch(e){}},2000)}
// Rewrites every attachment (and the automatic backups) in the form the account asks for: encrypted or plain.
async function accConvertExtra(on){let n=0;
 const names=TAURI?await TAURI.invoke('list_attachments'):[...new Set(Object.values(FS).flatMap(t=>[...String(t).matchAll(/attachments\/([^)\s"'<>]+)/g)].map(m=>decodeURIComponent(m[1]))))];
 for(const name of names){try{const u=await attRead(name);if(!u)continue;if(on&&!isEncB(u)){await attWrite(name,await encBytes(u));n++}else if(!on&&isEncB(u)){await attWrite(name,await decBytes(u));n++}}catch(e){}}
 for(const k in ATTURL){if(String(ATTURL[k]).startsWith('blob:'))URL.revokeObjectURL(ATTURL[k]);delete ATTURL[k]}
 try{for(const[name]of await BK.list()){let raw=await BK.read(name);if(!raw)continue;const enc=isEncT(raw);if(enc===on)continue;raw=enc?await decText(raw):raw;await BK.write(name,on?await encText(raw):raw)}}catch(e){}
 return n}
// Turns encryption on or off: every file is rewritten in the new form, then attachments and backups.
async function accSetEnc(on){ACCT.enc=on;FS[ACCK]=accText(ACCT);Object.keys(FS).forEach(k=>{if(k!==ACCK)NEEDW.add(k)});save();await SQ;await accConvertExtra(on);if(typeof mirReset==='function')mirReset()}
async function accCreate(name,pw,enc){DKRAW=crypto.getRandomValues(new Uint8Array(32));NHK=null;DK=await aesKey(DKRAW);const rk=recNew(),a={name,enc:false,iter:600000,riter:100000,created:TD()};
 await accSeal(a,pw,rk);a.kid=await keyId();ACCT=a;ACCREADY=true;FS[ACCK]=accText(a);delete CFG.lock;saveCfg();save();if(enc)await accSetEnc(true);return rk}
async function accRemove(){if(ACCT.enc)await accSetEnc(false);delete FS[ACCK];save();await SQ;ACCT=null;DK=null;DKRAW=null;NEEDW.clear();if(typeof mirReset==='function')mirReset()}
const userSave=()=>store.set('prodify.users',JSON.stringify(USERS));
const uInit=u=>esc((String(u.name||'?').trim()[0]||'?').toUpperCase());
const uColor=u=>['#5cb8c2','#d4a43a','#9a5fa0','#5fa57f','#e0566f','#6f7fb0','#c9733d'][[...String(u.id)].reduce((a,c)=>a+c.charCodeAt(0),0)%7];
// The first time a second user is added, the current folder becomes the first user.
function usersInit(){if(!USERS.length)USERS=[{id:'main',name:(ACCT&&ACCT.name)||CFG.name||'Me',dir:TAURI?BOOT.dir:'',main:true}]}
// Data of the user's own (anything beyond the templates and question list every new space starts with).
const hasOwnData=()=>Object.keys(FS).some(k=>k!==ACCK&&!k.startsWith('templates/')&&k!=='questions.md');
// Adds a user with their own (empty) folder and returns their id, or '' with a toast when it can't.
function userCreate(nm,dirPick){const dir=TAURI?(dirPick||userDefDir(nm)):'';usersInit();
 if(TAURI&&USERS.some(u=>u.dir===dir)){toast('That folder already belongs to a user');return ''}if(TAURI&&dir===BOOT.dir){toast('Pick a different folder');return ''}
 const id=Date.now().toString(36)+Math.random().toString(36).slice(2,6);USERS.push({id,name:nm,dir});userSave();return id}
// Starting fresh: a new user with an empty folder; once it opens, account creation continues there ('settings' or 'onb').
function userFresh(nm,then){const id=userCreate(nm);if(!id)return;try{sessionStorage.setItem('prodify.fresh',then)}catch(e){}toast(`Opening a new, empty space for ${nm}…`);userSwitch(id)}
async function userSwitch(id){const u=USERS.find(x=>x.id===id);if(!u)return;if(ME?u.id===ME.id:u.main){WHO=false;whoShow();return}
 try{flushNote()}catch(e){}save();try{sessionStorage.setItem('prodify.switched','1')}catch(e){}
 try{if(TAURI){await SQ;await TAURI.invoke('set_data_dir',{path:u.dir,copy:false})}else store.set('prodify.user',u.id);await SQ;location.reload()}catch(e){toast('Could not switch user: '+e)}}
const userTiles=(skipMe)=>USERS.filter(u=>!skipMe||!(ME?u.id===ME.id:u.main)).map(u=>`<button type="button" class="whotile" data-act="userGo" data-v="${esc(u.id)}" style="--uc:${uColor(u)}"><span class="whoav">${uInit(u)}</span><span class="whonm" data-notr>${esc(u.name)}</span></button>`).join('');
function whoShow(){let o=$('whoscr');document.body.classList.toggle('locked',PWLOCK||WHO);if(!WHO){if(o)o.remove();lockShow();return}
 if(!o){o=document.createElement('div');o.id='whoscr';o.className='lockscr whoscr';o.setAttribute('role','dialog');o.setAttribute('aria-modal','true');o.setAttribute('aria-label','Who’s using Prodify?');document.body.appendChild(o)}
 o.innerHTML=`<div class="whobox"><h2>Who’s using Prodify?</h2><div class="whogrid">${userTiles(false)}</div></div>`}
function lockShow(){let o=$('lockscr');document.body.classList.toggle('locked',PWLOCK||WHO);if(!PWLOCK){if(o)o.remove();return}
 if(!o){o=document.createElement('div');o.id='lockscr';o.className='lockscr';o.setAttribute('role','dialog');o.setAttribute('aria-modal','true');o.setAttribute('aria-label','Prodify is locked');document.body.appendChild(o)}
 o.innerHTML=`<form class="lockbox" id="lockform"><span class="lockico">${lineIco('M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z')}</span><h2>${ACCT?(ACCT.name?`Welcome back, <span data-notr>${esc(ACCT.name)}</span>`:'Welcome back'):'Prodify is locked'}</h2>${ACCT&&!ACCREADY&&ACCT.enc?'<p class="lockinfo">Your data is encrypted. Unlock to open it.</p>':''}${lockRec?'<input type="text" id="lockpw" placeholder="Recovery key (XXXX-XXXX-…)" autocomplete="off" spellcheck="false" aria-label="Recovery key">':'<input type="password" id="lockpw" placeholder="Password" autocomplete="current-password" aria-label="Password">'}<button class="b" type="submit">Unlock</button><p class="meta" id="lockmsg"></p>${ACCT?`<button type="button" class="x" data-act="lockRec">${lockRec?'Use my password':'Forgot your password? Use your recovery key'}</button>`:''}${USERS.length>1?`<div class="lockusers"><span class="lockinfo">Not you? Switch user</span><div class="whogrid sm">${userTiles(true)}</div></div>`:''}</form>`;
 setTimeout(()=>{const i=$('lockpw');if(i)i.focus()},30)}
document.addEventListener('submit',async e=>{if(e.target.id!=='lockform')return;e.preventDefault();if(lockBusy)return;lockBusy=true;const m0=$('lockmsg');if(m0&&ACCT&&!ACCREADY)m0.textContent=ACCT.enc?'Unlocking and decrypting…':'Unlocking…';const v=($('lockpw')||{}).value||'',ok=ACCT?await accUnlock(v,lockRec):await lockCheck(v);lockBusy=false;
 if(ok){PWLOCK=false;lockLast=Date.now();if(lockRec){lockRec=false;accViaRec=true;ACCUI='pw';view='settings';SETG='account';toast('Unlocked with your recovery key · set a new password')}lockShow();render();if(ACCUI==='pw')setTimeout(()=>{const x=document.querySelector('.accsec');if(x)x.scrollIntoView({block:'center'});const i=$('accpw');if(i)i.focus()},50)}else{const m=$('lockmsg');if(m)m.textContent=lockRec?'That recovery key doesn’t match':'Wrong password';const i=$('lockpw');if(i){i.value='';i.focus();i.classList.remove('shake');void i.offsetWidth;i.classList.add('shake')}}});
['pointerdown','keydown'].forEach(t=>document.addEventListener(t,()=>{if(!PWLOCK)lockLast=Date.now()},true));
setInterval(()=>{if(!PWLOCK&&lockOn()&&lockIdleMin()>0&&Date.now()-lockLast>lockIdleMin()*60000){PWLOCK=true;lockShow()}},10000);
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&!e.shiftKey&&!e.altKey&&e.key.toLowerCase()==='l'&&lockOn()&&!PWLOCK){e.preventDefault();PWLOCK=true;lockShow()}});
const aiKeyBody=()=>TAURI?`<div class="aikey">${L('Anthropic API key')}<div class="row" style="margin:0"><input type="password" id="aikey" placeholder="${CFG.aiKey?'Saved · paste a new key to replace it':'sk-ant-…'}" autocomplete="off" spellcheck="false" aria-label="Anthropic API key"><button class="b" data-act="aiKeySave">Save</button>${CFG.aiKey?'<button class="x" data-act="aiKeyDel">Remove</button>':''}</div>
<p class="meta" style="margin:6px 0 0">Powers AI questions and the AI tools on notes. It stays on this computer (never in your notes folder) and is only sent to Anthropic. Create one at console.anthropic.com.</p>
${L('AI model')}${seg('aiModel',AIMODELS,CFG.aiModel||'claude-haiku-5-5')}<div class="row" style="margin:10px 0 0"><button class="g" data-act="aiTest" ${CFG.aiKey?'':'disabled'}>Test connection</button></div></div>`:'';
const lockSettings=()=>{const on=!!(CFG.lock&&CFG.lock.hash);
 return `<section><h2>Privacy</h2>${on?`<div class="swrow"><span>Password lock is on <span class="meta">Prodify asks for the password when it opens. Press Ctrl+L to lock it now.</span></span><button class="g" data-act="lockNow">Lock now</button></div>
${L('Lock after')}${seg('lockIdle',[['0','Only at start'],['5','5 min idle'],['15','15 min'],['30','30 min'],['60','1 hour']],String(CFG.lock.idle||0)).replace(/data-act="set" data-s="lockIdle"/g,'data-act="lockIdle"')}
${lockSet?`<div class="lockfields">${L('Current password')}<input type="password" id="lkold" autocomplete="current-password" aria-label="Current password"><div class="row"><button class="x" data-act="lockOff">Turn off the lock</button><button class="g" data-act="lockCancel">Cancel</button></div></div>`:'<div class="row" style="margin-top:10px"><button class="x" data-act="lockAsk">Turn off the lock…</button></div>'}`
 :lockSet?`<div class="lockfields">${L('New password')}<input type="password" id="lknew" autocomplete="new-password" aria-label="New password">${L('Repeat it')}<input type="password" id="lknew2" autocomplete="new-password" aria-label="Repeat the password"><div class="row"><button class="b" data-act="lockOn">Turn on the lock</button><button class="g" data-act="lockCancel">Cancel</button></div></div>`
 :`<div class="swrow"><span>Lock with a password <span class="meta">Hides your notes behind a password when Prodify opens.</span></span><button class="g" data-act="lockAsk">Set a password</button></div>`}
<p class="meta" style="margin:8px 0 0">The lock keeps people from opening your notes in the app. Your files are not encrypted: they stay readable in ${TAURI?'your Prodify folder':'this browser’s storage'}. There is no way to recover a forgotten password from the app.</p></section>`};
// Settings → Users: everyone who uses Prodify on this computer, each with their own data and settings.
let UADD=null;// the Add user form: {name, dir}
const userDefDir=n=>{const b=BOOT.default_dir||BOOT.dir||'';return b?b+' - '+String(n||'').replace(/[\\/:*?"<>|]/g,'').trim():''};
const usersSettings=()=>{const me=u=>ME?u.id===ME.id:u.main,list=USERS.length?USERS:[{id:'main',name:(ACCT&&ACCT.name)||CFG.name||'Me',dir:BOOT.dir||'',main:true}];
 return `<section class="usersec"><h2>Users</h2><p class="meta" style="margin:0 0 10px">Each person gets their own notes, journal, tasks and settings in their own ${TAURI?'folder':'storage'}, and can add a password and encryption in their Account.</p>
<div class="ulist">${list.map(u=>`<div class="urow"><span class="whoav" style="--uc:${uColor(u)}">${uInit(u)}</span><div class="uwho"><b data-notr>${esc(u.name)}</b>${me(u)?'<span class="ubadge">You</span>':''}${TAURI&&u.dir?`<span class="meta" data-notr>${esc(u.dir)}</span>`:''}</div>${me(u)?'':`<button class="g" data-act="userGo" data-v="${esc(u.id)}">Switch</button><button class="x" data-act="userDel" data-v="${esc(u.id)}">Remove…</button>`}</div>`).join('')}</div>
${UADD?`<div class="accpanel">${L('Name')}<input id="uname" value="${esc(UADD.name)}" placeholder="Their name" autocomplete="off" aria-label="Name">${TAURI?`${L('Their folder')}<p class="path" data-notr>${esc(UADD.dir||userDefDir(UADD.name)||'')}</p><div class="row" style="margin:0"><button class="g" data-act="userDir">Choose folder…</button></div>`:''}
<div class="row" style="margin-top:12px"><button class="b" data-act="userAdd">Add and switch to them</button><button class="g" data-act="userCancel">Cancel</button></div></div>`:`<div class="row" style="margin-top:10px"><button class="g" data-act="userNew">${lineIco('M12 5v14M5 12h14')}Add user</button></div>`}
${USERS.length>1?swRow('Ask who’s using Prodify when it opens','u:ask',store.get('prodify.ask')!=='0'):''}</section>`};
// When the space already has data, creating an account asks: lock this data, or start fresh as a separate user.
let accFresh=false,accNameDraft='';
const accChoice=(fresh,act)=>`<p class="meta" style="margin:8px 0 6px">This ${TAURI?'folder':'browser'} already has notes and files.</p><div class="onbacc accchoice" role="radiogroup" aria-label="What the account is for">
<button class="onbopt ${fresh?'':'on'}" role="radio" aria-checked="${!fresh}" data-act="${act}" data-val="0"><span class="onboptico">${lineIco('M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z')}</span><span class="onbopttx"><b>Protect my existing data</b><span class="meta">The account locks the notes, tasks and files that are already here.</span></span><span class="onbradio"></span></button>
<button class="onbopt ${fresh?'on':''}" role="radio" aria-checked="${fresh}" data-act="${act}" data-val="1"><span class="onboptico">${lineIco('M12 5v14M5 12h14')}</span><span class="onbopttx"><b>Start fresh as a new user</b><span class="meta">A separate, empty space with its own ${TAURI?'folder':'storage'}. What’s here now stays as it is.</span></span><span class="onbradio"></span></button></div>`;
// Settings → Account: create a local account (optionally encrypted), or manage the one there is.
const accField=(id,lab,ac,type)=>`${L(lab)}<input type="${type||'password'}" id="${id}" autocomplete="${ac}" aria-label="${esc(lab)}" ${accBusy?'disabled':''}>`;
const accSettings=()=>{const a=ACCT,dis=accBusy?'disabled':'';
 if(ACCUI==='recovery')return `<section class="accsec"><h2>Your recovery key</h2><p class="meta" style="margin:0 0 10px">Write it down or keep it somewhere safe, away from this computer. If you forget your password, it’s the only way back in${a&&a.enc?': without either, nobody can open your encrypted data, not even you':''}. It isn’t shown again.</p>
<p class="rkey" data-notr>${esc(ACCRK)}</p><div class="row"><button class="g" data-act="accCopyRk">${lineIco('M8 8h11v11H8zM5 16V5h11')}Copy</button><button class="b" data-act="accRkDone">I’ve saved it</button></div></section>`;
 if(!a){const legacy=CFG.lock&&CFG.lock.hash;
  if(ACCUI==='create'){const own=hasOwnData(),fresh=own&&accFresh,nm=`${L('Your name')}<input type="text" id="accname" value="${esc(accNameDraft)}" autocomplete="name" aria-label="Your name" ${dis}>`;
  return `<section class="accsec"><h2>Create a local account</h2><p class="meta" style="margin:0 0 4px">It stays on your devices: no email, no server. Prodify asks for the password when it opens${TAURI?', on every device that syncs this folder':''}.</p>
${own?accChoice(fresh,'accFreshSet'):''}${nm}${fresh?`<p class="meta" style="margin:8px 0 0">A new user gets their own empty ${TAURI?'folder':'storage'}. Your current notes and files stay as they are, as their own user. You choose the new account’s password next.</p>
<div class="row" style="margin-top:12px"><button class="b" data-act="accFreshGo" ${dis}>Start fresh</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></section>`:`${accField('accpw','Password','new-password')}${accField('accpw2','Repeat the password','new-password')}
<div class="swrow" style="margin-top:12px"><span>Encrypt my data <span class="meta">Notes, journal, tasks, photos and everything else are stored encrypted, so they can only be opened in Prodify with your password or recovery key.</span></span>${swBtn(accEncOn,'data-act="accEncTog"','Encrypt my data')}</div>
<div class="row" style="margin-top:12px"><button class="b" data-act="accCreate" ${dis}>${accBusy?'Creating…':'Create account'}</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></section>`}`}
  return `<section class="accsec"><h2>Account</h2><div class="swrow"><span>Local account <span class="meta">Protect Prodify with a password, and encrypt your data if you like. Everything stays on your devices.</span></span><button class="b" data-act="accUi" data-v="create">Create account</button></div>${legacy?'<p class="meta" style="margin:8px 0 0">Your current password lock is replaced by the account.</p>':''}</section>${legacy?lockSettings():''}`}
 const panel=ACCUI==='enc'?`<div class="accpanel"><p style="margin:0 0 6px">${a.enc?'Decrypt your data? Your files go back to plain Markdown that any app can read.':'Encrypt your data? Every file, photo and backup is rewritten encrypted. Other apps won’t be able to read them.'}</p>${accField('accpw0','Your password','current-password')}<div class="row"><button class="b" data-act="accEncGo" ${dis}>${accBusy?(a.enc?'Decrypting…':'Encrypting…'):a.enc?'Decrypt my data':'Encrypt my data'}</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></div>`
  :ACCUI==='pw'?`<div class="accpanel">${accViaRec?'<p style="margin:0">You unlocked with your recovery key. Choose a new password.</p>':accField('accpw0','Current password','current-password')}${accField('accpw','New password','new-password')}${accField('accpw2','Repeat it','new-password')}<div class="row"><button class="b" data-act="accPwGo" ${dis}>Change password</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></div>`
  :ACCUI==='rk'?`<div class="accpanel"><p style="margin:0 0 6px">The old recovery key stops working.</p>${accField('accpw0','Your password','current-password')}<div class="row"><button class="b" data-act="accRkGo" ${dis}>Make a new recovery key</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></div>`
  :ACCUI==='del'?`<div class="accpanel"><p style="margin:0 0 6px">${a.enc?'Your data is decrypted first, so it stays readable without the account. ':''}Prodify won’t ask for a password anymore.</p>${accField('accpw0','Your password','current-password')}<div class="row"><button class="b" data-act="accDelGo" ${dis}>${accBusy?'Removing…':'Remove account'}</button><button class="g" data-act="accCancel" ${dis}>Cancel</button></div></div>`:'';
 return `<section class="accsec"><h2>Account</h2><div class="acchead"><span class="accav">${esc((a.name||'?').trim()[0]||'?').toUpperCase()}</span><div class="accwho"><b data-notr>${esc(a.name||'Your account')}</b><span class="meta">Local account · ${a.enc?'data encrypted':'not encrypted'}</span></div><button class="g" data-act="lockNow">Lock now</button></div>
${L('Lock after')}${seg('accIdle',[['0','Only at start'],['5','5 min idle'],['15','15 min'],['30','30 min'],['60','1 hour']],String(CFG.accIdle||0))}
<div class="swrow" style="margin-top:10px"><span>Encrypt my data <span class="meta">${a.enc?'Your files, photos and backups are encrypted. They open only in Prodify, with your password or recovery key.':'Your files are plain Markdown that any app can read.'}</span></span>${swBtn(a.enc,'data-act="accUi" data-v="enc"','Encrypt my data')}</div>
<div class="row" style="margin-top:12px"><button class="g" data-act="accUi" data-v="pw">Change password…</button><button class="g" data-act="accUi" data-v="rk">New recovery key…</button><button class="x" data-act="accUi" data-v="del">Remove account…</button></div>${panel}
<p class="meta" style="margin:10px 0 0">Press Ctrl+L to lock Prodify. ${a.enc?'Your data key never leaves this device unencrypted. If you lose both your password and your recovery key, your data can’t be recovered.':'Your password protects the app, but your files stay readable in '+(TAURI?'your Prodify folder':'this browser’s storage')+'.'}</p></section>`};
/* Setup (first run, or Settings → General → Run setup again): a welcome step, one step per section asking whether to
   use it (Use it / Not now updates CFG.tabOff straight away), a look step, and a summary. Done sets CFG.onboarded. */
const ONBF=[
 ['notes','Write notes in Markdown, sort them into categories and tags, link them with [[ ]], and use templates.',['Categories, tags and templates','Links between notes','AI summaries and task finding']],
 ['journal','Write free entries with your mood, answer a daily reflection question, and add photos.',['A mood for each entry','A new question every day','Entries can also show in Notes']],
 ['tasks','Keep tasks in lists, with due dates, reminders and subtasks.',['Lists, smart lists and reminders','Kanban boards','Home cards for any list']],
 ['projects','Group tasks and notes into projects and follow their progress.',['Progress per project','Tasks and notes in one place','Board view for tasks']],
 ['habits','Track yes/no or number habits, daily or weekly, with streaks.',['Daily and weekly goals','Streaks and success rates','Linked to Health']],
 ['health','Log gym workouts with routines and charts, meditate with a timer, and see healthy habits together.',['Multi-day gym routines','Progress charts per exercise','Meditation timer']],
 ['collections','Keep track of books, movies, series, anime and games, with covers, ratings and status.',['Covers pulled from online catalogs','Want to / In progress / Done','Favorites and Home cards']],
 ['calendar','See events, tasks, journal days and notes on a month, week or day calendar.',['Events with times','Month, week and day views','Click a slot to add an event']],
 ['insights','See charts of your mood, writing, tasks and habits over time.',['Mood and writing trends','Tasks finished per week','Habit streaks']],
 ['files','Save links, images and PDFs in one place, next to your Markdown files.',['Paste links, images or PDFs','Pins and favorites','Card or list view']],
 ['music','Listen to radio stations and mix ambient sounds while you work. Needs an internet connection.',['Lofi, ambient and jazz radio','Rain, waves, fire and more','A player in the sidebar']]];
let ONB=null;
// The account step shows when setup starts without an account or a cloud sign-in (and stays while it's in use).
const onbSteps=()=>{if(ONB&&ONB.accStep===undefined)ONB.accStep=!ACCT&&!cloudOn();return ['welcome',...(ONB&&ONB.accStep?['account']:[]),...ONBF.map(f=>f[0]),'look','done']};
// Shows setup on first launch. Off while developing; set to true before building a release.
const ONB_AUTO=false;
function onbShow(){let o=$('onb');if(!ONB){if(o)o.remove();document.body.classList.remove('onboarding');return}
 if(!o){o=document.createElement('div');o.id='onb';o.className='onb';o.setAttribute('role','dialog');o.setAttribute('aria-modal','true');o.setAttribute('aria-label','Set up Prodify');document.body.appendChild(o)}
 document.body.classList.add('onboarding');const st=onbSteps(),i=Math.max(0,Math.min(ONB.i,st.length-1)),id=st[i],n=ONBF.length,fi=ONBF.findIndex(f=>f[0]===id);
 const dots=`<div class="onbdots">${st.map((x,j)=>`<i class="${j===i?'on':j<i?'past':''}"></i>`).join('')}</div>`,back=i?`<button class="circ onbback" data-act="onbGo" data-val="${i-1}" aria-label="Back" title="Back">${lineIco('M15 5l-7 7 7 7')}</button>`:'<span></span>';
 const head=`<div class="onbtop">${back}${dots}<button class="x onbskip" data-act="onbDone">${id==='done'?'':'Skip setup'}</button></div>`;
 const icon=t=>`<span class="onbico" style="--tc:${vivid(secColor(t))}">${symbols()?sym(symName(t)):ico(t)}</span>`;
 let body='';
 if(id==='welcome')body=`<div class="onbhero"><span class="onblogo">P</span><h1>Welcome to Prodify</h1><p class="sub">Notes, journal, tasks, habits and more, saved as plain Markdown files ${TAURI?'on your computer':'in this browser'}. Let’s set it up: choose the parts you want to use. You can change everything later in Settings.</p></div>
${L('What should we call you?')}<input id="onbname" value="${esc(CFG.name||'')}" placeholder="Your name (optional)" autocomplete="off">
<div class="onblang">${L('Language')}${seg('lang',[['en','English'],['es','Español']],CFG.lang==='es'?'es':'en')}</div>
<div class="onbnav"><button class="b onbbig" data-act="onbNext">Let’s go${lineIco('M9 5l7 7-7 7')}</button></div>`;
 else if(id==='account')body=onbAccBody();
 else if(fi>=0){const f=ONBF[fi],t=TABS.find(x=>x[0]===id),on=secOn(id);
  body=`<p class="meta onbcount">Feature ${fi+1} of ${n}</p>${icon(id)}<h1>${t[1]}</h1><p class="onbdesc">${f[1]}</p><ul class="onbpts">${f[2].map(x=>`<li>${lineIco('M5 12.5l4.5 4.5L19 7')}<span>${x}</span></li>`).join('')}</ul>
<p class="meta">Do you want to use ${t[1]}?</p><div class="onbnav two"><button class="g onbbig ${!on?'chosen':''}" data-act="onbPick" data-id="${id}" data-val="off">Not now</button><button class="b onbbig ${on?'chosen':''}" data-act="onbPick" data-id="${id}" data-val="on">${lineIco('M5 12.5l4.5 4.5L19 7')}Use ${t[1]}</button></div>`}
 else if(id==='look')body=`${icon('settings')}<h1>Make it yours</h1><p class="onbdesc">Pick how Prodify looks. There are more themes, colors and fonts in Settings → Appearance.</p>
${L('Mode')}${seg('theme',[['system','System'],['light','Light'],['dark','Dark']],CFG.theme)}
${L('Theme')}<div class="tgrid onbthemes">${Object.keys(THEMES).filter(k=>!THEMES[k].custom).map(themeCard).join('')}</div>
${L('Design style')}${seg('uiStyle',[['default','Prodify'],['accent','Accent'],['colorful','Colorful'],['mono','Black & gray'],['material','Material']],['accent','colorful','mono','material'].includes(CFG.uiStyle)?CFG.uiStyle:'default')}
<div class="onbnav"><button class="b onbbig" data-act="onbNext">Continue${lineIco('M9 5l7 7-7 7')}</button></div>`;
 else{const used=ONBF.filter(f=>secOn(f[0])),off=ONBF.filter(f=>!secOn(f[0]));
  body=`<div class="onbhero"><span class="onblogo done">${lineIco('M5 12.5l4.5 4.5L19 7')}</span><h1>You’re all set${CFG.name?', '+esc(CFG.name):''}</h1><p class="sub">${used.length} of ${n} features are on. Turn any of them on or off later in Settings → Sections.</p></div>
<div class="onbsum">${used.map(f=>`<span class="onbchip">${symbols()?sym(symName(f[0])):ico(f[0])}${TABS.find(x=>x[0]===f[0])[1]}</span>`).join('')}${off.map(f=>`<span class="onbchip off">${symbols()?sym(symName(f[0])):ico(f[0])}${TABS.find(x=>x[0]===f[0])[1]}</span>`).join('')}</div>
<div class="onbnav"><button class="b onbbig" data-act="onbDone">Start using Prodify${lineIco('M9 5l7 7-7 7')}</button></div>`}
 o.innerHTML=`<div class="onbcard">${head}<div class="onbbody">${body}</div></div>`;
 const f=o.querySelector('.onbbig.chosen')||o.querySelector('#onbname')||o.querySelector('.onbnav .b');if(f&&document.activeElement&&!o.contains(document.activeElement))f.focus()}
/* Setup's account step: a local account (the default: no sign-up, optional password and encryption) or Prodify Cloud
   (sync with cloud storage; Free 100 MB, Basic and Pro as subscriptions). ONB.acc keeps the choice and what's typed. */
const onbA=()=>ONB.acc||(ONB.acc={mode:'local',pw:false,enc:true,step:null,email:CFG.cloud&&CFG.cloud.email||'',dev:'',err:'',busy:false,p1:'',p2:'',code:''});
function onbAccSync(){const A=onbA(),g=id=>{const e=$(id);return e?e.value:null};[['onbpw','p1'],['onbpw2','p2'],['onbemail','email'],['onbcode','code']].forEach(([id,k])=>{const x=g(id);if(x!==null)A[k]=x})}
const onbPw=(two,lab)=>`${L(lab||'Password')}<input type="password" id="onbpw" value="${esc(onbA().p1)}" autocomplete="new-password" aria-label="${lab||'Password'}">${two?`${L('Repeat it')}<input type="password" id="onbpw2" value="${esc(onbA().p2)}" autocomplete="new-password" aria-label="Repeat the password">`:''}`;
function onbAccBody(){const A=onbA(),dis=A.busy?'disabled':'',local=A.mode==='local';
 if(A.step==='rk')return `${lineIco('M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z').replace('class="sym"','class="sym onbkey"')}<h1>Your recovery key</h1><p class="onbdesc">Write it down or keep it somewhere safe. If you forget your password, it’s the only way back in${ACCT&&ACCT.enc?': without either, nobody can open your encrypted data':''}. It isn’t shown again.</p><p class="rkey" data-notr>${esc(ACCRK)}</p><div class="row" style="margin:0"><button class="g" data-act="accCopyRk">Copy</button></div><div class="onbnav"><button class="b onbbig" data-act="onbRkDone">I’ve saved it${lineIco('M9 5l7 7-7 7')}</button></div>`;
 const cards=`<div class="onbacc" role="radiogroup" aria-label="Account type">
<button class="onbopt ${local?'on':''}" role="radio" aria-checked="${local}" data-act="onbAcc" data-val="local" ${dis}><span class="onboptico">${lineIco('M4 5h16v11H4zM9 20h6M12 16v4')}</span><span class="onbopttx"><b>Local account <span class="onbtag">Default · Free</span></b><span class="meta">Everything stays on this ${TAURI?'device':'browser'}. No sign-up, works offline. Add a password and encryption if you like.</span></span><span class="onbradio"></span></button>
<button class="onbopt ${local?'':'on'}" role="radio" aria-checked="${!local}" data-act="onbAcc" data-val="cloud" ${dis}><span class="onboptico">${lineIco('M7 18h10a4 4 0 0 0 .6-7.96A6 6 0 0 0 6.1 9.3 4.5 4.5 0 0 0 7 18z')}</span><span class="onbopttx"><b>Prodify Cloud <span class="onbtag plus">Sync</span></b><span class="meta">Sync across your devices with encrypted cloud storage. Start free, and upgrade for more space.</span>
<span class="onbplans"><span><b>Free</b>100 MB</span><span><b>Basic</b>5 GB<em>Subscription</em></span><span><b>Pro</b>50 GB<em>Subscription</em></span></span></span><span class="onbradio"></span></button></div>`;
 let more='',next='';
 if(local&&hasOwnData()&&A.fresh){more=accChoice(true,'onbFreshSet')+`<p class="meta" style="margin:8px 0 0">Prodify opens a new, empty space for you next, where you can set its password.</p>`;next=`<button class="b onbbig" data-act="onbFreshGo">Start fresh${lineIco('M9 5l7 7-7 7')}</button>`}
 else if(local){more=`${hasOwnData()?accChoice(false,'onbFreshSet'):''}<div class="swrow onbpwrow"><span>Protect with a password <span class="meta">Prodify asks for it when it opens. Optional.</span></span>${swBtn(A.pw,'data-act="onbPwT"','Protect with a password')}</div>
${A.pw?`<div class="onbfields">${onbPw(true)}<div class="swrow"><span>Encrypt my data <span class="meta">Your files can only be opened in Prodify, with your password or recovery key.</span></span>${swBtn(A.enc,'data-act="onbEncT"','Encrypt my data')}</div></div>`:''}`;
  next=`<button class="b onbbig" data-act="onbAccNext" ${dis}>${A.busy?'Creating…':'Continue'}${lineIco('M9 5l7 7-7 7')}</button>`}
 else if(!cloudUrl())more='<p class="meta">Prodify Cloud isn’t available in this version yet. Choose a local account for now; you can switch later in Settings.</p>';
 else if(!cloudOn()){more=A.step==='code'?`<div class="onbfields"><p style="margin:0">We sent a 6-digit code to <b data-notr>${esc(A.email)}</b>.</p>${A.dev?`<p class="meta" style="margin:4px 0 0">Test server: your code is <b data-notr>${esc(A.dev)}</b></p>`:''}${L('Code')}<input id="onbcode" value="${esc(A.code)}" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" aria-label="Code"><div class="row"><button class="x" data-act="onbCloudBack" ${dis}>Use another email</button></div></div>`
   :`<div class="onbfields">${L('Your email')}<input id="onbemail" type="email" value="${esc(A.email)}" placeholder="you@example.com" autocomplete="email" aria-label="Email"><p class="meta" style="margin:6px 0 0">No password to remember for the cloud: we email you a sign-in code.</p></div>`;
  next=A.step==='code'?`<button class="b onbbig" data-act="onbCloudVerify" ${dis}>${A.busy?'Signing in…':'Sign in'}${lineIco('M9 5l7 7-7 7')}</button>`:`<button class="b onbbig" data-act="onbCloudStart" ${dis}>${A.busy?'Sending…':'Send me a code'}${lineIco('M9 5l7 7-7 7')}</button>`}
 else if(A.step==='join'){more=`<div class="onbfields"><p style="margin:0">Your cloud already has data. Enter your account password to unlock it on this ${TAURI?'device':'browser'}.</p>${onbPw(false,'Account password').replace('autocomplete="new-password"','autocomplete="current-password"')}</div>`;next=`<button class="b onbbig" data-act="onbCloudJoin" ${dis}>${A.busy?'Unlocking…':'Unlock'}${lineIco('M9 5l7 7-7 7')}</button>`}
 else if(A.step==='create'||!ACCT){more=`<div class="onbfields"><p style="margin:0">Choose a password for your account. Everything is encrypted on this ${TAURI?'device':'browser'} before it’s uploaded, so nobody else can read it.</p>${onbPw(true)}</div>`;next=`<button class="b onbbig" data-act="onbCloudCreate" ${dis}>${A.busy?'Creating…':'Create account'}${lineIco('M9 5l7 7-7 7')}</button>`}
 else{more=`<div class="onbfields onbok">${lineIco('M5 12.5l4.5 4.5L19 7')}<span>Signed in as <b data-notr>${esc(CFG.cloud.email||'')}</b> · your data syncs on the ${(PLANL[(CFG.cloud.me||{}).plan]||'Free')} plan.</span></div>`;next=`<button class="b onbbig" data-act="onbNext">Continue${lineIco('M9 5l7 7-7 7')}</button>`}
 return `<h1>How do you want to keep your data?</h1><p class="onbdesc">You can change this later in Settings → Account and data.</p>${cards}${more}${A.err?`<p class="meta mirerr">${esc(A.err)}</p>`:''}<div class="onbnav">${next}</div>`}
const onbSave=()=>{const n=$('onbname');if(n&&n.value.trim()!==(CFG.name||'')){CFG.name=n.value.trim();saveCfg()}};
/* Backups: a JSON snapshot of every file, kept in <folder>/.prodify-backups (newest 7) in the app, or in IndexedDB in a
   browser. One runs automatically each day (CFG.autoBackup, on by default); any of them can be restored. Photos and PDFs
   (attachments) are not included. */
let BKL=null,bkBusy=false;
const bkIdx=()=>{try{return JSON.parse(localStorage.getItem('prodify.backups'+USUF)||'[]')}catch(e){return[]}};
const BK={write:async(name,data)=>{if(TAURI)return TAURI.invoke('backup_write',{name,data});await IDB.put('backup:'+name,data);const l=[[name,data.length],...bkIdx().filter(x=>x[0]!==name)].sort((a,b)=>b[0].localeCompare(a[0]));l.slice(7).forEach(x=>IDB.put('backup:'+x[0],null));try{localStorage.setItem('prodify.backups'+USUF,JSON.stringify(l.slice(0,7)))}catch(e){}},
 list:async()=>TAURI?TAURI.invoke('backup_list'):bkIdx(),read:async name=>TAURI?TAURI.invoke('backup_read',{name}):IDB.get('backup:'+name)};
async function backupNow(quiet){if(bkBusy||!ACCREADY)return;bkBusy=true;try{const n=new Date(),name=`${TD()}_${pad(n.getHours())}${pad(n.getMinutes())}${quiet==='pre'?'_before-restore':''}`;const js=JSON.stringify({prodifyBackup:1,at:stamp(n),files:FS});await BK.write(name,encOn()?await encText(js):js);CFG.lastBackup=TD();saveCfg();BKL=await BK.list();if(!quiet)toast('Backup saved')}catch(e){if(!quiet)toast('Backup failed: '+(e&&e.message||e))}bkBusy=false;if(view==='settings')render()}
async function backupRestore(name){try{let raw=await BK.read(name);if(isEncT(raw))raw=await decText(raw);const o=JSON.parse(raw||'null');if(!o||!o.files)throw 0;await backupNow('pre');for(const k in FS)delete FS[k];Object.assign(FS,o.files);save();toast('Backup restored · your files before it were backed up too');ND=null;edN=null;render()}catch(e){toast('Could not restore that backup')}}
const bkAuto=()=>{if(CFG.autoBackup!==false&&CFG.lastBackup!==TD()&&Object.keys(FS).length)backupNow(true)};
const bkLabel=n=>{const m=String(n).match(/^(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})(_before-restore)?$/);return m?`${m[1]===TD()?'Today':m[1]===dAdd(TD(),-1)?'Yesterday':fmt(m[1])}, ${tf(m[2]+':'+m[3])}${m[4]?' · before a restore':''}`:n};
function backupSettings(){if(BKL===null){BK.list().then(l=>{BKL=l||[];if(view==='settings')render()}).catch(()=>{BKL=[]})}
 return `<section><h2>Backups</h2><div class="swrow"><span>Daily automatic backup <span class="meta">Keeps the last 7 backups of all your notes, tasks and other files (photos and PDFs aren’t included).</span></span>${swBtn(CFG.autoBackup!==false,'data-act="bkAutoT"','Daily automatic backup')}</div>
<div class="row" style="margin:10px 0"><button class="g" data-act="bkNow">${lineIco('M12 3v12M7 10l5 5 5-5M5 21h14')}Back up now</button><span class="meta">${TAURI?'Saved in your Prodify folder, in .prodify-backups':'Saved in this browser'}</span></div>
${(BKL||[]).length?(BKL||[]).map(([n,sz])=>`<div class="hlrow static"><span class="t"><b>${bkLabel(n)}</b><span class="meta">${(sz/1024).toFixed(0)} KB</span></span><button class="x" data-act="bkRestore" data-val="${esc(n)}">${armed==='bk:'+n?'Click again to restore':'Restore'}</button></div>`).join(''):`<p class="meta">${BKL===null?'Loading…':'No backups yet.'}</p>`}</section>`}
/* Keyboard shortcuts: ? shows them all; g then a letter jumps to a section; q opens quick capture. They work when you
   aren't typing in a field. */
const KSEC=[['h','today'],['n','notes'],['j','journal'],['t','tasks'],['p','projects'],['b','habits'],['e','health'],['c','collections'],['a','calendar'],['i','insights'],['s','files'],[',','settings']];
let kGo=0,KSH=false;
function kbShow(){let o=$('kbhelp');if(!KSH){if(o)o.remove();return}if(!o){o=document.createElement('div');o.id='kbhelp';o.className='onb';o.setAttribute('role','dialog');o.setAttribute('aria-label','Keyboard shortcuts');document.body.appendChild(o)}
 const k=x=>x.split('+').map(y=>`<kbd>${y}</kbd>`).join(' ');const row=(keys,l)=>`<div class="kbrow"><span>${l}</span><span>${keys}</span></div>`;
 o.innerHTML=`<div class="onbcard kbcard"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Keyboard shortcuts</h2><button class="cx" data-act="kbClose" aria-label="Close" title="Close (Esc)">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
<p class="meta kbh">Anywhere</p>${row(k('Ctrl+K'),'Search or run a command')+row(k('q'),'Quick capture')+row(k('Ctrl +')+' '+k('Ctrl −'),'Zoom in / out')+row(k('Ctrl 0'),'Reset zoom')+row(k('?'),'Show these shortcuts')+(CFG.lock&&CFG.lock.hash?row(k('Ctrl+L'),'Lock Prodify'):'')+row(k('Esc'),'Close a menu or panel')}
<p class="meta kbh">Go to (press g, then the letter)</p><div class="kbgrid">${KSEC.filter(([,v])=>v==='settings'||secOn(v)).map(([key,v])=>row(k('g')+' '+k(key),(TABS.find(x=>x[0]===v)||[])[1]||v)).join('')}</div>
<p class="meta kbh">Notes</p>${row(k('Ctrl+E'),'Switch between View and Edit')+row(k('[[')+'','Link to a note, project or item')}</div>`}
document.addEventListener('keydown',e=>{if(e.ctrlKey||e.metaKey||e.altKey||PWLOCK||ONB)return;const t=e.target;if(t&&(t.closest&&t.closest('input,textarea,select,[contenteditable="true"]')))return;
 if(KSH&&e.key==='Escape'){KSH=false;kbShow();e.preventDefault();return}
 if(e.key==='?'){KSH=!KSH;kbShow();e.preventDefault();return}
 if(kGo&&Date.now()-kGo<1500){kGo=0;const m=KSEC.find(([x])=>x===e.key.toLowerCase());if(m&&(m[1]==='settings'||secOn(m[1]))){e.preventDefault();flushNote&&flushNote();view=m[1];hq='';window.scrollTo(0,0);render()}return}
 if(e.key==='g'){kGo=Date.now();e.preventDefault();return}
 if(e.key==='q'&&!QC){e.preventDefault();QC={text:'',type:'auto',f:{}};qcShow()}});
document.addEventListener('pointerdown',e=>{if(KSH&&e.target.id==='kbhelp'){KSH=false;kbShow()}});
/* Pasting into the Home search bar never saves on its own. A link or text lands in the bar with a "Save" row on
   top of the results (links → Storage › Links, text → a new note, first line as the title); images and PDFs wait in
   a tray under the bar. Enter or the Save button saves; a toast then offers Open and Undo. */
let HQP=null;
const hqNorm=x=>x.replace(/\s+/g,' ').trim();
function hqOffer(){if(HQP&&HQP.files)return 'files';const q=hq.trim();if(!q||q.startsWith('/'))return '';const u=stUrl(q);if(u&&!/\s/.test(q))return stRead('links').some(x=>urlKey(x.url)===urlKey(u))?'had':'link';
 return HQP&&HQP.txt&&hqNorm(HQP.txt)===hqNorm(q)?'text':''}
const hqSaveRow=()=>{const o=hqOffer(),q=hq.trim(),u=stUrl(q);if(!o||o==='files')return '';
 if(o==='had')return `<div class="hqsave"><span class="hqsico">${uiIco('link-simple','🔗')}</span><span class="hqstxt"><b>Already in Storage</b><span class="meta" data-notr>${esc(host(u))}</span></span><button class="g" data-act="hqOpenLink">Open</button></div>`;
 return `<div class="hqsave"><span class="hqsico">${o==='link'?uiIco('link-simple','🔗'):uiIco('note','📝')}</span><span class="hqstxt"><b>${o==='link'?'Save link to Storage':'Save as a note'}</b><span class="meta" data-notr>${esc(o==='link'?host(u):(HQP.txt.split('\n')[0].replace(/^#+\s*/,'').slice(0,80)))}</span></span><span class="meta hqsenter">${lineIco('M9 10l-5 5 5 5M20 4v7a4 4 0 0 1-4 4H4')}Enter</span><button class="b" data-act="hqSave">${lineIco('M5 12.5l4.5 4.5L19 7')}Save</button></div>`};
const hqTray=()=>!(HQP&&HQP.files)?'':`<section class="sttray hqtray"><div class="sttitems">${HQP.files.map((x,i)=>`<div class="sttitem"><span class="sttthumb">${x.kind==='images'?`<img src="${x.url}" alt="">`:'<b>PDF</b>'}<button class="stchx" data-act="hqUnstage" data-i="${i}" aria-label="Remove" title="Remove">${lineIco('M6 6l12 12M18 6L6 18')}</button></span><span class="meta" data-notr>${esc((x.f.name||'').replace(/\.[^.]+$/,'')||(x.kind==='images'?'Image':'PDF'))}</span></div>`).join('')}</div>
<div class="sttbar"><span class="meta">${lineIco('M9 10l-5 5 5 5M20 4v7a4 4 0 0 1-4 4H4')}Press Enter to save ${HQP.files.length===1?(HQP.files[0].kind==='images'?'this image':'this PDF'):HQP.files.length+' items'} to Storage · Esc to cancel</span><span class="row" style="margin:0;gap:8px"><button class="g" data-act="hqCancel">Cancel</button><button class="b" data-act="hqSave">${lineIco('M5 12.5l4.5 4.5L19 7')}Save${HQP.files.length>1?' '+HQP.files.length:''}</button></span></div></section>`;
function hqClear(){if(HQP&&HQP.files)HQP.files.forEach(x=>x.url&&URL.revokeObjectURL(x.url));HQP=null}
async function hqSave(){const o=hqOffer();if(!o||o==='had')return false;
 if(o==='files'){const p=HQP.files,im=p.filter(x=>x.kind==='images').map(x=>x.f),pd=p.filter(x=>x.kind==='pdfs').map(x=>x.f);hqClear();render();
  const add=[...(im.length?await stAddFiles('images',im):[]),...(pd.length?await stAddFiles('pdfs',pd):[])];if(!add.length)return true;
  toastAct(`${add.length===1?(add[0].k==='images'?'Image':'PDF'):add.length+' files'} saved to Storage`,[['Open',()=>{view='files';stTab=add.length===1?add[0].k:'all';stQ='';render()}],['Undo',()=>{['images','pdfs'].forEach(kd=>stWrite(kd,stRead(kd).filter(x=>!add.some(a=>a.att===x.att))));save();render();toast('Removed')}]]);return true}
 if(o==='link'){const u=stUrl(hq.trim());hq='';hqClear();await stAddLink(u);render();
  toastAct('Link saved to Storage',[['Open',()=>{view='files';stTab='links';stQ='';render()}],['Undo',()=>{stWrite('links',stRead('links').filter(x=>urlKey(x.url)!==urlKey(u)));save();render();toast('Removed')}]]);return true}
 const txt=HQP.txt.trim(),l=txt.split('\n'),ttl=l[0].replace(/^#+\s*/,'').slice(0,80).trim()||'Pasted text',rest=l[0].length>80?txt:l.slice(1).join('\n').trim(),k=noteKeyFor('notes/',ttl,TD());
 FS[k]=`---\ncreated: ${TD()}\n---\n# ${ttl}\n\n${rest}\n`;hq='';hqClear();save();render();
 toastAct('Saved to Notes',[['Open',()=>{view='notes';nmode='notes';edN=k;ND=null;render()}],['Undo',()=>{delete FS[k];save();render();toast('Removed')}]]);return true}
document.addEventListener('paste',e=>{if(e.target.id!=='hq')return;const cd=e.clipboardData;if(!cd)return;const fs=[...(cd.files||[])];
 if(fs.length){e.preventDefault();const ok=fs.filter(f=>f.type.startsWith('image/')||f.type==='application/pdf'||/\.pdf$/i.test(f.name||''));if(!ok.length){toast('Only images and PDFs can be saved from here');return}
  if(!(HQP&&HQP.files))hqClear();HQP={files:[...(HQP&&HQP.files||[]),...ok.map(f=>{const img=f.type.startsWith('image/');return{f,kind:img?'images':'pdfs',url:img?URL.createObjectURL(f):''}})]};rerenderKeep();return}
 // Text is pasted as usual; remember it (with its line breaks) so it can be saved as a note.
 const txt=(cd.getData('text/plain')||'').trim();if(txt&&!e.target.value.trim())HQP={txt}});
// AI tools for a note: a summary, category suggestions (from your categories), and action items to add as tasks.
let AIN=null,aiMenu=false;
async function aiNote(kind){const k=edN;aiMenu=false;if(!k||!FS[k])return;const S=aiFn();if(!S){toast(TAURI?'Add your Anthropic API key in Settings → Integrations':'AI isn’t available here');render();return}
 const n=readNote(FS[k]),body=n.body.slice(0,12000),es=CFG.lang==='es'?' Write in Spanish (Spain).':'',ask=p=>S(p,{modelTier:'quick',cache:false}).then(r=>(r&&r.text||'').trim());AIN={k,kind,busy:true};render();
 try{if(kind==='sum')AIN={k,kind,text:await ask(`Summarize this note in 2 to 4 short bullet points, each starting with "- ". Plain and specific, no preamble.${es}\n\n${body}`)};
  else if(kind==='cats'){const have=(n.fm.categories||[]).map(x=>String(x).toLowerCase()),opts=[...allCats('notes').values()].map(c=>c.name);
   const t=await ask(`Pick up to 3 categories for this note from this list: ${opts.join(', ')}. Reply with the names only, separated by commas. If none fit, reply with one short new category name.\n\nNote:\n${body}`);
   AIN={k,kind,items:[...new Set(t.split(/[,\n]/).map(x=>x.replace(/^[-*\s"']+|["'\s.]+$/g,'').trim()))].filter(x=>x&&x.length<40&&!have.includes(x.toLowerCase())).slice(0,4)}}
  else{const t=await ask(`List the action items in this note as short tasks, one per line, each starting with "- ". Only things someone should do. If there are none, reply with the word none.${es}\n\n${body}`);
   AIN={k,kind,items:t.split('\n').map(x=>x.replace(/^[-*\d.)\s]+/,'').trim()).filter(x=>x&&!/^(none|ninguna?)\.?$/i.test(x)&&x.length<160).slice(0,12)}}}
 catch(e){AIN=null;toast('AI: '+(e&&e.message||e))}
 if(view==='notes')render()}
const aiTools=k=>{const menu=`<span class="aiwrap"><button class="g aibtn" data-act="aiMenu" aria-expanded="${aiMenu}" title="AI tools">${symbols()?sym('sparkle'):'✨'}AI</button>${aiMenu?`<span class="dmenu aimenu" role="menu"><button data-act="aiNote" data-val="sum" role="menuitem">Summarize</button><button data-act="aiNote" data-val="cats" role="menuitem">Suggest categories</button><button data-act="aiNote" data-val="tasks" role="menuitem">Find tasks</button></span>`:''}</span>`;
 if(!AIN||AIN.k!==k)return {menu,panel:''};
 const close=`<button class="cx" data-act="aiClose" aria-label="Close" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button>`,head=t=>`<div class="aihead"><b>${symbols()?sym('sparkle'):'✨'} ${t}</b>${close}</div>`;
 const panel=AIN.busy?`<div class="aipanel"><p class="meta aithink">Thinking…</p></div>`
  :AIN.kind==='sum'?`<div class="aipanel">${head('Summary')}<div class="md">${md(AIN.text||'')}</div><div class="row"><button class="g" data-act="aiSumAdd">Add to note</button></div></div>`
  :AIN.kind==='cats'?`<div class="aipanel">${head('Suggested categories')}${AIN.items.length?`<div class="row" style="margin:0;gap:6px">${AIN.items.map(c=>`<button class="chip clink" data-act="aiCat" data-v="${esc(c)}">+ ${esc(c)}</button>`).join('')}</div>`:'<p class="meta">No new categories to suggest.</p>'}</div>`
  :`<div class="aipanel">${head('Tasks found')}${AIN.items.length?`<ul class="aitasks">${AIN.items.map(x=>`<li data-notr>${esc(x)}</li>`).join('')}</ul><div class="row">${secOn('tasks')?`<button class="b" data-act="aiTasksAdd">Add ${AIN.items.length} to Tasks</button>`:''}</div>`:'<p class="meta">No action items in this note.</p>'}</div>`;
 return {menu,panel}};
document.addEventListener('pointerdown',e=>{if(aiMenu&&!(e.target.closest&&e.target.closest('.aiwrap'))){aiMenu=false;setTimeout(()=>{if(view==='notes')render()})}});
// Notes and entries that link to this one.
const wlBack=k=>{if(!k||!FS[k])return '';const f=fold(noteTitle(k)),re=/\[\[([^\]|\n]+)(?:\|[^\]\n]+)?\]\]/g,from=[...keys('notes/'),...entKeys()].filter(x=>x!==k&&[...(FS[x]||'').matchAll(re)].some(m=>fold(m[1].trim())===f));
 return from.length?`<div class="wlback"><p class="meta">Linked from</p>${from.map(x=>`<button class="wl wl-${isJE(x)?'journal':'note'}" data-act="wlGo" data-kind="note" data-v="${esc(x)}"><span class="wli">${symbols()?sym(isJE(x)?'notebook':'note'):'📝'}</span><span class="wlt">${esc(noteTitle(x))}</span></button>`).join('')}</div>`:''};
const noteViewer=n=>{const props=Object.entries(n.fm).filter(([k])=>k!=='pinned'&&k!=='daily').map(([k,v])=>propView(k,v)).join(''),ai=aiTools(edN);
 return `<section class="neditor nview"><div class="head" style="margin:0 0 10px;gap:12px;align-items:flex-start"><h1 class="ntitle">${esc(n.title)||'<span style="color:var(--mut)">Untitled</span>'}</h1><span class="ntools">${edN&&!isJE(edN)?`<button class="cx rbtn ${histOpen?'on':''}" data-act="histT" aria-label="Version history" title="Version history">${lineIco('M12 7v5l3 2M3.5 12a8.5 8.5 0 1 0 2.5-6M3 4v4h4')}</button>`:''}${ai.menu}${modeSeg()}</span></div>
${dailyNav(n)}${props?`<div class="props">${props}</div>`:''}${histPanel(edN)}${ai.panel}<div class="md mdview" title="Double-click to edit">${n.body.trim()?md(n.body):'<p class="empty">This note is empty. Switch to Edit to write.</p>'}</div>${wlBack(edN)}
${edN&&CFG.notesView==='panel'?`<div class="row"><span style="flex:1"></span><button class="x" data-act="pin" data-k="${esc(edN)}">${isPinned(edN)?'Unpin':'Pin'}</button><button class="x" data-act="delF" data-k="${esc(edN)}">${armed===edN?'Click again to delete':'Delete'}</button></div>`:''}</section>`};
const noteEditor=()=>{const n=draft(),isT=!!edN&&isTplKey(edN),tpls=keys('templates/').sort(),panel=CFG.notesView==='panel'&&!isT;
 if(nViewK!==edN){nViewK=edN;nView=!!edN&&!isT&&CFG.noteOpen==='view'}
 if(nView&&edN)return noteViewer(n);
 return `<section class="neditor">${isT?`<p class="meta" style="margin:0 0 2px">Template: ${esc(tplName(edN))}</p>`:''}<div class="head" style="margin:0 0 10px;gap:12px;align-items:flex-start"><input id="ntitle" class="ntitle" value="${esc(n.title)}" placeholder="${isT?'Title new notes start with (optional)':'Untitled'}" aria-label="${isT?'Template title':'Note title'}"><span class="ntools">${edN&&!isT?modeSeg():''}<span id="nstat" class="meta" aria-live="polite">${n.k?'Saved':''}</span></span>${!edN&&tpls.length?`<label class="meta" style="display:flex;gap:8px;align-items:center">Template <select id="ntpl"><option value="">Blank</option>${tpls.map(k=>`<option value="${esc(k)}" ${n.tpl===k?'selected':''}>${esc(tplName(k))}</option>`).join('')}</select></label>`:''}</div>
${propsPanel()}${mdBar()}<textarea id="nb" class="mono" placeholder="${isT?'Text that new notes start with (optional)':'Write in Markdown'}">${esc(n.body)}</textarea>
<div class="row">${edN?`<button class="g" data-act="cancel">${isT?'Close':'New note'}</button>`:''}${edN&&panel?`<span style="flex:1"></span><button class="x" data-act="pin" data-k="${esc(edN)}">${isPinned(edN)?'Unpin':'Pin'}</button><button class="x" data-act="delF" data-k="${esc(edN)}">${armed===edN?'Click again to delete':'Delete'}</button>`:''}</div>${dataLists()}</section>`};
const noteChips=k=>{const f=readNote(FS[k]).fm,c=f.categories||[],t=f.tags||[];if(!c.length&&!t.length)return '';
 return `<div class="nchips">${c.map(x=>`<button class="clink" data-act="openCat" data-v="${esc(x)}">${esc(x)}</button>`).join('')}${t.map(x=>`<button class="chip tagc clink" data-act="tagGo" data-v="${esc(x)}">${esc(x)}</button>`).join('')}</div>`};
// Sort switch shown with the list of notes itself (panel list and above the cards).
const focusNew=()=>{const el=$(CFG.newNoteFocus==='body'?'nb':'ntitle');if(!el)return;el.focus();const n=el.value.length;try{el.setSelectionRange(n,n)}catch(e){}};
const sortBar=()=>`<div class="nsort"><span class="meta">Sort</span>${seg('notesSort',[['date','Date created'],['alpha','A–Z']],CFG.notesSort)}</div>`;
const wlPlain=t=>String(t).replace(/\[\[([^\]|\n]+)(?:\|([^\]\n]+))?\]\]/g,(_,a,b)=>b||a);
const nItem=k=>{const l=noteLines(k).map(wlPlain),d=noteDate(k);return `<button class="nli ${edN===k?'on':''}" data-act="editN" data-k="${esc(k)}" data-note="${esc(k)}"><b>${esc(wlPlain(noteTitle(k)))}</b><span class="meta">${d?fmt(d):esc(k.replace(/^[^/]+\//,'').slice(0,-3))}${l.length>1?' · '+esc(l.slice(1).join(' ').slice(0,80)):''}</span></button>`};
const arch=()=>nmode==='archive';
const notePanel=ks=>{const p=ks.filter(isPinned),o=ks.filter(k=>!isPinned(k)),lab=t=>`<p class="meta nlab">${t}</p>`;
 return `<div class="npanel"><aside class="nlist"><span class="sbox"><input id="q" placeholder="Search notes" value="${esc(q)}">${q?`<button class="sclr" data-act="sclr" data-for="q" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span>${arch()?'':'<button class="g" data-act="newN">+ New note</button>'}${sortBar()}
${p.length?lab('Pinned')+p.map(nItem).join('')+(o.length?lab('Notes'):''):''}${o.map(nItem).join('')}${ks.length?'':`<p class="empty" style="padding:8px">${q||tagF?'No notes match.':'No notes yet.'}</p>`}</aside>
<div class="nedit">${arch()&&!edN?'<section><p class="empty">Select an archived note to read or edit it. Right-click it to unarchive or delete it.</p></section>':noteEditor()}</div></div>`};
// A category's page lists every note in it, like an Obsidian category note.
// Category covers: a colored cover with the category's icon, like the covers in Collections.
const catColor=n=>{let h=0;for(const ch of String(n).toLowerCase())h=(h*31+ch.charCodeAt(0))>>>0;return LCOLORS[h%LCOLORS.length]};
const catLast=ks=>ks.map(noteDate).filter(Boolean).sort().pop()||'';
const catCover=(name,n,big)=>`<span class="ccov catcov ${big?'big':''}" style="--cc:${vivid(catColor(name))}"><span class="catcovi">${catIco(name)}</span>${n?`<span class="cbadge">${n}</span>`:''}</span>`;
const catCard=c=>{const l=catLast(c.keys);return `<button class="ccard catcard" data-act="openCat" data-v="${esc(c.name)}" data-cat="${esc(c.name)}">${catCover(c.name,c.keys.length)}<b data-notr>${esc(c.name)}</b><span class="meta">${c.keys.length} note${c.keys.length===1?'':'s'}${l?' · '+fmt(l,{month:'short',day:'numeric'}):''}</span></button>`};
// A note as a small page: its title and first lines on a paper-like cover, the date under it.
const noteCard=k=>{const l=noteLines(k).map(wlPlain),d=noteDate(k),pv=l.slice(1).join(' ').replace(/[#*_>`~\[\]]/g,'').trim().slice(0,220);
 return `<button class="ccard ncv" data-act="openNote" data-k="${esc(k)}" data-note="${esc(k)}"><span class="ncvp">${isPinned(k)?`<span class="cnpin">${sym('push-pin')}</span>`:''}<b>${esc(noteTitle(k))}</b><span>${esc(pv)}</span></span><span class="meta">${isJE(k)?'Journal · ':''}${d?fmt(d):''}</span></button>`};
// Each note is a grouped row: title (with a pin when pinned), a line of its text, the date and a chevron.
const cnRow=k=>{const l=noteLines(k).map(wlPlain),d=noteDate(k),pv=l.slice(1).join(' ').replace(/[#*_>`~\[\]]/g,'').trim().slice(0,140);
 return `<button class="lrow cnrow" data-act="openNote" data-k="${esc(k)}" data-note="${esc(k)}"><span class="cnt"><b>${isPinned(k)?`<span class="cnpin" title="Pinned">${sym('push-pin')}</span>`:''}${esc(noteTitle(k))}</b>${pv?`<span class="meta">${esc(pv)}</span>`:''}</span>${isJE(k)?'<span class="cntag">Journal</span>':''}<span class="meta cnd">${d?fmt(d):''}</span><span class="lrch" aria-hidden="true">›</span></button>`};
const catView=()=>{const ix=allCats();
 if(selCat){const e=ix.get(selCat.toLowerCase()),ks=e?e.keys.slice().sort((a,b)=>alpha(noteTitle(a),noteTitle(b))):[];
  const nm=e?e.name:selCat,grid=CFG.catNotes!=='list',l=catLast(ks);
  return `${catEd&&catEd.sc!=='journal'?catEditor():''}<div class="catdhead">${catCover(nm,undefined,1)}<div class="catdinfo">${NAVH.length?backBtn('catAll','All categories','All categories'):'<button class="x" data-act="catAll" style="margin-left:-6px">← All categories</button>'}<h1 data-notr>${esc(nm)}</h1><p class="meta">${ks.length} note${ks.length===1?'':'s'}${l?' · last on '+fmt(l):''}</p>
<div class="row" style="margin:8px 0 0"><button class="g" data-act="catEditPage" data-v="${esc(nm)}">Edit category</button></div></div></div>
${(()=>{/* the same list and editor as Notes, showing this category's notes; new notes start in it */const fk=sortNotes(ks.filter(k=>FS[k].toLowerCase().includes(q.toLowerCase())));
 return CFG.notesView==='panel'?notePanel(fk):`${noteEditor()}<div class="row" style="margin:0 0 16px;align-items:center"><span class="sbox"><input id="q" placeholder="Search notes" value="${esc(q)}">${q?`<button class="sclr" data-act="sclr" data-for="q" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span>${sortBar()}</div>${fk.length?noteBoards(fk):'<section><p class="empty">No notes in this category yet. Write one above and it’s added here.</p></section>'}`})()}`}
 const cs=[...ix.values()].sort(CFG.catSort==='count'?(a,b)=>b.keys.length-a.keys.length||alpha(a.name,b.name):(a,b)=>alpha(a.name,b.name)),list=CFG.catView==='list';
 const pseg=(k,o,c,lab)=>`<div class="pseg" role="group" aria-label="${lab}">${o.map(([v,l,ic])=>`<button data-act="set" data-s="${k}" data-val="${v}" class="${c===v?'on':''}" aria-pressed="${c===v}">${sym(ic)}${l}</button>`).join('')}</div>`;
 const bar=`<div class="catbar">${pseg('catView',[['covers','Covers','book-open'],['tiles','Tiles','squares-four'],['list','List','list-bullets']],list?'list':CFG.catView==='tiles'?'tiles':'covers','View')}${pseg('catSort',[['alpha','A–Z','sort-ascending'],['count','Most notes','sort-descending']],CFG.catSort==='count'?'count':'alpha','Sort')}<span style="flex:1"></span><button class="circ" data-act="catNew" aria-label="New category" title="New category">${lineIco('M12 5v14M5 12h14')}</button></div>`;
 const body=!cs.length?'<section><p class="empty">No categories yet. Press + to create one.</p></section>'
  :list?`<section class="catlist">${cs.map(c=>`<button class="catrow" data-act="openCat" data-v="${esc(c.name)}" data-cat="${esc(c.name)}"><span class="catri">${catIco(c.name)}</span><span class="catrn">${esc(c.name)}</span><span class="meta">${c.keys.length} note${c.keys.length===1?'':'s'}</span></button>`).join('')}</section>`
  :CFG.catView==='tiles'?`<div class="ntabs cattiles">${cs.map(c=>catTile(c.name,c.keys.length)).join('')}</div>`:`<div class="cgrid catgrid">${cs.map(catCard).join('')}</div>`;
 return bar+(catEd&&catEd.sc!=='journal'?catEditor():'')+body};
const trashView=()=>{trashPurge();const ks=keys('trash/').sort((a,b)=>String(readNote(FS[b]).fm.deleted||'').localeCompare(String(readNote(FS[a]).fm.deleted||''))),where=f=>/^archive\//.test(f)?'Archived':/^templates\//.test(f)?'Templates':'Notes';
 return `<section><div class="head" style="margin:0 0 ${ks.length?'10':'0'}px;align-items:center"><p class="meta" style="margin:0">Deleted notes stay here for ${TRASH_DAYS} days, then they’re removed for good. Restore one to put it back where it was.</p>${ks.length?'<button class="g" data-act="trashEmpty">Empty Trash</button>':''}</div>
${ks.map(k=>{const f=readNote(FS[k]).fm,left=trashLeft(k),l=noteLines(k);return `<div class="trow"><div class="t"><b data-notr>${esc(wlPlain(noteTitle(k)))}</b><span class="meta">From ${where(String(f.from||''))} · deleted ${fmt(String(f.deleted||TD()).slice(0,10))} · ${left} day${left===1?'':'s'} left</span>${l[1]?`<span class="meta tprev" data-notr>${esc(wlPlain(l[1]).slice(0,140))}</span>`:''}</div><span class="row" style="margin:0;gap:6px;flex:none"><button class="g" data-act="trashRestore" data-k="${esc(k)}">Restore</button><button class="x trdel" data-act="trashDel" data-k="${esc(k)}">Delete forever</button></span></div>`}).join('')||'<p class="empty" style="margin-top:10px">Trash is empty.</p>'}</section>`};
const tagView=()=>{const ts=[...propIndex('tags').values()].sort((a,b)=>alpha(a.name,b.name));
 return `<section><div class="nchips" style="margin:0">${ts.map(t=>`<button class="chip tagc clink" data-act="tagGo" data-v="${esc(t.name)}">${esc(t.name)} <span class="meta">${t.keys.length}</span></button>`).join('')||'<p class="empty">No tags yet. Add some in a note’s Tags property.</p>'}</div></section>`};
const tplSummary=k=>{const f=readNote(FS[k]).fm,parts=[];if((f.tags||[]).length)parts.push('tags: '+f.tags.join(', '));if((f.categories||[]).length)parts.push('categories: '+f.categories.join(', '));
 const n=Object.keys(f).length;parts.push(n+' propert'+(n===1?'y':'ies'));return esc(parts.join(' · '))};
const tplView=()=>{const ts=keys('templates/').sort();
 return `<section><h2>Templates</h2><p class="meta" style="margin:0 0 10px">A template is a note whose properties and text are copied into new notes. {{date}} and {{time}} are filled in when you use it. Templates are saved in the templates folder.</p>
${ts.map(k=>`<div class="item"><div class="t"><b>${esc(tplName(k))}</b><span class="meta">${tplSummary(k)}${CFG.defaultTpl===k?' · default for new notes':''}</span></div>${CFG.defaultTpl===k?'':`<button class="x" data-act="tplDef" data-k="${esc(k)}">Make default</button>`}<button class="x" data-act="tplUse" data-k="${esc(k)}">New note</button><button class="x" data-act="editN" data-k="${esc(k)}">Edit</button><button class="x" data-act="delF" data-k="${esc(k)}">${armed===k?'Click again to delete':'Delete'}</button></div>`).join('')||'<p class="empty">No templates yet.</p>'}
<div class="row"><input id="tplNew" placeholder="New template name"><button class="b" data-act="tplAdd">Create template</button>${ts.length?'':'<button class="g" data-act="tplStarter">Add starter template</button>'}</div></section>
${edN&&isTplKey(edN)?noteEditor():''}`};
V.notes=()=>{if(edN&&!FS[edN])edN=null;if(CFG.defaultTpl&&!FS[CFG.defaultTpl])CFG.defaultTpl='';
 const head=`<div class="lnav"><h1 style="margin:0">Notes</h1><button class="g dailybtn" data-act="dailyGo" data-d="${TD()}">${symbols()?sym('calendar-check'):'📅'}Today’s note</button></div>${notesBar()}`;
 if(nmode==='trash')return head+trashView();if(nmode==='categories')return head+catView();if(nmode==='tags')return head+tagView();if(nmode==='templates')return head+tplView();
 const tl=tagF&&tagF.toLowerCase(),ks=sortNotes([...keys(arch()?'archive/':'notes/'),...(!arch()&&CFG.jInNotes!==false&&secOn('journal')?entKeys():[])].filter(k=>FS[k].toLowerCase().includes(q.toLowerCase())&&(!tl||(readNote(FS[k]).fm.tags||[]).some(t=>t.toLowerCase()===tl))));
 const tf=tagF?`<div class="row" style="margin:-4px 0 14px"><span class="meta">Showing notes tagged</span><span class="chip tagc">${esc(tagF)}<button class="cx" data-act="tagClear" aria-label="Show all notes">×</button></span></div>`:'';
 return head+tf+(CFG.notesView==='panel'?notePanel(ks):`${arch()&&!edN?'':noteEditor()}
<div class="row" style="margin:0 0 16px;align-items:center"><span class="sbox"><input id="q" placeholder="Search notes" value="${esc(q)}">${q?`<button class="sclr" data-act="sclr" data-for="q" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span>${sortBar()}</div>
${noteBoards(ks)}`)};

// One card per entry (newest first), with that moment's mood (click to change), categories, text and location;
// older day files show as before. The category tiles at the top filter both.
// Entries are read-only until Edit: then mood, categories, text and location can be changed (Save / Cancel).
let jeEd=null;
const jeCard=e=>{const k=e.k,ed=jeEd===k,m=e.mood?MOOD[e.mood-1]:null;
 const head=`<div class="head" style="margin:0;gap:10px;flex-wrap:wrap"><b style="font-size:17px">${fmt(e.date,LONG)}${e.time?` <span class="meta" style="font-size:14px">· ${esc(tf(e.time))}</span>`:''}</b>
${ed?`<div class="jemood" role="group" aria-label="Mood">${MOOD.map((mm,i)=>`<button data-act="jeMood" data-k="${esc(k)}" data-n="${i+1}" class="${e.mood===i+1?'on':''}" aria-pressed="${e.mood===i+1}" title="${mm[0]}"><span class="dot" style="background:var(${mm[1]})"></span>${e.mood===i+1?mm[0]:''}</button>`).join('')}</div>`
  :m?`<span class="jemoodro"><span class="dot" style="background:var(${m[1]})"></span>${m[0]}</span>`:''}</div>`;
 if(ed)return `<section class="jent editing">${head}<p class="meta" style="margin:8px 0 4px">Emotions</p>${emoChips(e.emos,'jeEmoE',k)}${jCatPick(k,e.cats)}
<textarea id="jeb" class="mono" aria-label="Entry text" style="min-height:110px;margin-top:6px">${esc(e.body.trim())}</textarea>
<label class="jlocin">${sym('map-pin')}<input id="jel" value="${esc(e.loc)}" placeholder="Add location" list="dl-places" autocomplete="off" aria-label="Location"></label><datalist id="dl-places">${places().map(x=>`<option value="${esc(x)}">`).join('')}</datalist>
<div class="row"><button class="b tick" data-act="jeSave" data-k="${esc(k)}" aria-label="Save" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="jeCancel">Cancel</button></div></section>`;
 return `<section class="jent">${head}${emoRead(e.emos)}${e.cats.length?`<div class="cattiles jcatro">${e.cats.map(x=>catTile(x,undefined,1,'journal')).join('')}</div>`:''}<div class="md">${md(e.body)}</div>${e.loc?`<p class="jloc">${sym('map-pin')}<span>${esc(e.loc)}</span></p>`:''}
<div class="row"><button class="x" data-act="jeEdit" data-k="${esc(k)}">Edit</button><button class="x" data-act="jeOpen" data-k="${esc(k)}">Open in Notes</button><button class="x" data-act="delF" data-k="${esc(k)}">${armed===k?'Click again to delete':'Delete'}</button></div></section>`};
const jMoodCard=(d,l)=>`<section class="jmoods"><div class="head" style="margin:0"><b style="font-size:17px">${fmt(d,LONG)}</b><span class="meta">${l.length} mood check-in${l.length===1?'':'s'}</span></div><div class="mclist">${l.slice().reverse().map(mcRow).join('')}</div></section>`;
/* Journal → Emotions: log how you feel, then track it over 7/30/90 days or a year: average mood per day,
   the emotions you name most, how the levels split, and the log itself. Data: journal/moods.md. */
function jEmotions(){const t=TD(),from=dAdd(t,-(jer-1)),l=moodsRead().filter(x=>x.d>=from&&x.d<=t);
 const rng=`<div class="moods seg emorng">${[[7,'7 days'],[30,'30 days'],[90,'90 days'],[365,'Year']].map(([n,lab])=>`<button data-act="jer" data-val="${n}" class="${jer===n?'on':''}" aria-pressed="${jer===n}">${lab}</button>`).join('')}</div>`;
 if(!l.length)return `${writeBox(2)}${rng}<section><p class="empty">No mood check-ins in this period. Pick how you feel above to log one.</p></section>`;
 const avg=l.reduce((a,x)=>a+x.m,0)/l.length,am=MOOD[Math.round(avg)-1],cnt={};l.forEach(x=>x.emos.forEach(e=>cnt[e]=(cnt[e]||0)+1));
 const top=Object.entries(cnt).sort((a,b)=>b[1]-a[1]||alpha(a[0],b[0])),pos=top.filter(([e])=>emoKind(e)==='pos').reduce((a,x)=>a+x[1],0),tot=top.reduce((a,x)=>a+x[1],0);
 const stats=`<div class="emostats"><div><b>${l.length}</b><span class="meta">check-in${l.length===1?'':'s'}</span></div><div><b class="emoavg"><span class="dot" style="background:var(${am[1]})"></span>${am[0]}</b><span class="meta">average mood</span></div><div><b>${tot?Math.round(pos/tot*100)+'%':'–'}</b><span class="meta">positive emotions</span></div></div>`;
 // Average mood per day: a dot per day with check-ins, joined by a line.
 const days=[];for(let i=jer-1;i>=0;i--)days.push(dAdd(t,-i));const W=640,H=170,L=58,R=10,T=12,B=22,xs=i=>L+(days.length<2?0:i*(W-L-R)/(days.length-1)),ys=m=>T+(5-m)*(H-T-B)/4;
 const pts=days.map((d,i)=>{const dl=l.filter(x=>x.d===d);return dl.length?{i,m:dl.reduce((a,x)=>a+x.m,0)/dl.length}:null}).filter(Boolean),r=jer>90?2.5:jer>30?3.5:4.5;
 const chart=`<svg class="emochart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Average mood per day">${MOOD.map((m,i)=>`<line x1="${L}" x2="${W-R}" y1="${ys(i+1)}" y2="${ys(i+1)}" class="egrid"/><text x="0" y="${ys(i+1)+4}" class="elab">${m[0]}</text>`).join('')}
${pts.length>1?`<polyline points="${pts.map(p=>`${xs(p.i).toFixed(1)},${ys(p.m).toFixed(1)}`).join(' ')}" class="eline"/>`:''}${pts.map(p=>`<circle cx="${xs(p.i).toFixed(1)}" cy="${ys(p.m).toFixed(1)}" r="${r}" style="fill:var(${MOOD[Math.round(p.m)-1][1]})"><title>${fmt(days[p.i])}: ${MOOD[Math.round(p.m)-1][0]}</title></circle>`).join('')}
<text x="${L}" y="${H-4}" class="elab">${fmt(days[0])}</text><text x="${W-R}" y="${H-4}" class="elab" text-anchor="end">${fmt(t)}</text></svg>`;
 const mx=top.length?top[0][1]:1,emo=top.length?`<div class="emobars">${top.slice(0,10).map(([e,n])=>`<div class="emobar"><span class="emo ${emoKind(e)} on">${esc(e)}</span><span class="ebar"><i class="${emoKind(e)}" style="width:${Math.max(4,Math.round(n/mx*100))}%"></i></span><b>${n}</b></div>`).join('')}</div>`:'<p class="meta" style="margin:0">No emotions picked in this period yet.</p>';
 const lv=MOOD.map((m,i)=>[m,l.filter(x=>x.m===i+1).length]),dist=`<div class="emodist">${lv.filter(x=>x[1]).map(([m,n])=>`<i style="flex:${n};background:var(${m[1]})" title="${m[0]}: ${n}"></i>`).join('')}</div><div class="emoleg">${lv.map(([m,n])=>`<span class="meta"><span class="dot" style="background:var(${m[1]})"></span>${m[0]} <b>${n}</b></span>`).join('')}</div>`;
 const byDay={};l.forEach(x=>(byDay[x.d]=byDay[x.d]||[]).push(x));const log=Object.keys(byDay).sort().reverse().slice(0,60).map(d=>jMoodCard(d,byDay[d])).join('');
 return `${writeBox(2)}${rng}${stats}<section><h2>Mood over time</h2>${chart}</section><div class="emogrid"><section><h2>Emotions you feel most</h2>${emo}</section><section><h2>Mood levels</h2>${dist}</section></div><h2 class="emologh">Log</h2>${log}`}
const jDayCard=k=>{const d=k.slice(8,-3),m=(FS[k].match(/^mood:\s*(\d)/m)||[])[1];
 return `<section><div class="head" style="margin:0"><b style="font-size:17px">${fmt(d,LONG)}</b>${m?`<span class="meta"><span class="dot" style="background:var(${MOOD[m-1][1]});width:10px;height:10px"></span> ${MOOD[m-1][0]}</span>`:''}</div>${jCatPick(k,jCats(k))}
${edJ===k?`<textarea id="je" class="mono" style="margin-top:10px">${esc(FS[k])}</textarea><div class="row"><button class="b" data-act="saveJE" data-k="${esc(k)}">Save</button><button class="g" data-act="cancel">Cancel</button></div>`:`<div class="md">${md(freeText(k))}</div><div class="row">${fileBtns(k)}</div>`}</section>`};
/* Journal extras: a writing streak, "On this day" (1 month, 6 months and 1 year ago) and a follow-up question that
   changes with the mood picked for a new entry. */
const jDays=()=>new Set([...entKeys().map(k=>jeRead(k).date),...dayKeys().filter(k=>freeText(k)!==null).map(k=>k.slice(8,-3))]);
function jStreak(){const ds=jDays();let d=TD(),n=0;if(!ds.has(d))d=dAdd(d,-1);while(ds.has(d)){n++;d=dAdd(d,-1)}return n}
const monthsAgo=(d,m)=>{const x=pd(d),y=new Date(x.getFullYear(),x.getMonth()-m,x.getDate());return y.getMonth()===((x.getMonth()-m)%12+12)%12?iso(y):''};
function onThisDay(){const t=TD(),out=[];[[1,'1 month ago'],[6,'6 months ago'],[12,'1 year ago']].forEach(([m,l])=>{const d=monthsAgo(t,m);if(!d)return;
  const es=entKeys().map(jeRead).filter(e=>e.date===d),df=FS[jp(d)]?freeText(jp(d)):null,txt=es.map(e=>e.body.trim()).filter(Boolean).join('\n\n')||df||'';if(txt)out.push({l,d,txt,mood:getMood(d)})});
 if(!out.length)return '';
 return `<section class="otd"><h2>On this day</h2>${out.map(x=>`<div class="otdrow"><div class="head" style="margin:0 0 4px"><b>${x.l}</b><span class="meta">${fmt(x.d,LONG)}${x.mood?` · <span class="dot" style="background:var(${MOOD[Math.round(x.mood)-1][1]});width:8px;height:8px"></span> ${MOOD[Math.round(x.mood)-1][0]}`:''}</span></div><p class="body otdtxt" data-notr>${esc(x.txt.slice(0,420))}${x.txt.length>420?'…':''}</p></div>`).join('')}</section>`}
const MOODQ=[['What would help a little right now?','What is weighing on you the most?','Who could you reach out to today?'],['What drained your energy today?','What is one small thing you can let go of?','What would make tomorrow a bit easier?'],
 ['What is on your mind right now?','What would turn today into a good day?','What are you looking forward to?'],['What went well today?','What are you grateful for right now?','Who made your day better?'],['What made today great?','How can you keep this feeling going?','What did you do that you are proud of?']];
const moodQ=m=>{if(!m)return '';const l=MOODQ[m-1],q=l[(pd(TD()).getDate()+m)%l.length];return `<div class="moodq"><span class="meta">${lineIco('M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5M12 17h.01')}<span>${q}</span></span><button class="x" data-act="moodQUse" data-v="${esc(q)}">Answer this</button></div>`};
const jEntries=all=>{const f=jCatF&&jCatF.toLowerCase(),words=fold(jq).split(/\s+/).filter(Boolean),
 // search: every word must appear in the entry's text, location, categories or date
 hit=(...parts)=>{if(!words.length)return true;const t=fold(parts.join(' '));return words.every(w=>t.includes(w))},
 inCat=k=>(!f||jCats(k).some(c=>c.toLowerCase()===f))&&(isJE(k)?(e=>hit(e.body,e.loc,e.cats.join(' '),e.emos.join(' '),fmt(e.date,LONG),e.time))(jeRead(k)):hit(freeText(k)||'',jCats(k).join(' '),fmt(k.slice(8,-3),LONG)));
 // Mood check-ins from Home, one card per day (not in any category).
 const mcDays={};if(all&&!f)moodsRead().filter(x=>hit(MOOD[x.m-1][0],x.emos.join(' '),fmt(x.d,LONG),x.t,'mood check-in')).forEach(x=>(mcDays[x.d]=mcDays[x.d]||[]).push(x));
 const items=[...Object.entries(mcDays).map(([d,l])=>({s:d+' '+l[l.length-1].t,h:jMoodCard(d,l)})),...entKeys().filter(inCat).map(jeRead).map(e=>({s:e.date+' '+(e.time||'99'),h:jeCard(e)})),...dayKeys().filter(k=>freeText(k)!==null&&inCat(k)).map(k=>({s:k.slice(8,-3)+' 00',h:jDayCard(k)}))].sort((a,b)=>b.s.localeCompare(a.s));
 return `${jCatBar()}<div class="row" style="margin:0 0 14px"><span class="sbox"><input id="jq" value="${esc(jq)}" placeholder="Search the journal" aria-label="Search the journal" autocomplete="off">${jq?`<button class="sclr" data-act="sclr" data-for="jq" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span></div>
${f?`<p class="meta" style="margin:-6px 0 14px">${items.length} entr${items.length===1?'y':'ies'} in ${esc(jCatF)} · <button class="x" data-act="jCat" data-v="${esc(jCatF)}">Show all</button></p>`:''}
${jNew?writeBox(1):''}${!jq&&!f?onThisDay():''}${items.map(x=>x.h).join('')||(jq||f?`<section><p class="empty">No entries match${jq?` “${esc(jq)}”`:''}.</p></section>`:'<section><p class="empty">No entries yet. Press + to write your first one.</p></section>')}`};

/* Task lists. Today, All and Completed are built in; tasks in no list show in Today and All.
   Each list's name, icon, color and pin live in lists/<id>.md (built-in ones only once customized);
   a task's list is written in tasks.md as "(list: id)". Pinned lists show as cards, the rest under My lists. */
let curList=null,edL=false;
const SMART=['today','all','completed'];
const LDEF={today:{name:'Today',symbol:'calendar-check',emoji:'📅',color:'#4a8fd9',pinned:'true',order:'1'},
 all:{name:'All',symbol:'tray',emoji:'📥',color:'#7a8794',pinned:'true',order:'2'},
 completed:{name:'Completed',symbol:'check-circle',emoji:'✅',color:'#5fa57f',pinned:'false',order:'3'}};
// List colors: the muted tones of the section cards, extended to 20; any other color comes from the custom picker.
const LCOLORS=['#d4605a','#e0566f','#c9629b','#9a5fa0','#9a7fd0','#6f7fb0','#5b9bd5','#4a8fd9','#3f9aa5','#4fa8a0','#5fa57f','#7fa55a','#a8a84a','#d4a43a','#e08a3f','#b0794a','#c6a780','#a07870','#7a8794','#5a6270'];
// The custom swatch: a color input inside a round swatch (rainbow until a color outside the palette is chosen).
const swCustom=(cur,attr,cls)=>{const own=!!cur&&!LCOLORS.includes(cur);return `<label class="${cls} swcustom ${own?'on':''}" style="${own?`--c:${cur};background:${cur}`:''}" title="Custom color"><input type="color" ${attr} value="${own?cur:'#888888'}" aria-label="Custom color"></label>`};
const listKey=id=>'lists/'+id+'.md';
function getList(id){const f=FS[listKey(id)]?readNote(FS[listKey(id)]).fm:{},l={id,...(LDEF[id]||{name:id,symbol:'list-bullets',emoji:'📋',color:'#6f7fb0',pinned:'false',order:'99'}),...f};
 if(!/^#[0-9a-f]{3,8}$/i.test(l.color))l.color='#6f7fb0';return l}
const putList=l=>{FS[listKey(l.id)]=writeNote({fm:{name:l.name,symbol:l.symbol,emoji:l.emoji,color:l.color,pinned:String(l.pinned),order:String(l.order)},body:''})};
const userLists=()=>keys('lists/').map(k=>k.slice(6,-3)).filter(id=>!SMART.includes(id)).map(getList).sort((a,b)=>(+a.order||99)-(+b.order||99)||alpha(a.name,b.name));
const allLists=()=>[...SMART.map(getList),...userLists()].sort((a,b)=>(+a.order||99)-(+b.order||99)||alpha(a.name,b.name));
const listOpts=sel=>'<option value="">No list</option>'+userLists().map(l=>`<option value="${esc(l.id)}" ${l.id===sel?'selected':''}>${esc(l.name)}</option>`).join('');
// Today: due today or overdue (plus ones finished today). All: everything. Completed: every finished task.
const listTasks=(id,ts)=>{const t=TD();return ts.filter(x=>id==='today'?x.due&&x.due<=t&&(!x.done||x.doneOn===t):id==='all'?true:id==='completed'?x.done:x.list===id)};
const lIcon=l=>symbols()?sym(l.symbol):esc(l.emoji||'');
// The count on a list: open tasks, or for Completed the finished ones.
const lOpen=(l,ts)=>listTasks(l.id,ts).filter(x=>l.id==='completed'?x.done:!x.done).length;
const lcard=(l,ts)=>`<button class="lcard" data-act="openList" data-val="${esc(l.id)}" data-list="${esc(l.id)}" data-dnd="lpin" data-id="${esc(l.id)}" title="Drag to reorder" style="--tc:${vivid(l.color)}"><span class="lci">${lIcon(l)}</span><span class="lcn">${lOpen(l,ts)}</span><span class="lcl">${esc(l.name)}</span></button>`;
const lrow=(l,ts)=>`<button class="lrow" data-act="openList" data-val="${esc(l.id)}" data-list="${esc(l.id)}" data-dnd="lrow" data-id="${esc(l.id)}"><span class="lri" style="background:${vivid(l.color)}">${lIcon(l)}</span><span class="lrl">${esc(l.name)}</span><span class="meta lrc">${lOpen(l,ts)}</span><span class="lrch" aria-hidden="true">›</span></button>`;
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&!e.shiftKey&&!e.altKey&&e.key.toLowerCase()==='e'&&view==='notes'&&edN&&!isTplKey(edN)&&document.querySelector('.neditor')){e.preventDefault();flushNote();nView=!nView;render();if(!nView){const el=$('nb');if(el)el.focus()}}});
// While editing, a click outside the note (not on its menus or pickers) saves it and switches to View mode,
// when notes open in View mode by default.
document.addEventListener('pointerdown',e=>{if(nView||view!=='notes'||!edN||isTplKey(edN)||CFG.noteOpen==='edit'||!document.querySelector('.neditor'))return;
 const t=e.target;if(!t.closest||t.closest('.neditor,.dmenu,#ctx,.exsug,.epick,#rem,#toast,.npanel .nli[data-k]'))return;
 if(t.closest('[data-act="editN"],[data-act="newN"]'))return;
 // re-render after the click finishes, so the button that was clicked (e.g. in the sidebar) still receives it
 flushNote();nView=true;const done=()=>setTimeout(()=>{if(view==='notes'&&nView)render()});document.addEventListener('click',done,{once:true});setTimeout(()=>document.removeEventListener('click',done),1500);setTimeout(()=>{if(view==='notes'&&nView&&!document.querySelector('.nview'))render()},400)},true);
document.addEventListener('dblclick',e=>{if(e.target.closest&&e.target.closest('.mdview')&&!e.target.closest('button,a')){nView=false;render();const el=$('nb');if(el)el.focus()}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&LD&&view==='tasks'&&!document.querySelector('.ppick, .exsug')){LD=null;if(icoPick==='newlist')icoPick=null;render()}});
// A new list is a draft (LD) until "Create list" is clicked; Cancel or the + button again discards it.
let LD=null;
// The New list page, styled as a sheet: ✕ and ✓ in the header, a big icon above the name, color and icon grids.
const newListModal=()=>{const l=LD,s=symbols();
 return `<div class="sheet" style="--tc:${vivid(l.color)}">
<div class="shead"><button class="circ" data-act="ldCancel" aria-label="Cancel" title="Cancel">${lineIco('M6 6l12 12M18 6L6 18')}</button><h2 id="ldtitle">New list</h2><button class="circ ok" data-act="ldCreate" aria-label="Create list" title="Create list">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>
<div class="sbody"><div class="scard ldhero"><span class="ldbig">${lIcon(l)}</span><input id="ldname" value="${esc(l.name)}" placeholder="List name" aria-label="List name" autocomplete="off"></div>
<div class="scard"><div class="swrow"><span><span class="lri" style="background:${l.color}">${s?sym('push-pin'):'📌'}</span>Pinned</span>${swBtn(l.pinned==='true','data-act="ldPin"','Pinned')}</div></div>
<div class="scard"><div class="ldgrid">${LCOLORS.map(c=>`<button class="ldsw ${l.color===c?'on':''}" data-act="ldColor" data-val="${c}" style="--c:${c}" aria-label="Color ${c}" aria-pressed="${l.color===c}"></button>`).join('')}${swCustom(l.color,'data-ldcolor','ldsw')}</div></div>
<div class="scard ldpick">${picker('newlist',l.emoji)}</div>
</div></div>`};
const tasksHome=()=>{const ts=tasks(),ls=allLists(),pin=ls.filter(l=>l.pinned==='true'),rest=ls.filter(l=>l.pinned!=='true');
 return `<div class="lnav"><h1 style="margin:0">Tasks</h1><button class="circ" data-act="newList" aria-label="New list" title="New list">${lineIco('M12 5v14M5 12h14')}</button></div>${pin.length?`<div class="lgrid">${pin.map(l=>lcard(l,ts)).join('')}</div>`:''}
${rest.length?`<h2 class="lhead">My lists</h2><section class="lrows">${rest.map(l=>lrow(l,ts)).join('')}</section>`:''}`};
const listEditor=l=>{const builtin=SMART.includes(l.id),pk='list:'+l.id;
 return `<section><h2>List settings</h2>
${L('Name')}<input id="lname" value="${esc(l.name)}" style="max-width:320px" aria-label="List name">
${L('Color')}<div class="row" style="margin:0;gap:8px">${LCOLORS.map(c=>`<button class="lsw ${l.color===c?'on':''}" data-act="lColor" data-val="${c}" style="background:${c}" aria-label="Color ${c}" aria-pressed="${l.color===c}"></button>`).join('')}${swCustom(l.color,'data-lcolor','lsw')}</div>
${L('Icon')}<div class="row" style="margin:0"><button class="g" data-act="icoPick" data-id="${pk}"><span class="lri" style="background:${l.color};width:26px;height:26px;display:inline-grid;vertical-align:middle;margin-right:8px">${lIcon(l)}</span>${icoPick===pk?'Close':'Choose icon'}</button></div>${icoPick===pk?picker(pk,l.emoji):''}
<div class="swrow"><span>Pinned</span>${swBtn(l.pinned==='true','data-act="lPin"','Pinned')}</div>
${builtin?'':`<div class="row" style="margin-top:16px"><button class="g" data-act="delList">${armed==='list:'+l.id?'Click again to delete (its tasks stay in All)':'Delete list'}</button></div>`}</section>`};
/* Inside a list, tasks are checklist rows: a round checkbox in the list color, the title, and a date line
   ("Today", "Tomorrow", "Yesterday, 23:00"…) that turns red when overdue. Edit, subtask and delete show on hover. */
let showDone=false,tDet=false;
const remDue=t=>{const d=t.rem?t.rem.slice(0,10):t.due;if(!d)return '';const n=TD(),time=t.rem?tf(t.rem.slice(11)):'';
 const rel=d===n?'Today':d===dAdd(n,1)?'Tomorrow':d===dAdd(n,-1)?'Yesterday':fmt(d);
 const late=!t.done&&(t.rem?t.rem<stamp(new Date()):t.due<n);return `<span class="rdue ${late?'late':''}">${rel}${time?', '+time:''}</span>`};
const remRow=t=>{if(edT===t.i)return `<div class="rrow redit">${editRow(t)}</div>`;
 const extra=[t.list&&curList!==t.list&&FS[listKey(t.list)]?esc(getList(t.list).name):'',t.proj&&secOn('projects')&&!(view==='projects'&&curP===t.proj)?'Project · '+esc(pname(t.proj)):'',(t.subs||[]).length?`${t.subs.filter(x=>x.done).length}/${t.subs.length} subtasks`:''].filter(Boolean).join(' · ');
 return `<div class="rrow ${t.done?'done':''}" data-tk="${t.i}"><button class="rchk" data-act="tog" data-i="${t.i}" role="checkbox" aria-checked="${t.done}" aria-label="${t.done?'Mark as not done':'Mark as done'}"></button>
<div class="rt"><span class="rtt">${t.pri&&!t.done?`<span class="tpri p-${t.pri}" title="${t.pri==='high'?'High':t.pri==='medium'?'Medium':'Low'} priority">${t.pri==='high'?'!!!':t.pri==='medium'?'!!':'!'}</span>`:''}${esc(t.title)}</span>${remDue(t)}${t.rep?`<span class="trep">${lineIco('M17 2l4 4-4 4M3 11V9a3 3 0 0 1 3-3h15M7 22l-4-4 4-4M21 13v2a3 3 0 0 1-3 3H3')}${REPL[t.rep]}</span>`:''}${extra?`<span class="meta rex">${extra}</span>`:''}${(t.subs||[]).map((x,j)=>subRow(t,x,j)).join('')}${addSubT===t.i?`<div class="sub sjoin"><input id="sin" placeholder="New subtask (Esc to close)" aria-label="New subtask"><button class="b tick" data-act="addS" data-i="${t.i}" aria-label="Add subtask" title="Add subtask">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>`:''}</div>
<span class="ract ${armed==='task:'+t.i?'armed':''}"><button class="cx rbtn" data-act="editT" data-i="${t.i}" aria-label="Edit task" title="Edit">${lineIco('M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4')}</button><button class="cx rbtn" data-act="subT" data-i="${t.i}" aria-label="Add a subtask" title="Add a subtask">${lineIco('M5 5v6a3 3 0 0 0 3 3h11M15 10l4 4-4 4')}</button>${armed==='task:'+t.i?`<button class="rdel on" data-act="delT" data-i="${t.i}" title="Click again to delete">${lineIco('M5 7h14M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3')}Delete?</button>`:`<button class="cx rbtn" data-act="delT" data-i="${t.i}" aria-label="Delete task" title="Delete">${lineIco('M5 7h14M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3')}</button>`}</span></div>`};
// Thin line icons for the checklist-row buttons (the filled icon set has a boxed plus and a solid triangle).
const lineIco=d=>`<svg class="sym" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${d}"/></svg>`;
const remHead=(l,count)=>`<div class="lnav">${backBtn('closeList','Back to lists','Lists')}<span class="meta">${count}</span><button class="circ" data-act="editList" aria-label="List settings" title="List settings" aria-pressed="${edL}"><svg class="sym" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5.5" cy="12" r="1.9"/><circle cx="12" cy="12" r="1.9"/><circle cx="18.5" cy="12" r="1.9"/></svg></button></div>
<h1 class="ltitle" style="--tc:${vivid(l.color)}">${esc(l.name)}</h1>${edL?listEditor(l):''}${l.id!=='completed'&&!boardOn('l:'+l.id)?kbTog('l:'+l.id):''}`;
// Completed: finished tasks, newest first, grouped by the day they were finished.
const doneView=l=>{const ts=listTasks('completed',tasks()).sort((a,b)=>(b.doneOn||'').localeCompare(a.doneOn||'')),t=TD(),days=[];
 ts.forEach(x=>{const d=x.doneOn||'';let g=days.find(y=>y.d===d);if(!g)days.push(g={d,items:[]});g.items.push(x)});
 const lab=d=>!d?'Earlier':d===t?'Today':d===dAdd(t,-1)?'Yesterday':fmt(d,LONG);
 return `<div class="rlist" style="--tc:${vivid(l.color)}">${remHead(l,`${ts.length} completed`)}
${days.map(g=>`<h2 class="rday">${lab(g.d)}</h2>${g.items.map(remRow).join('')}`).join('')||'<p class="empty">Nothing completed yet.</p>'}</div>`};
/* Kanban: a project or list can show its tasks as a board (CFG.boards[key]). Columns: To do, Doing, Done.
   "Doing" is kept in tasks.md as "(status: doing)". Cards drag between columns, or move with ‹ ›. */
// CFG.boards[key]: true (or 'board') for the board, 'matrix' for the Eisenhower matrix; missing = list.
const viewMode=key=>{const v=(CFG.boards||{})[key];return v==='matrix'?'matrix':v?'board':'list'};
const boardOn=key=>viewMode(key)==='board',matrixOn=key=>viewMode(key)==='matrix';
const kbTog=key=>`<div class="kbtog"><div class="pseg" role="group" aria-label="View">${[['list','List','list-bullets'],['board','Board','kanban'],['matrix','Matrix','squares-four']].map(([v,l,ic])=>`<button data-act="boardTog" data-val="${key}" data-mode="${v}" class="${viewMode(key)===v?'on':''}" aria-pressed="${viewMode(key)===v}">${sym(ic)}${l}</button>`).join('')}</div></div>`;
/* Eisenhower matrix: open tasks in four quadrants. Important = marked as important (high priority); urgent = overdue
   or due (or reminding) within the next 2 days. Dragging a task to another quadrant changes those two things. */
const EQ=[[1,'Do first','Urgent · important','#d4605a'],[2,'Schedule','Important · not urgent','#4a8fd9'],[3,'Quick wins','Urgent · not important','#e08a3f'],[4,'Later','Not urgent · not important','#7a8794']];
const tUrgent=t=>{const d=t.due||(t.rem?t.rem.slice(0,10):'');return !!d&&d<=dAdd(TD(),2)},tImp=t=>t.pri==='high';
const eqOf=t=>tImp(t)?(tUrgent(t)?1:2):(tUrgent(t)?3:4);
const eMatrix=ts=>{const o=ts.filter(x=>!x.done);return `<div class="emx"><span class="emxax emxu">Urgent</span><span class="emxax emxn">Not urgent</span><span class="emxax emxi">Important</span><span class="emxax emxl">Not important</span>
${[1,2,3,4].map(q=>{const [,l,sub,c]=EQ[q-1],it=o.filter(x=>eqOf(x)===q).sort((a,b)=>((a.due||a.rem||'9')<(b.due||b.rem||'9')?-1:1));return `<section class="emq q${q}" data-eq="${q}" style="--qc:${c}"><div class="emqh"><span class="emqd"></span><b>${l}</b><span class="meta">${it.length}</span><span class="meta emqs">${sub}</span></div><div class="emqb">${it.map(remRow).join('')||'<p class="kempty meta">Drop tasks here</p>'}</div></section>`}).join('')}</div>
<p class="meta emxhint">Urgent: overdue or due in the next 2 days. Important: right-click a task and mark it as important. Drag tasks between quadrants to change them.</p>`};
function eqSet(i,q){const ts=tasks(),t=ts[i];if(!t||eqOf(t)===q)return;const msg=[];const imp=q<=2,urg=q===1||q===3;
 if(imp!==tImp(t)){t.pri=imp?'high':'';msg.push(imp?'important':'not important')}
 if(urg&&!tUrgent(t)){t.due=TD();msg.push('due today')}
 else if(!urg&&tUrgent(t)){if(q===4&&!t.rep){t.due='';msg.push('no due date')}else{t.due=dAdd(TD(),7);msg.push('due '+fmt(t.due))}if(t.rem&&t.rem.slice(0,10)<=dAdd(TD(),2))t.rem=''}
 putTasks(ts);save();toast(`${EQ[q-1][1]} · ${msg.join(', ')}`)}
const KCOLS=[['todo','To do',x=>!x.done&&!x.doing],['doing','Doing',x=>!x.done&&x.doing],['done','Done',x=>x.done]];
const kcard=(x,col)=>{const c=x.list&&FS[listKey(x.list)]?vivid(getList(x.list).color):'var(--tc,var(--ac))',subs=x.subs||[];
 return `<div class="kcard" data-ki="${x.i}" data-tk="${x.i}" style="--kc:${c}"><span class="kt" data-notr>${esc(x.title)}</span>${x.due||x.rem||subs.length?`<span class="kmeta">${remDue(x)}${subs.length?`<span class="meta">${subs.filter(y=>y.done).length}/${subs.length}</span>`:''}</span>`:''}
<span class="kmv">${col!=='todo'?`<button class="cx" data-act="kMove" data-i="${x.i}" data-val="${col==='done'?'doing':'todo'}" aria-label="Move left" title="Move left">${lineIco('M15 5l-7 7 7 7')}</button>`:''}${col!=='done'?`<button class="cx" data-act="kMove" data-i="${x.i}" data-val="${col==='todo'?'doing':'done'}" aria-label="Move right" title="Move right">${lineIco('M9 5l7 7-7 7')}</button>`:''}</span></div>`};
const kBoard=ts=>`<div class="kanban">${KCOLS.map(([id,l,f])=>{const it=ts.filter(f).sort(id==='done'?(a,b)=>(b.doneOn||'').localeCompare(a.doneOn||''):(a,b)=>(a.due||'9')<(b.due||'9')?-1:1);return `<div class="kcol k-${id}" data-kcol="${id}"><div class="khead"><b>${l}</b><span class="meta">${it.length}</span></div><div class="kdrop">${it.map(x=>kcard(x,id)).join('')||'<p class="kempty meta">Drop tasks here</p>'}</div></div>`}).join('')}</div>`;
function kSet(i,col){const ts=tasks(),t=ts[i];if(!t)return;if(col==='done'){if(!t.done){t.done=true;t.doneOn=TD()}t.doing=false}else{t.done=false;t.doneOn='';t.doing=col==='doing'}putTasks(ts)}
// Dragging a card uses pointer events (native drag and drop is unreliable inside the app window).
let kDrag=null;
document.addEventListener('pointerdown',e=>{const c=e.button===0&&e.target.closest&&e.target.closest('.kcard,.emq .rrow');if(!c||e.target.closest('button,input,textarea,select'))return;kDrag={c,i:+(c.dataset.ki||c.dataset.tk),x:e.clientX,y:e.clientY,on:false,g:null}});
document.addEventListener('pointermove',e=>{if(!kDrag)return;const dx=e.clientX-kDrag.x,dy=e.clientY-kDrag.y;
 if(!kDrag.on){if(Math.hypot(dx,dy)<6)return;kDrag.on=true;const r=kDrag.c.getBoundingClientRect(),g=kDrag.c.cloneNode(true);g.classList.add('kghost');const z=cz();g.style.width=r.width/z+'px';g.style.left=r.left/z+'px';g.style.top=r.top/z+'px';document.body.appendChild(g);kDrag.g=g;kDrag.r=r;kDrag.c.classList.add('dragging');document.body.classList.add('kdragging')}
 kDrag.g.style.transform=`translate(${dx/cz()}px,${dy/cz()}px) rotate(1.5deg)`;const t=document.elementFromPoint(e.clientX,e.clientY),col=t&&t.closest&&t.closest('.kcol,.emq');document.querySelectorAll('.kcol.over,.emq.over').forEach(x=>x!==col&&x.classList.remove('over'));if(col)col.classList.add('over')});
document.addEventListener('pointerup',e=>{if(!kDrag)return;const d=kDrag;kDrag=null;if(!d.on)return;d.g.remove();document.body.classList.remove('kdragging');document.querySelectorAll('.kcol.over,.emq.over').forEach(x=>x.classList.remove('over'));d.c.classList.remove('dragging');
 const t=document.elementFromPoint(e.clientX,e.clientY),col=t&&t.closest&&t.closest('.kcol,.emq');if(col&&col.dataset.kcol){kSet(d.i,col.dataset.kcol);save();render()}else if(col&&col.dataset.eq){eqSet(d.i,+col.dataset.eq);render()}
 const stop=ev=>{ev.stopPropagation();ev.preventDefault()};document.addEventListener('click',stop,{capture:true,once:true});setTimeout(()=>document.removeEventListener('click',stop,{capture:true}),50)});
const listView=id=>{if(id==='completed')return doneView(getList(id));if(boardOn('l:'+id))return listBoard(id);if(matrixOn('l:'+id))return listMatrix(id);const l=getList(id),all=tasks(),ts=listTasks(id,all),o=ts.filter(x=>!x.done).sort((a,b)=>(a.due||'9')<(b.due||'9')?-1:1),d=ts.filter(x=>x.done).sort((a,b)=>(b.doneOn||'').localeCompare(a.doneOn||'')),lab='display:flex;gap:8px;align-items:center;flex:1;min-width:200px';
 return `<div class="rlist" style="--tc:${vivid(l.color)}">${remHead(l,`${o.length} open`)}
${o.map(remRow).join('')}
<div class="rrow rnew"><span class="rchk ghost" aria-hidden="true"></span><div class="rt"><div class="rnline"><input id="tt" class="rin" placeholder="New task" aria-label="New task"><button class="b tick" data-act="addT" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="x" data-act="tDet" aria-expanded="${tDet}">${tDet?'Hide details':'Details'}</button></div>
<div class="row rdet" ${tDet?'':'hidden'}><label class="meta" style="${lab}">Due <input id="td" type="date" value="${id==='today'?TD():''}"></label><label class="meta" style="${lab};min-width:240px">Remind me ${dtField('tr','','Remind me')}</label><label class="meta" style="${lab}">Project <select id="tp">${projOpts('')}</select></label><label class="meta" style="${lab}">List <select id="tl">${listOpts(SMART.includes(id)?'':id)}</select></label></div></div></div>
${d.length?`<button class="x rshow" data-act="showDone" aria-expanded="${showDone}">${showDone?'Hide':'Show'} completed (${d.length})</button>${showDone?d.map(remRow).join(''):''}`:''}
<button class="fab" data-act="fabAdd" aria-label="New task" title="New task">${lineIco('M12 5v14M5 12h14')}</button></div>`};
// A list as an Eisenhower matrix: the header (with the view switch), the new-task row and the four quadrants.
const listMatrix=id=>{const l=getList(id),ts=listTasks(id,tasks()),o=ts.filter(x=>!x.done);
 return `<div class="rlist" style="--tc:${vivid(l.color)}">${remHead(l,`${o.length} open`)}
<div class="rrow rnew"><span class="rchk ghost" aria-hidden="true"></span><div class="rt"><div class="rnline"><input id="tt" class="rin" placeholder="New task" aria-label="New task"><button class="b tick" data-act="addT" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div><input id="tl" type="hidden" value="${SMART.includes(id)?'':esc(id)}"><input id="td" type="hidden" value="${id==='today'?TD():''}"></div></div>
${eMatrix(ts)}</div>`};
// A list as a board: the header, the new-task row and the three columns.
const listBoard=id=>{const l=getList(id),ts=listTasks(id,tasks()),o=ts.filter(x=>!x.done);
 return `<div class="rlist" style="--tc:${vivid(l.color)}">${remHead(l,`${o.length} open`)}${kbTog('l:'+id)}
<div class="rrow rnew"><span class="rchk ghost" aria-hidden="true"></span><div class="rt"><div class="rnline"><input id="tt" class="rin" placeholder="New task" aria-label="New task"><button class="b tick" data-act="addT" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div><input id="tl" type="hidden" value="${SMART.includes(id)?'':esc(id)}"><input id="td" type="hidden" value="${id==='today'?TD():''}"></div></div>
${kBoard(ts)}</div>`};
V.tasks=()=>{if(curList&&!SMART.includes(curList)&&!FS[listKey(curList)])curList=null;return LD?newListModal():curList?listView(curList):tasksHome()};

/* Calendar: Month, Week and Day views (CFG.calView). Week and Day show a time grid: all-day events and tasks due on top,
   timed events placed by their hours, task reminders as small marks, and a line for the current time.
   Clicking an empty slot starts an event at that time; clicking an event opens it in the event form (EV). */
let EV=null,calTop=null,bdOpen=false;
function bdPanel(){if(!bdOpen)return '';const l=bdays(),t=TD(),next=b=>{let y=+t.slice(0,4),d=`${y}-${b.m}-${b.d}`;if(d<t)d=`${y+1}-${b.m}-${b.d}`;return d};
 const rows=l.map(b=>({...b,nx:next(b)})).sort((a,b)=>a.nx.localeCompare(b.nx));
 return `<section class="bdpanel"><div class="head" style="margin:0 0 10px"><h2 class="h2i" style="margin:0">${uiIco('cake','🎂')}Birthdays</h2><button class="cx" data-act="bdT" aria-label="Close" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
<div class="row" style="margin:0 0 10px"><input id="bdname" placeholder="Name" autocomplete="off"><input id="bddate" type="date" style="flex:0 0 170px" aria-label="Birthday"><label class="meta" style="display:flex;align-items:center;gap:6px;flex:none"><input type="checkbox" id="bdnoy" style="width:auto;min-width:0;flex:none;margin:0">Year unknown</label><button class="b tick" data-act="bdAdd" aria-label="Add birthday" title="Add">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>
${rows.length?rows.map(b=>{const days=Math.round((pd(b.nx)-pd(t))/864e5);return `<div class="hlrow static"><span class="t"><b data-notr>${esc(b.name)}</b><span class="meta">${fmt(b.nx,{month:'long',day:'numeric'})}${b.y?` · turns ${+b.nx.slice(0,4)-+b.y}`:''}</span></span><span class="meta">${days===0?'Today 🎉':days===1?'Tomorrow':`in ${days} days`}</span><button class="cx rbtn" data-act="bdDel" data-i="${b.i}" aria-label="Delete" title="Delete">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`}).join(''):'<p class="empty">No birthdays yet. They show on the calendar every year and remind you the day before.</p>'}</section>`}
// Imports events from a .ics file (Google, Outlook and others): one-off events and simple daily/weekly/monthly/yearly repeats.
function icsImport(text){const un=text.replace(/\r?\n[ \t]/g,''),evs=[],out=events();let n=0;
 un.split('BEGIN:VEVENT').slice(1).forEach(b=>{const g=k=>{const m=b.match(new RegExp('^'+k+'(?:;[^:\\n]*)?:(.*)$','m'));return m?m[1].trim():''};
  const ds=g('DTSTART'),de=g('DTEND'),sum=g('SUMMARY').replace(/\\,/g,',').replace(/\\;/g,';').replace(/\\n/g,' ');if(!ds||!sum)return;
  const dt=x=>{const m=x.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?/);if(!m)return null;if(m[4]&&m[7]){const d=new Date(Date.UTC(+m[1],+m[2]-1,+m[3],+m[4],+m[5]));return{d:iso(d),t:pad(d.getHours())+':'+pad(d.getMinutes())}}return{d:`${m[1]}-${m[2]}-${m[3]}`,t:m[4]?m[4]+':'+m[5]:''}};
  const a=dt(ds),z=de?dt(de):null;if(!a)return;const fr=(g('RRULE').match(/FREQ=(DAILY|WEEKLY|MONTHLY|YEARLY)/)||[])[1];
  const e={date:a.d,start:a.t,end:z&&z.t&&z.d===a.d?z.t:'',title:sum,rep:fr?fr.toLowerCase():''};if(out.some(x=>x.date===e.date&&x.start===e.start&&x.title===e.title))return;out.push(e);n++});
 putEvents(out);return n}
const TGH=48;// pixels per hour in the time grid
const calLabel=mode=>{if(mode==='day')return fmt(sel,LONG);if(mode==='week'){const a=weekStart(sel),z=dAdd(a,6),A=pd(a),Z=pd(z);
  return A.getMonth()===Z.getMonth()?(CFG.lang==='es'?`${A.getDate()}–${Z.getDate()} ${A.toLocaleDateString(LOC(),{month:'short'})} ${Z.getFullYear()}`:`${A.toLocaleDateString(LOC(),{month:'short'})} ${A.getDate()}–${Z.getDate()}, ${Z.getFullYear()}`):`${A.toLocaleDateString(LOC(),{month:'short',day:'numeric'})} – ${Z.toLocaleDateString(LOC(),{month:'short',day:'numeric',year:'numeric'})}`}
 return cm.toLocaleDateString(LOC(),{month:'long',year:'numeric'})};
// Places overlapping timed events side by side: each gets a lane and the number of lanes in its group.
function evLanes(list){const out=[];let grp=[],end=-1;const flush=()=>{const lanes=[];grp.forEach(x=>{let l=lanes.findIndex(z=>z<=x.a);if(l<0){l=lanes.length;lanes.push(0)}lanes[l]=x.b;x.lane=l});grp.forEach(x=>x.n=lanes.length);out.push(...grp);grp=[]};
 list.map(e=>{const a=mins(e.start),b=e.end&&mins(e.end)>a?mins(e.end):a+60;return{e,a,b}}).sort((x,y)=>x.a-y.a||y.b-x.b).forEach(x=>{if(grp.length&&x.a>=end){flush();end=-1}grp.push(x);end=Math.max(end,x.b)});if(grp.length)flush();return out}
function timeGrid(days){const t=TD(),E=events(),T=secOn('tasks')&&cOn('tasks','calTasks')?tasks():[],now=new Date(),nm=now.getHours()*60+now.getMinutes();
 const head=`<div class="tghead"><span class="tgcorner"></span>${days.map(d=>`<button class="tgday ${d===t?'td':''} ${d===sel?'sel':''}" data-act="day" data-d="${d}"><span>${DN[pd(d).getDay()]}</span><b>${pd(d).getDate()}</b></button>`).join('')}</div>`;
 const all=`<div class="tgall"><span class="meta tglab">All day</span>${days.map(d=>{const ae=evOn(E,d).filter(e=>!e.start),td=T.filter(x=>x.due===d&&!x.done);
  return `<div class="tgad" data-d="${d}">${ae.map(e=>`<button class="tgchip" data-act="evEdit" data-i="${e.i}" title="${esc(e.title)}">${esc(e.title)}</button>`).join('')}${td.map(x=>`<span class="tgchip task" title="${esc(x.title)}">${esc(x.title)}</span>`).join('')}</div>`}).join('')}</div>`;
 const hours=[...Array(24)].map((_,h)=>`<span class="tgh" style="top:${h*TGH}px">${h?tf(pad(h)+':00'):''}</span>`).join('');
 const cols=days.map(d=>{const evs=evLanes(evOn(E,d).filter(e=>e.start)),rs=T.filter(x=>x.rem&&x.rem.slice(0,10)===d&&!x.done);
  return `<div class="tgcol ${d===t?'td':''}" data-d="${d}">${evs.map(({e,a,b,lane,n})=>`<button class="tgev ${b-a<45?'short':''}" data-act="evEdit" data-i="${e.i}" style="top:${a/60*TGH}px;height:${Math.max(18,(b-a)/60*TGH-2)}px;left:calc(${lane/n*100}% + 2px);width:calc(${100/n}% - 4px)" title="${esc(evTime(e)+' · '+e.title)}"><b>${esc(e.title)}</b><span>${evTime(e)}</span></button>`).join('')}
${rs.map(x=>`<span class="tgrem" style="top:${mins(x.rem.slice(11))/60*TGH}px" title="${esc('Reminder · '+tf(x.rem.slice(11))+' · '+x.title)}">${esc(tf(x.rem.slice(11))+' '+x.title)}</span>`).join('')}${d===t?`<i class="tgnow" style="top:${nm/60*TGH}px"></i>`:''}</div>`}).join('');
 return `<div class="tg" style="--days:${days.length}">${head}${all}<div class="tgscroll" id="tgs"><div class="tgbody" style="height:${24*TGH}px"><div class="tghours">${hours}</div>${cols}</div></div></div>`}
function evForm(){const e=EV;
 return `<section class="evform"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${e.i!=null?'Edit event':'New event'}</h2></div>
<input id="evt" value="${esc(e.title)}" placeholder="Event title" autocomplete="off" aria-label="Event title">
<div class="evrow"><label class="meta lab">Date<input type="date" id="evd" value="${e.date}"></label>${e.allDay?'':`<label class="meta lab">Starts${timeField('evs',e.start,'Starts')}</label><label class="meta lab">Ends${timeField('eve',e.end,'Ends')}</label>`}
<label class="meta lab">Repeat<select id="evr"><option value="">Never</option>${[['daily','Every day'],['weekly','Every week'],['monthly','Every month'],['yearly','Every year']].map(([k,l])=>`<option value="${k}" ${e.rep===k?'selected':''}>${l}</option>`).join('')}</select></label>
<div class="swrow evall"><span>All day</span>${swBtn(e.allDay,'data-act="evAllDay"','All day')}</div></div>
${e.rep==='weekly'?`<div class="evrow evweeks"><label class="meta lab">Every<span class="evevery"><input type="number" id="evn" min="1" max="12" value="${e.every||1}" aria-label="Repeat every how many weeks"><span>${(e.every||1)===1?'week':'weeks'}</span></span></label><div class="lab"><span class="meta">On</span><div class="evdays" role="group" aria-label="Days of the week">${[0,1,2,3,4,5,6].map(x=>(x+CFG.week)%7).map(n=>{const on=(e.days||[]).length?(e.days||[]).includes(n):pd(e.date||TD()).getDay()===n;return `<button class="${on?'on':''}" data-act="evDay" data-n="${n}" aria-pressed="${on}" title="${WKN[n]}">${WKN[n].slice(0,2)}</button>`}).join('')}</div></div></div>
<p class="meta evhint">${(e.every||1)>1?`Repeats every ${e.every} weeks, counting from the week of ${fmt(e.date||TD())}. For a rotation, add one event per week with the same repeat, starting on consecutive weeks.`:'Pick the days it repeats on.'}</p>`:''}
<div class="row" style="margin-top:14px"><button class="b tick" data-act="evSave" aria-label="Save event" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="evCancel">Cancel</button>${e.i!=null?`<span style="flex:1"></span><button class="x" data-act="evDel">Delete event</button>`:''}</div></section>`}
const evSync=()=>{if(!EV)return;const g=id=>$(id)?$(id).value:null;if(g('evn')!==null)EV.every=Math.max(1,Math.min(12,parseInt(g('evn'))||1));if(g('evr')!==null)EV.rep=g('evr');if(g('evt')!==null)EV.title=g('evt');if(g('evd'))EV.date=g('evd');if(g('evs')!==null)EV.start=g('evs');if(g('eve')!==null)EV.end=g('eve')};
V.calendar=()=>{const mode=['month','week','day'].includes(CFG.calView)?CFG.calView:'month',t=TD(),T=tasks(),E=events(),dt=c=>`<i style="background:var(${c})"></i>`;
 const lg=(c,l)=>`<span class="dot" style="background:var(${c});width:9px;height:9px"></span> ${l} &nbsp;`;
 const bar=`<div class="calbar"><div class="calnav"><button class="circ" data-act="calPrev" aria-label="Previous" title="Previous">${lineIco('M15 5l-7 7 7 7')}</button><button class="circ" data-act="calNext" aria-label="Next" title="Next">${lineIco('M9 5l7 7-7 7')}</button><button class="g" data-act="calToday">Today</button><b class="caltitle">${esc(calLabel(mode))}</b></div>
<div class="calnav"><button class="g calx ${bdOpen?'on':''}" data-act="bdT" aria-pressed="${bdOpen}" title="Birthdays">🎂<span>Birthdays</span></button><button class="g calx" data-act="icsImp" title="Import events from a .ics file">${lineIco('M12 3v12M7 10l5 5 5-5M5 21h14')}<span>Import .ics</span></button>${seg('calView',[['month','Month'],['week','Week'],['day','Day']],mode)}<button class="circ" data-act="evNew" data-d="${sel}" aria-label="New event" title="New event">${lineIco('M12 5v14M5 12h14')}</button></div></div>`;
 let body;
 if(mode==='month'){const y=cm.getFullYear(),m=cm.getMonth(),off=(cm.getDay()-CFG.week+7)%7,n=new Date(y,m+1,0).getDate();
  const NS=new Set(keys('notes/').map(noteDate)),HS=new Set(habits().flatMap(x=>Object.keys(x.log))),QS=new Set(qLines().map(x=>x.d)),JS=new Set(entKeys().map(k=>jeRead(k).date));
  let c=[0,1,2,3,4,5,6].map(j=>`<div class="h">${DN[(CFG.week+j)%7]}</div>`).join('');
  for(let i=0;i<off;i++)c+='<span></span>';
  for(let d=1;d<=n;d++){const s=`${y}-${pad(m+1)}-${pad(d)}`,ev=evOn(E,s).sort(evSort);
   const dots=(cOn('tasks','calTasks')&&T.some(x=>(x.due===s&&!x.done)||(x.done&&x.doneOn===s)||(x.rem&&x.rem.slice(0,10)===s&&!x.done))?dt('--ac'):'')+((cOn('journal','calJournal')&&(FS[jp(s)]||JS.has(s)))||(cOn('journal','calJournal')&&QS.has(s))?dt('--pl'):'')+(cOn('notes','calNotes')&&NS.has(s)?dt('--m2'):'')+(cOn('habits','calHabits')&&HS.has(s)?dt('--m4'):'');
   c+=`<button data-act="day" data-d="${s}" class="${s===t?'td':''} ${s===sel?'sel':''}"><span class="cdn">${d}</span>${ev.slice(0,3).map(e=>`<span class="cev ${e.start?'':'ad'}">${e.start?`<em>${tf(e.start)}</em> `:''}${esc(e.title)}</span>`).join('')}${ev.length>3?`<span class="cev more">+${ev.length-3}</span>`:''}<span class="dots">${dots}</span></button>`}
  body=`<section><div class="cal">${c}</div></section>`}
 else body=`<section class="tgsec">${timeGrid(mode==='day'?[sel]:[0,1,2,3,4,5,6].map(i=>dAdd(weekStart(sel),i)))}</section>`;
 const add=EV?evForm():`<div class="row" style="margin-top:16px"><input id="et" placeholder="Add an event (e.g. 18:30 Dinner)"><button class="b tick" data-act="addE" aria-label="Add event" title="Add event">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div>`;
 return `<h1>Calendar</h1><p class="sub">${lg('--ac','task')}${lg('--am','event')}${lg('--pl','journal')}${lg('--m2','note')}${lg('--m4','habit')}</p>
${bar}${bdPanel()}${body}${EV?add:''}<section><h2 style="margin:0">${fmt(sel,LONG)}</h2>${dayDetail(sel,T,E,dayData(sel))}${EV?'':add}</section>`};
// Keeps the time grid's scroll position; it first opens at 7:00, or a few hours before now when today is shown.
function calScroll(){const g=$('tgs');if(!g)return;if(calTop===null){const n=new Date();calTop=(document.querySelector('.tgcol.td')?Math.max(0,n.getHours()-3):7)*TGH}g.scrollTop=calTop;g.onscroll=()=>{calTop=g.scrollTop}}
document.addEventListener('click',e=>{const c=e.target.closest&&e.target.closest('.tgcol,.tgad');if(!c||e.target!==c||view!=='calendar')return;
 if(c.classList.contains('tgad')){EV={i:null,date:c.dataset.d,title:'',start:'',end:'',allDay:true}}
 else{const r=c.getBoundingClientRect(),m=Math.max(0,Math.min(23*60+30,Math.floor((e.clientY-r.top)/TGH*2)*30));EV={i:null,date:c.dataset.d,title:'',start:hhmm(m),end:hhmm(Math.min(23*60+59,m+60)),allDay:false}}
 sel=c.dataset.d;render();const i=$('evt');if(i){i.focus();i.scrollIntoView({block:'nearest',behavior:'smooth'})}});

const STOP=new Set("about after again also always because been before being could didn’t doesn’t does doing done don’t each even every feel feeling felt from have having here just know like made make more most much need really should still than that their them then there these they things think this those through today very want well were what when where which while will with would your you’re i’m it’s i’ve that’s into over only some such back going got get was but and the for not are had has her his how its our out she too use who why can did one two".split(' '));
/* Mood correlations: for the last 180 days with a mood, the average mood on days with and without each activity
   (workout, meditation, journaling, tasks finished, each daily habit, 7h+ sleep). Shown when both sides have 3+ days. */
function moodCorr(){const t=TD(),days=[...Array(180)].map((_,i)=>dAdd(t,-i)).map(d=>[d,getMood(d)]).filter(x=>x[1]);if(days.length<6)return `<section><h2>What goes with your good days</h2><p class="empty">Check in your mood on at least 6 days to see what tends to go with your good days.</p></section>`;
 const T=tasks(),body=Object.fromEntries(bodyRead().map(x=>[x.d,x])),f=[];
 if(secOn('health')){f.push(['Working out',d=>{const w=wkRead(d);return !!(w&&w.ex.length)}],['Meditating',d=>medTotal(d)>0],['Sleeping 7 h or more',d=>body[d]&&body[d].sleep!=null?body[d].sleep>=7:null])}
 if(secOn('journal'))f.push(['Writing in your journal',d=>entOn(d).length>0||!!(FS[jp(d)]&&freeText(jp(d)))]);
 if(secOn('tasks'))f.push(['Finishing 3+ tasks',d=>T.filter(x=>x.done&&x.doneOn===d).length>=3]);
 if(secOn('habits'))habits().filter(h=>h.period!=='weekly').forEach(h=>f.push([h.name,d=>hOk(h,d)]));
 const rows=f.map(([l,fn])=>{const a=[],b=[];days.forEach(([d,m])=>{const r=fn(d);if(r===true)a.push(m);else if(r===false)b.push(m)});if(a.length<3||b.length<3)return null;const av=x=>x.reduce((p,q)=>p+q,0)/x.length,ma=av(a),mb=av(b);return{l,ma,mb,df:ma-mb,n:a.length}}).filter(Boolean).sort((x,y)=>Math.abs(y.df)-Math.abs(x.df));
 if(!rows.length)return `<section><h2>What goes with your good days</h2><p class="empty">Not enough data yet. Keep checking in your mood and logging habits, workouts and tasks.</p></section>`;
 const mx=Math.max(.5,...rows.map(r=>Math.abs(r.df)));
 return `<section><h2>What goes with your good days</h2><p class="meta" style="margin:-4px 0 12px">Average mood on days with and without each activity, last 6 months. A pattern, not proof.</p>${rows.slice(0,8).map(r=>`<div class="mcrow"><span class="mcl" data-notr>${esc(r.l)}</span><span class="mcbar"><i class="${r.df>=0?'up':'down'}" style="width:${Math.abs(r.df)/mx*50}%;${r.df>=0?'left:50%':'right:50%'}"></i></span><span class="mcv ${r.df>=0?'up':'down'}">${r.df>=0?'+':'−'}${Math.abs(r.df).toFixed(1)}</span><span class="meta mcd">${r.ma.toFixed(1)} vs ${r.mb.toFixed(1)}</span></div>`).join('')}</section>`}
/* Monthly review: a month at a glance: mood, most active day, workouts, tasks, books and shows finished, best habits, and
   a few journal highlights. */
let revMonth=null;
function monthReview(){const t=TD(),mo=revMonth||(+t.slice(8)<5?dAdd(t,-6).slice(0,7):t.slice(0,7)),y=+mo.slice(0,4),m=+mo.slice(5)-1,n=new Date(y,m+1,0).getDate(),days=[...Array(n)].map((_,i)=>`${mo}-${pad(i+1)}`).filter(d=>d<=t);
 const T=tasks(),moods=days.map(getMood).filter(Boolean),act={};days.forEach(d=>{act[d]=T.filter(x=>x.done&&x.doneOn===d).length+entOn(d).length+(wkRead(d)?1:0)+keys('notes/').filter(k=>noteDate(k)===d).length});
 const top=Object.entries(act).sort((a,b)=>b[1]-a[1])[0],wk=days.filter(d=>{const w=wkRead(d);return w&&w.ex.length}).length,td=T.filter(x=>x.done&&String(x.doneOn).startsWith(mo)).length,cols=colKeys().map(colRead).filter(it=>String(it.finished||'').startsWith(mo));
 const hb=habits().filter(h=>h.period!=='weekly').map(h=>[h,days.filter(d=>hOk(h,d)).length]).filter(x=>x[1]).sort((a,b)=>b[1]-a[1]).slice(0,3);
 const hi=entKeys().map(jeRead).filter(e=>e.date.startsWith(mo)&&e.body.trim()).sort((a,b)=>(b.mood||0)-(a.mood||0)||b.body.length-a.body.length).slice(0,3);
 const tile=(v,l)=>`<div><b>${v}</b><span class="meta">${l}</span></div>`;
 return `<section class="mreview"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${new Date(y,m,1).toLocaleDateString(LOC(),{month:'long',year:'numeric'})} in review</h2><span class="row" style="margin:0;gap:4px"><button class="cx rbtn" data-act="revNav" data-val="-1" aria-label="Previous month">${lineIco('M15 5l-7 7 7 7')}</button><button class="cx rbtn" data-act="revNav" data-val="1" aria-label="Next month" ${mo>=t.slice(0,7)?'disabled':''}>${lineIco('M9 5l7 7-7 7')}</button></span></div>
<div class="stats">${tile(moods.length?(moods.reduce((a,b)=>a+b,0)/moods.length).toFixed(1):'–','Average mood')}${tile(td,'Tasks done')}${tile(wk,'Workouts')}${tile(cols.length,'Finished in Collections')}</div>
${moods.length?`<div class="mrmoods">${MOOD.map((x,i)=>{const c=moods.filter(v=>v===i+1).length;return c?`<span style="flex:${c};background:var(${x[1]})" title="${x[0]}: ${c}"></span>`:''}).join('')}</div>`:''}
${(c=>c.length?`<p class="meta" style="margin:12px 0 6px">Most felt</p><div class="emos ro">${c.map(([x,n])=>`<span class="emo ${emoKind(x)} on">${esc(x)} <em>${n}</em></span>`).join('')}</div>`:'')(Object.entries([...entKeys().map(jeRead).filter(e=>e.date.startsWith(mo)).flatMap(e=>e.emos),...moodsRead().filter(x=>x.d.startsWith(mo)).flatMap(x=>x.emos)].reduce((o,x)=>(o[x]=(o[x]||0)+1,o),{})).sort((a,b)=>b[1]-a[1]).slice(0,6))}
<div class="mrlist">${top&&top[1]?`<p><b>Most active day:</b> ${fmt(top[0],LONG)} <span class="meta">(${top[1]} things logged)</span></p>`:''}${cols.length?`<p><b>Finished:</b> <span data-notr>${cols.map(c=>esc(c.title)).join(', ')}</span></p>`:''}${hb.length?`<p><b>Best habits:</b> ${hb.map(([h,c])=>`<span data-notr>${esc(h.name)}</span> <span class="meta">${c}/${days.length} days</span>`).join(' · ')}</p>`:''}</div>
${hi.length?`<p class="meta" style="margin:12px 0 6px">Journal highlights</p>${hi.map(e=>`<div class="mrhi"><span class="meta">${fmt(e.date,{month:'short',day:'numeric'})}${e.mood?` · ${MOOD[e.mood-1][0]}`:''}</span><p class="body" data-notr>${esc(e.body.trim().split('\n')[0].slice(0,200))}</p></div>`).join('')}`:''}</section>`}
// Insights → Focus: time and sessions this week, average and longest session, minutes per day (14 days), recent sessions.
function focusInsights(){const L=focusLog();if(!L.length)return secOn('tasks')?'<section><h2>Focus</h2><p class="empty">Start a focus session from Home. Each session’s time shows up here.</p></section>':'';
 const t=TD(),ws=weekStart(t),wk=L.filter(x=>x.d>=ws&&x.d<=t),wkMin=wk.reduce((a,x)=>a+x.min,0),avgM=Math.round(L.reduce((a,x)=>a+x.min,0)/L.length),longest=Math.max(...L.map(x=>x.min));
 const days=[];for(let i=13;i>=0;i--)days.push(dAdd(t,-i));const per=days.map(d=>L.filter(x=>x.d===d).reduce((a,x)=>a+x.min,0)),mx=Math.max(30,...per);
 return `<section class="fins"><h2>Focus</h2><div class="stats"><div><b>${fmtMin(wkMin)}</b><span class="meta">Focused this week</span></div><div><b>${wk.length}</b><span class="meta">Sessions this week</span></div><div><b>${fmtMin(avgM)}</b><span class="meta">Average session</span></div><div><b>${fmtMin(longest)}</b><span class="meta">Longest session</span></div></div>
<div class="fbars" role="img" aria-label="Focus minutes per day, last 14 days">${days.map((d,i)=>`<div title="${fmt(d)}: ${fmtMin(per[i])}"><i style="height:${per[i]?Math.max(4,per[i]/mx*100):0}%"></i><span>${d===t?'Today':DN[pd(d).getDay()].slice(0,2)}</span></div>`).join('')}</div>
<p class="meta lab0" style="margin:14px 0 4px">Recent sessions</p>${L.slice(-6).reverse().map(x=>`<div class="frec"><span class="meta">${fmt(x.d)} · ${tf(x.t)}</span><b>${fmtMin(x.min)}</b>${x.of?`<span class="meta">${x.done}/${x.of} tasks</span>`:''}${x.titles?`<span class="meta frect" data-notr>${esc(x.titles)}</span>`:''}</div>`).join('')}</section>`}
V.insights=()=>{const jk=[...new Set([...dayKeys().map(k=>k.slice(8,-3)),...entKeys().map(k=>jeRead(k).date)])].map(d=>jp(d)),mo=jk.map(k=>[k.slice(8,-3),getMood(k.slice(8,-3))]).filter(x=>x[1]).sort(),n=mo.length;
const avg=a=>a.length?a.reduce((x,y)=>x+y,0)/a.length:0;
const recent=mo.slice(-14);let spark='<p class="empty">Check in on at least two days to see your trend.</p>';
if(recent.length>1){const P=recent.map((e,i)=>[10+i*(260/(recent.length-1)),50-(e[1]-1)*10]);
spark=`<svg viewBox="0 0 280 60" role="img" aria-label="Mood over your last ${recent.length} check-ins"><polyline points="${P.map(p=>p.join(',')).join(' ')}" fill="none" stroke="var(--ac)" stroke-width="2"/>${P.map((p,i)=>`<circle cx="${p[0]}" cy="${p[1]}" r="4" fill="var(${MOOD[recent[i][1]-1][1]})"/>`).join('')}</svg>`}
const wd=[[],[],[],[],[],[],[]];mo.forEach(([d,v])=>wd[pd(d).getDay()].push(v));
const names=DN,wa=wd.map(avg);
const bars=`<div class="bars">${[0,1,2,3,4,5,6].map(j=>{const i=(CFG.week+j)%7,v=wa[i];return `<div><i style="height:${v/5*100}%"></i>${names[i]}</div>`}).join('')}</div>`;
let note='';if(n>=7){const ok=wa.map((v,i)=>[v,i]).filter(x=>wd[x[1]].length);const hi=ok.reduce((a,b)=>b[0]>a[0]?b:a),lo=ok.reduce((a,b)=>b[0]<a[0]?b:a);
if(hi[1]!==lo[1])note=`<p>You tend to feel best on <b>${names[hi[1]]}</b> and lowest on <b>${names[lo[1]]}</b>. Worth asking what’s different about those days.</p>`}
else note=`<p class="empty">Patterns appear after about a week of check-ins (${n}/7 so far).</p>`;
const cnt={};let words=0;
jk.forEach(k=>{const b=((FS[k]||'')+'\n'+entOn(k.slice(8,-3)).map(e=>e.body).join('\n')).replace(/^---[\s\S]*?---\n/,'').split('\n').filter(l=>!l.startsWith('#')).join(' ');words+=b.split(/\s+/).filter(Boolean).length;
 b.toLowerCase().split(/[^a-zA-Z’']+/).forEach(w=>{if(w.length>3&&!STOP.has(w))cnt[w]=(cnt[w]||0)+1})});
const top=Object.entries(cnt).sort((a,b)=>b[1]-a[1]).slice(0,14);
let st=0,d=new Date();if(!FS[jp(iso(d))])d.setDate(d.getDate()-1);while(FS[jp(iso(d))]){st++;d.setDate(d.getDate()-1)}
const T=tasks();
return `<h1>Insights</h1><p class="sub">What your own entries say about you. Computed from your Markdown files, on this device.</p>${monthReview()}${focusInsights()}${moodCorr()}
<section><div class="stats"><div><b>${n?avg(mo.map(x=>x[1])).toFixed(1):'–'}</b><span class="meta">Average mood (1–5)</span></div><div><b>${st}</b><span class="meta">Day journaling streak</span></div><div><b>${T.filter(x=>x.done).length}/${T.length}</b><span class="meta">Tasks done</span></div><div><b>${words}</b><span class="meta">Words written</span></div></div></section>
<section><h2>Mood, last ${recent.length||14} check-ins</h2>${spark}</section>
<section><h2>Mood by weekday</h2>${bars}${note}</section>
<section><h2>Words you keep coming back to</h2>${top.length?`<div class="chips">${top.map(([w,c])=>`<span style="font-size:${13+Math.min(c,8)*1.5}px">${esc(w)}</span>`).join('')}</div>`:'<p class="empty">Write a few journal entries and recurring themes will show up here.</p>'}</section>`};

/* Storage: Links, Images and PDFs, plus the raw Files list. Each kind has an index file in storage/ (readable anywhere):
     storage/links.md   - 2026-10-22: [Title](https://…) — description
     storage/images.md  - 2026-10-22: ![Caption](../attachments/2026-10-22-abc.jpg)
     storage/pdfs.md    - 2026-10-22: [Title](../attachments/2026-10-22-abc.pdf)
   Images and PDFs are saved in attachments/ (IndexedDB in a plain browser), like journal photos. */
let stTab='all',stQ='',stPrev=null,stFavF=false,stRen=null,stFolder=null,stMove=null;
/* Folders ("{folder: Name}" on an item's line) and Read later ("🔖" on a link) in Storage. */
const stAll=()=>[...stRead('links'),...stRead('images'),...stRead('pdfs')];
const stFolders=()=>[...new Set(stAll().map(x=>x.folder).filter(Boolean))].sort(alpha);
function stFolderBar(){const fs=stFolders(),later=stRead('links').filter(x=>x.later).length;if(!fs.length&&!later&&stFolder===null)return '';const all=stAll().filter(x=>stTab==='all'||x.k===stTab||stTab==='files');
 const chip=(v,l,n,ic)=>`<button class="stfchip ${stFolder===v?'on':''}" data-act="stFolderSet" data-val="${v===null?'':esc(v)}" aria-pressed="${stFolder===v}">${ic||''}<span ${v&&v[0]!=='@'?'data-notr':''}>${l}</span>${n!=null?`<em>${n}</em>`:''}</button>`;
 return `<div class="stfolders">${chip(null,'All',null)}${later?chip('@later','Read later',later,uiIco('bookmark-simple','🔖 ')):''}${fs.map(f=>chip(f,esc(f),all.filter(x=>x.folder===f).length,symbols()?sym('folder-simple'):'📁')).join('')}${fs.length?chip('@none','No folder',all.filter(x=>!x.folder).length):''}</div>`}
const stMoveBar=()=>{if(!stMove)return '';const[k,i]=stMove.split(':'),x=stRead(k)[+i];if(!x){stMove=null;return ''}
 return `<div class="row strename"><span class="meta">Move to folder</span><input id="stfold" list="dl-stf" value="${esc(x.folder||'')}" placeholder="Folder name (new or existing)" autocomplete="off"><datalist id="dl-stf">${stFolders().map(f=>`<option value="${esc(f)}">`).join('')}</datalist><button class="b tick" data-act="stMoveSave" aria-label="Move" title="Move">${lineIco('M5 12.5l4.5 4.5L19 7')}</button>${x.folder?'<button class="g" data-act="stMoveOut">Remove from folder</button>':''}<button class="g" data-act="stMoveCancel">Cancel</button></div>`};
const STK={links:'storage/links.md',images:'storage/images.md',pdfs:'storage/pdfs.md'},STH={links:'# Links',images:'# Images',pdfs:'# PDFs'};
const SLRE=/^- (\d{4}-\d{2}-\d{2}): (!?)\[([^\]]*)\]\(([^)\s]+)\)((?: (?:📌|★|🔖))*)(?: \{folder: ([^}]+)\})?(?: — (.*))?$/;
const stRead=kind=>(FS[STK[kind]]||'').split('\n').map(l=>l.match(SLRE)).filter(Boolean).map((m,i)=>({i,k:kind,d:m[1],title:m[3],url:m[4],pin:/📌/.test(m[5]),fav:/★/.test(m[5]),later:/🔖/.test(m[5]),folder:(m[6]||'').trim(),desc:m[7]||'',att:(m[4].match(/attachments\/([^)\s]+)$/)||[])[1]||''}));
const stWrite=(kind,list)=>{const cl=t=>String(t||'').replace(/[\[\]\n]/g,' ').trim();FS[STK[kind]]=STH[kind]+'\n\n'+list.map(x=>`- ${x.d}: ${kind==='images'?'!':''}[${cl(x.title)}](${x.att?'../attachments/'+x.att:x.url})${x.pin?' 📌':''}${x.fav?' ★':''}${x.later?' 🔖':''}${x.folder?` {folder: ${String(x.folder).replace(/[{}\n]/g,' ').trim()}}`:''}${x.desc?' — '+cl(x.desc):''}`).join('\n')+(list.length?'\n':'')};
const stMatch=x=>(!stFavF||x.fav)&&(stFolder===null||(stFolder==='@later'?x.later:stFolder==='@none'?!x.folder:x.folder===stFolder))&&(!stQ||fold(x.title+' '+x.url+' '+x.desc).includes(fold(stQ)));
const stPinSort=l=>l.slice().sort((a,b)=>(b.pin-a.pin));
const stMarks=x=>`${x.later?`<span class="stmk later" title="Read later">${uiIco('bookmark-simple','🔖')}</span>`:''}${x.folder&&stFolder===null?`<span class="stmk fold" title="Folder" data-notr>${esc(x.folder)}</span>`:''}${x.pin?`<span class="stmk pin" title="Pinned">${sym('push-pin')}</span>`:''}${x.fav?`<span class="stmk fav" title="Favorite">${heartIco(true)}</span>`:''}`;
const host=u=>{try{return new URL(u).hostname.replace(/^www\./,'')}catch(e){return u}};
async function stAddLink(raw){let u=raw.trim();if(!u)return;if(!/^https?:\/\//i.test(u))u='https://'+u;try{new URL(u)}catch(e){toast('That doesn’t look like a link');return}
 const l=stRead('links');if(l.some(x=>x.url===u)){toast('That link is already saved');return}l.unshift({d:TD(),title:host(u),url:u,desc:''});stWrite('links',l);save();render();toast('Link saved');
 if(TAURI)try{const[t,ds]=await TAURI.invoke('link_info',{url:u});const m=stRead('links'),x=m.find(y=>y.url===u);if(x&&(t||ds)){if(t)x.title=t;if(ds)x.desc=ds.slice(0,240);stWrite('links',m);save();if(view==='files')render()}}catch(e){}}
async function stAddFiles(kind,files){let n=0;const l=stRead(kind),added=[];
 for(const f of files){try{if(kind==='images'){if(!f.type.startsWith('image/'))continue;const blob=await prepImage(f),name=attName();await saveAtt(name,blob);const it={d:TD(),title:(f.name||'').replace(/\.[^.]+$/,''),url:'',att:name,desc:''};l.unshift(it);added.push({...it,k:'images'})}
  else{if(f.type!=='application/pdf'&&!/\.pdf$/i.test(f.name||''))continue;if(f.size>50*1024*1024){toast(`${f.name} is larger than 50 MB`);continue}const name=attName().replace(/\.jpg$/,'.pdf');await saveAtt(name,f);const it={d:TD(),title:(f.name||'Document').replace(/\.pdf$/i,''),url:'',att:name,desc:''};l.unshift(it);added.push({...it,k:'pdfs'})}n++}
  catch(e){toast('Could not save '+(f.name||'that file'))}}
 if(n){stWrite(kind,l);save();render();toast(`${n} ${kind==='images'?'image':'PDF'}${n===1?'':'s'} added`)}return added}
const stPick=kind=>{const f=document.createElement('input');f.type='file';f.accept=kind==='images'?'image/*':'application/pdf,.pdf';f.multiple=true;f.onchange=()=>stAddFiles(kind,[...f.files]);f.click()};
const stOpenPdf=att=>TAURI&&(ACCT||STORE_DB)?attRead(att).then(async u=>isEncB(u)?TAURI.invoke('open_temp_file',{name:att,data:u8b64(await decBytes(u))}):TAURI.invoke('open_attachment',{name:att})).catch(e=>toast('Could not open the PDF: '+e)):TAURI?TAURI.invoke('open_attachment',{name:att}).catch(e=>toast('Could not open the PDF: '+e)):attURL(att).then(u=>u&&window.open(u,'_blank','noopener'));
// Inline rename (from the right-click menu): a bar above the list with the item's title.
const stRenBar=()=>{if(!stRen)return '';const[k,i]=stRen.split(':'),x=stRead(k)[+i];if(!x){stRen=null;return ''}
 return `<div class="row strename"><span class="meta">Rename</span><input id="stren" value="${esc(x.title)}" autocomplete="off" aria-label="New name"><button class="b tick" data-act="stRenSave" aria-label="Save name" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="stRenCancel">Cancel</button></div>`};
// The right-click menu for a stored link, image or PDF.
const stCtx=()=>{const[k,i]=ctxK.slice(3).split(':'),x=stRead(k)[+i];if(!x)return '';
 return `<button role="menuitem" data-ctx="stopen">${k==='links'?'Open link':k==='pdfs'?'Open PDF':'View image'}</button>${k==='links'?'<button role="menuitem" data-ctx="stcopy">Copy link</button>':''}${x.att?'<button role="menuitem" data-ctx="stdl">Download…</button>':''}<button role="menuitem" data-ctx="stpin">${x.pin?'Unpin':'Pin to top'}</button><button role="menuitem" data-ctx="stfav">${x.fav?'Remove from favorites':'Add to favorites'}</button>${k==='links'?`<button role="menuitem" data-ctx="stlater">${x.later?'Mark as read':'Read later'}</button>`:''}<button role="menuitem" data-ctx="stmove">${x.folder?'Change folder…':'Move to folder…'}</button><button role="menuitem" data-ctx="stren">Rename…</button><button role="menuitem" class="danger" data-ctx="stdel">Delete…</button>`};
// Layout (CFG.stView: list or cards) and order (CFG.stSort). Pinned items always come first.
const STSORT=[['new','Newest'],['old','Oldest'],['az','A–Z'],['type','Type']];
const stOrder=l=>{const m=CFG.stSort||'new',kt={links:0,images:1,pdfs:2},by={new:(a,b)=>b.d.localeCompare(a.d)||(b.att||'').localeCompare(a.att||'')||b.i-a.i,old:(a,b)=>a.d.localeCompare(b.d)||a.i-b.i,az:(a,b)=>alpha(a.title||'',b.title||''),type:(a,b)=>kt[a.k]-kt[b.k]||b.d.localeCompare(a.d)};
 return l.slice().sort((a,b)=>(b.pin-a.pin)||by[m](a,b)||by.new(a,b))};
const stDelBtn=x=>`<button class="cx stdel" data-act="stDel" data-val="${x.k}" data-i="${x.i}" aria-label="Delete" title="Delete">${lineIco('M6 6l12 12M18 6L6 18')}</button>`;
const stOpenAttr=(x,set)=>x.k==='links'?`data-act="stOpen" data-val="${esc(x.url)}" title="${esc(x.url)}"`:x.k==='pdfs'?`data-act="stPdf" data-val="${esc(x.att)}"`:`data-act="lightbox" data-att="${esc(x.att)}" data-set="${set}"`;
const stFavicon=x=>`<span class="stfav"><img src="https://icons.duckduckgo.com/ip3/${esc(host(x.url))}.ico" alt="" loading="lazy" onerror="this.remove()"><i>${esc(host(x.url)[0]||'?').toUpperCase()}</i></span>`;
const stKindLab=x=>x.k==='links'?`<span>Link</span> · <span data-notr>${esc(host(x.url))}</span>`:x.k==='pdfs'?'PDF':'Image';
const stRow=(x,set,mixed)=>`<div class="strow ${x.pin?'pinned':''}" data-stk="${x.k}:${x.i}"><button class="lrow" ${stOpenAttr(x,set)}>${x.k==='links'?stFavicon(x):x.k==='pdfs'?'<span class="stpdf">PDF</span>':`<span class="stthumb"><img data-att="${esc(x.att)}" alt="" loading="lazy"></span>`}<span class="cnt"><b><span data-notr>${esc(x.title||(x.k==='images'?'Image':''))}</span>${stMarks(x)}</b><span class="meta">${mixed?stKindLab(x):x.k==='links'?`<span data-notr>${esc(x.desc||host(x.url))}</span>`:fmt(x.d,LONG)}</span></span>${!mixed&&x.k==='pdfs'?`<span class="cx stprev ${stPrev===x.att?'on':''}" data-act="stPrev" data-val="${esc(x.att)}" role="button" title="Preview here">${lineIco('M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6')}</span>`:''}<span class="meta cnd">${fmt(x.d,{month:'short',day:'numeric'})}</span></button>${stDelBtn(x)}</div>${x.k==='pdfs'&&stPrev===x.att?`<div class="stframe"><iframe data-att="${esc(x.att)}" title="${esc(x.title)}"></iframe><p class="meta">If the preview stays blank, click the PDF to open it in your PDF app.</p></div>`:''}`;
const stCard=(x,set)=>`<div class="stcard ${x.pin?'pinned':''}" data-stk="${x.k}:${x.i}">${x.pin||x.fav?`<span class="stimk">${stMarks(x)}</span>`:''}<button class="stcov stcov-${x.k}" ${stOpenAttr(x,set)} aria-label="Open ${esc(x.title||x.k)}">${x.k==='images'?`<img data-att="${esc(x.att)}" alt="" loading="lazy">`:x.k==='pdfs'?'<span class="stcpdf">PDF</span>':`<span class="stcfav"><img src="https://icons.duckduckgo.com/ip3/${esc(host(x.url))}.ico" alt="" loading="lazy" onerror="this.remove()"><i>${esc(host(x.url)[0]||'?').toUpperCase()}</i></span><span class="stchost" data-notr>${esc(host(x.url))}</span>`}</button><b data-notr>${esc(x.title||(x.k==='images'?'Image':''))}</b><span class="meta">${x.k==='links'?'Link':x.k==='pdfs'?'PDF':'Image'} · ${fmt(x.d,{month:'short',day:'numeric'})}</span>${stDelBtn(x)}</div>`;
const stItems=(l,mixed)=>{const set=esc(l.filter(x=>x.k==='images').map(x=>x.att).join('|')),cards=CFG.stView==='cards'||(CFG.stView==null&&stTab==='images');
 return cards?`<div class="stcards">${l.map(x=>stCard(x,set)).join('')}</div>`:`<section class="lrows">${l.map(x=>stRow(x,set,mixed)).join('')}</section>`};
const stBar=()=>{const cards=CFG.stView==='cards'||(CFG.stView==null&&stTab==='images'),srt=CFG.stSort||'new';
 return `<div class="stbar"><div class="pseg" role="group" aria-label="View">${[['list','List','list-bullets'],['cards','Cards','squares-four']].map(([v,l,ic])=>`<button data-act="stViewSet" data-val="${v}" class="${(cards?'cards':'list')===v?'on':''}" aria-pressed="${(cards?'cards':'list')===v}">${sym(ic)}${l}</button>`).join('')}</div>
<div class="pseg" role="group" aria-label="Sort">${STSORT.filter(([v])=>v!=='type'||stTab==='all').map(([v,l])=>`<button data-act="stSortSet" data-val="${v}" class="${srt===v?'on':''}" aria-pressed="${srt===v}">${l}</button>`).join('')}</div></div>`};
function stView(){const tab=stTab,add=lineIco('M12 5v14M5 12h14'),srch=`<div class="stsrow"><span class="sbox stsearch">${stPend.length?`<span class="stpendico" title="${stPend.length} waiting to be added">${stPend[0].kind==='images'?`<img src="${stPend[0].url}" alt="">`:'<b>PDF</b>'}${stPend.length>1?`<em>${stPend.length}</em>`:''}</span>`:''}<input id="stq" placeholder="Search ${({all:'everything',links:'links',images:'images',pdfs:'PDFs'})[tab]}, or paste or drop a link or file" value="${esc(stQ)}" autocomplete="off">${stQ?`<button class="sclr" data-act="sclr" data-for="stq" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span><button class="g stfavf ${stFavF?'on':''}" data-act="stFavF" aria-pressed="${stFavF}" title="Show favorites only">${heartIco(stFavF)}Favorites</button></div>${stPend.length?`<section class="sttray"><div class="sttitems">${stPend.map((x,i)=>`<div class="sttitem"><span class="sttthumb">${x.kind==='images'?`<img src="${x.url}" alt="">`:'<b>PDF</b>'}<button class="stchx" data-act="stUnstage" data-i="${i}" aria-label="Remove" title="Remove">${lineIco('M6 6l12 12M18 6L6 18')}</button></span><span class="meta" data-notr>${esc((x.f.name||'').replace(/\.[^.]+$/,'')||(x.kind==='images'?'Image':'PDF'))}</span><span class="meta sttsize">${x.f.size>=1048576?(x.f.size/1048576).toFixed(1)+' MB':Math.max(1,Math.round(x.f.size/1024))+' KB'}</span></div>`).join('')}</div>
<div class="sttbar"><span class="meta">${lineIco('M9 10l-5 5 5 5M20 4v7a4 4 0 0 1-4 4H4')}Press Enter to add ${stPend.length===1?(stPend[0].kind==='images'?'this image':'this PDF'):stPend.length+' items'} · Esc to cancel</span><span class="row" style="margin:0;gap:8px"><button class="g" data-act="stPendCancel">Cancel</button><button class="b" data-act="stPendAdd">${lineIco('M5 12.5l4.5 4.5L19 7')}Add${stPend.length>1?' '+stPend.length:''}</button></span></div></section>`:''}${!stPend.length&&stUrl(stQ)&&!stRead('links').some(x=>urlKey(x.url)===urlKey(stUrl(stQ)))?`<p class="meta sthint">${lineIco('M9 10l-5 5 5 5M20 4v7a4 4 0 0 1-4 4H4')}Press Enter to save this link</p>`:''}${stBar()}${stFolderBar()}${stRenBar()}${stMoveBar()}`;
 const empty=t=>`<section><p class="empty">${t}</p></section>`;
 if(tab==='all'){const l=stOrder([...stRead('links'),...stRead('images'),...stRead('pdfs')].filter(stMatch));
  return `<div class="row stadd" style="margin:0 0 12px"><button class="g" data-act="stTab" data-val="links">${add}Link</button><button class="g" data-act="stAdd" data-val="images">${add}Images</button><button class="g" data-act="stAdd" data-val="pdfs">${add}PDFs</button></div>${srch}
${l.length?stItems(l,true):empty(stQ||stFavF?'Nothing matches.':'Your saved links, images and PDFs show up here together. Add some with the buttons above.')}`}
 if(tab==='links'){const l=stOrder(stRead('links').filter(stMatch));
  return `<section><div class="row" style="margin:0"><input id="stlink" placeholder="Paste a link (https://…)" autocomplete="off" aria-label="Link"><button class="b tick" data-act="stLinkAdd" aria-label="Save link" title="Save link">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div></section>${srch}
${l.length?stItems(l):empty(stQ||stFavF?'No links match.':'Save links to articles, videos or anything you want to keep. The page title is filled in for you.')}`}
 if(tab==='images'){const l=stOrder(stRead('images').filter(stMatch));
  return `<div class="row" style="margin:0 0 12px"><button class="b" data-act="stAdd" data-val="images">${add}Add images</button><span class="meta">Or paste an image here.</span></div>${srch}
${l.length?stItems(l):empty(stQ||stFavF?'No images match.':'Keep screenshots, photos and references here. They are saved in attachments/.')}`}
 if(tab==='pdfs'){const l=stOrder(stRead('pdfs').filter(stMatch));
  return `<div class="row" style="margin:0 0 12px"><button class="b" data-act="stAdd" data-val="pdfs">${add}Add PDFs</button></div>${srch}
${l.length?stItems(l):empty(stQ||stFavF?'No PDFs match.':'Add PDFs to keep documents, papers and manuals with your notes. Click one to open it.')}`}
 const ks=Object.keys(FS).sort();
 return `<p class="sub">${TAURI?`Everything is stored as Markdown files in <code>${esc(BOOT.dir||'~/Prodify')}</code>. You can open, edit or back up that folder with other tools. Changes made outside Prodify, for example by Syncthing or Dropbox on another device, show up within a few seconds. If both devices changed the same file, the changes are merged.`:'Everything is stored as Markdown files in this browser. Export a zip to keep a copy on your computer, for example in a ~/Prodify folder.'} Importing replaces files with the same name, except tasks.md and events.md, which are merged.</p>
<section><div class="row" style="margin:0">${TAURI?'<button class="b" data-act="openDir">Open folder</button>':''}<button class="${TAURI?'g':'b'}" data-act="exportAll">Export all as .zip</button><button class="g" data-act="import">Import .md files</button></div></section>
<section><h2>${ks.length} file${ks.length===1?'':'s'}</h2>${ks.map(k=>`<div class="item"><div class="t"><b>${esc(k)}</b><span class="meta">${(FS[k].length/1024).toFixed(1)} KB</span></div><button class="x" data-act="dl" data-k="${esc(k)}">Download</button></div>`).join('')||'<p class="empty">No files yet. They appear as you write.</p>'}</section>`}
V.files=()=>`<h1>Storage</h1><div class="sttabs">${tileBar('stTab',stTab,[['all','All','squares-four','🗃️','#9a7fd0',stRead('links').length+stRead('images').length+stRead('pdfs').length],['links','Links','link','🔗','#4a8fd9',stRead('links').length],['images','Images','image','🖼️','#c9629b',stRead('images').length],['pdfs','PDFs','file-pdf','📄','#d4605a',stRead('pdfs').length],['files','Files','folder-open','🗂️','#7a8794',Object.keys(FS).length]])}</div>${stView()}`;
// PDF previews load their file after each render (an asset or blob URL), like photos.
function hydratePdf(){document.querySelectorAll('iframe[data-att]:not([src])').forEach(f=>attURL(f.dataset.att).then(u=>{if(u)f.src=u}).catch(()=>{}))}
document.addEventListener('input',e=>{if(e.target.id==='ipq'){ipQ=e.target.value;const p=e.target.selectionStart;render();const i=$('ipq');if(i){i.focus();i.setSelectionRange(p,p)}}});
document.addEventListener('keydown',e=>{if(e.target.id==='ipq'&&e.key==='Enter'){e.preventDefault();const f=document.querySelector('.ipitem');if(f)f.click();else{const w=document.querySelector('[data-act="ipWeb"]');if(w)w.click()}}if(e.target.id==='ipq'&&e.key==='Escape'){ipAdd=false;ipQ='';render()}});
document.addEventListener('input',e=>{if(e.target.id==='colqq'){colQQ=e.target.value;const p=e.target.selectionStart;render();const i=$('colqq');if(i){i.focus();i.setSelectionRange(p,p)}}});
document.addEventListener('input',e=>{if(e.target.id==='pfq'){pfQ=e.target.value;const p=e.target.selectionStart;render();const i=$('pfq');if(i){i.focus();i.setSelectionRange(p,p)}}});
document.addEventListener('keydown',e=>{if(e.target.id==='pflink'&&e.key==='Enter'){e.preventDefault();const b=document.querySelector('[data-act="pfLinkAdd"]');if(b)b.click()}});
document.addEventListener('keydown',e=>{if(e.target.id==='stfold'&&(e.key==='Enter'||e.key==='Escape')){e.preventDefault();const b=document.querySelector(`[data-act="${e.key==='Enter'?'stMoveSave':'stMoveCancel'}"]`);if(b)b.click()}});
document.addEventListener('keydown',e=>{if(e.target.id==='stren'&&(e.key==='Enter'||e.key==='Escape')){e.preventDefault();const b=document.querySelector(`[data-act="${e.key==='Enter'?'stRenSave':'stRenCancel'}"]`);if(b)b.click();return}if(e.target.id==='stlink'&&e.key==='Enter'){e.preventDefault();stAddLink(e.target.value)}
 if(e.target.id==='stq'&&e.key==='Enter'){if(stPend.length){e.preventDefault();stCommit();return}const u=stUrl(e.target.value);if(u){e.preventDefault();stPasteLink(u)}}
 if(e.target.id==='stq'&&e.key==='Backspace'&&!e.target.value&&stPend.length){e.preventDefault();const x=stPend.pop();if(x.url)URL.revokeObjectURL(x.url);render();const i=$('stq');if(i)i.focus()}
 if(e.target.id==='stq'&&e.key==='Escape'&&stPend.length){e.preventDefault();stPend.forEach(x=>x.url&&URL.revokeObjectURL(x.url));stPend=[];render();const i=$('stq');if(i)i.focus()}});
/* The Storage search bar: a link typed or pasted there filters the list; Enter saves it (or shows it, if it's already
   saved). Pasted images or PDFs are added right away. */
const stUrl=t=>{t=String(t||'').trim();if(/\s/.test(t))return '';if(/^www\.[^\s]+\.[a-z]{2,}/i.test(t))t='https://'+t;if(!/^https?:\/\/[^\s.]+\.[^\s]+/i.test(t))return '';try{return new URL(t).href}catch(e){return ''}};
const urlKey=u=>{try{const x=new URL(u);return (x.hostname.replace(/^www\./,'')+x.pathname.replace(/\/+$/,'')+x.search).toLowerCase()}catch(e){return u}};
function stPasteLink(u){const have=stRead('links').find(x=>urlKey(x.url)===urlKey(u));
 if(have){stQ=have.title&&have.title!==host(have.url)?have.title:host(have.url);render();const i=$('stq');if(i){i.focus();i.setSelectionRange(i.value.length,i.value.length)}toast('Already saved · showing it');return}
 stQ='';if(stTab!=='all'&&stTab!=='links')stTab='all';stAddLink(u)}
// Pasted images and PDFs wait in the search bar as small chips (a thumbnail or a PDF badge) until Enter adds them.
let stPend=[];
function stStage(fs){const ok=fs.filter(f=>f.type.startsWith('image/')||f.type==='application/pdf'||/\.pdf$/i.test(f.name||''));if(!ok.length){toast('Only links, images and PDFs can be added here');return}
 ok.forEach(f=>{const img=f.type.startsWith('image/');stPend.push({f,kind:img?'images':'pdfs',url:img?URL.createObjectURL(f):''})});render();const i=$('stq');if(i)i.focus()}
function stCommit(){const p=stPend;stPend=[];const im=p.filter(x=>x.kind==='images').map(x=>x.f),pd=p.filter(x=>x.kind==='pdfs').map(x=>x.f);p.forEach(x=>x.url&&URL.revokeObjectURL(x.url));if(im.length)stAddFiles('images',im);if(pd.length)stAddFiles('pdfs',pd);if(!im.length&&!pd.length)render()}
document.addEventListener('paste',e=>{if(e.target.id!=='stq')return;const cd=e.clipboardData;if(!cd)return;const fs=[...(cd.files||[])];
 if(fs.length){e.preventDefault();stStage(fs)}});
// Enter saves what is waiting (dropped or pasted files, or a link in the search bar) from anywhere in Storage, even with a
// button focused; Esc cancels. After a drop, or when the window comes back to the front, the search bar gets the cursor.
const stFocusBar=()=>{if(view!=='files'||(!stPend.length&&!stUrl(stQ||'')))return;const a=document.activeElement;if(a&&a.closest&&a.closest('input,textarea,select,[contenteditable="true"]')&&a.id!=='stq')return;const i=$('stq');if(i){i.focus();i.setSelectionRange(i.value.length,i.value.length)}};
window.addEventListener('focus',()=>setTimeout(stFocusBar,0));
document.addEventListener('keydown',e=>{if(view!=='files'||PWLOCK||e.ctrlKey||e.metaKey||e.altKey||(e.key!=='Enter'&&e.key!=='Escape'))return;const t=e.target;
 if(t&&t.closest&&(t.id==='stq'||t.closest('input:not([type=checkbox]):not([type=button]),textarea,select,[contenteditable="true"],#ctx,.lb')))return;
 if(stPend.length){e.preventDefault();if(e.key==='Enter')stCommit();else{stPend.forEach(x=>x.url&&URL.revokeObjectURL(x.url));stPend=[];render()}return}
 const u=e.key==='Enter'&&stUrl(stQ||'');if(u&&!/\s/.test(stQ.trim())){e.preventDefault();stPasteLink(u)}});
document.addEventListener('input',e=>{if(e.target.id==='stq'){stQ=e.target.value;const p=e.target.selectionStart;render();const i=$('stq');if(i){i.focus();i.setSelectionRange(p,p)}}});
document.addEventListener('paste',e=>{if(view!=='files'||e.target.id==='stq'||e.target.closest&&e.target.closest('input,textarea'))return;const fs=[...(e.clipboardData&&e.clipboardData.files||[])];if(fs.length){e.preventDefault();stStage(fs)}});
/* Drag and drop into Storage: files show a drop overlay; dropped images and PDFs wait in the tray (Enter or Add saves
   them), a dropped link goes into the search bar ("Press Enter to save this link"). Elsewhere, dropping a file does
   nothing (so the window never navigates to it). */
let stDragN=0;
const dragKind=e=>{if(e.target&&e.target.closest&&e.target.closest('input,textarea,[contenteditable="true"]')&&![...((e.dataTransfer&&e.dataTransfer.types)||[])].includes('Files'))return '';const t=[...((e.dataTransfer&&e.dataTransfer.types)||[])];return t.includes('Files')?'files':t.includes('text/uri-list')?'link':''};
function stDropShow(on){let o=$('stdrop');if(!on){if(o)o.remove();return}if(o)return;o=document.createElement('div');o.id='stdrop';o.className='stdrop';
 o.innerHTML=`<div class="stdropin">${uiIco('upload-simple','⬆️')}<b>Drop to add to Storage</b><span class="meta">Images, PDFs and links</span></div>`;document.body.appendChild(o);if(CFG.lang==='es')i18nRun(o)}
document.addEventListener('dragenter',e=>{const k=dragKind(e);if(!k)return;e.preventDefault();if(view!=='files'||PWLOCK)return;stDragN++;stDropShow(true)});
document.addEventListener('dragover',e=>{const k=dragKind(e);if(!k)return;e.preventDefault();if(e.dataTransfer)e.dataTransfer.dropEffect=view==='files'?'copy':'none'});
document.addEventListener('dragleave',e=>{if(!dragKind(e)||view!=='files')return;stDragN=Math.max(0,stDragN-1);if(!stDragN)stDropShow(false)});
document.addEventListener('drop',e=>{const k=dragKind(e);if(!k)return;e.preventDefault();stDragN=0;stDropShow(false);if(view!=='files'||PWLOCK)return;
 const fs=[...(e.dataTransfer.files||[])];if(fs.length){stStage(fs);setTimeout(stFocusBar,50);return}
 const u=stUrl(((e.dataTransfer.getData('text/uri-list')||e.dataTransfer.getData('text/plain')||'').split('\n').find(x=>x.trim()&&!x.startsWith('#'))||'').trim());
 if(!u){toast('Only links, images and PDFs can be added here');return}stQ=u;if(stTab!=='all'&&stTab!=='links')stTab='all';render();const i=$('stq');if(i){i.focus();i.setSelectionRange(i.value.length,i.value.length)}});
/* Journal has two views: free-writing entries and reflection questions with their answers. */
let jtab='all',jer=30,jCatF=null,JC=[],JM=0,jNew=false,jq='';
// Saves a new journal entry: the Journal entry template's properties and text, plus this moment's mood,
// the location, the chosen categories and what was written.
function jeNew(text,loc){const tp=fromTpl(FS[JTPL]?JTPL:null),fm={...tp.fm};if(!fm.created)fm.created=TD();fm.time=fm.time||hm(':');
 if(JM)fm.mood=String(JM);if(JEMO.length)fm.emotions=JEMO.slice();if(loc)fm.location=loc;if(JC.length)fm.categories=[...new Map([...(fm.categories||[]),...JC].map(x=>[x.toLowerCase(),x])).values()];
 const base=`${JE}${String(fm.created).slice(0,10)} ${String(fm.time).replace(':','-')}`;let k=base+'.md',n=2;while(FS[k])k=`${base} ${n++}.md`;
 FS[k]=writeNote({fm,body:[tp.body.trim(),text].filter(Boolean).join('\n\n')+'\n'});JM=0;JC=[];JEMO=[];emoOpen=false;return k}
// Journal categories live in each day file's front matter ("categories:"), like notes. JC holds the ones picked
// in the Write freely box until the entry is saved.
const jCats=k=>FS[k]?(readNote(FS[k]).fm.categories||[]):[];
function jSetCats(k,list){if(!FS[k])return;const n=readNote(FS[k]);n.fm.categories=[...new Map(list.map(x=>[x.toLowerCase(),x])).values()];if(!n.fm.categories.length)delete n.fm.categories;FS[k]=writeNote(n)}
const jCatPick=(k,list)=>`<div class="jcatpick">${list.map(x=>`<span class="catedit">${catTile(x,undefined,1,'journal')}<button class="cx" data-act="jcatDel" data-k="${esc(k)}" data-v="${esc(x)}" aria-label="Remove ${esc(x)}">×</button></span>`).join('')}<input class="pinp" data-jcat="${esc(k)}" placeholder="${list.length?'Add category':'Add a category'}" autocomplete="off" aria-label="Add a category" aria-autocomplete="list"></div>`;
// The journal's categories as small tiles under the Entries / Questions tabs: click one to show only those days.
const jCatBar=()=>{const cs=[...allCats('journal').values()].sort((a,b)=>(b.keys.length-a.keys.length)||alpha(a.name,b.name)),f=jCatF&&jCatF.toLowerCase();
 return `<div class="jcatbar">${cs.map(c=>catTile(c.name,c.keys.length||undefined,1,'journal',c.name.toLowerCase()===f)).join('')}<button class="jcatadd" data-act="catNew" data-sc="journal" title="New category" aria-label="New category">${lineIco('M12 5v14M5 12h14')}</button></div>${catEd&&catEd.sc==='journal'?catEditor():''}`};
V.journal=()=>`<div class="lnav"><h1 style="margin:0">Journal${(n=>n?`<span class="jstreak" title="Days in a row with an entry">${uiIco('fire','🔥 ')}${n}-day streak</span>`:'')(jStreak())}</h1>${jtab==='entries'||jtab==='all'?`<button class="circ" data-act="jNew" aria-label="New entry" title="New entry" aria-pressed="${jNew}">${lineIco('M12 5v14M5 12h14')}</button>`:''}</div>${tileBar('jtab',jtab,[['all','All','cards','🗂️','#5b9bd5',navCount('journal')+moodsRead().length],['entries','Entries','notebook','📓','#9a5fa0',navCount('journal')],['emotions','Emotions','heart','💗','#e0566f',moodsRead().length],['questions','Questions','question','❓','#e07a3f',allQ().length]])}`+(jtab==='questions'?qView():jtab==='emotions'?jEmotions():jEntries(jtab==='all'));
const qView=()=>{const all=allQ(),done=all.filter(x=>x.a.length).length;
 const l=all.filter(x=>qf==='all'||(qf==='open'?!x.a.length:x.a.length)).filter(x=>!qs||nq(x.q+' '+x.a.map(y=>y.t).join(' ')).includes(nq(qs)));
 return `<p class="sub">${all.length} asked · ${done} answered · ${all.length-done} still open. Saved in questions.md and your journal files.</p>
${qBox()}<p class="meta" style="margin:-4px 0 16px">Questions are never repeated. The AI only sees your past questions, never what you wrote.</p>
<div class="moods seg" style="margin-bottom:12px">${[['all','All'],['open','Unanswered'],['done','Answered']].map(([v,t])=>`<button data-act="qf" data-val="${v}" class="${qf===v?'on':''}">${t}</button>`).join('')}</div>
<span class="sbox" style="margin-bottom:16px"><input id="qsearch" placeholder="Search questions and answers" value="${esc(qs)}">${qs?`<button class="sclr" data-act="sclr" data-for="qsearch" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span>
${l.map(x=>`<section><p class="q" style="margin-bottom:6px">${esc(x.q)}</p><p class="meta">Asked ${fmt(x.d)}${x.a.length?' · Answered '+x.a.map(y=>fmt(y.d)).join(', '):' · Not answered yet'}</p>${x.a.map(y=>`<div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:color-mix(in srgb,var(--ink) 5%,transparent)"><span class="meta">${fmt(y.d)}</span><p class="body" style="margin-top:2px">${esc(y.t)}</p></div>`).join('')}${ansQ===x.q?`<textarea id="qa" autofocus placeholder="Write your answer" style="margin-top:10px"></textarea><div class="row"><button class="b" data-act="saveQ" data-k="${esc(x.q)}" data-t="qa">Save answer</button><button class="g" data-act="cancel">Cancel</button></div>`:`<div class="row"><button class="g" data-act="ask" data-k="${esc(x.q)}">${x.a.length?'Answer again':'Answer this'}</button><button class="x" data-act="delQ" data-k="${esc(x.q)}">${armed==='q:'+nq(x.q)?(x.a.length?'Click again to delete question and answers':'Click again to delete'):'Delete'}</button></div>`}</section>`).join('')||'<section><p class="empty">No questions match.</p></section>'}`};
// A project's color: the one chosen in its settings, else one picked from its name.
const pColor=p=>/^#[0-9a-f]{3,8}$/i.test(p.color||'')?p.color:catColor(p.id);
/* Milestones: dated goals in a project ("## Milestones": "- [ ] 2026-11-01: Beta"), shown on a horizontal timeline from
   the project's start to its last milestone, with today marked. */
let msNew=false;
function msSection(p){const ms=(p.ms||[]).slice().sort((a,b)=>a.d.localeCompare(b.d)),t=TD();
 const start=[p.created,...ms.map(m=>m.d)].sort()[0],end0=ms.length?ms[ms.length-1].d:dAdd(t,30),end=end0<=start?dAdd(start,30):end0,span=Math.max(1,(pd(end)-pd(start))/864e5),pos=d=>Math.max(0,Math.min(100,(pd(d)-pd(start))/864e5/span*100));
 const line=ms.length?`<div class="mstl"><div class="mstrack"><i class="msfill" style="width:${pos(t)}%"></i>${t>=start&&t<=end?`<span class="mstoday" style="left:${pos(t)}%" title="Today"></span>`:''}${ms.map((m,i)=>`<span class="msdot ${m.done?'done':m.d<t?'late':''}" style="left:${pos(m.d)}%" title="${esc(m.t)} · ${fmt(m.d)}"></span>`).join('')}</div><div class="msends"><span class="meta">${fmt(start,{month:'short',day:'numeric'})}</span><span class="meta">${fmt(end,{month:'short',day:'numeric'})}</span></div></div>`:'';
 return `<div class="head" style="margin:26px 0 10px"><h2 class="lhead" style="margin:0">Milestones</h2><button class="circ" data-act="msNewT" aria-label="New milestone" title="New milestone" aria-pressed="${msNew}">${lineIco('M12 5v14M5 12h14')}</button></div>
${msNew?`<section><div class="row" style="margin:0"><input id="mst" placeholder="Milestone (e.g. Beta release)" autocomplete="off"><input id="msd" type="date" value="${dAdd(t,14)}" style="flex:0 0 170px"><button class="b tick" data-act="msAdd" aria-label="Add milestone" title="Add">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div></section>`:''}
${line}${ms.length?`<div class="mslist">${ms.map((m,i)=>`<div class="msrow ${m.done?'done':''}"><button class="rchk ${m.done?'on':''}" data-act="msTog" data-i="${(p.ms||[]).indexOf(m)}" role="checkbox" aria-checked="${m.done}" aria-label="Done"></button><span class="t" data-notr>${esc(m.t)}</span><span class="meta ${!m.done&&m.d<t?'late':''}">${m.d===t?'Today':fmt(m.d)}${!m.done?` · ${(d=>d===0?'today':d>0?`in ${d} day${d===1?'':'s'}`:`${-d} day${d===-1?'':'s'} late`)(Math.round((pd(m.d)-pd(t))/864e5))}`:''}</span><button class="cx rbtn" data-act="msDel" data-i="${(p.ms||[]).indexOf(m)}" aria-label="Delete milestone" title="Delete">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`).join('')}</div>`:msNew?'':'<p class="empty">No milestones yet. Add dated goals with + to see them on a timeline.</p>'}`}
/* Project templates: project-templates/<name>.md keeps a project's description, tasks (with due offsets in days) and
   milestones (offsets from the start), so a new project can start from it. */
const ptKeys=()=>keys('project-templates/').sort();
function ptSave(p){const T=tasks().filter(t=>t.proj===p.id),off=d=>d?Math.round((pd(d)-pd(p.created))/864e5):'';
 const body=`${p.desc?p.desc+'\n\n':''}## Tasks\n\n${T.map(t=>`- ${t.title}${t.due?` (+${off(t.due)}d)`:''}`).join('\n')}\n\n## Milestones\n\n${(p.ms||[]).map(m=>`- ${m.t} (+${off(m.d)}d)`).join('\n')}\n`;
 FS['project-templates/'+safeName(p.name)+'.md']=writeNote({fm:{template:'project'},body})}
function ptApply(pid,k){const b=readNote(FS[k]).body,sec=h=>{const i=b.indexOf('## '+h);if(i<0)return[];const rest=b.slice(i).split('\n').slice(1),e=rest.findIndex(l=>/^## /.test(l));return (e<0?rest:rest.slice(0,e)).filter(l=>/^- /.test(l)).map(l=>{const m=l.match(/^- (.*?)(?: \(\+(-?\d+)d\))?\s*$/);return{t:m[1],o:m[2]!==undefined?+m[2]:null}})};
 const p=getP(pid),i=b.indexOf('## Tasks');p.desc=(i<0?b:b.slice(0,i)).trim();p.ms=sec('Milestones').map(x=>({done:false,d:dAdd(p.created,x.o||0),t:x.t}));putP(p);
 putTasks(tasks().concat(sec('Tasks').map(x=>({done:false,title:x.t,due:x.o!==null?dAdd(p.created,x.o):'',rem:'',proj:pid,list:'',added:TD()}))))}
let pTpl='';
let pNew=false,pDone=false,pNoteNew=false,pEdColor=null,pfLink=false,pfPick=false,pfQ='';
/* Project files: links, images and PDFs from Storage. A project lists references (its "## Files" section); new ones are
   saved in Storage first. Titles come from Storage when the item is still there. */
const pfKey=f=>f.att?'a:'+f.att:'u:'+urlKey(f.url);
const pfLive=f=>{const x=stRead(f.k).find(y=>pfKey({...y})===pfKey(f));return x?{...x,k:f.k}:{...f,i:-1,d:'',pin:false,fav:false,desc:''}};
function pfAttach(pid,items){const p=getP(pid),have=new Set((p.files||[]).map(pfKey));let n=0;items.forEach(x=>{const f={k:x.k,title:x.title||'',url:x.att?'':x.url,att:x.att||''};if(!have.has(pfKey(f))){p.files=[...(p.files||[]),f];have.add(pfKey(f));n++}});if(n)putP(p);return n}
async function pfAddLink(pid,raw){const u=stUrl(raw)||(/^[^\s]+\.[a-z]{2,}/i.test(String(raw).trim())?stUrl('https://'+String(raw).trim()):'');if(!u){toast('That doesn’t look like a link');return}
 if(!stRead('links').some(x=>urlKey(x.url)===urlKey(u)))await stAddLink(u);const x=stRead('links').find(y=>urlKey(y.url)===urlKey(u))||{url:u,title:host(u)};pfAttach(pid,[{...x,k:'links'}]);save();render();toast('Link added to the project')}
const pfPickFiles=(pid,kind)=>{const f=document.createElement('input');f.type='file';f.accept=kind==='images'?'image/*':'application/pdf,.pdf';f.multiple=true;f.onchange=async()=>{const add=await stAddFiles(kind,[...f.files]);if(add.length){pfAttach(pid,add);save();render()}};f.click()};
function pfSection(p){const files=(p.files||[]).map(pfLive),set=esc(files.filter(x=>x.k==='images').map(x=>x.att).join('|')),add=lineIco('M12 5v14M5 12h14');
 const card=x=>`<div class="stcard pfcard">${''}<button class="stcov stcov-${x.k}" ${stOpenAttr(x,set)} aria-label="Open ${esc(x.title||x.k)}">${x.k==='images'?`<img data-att="${esc(x.att)}" alt="" loading="lazy">`:x.k==='pdfs'?'<span class="stcpdf">PDF</span>':`<span class="stcfav"><img src="https://icons.duckduckgo.com/ip3/${esc(host(x.url))}.ico" alt="" loading="lazy" onerror="this.remove()"><i>${esc(host(x.url)[0]||'?').toUpperCase()}</i></span><span class="stchost" data-notr>${esc(host(x.url))}</span>`}</button><b data-notr>${esc(x.title||(x.k==='images'?'Image':host(x.url)))}</b><span class="meta">${x.k==='links'?'Link':x.k==='pdfs'?'PDF':'Image'}${x.i<0?' · not in Storage':''}</span><button class="cx stdel" data-act="pfRemove" data-val="${esc(pfKey(x))}" aria-label="Remove from project" title="Remove from project">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`;
 const pool=[...stRead('links').map(x=>({...x,k:'links'})),...stRead('images').map(x=>({...x,k:'images'})),...stRead('pdfs').map(x=>({...x,k:'pdfs'}))].sort((a,b)=>b.d.localeCompare(a.d)),have=new Set(files.map(pfKey)),pq=fold(pfQ);
 const picker=pfPick?`<section class="pfpicker"><div class="head" style="margin:0 0 8px"><b>Add from Storage</b><button class="cx" data-act="pfPickT" aria-label="Close" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button></div><span class="sbox"><input id="pfq" value="${esc(pfQ)}" placeholder="Search Storage" autocomplete="off"></span>
${(l=>l.length?`<div class="pfpool">${l.map(x=>{const on=have.has(pfKey(x));return `<button class="pfopt ${on?'on':''}" data-act="pfToggle" data-val="${x.k}:${x.i}" aria-pressed="${on}">${x.k==='images'?`<span class="stthumb"><img data-att="${esc(x.att)}" alt="" loading="lazy"></span>`:x.k==='pdfs'?'<span class="stpdf">PDF</span>':stFavicon(x)}<span class="cnt"><b data-notr>${esc(x.title||(x.k==='images'?'Image':''))}</b><span class="meta">${x.k==='links'?'Link · '+esc(host(x.url)):x.k==='pdfs'?'PDF':'Image'}</span></span><span class="pfchk">${on?lineIco('M5 12.5l4.5 4.5L19 7'):''}</span></button>`}).join('')}</div>`:`<p class="empty">${pool.length?'Nothing matches.':'Storage is empty. Add new files with the buttons above.'}</p>`)(pool.filter(x=>!pq||fold(x.title+' '+x.url).includes(pq)))}</section>`:'';
 return `<div class="head" style="margin:26px 0 10px"><h2 class="lhead" style="margin:0">Files</h2><span class="row" style="margin:0;gap:6px"><button class="g pfbtn" data-act="pfLinkT" aria-pressed="${pfLink}">${add}Link</button><button class="g pfbtn" data-act="pfAdd" data-val="images">${add}Images</button><button class="g pfbtn" data-act="pfAdd" data-val="pdfs">${add}PDFs</button><button class="g pfbtn" data-act="pfPickT" aria-pressed="${pfPick}">${symbols()?sym('folder-open'):'🗂️'}From Storage</button></span></div>
${pfLink?`<section class="pflink"><div class="row" style="margin:0"><input id="pflink" placeholder="Paste a link (https://…)" autocomplete="off" aria-label="Link"><button class="b tick" data-act="pfLinkAdd" aria-label="Add link" title="Add link">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div><p class="meta" style="margin:6px 0 0">New links are also saved in Storage.</p></section>`:''}${picker}
${files.length?`<div class="stcards pfcards">${files.map(card).join('')}</div>`:'<p class="empty">No files yet. Add links, images or PDFs, new or from Storage.</p>'}`}
function projectView(p){const all=tasks(),ts=all.filter(t=>t.proj===p.id),open=ts.filter(t=>!t.done).sort((a,b)=>(a.due||'9')<(b.due||'9')?-1:1),done=ts.filter(t=>t.done),free=all.filter(t=>!t.proj&&!t.done);
 const nk=p.notes.filter(k=>FS[k]&&!isArch(k)),other=keys('notes/').filter(k=>!p.notes.includes(k)),c=vivid(pColor(p)),pct=ts.length?Math.round(done.length/ts.length*100):0;
 const nt=k=>(stripFM(FS[k]).split('\n').find(l=>l.trim())||'Untitled').replace(/^#+\s*/,'');
 const ec=pEdColor||pColor(p);
 const settings=edP?`<section class="psettings"><h2>Project settings</h2>
${L('Name')}<input id="pen" value="${esc(p.name)}" aria-label="Project name" style="max-width:420px">
${L('Description')}<textarea id="ped" style="min-height:80px" placeholder="What is this project about?">${esc(p.desc)}</textarea>
${L('Color')}<div class="row" style="margin:0;gap:8px">${LCOLORS.map(x=>`<button class="lsw ${ec===x?'on':''}" data-act="pColor" data-val="${x}" style="background:${x}" aria-label="Color ${x}" aria-pressed="${ec===x}"></button>`).join('')}</div>
${(pk=>`${L('Icon')}<div class="row" style="margin:0"><button class="g" data-act="icoPick" data-id="${pk}"><span class="lri" style="background:${vivid(pColor(p))};width:26px;height:26px;display:inline-grid;vertical-align:middle;margin-right:8px">${pIcon(p)}</span>${icoPick===pk?'Close':'Choose icon'}</button></div>${icoPick===pk?picker(pk,p.emoji):''}`)('proj:'+p.id)}
<div class="swrow" style="max-width:420px"><span>Complete</span>${swBtn(p.status==='done','data-act="pStat"','Complete')}</div>
<div class="row" style="margin-top:16px"><button class="b tick" data-act="saveP" aria-label="Save project" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="editP">Cancel</button><button class="g" data-act="ptSave" title="Save this project's tasks and milestones as a template">Save as template</button><span style="flex:1"></span><button class="x" data-act="delP" data-k="${esc(p.id)}">Delete project…</button></div></section>`:'';
 const pb=boardOn('p:'+p.id),pm=matrixOn('p:'+p.id);
 const tk=secOn('tasks')?`<div class="head" style="margin:0 0 6px"><h2 class="lhead" style="margin:0">Tasks</h2>${kbTog('p:'+p.id)}</div>${pb||pm?'':open.map(remRow).join('')}
<div class="rrow rnew"><span class="rchk ghost" aria-hidden="true"></span><div class="rt"><div class="rnline"><input id="ptt" class="rin" placeholder="New task" aria-label="New task"><input id="ptd" type="date" class="pdue" aria-label="Due date" title="Due date"><button class="b tick" data-act="addPT" aria-label="Add task" title="Add task">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div></div></div>
${pb?kBoard(ts):pm?eMatrix(ts):done.length?`<button class="x pdonet" data-act="pDoneT" aria-expanded="${pDone}">${pDone?'Hide':'Show'} ${done.length} completed</button>${pDone?done.map(remRow).join(''):''}`:''}
${free.length?`<div class="row plink"><select id="lt" aria-label="Existing task">${free.map(t=>`<option value="${t.i}">${esc(t.title)}</option>`).join('')}</select><button class="g" data-act="linkT">Link task</button></div>`:''}`:'';
 const pf=pfSection(p),msx=msSection(p);
 const nt2=secOn('notes')?`<div class="head" style="margin:26px 0 10px"><h2 class="lhead" style="margin:0">Notes</h2><button class="circ" data-act="pNoteT" aria-label="New note" title="New note" aria-pressed="${pNoteNew}">${lineIco('M12 5v14M5 12h14')}</button></div>
${pNoteNew?`<section><input id="pnt" placeholder="Note title"><textarea id="pnb" style="margin-top:8px;min-height:90px" placeholder="Write a note for this project"></textarea><div class="row"><button class="b tick" data-act="newPN" aria-label="Add note" title="Add note">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="pNoteT">Cancel</button></div></section>`:''}
${nk.length?`<section class="lrows cnrows">${nk.map(k=>`<div class="pnrow">${cnRow(k).replace('data-act="openNote"','data-act="openN"')}<button class="cx pnun" data-act="unlinkN" data-k="${esc(k)}" aria-label="Unlink note" title="Unlink from project">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`).join('')}</section>`:'<p class="empty">No notes yet.</p>'}
${other.length?`<div class="row plink"><select id="ln" aria-label="Existing note">${other.map(k=>`<option value="${esc(k)}">${esc(nt(k))}</option>`).join('')}</select><button class="g" data-act="linkN">Link note</button></div>`:''}`:'';
 return `<div class="rlist" style="--tc:${c}"><div class="lnav">${backBtn('closeP','Back to projects','Projects')}<span class="meta">${open.length} open</span><button class="circ" data-act="editP" aria-label="Project settings" title="Project settings" aria-pressed="${edP}"><svg class="sym" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5.5" cy="12" r="1.9"/><circle cx="12" cy="12" r="1.9"/><circle cx="18.5" cy="12" r="1.9"/></svg></button></div>
<h1 class="ltitle ptitle" style="--tc:${c}" data-notr><span class="pti" style="background:${vivid(c)}">${pIcon(p)}</span>${esc(p.name)}</h1>
<div class="pinfo"><span class="meta">${p.status==='done'?'Complete':'Active'} · started ${fmt(p.created)} · ${done.length}/${ts.length} tasks done</span><div class="bar pbar"><i style="width:${pct}%;background:${c}"></i></div></div>
${p.desc?`<p class="body pdesc">${esc(p.desc)}</p>`:''}${settings}${msx}${tk}${nt2}${pf}</div>`}
V.projects=()=>{if(curP&&!FS['projects/'+curP+'.md'])curP=null;if(curP)return projectView(getP(curP));
 const ps=projects(),T=tasks(),act=ps.filter(p=>p.status!=='done'),dn=ps.filter(p=>p.status==='done');
 const st=p=>{const ts=T.filter(t=>t.proj===p.id),o=ts.filter(t=>!t.done).length;return{ts,o,pct:ts.length?Math.round((ts.length-o)/ts.length*100):0}};
 const pcard=p=>{const x=st(p);return `<button class="lcard pcard" data-act="openP" data-k="${esc(p.id)}" data-pk="${esc(p.id)}" style="--tc:${vivid(pColor(p))}"><span class="lci">${pIcon(p)}</span><span class="lcn">${x.o}</span><span class="lcl"><span data-notr>${esc(p.name)}</span><span class="pcbar"><i style="width:${x.pct}%"></i></span></span></button>`};
 const prow=p=>{const x=st(p);return `<button class="lrow" data-act="openP" data-k="${esc(p.id)}"><span class="lri" style="background:${vivid(pColor(p))}">${symbols()?sym('check'):'✓'}</span><span class="lrl" data-notr>${esc(p.name)}</span><span class="meta lrc">${x.ts.length}</span><span class="lrch" aria-hidden="true">›</span></button>`};
 return `<div class="lnav"><h1 style="margin:0">Projects</h1><button class="circ" data-act="pNewT" aria-label="New project" title="New project" aria-pressed="${pNew}">${lineIco('M12 5v14M5 12h14')}</button></div>
${pNew?`<section><div class="row" style="margin:0"><button class="circ pnico ${icoPick==='newproj'?'on':''}" data-act="icoPick" data-id="newproj" aria-label="Choose icon" title="Choose icon">${pIcon(PN)}</button><input id="pnm" placeholder="New project name" autocomplete="off" value="${esc(PN.name)}">${ptKeys().length?`<select id="ptpl" aria-label="Template" style="flex:0 0 190px"><option value="">No template</option>${ptKeys().map(k=>`<option value="${esc(k)}">${esc(k.slice(18,-3))}</option>`).join('')}</select>`:''}<button class="b tick" data-act="newP" aria-label="Create project" title="Create project">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="pNewT">Cancel</button></div>${icoPick==='newproj'?picker('newproj',PN.emoji):''}</section>`:''}
${act.length?`<div class="lgrid">${act.map(pcard).join('')}</div>`:pNew?'':'<section><p class="empty">No projects yet. Press + to create your first one. Projects group tasks and notes, and each one is a Markdown file in projects/.</p></section>'}
${dn.length?`<h2 class="lhead">Completed</h2><section class="lrows">${dn.map(prow).join('')}</section>`:''}`};
/* ---------- habits: habits/<id>.md, front matter + "- YYYY-MM-DD: value" log ---------- */
function freshHD(){return {name:'',kind:'yesno',period:'daily',health:'healthy',link:'',cmp:'atleast',target:'',unit:'',after:'',goal:'daily',amode:'never',more:false}}
// Health replaces the old good/bad polarity: "unhealthy" habits work like bad ones (aim for No / less than).
const HEALTHL={healthy:'Healthy',unhealthy:'Not healthy',none:'Not health-related'};
// Small chips on a habit linking it to Health: its health label, and Gym or Meditation when they check it off.
const hLinks=x=>{const on=secOn('health'),ch=(cls,ic,t,act)=>`<button class="hlink ${cls}" ${on?act:'disabled'}>${symbols()?sym(ic):''}${t}</button>`;
 return `<span class="hlinks">${x.health&&x.health!=='none'?ch(x.health,x.health==='healthy'?'heart':'warning-circle',HEALTHL[x.health],'data-act="goHealth" data-val="overview"'):''}${x.link&&HLINK[x.link]?ch('hlinked',HLINK[x.link].ico,'Linked to '+HLINK[x.link].l.replace(/ \(.*\)$/,'').toLowerCase(),x.link==='workouts'?'data-act="goHealth" data-val="gym"':x.link==='meditation'?'data-act="goHealth" data-val="meditation"':''):''}</span>`};
// One-click habits for Health: a weekly gym habit (3 workouts) or a daily meditation habit, filled in from past sessions.
/* Linked habits ("link: <source>" in a habit's front matter) check themselves off from what you do in the app:
   a yes/no habit gets Yes on days with activity; a number habit gets the day's amount (minutes, tasks, glasses…).
   hLinkSync() fills the last 60 days (from the habit's creation) on every render of Home, Habits and Insights; it only
   ever adds, so days you set by hand are never cleared. */
const HLINK={
 meditation:{l:'Meditation sessions',sec:'health',u:'min',ico:'flower-lotus',em:'🧘'},
 workouts:{l:'Gym workouts',sec:'health',u:'workouts',ico:'barbell',em:'🏋️'},
 journal:{l:'Journal entries',sec:'journal',u:'entries',ico:'notebook',em:'📓'},
 mood:{l:'Mood check-ins',sec:'journal',u:'check-ins',ico:'smiley',em:'🙂'},
 question:{l:'Today’s question',sec:'journal',u:'answers',ico:'question',em:'❓'},
 focus:{l:'Focus sessions',sec:'tasks',u:'min',ico:'target',em:'🎯'},
 tasks:{l:'Tasks done',sec:'tasks',u:'tasks',ico:'check-circle',em:'✅'},
 water:{l:'Water (Health → Body)',sec:'health',u:'glasses',ico:'drop',em:'💧'},
 sleep:{l:'Sleep (Health → Body)',sec:'health',u:'h',ico:'moon',em:'😴'}};
// Per-day amounts for every source, built once per sync.
function hSources(){const by=(arr)=>{const o={};arr.forEach(([d,v])=>{if(d)o[d]=(o[d]||0)+v});return o},body={};bodyRead().forEach(x=>body[x.d]=x);
 const jd=by([...entKeys().map(k=>[jeRead(k).date,1]),...dayKeys().filter(k=>freeText(k)!==null).map(k=>[k.slice(8,-3),1])]);
 const qa=by(Object.values(answers()).flatMap(v=>v.a.map(x=>[x.d,1])));
 return{meditation:d=>FS['health/meditation/'+d+'.md']?medTotal(d):0,
  workouts:d=>{const w=FS[wkKey(d)]&&wkRead(d);return w&&(w.day?w.ex.some(e=>e.done):w.ex.some(e=>e.sets.some(s=>setFilled(e,s))))?1:0},
  journal:d=>jd[d]||0,mood:(m=>d=>m[d]||0)(by(moodsRead().map(x=>[x.d,1]))),question:d=>qa[d]||0,
  focus:(m=>d=>m[d]||0)(by(focusLog().map(x=>[x.d,x.min]))),tasks:(m=>d=>m[d]||0)(by(tasks().filter(t=>t.done&&t.doneOn).map(t=>[t.doneOn,1]))),
  water:d=>(body[d]&&body[d].water)||0,sleep:d=>(body[d]&&body[d].sleep)||0}}
let hSyncing=false;
function hLinkSync(){if(hSyncing)return;const hs=habits().filter(h=>h.link&&HLINK[h.link]);if(!hs.length)return;hSyncing=true;let changed=false;
 try{const S=hSources(),t=TD();hs.forEach(h=>{const f=S[h.link];if(!f)return;let ch=false;const from=dAdd(t,-60);
  for(let d=from;d<=t;d=dAdd(d,1)){const v=Math.round(f(d)*100)/100;if(!(v>0))continue;
   if(h.kind==='yesno'){if(h.pol==='good'&&h.log[d]!=='yes'){h.log[d]='yes';ch=true}}
   else if(h.log[d]!==String(v)){h.log[d]=String(v);ch=true}}
  if(ch){putH(h);changed=true}})}finally{hSyncing=false}
 if(changed)save()}
// One-click linked habits (Habits → New habit): only the ones whose section is on and that don't exist yet.
const HPRESETS=[['meditation','Meditate','times',3],['workouts','Gym','times',3],['journal','Journal','daily'],['mood','Check in on my mood','daily'],['question','Answer today’s question','daily'],
 ['focus','Deep work','amount',60,'min'],['tasks','Get things done','amount',3,'tasks'],['water','Drink water','amount',8,'glasses'],['sleep','Sleep well','amount',7,'h']];
const hPresetsOpen=()=>HPRESETS.filter(([l])=>secOn(HLINK[l].sec)&&!habits().some(h=>h.link===l));
function hPreset(l){const p=HPRESETS.find(x=>x[0]===l);if(!p)return;const [link,name,goal,target,unit]=p;let id=slug(name),c=2;while(FS['habits/'+id+'.md'])id=slug(name)+'-'+c++;
 putH({id,name,kind:goal==='amount'?'number':'yesno',period:goal==='times'?'weekly':'daily',health:'healthy',link,cmp:'atleast',target:target||0,unit:unit||'',created:TD(),log:{},symbol:HLINK[link].ico,emoji:HLINK[link].em});
 hLinkSync();save();toast(`Habit “${name}” added · it checks itself off from ${HLINK[link].l.replace(/ \(.*\)$/,'').toLowerCase()}`)}
function hMake(kind){hPreset(kind==='gym'?'workouts':'meditation');return;const name=kind==='gym'?'Gym':'Meditate';let id=slug(name),c=2;while(FS['habits/'+id+'.md'])id=slug(name)+'-'+c++;
 putH({id,name,kind:'yesno',period:kind==='gym'?'weekly':'daily',health:'healthy',workouts:kind==='gym',meditation:kind!=='gym',cmp:'atleast',target:kind==='gym'?3:0,unit:'',created:TD(),log:{},symbol:kind==='gym'?'barbell':'flower-lotus',emoji:kind==='gym'?'🏋️':'🧘'});
 if(kind==='gym')workouts().forEach(syncGym);else medDays().forEach(medSync);toast(`Habit “${name}” created`)}
const hlHabitTip=kind=>{const h=kind==='gym'?gymHabit():medHabit();if(!secOn('habits'))return '';
 return h?`<p class="meta hltip">${kind==='gym'?'Workouts check':'Meditating checks'} off your <button class="clink" data-act="hGo" data-k="${esc(h.id)}">“${esc(h.name)}”</button> habit.</p>`
 :`<div class="hltip row" style="margin:8px 0 0"><span class="meta">${kind==='gym'?'Workouts':'Sessions'} can check off a habit automatically.</span><button class="g" data-act="hMake" data-val="${kind}">${kind==='gym'?'Create a gym habit':'Create a meditation habit'}</button></div>`};
function parseH(k){const s=FS[k]||'',g=n=>{const m=s.match(new RegExp('^'+n+':[ \\t]*(.*)$','m'));return m?m[1].trim():''},log={};
 s.split('\n').forEach(l=>{const m=l.match(/^- (\d{4}-\d{2}-\d{2}): (.+)$/);if(m)log[m[1]]=m[2].trim()});
 const r={id:k.slice(7,-3),key:k,name:g('name')||k.slice(7,-3),kind:g('type')==='number'?'number':'yesno',period:g('period')==='weekly'?'weekly':'daily',health:/^(healthy|unhealthy|none)$/.test(g('health'))?g('health'):g('polarity')==='bad'?'unhealthy':'healthy',link:HLINK[g('link')]?g('link'):g('workouts')==='true'?'workouts':g('meditation')==='true'?'meditation':'',cmp:g('goal')==='lessthan'?'lessthan':'atleast',target:parseFloat(g('target'))||0,unit:g('unit'),symbol:g('symbol'),emoji:g('emoji'),after:g('after'),created:g('created')||TD(),log};r.pol=r.health==='unhealthy'?'bad':'good';r.workouts=r.link==='workouts';r.meditation=r.link==='meditation';return r}
const getH=id=>parseH('habits/'+id+'.md');
// A habit's icon in the current icon style (symbols or emoji), shown in a small round badge.
const hIcon=x=>symbols()?(x.symbol&&SYM[x.symbol]?sym(x.symbol):''):esc(x.emoji||'');
const habits=()=>Object.keys(FS).filter(k=>k.startsWith('habits/')).sort().map(parseH);
const putH=x=>{const ds=Object.keys(x.log).sort();FS['habits/'+x.id+'.md']=`---\nname: ${x.name}\ntype: ${x.kind}\nhealth: ${x.health||'healthy'}\n`+(x.link?`link: ${x.link}\n`:'')+(x.period==='weekly'?'period: weekly\n':'')+(x.kind==='number'||x.period==='weekly'?`goal: ${x.cmp}\ntarget: ${x.target}\n`:'')+(x.kind==='number'?`unit: ${x.unit}\n`:'')+(x.symbol?`symbol: ${x.symbol}\n`:'')+(x.emoji?`emoji: ${x.emoji}\n`:'')+(x.after?`after: ${x.after}\n`:'')+`created: ${x.created}\n---\n\n## Log\n\n`+ds.map(d=>`- ${d}: ${x.log[d]}`).join('\n')+(ds.length?'\n':'')};
const dAdd=(d,n)=>{const x=pd(d);x.setDate(x.getDate()+n);return iso(x)};
const hOk=(x,d)=>{const v=x.log[d];if(v===undefined)return null;
 if(x.kind==='yesno')return x.pol==='good'?v==='yes':v==='no';
 const n=parseFloat(v);if(isNaN(n))return null;return x.cmp==='atleast'?n>=x.target:n<x.target};
/* Weekly habits: each day is still logged, and the week (starting on the Settings week day) is judged as a whole:
   yes/no habits count their "yes" days, number habits add up their values, then compare with the goal. */
const weekStart=d=>dAdd(d,-((pd(d).getDay()-CFG.week+7)%7));
const weekVal=(x,ws)=>{let v=0;for(let i=0;i<7;i++){const l=x.log[dAdd(ws,i)];if(l===undefined)continue;if(x.kind==='yesno'){if(l==='yes')v++}else{const n=parseFloat(l);if(!isNaN(n))v+=n}}return Math.round(v*100)/100};
const weekOk=(x,ws)=>{const v=weekVal(x,ws);return x.cmp==='atleast'?v>=x.target:v<x.target};
const weekUnit=x=>x.kind==='yesno'?'times':(x.unit||'');
function weekStats(x){const cur=weekStart(TD()),first=weekStart(x.created||TD());let ws=weekOk(x,cur)?cur:dAdd(cur,-7),streak=0,ok=0,tot=0;
 for(let n=0;n<520&&ws>=first&&weekOk(x,ws);n++){streak++;ws=dAdd(ws,-7)}
 for(let i=1;i<=8;i++){const w=dAdd(cur,-7*i);if(w<first)break;tot++;if(weekOk(x,w))ok++}
 return {streak,rate:tot?Math.round(ok/tot*100):null,cur:weekVal(x,cur)}}
function hStats(x){if(x.period==='weekly')return weekStats(x);const t=TD();let d=x.log[t]!==undefined?t:dAdd(t,-1),streak=0,ok=0,tot=0;
 while(hOk(x,d)===true){streak++;d=dAdd(d,-1)}
 for(let i=0;i<30;i++){const r=hOk(x,dAdd(t,-i));if(r!==null){tot++;if(r)ok++}}
 return {streak,rate:tot?Math.round(ok/tot*100):null}}
// A habit's goal in words: "Every day", "3 times a week", "At least 8 glasses a day", "Not at all", "Less than 2 coffees a day".
const hGoal=x=>{const per=x.period==='weekly'?' a week':' a day',u=x.kind==='yesno'?(x.target===1?'time':'times'):(x.unit||'');
 if(x.kind==='yesno'&&x.period!=='weekly')return x.pol==='good'?'Every day':'Not at all (aim for No each day)';
 if(x.kind==='yesno')return `${x.cmp==='atleast'?'':'Less than '}${x.target} ${u}${per}`;
 return `${x.cmp==='atleast'?'At least':'Less than'} ${x.target}${u?' '+u:''}${per}`};
const opt=(v,l,c)=>`<option value="${v}" ${c===v?'selected':''}>${l}</option>`;
// Segmented choice for a habit field (HD[f]).
const hseg=(f,o)=>`<div class="moods seg">${o.map(([v,l])=>`<button type="button" data-act="hdSet" data-f="${f}" data-val="${v}" class="${HD[f]===v?'on':''}" aria-pressed="${HD[f]===v}">${l}</button>`).join('')}</div>`;
/* New and edit habit form, built around the goal:
   Every day (yes/no daily) · Times a week (yes/no weekly, at least N) · An amount (number per day or week, at least N)
   · Avoid or limit (yes/no daily aiming for No, or less than N per day or week). hdApply() turns it into the habit fields. */
const HGOALS=[['daily','Every day','Read, journal, take vitamins'],['times','Times a week','Meditate 3 times, gym 4 times'],['amount','An amount','8 glasses a day, 150 min a week'],['avoid','Avoid or limit','No smoking, less than 2 coffees']];
const hdGoalOf=h=>h.kind==='yesno'?(h.period==='weekly'?(h.cmp==='lessthan'?'avoid':'times'):(h.health==='unhealthy'?'avoid':'daily')):(h.cmp==='lessthan'?'avoid':'amount');
const hdKindOf=g=>g==='daily'||g==='times'?'yesno':g==='amount'?'number':(HD.amode==='never'||(!(HD.unit||'').trim()&&HD.period==='weekly'))?'yesno':'number';
function hdApply(){const g=HD.goal;HD.kind=hdKindOf(g);
 if(g==='daily'){HD.period='daily';HD.cmp='atleast';if(HD.health==='unhealthy')HD.health='healthy'}
 else if(g==='times'){HD.period='weekly';HD.cmp='atleast';if(HD.health==='unhealthy')HD.health='healthy'}
 else if(g==='amount'){HD.cmp='atleast';if(HD.health==='unhealthy')HD.health='healthy'}
 else{HD.health='unhealthy';if(HD.amode==='never'){HD.period='daily';HD.cmp='atleast'}else HD.cmp='lessthan'}}
const hdNeedsTarget=()=>HD.goal==='times'||HD.goal==='amount'||(HD.goal==='avoid'&&HD.amode==='limit');
const hdSummary=()=>hdSum0()+(HD.link&&HLINK[HD.link]?' · from '+HLINK[HD.link].l.replace(/ \(.*\)$/,'').toLowerCase():'');
const hdSum0=()=>{const n=(HD.name||'').trim()||'This habit',t=HD.target||'…',u=(HD.unit||'').trim(),per=HD.period==='weekly'?' a week':' a day';
 return HD.goal==='daily'?`${n} · every day`:HD.goal==='times'?`${n} · ${t} time${+HD.target===1?'':'s'} a week`:HD.goal==='amount'?`${n} · at least ${t}${u?' '+u:''}${per}`:HD.amode==='never'?`${n} · not at all`:`${n} · less than ${t}${u?' '+u:(HD.period==='weekly'?' times':'')}${per}`};
const hForm=ed=>{const g=HD.goal||'daily',lock=ed?getH(ed).kind:'',num=(attr,ph)=>`<input type="number" step="any" min="0" data-hd="target" value="${esc(HD.target)}" placeholder="${ph}" ${attr||''} class="hgnum" aria-label="Target">`;
 const perSeg=hseg('period',[['daily','a day'],['weekly','a week']]);
 const det=g==='times'?`<div class="hgdet"><button type="button" class="circ" data-act="hdStep" data-val="-1" aria-label="Fewer">−</button>${num('','3')}<button type="button" class="circ" data-act="hdStep" data-val="1" aria-label="More">+</button><span>times a week</span></div>`
  :g==='amount'?`<div class="hgdet"><span>At least</span>${num('','8')}<input data-hd="unit" class="hgunit" placeholder="glasses, km, min…" value="${esc(HD.unit)}" aria-label="Unit">${perSeg}</div>`
  :g==='avoid'?`<div class="hgdet">${hseg('amode',[['never','Not at all'],['limit','Limit it']])}${HD.amode==='limit'?`<span>Less than</span>${num('','2')}<input data-hd="unit" class="hgunit" placeholder="coffees, cigarettes… (optional)" value="${esc(HD.unit)}" aria-label="Unit">${perSeg}`:''}</div>`:'';
 const tiles=`<div class="hgoals" role="group" aria-label="Goal">${HGOALS.map(([v,l,ex])=>{const dis=lock&&hdKindOf(v)!==lock&&!(v==='avoid');return `<button type="button" class="hgoal ${g===v?'on':''}" data-act="hdSet" data-f="goal" data-val="${v}" aria-pressed="${g===v}" ${dis?'disabled title="An existing habit can’t switch between yes/no and amounts"':''}><b>${l}</b><span>${ex}</span></button>`}).join('')}</div>`;
 const hs=habits().filter(h=>h.id!==ed&&h.period!=='weekly');
 const more=`<button type="button" class="x hmoret" data-act="hdMore" aria-expanded="${!!HD.more}">${HD.more?'Fewer options':'More options'}</button>${HD.more?`<div class="hmore">${g!=='avoid'?`<div><p class="meta lab0">This habit is</p>${hseg('health',[['healthy','Healthy'],['none','Not health-related']])}</div>`:''}
<label class="meta lab" style="margin-top:6px">Checks itself off from <select data-hd="link"><option value="">Nothing, I check it off myself</option>${Object.entries(HLINK).filter(([,v])=>secOn(v.sec)).map(([k,v])=>`<option value="${k}" ${HD.link===k?'selected':''}>${v.l}</option>`).join('')}</select></label>${HD.link&&HLINK[HD.link]?`<p class="meta" style="margin:0">${g==='amount'||(g==='avoid'&&HD.amode==='limit')?`Each day gets your ${HLINK[HD.link].u} from ${HLINK[HD.link].l.replace(/ \(.*\)$/,'').toLowerCase()}.`:`Days with ${HLINK[HD.link].l.replace(/ \(.*\)$/,'').toLowerCase()} are checked off automatically.`}</p>`:''}
${hs.length&&g!=='times'?`<label class="meta lab" style="margin-top:10px">Do it right after <select data-hd="after"><option value="">Nothing (start of a routine)</option>${hs.map(h=>`<option value="${esc(h.id)}" ${HD.after===h.id?'selected':''}>${esc(h.name)}</option>`).join('')}</select></label>`:''}</div>`:''}`;
 const pre=ed?[]:hPresetsOpen();
 return `<div class="hform">${pre.length?`<p class="meta lab0">Quick add · these check themselves off</p><div class="hpresets">${pre.map(([l,n,gl,tg,u])=>`<button type="button" class="hpre ${HD.pre===l?'on':''}" data-act="hPreset" data-val="${l}" aria-pressed="${HD.pre===l}">${uiIco(HLINK[l].ico,HLINK[l].em)}<span><b>${n}</b><span class="meta">${gl==='times'?tg+' times a week':gl==='amount'?tg+' '+u+' a day':'Every day'} · from ${HLINK[l].l.replace(/ \(.*\)$/,'').toLowerCase()}</span></span></button>`).join('')}</div><p class="meta lab0" style="margin-top:14px">${HD.pre?'Choose the goal, then add it':'Or make your own'}</p>`:''}<input data-hd="name" placeholder="Habit name, e.g. Meditate" value="${esc(HD.name)}" aria-label="Habit name">
<p class="meta lab0" style="margin-top:12px">Goal</p>${tiles}${det}<p class="hgsum" id="hgsum" data-notr>${esc(hdSummary())}</p>${more}
<div class="row"><button class="b" data-act="${ed?'saveH':'newH'}"${ed?` data-k="${esc(ed)}"`:''}>${ed?'Save':'Add habit'}</button><button class="g" data-act="cancel">Cancel</button></div></div>`};
let hNew=false,hYear=new Set();
/* Habit stacking: a habit can be done "after" another (front matter "after: <id>"); linked habits form a routine.
   Routines show on Habits and Home with the next step highlighted. */
const hChainOf=id=>{const out=[],seen=new Set();let x=habits().find(h=>h.id===id);while(x&&x.after&&!seen.has(x.id)){seen.add(x.id);out.push(x.after);x=habits().find(h=>h.id===x.after)}return out};
function hChains(){const hs=habits().filter(h=>h.period!=='weekly'),by=id=>hs.find(h=>h.id===id),kids=id=>hs.filter(h=>h.after===id),roots=hs.filter(h=>(!h.after||!by(h.after))&&kids(h.id).length);
 return roots.map(r=>{const c=[r];let cur=r,g=0;while(g++<20){const n=kids(cur.id)[0];if(!n||c.includes(n))break;c.push(n);cur=n}return c})}
const chainStrip=(d,small)=>{const cs=hChains();if(!cs.length)return '';
 return `<div class="hchains ${small?'sm':''}">${cs.map(c=>{const st=c.map(h=>hOk(h,d)),ni=st.findIndex(x=>!x);return `<div class="hchain"><span class="meta hchl">${ni<0?'Routine done':'Routine'}</span>${c.map((h,i)=>`${i?`<span class="hcar">${lineIco('M9 5l7 7-7 7')}</span>`:''}<button class="hstep ${st[i]?'ok':i===ni?'next':''}" ${h.kind==='yesno'?`data-act="hSet" data-k="${esc(h.id)}" data-d="${d}" data-val="${st[i]?'no':'yes'}"`:`data-act="hGo" data-k="${esc(h.id)}"`} title="${st[i]?'Done':i===ni?'Next':''}">${st[i]?lineIco('M5 12.5l4.5 4.5L19 7'):hIcon(h)||''}<span data-notr>${esc(h.name)}</span></button>`).join('')}</div>`}).join('')}</div>`};
// Year heatmap: the last 53 weeks, one square per day, colored by how the day went.
function hHeat(x){const t=TD(),ws=weekStart(dAdd(t,-364)),cols=[];for(let w=0;w<53;w++){const days=[];for(let i=0;i<7;i++){const d=dAdd(ws,w*7+i);if(d>t){days.push('<i class="fut"></i>');continue}
  const v=x.log[d],r=hOk(x,d),lv=v===undefined?0:x.kind==='number'&&x.target?Math.max(1,Math.min(4,Math.ceil((parseFloat(v)||0)/x.target*4))):4;days.push(`<i class="${r===null?'':r?'ok l'+lv:'no'}" title="${fmt(d)}${v!==undefined?' · '+esc(v):''}"></i>`)}cols.push(`<span>${days.join('')}</span>`)}
 const done=Object.keys(x.log).filter(d=>d>=dAdd(t,-364)&&hOk(x,d)).length;
 return `<div class="hheat"><div class="hhgrid">${cols.join('')}</div><p class="meta" style="margin:6px 0 0">${done} good day${done===1?'':'s'} in the last year</p></div>`}
// On Habits, a strip linking to Health: today's healthy habits done, unhealthy ones avoided, and this week's workouts.
const hHealthBar=(hs,t)=>{if(!secOn('health'))return '';const g=hs.filter(h=>h.health==='healthy'&&h.period!=='weekly'),b=hs.filter(h=>h.health==='unhealthy'&&h.period!=='weekly');if(!g.length&&!b.length&&!gymHabit()&&!medHabit())return '';
 const gd=g.filter(h=>hOk(h,t)).length,bd=b.filter(h=>hOk(h,t)).length,ws=weekStart(t),wk=workouts().filter(d=>d>=ws).length;
 return `<button class="hhbar" data-act="goHealth" data-val="overview"><span class="hhico">${symbols()?sym('heartbeat'):'❤️'}</span><span class="t"><b>Health today</b><span class="meta">${[g.length?`${gd}/${g.length} healthy done`:'',b.length?`${bd}/${b.length} avoided`:'',`${wk} workout${wk===1?'':'s'} this week`,medTotal(t)?`${medFmt(medTotal(t))} meditated`:''].filter(Boolean).join(' · ')}</span></span><span class="lrch" aria-hidden="true">›</span></button>`};
V.habits=()=>{const hs=habits(),t=TD(),d=hday;
 // weekly: this week's total against the goal, a bar, and one dot per day (filled when logged as done)
 const weekBar=(x,ws)=>{const v=weekVal(x,ws),pct=x.target?Math.min(100,Math.round(v/x.target*100)):0,good=x.cmp==='atleast';
  return `<p class="meta" style="margin:10px 0 2px"><b style="color:var(--ink)">${v} / ${x.target}</b> ${esc(weekUnit(x))} this week${good?'':' (stay under)'}</p><div class="bar" style="max-width:320px"><i style="width:${pct}%;${good?'':v>=x.target?'background:#c4564f':''}"></i></div>
<div class="hs">${[0,1,2,3,4,5,6].map(i=>{const y=dAdd(ws,i),l=x.log[y],on=x.kind==='yesno'?l==='yes':l!==undefined&&parseFloat(l)>0;return `<span class="hd ${y>TD()?'fut':on?(good?'ok':'no'):''}" title="${fmt(y)}${l!==undefined?' · '+esc(l):''}"></span>`}).join('')}</div>`};
 const strip=x=>[6,5,4,3,2,1,0].map(i=>{const y=dAdd(t,-i),r=hOk(x,y);return `<span class="hd ${r===null?'':r?'ok':'no'}" title="${fmt(y)}"></span>`}).join('');
 const card=x=>{if(edH===x.id)return `<section><h2>Edit habit</h2>${hForm(x.id)}</section>`;
  const wk=x.period==='weekly',st=hStats(x),ws=weekStart(d),r=wk?(weekOk(x,ws)?true:null):hOk(x,d),v=x.log[d],e=esc(x.id);
  const ctl=x.kind==='yesno'
   ?`<div class="moods seg"><button data-act="hSet" data-k="${e}" data-val="yes" class="${v==='yes'?'on':''}">Yes</button><button data-act="hSet" data-k="${e}" data-val="no" class="${v==='no'?'on':''}">No</button></div>`
   :`<div class="row" style="margin:0"><input type="number" step="any" id="hv-${e}" data-hv="${e}" value="${v!==undefined?esc(v):''}" placeholder="Value" style="max-width:140px" aria-label="Value"><span class="meta">${esc(x.unit)}</span><button class="b" data-act="hLog" data-k="${e}">Save</button>${v!==undefined?`<button class="g" data-act="hClr" data-k="${e}">Clear</button>`:''}</div>`;
  return `<section><div class="head" style="margin:0"><span class="hname"><button class="hico hbtn" data-act="icoPick" data-id="habit:${e}" aria-label="Choose icon for ${esc(x.name)}" title="Choose icon">${hIcon(x)||'＋'}</button><b style="font-size:17px">${esc(x.name)}</b></span></div>${icoPick==='habit:'+x.id?picker('habit:'+x.id,x.emoji||''):''}
<p class="meta" style="margin:4px 0 6px">Goal: ${esc(hGoal(x))}</p><div style="margin:0 0 10px">${hLinks(x)}</div>
<div class="row" style="margin:0;align-items:center">${ctl}${r===null?'':`<span class="meta" style="color:${r?'#4f9d7c':'#c4564f'};font-weight:700">${r?'Goal met':'Goal missed'}</span>`}</div>
${wk?weekBar(x,ws):`<div class="hs">${strip(x)}</div>`}
<p class="meta" style="margin:0">${st.streak?st.streak+(wk?'-week':'-day')+' streak':'No streak yet'}${st.rate!==null?` · ${st.rate}% success over the last ${wk?'8 weeks':'30 days'}`:''}</p>
${hYear.has(x.id)?hHeat(x):''}<div class="row" style="margin:6px 0 0"><button class="x" data-act="hYearT" data-k="${e}" aria-pressed="${hYear.has(x.id)}">${hYear.has(x.id)?'Hide year':'Year'}</button><button class="x" data-act="editH" data-k="${e}">Edit</button><button class="x" data-act="delH" data-k="${e}">${armed==='habit:'+x.id?'Click again to delete':'Delete'}</button></div></section>`};
 return `<div class="lnav"><h1 style="margin:0">Habits</h1><button class="circ" data-act="hNew" aria-label="New habit" title="New habit" aria-pressed="${hNew}">${lineIco('M12 5v14M5 12h14')}</button></div><p class="sub">Track yes/no habits or numeric goals, daily or weekly. Saved as Markdown in habits/.</p>
${hNew&&!edH?`<section><h2>New habit</h2>${hForm('')}</section>`:''}${hHealthBar(hs,t)}${chainStrip(d)}
<section><div class="head" style="margin:0"><button class="g" data-act="hPrev" aria-label="Previous day">Prev</button><b>${d===t?'Today · ':''}${fmt(d,LONG)}</b><span style="display:flex;gap:8px">${d!==t?'<button class="g" data-act="hToday">Today</button>':''}<button class="g" data-act="hNext" ${d>=t?'disabled':''} aria-label="Next day">Next</button></span></div></section>
${hs.length?'':'<section><p class="empty">No habits yet. Press + to add your first one.</p></section>'}
${hs.some(x=>x.period!=='weekly')?`<h2 class="hsec">Daily habits</h2>${hs.filter(x=>x.period!=='weekly').map(card).join('')}`:''}
${hs.some(x=>x.period==='weekly')?`<h2 class="hsec">Weekly habits <span class="meta">${fmt(weekStart(d))} – ${fmt(dAdd(weekStart(d),6))}</span></h2>${hs.filter(x=>x.period==='weekly').map(x=>edH===x.id?card(x):weekCard(x,d)).join('')}`:''}`};
/* Weekly habit card: tick the days you did it (Mon…Sun of the shown week); the badge says Complete once the week's
   minimum is reached ("Within limit" for less-than goals). Number habits keep a value box for the shown day. */
const weekStatus=(x,ws)=>{const v=weekVal(x,ws),ok=weekOk(x,ws);
 return x.cmp==='atleast'?{ok,text:ok?'✓ Complete':`${Math.max(0,Math.round((x.target-v)*100)/100)} more to go`}:{ok,text:ok?'✓ Within limit':'Over the limit'}};
function weekCard(x,d){const ws=weekStart(d),t=TD(),e=esc(x.id),st=hStats(x),ws2=weekStatus(x,ws),v=weekVal(x,ws),pct=x.target?Math.min(100,Math.round(v/x.target*100)):0;
 const days=[0,1,2,3,4,5,6].map(i=>{const y=dAdd(ws,i),l=x.log[y],on=x.kind==='yesno'?l==='yes':l!==undefined&&parseFloat(l)>0,fut=y>t;
  return x.kind==='yesno'?`<button class="wday ${on?'on':''} ${y===d?'sel':''}" data-act="hChk" data-k="${e}" data-d="${y}" ${fut?'disabled':''} aria-pressed="${on}" aria-label="${fmt(y,LONG)}${on?', done':''}"><span>${DN[pd(y).getDay()]}</span><i>✓</i></button>`
   :`<span class="wday ${on?'on':''} ${y===d?'sel':''} ${fut?'fut':''}" title="${fmt(y)}${l!==undefined?' · '+esc(l):''}"><span>${DN[pd(y).getDay()]}</span><i>${l!==undefined?esc(l):''}</i></span>`}).join('');
 const val=x.kind==='number'?`<div class="row" style="margin:10px 0 0"><input type="number" step="any" id="hv-${e}" data-hv="${e}" value="${x.log[d]!==undefined?esc(x.log[d]):''}" placeholder="Value for ${fmt(d)}" style="max-width:180px" aria-label="Value"><span class="meta">${esc(x.unit)}</span><button class="b" data-act="hLog" data-k="${e}">Save</button></div>`:'';
 return `<section class="hweek ${ws2.ok&&x.cmp==='atleast'?'complete':''}"><div class="head" style="margin:0"><span class="hname"><button class="hico hbtn" data-act="icoPick" data-id="habit:${e}" aria-label="Choose icon for ${esc(x.name)}" title="Choose icon">${hIcon(x)||'＋'}</button><b style="font-size:17px">${esc(x.name)}</b></span><span class="wbadge ${ws2.ok?'ok':x.cmp==='lessthan'?'bad':''}">${ws2.text}</span></div>${icoPick==='habit:'+x.id?picker('habit:'+x.id,x.emoji||''):''}
<p class="meta" style="margin:4px 0 6px">Goal: ${esc(hGoal(x))}</p><div style="margin:0 0 10px">${hLinks(x)}</div>
<div class="wdays">${days}</div>${val}
<p class="meta" style="margin:10px 0 2px"><b style="color:var(--ink)">${v} / ${x.target}</b> ${esc(weekUnit(x))}</p><div class="bar" style="max-width:360px"><i style="width:${pct}%;${x.cmp==='lessthan'&&!ws2.ok?'background:#c4564f':''}"></i></div>
<p class="meta" style="margin:6px 0 0">${st.streak?st.streak+'-week streak':'No streak yet'}${st.rate!==null?` · ${st.rate}% of weeks met over the last 8`:''}</p>
${hYear.has(x.id)?hHeat(x):''}<div class="row" style="margin:6px 0 0"><button class="x" data-act="hYearT" data-k="${e}" aria-pressed="${hYear.has(x.id)}">${hYear.has(x.id)?'Hide year':'Year'}</button><button class="x" data-act="editH" data-k="${e}">Edit</button><button class="x" data-act="delH" data-k="${e}">${armed==='habit:'+x.id?'Click again to delete':'Delete'}</button></div></section>`}
/* ---------- calendar day: everything created on or relevant to a date ---------- */
const sub=t=>`<p class="meta" style="margin:18px 0 4px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;font-size:12px">${t}</p>`;
const noteLines=k=>stripFM(FS[k]).split('\n').filter(l=>l.trim());
const habitItem=(x,d)=>{const v=x.log[d],wk=x.period==='weekly',wv=wk?weekVal(x,weekStart(d)):0,r=wk?(weekOk(x,weekStart(d))?true:x.cmp==='atleast'?null:false):hOk(x,d),e=esc(x.id);
  const ctl=wk&&x.kind==='yesno'?`<button class="hcheck ${v==='yes'?'on':''}" data-act="hChk" data-k="${e}" data-d="${d}" aria-pressed="${v==='yes'}"><i>✓</i>${v==='yes'?'Done':'Mark as done'}${d===TD()?' today':''}</button>`
   :x.kind==='yesno'
   ?`<div class="moods seg"><button data-act="hSet" data-k="${e}" data-d="${d}" data-val="yes" class="${v==='yes'?'on':''}">Yes</button><button data-act="hSet" data-k="${e}" data-d="${d}" data-val="no" class="${v==='no'?'on':''}">No</button></div>`
   :`<div class="row" style="margin:0"><input type="number" step="any" id="hv-${e}" data-hv="${e}" value="${v!==undefined?esc(v):''}" placeholder="Value" style="max-width:130px" aria-label="Value"><span class="meta">${esc(x.unit)}</span><button class="b" data-act="hLog" data-k="${e}" data-d="${d}">Save</button>${v!==undefined?`<button class="g" data-act="hClr" data-k="${e}" data-d="${d}">Clear</button>`:''}</div>`;
  return `<div class="item" style="display:block"><div class="head" style="margin:0 0 2px"><b class="hname">${hIcon(x)?`<span class="hico">${hIcon(x)}</span>`:''}${esc(x.name)}</b><span class="meta" style="font-weight:700;color:${r===null?'inherit':r?'#4f9d7c':'#c4564f'}">${wk?`${weekStatus(x,weekStart(d)).ok?weekStatus(x,weekStart(d)).text+' · ':''}${wv}/${x.target} ${esc(weekUnit(x))} this week`:r===null?'Not logged':r?'Goal met':'Goal missed'}</span></div><span class="meta" style="display:block;margin-bottom:8px">${esc(hGoal(x))}</span>${ctl}</div>`};
function dayData(d){const ans=answers(),jf=FS[jp(d)]||'';
 const entries=[...entOn(d).map(e=>({time:e.time,q:'',text:e.body.trim(),mood:e.mood})),...jf.split(/\n(?=## )/).slice(1).map(s=>{const m=s.match(/^## ([^\n]*)\n*([\s\S]*)$/),hd=m[1],i=hd.indexOf(' — ');return {time:i<0?hd.trim():hd.slice(0,i).trim(),q:i<0?'':hd.slice(i+3).trim(),text:m[2].trim()}})].sort((a,b)=>(a.time||'').localeCompare(b.time||''));
 return {mood:getMood(d),free:entries.filter(e=>!e.q),qa:entries.filter(e=>e.q),
  asked:qLines().filter(x=>x.d===d).map(x=>({q:x.q,answered:(ans[nq(x.q)]||{a:[]}).a.length>0})),
  notes:keys('notes/').filter(k=>noteDate(k)===d).sort().map(k=>{const l=noteLines(k);return {k,t:(l[0]||'Untitled').replace(/^#+\s*/,''),snip:l.slice(1).join(' ').slice(0,140)}}),
  hs:d<=TD()?habits():[],
  ps:projects().filter(p=>p.created===d)}}
function dayDetail(d,T,E,dd){const out=[],tk=T.filter(x=>x.due===d),ev=evOn(E,d),
 dn=T.filter(x=>x.done&&x.doneOn===d),rem=T.filter(x=>x.rem&&x.rem.slice(0,10)===d&&!tk.some(y=>y.i===x.i)),
 dot=c=>`<span class="dot" style="background:var(${c});margin-top:6px"></span>`,line=(c,t)=>`<div class="item">${dot(c)}<div class="t">${esc(t)}</div></div>`;
 if(dd.mood&&cOn('journal','calJournal'))out.push(sub('Mood')+`<p style="margin:0"><span class="dot" style="background:var(${MOOD[dd.mood-1][1]});width:10px;height:10px"></span> ${MOOD[dd.mood-1][0]}</p>`);
 if(ev.length)out.push(sub('Events')+ev.sort(evSort).map(e=>`<div class="item">${dot('--am')}<div class="t"><button class="clink evlink" data-act="evEdit" data-i="${e.i}" title="Edit event">${esc(e.title)}</button><span class="meta" style="display:block">${e.start?evTime(e):'All day'}</span></div><button class="x" data-act="delE" data-i="${e.i}">Delete</button></div>`).join(''));
 if(tk.length&&cOn('tasks','calTasks'))out.push(sub('Tasks due')+tk.map(taskRow).join(''));
 if(rem.length&&cOn('tasks','calTasks'))out.push(sub('Reminders')+rem.map(x=>`<div class="item">${dot('--ac')}<div class="t">${esc(x.title)}<span class="meta" style="display:block">Reminder · ${tf(x.rem.slice(11))}</span></div></div>`).join(''));
 if(dn.length&&cOn('tasks','calTasks'))out.push(sub('Tasks completed')+dn.map(x=>line('--m4',x.title)).join(''));
 if(dd.free.length&&cOn('journal','calJournal'))out.push(sub('Journal')+dd.free.map(e=>`<div class="item" style="display:block"><span class="meta">${esc(tf(e.time))}${e.mood?` · <span class="dot" style="background:var(${MOOD[e.mood-1][1]});width:8px;height:8px"></span> ${MOOD[e.mood-1][0]}`:''}</span><p class="body">${esc(e.text)}</p></div>`).join(''));
 if(dd.qa.length&&cOn('journal','calJournal'))out.push(sub('Questions answered')+dd.qa.map(e=>`<div class="item" style="display:block"><p class="q" style="font-size:16px;margin:0 0 2px">${esc(e.q)}</p><span class="meta">${esc(tf(e.time))}</span><p class="body">${esc(e.text)}</p></div>`).join(''));
 const open=dd.asked.filter(x=>!x.answered);
 if(open.length&&cOn('journal','calJournal'))out.push(sub('Questions asked, not answered')+open.map(x=>`<div class="item"><div class="t"><span class="q" style="font-size:16px">${esc(x.q)}</span></div><button class="x" data-act="askGo" data-k="${esc(x.q)}">Answer</button></div>`).join(''));
 if(dd.notes.length&&cOn('notes','calNotes'))out.push(sub('Notes created')+dd.notes.map(n=>`<div class="item" style="display:block"><b>${esc(n.t)}</b>${n.snip?`<p class="meta" style="margin:2px 0">${esc(n.snip)}</p>`:''}<button class="x" data-act="openN" data-k="${esc(n.k)}" style="margin-left:-6px">Open in Notes</button></div>`).join(''));
  if(dd.hs.length&&cOn('habits','calHabits'))out.push(sub('Habits')+dd.hs.map(x=>habitItem(x,d)).join('')+`<button class="x" data-act="hOpen" data-d="${d}" style="margin-left:-6px">Open in Habits</button>`);
 if(dd.ps.length&&cOn('projects','calProjects'))out.push(sub('Projects started')+dd.ps.map(p=>`<div class="item">${dot('--m2')}<div class="t">${esc(p.name)}</div><button class="x" data-act="openPj" data-k="${esc(p.id)}">Open</button></div>`).join(''));
 return out.join('')||'<p class="empty">Nothing on this day.</p>'}
/* Settings → Storage: which folder the desktop app keeps its files in. After a folder is picked the person chooses
   to copy their files there or just switch; pending saves are finished first, then the app reloads from the new folder. */
let pendDir=null,dirBusy=false;
const atDefault=()=>!BOOT.default_dir||BOOT.dir===BOOT.default_dir;
const storageBody=()=>!TAURI?'<p class="meta" style="margin:0">In this browser preview everything is stored inside the browser. In the desktop app you can choose any folder on your computer; the default is ~/Prodify.</p>'
 :`<p class="meta" style="margin:0 0 6px">Your notes, journal, tasks, lists and photos are files in${atDefault()?' the default folder':' this folder'}:</p><p class="path">${esc(BOOT.dir||'')}</p>
${pendDir?`<div class="callout"><p style="margin:0 0 4px">Switch to <span class="path inline">${esc(pendDir)}</span>?</p><p class="meta" style="margin:0 0 10px">Copying never overwrites files already in that folder, and your current folder is left as it is.</p>
<div class="row" style="margin:0"><button class="b" data-act="dirGo" data-copy="1" ${dirBusy?'disabled':''}>Copy my files there and switch</button><button class="g" data-act="dirGo" data-copy="0" ${dirBusy?'disabled':''}>Switch without copying</button><button class="x" data-act="dirCancel" ${dirBusy?'disabled':''}>Cancel</button></div></div>`
 :`<div class="row" style="margin:0"><button class="g" data-act="dirPick">Change folder…</button><button class="g" data-act="openDir">Open folder</button>${atDefault()?'':`<button class="x" data-act="dirDefault">Use default (${esc(BOOT.default_dir)})</button>`}</div>`}`;
/* Backup folder (Settings → Storage): a second folder that gets a copy of the chosen kinds of data as you work.
   Write-only: files are copied there when they change, nothing is ever read back from it or deleted in it (a note
   deleted or renamed here keeps its old copy there). CFG.mirDir = the folder, CFG.mirWhat = the kinds to copy
   (missing = all). MIRM remembers what was copied this session, so only changes are written; the first copy after
   the app opens writes everything once. */
const MIRC=[['notes','Notes',k=>/^(notes|archive|templates|history|trash)\//.test(k)],['journal','Journal',k=>/^journal\//.test(k)||k==='questions.md'],
 ['tasks','Tasks and lists',k=>k==='tasks.md'||k==='focus.md'||/^lists\//.test(k)],['projects','Projects',k=>/^projects\//.test(k)],
 ['calendar','Calendar and birthdays',k=>k==='events.md'||k==='birthdays.md'],['habits','Habits',k=>/^habits\//.test(k)],['health','Health',k=>/^health\//.test(k)],
 ['collections','Collections and quotes',k=>/^collections\//.test(k)||k==='quotes.md'],['storage','Storage (links, images, PDFs)',k=>/^storage\//.test(k)],
 ['board','Home board',k=>k==='board.md'],['other','Everything else',null],['att','Photos and files (attachments)',null]];
const mirOn=id=>!CFG.mirWhat||CFG.mirWhat.includes(id);
const mirKind=k=>{for(const[id,,t]of MIRC)if(t&&t(k))return id;return 'other'};
let MIRM={},MIRA=new Set(),mirTimer=null,mirBusy=false,mirErr='',mirLast=0;
function mirSoon(ms){if(!TAURI||!CFG.mirDir)return;clearTimeout(mirTimer);mirTimer=setTimeout(mirRun,ms==null?2000:ms)}
async function mirRun(){if(!TAURI||!CFG.mirDir||LOCKED||!ACCREADY)return;if(mirBusy){mirSoon();return}mirBusy=true;const dir=CFG.mirDir;
 try{const write={},plain={};for(const k in FS)if(FS[k]!==MIRM[k]&&(k===ACCK||mirOn(mirKind(k)))){write[k]=encOn()&&k!==ACCK?await encText(FS[k]):FS[k];plain[k]=FS[k]}
  const att=[];if(mirOn('att')){const rx=/attachments\/([^)\s"'<>]+)/g;for(const k in FS){let m;rx.lastIndex=0;while((m=rx.exec(FS[k])))if(!MIRA.has(m[1]))att.push(decodeURIComponent(m[1]))}}
  const names=[...new Set(att)];if(!Object.keys(write).length&&!names.length){mirBusy=false;return}
  await TAURI.invoke('mirror_files',{dir,write,attachments:names});if(CFG.mirDir!==dir)return;
  Object.assign(MIRM,plain);names.forEach(n=>MIRA.add(encodeURI(n)).add(n));const was=mirErr;mirErr='';mirLast=Date.now();if(was&&view==='settings')rerenderKeep()}
 catch(e){const m=String(e);if(m!==mirErr){mirErr=m;toast('Backup folder: '+m);if(view==='settings')rerenderKeep()}}
 finally{mirBusy=false}}
// A new folder or a different choice of data starts a full copy.
const mirReset=()=>{MIRM={};MIRA=new Set();mirErr='';mirSoon(300)};
const mirSection=()=>!TAURI?'':`<section><h2>Backup folder</h2><p class="meta" style="margin:0 0 10px">A second folder, for example on another drive, that gets a copy of your data as you work. Prodify only writes to it: it never reads from it and never deletes anything there, so notes you delete here are kept in the backup.</p>
${CFG.mirDir?`<p class="path">${esc(CFG.mirDir)}</p>${mirErr?`<p class="meta mirerr" style="margin:6px 0">${esc(mirErr)}</p>`:mirLast?`<p class="meta" style="margin:6px 0">Up to date · last copy ${tf((d=>pad(d.getHours())+':'+pad(d.getMinutes()))(new Date(mirLast)))}</p>`:''}
<div class="row" style="margin:8px 0 14px"><button class="g" data-act="mirPick">Change folder…</button><button class="g" data-act="mirNow">Copy now</button><button class="x" data-act="mirOff">Stop backing up</button></div>
<p class="meta" style="margin:0 0 6px">What to copy</p><div class="mirwhat">${MIRC.map(([id,l])=>swRow(l,'mir:'+id,mirOn(id))).join('')}</div>`
 :`<div class="row" style="margin:0"><button class="g" data-act="mirPick">Choose backup folder…</button></div>`}</section>`;
// Where the data lives: the Markdown folder (the default) or app storage, a private database inside Prodify.
let storeBusy=false;
const storeModeBody=()=>!TAURI?'':`${L('Where your data is kept')}<div class="pseg storeseg" role="group" aria-label="Where your data is kept"><button class="${STORE_DB?'':'on'}" data-act="${STORE_DB?'storeMd':''}" aria-pressed="${!STORE_DB}" ${storeBusy?'disabled':''}>Markdown folder</button><button class="${STORE_DB?'on':''}" data-act="${STORE_DB?'':'storeDb'}" aria-pressed="${STORE_DB}" ${storeBusy?'disabled':''}>App storage</button></div>
<p class="meta" style="margin:6px 0 0">${STORE_DB?'Your notes, journal, tasks, photos and backups are in a private database inside Prodify. Other apps can’t open them'+(encOn()?', and with encryption on even their names are hidden':'')+'. Switching back writes them out as Markdown files again.':'Your data is plain Markdown files that other apps (Obsidian, any editor, Syncthing) can open. App storage keeps everything in a private database inside Prodify instead'+(ACCT&&ACCT.enc?', with even file names encrypted':'')+'.'}</p>`;
const storageSection=()=>`<section><h2>Storage</h2>${STORE_DB?'':storageBody()}${storeModeBody()}</section>${mirSection()}`;
async function storeSwitch(to){const db=to==='db',ok=await askConfirm(db?{title:'Keep your data inside Prodify?',text:'Everything in your folder is copied into a private database inside the app. Your folder is left as it is, as a copy, but Prodify stops using it. You can switch back at any time.',ok:'Move into the app'}
  :{title:'Go back to the Markdown folder?',text:`Your data is written out as Markdown files in ${BOOT.dir}. Files already there from before are moved into a hidden .prodify-old folder, not deleted.`,ok:'Write the files'});
 if(!ok)return;storeBusy=true;render();
 try{flushNote();save();await SQ;let files=null;
  if(!db){files={};for(const k in FS)files[k]=encOn()&&k!==ACCK?await encText(FS[k]):FS[k]}
  const r=await TAURI.invoke('storage_switch',{mode:to,files});
  toast(db?`Moved ${r.files} file${r.files===1?'':'s'} into the app · restarting…`:`Wrote ${r.files} file${r.files===1?'':'s'} to the folder · restarting…`);
  try{sessionStorage.setItem('prodify.switched','1')}catch(e){}setTimeout(()=>location.reload(),900)}
 catch(e){storeBusy=false;render();fail('Could not switch storage: '+e)}}
async function switchFolder(copy){const path=pendDir;if(!path)return;if(path===BOOT.dir){pendDir=null;render();toast('That is already the current folder');return}
 dirBusy=true;render();flushNote();
 try{await SQ;const r=await TAURI.invoke('set_data_dir',{path,copy});
  if(ME){ME.dir=r.dir;userSave()}try{sessionStorage.setItem('prodify.switched','1')}catch(e){}
  toast(copy?`Switched. Copied ${r.copied} file${r.copied===1?'':'s'}${r.skipped?`, kept ${r.skipped} already there`:''}.`:'Switched folder.');setTimeout(()=>location.reload(),900)}
 catch(e){dirBusy=false;render();fail('Could not switch folder: '+e)}}
// Toggle switch. swBtn takes the button's own data attributes; tog flips a setting; swRow lays a label beside it.
const swBtn=(on,attrs,label)=>`<button class="sw ${on?'on':''}" role="switch" aria-checked="${!!on}" aria-label="${esc(label||'')}" ${attrs}><i></i></button>`;
const tog=(s,on,label)=>swBtn(on,`data-act="set" data-s="${s}" data-val="${on?'off':'on'}"`,label);
const swRow=(label,s,on)=>`<div class="swrow"><span>${label}</span>${tog(s,on,label)}</div>`;
const wxSettings=()=>`${L('Weather city')}<div class="row" style="margin:0;gap:8px;flex-wrap:nowrap;max-width:420px"><input id="wcity" value="${esc(CFG.weather?CFG.weather.name:'')}" placeholder="For example Madrid" autocomplete="off" aria-label="Weather city"><button class="g" data-act="wxFind">Save</button></div><p class="meta" style="margin:6px 0 0">${CFG.weather?`Showing the weather for ${esc([...new Set([CFG.weather.name,CFG.weather.admin,CFG.weather.country].filter(Boolean))].join(', '))}. Leave it empty and save to turn it off.`:'Shown on the Time & weather card on Home. Forecasts come from Open-Meteo.'}</p>${L('Temperature')}${seg('tempUnit',[['c','°C'],['f','°F']],CFG.tempUnit==='f'?'f':'c')}`;
const seg=(s,o,c)=>`<div class="moods seg">${o.map(([v,l])=>`<button data-act="set" data-s="${s}" data-val="${v}" class="${String(c)===String(v)?'on':''}">${l}</button>`).join('')}</div>`;
const L=t=>`<p class="meta" style="margin:14px 0 6px">${t}</p>`;
// Settings search: filters the searchable settings (SETS) and shows each with its control, so it can be changed in place.
let setQ='';
const setSearch=()=>{const w=hWords(setQ),hits=SETS().filter(setOk).filter(x=>{const t=fold(x[0]+' '+x[1]);return w.every(y=>t.includes(y))});
 return hits.length?`<section>${hits.map(x=>setRow(x,w)).join('')}</section>`:`<section><p class="empty">No settings match “${esc(setQ.trim())}”.</p></section>`};
/* Settings groups: the Settings page shows them as tiles, and each opens only its own sections (no long scroll).
   Sections are matched to a group by their heading (the Account section by its class); anything unknown goes to General. */
let SETG=null;
const SETGROUPS=[['look','Appearance','palette','🎨',['Appearance'],'Theme, colors, fonts, sidebar and page width'],['general','General','gear','⚙️',['General','Calendar and time'],'Name, language, weather, time format and calendar'],
 ['sections','Sections and Home','squares-four','▦',['Sections','Home cards'],'Turn sections on or off, icons and Home cards'],['content','Notes, journal and more','note','📝',['Notes','Journal','Reminders','Collections'],'Notes, journal, reminders and collections'],
 ['account','Account and data','user-circle','👤',['@acc','Prodify Cloud','Privacy','Users','Storage','Backup folder','Backups','Reset'],'Password, encryption, cloud sync, users, where your data lives and backups'],
 ['tools','Integrations and commands','plug','🔌',['Integrations','Commands'],'AI, connected services and custom commands']];
function setSplit(){const t=document.createElement('template'),by={};t.innerHTML=V.settingsAll();
 [...t.content.children].forEach(el=>{const h=((el.querySelector('h2')||{}).textContent||'').trim(),key=el.classList&&el.classList.contains('accsec')?'@acc':h,g=(SETGROUPS.find(x=>x[4].includes(key))||SETGROUPS[1])[0];el._k=key;(by[g]=by[g]||[]).push(el)});
 SETGROUPS.forEach(([id,,,,ks])=>{if(by[id])by[id].sort((a,b)=>(ks.indexOf(a._k)+1||99)-(ks.indexOf(b._k)+1||99))});return by}
const setTiles=by=>`<div class="setgrid">${SETGROUPS.map(([id,l,ic,em,,d])=>{const vis=(by[id]||[]).filter(el=>!el.hidden);if(!vis.length)return '';
 return `<button class="settile" data-act="setGroup" data-v="${id}"><span class="setico">${uiIco(ic,em)}</span><span class="settxt"><b>${l}</b><span class="meta">${d}</span></span>${lineIco('M9 5l7 7-7 7')}</button>`}).join('')}</div>`;
// The installed version, shown at the bottom right of Settings (the desktop and phone apps report it; the preview says so).
let APPVER='';try{if(TAURI&&window.__TAURI__.app)window.__TAURI__.app.getVersion().then(v=>{APPVER=v;if(view==='settings')rerenderKeep()}).catch(()=>{})}catch(e){}
const verLine=()=>`<p class="appver" data-notr>Prodify ${APPVER?esc(APPVER):TAURI?'':'· preview'}</p>`;
V.settings=()=>V.settingsPage()+verLine();
V.settingsPage=()=>{if(SETG&&!setQ.trim()){const g=SETGROUPS.find(x=>x[0]===SETG),by=setSplit();if(g)return `<div class="lnav">${backBtn('setGroup','Back to settings','Settings')}</div><h1 class="h1i">${uiIco(g[2],g[3])}${g[1]}</h1>${(by[g[0]]||[]).map(el=>{const h=el.querySelector('h2');if(h&&h.textContent.trim()===g[1])h.remove();return el.outerHTML}).join('')}`;SETG=null}
 return `<h1>Settings</h1><p class="sub">Saved ${TAURI?'on this computer':'in this browser'}. Your notes and journal are not affected by these.</p>
<div class="hsearch setsearch">${sym('magnifying-glass')}<input id="setq" value="${esc(setQ)}" placeholder="Search settings" aria-label="Search settings" autocomplete="off">${setQ?'<button class="x" data-act="setqClear" aria-label="Clear search">Clear</button>':''}</div>
${setQ.trim()?setSearch():setTiles(setSplit())}`};
V.settingsAll=()=>`<section><h2>Appearance</h2>${L('Theme')}${themeGrid()}
${L('Mode')}${seg('theme',[['system','System'],['light','Light'],['dark','Dark']],CFG.theme)}
${L('Design style')}${seg('uiStyle',[['default','Prodify'],['accent','Accent'],['colorful','Colorful'],['mono','Black & gray'],['material','Material']],['accent','colorful','mono','material'].includes(CFG.uiStyle)?CFG.uiStyle:'default')}<p class="meta" style="margin:6px 0 0">Changes shapes, buttons, fields and type across the app. Works with any theme and color.</p>
${(THEMES[CFG.palette]||THEMES.classic).acc?`${L('Accent color')}<div class="moods">${Object.entries(ACC).map(([k,a])=>`<button data-act="set" data-s="accent" data-val="${k}" class="${CFG.accent===k?'on':''}"><span class="dot" style="background:${a[0]}"></span>${k[0].toUpperCase()+k.slice(1)}</button>`).join('')}</div>`:''}
${L('Font')}${seg('font',[['jetbrains','JetBrains Mono'],['default','Classic'],['serif','Serif'],['sans','Sans'],['mono','Mono']],CFG.font)}<p class="meta" style="margin:6px 0 0">JetBrains Mono is the default. Classic uses Figtree for menus and Literata for writing. The others change the whole app.</p>
${L('Text size')}${seg('size',[[14,'Small'],[16,'Medium'],[18,'Large']],CFG.size)}
${L('Zoom')}${seg('zoom',ZOOMS.map(z=>[z,z+'%']),ZOOMS.includes(+CFG.zoom)?+CFG.zoom:100)}<p class="meta" style="margin:6px 0 0">Makes everything bigger or smaller. Ctrl + and Ctrl − also zoom, Ctrl 0 goes back to 100%.</p>
${L('Page width')}${seg('pageWidth',[['comfortable','Comfortable'],['wide','Wide'],['full','Full']],{comfortable:1,wide:1,full:1}[CFG.pageWidth]?CFG.pageWidth:'wide')}<p class="meta" style="margin:6px 0 0">How wide pages get on big windows. The rest is left as space on both sides.</p>
${L('Section icons')}${seg('iconStyle',[['emoji','Emoji'],['symbols','Symbols']],CFG.iconStyle)}
${secOn('collections')||secOn('files')?swRow('Shine on hover','shine',CFG.shine!==false):''}<p class="meta" style="margin:6px 0 0">Collection covers and Storage cards tilt toward the pointer and a band of light sweeps across them, like light on hard plastic.</p>
${CFG.shine!==false&&secOn('collections')?`${L('Shine color')}${seg('shineColor',[['status','By status'],['white','White']],CFG.shineColor||'status')}<p class="meta" style="margin:6px 0 0">By status tints the light like the cover’s badge: yellow for Want, blue for In progress, green for Done, red for Dropped.</p>`:''}
${L('Navigation layout')}${seg('navLayout',[['side','Sidebar'],['top','Top bar'],['cards','Cards'],['grid','Icon grid'],['icons','Icons']],CFG.navLayout)}<p class="meta" style="margin:6px 0 0">Cards shows each section as a tile with its icon and item count; Icon grid shows the cards as square icon tiles without names; Icons shows only the colored icons in a slim bar (hover for the name). Right-click a card to change its width or hide it.</p>
${CFG.navLayout!=='top'?swRow('Auto-hide sidebar','navAuto',!!CFG.navAuto)+'<p class="meta" style="margin:6px 0 0">The sidebar hides and slides in when you move the pointer to the left edge of the window, like Zen Browser’s compact mode. Ctrl+B switches it on and off.</p>':''}
${swRow('Show scrollbars','scrollbars',!!CFG.scrollbars)}<p class="meta" style="margin:6px 0 0">Off hides every scrollbar in the app; you can still scroll with the wheel, touchpad or keyboard.</p>
${L('Card colors')}${seg('cardColors',[['soft','Soft'],['vibrant','Vibrant']],CFG.cardColors==='vibrant'?'vibrant':'soft')}<p class="meta" style="margin:6px 0 0">Colors of the side cards and the section tiles (Notes, Collections, Health…).</p>
${swRow('Show item counts on cards','navCounts',CFG.navCounts!==false)}
${secOn('today')?L('Home layout')+seg('homeLayout',[['columns','Columns'],['board','Board']],CFG.homeLayout==='board'?'board':'columns')+'<p class="meta" style="margin:6px 0 0">Board lets you place cards anywhere, with sticky notes, pinned messages and images from Storage.</p>':''}${secOn('today')?swRow('Search bar above the tab bar on phones','searchLow',!!CFG.searchLow)+'<p class="meta" style="margin:6px 0 0">On a phone, Home’s search bar sits just above the icons at the bottom, within reach of your thumb.</p>':''}${secOn('today')?swRow('Keep Home cards in the column you put them','homeFixed',!!CFG.homeFixed)+'<p class="meta" style="margin:6px 0 0">Off: cards flow into the shortest column. On: each card stays in the column you drag it to.</p>':''}${secOn('today')?L('Home columns'):''}${secOn('today')?seg('homeCols',[['auto','Auto'],[2,'2'],[3,'3'],[4,'4']],homeColsCfg())+'<p class="meta" style="margin:6px 0 0">Auto uses 4 columns on big screens (like a full-screen 2K monitor) and 3 otherwise.</p>':''}
${secOn('health')?L('Health overview columns'):''}${secOn('health')?seg('healthCols',[[2,'2'],[3,'3'],[4,'4']],+CFG.healthCols||2):''}<p class="meta" style="margin:6px 0 0">Narrow windows show fewer columns so cards don’t get squeezed.</p></section>
<section><h2>Calendar and time</h2>${L('Week starts on')}${seg('week',[[1,'Monday'],[0,'Sunday'],[6,'Saturday']],CFG.week)}
</section>
<section ${secOn('notes')?'':'hidden'}><h2>Notes</h2>${L('Layout')}${seg('notesView',[['cards','Cards'],['panel','Panel']],CFG.notesView)}<p class="meta" style="margin:6px 0 0">Panel lists your notes in a column and opens the selected one beside it.</p>
${L('Sort by')}${seg('notesSort',[['date','Date created'],['alpha','Alphabetical']],CFG.notesSort)}
${L('Open notes in')}${seg('noteOpen',[['edit','Edit mode'],['view','View mode']],CFG.noteOpen||'view')}<p class="meta" style="margin:6px 0 0">New notes always open in Edit mode. Press Ctrl+E to switch.</p>
${secOn('journal')?swRow('Show journal entries in Notes','jInNotes',CFG.jInNotes!==false)+'<p class="meta" style="margin:6px 0 0">Journal entries are listed with your notes and open in the same editor.</p>':''}
${L('New notes start typing in')}${seg('newNoteFocus',[['title','Title'],['body','Text']],CFG.newNoteFocus)}</section>
<section ${secOn('journal')?'':'hidden'}><h2>Journal</h2>${L('Your name (shown in the greeting)')}<input id="sname" value="${esc(CFG.name)}" placeholder="Optional" style="max-width:300px">
${secOn('journal')?swRow('Daily reflection question','prompts',CFG.prompts):''}
${secOn('journal')?L('What new AI questions focus on'):''}${secOn('journal')?topicPick():''}<p class="meta" style="margin:6px 0 0">Pick as many as you like; each new question focuses on one of them at random. Anything clears the choice.</p></section>
<section><h2>General</h2><div class="row" style="margin:0 0 6px"><button class="g" data-act="onbStart">${lineIco('M4 12a8 8 0 1 0 2.5-5.8M4 4v4h4')}Run setup again</button><span class="meta">Choose again which features you use.</span></div>${wxSettings()}${L('Time format')}${seg('time',[['24','24-hour · 15:30'],['12','12-hour · 3:30 PM']],CFG.time==='12'?'12':'24')}<p class="meta" style="margin:6px 0 0">Used for every time in the app: clocks, events, reminders, alarms, journal entries and history.</p>${L('Language')}${seg('lang',[['en','English'],['es','Español']],CFG.lang==='es'?'es':'en')}${L('Open Prodify on')}${seg('start',visTabs().filter(t=>t[0]!=='settings').map(t=>[t[0],t[1]]),CFG.start)}
${secOn('tasks')?swRow('Confirm before deleting a task','confirmTask',CFG.confirmTask):''}
${secOn('notes')?swRow('Confirm before deleting a note','confirmNote',CFG.confirmNote):''}
${secOn('projects')?swRow('Confirm before deleting a project','confirmProject',CFG.confirmProject):''}
${secOn('journal')?swRow('Confirm before deleting a question','confirmQuestion',CFG.confirmQuestion):''}</section>
<section><h2>Sections</h2><p class="meta" style="margin:0 0 10px">Drag to reorder. Click the icon to change it. 1 col / 2 col sets how wide its card is in the Cards layout. Turning a section off disables it everywhere: it leaves the sidebar, Home, search, commands, Calendar, reminders and the settings that belong to it, and other sections stop linking to it. Your files are kept and come back when you turn it on.</p>${tabList().map(t=>dndRow('tab',t[0],t[1],secOn(t[0]),t[0]==='settings')).join('')}</section>
<section><h2>Home cards</h2><p class="meta" style="margin:0 0 10px">You can also drag cards directly on Home with the Customize button.</p>${secOn('collections')||secOn('tasks')?`<div class="row" style="margin:0 0 10px">${secOn('tasks')?'<button class="g" data-act="tcNew">+ Task list card</button>':''}${secOn('collections')?'<button class="g" data-act="ccNew">+ Collection card</button>':''}</div>`:''}${homeList().map(id=>{const x=homeDefs().find(y=>y[0]===id);return dndRow('home',id,x[1],!(CFG.homeOff||[]).includes(id),false,x[2]&&!secOn(x[2])?'· its section is off':'')}).join('')}</section>
${accSettings()}${cloudSection()}${usersSettings()}${backupSettings()}
<section><h2>Integrations</h2>${secOn('journal')?swRow('AI-generated questions (Claude)','intAi',CFG.intAi):''}<p class="meta" style="margin:6px 0 0">Off: new questions come only from the built-in list.</p>
${aiKeyBody()}
${secOn('tasks')?swRow('In-app reminder banner','intRem',CFG.intRem):''}
${secOn('tasks')?swRow('Desktop notifications for reminders','intNotif',CFG.intNotif):''}
${secOn('calendar')&&secOn('tasks')?swRow('Calendar shows tasks and reminders','calTasks',CFG.calTasks):''}
${secOn('calendar')&&secOn('journal')?swRow('Calendar shows journal, mood and questions','calJournal',CFG.calJournal):''}
${secOn('calendar')&&secOn('notes')?swRow('Calendar shows notes','calNotes',CFG.calNotes):''}
${secOn('calendar')&&secOn('habits')?swRow('Calendar shows habits','calHabits',CFG.calHabits):''}
${secOn('calendar')&&secOn('projects')?swRow('Calendar shows projects','calProjects',CFG.calProjects):''}</section>
<section ${secOn('tasks')?'':'hidden'}><h2>Reminders</h2>${TAURI?'<p class="meta" style="margin:0">Reminders appear as a banner and a desktop notification while Prodify is open. Ones you miss show up the next time you open it.</p>':`<p class="meta" style="margin:0 0 10px">Reminders appear as a banner while Prodify is open in a browser tab. Ones you miss show up the next time you open it. Desktop notifications are optional and may not be available in this view.</p><div class="row" style="margin:0"><button class="g" data-act="notif">${NS()==='granted'?'Desktop notifications are on':'Allow desktop notifications'}</button><span class="meta">Status: ${NS()}</span></div>`}</section>
<section ${secOn('collections')?'':'hidden'}><h2>Collections</h2>${colSettings()}<h3 class="ptitle" style="margin-top:18px">Fields per type</h3>${colFieldSettings()}</section>
<section><h2>Commands</h2>${cmdSettings()}</section>
${storageSection()}
<section><h2>Reset</h2><div class="row" style="margin:0"><button class="g" data-act="resetCfg">Reset settings</button><button class="g" data-act="wipe">${armed==='wipe'?'Click again to erase everything':'Erase all notes, journal and tasks'}</button></div><p class="meta">${TAURI?'This deletes the Markdown files in your Prodify folder. ':''}Export a .zip from Files first if you want a backup.</p></section>`;
/* ---------- Collections: books, movies, series, anime and games ----------
   Each item is a Markdown file in collections/<type>/ named "Title (Year).md", with Obsidian-style properties
   (type, title, creator, year, status, rating, genres, cover, length, source, added, started, finished) and the
   person's own notes as the body. Search pulls metadata from free online catalogs: Open Library (books),
   TVmaze (series) and AniList (anime) need no key; TMDB (movies) and RAWG (games) need a free API key, set in
   Settings → Collections. Covers are downloaded into attachments/ so they work offline. */
const CTYPES=[
 {id:'book',label:'Books',one:'book',sym:'books',emoji:'📚',color:'#d4a43a',by:'Author',src:'Open Library',st:['Want to read','Reading','Read','Dropped']},
 {id:'movie',label:'Movies',one:'movie',sym:'film-strip',emoji:'🎬',color:'#e0566f',by:'Director',src:'TMDB',key:'tmdbKey',st:['Want to watch','Watching','Watched','Dropped']},
 {id:'series',label:'Series',one:'series',sym:'television',emoji:'📺',color:'#4a8fd9',by:'Network',src:'TVmaze',st:['Want to watch','Watching','Watched','Dropped']},
 {id:'anime',label:'Anime',one:'anime',sym:'flower-lotus',emoji:'🌸',color:'#c9629b',by:'Studio',src:'AniList',st:['Want to watch','Watching','Watched','Dropped']},
 {id:'game',label:'Games',one:'game',sym:'game-controller',emoji:'🎮',color:'#5fa57f',by:'Platforms',src:'RAWG',key:'rawgKey',st:['Want to play','Playing','Played','Dropped']}];
/* Metadata fields an item can keep. Settings → Collections turns each on or off per type (CFG.colFields[type]);
   without a choice, a field is on if def says so (default: every type it applies to). Turning a field off hides it and
   stops filling it from the catalogs; values already in a file are kept. */
const ALLT=['book','movie','series','anime','game'];
const CFIELDS=[{id:'creator',label:'Creator'},{id:'year',label:'Year'},{id:'length',label:'Length'},{id:'genres',label:'Genres'},{id:'source',label:'Link'},{id:'cover',label:'Cover'},
 {id:'rating',label:'Rating'},{id:'dates',label:'Dates'},{id:'notes',label:'Notes'},
 {id:'platform',label:'Platform',types:['movie','series','anime'],def:['movie'],sugg:['Netflix','Disney+','Prime Video','Max','Movistar+','SkyShowtime','Filmin','Crunchyroll','YouTube','Cinema','Blu-ray / DVD']},
 {id:'downloaded',label:'Downloaded',types:['movie','series','anime'],def:['movie'],yesno:1},
 {id:'store',label:'Store',types:['game'],sugg:['Steam','Epic Games','GOG','PlayStation Store','Xbox / Microsoft Store','Nintendo eShop','itch.io','Physical copy']},
 {id:'device',label:'Device',types:['game'],sugg:['PC','Steam Deck','PS5','PS4','Xbox Series','Nintendo Switch','Mobile']}];
const fieldsFor=type=>CFIELDS.filter(f=>(f.types||ALLT).includes(type));
const fieldOn=(type,id)=>{const c=(CFG.colFields||{})[type];if(Array.isArray(c))return c.includes(id);const f=CFIELDS.find(x=>x.id===id);return !!f&&(f.def||f.types||ALLT).includes(type)};
const fieldLabel=(type,f)=>f.id==='creator'?ctype(type).by:f.label;
const CSTAT=['want','doing','done','dropped'],CSTATL=['Want','In progress','Done','Dropped'];
const ctype=id=>CTYPES.find(t=>t.id===id)||CTYPES[0];
// Types in the order the person dragged them into (Collections tiles and the add panel).
const ctypesOrdered=()=>{const o=(CFG.colTypeOrder||[]).filter(id=>CTYPES.some(t=>t.id===id));return [...o.map(ctype),...CTYPES.filter(t=>!o.includes(t.id))]};
const statLabel=(type,s)=>{const i=CSTAT.indexOf(s);return i<0?'':ctype(type).st[i]};
let colFav=false,colTok=0,colType='all',colStat='',colSort=CFG.colSort||'added',colQ='',colSel=null,colAdd=false,colRes=null,colBusy=false,colErr='',colSType='book',colSQ='',CD=null,colTimer=null;
const colKeys=()=>Object.keys(FS).filter(k=>k.startsWith('collections/')&&k.endsWith('.md'));
function colRead(k){const n=readNote(FS[k]),f=n.fm,g=f.genres;
 return{k,type:CTYPES.some(t=>t.id===f.type)?f.type:(k.split('/')[1]||'book'),title:String(f.title||noteTitle(k)),creator:String(f.creator||''),year:String(f.year||''),
  status:CSTAT.includes(f.status)?f.status:'want',rating:/^[1-5]$/.test(String(f.rating))?+f.rating:0,genres:Array.isArray(g)?g.map(String):g?[String(g)]:[],
  cover:String(f.cover||'').replace(/^\[\[|\]\]$/g,''),length:String(f.length||''),source:String(f.source||''),added:String(f.added||''),started:String(f.started||''),finished:String(f.finished||''),order:+f.order||0,platform:String(f.platform||''),downloaded:/^(yes|no)$/.test(f.downloaded)?f.downloaded:'',store:String(f.store||''),device:String(f.device||''),fav:String(f.favorite)==='true',body:n.body}}
const colWrite=it=>writeNote({fm:{type:it.type,title:it.title,creator:it.creator,year:it.year,status:it.status,rating:it.rating?String(it.rating):'',genres:it.genres,
 cover:it.cover?(/^https?:/.test(it.cover)?it.cover:`[[${it.cover}]]`):'',length:it.length,source:it.source,added:it.added,started:it.started,finished:it.finished,...(it.order?{order:String(it.order)}:{}),...Object.fromEntries(['platform','downloaded','store','device'].filter(x=>it[x]).map(x=>[x,it[x]])),...(it.fav?{favorite:'true'}:{})},body:it.body||''});
function colKeyFor(it,cur){const base=`collections/${it.type}/${safeName(it.title||'Untitled')}${it.year?` (${it.year})`:''}`;let k=base+'.md',n=2;while(FS[k]&&k!==cur)k=`${base} ${n++}.md`;return k}
// Writes an item, renaming its file when the title, year or type changed. Returns the (new) key.
function colPut(it){const k=colKeyFor(it,it.k);if(it.k&&it.k!==k)delete FS[it.k];FS[k]=colWrite(it)+(it.body&&!it.body.endsWith('\n')?'\n':'');if(colSel===it.k)colSel=k;it.k=k;return k}
const cimg=(it,big)=>it.cover&&fieldOn(it.type,'cover')?`<img ${/^https?:/.test(it.cover)?`src="${esc(it.cover)}"`:`data-att="${esc(it.cover)}"`} alt="" loading="lazy">`:`<span class="cph">${symbols()?sym(ctype(it.type).sym):ctype(it.type).emoji}</span>`;
const stars=(n,act)=>`<span class="stars" ${act?'role="group" aria-label="Rating"':`aria-label="${n?n+' of 5 stars':'Not rated'}"`}>${[1,2,3,4,5].map(i=>act?`<button class="star ${i<=n?'on':''}" data-act="col:rate" data-val="${i}" aria-label="${i} star${i>1?'s':''}" aria-pressed="${i<=n}">★</button>`:`<span class="star ${i<=n?'on':''}">★</span>`).join('')}</span>`;
const hostOf=u=>{try{return new URL(u).hostname.replace(/^www\./,'')}catch(e){return 'source'}};
const openLink=u=>/^https?:\/\//.test(u)?(TAURI?TAURI.invoke('open_link',{url:u}).catch(e=>toast('Could not open the link: '+e)):window.open(u,'_blank','noopener')):null;

/* Catalog search. Each returns [{title, creator, year, cover, thumb, genres, length, source}] (tmdb: id for details). */
const getJSON=async(url,opt)=>{const r=await fetch(url,opt);if(!r.ok)throw new Error(r.status===401?'the API key was refused':`the catalog answered ${r.status}`);return r.json()};
const CAPI={
 book:async q=>(await getJSON(`https://openlibrary.org/search.json?q=${encodeURIComponent(q)}&limit=12&fields=key,title,author_name,first_publish_year,cover_i,subject,number_of_pages_median`)).docs.map(d=>({
  title:d.title,creator:(d.author_name||[]).slice(0,2).join(', '),year:d.first_publish_year||'',cover:d.cover_i?`https://covers.openlibrary.org/b/id/${d.cover_i}-L.jpg`:'',thumb:d.cover_i?`https://covers.openlibrary.org/b/id/${d.cover_i}-M.jpg`:'',
  genres:(d.subject||[]).filter(x=>x.length<30).slice(0,3),length:d.number_of_pages_median?d.number_of_pages_median+' pages':'',source:'https://openlibrary.org'+d.key})),
 series:async q=>(await getJSON(`https://api.tvmaze.com/search/shows?q=${encodeURIComponent(q)}`)).slice(0,12).map(({show:s})=>({
  title:s.name,creator:((s.network||s.webChannel)||{}).name||'',year:(s.premiered||'').slice(0,4),cover:s.image?s.image.original:'',thumb:s.image?s.image.medium:'',genres:s.genres||[],length:'',source:s.url})),
 anime:async q=>{const r=await getJSON('https://graphql.anilist.co',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({variables:{s:q},
  query:'query($s:String){Page(perPage:12){media(search:$s,type:ANIME,sort:SEARCH_MATCH){title{romaji english}seasonYear startDate{year}episodes genres coverImage{extraLarge medium}studios(isMain:true){nodes{name}}siteUrl}}}'})});
  return r.data.Page.media.map(m=>({title:m.title.english||m.title.romaji,creator:(m.studios.nodes[0]||{}).name||'',year:m.seasonYear||(m.startDate||{}).year||'',cover:m.coverImage.extraLarge||'',thumb:m.coverImage.medium||'',genres:m.genres||[],length:m.episodes?m.episodes+' episodes':'',source:m.siteUrl}))},
 movie:async q=>(await getJSON(`https://api.themoviedb.org/3/search/movie?api_key=${encodeURIComponent(CFG.tmdbKey)}&query=${encodeURIComponent(q)}`)).results.slice(0,12).map(m=>({
  title:m.title,creator:'',year:(m.release_date||'').slice(0,4),cover:m.poster_path?'https://image.tmdb.org/t/p/w500'+m.poster_path:'',thumb:m.poster_path?'https://image.tmdb.org/t/p/w185'+m.poster_path:'',genres:[],length:'',source:'https://www.themoviedb.org/movie/'+m.id,tmdb:m.id})),
 game:async q=>(await getJSON(`https://api.rawg.io/api/games?key=${encodeURIComponent(CFG.rawgKey)}&search=${encodeURIComponent(q)}&page_size=12`)).results.map(g=>({
  title:g.name,creator:(g.platforms||[]).map(p=>p.platform.name).slice(0,3).join(', '),year:(g.released||'').slice(0,4),cover:g.background_image||'',thumb:g.background_image||'',genres:(g.genres||[]).map(x=>x.name),length:'',source:'https://rawg.io/games/'+g.slug}))};
async function colSearch(){const q=colSQ.trim(),t=ctype(colSType);if(!q)return;colPicks=new Set();if(t.key&&!CFG[t.key]){colErr=`Searching ${t.label.toLowerCase()} needs a free ${t.src} API key. Add it in Settings → Collections, or add this one by hand.`;colRes=null;render();return}
 // only the latest search may show its results (an older, slower one can finish later)
 const tok=++colTok;colBusy=true;colErr='';colRes=null;render();let res=null,err='';
 try{res=await CAPI[colSType](q);if(!res.length)err=`${t.src} found nothing for “${q}”.`}catch(e){err=`Couldn’t search ${t.src}: ${e.message||e}. Check your internet connection.`}
 if(tok!==colTok)return;colRes=res;colErr=err;colBusy=false;render();const i=$('cols');if(i)i.focus()}
/* Other covers for an item, from its catalog: book editions (Open Library), posters (TMDB, TVmaze, including
   season posters), AniList covers of the matching entries, and RAWG artwork and screenshots. Each is {url, thumb, label}. */
const COVERS={
 book:async it=>{let key=(it.source.match(/openlibrary\.org(\/works\/OL\d+W)/)||[])[1];
  if(!key){const d=(await getJSON(`https://openlibrary.org/search.json?title=${encodeURIComponent(it.title)}${it.creator?'&author='+encodeURIComponent(it.creator.split(',')[0]):''}&limit=1&fields=key`)).docs[0];key=d&&d.key}
  if(!key)return[];const e=await getJSON(`https://openlibrary.org${key}/editions.json?limit=100`),seen=new Set(),out=[];
  for(const x of e.entries||[])for(const c of x.covers||[])if(c>0&&!seen.has(c)){seen.add(c);out.push({url:`https://covers.openlibrary.org/b/id/${c}-L.jpg`,thumb:`https://covers.openlibrary.org/b/id/${c}-M.jpg?default=false`,label:[x.publish_date,(x.publishers||[])[0]].filter(Boolean).join(' · ')})}
  return out},
 movie:async it=>{if(!CFG.tmdbKey)throw new Error('a TMDB key is needed (Settings → Collections)');let id=(it.source.match(/themoviedb\.org\/movie\/(\d+)/)||[])[1];const k=encodeURIComponent(CFG.tmdbKey);
  if(!id){const r=(await getJSON(`https://api.themoviedb.org/3/search/movie?api_key=${k}&query=${encodeURIComponent(it.title)}${it.year?'&year='+it.year:''}`)).results[0];id=r&&r.id}
  if(!id)return[];const im=await getJSON(`https://api.themoviedb.org/3/movie/${id}/images?api_key=${k}&include_image_language=en,es,null`);
  return(im.posters||[]).slice(0,60).map(x=>({url:'https://image.tmdb.org/t/p/w780'+x.file_path,thumb:'https://image.tmdb.org/t/p/w185'+x.file_path,label:(x.iso_639_1||'no text').toUpperCase()}))},
 series:async it=>{let id=(it.source.match(/tvmaze\.com\/shows\/(\d+)/)||[])[1];
  if(!id){const r=await getJSON(`https://api.tvmaze.com/singlesearch/shows?q=${encodeURIComponent(it.title)}`).catch(()=>null);id=r&&r.id}
  if(!id)return[];const[im,se]=await Promise.all([getJSON(`https://api.tvmaze.com/shows/${id}/images`),getJSON(`https://api.tvmaze.com/shows/${id}/seasons`).catch(()=>[])]);
  return[...im.filter(x=>x.type==='poster').map(x=>({url:x.resolutions.original.url,thumb:(x.resolutions.medium||x.resolutions.original).url,label:'Poster'})),
   ...se.filter(x=>x.image).map(x=>({url:x.image.original,thumb:x.image.medium,label:'Season '+x.number}))]},
 anime:async it=>{const r=await getJSON('https://graphql.anilist.co',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({variables:{s:it.title},
  query:'query($s:String){Page(perPage:16){media(search:$s,type:ANIME,sort:SEARCH_MATCH){title{romaji english}seasonYear coverImage{extraLarge large}}}}'})});
  return r.data.Page.media.filter(m=>m.coverImage.extraLarge).map(m=>({url:m.coverImage.extraLarge,thumb:m.coverImage.large||m.coverImage.extraLarge,label:[m.title.english||m.title.romaji,m.seasonYear].filter(Boolean).join(' · ')}))},
 game:async it=>{if(!CFG.rawgKey)throw new Error('a RAWG key is needed (Settings → Collections)');const k=encodeURIComponent(CFG.rawgKey);let slug=(it.source.match(/rawg\.io\/games\/([^/?#]+)/)||[])[1];
  if(!slug){const r=(await getJSON(`https://api.rawg.io/api/games?key=${k}&search=${encodeURIComponent(it.title)}&page_size=1`)).results[0];slug=r&&r.slug}
  if(!slug)return[];const[g,sh]=await Promise.all([getJSON(`https://api.rawg.io/api/games/${slug}?key=${k}`),getJSON(`https://api.rawg.io/api/games/${slug}/screenshots?key=${k}`).catch(()=>({results:[]}))]);
  return[g.background_image&&{url:g.background_image,thumb:g.background_image,label:'Artwork'},g.background_image_additional&&{url:g.background_image_additional,thumb:g.background_image_additional,label:'Artwork'},
   ...(sh.results||[]).map(x=>({url:x.image,thumb:x.image,label:'Screenshot'}))].filter(Boolean)}};
// The open "other covers" panel: {k, busy, list, err, saving}.
let CALT=null;
// Covers that fail to load, or are tiny placeholders, are dropped from the picker.
document.addEventListener('error',e=>{const t=e.target;if(t&&t.closest&&t.closest('.caltc'))t.closest('.caltc').remove()},true);
document.addEventListener('load',e=>{const t=e.target;if(t&&t.tagName==='IMG'&&t.closest&&t.closest('.caltc')&&t.naturalWidth<20)t.closest('.caltc').remove()},true);
async function coverAlts(it){const k=it.k;CALT={k,busy:true,list:[],err:''};render();let list=[],err='';
 try{list=await COVERS[it.type](it);if(!list.length)err='No other covers found online for this one.'}catch(e){err=`Couldn’t load covers: ${e.message||e}.`}
 if(!CALT||CALT.k!==k)return;CALT={k,busy:false,list,err};render()}
async function coverUse(i){const c=CALT&&CALT.list[i];if(!c||CALT.saving||!CD)return;CALT.saving=i;render();let cover;
 try{cover=await saveCover(c.url)}catch(e){cover=c.url}
 if(!CD||CD.k!==CALT.k)return;CD.cover=cover;colPut(CD);save();CALT=null;render();toast('Cover changed');if(/^https:/.test(cover))setTimeout(colOfflineCovers,2000)}
const coverPanel=()=>!CALT||!CD||CALT.k!==CD.k?'':`<section class="calt"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Other covers</h2><span class="row" style="margin:0"><button class="g" data-act="col:cover">${sym('upload-simple')}From your computer…</button><button class="g" data-act="col:altclose">Close</button></span></div>
${CALT.busy?'<p class="meta">Looking for covers…</p>':CALT.err?`<p class="empty">${esc(CALT.err)}</p>`:`<p class="meta" style="margin:0 0 10px">${CALT.list.length} found. Click one to use it; it is saved for offline use.</p><div class="caltgrid"><button class="caltc caltup" data-act="col:cover" title="Choose an image from your computer"><span class="caltbox">${sym('upload-simple')}<b>From your computer</b></span><span class="meta">Local image</span></button>${CALT.list.map((c,i)=>`<button class="caltc ${CALT.saving===i?'busy':''}" data-act="col:altuse" data-i="${i}" title="${esc(c.label)}"><img src="${esc(c.thumb)}" alt="" loading="lazy" referrerpolicy="no-referrer"><span class="meta">${esc(c.label||'')}</span></button>`).join('')}</div>`}</section>`;
// Adds a search result: TMDB gets a second request for the director and genres; the cover is downloaded (or linked if that fails).
// Saves a cover for offline use and returns its attachment name. The desktop app downloads it itself (some image
// hosts block web pages from fetching their files); a plain browser tries fetch, and the caller keeps the link if that fails.
async function saveCover(url){if(TAURI)return TAURI.invoke('download_attachment',{url,base:attName().slice(0,-4)}).then(async n=>{if(n&&encOn()){const u=await attRead(n);if(!isEncB(u))await attWrite(n,await encBytes(u))}return n});
 const res=await fetch(url);if(!res.ok)throw new Error(res.status);const blob=await prepImage(await res.blob()),name=attName();await saveAtt(name,blob);ATTURL[name]=URL.createObjectURL(blob);return name}
// Items whose cover is still an online link (saved before, or when a download failed) get it downloaded, quietly, one by one.
let coverJob=false;
async function colOfflineCovers(){if(coverJob||LOCKED)return;coverJob=true;let n=0;
 for(const k of colKeys()){const it=colRead(k);if(!/^https:\/\//.test(it.cover))continue;try{it.cover=await saveCover(it.cover);if(FS[k]!==undefined){colPut(it);n++}}catch(e){}}
 coverJob=false;if(n){save();if(view==='collections'){CD=null;render()}toast(`Saved ${n} cover${n>1?'s':''} for offline use`)}}
// Select several: in this mode a click on a result ticks it; "Add N" adds them all, one after another.
let colMulti=false,colPicks=new Set(),colAddingMany=false;
async function colAddMany(){const ids=[...colPicks].filter(i=>colRes&&colRes[i]&&!(colRes[i].key&&FS[colRes[i].key]));if(!ids.length||colAddingMany)return;colAddingMany=true;render();let n=0;
 for(const i of ids){try{if(await colAddResult(i,true))n++}catch(e){}render()}
 colAddingMany=false;colPicks=new Set();colMulti=false;colAdd=false;colRes=null;colSQ='';colErr='';colTok++;colSel=null;CD=null;view='collections';save();render();window.scrollTo(0,0);toast(`Added ${n} item${n===1?'':'s'} to ${ctype(colSType).label}`)}
async function colAddResult(i,many){const r=colRes&&colRes[i];if(!r||r.adding)return;r.adding=true;if(!many)render();
 if(r.tmdb){try{const d=await getJSON(`https://api.themoviedb.org/3/movie/${r.tmdb}?api_key=${encodeURIComponent(CFG.tmdbKey)}&append_to_response=credits`);
  r.genres=(d.genres||[]).map(g=>g.name);r.creator=((d.credits||{}).crew||[]).filter(c=>c.job==='Director').map(c=>c.name).slice(0,2).join(', ');if(d.runtime)r.length=d.runtime+' min'}catch(e){}}
 let cover='';if(r.cover&&fieldOn(colSType,'cover')){try{cover=await saveCover(r.cover)}catch(e){cover=r.cover}}
 const on=x=>fieldOn(colSType,x),it={type:colSType,title:r.title,creator:on('creator')?r.creator:'',year:on('year')?String(r.year||''):'',status:'want',rating:0,genres:on('genres')?r.genres||[]:[],cover,length:on('length')?r.length||'':'',source:on('source')?r.source||'':'',added:TD(),started:'',finished:'',body:''};
 const nk=colPut(it);r.adding=false;r.key=nk;if(/^https:/.test(cover))setTimeout(colOfflineCovers,2000);
 if(many)return nk;
 // done: clear the search and close the add panel
 // then open the new item's page
 colAdd=false;colRes=null;colSQ='';colErr='';colTok++;colSel=nk;CD=null;CALT=null;view='collections';save();render();window.scrollTo(0,0);toast(`Added to ${ctype(colSType).label}`)}
// Lets the person pick a local image as an item's cover (resized and stored in attachments/).
function pickCover(it){const f=document.createElement('input');f.type='file';f.accept='image/*';
 f.onchange=async()=>{const file=f.files[0];if(!file)return;try{const blob=await prepImage(file),name=attName();await saveAtt(name,blob);ATTURL[name]=URL.createObjectURL(blob);it.cover=name;colPut(it);if(CD&&CD!==it&&CD.k===it.k)CD=null;if(CALT&&CALT.k===it.k)CALT=null;save();render();toast('Cover updated')}catch(e){toast('Could not use that image')}};f.click()}
// Rating an item marks it as finished (Read / Watched / Played), unless it was dropped.
function rateDone(it){if(it.rating&&it.status!=='done'&&it.status!=='dropped'){colSetStatus(it,'done');toast(statLabel(it.type,'done'))}}
function colSetStatus(it,s){it.status=s;if(!fieldOn(it.type,'dates'))return;if(s==='doing'&&!it.started)it.started=TD();if(s==='done'){if(!it.finished)it.finished=TD();if(!it.started)it.started=it.finished}}

// The line under a card's title: creator and year, each only if that field is kept for the item's type.
const colMeta=it=>[fieldOn(it.type,'creator')?it.creator:'',fieldOn(it.type,'year')?it.year:''].filter(Boolean).join(' · ');
// Favorites: a heart on each cover (shown on hover, always shown when it is a favorite), on the item page and in the right-click menu.
const heartIco=on=>`<svg class="sym" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20.5s-7.5-4.6-9.5-9.2C1 7.9 3.4 4.5 6.9 4.5c2 0 3.6 1.1 5.1 3 1.5-1.9 3.1-3 5.1-3 3.5 0 5.9 3.4 4.4 6.8-2 4.6-9.5 9.2-9.5 9.2z" fill="${on?'currentColor':'none'}" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>`;
const colCard=it=>`<button class="ccard" data-act="col:open" data-k="${esc(it.k)}" data-colk="${esc(it.k)}" data-dnd="col" data-id="${esc(it.k)}"><span class="ccov s-${esc(it.status)}">${cimg(it)}<span class="cfav ${it.fav?'on':''}" data-act="col:fav" data-k="${esc(it.k)}" role="button" tabindex="0" aria-pressed="${it.fav}" aria-label="${it.fav?'Remove from favorites':'Add to favorites'}" title="${it.fav?'Remove from favorites':'Add to favorites'}">${heartIco(it.fav)}</span><span class="cbadge s-${it.status}">${esc(statLabel(it.type,it.status))}</span></span><b>${esc(it.title)}</b><span class="meta">${esc(colMeta(it)||ctype(it.type).label)}</span>${it.rating&&fieldOn(it.type,'rating')?stars(it.rating):''}</button>`;
const colAddPanel=()=>{const t=ctype(colSType),np=colPicks.size;return `<section class="cadd"><div class="caddhead"><div class="moods seg">${ctypesOrdered().map(x=>`<button data-act="col:stype" data-val="${x.id}" class="${x.id===colSType?'on':''}">${x.label}</button>`).join('')}</div>
<span class="caddtools">${colMulti&&np?`<button class="b" data-act="col:addsel" ${colAddingMany?'disabled':''}>${colAddingMany?'Adding…':`${lineIco('M5 12.5l4.5 4.5L19 7')}Add ${np}`}</button>`:''}<button class="g msel ${colMulti?'on':''}" data-act="col:multi" aria-pressed="${colMulti}" title="Select several results and add them together">${lineIco('M4 6.5l2 2 3.5-4M4 16.5l2 2 3.5-4M13 7h7M13 17h7')}${colMulti?'Done':'Select several'}</button><button class="circ cclose" data-act="col:add" aria-label="Close search" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button></span></div>
<div class="row" style="margin:0"><input id="cols" value="${esc(colSQ)}" placeholder="Search ${t.label.toLowerCase()} by title" aria-label="Search ${t.label.toLowerCase()}" autocomplete="off"><button class="b" data-act="col:search" ${colBusy?'disabled':''}>${colBusy?'Searching…':'Search'}</button><button class="g" data-act="col:manual">Add by hand</button></div>
${colErr?`<p class="meta" style="margin:10px 0 0">${esc(colErr)}</p>`:''}
${colRes&&colRes.length?`<div class="cres">${colRes.map((r,i)=>{const have=r.key&&FS[r.key],pk=colMulti&&!have,on=pk&&colPicks.has(i);return `<div class="crow ${on?'picked':''}" ${have?`data-act="col:open" data-k="${esc(r.key)}" title="Open"`:r.adding?'':pk?`data-act="col:tog" data-i="${i}" aria-pressed="${on}" title="${on?'Unselect':'Select'}"`:`data-act="col:pick" data-i="${i}" title="Add to your collection"`} role="button" tabindex="0"><span class="cthumb">${r.thumb?`<img src="${esc(r.thumb)}" alt="" loading="lazy">`:''}</span><span class="t"><b>${esc(r.title)}</b><span class="meta">${esc([r.creator,r.year,r.length].filter(Boolean).join(' · '))}</span></span>${have?`<button class="g" data-act="col:open" data-k="${esc(r.key)}">Added · Open</button>`:r.adding?'<span class="meta">Adding…</span>':pk?`<span class="pickchk ${on?'on':''}" aria-hidden="true">${on?lineIco('M5 12.5l4.5 4.5L19 7'):''}</span>`:`<button class="b tick" data-act="col:pick" data-i="${i}" aria-label="Add ${esc(r.title)}" title="Add">${lineIco('M12 5v14M5 12h14')}</button>`}</div>`}).join('')}</div>`:''}
<p class="meta" style="margin:10px 0 0">Results from ${t.src}${t.id==='movie'?'. This product uses the TMDB API but is not endorsed or certified by TMDB':''}.</p></section>`};
const colSortFn=()=>{const byAdded=(a,b)=>(b.added||'').localeCompare(a.added||'')||alpha(a.title,b.title);
 // status: in progress first, then want, done, dropped
 const SRANK={doing:0,want:1,done:2,dropped:3};
 return colSort==='status'?(a,b)=>SRANK[a.status]-SRANK[b.status]||byAdded(a,b):colSort==='title'?(a,b)=>alpha(a.title,b.title):colSort==='rating'?(a,b)=>b.rating-a.rating||alpha(a.title,b.title):colSort==='year'?(a,b)=>(b.year||'').localeCompare(a.year||'')||alpha(a.title,b.title)
  :colSort==='custom'?(a,b)=>(a.order||0)-(b.order||0)||byAdded(a,b):byAdded};
// Dragging a card saves the shown order as the custom order (renumbering every item) and switches to it.
function colSaveOrder(keysInOrder){keysInOrder.forEach((k,i)=>{if(!FS[k])return;const it=colRead(k);if(it.order!==i+1){it.order=i+1;colPut(it)}});colSort='custom';CFG.colSort='custom';saveCfg();save()}
/* Collections goals and stats: a yearly goal per type (CFG.colGoals = {"2026": {book: 24}}), progress on Collections,
   and a stats panel (finished per month, average rating, top genres, pages or hours from the Length field). */
let colStatsOn=false,colQuotes=false,colQQ='';
const colYear=()=>TD().slice(0,4);
const colFinished=(all,type,y)=>all.filter(it=>(type==='all'||it.type===type)&&it.status==='done'&&String(it.finished||'').slice(0,4)===y);
function colGoalsBar(all){const y=colYear(),g=(CFG.colGoals||{})[y]||{},ids=Object.keys(g).filter(k=>g[k]>0&&(colType==='all'||colType===k));if(!ids.length)return '';
 const doy=(pd(TD())-new Date(+y,0,1))/864e5+1,yl=((+y%4===0&&+y%100!==0)||+y%400===0)?366:365;
 return `<div class="cgoals">${ids.map(k=>{const t=ctype(k),n=colFinished(all,k,y).length,goal=g[k],exp=goal*doy/yl,st=n>=goal?'Goal reached 🎉':n>=exp-0.5?'On track':`${Math.ceil(exp-n)} behind`;
  return `<div class="cgoal" style="--gc:${t.color}"><span class="cgico">${symbols()?sym(t.sym):t.emoji}</span><div class="cgt"><b><span>${t.label}</span> <span class="meta">${n}/${goal} in ${y}</span></b><div class="bar"><i style="width:${Math.min(100,Math.round(n/goal*100))}%"></i></div><span class="meta cgst ${n>=exp-0.5?'ok':'late'}">${st}</span></div></div>`}).join('')}</div>`}
function colStatsPanel(all){const y=colYear(),ty=colType,its=all.filter(it=>ty==='all'||it.type===ty),fin=colFinished(all,ty,y),rated=its.filter(it=>it.rating),avg=rated.length?rated.reduce((a,b)=>a+b.rating,0)/rated.length:0;
 const gen={};fin.forEach(it=>it.genres.forEach(g=>gen[g]=(gen[g]||0)+1));const top=Object.entries(gen).sort((a,b)=>b[1]-a[1]).slice(0,5);
 let pages=0,mins=0;fin.forEach(it=>{const L=String(it.length||'').toLowerCase(),n=parseFloat(L);if(!n)return;if(/p[aá]g|page/.test(L)||(it.type==='book'&&!/h|min/.test(L)))pages+=n;else{const h=L.match(/(\d+(?:[.,]\d+)?)\s*h/),m=L.match(/(\d+)\s*m/);mins+=(h?parseFloat(h[1].replace(',','.'))*60:0)+(m?+m[1]:0)||(/min/.test(L)?n:0)}});
 const months=[...Array(12)].map((_,i)=>fin.filter(it=>+String(it.finished).slice(5,7)===i+1).length),mx=Math.max(1,...months),goalTypes=ty==='all'?ctypesOrdered():[ctype(ty)],g=(CFG.colGoals||{})[y]||{};
 return `<section class="cstats"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${ty==='all'?'All collections':ctype(ty).label} · ${y}</h2><button class="cx" data-act="col:statsT" aria-label="Close" title="Close">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>
<div class="stats"><div><b>${fin.length}</b><span class="meta">Finished in ${y}</span></div><div><b>${avg?avg.toFixed(1)+' ★':'–'}</b><span class="meta">Average rating</span></div><div><b>${pages?Math.round(pages).toLocaleString(LOC()):mins?Math.round(mins/60)+' h':'–'}</b><span class="meta">${pages?'Pages read':mins?'Hours watched or played':'Pages or hours'}</span></div><div><b>${its.filter(it=>it.status==='doing').length}</b><span class="meta">In progress</span></div></div>
<p class="meta" style="margin:14px 0 6px">Finished per month</p><div class="cmonths">${months.map((n,i)=>`<span title="${n}"><i style="height:${n/mx*100}%"></i><em>${new Date(2026,i,1).toLocaleDateString(LOC(),{month:'narrow'})}</em></span>`).join('')}</div>
${top.length?`<p class="meta" style="margin:14px 0 6px">Top genres</p><div class="nchips">${top.map(([g2,n])=>`<span class="chip">${esc(g2)} <span class="meta">${n}</span></span>`).join('')}</div>`:''}
<p class="meta" style="margin:16px 0 6px">Goals for ${y}</p><div class="cgoalset">${goalTypes.map(t=>`<label class="meta lab">${t.label}<input type="number" min="0" step="1" data-cgoal="${t.id}" value="${g[t.id]||''}" placeholder="0"></label>`).join('')}<button class="b tick" data-act="col:goalSave" aria-label="Save goals" title="Save goals">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div></section>`}
/* Quotes and highlights: quotes.md, one per line: - 2026-10-23: “Fear is the mind-killer.” — Dune (p. 42) {collections/book/Dune (1965).md} */
const quotesRead=()=>(FS['quotes.md']||'').split('\n').map(l=>l.match(/^- (\d{4}-\d{2}-\d{2}): “([\s\S]*)” — (.*?)(?: \(([^()]*)\))? \{(.+)\}$/)).filter(Boolean).map((m,i)=>({i,d:m[1],q:m[2],title:m[3],at:m[4]||'',k:m[5]}));
const quotesWrite=l=>{FS['quotes.md']='# Quotes\n\n'+l.map(x=>`- ${x.d}: “${String(x.q).replace(/\n+/g,' ').replace(/[“”]/g,'"')}” — ${x.title}${x.at?` (${x.at.replace(/[()]/g,'')})`:''} {${x.k}}`).join('\n')+(l.length?'\n':'')};
const quoteCard=(x,showItem)=>{const it=FS[x.k]?colRead(x.k):null;return `<div class="qcard"><p class="qtext" data-notr>“${esc(x.q)}”</p><div class="qmeta">${showItem?`<button class="qitem" data-act="col:open" data-k="${esc(x.k)}">${it?`<span class="qcov">${cimg(it)}</span>`:''}<span data-notr>${esc(it?it.title:x.title)}</span></button>`:''}<span class="meta">${x.at?esc(x.at)+' · ':''}${fmt(x.d,{month:'short',day:'numeric',year:'numeric'})}</span><button class="cx rbtn" data-act="col:quoteDel" data-i="${x.i}" aria-label="Delete quote" title="Delete">${lineIco('M6 6l12 12M18 6L6 18')}</button></div></div>`};
function quotesPage(){const all=quotesRead().filter(x=>!colQQ||fold(x.q+' '+x.title+' '+x.at).includes(fold(colQQ))).reverse();
 return `<div class="lnav">${backBtn('col:quotesT','Back to collections','Collections')}<span class="meta">${all.length} quote${all.length===1?'':'s'}</span><span></span></div><h1 style="margin:0 0 14px">Quotes</h1>
<span class="sbox" style="display:block;margin:0 0 14px"><input id="colqq" value="${esc(colQQ)}" placeholder="Search quotes" autocomplete="off"></span>${all.length?`<div class="qgrid">${all.map(x=>quoteCard(x,1)).join('')}</div>`:'<section><p class="empty">No quotes yet. Open any item and add a quote or highlight.</p></section>'}`}
// Home: this year's collection goals as small progress lines under In progress.
const colGoalMini=()=>{const y=colYear(),g=(CFG.colGoals||{})[y]||{},ids=Object.keys(g).filter(k=>g[k]>0);if(!ids.length)return '';const all=colKeys().map(colRead);
 return `<div class="hcgoals">${ids.map(k=>{const tp=ctype(k),n=colFinished(all,k,y).length;return `<div style="--gc:${tp.color}"><span class="meta"><span>${tp.label}</span> ${n}/${g[k]}</span><div class="bar"><i style="width:${Math.min(100,Math.round(n/g[k]*100))}%"></i></div></div>`}).join('')}</div>`};
function colHome(){if(colQuotes)return quotesPage();const all=colKeys().map(colRead),q=colQ.trim();
 let ls=all.filter(it=>(colType==='all'||it.type===colType)&&(!colStat||it.status===colStat)&&(!colFav||it.fav)&&(!q||wordsMatch([it.title,it.creator,it.year,it.platform,it.store,it.device,...it.genres].join(' '),q)));
 ls=ls.sort(colSortFn());
 const tiles=[['all','All','squares-four','🗂️','#7a8794',all.length],...ctypesOrdered().map(t=>[t.id,t.label,t.sym,t.emoji,t.color,all.filter(x=>x.type===t.id).length])];
 return `<div class="lnav"><h1 style="margin:0">Collections</h1><button class="circ" data-act="col:add" aria-label="Add to collections" title="Add" aria-pressed="${colAdd}">${lineIco('M12 5v14M5 12h14')}</button></div>
${tileBar('col:type',colType,tiles,'ctile')}${colAdd?colAddPanel():''}${colStatsOn?colStatsPanel(all):colGoalsBar(all)}<div class="row cextra"><button class="g" data-act="col:statsT" aria-pressed="${colStatsOn}">${symbols()?sym('chart-bar'):'📊'}Goals &amp; stats</button><button class="g" data-act="col:quotesT">${symbols()?sym('quotes'):'❝'}Quotes${(n=>n?` <span class="meta">${n}</span>`:'')(quotesRead().length)}</button></div>
<div class="row colbar"><span class="sbox"><input id="colq" value="${esc(colQ)}" placeholder="Filter by title, creator or genre" aria-label="Filter collections">${colQ?`<button class="sclr" data-act="sclr" data-for="colq" aria-label="Clear search" title="Clear">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span><div class="moods seg"><button data-act="col:favf" class="favf ${colFav?'on':''}" aria-pressed="${colFav}" title="Show only favorites">${heartIco(colFav)}Favorites${(n=>n?` <span class="meta">${n}</span>`:'')(all.filter(x=>x.fav&&(colType==='all'||x.type===colType)).length)}</button></div>${(o=>`<div class="segsel"><span class="meta msl">Show</span><div class="moods seg">${o.map(([s,l])=>`<button data-act="col:stat" data-val="${s}" class="${colStat===s?'on':''}">${l}</button>`).join('')}</div>${segPick('Show',o,colStat)}</div>`)([['','All'],...CSTAT.map((s,i)=>[s,colType==='all'?CSTATL[i]:ctype(colType).st[i]])])}
${(o=>`<div class="nsort segsel"><span class="meta">Sort</span><div class="moods seg">${o.map(([v,l])=>`<button data-act="col:sort" data-val="${v}" class="${colSort===v?'on':''}" aria-pressed="${colSort===v}">${l}</button>`).join('')}</div>${segPick('Sort',o,colSort)}</div>`)([['added','Recently added'],['custom','Custom order'],['title','Title'],['rating','Rating'],['year','Year'],['status','Status']])}</div>
${ls.length?`<div class="cgrid">${ls.map(colCard).join('')}</div>`:`<section><p class="empty">${q?`Nothing in your collection matches “${esc(q)}”. Press Enter to search ${esc(ctype(colType==='all'?colSType:colType).label.toLowerCase())} to add it.`:all.length?'Nothing matches these filters.':'Nothing here yet. Press + to search for a book, movie, series, anime or game.'}</p></section>`}`}
function colDetail(){if(!CD||CD.k!==colSel)CD=colRead(colSel);const it=CD,t=ctype(it.type),on=x=>fieldOn(it.type,x);
 const text=(f,ph,extra='')=>`<label class="meta">${esc(fieldLabel(it.type,CFIELDS.find(x=>x.id===f)||{label:f}))} <input data-colf="${f}" value="${esc(it[f])}"${ph?` placeholder="${esc(ph)}"`:''}${extra}></label>`;
 const sugg=f=>{const d=CFIELDS.find(x=>x.id===f);return `<datalist id="dl-${f}">${[...new Set([...colKeys().map(k=>colRead(k)[f]).filter(Boolean),...(d.sugg||[])])].map(x=>`<option value="${esc(x)}">`).join('')}</datalist>`};
 return `<div class="lnav">${backBtn('col:back','Back to collections','Collections')}<button class="g" data-act="col:del">Delete…</button></div>
${coverPanel()}<div class="cdetail" style="--tc:${t.color}"><div><div class="cbig">${cimg(it,1)}</div>${on('cover')?`<div class="row" style="justify-content:center"><button class="g" data-act="col:alts">${CALT&&CALT.k===it.k?'Hide covers':it.cover?'Change cover':'Add cover'}</button>${it.cover?'<button class="x" data-act="col:nocover">Remove</button>':''}</div>`:''}</div><div class="cinfo">
<input class="ntitle" data-colf="title" value="${esc(it.title)}" aria-label="Title"><button class="cfavbig ${it.fav?'on':''}" data-act="col:fav" data-k="${esc(it.k)}" aria-pressed="${it.fav}" title="${it.fav?'Remove from favorites':'Add to favorites'}">${heartIco(it.fav)}${it.fav?'Favorite':'Add to favorites'}</button>
<div class="cfields">
<label class="meta">Type <select data-colf="type">${CTYPES.map(x=>`<option value="${x.id}" ${x.id===it.type?'selected':''}>${x.one[0].toUpperCase()+x.one.slice(1)}</option>`).join('')}</select></label>
${on('creator')?text('creator'):''}${on('year')?text('year','',' inputmode="numeric"'):''}
${on('length')?text('length',{book:'e.g. 320 pages',movie:'e.g. 128 min',series:'e.g. 5 seasons',anime:'e.g. 24 episodes',game:'e.g. 40 hours'}[it.type]):''}
${on('platform')?text('platform','e.g. Netflix',' list="dl-platform"')+sugg('platform'):''}
${on('store')?text('store','e.g. Steam',' list="dl-store"')+sugg('store'):''}
${on('device')?text('device','e.g. PC',' list="dl-device"')+sugg('device'):''}
${on('downloaded')?`<div class="meta cfseg"><span>Downloaded</span><div class="moods seg">${[['yes','Yes'],['no','No']].map(([v,l])=>`<button data-act="col:dl" data-val="${v}" class="${it.downloaded===v?'on':''}" aria-pressed="${it.downloaded===v}">${l}</button>`).join('')}</div></div>`:''}
${on('source')?`<label class="meta cwide">Link <input data-colf="source" value="${esc(it.source)}" placeholder="https://…" inputmode="url"></label>`:''}
${on('genres')?`<div class="meta cwide">Genres<div class="pval" style="margin-top:4px">${it.genres.map((g,i)=>`<span class="chip">${esc(g)}<button class="cx" data-act="col:gdel" data-i="${i}" aria-label="Remove ${esc(g)}">×</button></span>`).join('')}<input class="pinp" id="colgen" placeholder="${it.genres.length?'Add genre':'Add genres (Enter or comma)'}" aria-label="Add a genre"></div></div>`:''}
</div>
${L('Status')}<div class="moods seg">${CSTAT.map((s,i)=>`<button data-act="col:status" data-val="${s}" class="${it.status===s?'on':''}">${t.st[i]}</button>`).join('')}</div>
${on('rating')?L('Your rating')+stars(it.rating,1):''}
${on('dates')?`<div class="row"><label class="meta lab">Started <input type="date" data-colf="started" value="${esc(it.started)}"></label><label class="meta lab">Finished <input type="date" data-colf="finished" value="${esc(it.finished)}"></label></div>`:''}
${on('notes')?L('Notes')+`<textarea data-colf="body" class="cnotes" placeholder="Your thoughts, quotes, where you left off…">${esc(it.body)}</textarea>`:''}
${(qs=>`${L('Quotes and highlights')}${qs.map(x=>quoteCard(x,0)).join('')}<div class="qadd"><textarea id="qnew" placeholder="Add a quote or a moment you want to remember…" rows="2"></textarea><div class="row" style="margin:6px 0 0"><input id="qat" placeholder="${it.type==='book'?'Page (e.g. p. 42)':'Time or episode (e.g. 1:12:05)'}" style="flex:0 0 220px"><button class="g" data-act="col:quoteAdd">${lineIco('M12 5v14M5 12h14')}Add quote</button></div></div>`)(quotesRead().filter(x=>x.k===it.k))}
<p class="meta">Added ${it.added?fmt(it.added):''}${on('source')&&/^https?:\/\//.test(it.source)?` · <button class="x" data-act="col:link" data-val="${esc(it.source)}" style="margin-left:-6px">Open on ${esc(hostOf(it.source))} ${sym('arrow-square-out')}</button>`:''}</p></div></div>`}
V.collections=()=>{if(colSel&&!FS[colSel])colSel=null;return colSel?colDetail():colHome()};
// Typing in an item's fields saves after a short pause; title or year changes rename the file.
function colField(f,v){if(!CD)return;CD[f]=v;clearTimeout(colTimer);colTimer=setTimeout(()=>{colTimer=null;if(CD&&FS[CD.k]!==undefined){colPut(CD);save()}},500)}
const colFlush=()=>{if(colTimer){clearTimeout(colTimer);colTimer=null;if(CD&&FS[CD.k]!==undefined){colPut(CD);save()}}};
function colAct(a,b){colFlush();const v=b.dataset.val;if(a==='back'||a==='open'||a==='type')CALT=null;
  if(a==='sort'){colSort=CFG.colSort=v;saveCfg()}
 if(a==='fav'){const k=b.dataset.k;if(FS[k]){const it=CD&&CD.k===k?CD:colRead(k);it.fav=!it.fav;colPut(it);if(CD&&CD.k===k)CD=null;save();toast(it.fav?'Added to favorites':'Removed from favorites')}}
 if(a==='favf')colFav=!colFav;
 else if(a==='statsT'){colStatsOn=!colStatsOn}
 else if(a==='goalSave'){const y=colYear(),g={...((CFG.colGoals||{})[y]||{})};document.querySelectorAll('[data-cgoal]').forEach(i=>{const n=parseInt(i.value);if(n>0)g[i.dataset.cgoal]=n;else delete g[i.dataset.cgoal]});CFG.colGoals={...(CFG.colGoals||{}),[y]:g};saveCfg();toast('Goals saved')}
 else if(a==='quotesT'){colQuotes=!colQuotes;colQQ='';window.scrollTo(0,0)}
 else if(a==='quoteAdd'&&CD){const q=(($('qnew')||{}).value||'').trim();if(!q){toast('Write the quote first');return}quotesWrite([...quotesRead(),{d:TD(),q,title:CD.title,at:(($('qat')||{}).value||'').trim(),k:CD.k}]);toast('Quote saved')}
 else if(a==='quoteDel'){const l=quotesRead();l.splice(+b.dataset.i,1);quotesWrite(l);toast('Quote deleted')}
 if(a==='multi'){colMulti=!colMulti;colPicks=new Set()}
 if(a==='tog'){const i=+b.dataset.i;colPicks.has(i)?colPicks.delete(i):colPicks.add(i)}
 if(a==='addsel'){colAddMany();return}
 if(a==='type'){colType=colType===v&&!colSel?'all':v;colSel=null;if(colType!=='all')colSType=colType}
 else if(a==='inprog'){view='collections';colSel=null;CD=null;colType='all';colStat='doing';colQ='';window.scrollTo(0,0)}
 else if(a==='add'){colAdd=!colAdd;colErr='';if(!colAdd){colRes=null;colSQ='';colMulti=false;colPicks=new Set();colTok++}if(colAdd&&colType!=='all')colSType=colType;setTimeout(()=>{const i=$('cols');if(i)i.focus()})}
 else if(a==='stype'){colSType=v;colRes=null;colPicks=new Set();colErr='';if(colSQ.trim()){colSearch();return}}
 else if(a==='search'){colSQ=($('cols')||{}).value||colSQ;colSearch();return}
 else if(a==='pick'){colAddResult(+b.dataset.i);return}
 else if(a==='manual'){const title=(($('cols')||{}).value||'').trim()||'Untitled';const k=colPut({type:colSType,title,creator:'',year:'',status:'want',rating:0,genres:[],cover:'',length:'',source:'',added:TD(),started:'',finished:'',body:''});colSel=k;CD=null;colAdd=false;colRes=null;colSQ='';colErr='';view='collections';window.scrollTo(0,0)}
 else if(a==='open'){colSel=b.dataset.k;CD=null;colQ='';view='collections';window.scrollTo(0,0)}
 else if(a==='back'){colSel=null;CD=null;if(wlFrom)wlReturn()}
 else if(a==='stat')colStat=v;
 else if(a==='sugNext'){colSug++}
 else if(a==='sugStart'){const it=FS[b.dataset.k]&&colRead(b.dataset.k);if(it){colSetStatus(it,'doing');colPut(it);toast(`${it.title} · ${statLabel(it.type,'doing')}`)}}
 else if(a==='status'&&CD){colSetStatus(CD,v);colPut(CD)}
 else if(a==='rate'&&CD){CD.rating=CD.rating===+v?0:+v;rateDone(CD);colPut(CD)}
 else if(a==='del'&&CD){colConfirmDel(CD.k);return}
 else if(a==='link'){openLink(v);return}
 else if(a==='cover'&&CD){pickCover(CD);return}
 else if(a==='alts'&&CD){if(CALT&&CALT.k===CD.k)CALT=null;else{coverAlts(CD);return}}
 else if(a==='altclose')CALT=null
 else if(a==='altuse'){coverUse(+b.dataset.i);return}
 else if(a==='nocover'&&CD){CD.cover='';colPut(CD)}
 else if(a==='dl'&&CD){CD.downloaded=CD.downloaded===v?'':v;colPut(CD)}
 else if(a==='fld'){const tp=b.dataset.type,id=b.dataset.id,cur=fieldsFor(tp).filter(f=>fieldOn(tp,f.id)).map(f=>f.id);CFG.colFields={...CFG.colFields,[tp]:cur.includes(id)?cur.filter(x=>x!==id):[...cur,id]};saveCfg()}
 else if(a==='fldReset'){CFG.colFields={};saveCfg()}
 else if(a==='gdel'&&CD){CD.genres.splice(+b.dataset.i,1);colPut(CD)}
 save();render()}
document.addEventListener('input',e=>{const t=e.target,f=t.dataset&&t.dataset.colf;
 if(f==='type'&&CD){colFlush();CD.type=t.value;colPut(CD);save();render();return}
 if(f){colField(f,t.value);return}
 if(t.id==='jq'){jq=t.value;const p=t.selectionStart;redraw();const n=$('jq');if(n){n.focus();n.setSelectionRange(p,p)}return}
 if(t.id==='setq'){setQ=t.value;const p=t.selectionStart;render();const n=$('setq');if(n){n.focus();n.setSelectionRange(p,p)}return}
 if(t.id==='colq'){colQ=t.value;const p=t.selectionStart;render();const n=$('colq');if(n){n.focus();n.setSelectionRange(p,p)}return}
 if(t.id==='cols'){colSQ=t.value;return}
 if(t.id==='colsort'){colSort=CFG.colSort=t.value;saveCfg();render();return}
 if(t.id==='tmdbkey'||t.id==='rawgkey'){CFG[t.id==='tmdbkey'?'tmdbKey':'rawgKey']=t.value.trim();saveCfg();return}});
document.addEventListener('input',e=>{const t=e.target;if(t.id==='pnm'){PN.name=t.value;return}
 if(t.dataset&&t.dataset.pcolor!==undefined){const c=document.querySelector(`.pcard[data-pk="${CSS.escape(t.dataset.pcolor)}"]`);if(c)c.style.setProperty('--tc',vivid(t.value));const sw=t.closest('.swcustom');if(sw)sw.style.background=t.value;return}
 if(t.dataset&&t.dataset.stickycolor!==undefined){const it=document.querySelector(`#hboard [data-bid="note:${CSS.escape(t.dataset.stickycolor)}"]`);if(it){it.style.setProperty('--sc',t.value);it.style.setProperty('--sink',stcInk(t.value))}const sw=t.closest('.swcustom');if(sw)sw.style.background=t.value;return}
 if(t.dataset&&t.dataset.homecolor){const c=document.querySelector(`section[data-dnd="home"][data-id="${t.dataset.homecolor}"]`);if(c){c.style.setProperty('--cc',t.value);c.classList.add('hcolored')}const sw=t.closest('.swcustom');if(sw)sw.style.background=t.value;return}
 if(t.dataset&&t.dataset.navcolor){const nb=document.querySelector(`#nav .navb[data-v="${t.dataset.navcolor}"]`);if(nb)nb.style.setProperty('--tc',vivid(t.value));const sw=t.closest('.swcustom');if(sw)sw.style.background=t.value;return}
 if(t.dataset&&t.dataset.ldcolor!==undefined&&LD){LD.color=t.value;const sh=document.querySelector('.sheet');if(sh)sh.style.setProperty('--tc',t.value);document.querySelectorAll('.sheet .lri').forEach(x=>x.style.background=t.value);const sw=t.closest('.swcustom');if(sw){sw.style.background=t.value}}});
document.addEventListener('change',e=>{const t=e.target;if(EV&&(t.id==='evr'||t.id==='evn')){evSync();render();return}if(t.dataset&&t.dataset.ldcolor!==undefined&&LD){LD.color=t.value;render();return}
 if(t.dataset&&t.dataset.pcolor!==undefined){const p=getP(t.dataset.pcolor);p.color=t.value;putP(p);save();closeCtx();render();return}
 if(t.dataset&&t.dataset.stickycolor!==undefined){const k=t.dataset.stickycolor;if(FS[k]){const n=readNote(FS[k]);n.fm.color=t.value;FS[k]=writeNote(n);save()}closeCtx();render();return}
 if(t.dataset&&t.dataset.homecolor){const id=t.dataset.homecolor;CFG.homeColors={...(CFG.homeColors||{}),[id]:t.value};saveCfg();closeCtx();render();return}
 if(t.dataset&&t.dataset.navcolor){const id=t.dataset.navcolor;CFG.navColors={...(CFG.navColors||{}),[id]:t.value};saveCfg();closeCtx();render();return}
 if(t.dataset&&t.dataset.lcolor!==undefined&&curList){const l=getList(curList);l.color=t.value;putList(l);save();render();return}
 if(e.target.id==='medcustom'&&e.target.value){medSetDur(+e.target.value);render()}});
document.addEventListener('keydown',e=>{if(e.target.id==='catname'&&e.key==='Enter'){e.preventDefault();const b=document.querySelector('[data-act="catSave"]');if(b)b.click();return}
 if(e.target.id==='catname'&&e.key==='Escape'){const b=document.querySelector('[data-act="catCancel"]');if(b)b.click();return}
 if(e.target.id==='cols'&&e.key==='Enter'){e.preventDefault();colSQ=e.target.value;colSearch();return}
 // Enter in the filter: when nothing in the collection matches, search online for it in the add panel.
 if(e.target.id==='colq'&&e.key==='Enter'){const q=e.target.value.trim();e.preventDefault();if(!q||document.querySelector('.cgrid .ccard'))return;
  if(colType!=='all')colSType=colType;colQ='';colStat='';colAdd=true;colSQ=q;colRes=null;colErr='';colSearch();render();return}
 if(e.target.id==='colgen'&&CD){const v=e.target.value.trim();
  if((e.key==='Enter'||e.key===',')&&v){e.preventDefault();colFlush();v.split(',').map(x=>x.trim()).filter(Boolean).forEach(g=>{if(!CD.genres.some(y=>y.toLowerCase()===g.toLowerCase()))CD.genres.push(g)});colPut(CD);save();render();const n=$('colgen');if(n)n.focus()}
  else if(e.key==='Backspace'&&!v&&CD.genres.length){CD.genres.pop();colPut(CD);save();render();const n=$('colgen');if(n)n.focus()}}});
window.addEventListener('blur',colFlush);document.addEventListener('visibilitychange',()=>{if(document.hidden)colFlush()});
// Settings → Collections: the two optional API keys.
const colFieldSettings=()=>`<p class="meta" style="margin:0 0 8px">Choose what to keep for each type. Turning a field off hides it and stops filling it from the catalogs; values already saved stay in the files.</p>
${ctypesOrdered().map(t=>`<div class="cfrow"><b>${symbols()?sym(t.sym):t.emoji} ${t.label}</b><div class="moods multi">${fieldsFor(t.id).map(f=>{const o=fieldOn(t.id,f.id);return `<button class="${o?'on':''}" data-act="col:fld" data-type="${t.id}" data-id="${f.id}" aria-pressed="${o}">${esc(fieldLabel(t.id,f))}</button>`}).join('')}</div></div>`).join('')}
<div class="row"><button class="x" data-act="col:fldReset">Restore default fields</button></div>`;
const colSettings=()=>`<p class="meta" style="margin:0 0 10px">Books (Open Library), series (TVmaze) and anime (AniList) work without a key. Movies and games need a free key from their catalog. Keys are stored with your settings on this computer.</p>
<label class="meta lab" style="margin-bottom:8px">TMDB API key (movies) <input id="tmdbkey" value="${esc(CFG.tmdbKey||'')}" autocomplete="off" spellcheck="false" placeholder="Not set"></label><button class="x" data-act="col:link" data-val="https://www.themoviedb.org/settings/api" style="margin:-4px 0 10px -6px">Get a TMDB key ${sym('arrow-square-out')}</button>
<label class="meta lab" style="margin-bottom:8px">RAWG API key (games) <input id="rawgkey" value="${esc(CFG.rawgKey||'')}" autocomplete="off" spellcheck="false" placeholder="Not set"></label><button class="x" data-act="col:link" data-val="https://rawg.io/apidocs" style="margin:-4px 0 0 -6px">Get a RAWG key ${sym('arrow-square-out')}</button>`;

/* Shine on hover, collection covers and Storage cards: the cover tilts toward the pointer (CSS reads --rx/--ry) while CSS plays a
   diagonal light sweep. Mouse only, and not while dragging. */
let tiltEl=null;
const tiltOff=()=>{if(tiltEl){tiltEl.classList.remove('tilt');tiltEl=null}};
document.addEventListener('pointermove',e=>{const card=e.pointerType==='mouse'&&document.body.classList.contains('shine')&&!(drg&&drg.started)&&e.target.closest&&e.target.closest('.ccard:not(.dragghost),.stcard,.mini'),el=card&&card.querySelector('.ccov,.stcov,.mcov');
 if(el!==tiltEl)tiltOff();if(!el)return;tiltEl=el;const r=el.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;
 el.style.setProperty('--rx',(-y*16).toFixed(2)+'deg');el.style.setProperty('--ry',(x*16).toFixed(2)+'deg');el.classList.add('tilt')},{passive:true});
document.addEventListener('pointerout',e=>{if(!e.relatedTarget||!(e.relatedTarget.closest&&e.relatedTarget.closest('.ccard,.stcard,.mini')))tiltOff()});
// Shine: one sweep starts the moment the pointer enters a cover card and always plays to the end;
// hovering again before it finishes does not restart it.
document.addEventListener('pointerover',e=>{if(!document.body.classList.contains('shine')||(drg&&drg.started))return;const card=e.target.closest&&e.target.closest('.ccard:not(.dragghost),.stcard,.mini');
 if(!card||(e.relatedTarget&&card.contains(e.relatedTarget)))return;const el=card.querySelector('.ccov,.stcov,.mcov');if(!el||el.classList.contains('shining'))return;
 el.classList.add('shining');const done=ev=>{if(ev.target!==el||ev.pseudoElement!=='::after')return;el.classList.remove('shining');el.removeEventListener('animationend',done);el.removeEventListener('animationcancel',done)};
 el.addEventListener('animationend',done);el.addEventListener('animationcancel',done)});
/* ---------- Health ----------
   Overview: healthy and not-healthy habits, mood, and a gym summary. Gym: a workout tracker tied to the habit marked
   "Count gym workouts" (a workout with at least one set ticks that habit for its day; deleting the workout unticks it).
   Workouts are Markdown files health/workouts/<YYYY-MM-DD>.md, readable anywhere:
     ---                       ## Bench press            ## Running
     date: 2026-10-20          - 60 kg × 8               - 5 km in 28 min
     routine: Push day         - 60 kg × 8
     duration: 60
     ---
   Routines are health/routines/<Name>.md with "type: routine" and one "## Day" heading per day:
     ## Push                    ## Pull
     - Bench press · 3 × 8      - Barbell row · 4 × 10
   (older routines, one "## Exercise" heading per exercise, read as a single day). A workout started from a routine
   keeps "day: Push" in its front matter, and an exercise checked off is written "## [x] Bench press". Weights are in kg. */
let gymTab='history',hv='overview',wkSel=null,WK=null,wkTimer=null,rtNew=false,exSel=null,RE=null;
const CARDIO=['Running','Cycling','Rowing machine','Elliptical','Swimming','Walking','Jump rope'];
const wkKey=d=>`health/workouts/${d}.md`;
const gymHabit=()=>habits().find(h=>h.workouts)||null;
// Parses a workout file: exercises with strength sets {kg,reps} or cardio sets {km,min}.
function wkRead(d){const k=wkKey(d);if(!FS[k])return null;const n=readNote(FS[k]),ex=[];let cur=null;const notes=[];
 for(const l0 of n.body.split('\n')){let m;const fl={};let l=l0;
  if(/^-/.test(l)){if(/\s✓\s*$/.test(l)){fl.ok=true;l=l.replace(/\s✓\s*$/,'')}const tm=l.match(/\s*\((warm-up|drop)\)\s*$/i);if(tm){fl.t=tm[1].toLowerCase()==='drop'?'d':'w';l=l.replace(tm[0],'')}}
  if(m=l.match(/^##\s+(?:\[([ xX])\]\s+)?(.+)$/)){cur={name:m[2].trim(),kind:'strength',sets:[],done:!!m[1]&&m[1]!==' '};ex.push(cur);continue}
  if(cur&&(m=l.match(/^-\s*([\d.,]+)\s*kg\s*[×x*]\s*(\d+)/i))){cur.sets.push({kg:m[1].replace(',','.'),reps:m[2],...fl});continue}
  if(cur&&(m=l.match(/^-\s*(\d+)\s*reps?\b/i))){cur.sets.push({kg:'',reps:m[1],...fl});continue}
  if(cur&&(m=l.match(/^-\s*(?:([\d.,]+)\s*km)?\s*(?:in\s*)?(?:([\d.,]+)\s*min)?\s*$/i))&&(m[1]||m[2])){cur.kind='cardio';cur.sets.push({km:(m[1]||'').replace(',','.'),min:(m[2]||'').replace(',','.'),...fl});continue}
  if(!cur&&l0.trim()&&!/^#\s/.test(l0))notes.push(l0)}
 ex.forEach(e=>{if(!e.sets.length)e.sets.push(isCardio(e.name)?{km:'',min:''}:{kg:'',reps:''})});
 return{d,routine:String(n.fm.routine||''),day:String(n.fm.day||''),duration:String(n.fm.duration||''),notes:notes.join('\n').trim(),ex}}
const setTag=s=>(s.t==='w'?' (warm-up)':s.t==='d'?' (drop)':'')+(s.ok?' ✓':'');
const setLine=(e,s)=>(e.kind==='cardio'?`- ${[s.km?s.km+' km':'',s.min?(s.km?'in ':'')+s.min+' min':''].filter(Boolean).join(' ')}`:s.kg?`- ${s.kg} kg × ${s.reps||0}`:`- ${s.reps||0} reps`)+setTag(s);
// The last earlier session of an exercise, and the heaviest working set (warm-ups left out) before a day.
const lastEx=(name,before)=>{for(const d of workouts()){if(before&&d>=before)continue;const w=wkRead(d),x=w&&w.ex.find(y=>fold(y.name)===fold(name));if(x&&x.sets.some(s=>setFilled(x,s)))return{d,x}}return null};
const bestBefore=(name,before)=>{let b=0;for(const d of workouts()){if(d>=before)continue;const x=(wkRead(d).ex||[]).find(y=>fold(y.name)===fold(name));if(x&&x.kind!=='cardio')x.sets.forEach(s=>{if(s.t!=='w')b=Math.max(b,parseFloat(s.kg)||0)})}return b};
const setShort=(e,s)=>e.kind==='cardio'?[s.km?s.km+' km':'',s.min?s.min+' min':''].filter(Boolean).join(' '):s.kg?`${s.kg}×${s.reps||0}`:`${s.reps||0} reps`;
/* Rest timer: after a set is checked off, a countdown pill (CFG.rest seconds; 0 = off) floats at the bottom of the window. */
let REST=null,restTick=null;
function restStart(sec){if(!sec)return;REST={end:Date.now()+sec*1000,total:sec};restShow()}
function restShow(){let el=$('restpill');if(!REST){if(el)el.remove();clearInterval(restTick);restTick=null;return}
 if(!el){el=document.createElement('div');el.id='restpill';el.className='restpill';document.body.appendChild(el)}
 const left=Math.max(0,Math.round((REST.end-Date.now())/1000)),pct=100-left/REST.total*100;
 el.innerHTML=`<span class="rpring" style="--p:${pct}%"></span><b>${Math.floor(left/60)}:${pad(left%60)}</b><span class="meta">Rest</span><button class="cx" data-act="hl:restadd" title="Add 15 seconds">+15s</button><button class="cx" data-act="hl:restskip" title="Skip rest">Skip</button>`;
 if(!left){REST=null;restShow();toast('Rest over · next set');try{const ac=new (window.AudioContext||window.webkitAudioContext)(),o=ac.createOscillator(),g=ac.createGain();o.frequency.value=880;g.gain.setValueAtTime(.15,ac.currentTime);g.gain.exponentialRampToValueAtTime(.001,ac.currentTime+.6);o.connect(g);g.connect(ac.destination);o.start();o.stop(ac.currentTime+.6)}catch(e){}return}
 if(!restTick)restTick=setInterval(restShow,250)}
const setFilled=(e,s)=>e.kind==='cardio'?!!(s.km||s.min):!!(s.reps||s.kg);
function wkWrite(w){const fm={date:w.d,...(w.routine?{routine:w.routine}:{}),...(w.routine&&w.day?{day:w.day}:{}),...(w.duration?{duration:w.duration}:{})};
 const body=(w.notes?w.notes+'\n\n':'')+w.ex.map(e=>`## ${e.done?'[x] ':''}${e.name}\n${e.sets.filter(s=>setFilled(e,s)).map(s=>setLine(e,s)).join('\n')}`).join('\n\n');
 FS[wkKey(w.d)]=writeNote({fm,body:body+'\n'});syncGym(w.d)}
// Keeps the gym habit in step with workouts: a workout with a set (from a routine day: a checked-off exercise) ticks the day; no workout unticks a tick it made.
function syncGym(d){const h=gymHabit();if(!h||h.kind!=='yesno')return;const w=wkRead(d),has=!!(w&&(w.day?w.ex.some(e=>e.done):w.ex.some(e=>e.sets.some(s=>setFilled(e,s)))));
 if(has&&h.log[d]!=='yes'&&d<=TD()){h.log[d]='yes';putH(h)}else if(!has&&h.log[d]==='yes'&&!FS[wkKey(d)]){delete h.log[d];putH(h)}}
const workouts=()=>Object.keys(FS).filter(k=>/^health\/workouts\/\d{4}-\d{2}-\d{2}\.md$/.test(k)).map(k=>k.slice(16,26)).sort().reverse();
// A routine: {k, name, days:[{name, ex:[{name, sets, reps}]}]}; ex lists every exercise name (older callers use it).
const rtParseEx=t=>{const m=t.match(/^(.*?)\s*(?:·|-|—)\s*(\d+)\s*[×x*]\s*(\d+(?:\s*-\s*\d+)?)\s*$/);return m?{name:m[1].trim(),sets:m[2],reps:m[3].replace(/\s+/g,'')}:{name:t.trim(),sets:'',reps:''}};
function rtRead(k){const n=readNote(FS[k]),name=k.slice(16,-3),days=[];
 if(n.fm.type==='routine'){let cur=null;for(const l of n.body.split('\n')){let m;if(m=l.match(/^##\s+(.+)$/)){cur={name:m[1].trim(),ex:[]};days.push(cur)}else if(cur&&(m=l.match(/^[-*]\s+(.+)$/)))cur.ex.push(rtParseEx(m[1]))}}
 else{const ex=n.body.split('\n').map(l=>l.match(/^##\s+(.+)$/)).filter(Boolean).map(m=>({name:m[1].trim(),sets:'',reps:''}));days.push({name:'Day 1',ex})}
 return{k,name,days,ex:[...new Set(days.flatMap(d=>d.ex.map(e=>e.name)))]}}
const routines=()=>Object.keys(FS).filter(k=>k.startsWith('health/routines/')&&k.endsWith('.md')).sort().map(rtRead);
const rtKey=name=>`health/routines/${safeName(name)}.md`;
const rtWrite=r=>{FS[rtKey(r.name)]=writeNote({fm:{type:'routine'},body:`# ${r.name}\n\n`+r.days.map((d,i)=>`## ${d.name.trim()||'Day '+(i+1)}\n`+d.ex.filter(e=>e.name.trim()).map(e=>`- ${e.name.trim()}${e.sets||e.reps?` · ${e.sets||1} × ${e.reps||'?'}`:''}`).join('\n')).join('\n\n')+'\n'})};
const rtTarget=e=>e&&(e.sets||e.reps)?`${e.sets||1} × ${e.reps||'?'}`:'';
// The day that comes after the last one done (the first day if the routine hasn't been used yet).
const rtNext=r=>{for(const d of workouts()){const w=wkRead(d);if(w&&w.routine===r.name){const i=r.days.findIndex(x=>x.name===w.day);return i<0?0:(i+1)%r.days.length}}return 0};
// The plan for an exercise in a workout started from a routine day.
const wkPlan=(w,name)=>{if(!w.routine)return null;const r=routines().find(x=>x.name===w.routine),d=r&&(r.days.find(x=>x.name===w.day)||(r.days.length===1?r.days[0]:null));return d?d.ex.find(e=>fold(e.name)===fold(name))||null:null};
const isCardio=n=>CARDIO.some(c=>fold(c)===fold(n))||(exFind(n)||{}).k==='cardio';
// The most recent earlier sets of an exercise (to prefill a new workout).
const lastSets=(name,before)=>{for(const d of workouts()){if(before&&d>=before)continue;const w=wkRead(d),e=w&&w.ex.find(x=>fold(x.name)===fold(name));if(e&&e.sets.length)return e}return null};
function exStats(){const m={};for(const d of workouts().slice().reverse()){const w=wkRead(d);for(const e of w.ex){const s=m[fold(e.name)]||(m[fold(e.name)]={name:e.name,kind:e.kind,days:0,last:null,best:null,bestKm:0});
 s.days++;s.last=d;s.kind=e.kind;for(const x of e.sets){if(x.t==='w')continue;if(e.kind==='cardio'){const km=parseFloat(x.km)||0;if(km>s.bestKm)s.bestKm=km}else{const kg=parseFloat(x.kg)||0,r=+x.reps||0;if(kg&&(!s.best||kg>s.best.kg||(kg===s.best.kg&&r>s.best.reps)))s.best={kg,reps:r,d}}}}}
 return Object.values(m).sort((a,b)=>alpha(a.name,b.name))}
const volume=w=>Math.round(w.ex.reduce((t,e)=>t+(e.kind==='cardio'?0:e.sets.reduce((u,s)=>u+(parseFloat(s.kg)||0)*(+s.reps||0),0)),0));
// Starts a workout for day d, empty or from a routine day (di = day index; the next day when left out).
// If the day already has a workout, it is opened, and a routine day's exercises are added to it (those not in it yet).
function newWorkout(d,routine,di){const old=wkRead(d);if(old&&!routine){wkSel=d;WK=null;return}
 const day=routine?routine.days[di!=null&&routine.days[di]?di:rtNext(routine)]:null,plan=day?day.ex.filter(e=>e.name.trim()&&!(old&&old.ex.some(x=>fold(x.name)===fold(e.name)))):[];
 const w={d,routine:routine?routine.name:'',day:day?day.name:'',duration:old?old.duration:'',notes:old?old.notes:'',ex:[...(old?old.ex:[]),...plan.map(pe=>{const n=pe.name,p=lastSets(n,d),kind=p?p.kind:isCardio(n)?'cardio':'strength';
  if(kind==='cardio')return{name:n,kind,sets:p?p.sets.map(s=>({...s})):[{km:'',min:''}]};
  const k=+pe.sets||(p?p.sets.length:1),reps=String(pe.reps||'').split('-')[0];
  return{name:n,kind,sets:[...Array(Math.max(1,k))].map((_,i)=>{const ps=p&&p.sets[Math.min(i,p.sets.length-1)];return{kg:ps?ps.kg:'',reps:reps||(ps?ps.reps:'')}})}})]};
 wkWrite(w);wkSel=d;WK=w}
const wkDraft=()=>{if(!WK||WK.d!==wkSel)WK=wkRead(wkSel);return WK};
const wkSave=()=>{clearTimeout(wkTimer);wkTimer=null;if(WK&&FS[wkKey(WK.d)]!==undefined){wkWrite(WK);save()}};
const wkSoon=()=>{clearTimeout(wkTimer);wkTimer=setTimeout(wkSave,500)};

// ----- views
const healthTiles=()=>{const gh=gymHabit(),ws=weekStart(TD()),n=workouts().filter(d=>d>=ws).length;
 return tileBar('hl:view',hv,[['overview','Overview','heartbeat','❤️','#e0566f',habits().filter(h=>h.health!=='none').length],['gym','Gym','barbell','🏋️','#5fa57f',n],['meditation','Meditation','flower-lotus','🧘','#8a7fd0',medDays().filter(d=>d>=ws).length],['body','Body','person','🧍','#4a8fd9',bodyRead().filter(x=>x.d>=ws).length]])};
function hlOverview(){const hs=habits(),good=hs.filter(h=>h.health==='healthy'),bad=hs.filter(h=>h.health==='unhealthy'),t=TD(),ws=weekStart(t);
 const row=h=>{const wk=h.period==='weekly',st=hStats(h),w=wk?weekStatus(h,ws):null,r=wk?null:hOk(h,t);
  const status=wk?`${w.text} · ${weekVal(h,ws)}/${h.target} ${esc(weekUnit(h))}`:r===null?'Not logged today':h.health==='unhealthy'?(r?'Avoided today':'Had it today'):r?'Done today':'Missed today';
  // controls to log today, like on Home: one check for weekly yes/no, Yes/No for daily, a value box for numbers
 const e=esc(h.id),v=h.log[t],ctl=wk&&h.kind==='yesno'?`<button class="hcheck ${v==='yes'?'on':''}" data-act="hChk" data-k="${e}" data-d="${t}" aria-pressed="${v==='yes'}"><i>✓</i>${v==='yes'?'Done':'Mark as done'}</button>`
  :h.kind==='yesno'?`<div class="moods seg"><button data-act="hSet" data-k="${e}" data-d="${t}" data-val="yes" class="${v==='yes'?'on':''}">Yes</button><button data-act="hSet" data-k="${e}" data-d="${t}" data-val="no" class="${v==='no'?'on':''}">No</button></div>`
  :`<span class="hlnum"><input type="number" step="any" id="hv-${e}" data-hv="${e}" value="${v!==undefined?esc(v):''}" placeholder="${esc(h.unit||'Value')}" aria-label="${esc(h.name)} today"><button class="b" data-act="hLog" data-k="${e}" data-d="${t}">Save</button></span>`;
 return `<div class="hlrow static"><span class="hico">${hIcon(h)||(symbols()?sym('heart'):'❤️')}</span><span class="t"><button class="clink hlname" data-act="hGo" data-k="${esc(h.id)}" title="Open in Habits">${esc(h.name)}</button><span class="meta">${esc(hGoal(h))} · <span class="hlst ${wk?(w.ok?'ok':''):r?'ok':r===false?'bad':''}">${status}</span>${st.streak?` · ${st.streak}${wk?'-week':'-day'} streak`:''}</span></span>${ctl}</div>`};
 // mood: last 14 days
 const days=[...Array(14)].map((_,i)=>dAdd(t,i-13)),mv=days.map(d=>getMood(d)),got=mv.filter(Boolean),avg=got.length?(got.reduce((a,b)=>a+b,0)/got.length).toFixed(1):'–';
 const mood=`<div class="mbars">${days.map((d,i)=>`<span title="${fmt(d)}${mv[i]?' · '+MOOD[mv[i]-1][0]:''}"><i style="height:${mv[i]*20}%;background:${mv[i]?`var(${MOOD[mv[i]-1][1]})`:'transparent'}"></i><em>${DN[pd(d).getDay()][0]}</em></span>`).join('')}</div><p class="meta" style="margin:8px 0 0">Average ${avg} over ${got.length} check-in${got.length===1?'':'s'}.${mv[13]?'':' <button class="x" data-act="nav" data-v="today" style="margin-left:-6px">Check in today</button>'}</p>`;
 const gh=gymHabit(),wk=workouts(),thisWeek=wk.filter(d=>d>=ws),last=wk[0]&&wkRead(wk[0]);
 const gym=`<div class="row" style="margin:0 0 6px;align-items:baseline"><b style="font-size:28px">${thisWeek.length}</b><span class="meta">workout${thisWeek.length===1?'':'s'} this week${gh&&gh.period==='weekly'?` · goal ${gh.target}`:''}</span></div>
${last?`<p class="meta" style="margin:0 0 8px">Last: ${fmt(last.d)}${last.routine?' · '+esc(last.routine):''} · ${last.ex.length} exercise${last.ex.length===1?'':'s'}${volume(last)?` · ${volume(last).toLocaleString()} kg lifted`:''}</p>`:'<p class="meta" style="margin:0 0 8px">No workouts yet.</p>'}
${gh?'':hlHabitTip('gym')}<div class="row" style="margin:0"><button class="b" data-act="hl:start">${FS[wkKey(t)]?'Open today’s workout':'Log a workout'}</button><button class="g" data-act="hl:view" data-val="gym">Gym</button></div>`;
 return `<div class="hgrid"><section class="hlhabits" ${secOn('habits')?'':'hidden'}><div class="head" style="margin:0 0 6px"><h2 style="margin:0">Habits</h2><button class="x" data-act="nav" data-v="habits">All habits</button></div>
${good.length||bad.length?`${good.length?`<p class="meta hlsub">Healthy</p>${good.map(row).join('')}`:''}${bad.length?`<p class="meta hlsub">Not healthy</p>${bad.map(row).join('')}`:''}`:'<p class="empty">No health habits yet. In Habits, mark a habit as Healthy or Not healthy.</p>'}</section>
<section><h2>Mood · last 14 days</h2>${mood}</section><section><h2>Gym</h2>${gym}</section>
<section><h2>Meditation</h2><div class="row" style="margin:0 0 6px;align-items:baseline"><b style="font-size:28px">${medFmt(medTotal(t))}</b><span class="meta">today · ${medStreak()}-day streak · ${medFmt(medDays().filter(d=>d>=ws).reduce((a,d)=>a+medTotal(d),0))} this week</span></div>
<div class="row" style="margin:0"><button class="b" data-act="hl:view" data-val="meditation">${MT.run?'Back to the timer':'Meditate'}</button></div></section></div>`}
function wkEditor(){const w=wkDraft();if(!w)return '';const rs=routines();
 const nd=w.ex.filter(e=>e.done).length,all=w.ex.length&&nd===w.ex.length;
 const ex=w.ex.map((e,i)=>{const pl=wkPlan(w,e.name),tg=rtTarget(pl);return `<div class="wkex ${e.done?'done':''}"><div class="head" style="margin:0 0 6px"><span class="wkexh"><button class="rchk wkchk ${e.done?'on':''}" data-act="hl:exdone" data-i="${i}" role="checkbox" aria-checked="${!!e.done}" aria-label="${e.done?'Mark as not done':'Mark as done'}" title="${e.done?'Mark as not done':'Mark as done'}">${e.done?lineIco('M5 12.5l4.5 4.5L19 7'):''}</button><button class="clink wkname" data-act="hl:ex" data-val="${esc(e.name)}" title="Exercise details">${esc(e.name)}</button>${tg?`<span class="wktg">${tg}</span>`:''}${e.done?`<span class="meta wksum">${e.sets.filter(s=>setFilled(e,s)).length} ${e.kind==='cardio'?'entr'+(e.sets.filter(s=>setFilled(e,s)).length===1?'y':'ies'):'set'+(e.sets.filter(s=>setFilled(e,s)).length===1?'':'s')}</span>`:''}</span><span><button class="x" data-act="hl:kind" data-i="${i}" title="Switch between weights and cardio">${e.kind==='cardio'?'Cardio':'Weights'}</button><button class="x" data-act="hl:exdel" data-i="${i}" aria-label="Remove ${esc(e.name)}">Remove</button></span></div>
${(()=>{const lx=lastEx(e.name,w.d);return lx&&!e.done?`<p class="meta wklast">Last time (${fmt(lx.d,{month:'short',day:'numeric'})}): ${lx.x.sets.filter(s=>setFilled(lx.x,s)).map(s=>esc(setShort(lx.x,s))).join(' · ')}</p>`:''})()}
<div class="wksets">${(()=>{const bb=e.kind==='cardio'?0:bestBefore(e.name,w.d);let n=0;return e.sets.map((s,j)=>{if(s.t!=='w')n++;const pr=bb&&s.t!=='w'&&(parseFloat(s.kg)||0)>bb;return `<div class="wkset ${s.ok?'ok':''} ${s.t?'t-'+s.t:''}"><button class="wkst" data-act="hl:settype" data-i="${i}" data-j="${j}" title="${s.t==='w'?'Warm-up set':s.t==='d'?'Drop set':'Working set'} · click to change">${s.t==='w'?'W':s.t==='d'?'D':n}</button>${e.kind==='cardio'?`<input data-wk="${i}.${j}.km" value="${esc(s.km)}" inputmode="decimal" placeholder="km" aria-label="Distance (km)"><span class="meta">km</span><input data-wk="${i}.${j}.min" value="${esc(s.min)}" inputmode="decimal" placeholder="min" aria-label="Time (min)"><span class="meta">min</span>`
  :`<input data-wk="${i}.${j}.kg" value="${esc(s.kg)}" inputmode="decimal" placeholder="kg" aria-label="Weight (kg)"><span class="meta">kg ×</span><input data-wk="${i}.${j}.reps" value="${esc(s.reps)}" inputmode="numeric" placeholder="reps" aria-label="Reps"><span class="meta">reps</span>`}${pr?'<span class="wkpr" title="Heavier than your best before this workout">PR</span>':''}<span style="flex:1"></span><button class="rchk sm wksok ${s.ok?'on':''}" data-act="hl:setok" data-i="${i}" data-j="${j}" role="checkbox" aria-checked="${!!s.ok}" aria-label="Set ${j+1} done" title="${s.ok?'Mark as not done':'Set done'}">${s.ok?lineIco('M5 12.5l4.5 4.5L19 7'):''}</button><button class="cx" data-act="hl:setdel" data-i="${i}" data-j="${j}" aria-label="Remove set ${j+1}">×</button></div>`}).join('')})()}</div>
<button class="x" data-act="hl:setadd" data-i="${i}" style="margin-left:-6px">+ ${e.kind==='cardio'?'Add entry':'Add set'}</button></div>`}).join('');
 return `<section class="wked"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${w.d===TD()?'Today’s workout':fmt(w.d,LONG)}${w.routine?`<span class="meta wkrt" data-notr>${esc(w.routine)}${w.day&&w.day!==w.routine?' · '+esc(w.day):''}</span>`:''}</h2><span><button class="g" data-act="hl:close">Done</button><button class="x" data-act="hl:wkdel">${armed==='wk:'+w.d?'Click again to delete':'Delete'}</button></span></div>
<div class="row" style="margin:0 0 10px"><label class="meta lab">Routine <input data-wkf="routine" value="${esc(w.routine)}" list="dl-routines" placeholder="Optional"></label><label class="meta lab" style="flex:0 0 160px;min-width:0">Duration <input data-wkf="duration" value="${esc(w.duration)}" inputmode="numeric" placeholder="min"></label></div>
<div class="row wkrest" style="margin:0 0 10px"><span class="meta">Rest timer</span><div class="moods seg">${[['0','Off'],['60','1 min'],['90','1:30'],['120','2 min'],['180','3 min']].map(([v,l])=>`<button data-act="hl:rest" data-val="${v}" class="${String(CFG.rest??90)===v?'on':''}" aria-pressed="${String(CFG.rest??90)===v}">${l}</button>`).join('')}</div></div>
<datalist id="dl-routines">${rs.map(r=>`<option value="${esc(r.name)}">`).join('')}</datalist>
${w.ex.length?`<div class="wkprog"><div class="head" style="margin:0 0 6px"><b>${all?'All exercises done':`${nd} of ${w.ex.length} exercises done`}</b>${all?'<button class="b" data-act="hl:close">Finish workout</button>':''}</div><div class="bar"><i style="width:${Math.round(nd/w.ex.length*100)}%"></i></div></div>`:''}
${ex||'<p class="empty">No exercises yet. Add one below.</p>'}
<div class="row"><input id="wkex" data-exs="one" autocomplete="off" placeholder="Add an exercise in English or Spanish (e.g. Press banca)" aria-label="Exercise name"><button class="b" data-act="hl:exadd">Add exercise</button></div>
${L('Notes')}<textarea data-wkf="notes" placeholder="How it felt, what to change next time…" style="min-height:80px">${esc(w.notes)}</textarea>
${rs.some(r=>r.name===w.routine)||!w.ex.length?'':`<div class="row"><button class="x" data-act="hl:saveRoutine">Save these exercises as a routine${w.routine?` “${esc(w.routine)}”`:''}</button></div>`}</section>`}
// The routine editor: a name, then days, each with exercises and a sets × reps target.
function reEditor(){const r=RE;
 return `<section class="rted"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${r.k?'Edit routine':'New routine'}</h2><span class="meta">${r.days.length} day${r.days.length===1?'':'s'}</span></div>
<input id="rename" data-re="name" value="${esc(r.name)}" placeholder="Routine name (e.g. Push Pull Legs)" aria-label="Routine name" autocomplete="off" style="max-width:420px">
${r.days.map((d,i)=>`<div class="reday"><div class="redhead"><span class="rednum">${i+1}</span><input data-re="${i}" value="${esc(d.name)}" placeholder="Day ${i+1}" aria-label="Day name" autocomplete="off"><span class="redtools">${i?`<button class="cx" data-act="hl:redayup" data-i="${i}" aria-label="Move day up" title="Move up">${lineIco('M12 19V5M6 11l6-6 6 6')}</button>`:''}${r.days.length>1?`<button class="cx" data-act="hl:redaydel" data-i="${i}" aria-label="Remove day" title="Remove day">${lineIco('M6 6l12 12M18 6L6 18')}</button>`:''}</span></div>
${d.ex.map((e,j)=>`<div class="rerow"><input class="rename" data-re="${i}.${j}.name" data-exs="rt" value="${esc(e.name)}" placeholder="Exercise (e.g. Bench press)" aria-label="Exercise" autocomplete="off"><input class="renum" data-re="${i}.${j}.sets" value="${esc(e.sets)}" inputmode="numeric" placeholder="sets" aria-label="Sets"><span class="meta">×</span><input class="renum" data-re="${i}.${j}.reps" value="${esc(e.reps)}" inputmode="numeric" placeholder="reps" aria-label="Reps"><button class="cx" data-act="hl:reexdel" data-i="${i}" data-j="${j}" aria-label="Remove exercise" title="Remove">×</button></div>`).join('')}
<button class="x" data-act="hl:reexadd" data-i="${i}" style="margin-left:-6px">+ Add exercise</button></div>`).join('')}
<div class="row" style="margin:12px 0 0"><button class="g" data-act="hl:redayadd">+ Add day</button></div>
<div class="row" style="margin-top:16px"><button class="b tick" data-act="hl:resave" aria-label="Save routine" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button><button class="g" data-act="hl:recancel">Cancel</button>${r.k?`<span style="flex:1"></span><button class="x" data-act="hl:rtdel" data-val="${esc(r.k.slice(16,-3))}">${armed==='rt:'+r.k.slice(16,-3)?'Click again to delete':'Delete routine'}</button>`:''}</div></section>`}
function hlGym(){if(wkSel&&!FS[wkKey(wkSel)])wkSel=null;const t=TD(),rs=routines(),wk=workouts(),gh=gymHabit();
 const tw=wkRead(t),busy=!!(tw&&tw.ex.length);
 const play=lineIco('M8 5.5v13l10.5-6.5z');
 const rcard=r=>{const nx=rtNext(r),n=r.days.reduce((a,d)=>a+d.ex.length,0);return `<div class="rtcard"><div class="rthead"><span class="rtico">${symbols()?sym('barbell'):'🏋️'}</span><span class="t"><b data-notr>${esc(r.name)}</b><span class="meta">${r.days.length} day${r.days.length===1?'':'s'} · ${n} exercise${n===1?'':'s'}</span></span><button class="x" data-act="hl:rtedit" data-val="${esc(r.k)}">Edit</button></div>
${r.days.map((d,x)=>`<div class="rtday ${x===nx?'next':''}"><span class="t"><b class="rtdn"><span data-notr>${esc(d.name)}</span>${x===nx&&r.days.length>1?'<span class="rtnext">Next</span>':''}</b><span class="meta">${d.ex.map(e=>`<span data-notr>${esc(e.name)}</span>${rtTarget(e)?' '+rtTarget(e):''}`).join(' · ')||'No exercises'}</span></span><button class="circ rtplay ${x===nx?'on':''}" data-act="hl:start" data-val="${esc(r.name)}" data-day="${x}" aria-label="Start ${esc(d.name)}" title="Start ${esc(d.name)}">${play}</button></div>`).join('')}</div>`};
 const start=`<section><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Workouts</h2><button class="circ" data-act="hl:rtnew" aria-label="New routine" title="New routine">${lineIco('M12 5v14M5 12h14')}</button></div>${busy?`<div class="row" style="margin:0 0 12px"><button class="b" data-act="hl:start">Open today’s workout</button>${rs.length?'<span class="meta">Starting a routine day adds its exercises to today’s workout.</span>':''}</div>`:''}${rs.length?`<div class="rtgrid">${rs.map(rcard).join('')}</div>`:'<p class="empty">Create a routine with one or more days (e.g. Push, Pull, Legs) with the + button, then start a day here and check off exercises as you go.</p>'}
${hlHabitTip('gym')}</section>`;
 const hist=`${wk.slice(0,30).map(d=>{const w=wkRead(d),v=volume(w);return `<button class="hlrow" data-act="hl:open" data-val="${d}"><span class="t"><b>${fmt(d,LONG)}</b><span class="meta">${[w.routine,w.ex.map(e=>e.name).slice(0,4).join(', ')+(w.ex.length>4?'…':'')].filter(Boolean).map(esc).join(' · ')}</span></span><span class="meta">${[w.duration?w.duration+' min':'',v?v.toLocaleString()+' kg':''].filter(Boolean).join(' · ')}</span></button>`}).join('')||'<p class="empty">No workouts yet. Start one from a routine above.</p>'}`;
 const st=exStats();
 const recs=`${st.map(s=>{const c=exFind(s.name);return `<button class="hlrow" data-act="hl:ex" data-val="${esc(s.name)}"><span class="t"><b>${esc(s.name)}</b><span class="meta">${[s.days+' session'+(s.days===1?'':'s'),'last '+fmt(s.last),c&&c.m&&c.m.length?c.m.map(exCap).join(', '):''].filter(Boolean).join(' · ')}</span></span><span class="meta">${s.kind==='cardio'?(s.bestKm?`Longest ${s.bestKm} km`:''):s.best?`Best ${s.best.kg} kg × ${s.best.reps}`:''}</span></button>`}).join('')||'<p class="empty">Exercises you log show up here with your records.</p>'}`;
 // History and Exercises share one card, switched with a segmented control.
 const log=`<section class="gymlog"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">Activity</h2><div class="moods seg">${[['history','History',wk.length],['ex','Exercises',st.length]].map(([v,l,n])=>`<button data-act="hl:gtab" data-val="${v}" class="${gymTab===v?'on':''}" aria-pressed="${gymTab===v}">${l}${n?` <span class="meta">${n}</span>`:''}</button>`).join('')}</div></div>${gymTab==='ex'?recs:hist}</section>`;
 return (exSel?exDetail():'')+(RE?reEditor():wkSel?wkEditor():start)+`<div class="hlgrid">${log}${muscleWeek()}</div>${workoutCal()}`}
/* ----- Meditation: one Markdown file per day, health/meditation/YYYY-MM-DD.md, one line per session:
   "- 07:30 · 10 min · timer" (timer = logged by the built-in timer, manual = added by hand).
   A habit with "Count meditation" is ticked on days with a session (a number habit gets the day's minutes). */
const medKey=d=>`health/meditation/${d}.md`;
const medDays=()=>Object.keys(FS).filter(k=>/^health\/meditation\/\d{4}-\d{2}-\d{2}\.md$/.test(k)).map(k=>k.slice(18,28)).filter(d=>medRead(d).length).sort().reverse();
function medRead(d){const k=medKey(d);if(!FS[k])return[];const out=[];
 for(const l of readNote(FS[k]).body.split('\n')){const m=l.match(/^-\s*(?:(\d{1,2}:\d{2})\s*·\s*)?([\d.,]+)\s*min(?:\s*·\s*(\w+))?/i);if(m)out.push({t:m[1]||'',min:parseFloat(m[2].replace(',','.'))||0,src:(m[3]||'manual').toLowerCase()})}
 return out}
function medWrite(d,list){const k=medKey(d);list=list.filter(x=>x.min>0).sort((a,b)=>(a.t||'99').localeCompare(b.t||'99'));
 if(!list.length)delete FS[k];else FS[k]=writeNote({fm:{date:d},body:list.map(x=>`- ${x.t?x.t+' · ':''}${+x.min.toFixed(1)} min · ${x.src}`).join('\n')+'\n'});medSync(d)}
const medAdd=(d,min,t,src)=>{medWrite(d,[...medRead(d),{t:t||'',min:Math.round(min*10)/10,src}])};
const medTotal=d=>Math.round(medRead(d).reduce((a,x)=>a+x.min,0)*10)/10;
const medHabit=()=>habits().find(h=>h.meditation)||null;
function medSync(d){const h=medHabit();if(!h||d>TD())return;const m=medTotal(d);
 if(h.kind==='number'){if(m>0)h.log[d]=String(m);else delete h.log[d]}else if(m>0)h.log[d]='yes';else if(h.log[d]==='yes')delete h.log[d];putH(h)}
// Days in a row with a session, counting back from today (or from yesterday when today has none yet).
function medStreak(){const t=TD();let d=medTotal(t)>0?t:dAdd(t,-1),n=0;while(medTotal(d)>0){n++;d=dAdd(d,-1)}return n}
const medFmt=m=>m>=60?`${Math.floor(m/60)} h${m%60?' '+Math.round(m%60)+' min':''}`:`${+(+m).toFixed(1)} min`;

// ----- timer: MT keeps running while you use the rest of the app; the clock updates in place (no re-render).
const MPRE=[5,10,15,20,30,45,60];
/* Full-screen meditation: only the time, over slow blurred green and yellow light. Controls show when the mouse moves;
   Esc or Minimize keeps the timer running in the background. */
let MEDFS=false,medFsT=null;
function medFsShow(){let o=$('medfs');if(!MEDFS){if(o)o.remove();document.body.classList.remove('medfs-on');return}
 if(!o){o=document.createElement('div');o.id='medfs';o.className='medfs';o.setAttribute('role','dialog');o.setAttribute('aria-label','Meditation');document.body.appendChild(o);
  o.innerHTML=`<div class="mfbg" aria-hidden="true"><i class="b1"></i><i class="b2"></i><i class="b3"></i><i class="b4"></i><i class="b5"></i></div>
<div class="mfcenter"><div id="medfsclock" class="mfclock" aria-live="off"></div><p class="mfhint">Breathe in… and out</p></div>
<div class="mfctl"><button class="mfbtn" data-act="medFsPause" aria-label="Pause or resume" title="Pause / resume (Space)"><span class="mfpause">${lineIco('M8 5v14M16 5v14')}</span><span class="mfplay">${lineIco('M8 5.5v13l10.5-6.5z')}</span></button><button class="mfbtn" data-act="medFsEnd" title="End and log the session">${lineIco('M5 12.5l4.5 4.5L19 7')}<span>End</span></button><button class="mfbtn" data-act="medFsMin" title="Minimize (Esc) · the timer keeps running">${lineIco('M6 6l12 12M18 6L6 18')}</button></div>`;
  o.addEventListener('pointermove',()=>{o.classList.add('show');clearTimeout(medFsT);medFsT=setTimeout(()=>o.classList.remove('show'),2500)})}
 document.body.classList.add('medfs-on');medPaint()}
document.addEventListener('keydown',e=>{if(!MEDFS)return;if(e.key==='Escape'){e.preventDefault();MEDFS=false;medFsShow();render()}else if(e.key===' '){e.preventDefault();MT.run?medPause():medStartT()}},true);
let MT={dur:(+CFG.medDur||10)*60,left:(+CFG.medDur||10)*60,run:false,end:0,start:'',timer:null};
let medAud=null;
// A soft singing-bowl tone: low fundamental, quiet inharmonic overtones, slow swell and a long fade.
function medBell(){try{medAud=medAud||new (window.AudioContext||window.webkitAudioContext)();const a=medAud,t0=a.currentTime+0.05,len=9;
 const out=a.createGain(),lp=a.createBiquadFilter();lp.type='lowpass';lp.frequency.setValueAtTime(1800,t0);lp.frequency.exponentialRampToValueAtTime(500,t0+len);lp.Q.value=0.3;out.gain.value=0.5;lp.connect(out).connect(a.destination);
 // Echo tail for a roomy feel.
 const dl=a.createDelay(1),fb=a.createGain(),wet=a.createGain();dl.delayTime.value=0.23;fb.gain.value=0.35;wet.gain.value=0.25;lp.connect(dl);dl.connect(fb).connect(dl);dl.connect(wet).connect(out);
 const f0=196;[[1,0.16,len],[1.006,0.08,len],[2.76,0.035,len*0.6],[5.4,0.012,len*0.35]].forEach(([r,v,d])=>{const o=a.createOscillator(),g=a.createGain();o.type='sine';o.frequency.value=f0*r;
  g.gain.setValueAtTime(0.0001,t0);g.gain.linearRampToValueAtTime(v,t0+0.12);g.gain.exponentialRampToValueAtTime(0.0001,t0+d);o.connect(g).connect(lp);o.start(t0);o.stop(t0+d+0.1)})}catch(e){}}
const mClock=s=>{s=Math.max(0,Math.ceil(s));return `${Math.floor(s/60)}:${pad(s%60)}`};
function medPaint(){const c=$('medclock'),r=$('medring'),fc=$('medfsclock');if(c)c.textContent=mClock(MT.left);if(fc){fc.textContent=mClock(MT.left);const o=$('medfs');if(o)o.classList.toggle('paused',!MT.run)}if(r){const p=MT.dur?1-MT.left/MT.dur:0;r.style.strokeDashoffset=String(Math.round(603*(1-p)*10)/10)}
 document.querySelectorAll('[data-medrun]').forEach(x=>x.hidden=x.dataset.medrun!==(MT.run?'1':'0'))}
function medTick(){if(!MT.run)return;MT.left=(MT.end-Date.now())/1000;if(MT.left<=0){medDone(true);return}medPaint()}
function medStartT(){if(MT.run)return;if(MT.left<=0)MT.left=MT.dur;if(!MT.start)MT.start=hm(':');MT.run=true;MT.end=Date.now()+MT.left*1000;clearInterval(MT.timer);MT.timer=setInterval(medTick,250);
 if(MT.left===MT.dur)medBell();medPaint()}
function medPause(){if(!MT.run)return;MT.left=Math.max(0,(MT.end-Date.now())/1000);MT.run=false;clearInterval(MT.timer);medPaint()}
// Ends the session: logs the time actually meditated (a full session, or at least a minute when finished early).
function medDone(full){clearInterval(MT.timer);const sec=full?MT.dur:MT.dur-Math.max(0,MT.run?(MT.end-Date.now())/1000:MT.left),min=Math.round(sec/60*10)/10,t=MT.start;
 MT={...MT,left:MT.dur,run:false,start:'',timer:null};
 if(min>=1){medAdd(TD(),full?MT.dur/60:Math.round(min),t,'timer');save();toast(`Meditation logged: ${medFmt(full?MT.dur/60:Math.round(min))}`);if(full){medBell();nAdd('Meditation complete',`${medFmt(MT.dur/60)} logged`,{ico:'flower-lotus',go:{view:'health'}});if(CFG.intNotif&&document.hidden)try{notifyOS('Meditation complete',`${medFmt(MT.dur/60)} logged`)}catch(e){}}}
 else if(!full)toast('Less than a minute, not logged');
 MEDFS=false;medFsShow();if(['health','today','habits','home'].includes(view))render();else medPaint()}
function medReset(){clearInterval(MT.timer);MT={...MT,left:MT.dur,run:false,start:'',timer:null};medPaint()}
function medSetDur(m){if(MT.run||MT.left<MT.dur)return;m=Math.max(1,Math.min(240,Math.round(m)));MT.dur=MT.left=m*60;CFG.medDur=m;saveCfg()}

// ----- views
function hlMed(){const t=TD(),ws=weekStart(t),days=medDays(),wk=days.filter(d=>d>=ws),wkMin=wk.reduce((a,d)=>a+medTotal(d),0),today=medTotal(t),mh=medHabit(),paused=!MT.run&&MT.left<MT.dur,cur=MT.dur/60;
 const timer=`<section class="medtimer"><h2>Timer</h2><div class="medwrap"><div class="medface"><svg viewBox="0 0 220 220" aria-hidden="true"><circle cx="110" cy="110" r="96" class="medtrack"/><circle id="medring" cx="110" cy="110" r="96" class="medprog" style="stroke-dashoffset:${Math.round(603*(MT.left/MT.dur)*10)/10}"/></svg>
<div class="medmid"><span id="medclock" class="medclock" aria-live="off">${mClock(MT.left)}</span><span class="meta">${MT.run?'Breathe':paused?'Paused':medFmt(cur)}</span></div></div>
<div class="medside"><p class="meta lab0">Length</p><div class="moods seg medpre">${MPRE.map(m=>`<button data-act="hl:mdur" data-val="${m}" class="${cur===m?'on':''}" ${MT.run||paused?'disabled':''} aria-pressed="${cur===m}">${m} min</button>`).join('')}</div>
<div class="row" style="margin:10px 0 0"><label class="meta lab" style="flex:0 1 220px;min-width:0">Custom <input id="medcustom" type="number" min="1" max="240" inputmode="numeric" placeholder="min" value="${MPRE.includes(cur)?'':cur}" ${MT.run||paused?'disabled':''} style="min-width:0"></label></div>
<div class="row medbtns"><span data-medrun="0" ${MT.run?'hidden':''}><button class="b" data-act="hl:mstart">${sym('play')}${paused?'Resume':'Start'}</button></span><span data-medrun="1" ${MT.run?'':'hidden'}><button class="b" data-act="hl:mpause">${sym('pause')}Pause</button></span>
${MT.run||paused?`<button class="g" data-act="hl:mfinish" title="End now and log the time so far">${sym('check')}Finish</button><button class="x" data-act="hl:mreset" title="Discard this session">${sym('arrow-counter-clockwise')}Reset</button>`:''}</div>
<p class="meta" style="margin:10px 0 0">A bell sounds at the start and the end. Finished sessions are logged automatically; Finish logs the time so far.</p></div></div></section>`;
 const stats=`<section><h2>Progress</h2><div class="stats medstats"><div><b>${medFmt(today)}</b><span class="meta">Today</span></div><div><b>${medFmt(wkMin)}</b><span class="meta">This week · ${wk.length} day${wk.length===1?'':'s'}</span></div><div><b>${medStreak()}</b><span class="meta">Day streak</span></div><div><b>${days.length}</b><span class="meta">Days in total</span></div></div>
${hlHabitTip('meditation')}</section>`;
 const ds=[...Array(14)].map((_,i)=>dAdd(t,i-13)),mv=ds.map(medTotal),mx=Math.max(10,...mv);
 const bars=`<section><h2>Last 14 days</h2><div class="mbars medbars">${ds.map((d,i)=>`<span title="${fmt(d)} · ${mv[i]?medFmt(mv[i]):'no session'}"><i style="height:${Math.round(mv[i]/mx*100)}%;background:${mv[i]?'var(--ac)':'var(--line)'}"></i><em>${DN[pd(d).getDay()][0]}</em></span>`).join('')}</div></section>`;
 const add=`<section><h2>Log by hand</h2><div class="row" style="margin:0;align-items:flex-end"><label class="meta lab" style="flex:1 1 150px">Date <input id="mdate" type="date" value="${t}" max="${t}"></label><label class="meta lab" style="flex:1 1 110px">Minutes <input id="mmin" type="number" min="1" step="any" inputmode="decimal" placeholder="10"></label><label class="meta lab" style="flex:1 1 120px">Time ${timeField('mtime','','Time (optional)')}</label><button class="b" data-act="hl:madd">Add session</button></div></section>`;
 const hist=`<section><h2>History</h2>${days.slice(0,30).map(d=>`<div class="medday"><div class="head" style="margin:0 0 4px"><b>${fmt(d,LONG)}</b><span class="meta">${medFmt(medTotal(d))}</span></div>${medRead(d).map((x,i)=>`<div class="medrow"><span>${x.t?esc(tf(x.t)):'—'}</span><span>${medFmt(x.min)}</span><span class="meta">${x.src==='timer'?'Timer':'By hand'}</span><button class="cx" data-act="hl:mdel" data-val="${d}" data-i="${i}" aria-label="Delete this session">×</button></div>`).join('')}</div>`).join('')||'<p class="empty">No sessions yet. Start the timer or log one by hand.</p>'}</section>`;
 return timer+`<div class="hlgrid">${stats}${bars}</div>${add}${hist}`}
/* Body: weight (kg), sleep (hours) and water (glasses) per day in health/body.md: "- 2026-10-23: weight 72.5 · sleep 7.5 · water 6". */
const BODYF=[['weight','Weight','kg','#4a8fd9'],['sleep','Sleep','h','#8a7fd0'],['water','Water','glasses','#3f9aa5']];
const bodyRead=()=>(FS['health/body.md']||'').split('\n').map(l=>l.match(/^- (\d{4}-\d{2}-\d{2}): (.+)$/)).filter(Boolean).map(m=>{const o={d:m[1]};m[2].split('·').forEach(p=>{const x=p.trim().match(/^(weight|sleep|water) ([\d.,]+)/);if(x)o[x[1]]=parseFloat(x[2].replace(',','.'))});return o}).sort((a,b)=>a.d.localeCompare(b.d));
const bodyWrite=l=>{FS['health/body.md']='# Body\n\n'+l.slice().sort((a,b)=>a.d.localeCompare(b.d)).map(o=>`- ${o.d}: ${BODYF.filter(([k])=>o[k]!=null&&!isNaN(o[k])).map(([k])=>`${k} ${+o[k].toFixed(2)}`).join(' · ')}`).filter(l=>!/: $/.test(l)).join('\n')+'\n'};
function spark(vals,col,w=260,h=60){const v=vals.filter(x=>x!=null);if(v.length<2)return '<p class="meta" style="margin:6px 0 0">Log at least two days to see a chart.</p>';
 const lo=Math.min(...v),hi=Math.max(...v),rg=hi-lo||1,pts=vals.map((x,i)=>x==null?null:[i/(vals.length-1)*(w-8)+4,h-4-(x-lo)/rg*(h-8)]).filter(Boolean);
 return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ')}" fill="none" stroke="${col}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>${pts.length?`<circle cx="${pts[pts.length-1][0]}" cy="${pts[pts.length-1][1]}" r="4" fill="${col}"/>`:''}</svg>`}
function hlBody(){const l=bodyRead(),t=TD(),today=l.find(x=>x.d===t)||{},days=[...Array(30)].map((_,i)=>dAdd(t,i-29)),by=Object.fromEntries(l.map(x=>[x.d,x]));
 const card=([k,lab,u,col])=>{const vals=days.map(d=>by[d]&&by[d][k]!=null?by[d][k]:null),got=vals.filter(x=>x!=null),last=[...l].reverse().find(x=>x[k]!=null),avg=got.length?got.reduce((a,b)=>a+b,0)/got.length:null,first=l.find(x=>x[k]!=null&&x.d>=days[0]);
  const ch=last&&first&&first!==last?last[k]-first[k]:null;
  return `<section class="bodycard" style="--bc:${col}"><div class="head" style="margin:0 0 4px"><h2 style="margin:0">${lab}</h2><span class="meta">last 30 days</span></div><div class="row" style="margin:0;align-items:baseline;gap:8px"><b class="bodyv">${last?+last[k].toFixed(1):'–'}</b><span class="meta">${u}${avg!=null?` · avg ${+avg.toFixed(1)}`:''}${ch?` · ${ch>0?'+':''}${+ch.toFixed(1)} since ${fmt(first.d,{month:'short',day:'numeric'})}`:''}</span></div>${spark(vals,col)}</section>`};
 return `<section class="bodylog"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">Log today</h2><span class="meta">${fmt(t,LONG)}</span></div><div class="bodyin">${BODYF.map(([k,lab,u])=>`<label class="meta lab">${lab} (${u})<input id="body-${k}" type="number" step="${k==='water'?1:.1}" min="0" value="${today[k]!=null?today[k]:''}" placeholder="${k==='weight'?'72.5':k==='sleep'?'7.5':'8'}"></label>`).join('')}<button class="b tick" data-act="hl:bodySave" aria-label="Save" title="Save">${lineIco('M5 12.5l4.5 4.5L19 7')}</button></div></section>
<div class="hlgrid bodygrid">${BODYF.map(card).join('')}</div>
${l.length?`<section><h2>Recent</h2>${[...l].reverse().slice(0,14).map(x=>`<div class="hlrow static"><span class="t"><b>${fmt(x.d,LONG)}</b></span><span class="meta">${BODYF.filter(([k])=>x[k]!=null).map(([k,lab,u])=>`${lab} ${+x[k].toFixed(1)} ${u}`).join(' · ')}</span></div>`).join('')}</section>`:''}`}
/* Workout calendar: a month with the days you trained, colored by the main muscle groups worked, plus the month's sets per group. */
let wcal=null;
const MGRP={chest:'Chest',shoulders:'Shoulders',triceps:'Arms',biceps:'Arms',forearms:'Arms',lats:'Back','middle back':'Back','lower back':'Back',traps:'Back',quadriceps:'Legs',hamstrings:'Legs',glutes:'Legs',calves:'Legs',adductors:'Legs',abductors:'Legs',abdominals:'Core',cardio:'Cardio'};
const MGCOL={Chest:'#e0566f',Shoulders:'#e08a3f',Arms:'#d4a43a',Back:'#4a8fd9',Legs:'#5fa57f',Core:'#9a7fd0',Cardio:'#3f9aa5',Other:'#7a8794'};
const wkGroups=w=>{const g={};(w.ex||[]).forEach(e=>{const n=e.sets.filter(s=>setFilled(e,s)&&s.t!=='w').length||1;if(e.kind==='cardio'){g.Cardio=(g.Cardio||0)+n;return}const c=exFind(e.name),ms=c&&(c.m||[]).length?c.m:[];if(!ms.length){g.Other=(g.Other||0)+n;return}[...new Set(ms.map(m=>MGRP[m]||'Other'))].forEach(x=>g[x]=(g[x]||0)+n)});return g};
function workoutCal(){const t=TD(),mo=wcal||t.slice(0,7),y=+mo.slice(0,4),m=+mo.slice(5,7)-1,first=new Date(y,m,1),n=new Date(y,m+1,0).getDate(),off=(first.getDay()-CFG.week+7)%7,tot={};let c=[0,1,2,3,4,5,6].map(j=>`<i class="wch">${DN[(CFG.week+j)%7][0]}</i>`).join('');
 for(let i=0;i<off;i++)c+='<span></span>';let cnt=0;
 for(let d=1;d<=n;d++){const ds=`${y}-${pad(m+1)}-${pad(d)}`,w=wkRead(ds),g=w&&w.ex.length?wkGroups(w):null;if(g){cnt++;Object.entries(g).forEach(([k,v])=>tot[k]=(tot[k]||0)+v)}
  c+=g?`<button class="wcd on ${ds===t?'td':''}" data-act="hl:open" data-val="${ds}" title="${fmt(ds)} · ${Object.keys(g).join(', ')}"><span>${d}</span><em>${Object.keys(g).slice(0,4).map(k=>`<i style="background:${MGCOL[k]}"></i>`).join('')}</em></button>`:`<span class="wcd ${ds===t?'td':''}"><span>${d}</span></span>`}
 const mx=Math.max(1,...Object.values(tot));
 return `<section class="wcal"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">${first.toLocaleDateString(LOC(),{month:'long',year:'numeric'})} <span class="meta">${cnt} workout${cnt===1?'':'s'}</span></h2><span class="row" style="margin:0;gap:4px"><button class="cx rbtn" data-act="hl:wcal" data-val="-1" aria-label="Previous month">${lineIco('M15 5l-7 7 7 7')}</button><button class="cx rbtn" data-act="hl:wcal" data-val="1" aria-label="Next month">${lineIco('M9 5l7 7-7 7')}</button></span></div>
<div class="wcgrid">${c}</div>${Object.keys(tot).length?`<div class="wcbars">${Object.entries(tot).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<div class="musrow"><span><i class="wcdot" style="background:${MGCOL[k]}"></i>${k}</span><i><b style="width:${Math.round(v/mx*100)}%;background:${MGCOL[k]}"></b></i><em>${v}</em></div>`).join('')}</div><p class="meta" style="margin:6px 0 0">Sets per muscle group this month. Compare months to spot imbalances.</p>`:''}</section>`}
V.health=()=>`<h1>Health</h1>${healthTiles()}${hv==='gym'?hlGym():hv==='meditation'?hlMed():hv==='body'?hlBody():hlOverview()}`;
function hlAct(a,b){const v=b.dataset.val,i=+b.dataset.i,j=+b.dataset.j;if(WK&&wkTimer)wkSave();
 if(a!=='wkdel'&&a!=='rtdel')armed=null;
 if(a==='view'){hv=v;if(v!=='gym'){wkSel=null;WK=null;exSel=null}}
 else if(a==='start'){view='health';hv='gym';RE=null;newWorkout(TD(),v?routines().find(r=>r.name===v):null,b.dataset.day!=null?+b.dataset.day:null);window.scrollTo(0,0)}
 else if(a==='gtab')gymTab=v
 else if(a==='wcal'){const base=wcal||TD().slice(0,7),d=new Date(+base.slice(0,4),+base.slice(5,7)-1+(+v),1);wcal=`${d.getFullYear()}-${pad(d.getMonth()+1)}`}
 else if(a==='bodySave'){const l=bodyRead().filter(x=>x.d!==TD()),o={d:TD()};BODYF.forEach(([k])=>{const x=parseFloat((($('body-'+k)||{}).value||'').replace(',','.'));if(!isNaN(x))o[k]=x});if(Object.keys(o).length<2){toast('Enter at least one value');return}bodyWrite([...l,o]);toast('Saved for today')}
 else if(a==='setok'){const w=wkDraft(),e=w&&w.ex[i],st=e&&e.sets[j];if(!st)return;st.ok=!st.ok;if(st.ok&&!setFilled(e,st)&&e.kind!=='cardio'){const pl=wkPlan(w,e.name);if(pl&&pl.reps)st.reps=String(pl.reps).split('-')[0]}
  const was=e.done;e.done=e.sets.every(x=>x.ok);wkWrite(w);if(st.ok&&!e.done)restStart(+(CFG.rest??90));else if(e.done&&!was){REST=null;restShow();toast(w.ex.every(x=>x.done)?'Workout complete 💪':`${e.name} done`)}}
 else if(a==='settype'){const w=wkDraft(),st=w&&w.ex[i]&&w.ex[i].sets[j];if(!st)return;st.t=!st.t?'w':st.t==='w'?'d':undefined;if(!st.t)delete st.t;wkWrite(w)}
 else if(a==='rest'){CFG.rest=+v;saveCfg()}
 else if(a==='restadd'){if(REST){REST.end+=15000;REST.total+=15;restShow()}return}
 else if(a==='restskip'){REST=null;restShow();return}
 else if(a==='exm')exMetric=v
 else if(a==='exdone'){const w=wkDraft(),e=w&&w.ex[i];if(!e)return;e.done=!e.done;e.sets.forEach(x=>{if(setFilled(e,x))x.ok=e.done});wkWrite(w);if(e.done&&w.ex.every(x=>x.done))toast('Workout complete 💪')}
 else if(a==='rtnew'){RE={k:null,name:'',days:[{name:'Day 1',ex:[{name:'',sets:'3',reps:'10'}]}]};wkSel=null;WK=null;pendingFocus='#rename';window.scrollTo(0,0)}
 else if(a==='rtedit'){const r=routines().find(x=>x.k===v);if(r){RE=JSON.parse(JSON.stringify({k:r.k,name:r.name,days:r.days.length?r.days:[{name:'Day 1',ex:[]}]}));wkSel=null;WK=null;window.scrollTo(0,0)}}
 else if(a==='recancel')RE=null
 else if(a==='redayadd'){RE.days.push({name:'Day '+(RE.days.length+1),ex:[{name:'',sets:'3',reps:'10'}]});pendingFocus=`[data-re="${RE.days.length-1}"]`}
 else if(a==='redaydel'){RE.days.splice(i,1);if(!RE.days.length)RE.days.push({name:'Day 1',ex:[]})}
 else if(a==='redayup'){if(i>0)[RE.days[i-1],RE.days[i]]=[RE.days[i],RE.days[i-1]]}
 else if(a==='reexadd'){const l=RE.days[i].ex,p=l[l.length-1];l.push({name:'',sets:p?p.sets:'3',reps:p?p.reps:'10'});pendingFocus=`[data-re="${i}.${l.length-1}.name"]`}
 else if(a==='reexdel'){RE.days[i].ex.splice(j,1)}
 else if(a==='resave'){const name=safeName(RE.name.trim()||'');if(!RE.name.trim()){toast('Give the routine a name');pendingFocus='#rename';render();const el=$('rename');if(el)el.focus();pendingFocus=null;return}
  if(rtKey(name)!==RE.k&&FS[rtKey(name)]){toast('A routine with that name already exists');return}
  const days=RE.days.map((d,x)=>({name:d.name.trim()||'Day '+(x+1),ex:d.ex.filter(e=>e.name.trim())}));
  if(RE.k&&RE.k!==rtKey(name)){const old=RE.k.slice(16,-3);delete FS[RE.k];workouts().forEach(d=>{const w=wkRead(d);if(w&&w.routine===old){w.routine=name;wkWrite(w)}})}
  rtWrite({name,days});RE=null;toast('Routine saved')}
 else if(a==='open'){hv='gym';wkSel=v;WK=null;window.scrollTo(0,0)}
 else if(a==='mdur')medSetDur(+v)
 else if(a==='mstart')medStartT()
 else if(a==='mpause'){medPause();render();return}
 else if(a==='mfinish'){medDone(false);return}
 else if(a==='mreset')medReset()
 else if(a==='madd'){const d=($('mdate')||{}).value||TD(),mn=parseFloat((($('mmin')||{}).value||'').replace(',','.')),tm=($('mtime')||{}).value||'';if(!(mn>0)){toast('Enter the minutes');return}if(d>TD()){toast('That date is in the future');return}medAdd(d,mn,tm,'manual');toast(`Logged ${medFmt(mn)}`)}
 else if(a==='mdel'){const l=medRead(v);l.splice(i,1);medWrite(v,l)}
 else if(a==='close'){wkSel=null;WK=null}
 else if(a==='ex'){hv='gym';exSel=v;window.scrollTo(0,0);const m=$('main');if(m)m.scrollTop=0}
 else if(a==='exclose')exSel=null
 else if(a==='exunlink'){const l={...(CFG.exLink||{})};delete l[fold(exSel)];CFG.exLink=l;saveCfg();exReset()}
 else if(a==='link'){openLink(v);return}
 else if(a==='exadd'){const n=(($('wkex')||{}).value||'').trim();if(!n)return;const w=wkDraft(),p=lastSets(n,w.d);w.ex.push({name:n,kind:p?p.kind:isCardio(n)?'cardio':'strength',sets:p?p.sets.map(s=>({...s})):[isCardio(n)?{km:'',min:''}:{kg:'',reps:''}]});wkWrite(w);pendingFocus='#wkex'}
 else if(a==='exdel'){const w=wkDraft();w.ex.splice(i,1);wkWrite(w)}
 else if(a==='kind'){const w=wkDraft(),e=w.ex[i];e.kind=e.kind==='cardio'?'strength':'cardio';e.sets=[e.kind==='cardio'?{km:'',min:''}:{kg:'',reps:''}];wkWrite(w)}
 else if(a==='setadd'){const w=wkDraft(),e=w.ex[i],l=e.sets[e.sets.length-1];e.sets.push(l?{...l}:e.kind==='cardio'?{km:'',min:''}:{kg:'',reps:''});wkWrite(w)}
 else if(a==='setdel'){const w=wkDraft();w.ex[i].sets.splice(j,1);wkWrite(w)}
 else if(a==='wkdel'){const d=wkSel;if(armed!=='wk:'+d){armed='wk:'+d;render();return}delete FS[wkKey(d)];syncGym(d);wkSel=null;WK=null;armed=null;toast('Workout deleted')}
 else if(a==='saveRoutine'){const w=wkDraft(),name=(w.routine||'').trim()||'Routine '+(routines().length+1);rtWrite({name,days:[{name:'Day 1',ex:w.ex.map(e=>({name:e.name,sets:e.kind==='cardio'?'':String(e.sets.length),reps:e.kind==='cardio'?'':(e.sets[0]||{}).reps||''}))}]});if(!w.routine){w.routine=name;wkWrite(w)}toast('Routine saved')}
 else if(a==='rtadd'){const name=(($('rtname')||{}).value||'').trim(),ex=(($('rtex')||{}).value||'').split(',').map(x=>x.trim()).filter(Boolean);if(!name)return;FS[`health/routines/${safeName(name)}.md`]=`# ${name}\n\n`+ex.map(e=>`## ${e}\n`).join('\n');toast('Routine created')}
 else if(a==='rtdel'){if(armed!=='rt:'+v){armed='rt:'+v;render();return}delete FS[`health/routines/${safeName(v)}.md`];armed=null;if(RE&&RE.k===rtKey(v))RE=null}
 save();render();if(pendingFocus){const el=document.querySelector(pendingFocus);pendingFocus=null;if(el)el.focus()}}
// Typing in a workout: set values and fields save after a short pause (no re-render, so the caret stays put).
document.addEventListener('input',e=>{const t=e.target,ds=t.dataset||{};
 if(ds.wk){const[i,j,f]=ds.wk.split('.'),w=wkDraft();if(w&&w.ex[+i]&&w.ex[+i].sets[+j]){w.ex[+i].sets[+j][f]=t.value.replace(',','.');wkSoon()}return}
 if(ds.wkf){const w=wkDraft();if(w){w[ds.wkf]=t.value;wkSoon()}return}
 if(ds.re!==undefined&&RE)reInput(t)});
// The routine editor keeps RE in memory while typing: data-re is "name", "<day>" (day name) or "<day>.<exercise>.<field>".
function reInput(t){const p=t.dataset.re.split('.');if(p[0]==='name')RE.name=t.value;else if(p.length===1){if(RE.days[+p[0]])RE.days[+p[0]].name=t.value}else{const e=RE.days[+p[0]]&&RE.days[+p[0]].ex[+p[1]];if(e)e[p[2]]=t.value.trim()&&p[2]!=='name'?t.value.replace(/[^\d-]/g,''):t.value}}
document.addEventListener('keydown',e=>{if(e.key!=='Enter')return;if(e.target.id==='wkex'){e.preventDefault();const b=document.querySelector('[data-act="hl:exadd"]');if(b)b.click()}else if(e.target.id==='rtex'||e.target.id==='rtname'){e.preventDefault();const b=document.querySelector('[data-act="hl:rtadd"]');if(b)b.click()}
 else if(e.target.dataset&&/^\d+\.\d+\.\w+$/.test(e.target.dataset.re||'')&&!(exsBox&&exsAct>=0)){e.preventDefault();exsHide();const b=document.querySelector(`[data-act="hl:reexadd"][data-i="${e.target.dataset.re.split('.')[0]}"]`);if(b)b.click()}});
window.addEventListener('blur',()=>{if(wkTimer)wkSave()});

/* ----- Exercise catalog: EXDB (exercises.js, offline, English + Spanish) and a live wger search for anything missing.
   Names can be typed in either language: Spanish words are also translated to English terms before matching.
   CFG.exExtra keeps wger exercises picked from the live search; CFG.exLink maps a logged name to a catalog id. */
const ESD=[['press de banca','bench press'],['press banca','bench press'],['peso muerto','deadlift'],['elevaciones laterales','lateral raise'],['elevacion lateral','lateral raise'],['curl femoral','leg curl'],['extension de rodilla','leg extension'],['extension de cuadriceps','leg extension'],['empuje de cadera','hip thrust'],['press frances','skullcrusher'],['press militar','military press'],['jalon al pecho','lat pull down'],['rueda abdominal','ab roller'],['de pie','standing'],['peso corporal','bodyweight'],
 ['sentadillas','squat'],['sentadilla','squat'],['remo','row'],['jalon','pulldown'],['mancuernas','dumbbell'],['mancuerna','dumbbell'],['barra','barbell'],['polea','cable'],['zancadas','lunge'],['zancada','lunge'],['dominadas','pull up'],['dominada','pull up'],['fondos','dips'],['gemelos','calf'],['gemelo','calf'],['prensa','leg press'],['aperturas','fly'],['apertura','fly'],['inclinado','incline'],['inclinadas','incline'],['declinado','decline'],['hombro','shoulder'],['hombros','shoulder'],['pecho','chest'],['espalda','back'],
 ['abdominales','crunch'],['plancha','plank'],['correr','running'],['carrera','running'],['bicicleta','cycling'],['natacion','swimming'],['nadar','swimming'],['caminar','walking'],['comba','jump rope'],['martillo','hammer'],['puente','bridge'],['cuerda','rope'],['sentado','seated'],['agarre','grip'],['cerrado','close'],['ancho','wide'],['inverso','reverse'],['frontal','front'],['maquina','machine'],['flexiones','push up'],['predicador','preacher curl'],['unilateral','one arm'],['oblicuo','oblique'],['bulgara','bulgarian split'],['rumano','romanian'],['piernas','leg'],['pierna','leg']].sort((a,b)=>b[0].length-a[0].length);
const EXSTOP=new Set(['de','del','con','en','a','al','la','el','los','las','y','o','por','the','with','on','of','and','in']);
const EXMUS={Shoulders:'shoulders',Glutes:'glutes',Abs:'abdominals',Lats:'lats',Quads:'quadriceps',Triceps:'triceps',Biceps:'biceps',Chest:'chest',Trapezius:'traps',Hamstrings:'hamstrings','Obliquus externus abdominis':'abdominals',Calves:'calves',Brachialis:'biceps','Serratus anterior':'chest',Soleus:'calves'};
const exClean=s=>' '+fold(s).replace(/[^a-z0-9]+/g,' ').trim()+' ';
const exToks=s=>exClean(s).trim().split(' ').filter(w=>w&&!EXSTOP.has(w));
const exTr=s=>{let f=exClean(s);for(const[a,b]of ESD)f=f.split(' '+a+' ').join(' '+b+' ');return f.trim()};
let EXI=null,EXID=null;
// Search index: every catalog entry with its folded names (rebuilt when a live wger exercise is kept).
function exIndex(){if(EXI)return EXI;EXI=EXDB.concat(CFG.exExtra||[]).map(e=>({e,en:exClean(e.en).trim(),es:e.es?exClean(e.es).trim():''}));EXID={};EXI.forEach(x=>String(x.e.i).split('|').forEach(i=>EXID[i]=x.e));return EXI}
// How well a folded name matches the query words; 0 unless at least `need` of them are found.
const exSg=w=>w.length>3&&w.endsWith('s')&&!w.endsWith('ss')?w.slice(0,-1):w;
function exScore(n,qt,need){if(!n||!qt.length)return 0;const ws=n.split(' ').filter(w=>!EXSTOP.has(w)).map(exSg);n=ws.join(' ');qt=qt.map(exSg);let s=0,hit=0;
 for(const t of qt){if(ws.includes(t)){s+=10;hit++}else if(ws.some(w=>w.startsWith(t))){s+=7;hit++}else if(t.length>3&&n.includes(t)){s+=3;hit++}}
 if(hit<need(qt.length))return 0;const q=qt.join(' ');if(n===q)s+=40;else if(n.startsWith(q))s+=15;return s-ws.length*.6}
const ALLW=k=>k,MOSTW=k=>Math.max(1,Math.ceil(k*.6));
// Catalog matches for what was typed: [{name, e, es}] where es says the Spanish name matched better.
function exMatch(q,lim,need=ALLW){const qt=exToks(q),tt=exToks(exTr(q)).filter(Boolean),out=[];if(!qt.length)return out;
 for(const x of exIndex()){const a=exScore(x.es,qt,need),b=Math.max(exScore(x.en,qt,need),exScore(x.en,tt,need)*.9),s=Math.max(a,b);if(s>0)out.push({e:x.e,s:s+(x.e.es?.5:0),es:a>0&&!!x.e.es})}
 return out.sort((p,q)=>q.s-p.s).slice(0,lim).map(r=>({...r,name:r.es?r.e.es:r.e.en}))}
// Suggestions while typing: your own exercises first, then the catalog.
function exSearch(q,lim=8){const f=exClean(q).trim(),own=exStats().filter(s=>exClean(s.name).includes(' '+f)||exClean(s.name).trim().startsWith(f)).slice(0,3).map(s=>({name:s.name,own:true,e:exFind(s.name)}));
 const seen=new Set(own.map(o=>fold(o.name))),out=[...own];for(const r of exMatch(q,lim+4)){if(out.length>=lim)break;if(seen.has(fold(r.name)))continue;seen.add(fold(r.name));out.push(r)}return out}
// The catalog entry for a logged exercise name ("A / B" tries A first), or null.
const EXF={};
function exFind(name){const key=fold(name);if(key in EXF)return EXF[key];exIndex();let r=null;const ln=(CFG.exLink||{})[key];
 if(ln)r=EXID[ln]||null;
 if(!r)for(const part of String(name).split('/').map(s=>s.trim()).filter(Boolean)){const c=exClean(part).trim(),x=EXI.find(x=>x.en===c||x.es===c);if(x){r=x.e;break}const m=exMatch(part,1,MOSTW)[0];if(m){r=m.e;break}}
 return EXF[key]=r}
const exReset=()=>{EXI=null;for(const k in EXF)delete EXF[k]};
const exImg=e=>!e||!e.img?'':e.img.startsWith('f:')?'https://raw.githubusercontent.com/yuhonas/free-exercise-db/main/exercises/'+e.img.slice(2):e.img;
const exCap=s=>s?s[0].toUpperCase()+s.slice(1):'';
function wgerEntry(x){const tr={};(x.translations||[]).forEach(t=>tr[t.language]=t);if(!tr[2])return null;const mn=y=>EXMUS[y.name_en||y.name]||(y.name_en||y.name).toLowerCase();
 const m=[...new Set((x.muscles||[]).map(mn))],m2=[...new Set((x.muscles_secondary||[]).map(mn))].filter(y=>!m.includes(y)),img=(x.images||[]).find(i=>i.is_main)||(x.images||[])[0];
 const desc=String(tr[2].description||'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();
 return{i:'w:'+x.id,en:tr[2].name.trim(),...(tr[4]?{es:tr[4].name.trim()}:{}),m,m2,q:(x.equipment||[]).map(y=>y.name==='none (bodyweight exercise)'?'body only':y.name.toLowerCase()).join(', '),k:x.category&&x.category.name==='Cardio'?'cardio':'strength',ins:desc?[desc.slice(0,700)]:[],img:img?img.image:''}}
// Live wger search (searches names in every language) for exercises the bundled catalog does not have.
async function wgerSearch(q){exIndex();const r=await fetch('https://wger.de/api/v2/exerciseinfo/?limit=12&name__search='+encodeURIComponent(q));if(!r.ok)return[];const j=await r.json(),qf=fold(q);
 return(j.results||[]).map(wgerEntry).filter(e=>e&&!EXID[e.i]).map(e=>({e,live:true,es:!!e.es&&fold(e.es).includes(qf)&&!fold(e.en).includes(qf)})).map(r=>({...r,name:r.es?r.e.es:r.e.en}))}
function exKeep(e){if(EXID&&EXID[e.i])return;CFG.exExtra=[...(CFG.exExtra||[]),e];saveCfg();exReset()}

// ----- suggestion box for inputs with data-exs ("one" adds right away, "list" is comma-separated, "link" re-links the open exercise)
let exsBox=null,exsIn=null,exsItems=[],exsAct=-1,exsTimer=null,exsTok=0;
const exsQuery=t=>(t.dataset.exs==='list'?t.value.split(',').pop():t.value).trim();
function exsHide(){if(exsBox)exsBox.remove();exsBox=null;exsItems=[];exsAct=-1;clearTimeout(exsTimer);exsTok++}
function exsDraw(){if(!exsIn||!document.body.contains(exsIn)||!exsItems.length){exsHide();return}
 if(!exsBox){exsBox=document.createElement('div');exsBox.className='exsug';exsBox.setAttribute('role','listbox');document.body.appendChild(exsBox);
  exsBox.addEventListener('pointerdown',e=>{e.preventDefault();const b=e.target.closest('[data-exi]');if(b)exsPick(+b.dataset.exi)})}
 const r=exsIn.getBoundingClientRect();exsBox.style.left=r.left+'px';exsBox.style.top=(r.bottom+4)+'px';exsBox.style.width=Math.max(r.width,320)+'px';
 exsBox.innerHTML=exsItems.map((x,i)=>{const e=x.e,other=e?(x.name===e.es?e.en:e.es)||'':'',mus=e&&e.m?e.m.map(exCap).join(', '):'';
  return `<div class="exo${i===exsAct?' on':''}" data-exi="${i}" role="option" aria-selected="${i===exsAct}"><span class="t"><b>${esc(x.name)}</b><span class="meta">${[other&&fold(other)!==fold(x.name)?other:'',mus].filter(Boolean).map(esc).join(' · ')}</span></span>${x.own?'<em>Yours</em>':x.live?'<em>wger</em>':''}</div>`}).join('')}
function exsShow(t){exsIn=t;const q=exsQuery(t);clearTimeout(exsTimer);const tok=++exsTok;if(q.length<2){exsHide();return}
 exsItems=exSearch(q);exsAct=-1;exsDraw();
 if(q.length>=3&&exsItems.filter(x=>!x.own).length<5&&navigator.onLine!==false)exsTimer=setTimeout(()=>wgerSearch(q).then(r=>{if(tok!==exsTok||exsIn!==t)return;
  const seen=new Set(exsItems.map(x=>fold(x.name)));for(const x of r)if(exsItems.length<10&&!seen.has(fold(x.name))){seen.add(fold(x.name));exsItems.push(x)}exsDraw()}).catch(()=>{}),350)}
function exsPick(i){const x=exsItems[i],t=exsIn;if(!x||!t)return;if(x.live)exKeep(x.e);const mode=t.dataset.exs;exsHide();
 if(mode==='link'){if(!x.e||!exSel)return;CFG.exLink={...(CFG.exLink||{}),[fold(exSel)]:x.e.i};saveCfg();exReset();render();return}
 if(mode==='list'){const p=t.value.split(',');p[p.length-1]=(p.length>1?' ':'')+x.name;t.value=p.join(',')+', ';t.focus();return}
 t.value=x.name;if(mode==='rt'){if(RE)reInput(t);t.focus();return}const b=document.querySelector('[data-act="hl:exadd"]');if(b)b.click()}
document.addEventListener('input',e=>{const t=e.target;if(t.dataset&&t.dataset.exs!==undefined)exsShow(t)});
document.addEventListener('focusout',e=>{if(e.target===exsIn)setTimeout(()=>{if(document.activeElement!==exsIn)exsHide()},120)});
document.addEventListener('scroll',e=>{if(exsBox&&!exsBox.contains(e.target))exsDraw()},true);
window.addEventListener('resize',()=>{if(exsBox)exsDraw()});
document.addEventListener('keydown',e=>{if(!exsBox||e.target!==exsIn)return;const n=exsItems.length;
 if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();let k=exsAct+(e.key==='ArrowDown'?1:-1);if(k<-1)k=n-1;if(k>=n)k=-1;exsAct=k;exsDraw()}
 else if(e.key==='Enter'&&exsAct>=0){e.preventDefault();e.stopImmediatePropagation();exsPick(exsAct)}
 else if(e.key==='Escape'){e.stopImmediatePropagation();exsHide()}},true);
document.addEventListener('error',e=>{const t=e.target;if(t&&t.classList&&t.classList.contains('eximg'))t.closest('.eximgw').remove()},true);

// ----- exercise details and weekly muscle summary
/* Progress chart for one exercise: one point per session, oldest to newest. Strength: heaviest weight, estimated
   1-rep max (Epley: kg × (1 + reps/30)), volume (kg × reps) or total reps. Cardio: distance, time or pace (min/km). */
let exMetric=null;
const EXM={top:['Heaviest weight','kg'],orm:['Estimated 1RM','kg'],vol:['Volume','kg'],reps:['Total reps','reps'],km:['Distance','km'],min:['Time','min'],pace:['Pace','min/km']};
function exSeries(name){const out=[];for(const d of workouts().slice().reverse()){const x=(wkRead(d).ex||[]).find(y=>fold(y.name)===fold(name));if(!x)continue;
 const ss=x.sets.filter(s=>setFilled(x,s));if(!ss.length)continue;const n=v=>parseFloat(v)||0;
 if(x.kind==='cardio'){const km=ss.reduce((a,s)=>a+n(s.km),0),min=ss.reduce((a,s)=>a+n(s.min),0);out.push({d,kind:'cardio',km,min,pace:km&&min?min/km:0})}
 else out.push({d,kind:'strength',top:Math.max(0,...ss.map(s=>n(s.kg))),orm:Math.max(0,...ss.map(s=>n(s.kg)*(1+n(s.reps)/30))),vol:ss.reduce((a,s)=>a+n(s.kg)*n(s.reps),0),reps:ss.reduce((a,s)=>a+n(s.reps),0)})}
 return out}
const exNum=(v,u)=>{const r=v>=100?Math.round(v):Math.round(v*10)/10;return (u==='min/km'?`${Math.floor(v)}:${String(Math.round(v%1*60)).padStart(2,'0')}`:r.toLocaleString(LOC()))+' '+u};
function exChart(name){const all=exSeries(name);if(!all.length)return '';
 const cardio=all[all.length-1].kind==='cardio',pts0=all.filter(p=>(p.kind==='cardio')===cardio);
 const opts=cardio?['km','min','pace']:pts0.some(p=>p.top)?['top','orm','vol','reps']:['reps'];
 const m=opts.includes(exMetric)?exMetric:opts[0],[lab,u]=EXM[m],pts=pts0.filter(p=>p[m]>0);
 const seg=opts.length>1?`<div class="moods seg">${opts.map(o=>`<button data-act="hl:exm" data-val="${o}" class="${o===m?'on':''}" aria-pressed="${o===m}">${EXM[o][0]}</button>`).join('')}</div>`:'';
 if(pts.length<2)return `<div class="exch"><div class="head" style="margin:0 0 8px"><h3 style="margin:0">Progress</h3>${seg}</div><p class="meta" style="margin:0">Log this exercise in at least two workouts to see how it evolves.${pts.length?` <span>So far: ${exNum(pts[0][m],u)} on ${fmt(pts[0].d)}.</span>`:''}</p></div>`;
 const W=640,H=220,L=46,R=14,T=14,B=28,vs=pts.map(p=>p[m]);let lo=Math.min(...vs),hi=Math.max(...vs);
 // round axis steps (1, 2, 2.5 or 5 × a power of ten), about 3–5 lines
 const span=(hi-lo)||Math.max(1,hi*.2),raw=span/3,p10=Math.pow(10,Math.floor(Math.log10(raw))),stp=[1,2,2.5,5,10].map(f=>f*p10).find(x=>x>=raw);
 lo=Math.max(0,Math.floor((lo-span*.08)/stp)*stp);hi=Math.ceil((hi+span*.08)/stp)*stp;if(hi===lo)hi=lo+stp;const ticks=[];for(let v=lo;v<=hi+stp/2;v+=stp)ticks.push(v);
 const t0=pd(pts[0].d).getTime(),t1=pd(pts[pts.length-1].d).getTime(),xs=p=>L+(t1>t0?(pd(p.d).getTime()-t0)/(t1-t0):.5)*(W-L-R),ys=v=>T+(1-(v-lo)/(hi-lo))*(H-T-B);
 const line=pts.map((p,i)=>`${i?'L':'M'}${xs(p).toFixed(1)} ${ys(p[m]).toFixed(1)}`).join(' '),area=`${line} L${xs(pts[pts.length-1]).toFixed(1)} ${H-B} L${xs(pts[0]).toFixed(1)} ${H-B} Z`;
 const grid=ticks.map(v=>{const y=ys(v);return `<line x1="${L}" x2="${W-R}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}" class="exgl"/><text x="${L-8}" y="${(y+4).toFixed(1)}" text-anchor="end" class="exax">${esc(m==='pace'?exNum(v,'min/km').replace(' min/km',''):exNum(v,'').trim())}</text>`}).join('');
 const xl=[pts[0],pts.length>2?pts[Math.floor((pts.length-1)/2)]:null,pts[pts.length-1]].filter(Boolean).map((p,i,a)=>`<text x="${xs(p).toFixed(1)}" y="${H-8}" text-anchor="${i===0?'start':i===a.length-1?'end':'middle'}" class="exax">${esc(fmt(p.d,{month:'short',day:'numeric'}))}</text>`).join('');
 const best=pts.reduce((a,p)=>(m==='pace'?p[m]<a[m]:p[m]>a[m])?p:a,pts[0]);
 const dots=pts.map(p=>`<g class="exdot ${p===best?'best':''}" data-act="hl:open" data-val="${p.d}" tabindex="0" role="button" aria-label="${esc(fmt(p.d)+': '+exNum(p[m],u))}"><circle cx="${xs(p).toFixed(1)}" cy="${ys(p[m]).toFixed(1)}" r="12" class="exhit"/><circle cx="${xs(p).toFixed(1)}" cy="${ys(p[m]).toFixed(1)}" r="${p===best?5:4}"/><title>${esc(fmt(p.d)+' · '+exNum(p[m],u))}</title></g>`).join('');
 const a=pts[0][m],z=pts[pts.length-1][m],dv=z-a,good=m==='pace'?dv<0:dv>0,pc=a?Math.round(dv/a*100):0;
 const chg=dv?`<span class="exchg ${good?'up':'down'}">${dv>0?'+':'−'}${exNum(Math.abs(dv),u)}${pc?` (${dv>0?'+':'−'}${Math.abs(pc)}%)`:''}</span>`:'<span class="exchg">No change</span>';
 return `<div class="exch"><div class="head" style="margin:0 0 6px"><h3 style="margin:0">Progress</h3>${seg}</div>
<div class="exstat"><div><span class="meta">Latest</span><b>${exNum(z,u)}</b></div><div><span class="meta">${m==='pace'?'Fastest':'Best'}</span><b>${exNum(best[m],u)}</b></div><div><span class="meta">Since ${fmt(pts[0].d,{month:'short',day:'numeric'})}</span><b>${chg}</b></div><div><span class="meta">Sessions</span><b>${pts.length}</b></div></div>
<svg class="exsvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(lab)} over time"><defs><linearGradient id="exgr" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5fa57f" stop-opacity=".35"/><stop offset="1" stop-color="#5fa57f" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${area}" fill="url(#exgr)"/><path d="${line}" class="exln"/>${dots}${xl}</svg>
<p class="meta" style="margin:4px 0 0">${esc(lab)} per workout${m==='pace'?' (lower is faster)':''}. Click a point to open that workout.</p></div>`}
function exDetail(){const name=exSel,e=exFind(name),st=exStats().find(s=>fold(s.name)===fold(name)),img=exImg(e);
 const hist=workouts().map(d=>({d,x:(wkRead(d).ex||[]).find(x=>fold(x.name)===fold(name))})).filter(h=>h.x).slice(0,8);
 const chip=(l,v)=>v?`<div><span class="meta">${l}</span><b>${esc(v)}</b></div>`:'';
 const src=!e?'':String(e.i).split('|').map(i=>i.startsWith('w:')?`<button class="clink" data-act="hl:link" data-val="https://wger.de/exercise/${i.slice(2)}/view/">wger</button> (CC BY-SA 4.0)`:'<button class="clink" data-act="hl:link" data-val="https://github.com/yuhonas/free-exercise-db">free-exercise-db</button>').join(' · ');
 return `<section class="exdet"><div class="head" style="margin:0 0 10px"><h2 style="margin:0">${esc(name)}</h2><button class="g" data-act="hl:exclose">Close</button></div>
${e?`<div class="exgrid">${img?`<div class="eximgw"><img class="eximg" src="${esc(img)}" alt="${esc(e.en)}" loading="lazy"></div>`:''}<div class="exinfo">
<p class="meta" style="margin:0 0 10px">${esc(e.en)}${e.es?' · '+esc(e.es):''}</p><div class="exchips">${chip('Main muscles',(e.m||[]).map(exCap).join(', '))}${chip('Also works',(e.m2||[]).map(exCap).join(', '))}${chip('Equipment',exCap(e.q||''))}${chip('Level',exCap(e.l||''))}${chip('Type',e.k==='cardio'?'Cardio':'Strength')}</div>
${e.ins&&e.ins.length?`<h3>How to do it</h3><ol class="exins">${e.ins.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>`:''}<p class="meta" style="margin:10px 0 0">Source: ${src}</p></div></div>`
:'<p class="meta">This exercise isn’t in the catalog yet. Search below to link it to one.</p>'}
${exChart(name)}<h3>Your history</h3>${st?`<p class="meta" style="margin:0 0 6px">${st.days} session${st.days===1?'':'s'} · last ${fmt(st.last)}${st.best?` · best ${st.best.kg} kg × ${st.best.reps}`:st.bestKm?` · longest ${st.bestKm} km`:''}</p>`:''}
${hist.map(h=>`<button class="hlrow" data-act="hl:open" data-val="${h.d}"><span class="t"><b>${fmt(h.d,LONG)}</b><span class="meta">${h.x.sets.filter(s=>setFilled(h.x,s)).map(s=>setLine(h.x,s).slice(2)).map(esc).join(' · ')||'No sets'}</span></span></button>`).join('')||'<p class="empty">Not logged yet.</p>'}
<div class="row" style="margin-top:12px"><label class="meta lab" style="flex:1">${e?'Not the right exercise? Link another one':'Link to a catalog exercise'}<input data-exs="link" autocomplete="off" placeholder="Search in English or Spanish" aria-label="Search the exercise catalog"></label>${(CFG.exLink||{})[fold(name)]?'<button class="x" data-act="hl:exunlink">Undo link</button>':''}</div></section>`}
function muscleWeek(){const ws=weekStart(TD()),m={},miss=new Set();
 for(const d of workouts().filter(d=>d>=ws)){for(const x of wkRead(d).ex){if(x.kind==='cardio')continue;const n=x.sets.filter(s=>setFilled(x,s)).length;if(!n)continue;const c=exFind(x.name);if(!c||!(c.m||[]).length){miss.add(x.name);continue}for(const k of c.m)m[k]=(m[k]||0)+n}}
 const rows=Object.entries(m).sort((a,b)=>b[1]-a[1]),max=rows.length?rows[0][1]:1;
 return `<section><h2>Sets per muscle · this week</h2>${rows.map(([k,n])=>`<div class="musrow"><span>${esc(exCap(k))}</span><i><b style="width:${Math.round(n/max*100)}%"></b></i><em>${n}</em></div>`).join('')||'<p class="empty">Log sets this week to see which muscles you trained.</p>'}
${miss.size?`<p class="meta" style="margin:8px 0 0">Not counted (not in the catalog): ${[...miss].map(n=>`<button class="clink" data-act="hl:ex" data-val="${esc(n)}">${esc(n)}</button>`).join(', ')}</p>`:''}</section>`}

// ----- resizable sidebar: drag the grip on its edge (double-click resets). Widths are kept per layout (Sidebar, Cards).
function navLim(){return CFG.navLayout==='icons'?['icons',84,84,84]:CFG.navLayout==='grid'?['grid',250,170,520]:CFG.navLayout==='cards'?['cards',300,220,560]:['side',200,150,420]}
function navW(){const[l,d,lo,hi]=navLim(),v=+(CFG.navW||{})[l];return v?Math.min(hi,Math.max(lo,v)):d}
function navWidth(){const ap=$('app');if(ap)ap.style.setProperty('--navw',navW()+'px')}
function navSetW(v){const[l,d,lo,hi]=navLim();CFG.navW={...(CFG.navW||{}),[l]:Math.round(Math.min(hi,Math.max(lo,v)))};if(v===d)delete CFG.navW[l];navWidth()}
let navDrag=null;
document.addEventListener('pointerdown',e=>{if(e.target.id!=='navgrip'||e.button!==0)return;if(navAutoOn()&&!$('app').classList.contains('navshow')){navShow();return}e.preventDefault();navDrag={x:e.clientX,w:navW()};e.target.setPointerCapture(e.pointerId);document.body.classList.add('navsizing')});
document.addEventListener('pointermove',e=>{if(!navDrag)return;navSetW(navDrag.w+e.clientX-navDrag.x)});
const navEnd=()=>{if(!navDrag)return;navDrag=null;document.body.classList.remove('navsizing');saveCfg();if(view==='today')layoutHome()};
document.addEventListener('pointerup',navEnd);document.addEventListener('pointercancel',navEnd);
document.addEventListener('dblclick',e=>{if(e.target.id!=='navgrip')return;navSetW(navLim()[1]);saveCfg();if(view==='today')layoutHome()});
document.addEventListener('keydown',e=>{if(e.target.id!=='navgrip'||(e.key!=='ArrowLeft'&&e.key!=='ArrowRight'))return;e.preventDefault();navSetW(navW()+(e.key==='ArrowLeft'?-10:10));saveCfg()});

// Back to Home: a page opened from something on Home (View all, a card, a search result or command) gets a
// "Home" back button; going to another section from the sidebar clears it.
let fromHome=false,lastView=null,mainClickAt=0;
document.addEventListener('pointerdown',e=>{if(e.target.closest&&e.target.closest('#main'))mainClickAt=Date.now()},true);
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.closest&&e.target.closest('#main'))mainClickAt=Date.now()},true);
function render(){if(['today','habits','insights'].includes(view))try{hLinkSync()}catch(e){}
setTimeout(()=>{try{sndPaint()}catch(e){}try{nBell()}catch(e){}});
if(!visTabs().some(t=>t[0]===view))view=visTabs()[0][0];if(view!=='settings')setQ='';if(!inBack)backArm();renderNav();renderMTabs();
 // Re-drawing the same page keeps the scroll position (swapping the page's content would otherwise jump to the top);
 // going somewhere else starts at the top, as do actions that scroll there themselves first.
 const keepY=view===lastView?window.scrollY:null;
 if(view!==lastView){fromHome=lastView==='today'&&view!=='today'&&Date.now()-mainClickAt<1500;lastView=view}
const pst=$('pgrid')&&$('pgrid').scrollTop;exsHide();navTrack();{const pg=V[view]();$('main').innerHTML=(view!=='today'&&secRoot()?`<button class="backhome" data-act="nav" data-v="today" title="Home">${lineIco('M15 5l-7 7 7 7')}<span>Home</span></button>`:NAVH.length&&view!=='today'&&!/data-act="navBack"/.test(pg)?`<button class="backhome" data-act="navBack" title="Back">${lineIco('M15 5l-7 7 7 7')}<span data-notr>${esc(navLabel(NAVH[NAVH.length-1]))}</span></button>`:'')+pg}if(pst&&$('pgrid'))$('pgrid').scrollTop=pst;$('main').style.setProperty('--pc',secColor(view));// Page width (Settings → Appearance): on big windows pages stop growing and are centered, with space on both sides.
 const pw={comfortable:'1280px',wide:'1600px',full:'none'}[CFG.pageWidth]||'1600px';$('main').style.maxWidth=view==='settings'?'':pw;$('main').classList.toggle('mcenter',view==='settings'||pw!=='none');
 if(document.querySelectorAll)document.querySelectorAll('.ncard .md').forEach(e=>{if(e.scrollHeight>e.clientHeight+2)e.classList.add('clip')});stMasonry();fmFit();if(view==='today'){if(boardMode())hbFit();else layoutHome(homeColsCfg())}if(view==='health'&&hv==='overview')layoutHome(+CFG.healthCols||2);if(view==='calendar')calScroll();hydrateImgs();hydratePdf();qcButton();showRem();if(keepY&&Math.abs(window.scrollY-keepY)>1)window.scrollTo(0,keepY)}
document.addEventListener('click',e=>{const b=e.target.closest('[data-act]');if(!b)return;if(b.tagName==='A')e.preventDefault();if(b.dataset.act!=='undoN'&&b.dataset.act!=='redoN')flushNote();const a=b.dataset.act,k=b.dataset.k,i=+b.dataset.i,j=+b.dataset.j,v=id=>$(id)?$(id).value.trim():'';
if(a!=='delF'&&a!=='wipe'&&a!=='delP'&&a!=='delT'&&a!=='delH'&&a!=='delQ'&&a!=='delList'&&a!=='col:del'&&a!=='hl:wkdel'&&a!=='hl:rtdel'&&a!=='ccDel'&&a!=='tcDel'&&a!=='thDel'&&a!=='bkRestore')armed=null;
if(a.startsWith('hl:')){hlAct(a.slice(3),b);return}
if(a.startsWith('col:')){if(a==='col:open')hq='';colAct(a.slice(4),b);return}
if(a==='dl'){dl(k.split('/').pop(),FS[k]);return}
if(a==='exportAll'){dl('prodify-'+TD()+'.zip',zip(FS));return}
if(a==='import'){$('imp').click();return}
if(a==='dirPick'){TAURI.invoke('pick_folder').then(d=>{if(d){pendDir=d;render()}}).catch(e=>toast('Could not open the folder picker: '+e));return}
if(a==='dirGo'){switchFolder(b.dataset.copy==='1');return}
if(a==='dirCancel'){pendDir=null;render();return}
if(a==='dirDefault'){pendDir=BOOT.default_dir;render();return}
if(a==='openDir'){TAURI.invoke('open_folder').catch(e=>toast('Could not open the folder: '+e));return}
if(a==='nav'){wlFrom=null;mSheet=null;if(b.dataset.v==='settings')SETG=null;// The sidebar starts a fresh trail: back buttons then step within the section (a list goes back to Tasks), never to the section you left.
if(b.closest('nav,#mtabs,#msheet')){NAVH=[];navSkip=true}
if(b.dataset.v==='tasks'&&view==='tasks'){curList=null;edL=false}view=b.dataset.v;edT=null;addSubT=null;window.scrollTo(0,0)}
else if(a==='mirPick'){TAURI.invoke('pick_folder',{title:'Choose a backup folder'}).then(d=>{if(!d)return;if(d===BOOT.dir){toast('Pick a different folder from the one Prodify uses');return}CFG.mirDir=d;saveCfg();mirReset();render();toast('Backup folder set · copying your data')}).catch(e=>toast('Could not open the folder picker: '+e));return}
else if(a==='mirNow'){mirReset();toast('Copying to the backup folder…');return}
else if(a==='mirOff'){CFG.mirDir='';saveCfg();clearTimeout(mirTimer);mirErr='';toast('Backup folder turned off · its files are left as they are')}
else if(a==='shEdit')shEdit=!shEdit;
else if(a==='shPick'){const id=b.dataset.v,pk=shPicks();CFG.homeShort=pk.includes(id)?pk.filter(x=>x!==id):[...pk,id];saveCfg()}
else if(a==='mMore')mSheet=mSheet?null:'more';
else if(a==='mEditOpen')mSheet='edit';
else if(a==='mClose')mSheet=null;
else if(a==='mEdit')mSheet='edit';
else if(a==='mEditDone')mSheet='more';
else if(a==='mPick'){const id=b.dataset.v,pk=mPicks();CFG.mobTabs=pk.includes(id)?pk.filter(x=>x!==id):pk.length<3?[...pk,id]:[...pk.slice(1),id];saveCfg()}
else if(a==='mood')setMood(TD(),+b.dataset.n);
else if(a==='mcPick'){const n=+b.dataset.n;MC=MC&&MC.m===n?null:{m:n,emos:MC?MC.emos:[]}}
else if(a==='mcEmo'){if(MC){const x=b.dataset.v;MC.emos=MC.emos.includes(x)?MC.emos.filter(y=>y!==x):[...MC.emos,x]}}
else if(a==='mcCancel'){MC=null}
else if(a==='mcSave'){if(MC){moodsWrite([...moodsRead(),{d:TD(),t:hm(':'),m:MC.m,emos:MC.emos}]);toast(`Mood logged · ${tf(hm(':'))}`);MC=null}}
else if(a==='mcDel'){const l=moodsRead();l.splice(i,1);moodsWrite(l)}
else if(a==='newQ'){newQ();return}
else if(a==='ask')ansQ=k;
else if(a==='saveQ'){const t=v(b.dataset.t);if(!t)return;addEntry(TD(),k,t);ansQ=null;toast('Saved to Questions');if(k===curQ){$(b.dataset.t).value='';curQ=null;save();newQ();return}}
else if(a==='jtab')jtab=b.dataset.val;
else if(a==='jer')jer=+b.dataset.val;
else if(a==='stTab'){stTab=b.dataset.val;stQ='';stPrev=null;stRen=null}
else if(a==='stFavF'){stFavF=!stFavF}
else if(a==='rlDone'){const l=stRead('links'),x=l.find(y=>y.url===b.dataset.val);if(x){x.later=false;stWrite('links',l);toast('Marked as read')}}
else if(a==='stFolderSet'){const v2=b.dataset.val;stFolder=v2===''?null:v2}
else if(a==='stMoveCancel'){stMove=null}
else if(a==='stMoveSave'||a==='stMoveOut'){if(stMove){const[k2,i2]=stMove.split(':'),l=stRead(k2),x=l[+i2];if(x){x.folder=a==='stMoveOut'?'':v('stfold');stWrite(k2,l);toast(x.folder?`Moved to ${x.folder}`:'Removed from folder')}stMove=null}}
else if(a==='stPendAdd'){stCommit();return}
else if(a==='stPendCancel'){stPend.forEach(x=>x.url&&URL.revokeObjectURL(x.url));stPend=[];pendingFocus='#stq'}
else if(a==='stUnstage'){const x=stPend.splice(i,1)[0];if(x&&x.url)URL.revokeObjectURL(x.url);pendingFocus='#stq'}
else if(a==='stViewSet'){CFG.stView=b.dataset.val;saveCfg()}
else if(a==='stSortSet'){CFG.stSort=b.dataset.val;saveCfg()}
else if(a==='stRenCancel'){stRen=null}
else if(a==='stRenSave'){if(stRen){const[k,ii]=stRen.split(':'),l=stRead(k),x=l[+ii],t=v('stren');if(x&&t){x.title=t;stWrite(k,l);toast('Renamed')}stRen=null}}
else if(a==='stLinkAdd'){stAddLink(v('stlink'));return}
else if(a==='stAdd'){stPick(b.dataset.val);return}
else if(a==='stOpen'){openLink(b.dataset.val);const l=stRead('links'),x=l.find(y=>y.url===b.dataset.val);if(x&&x.later){x.later=false;stWrite('links',l);save();setTimeout(render,300)}return}
else if(a==='stPdf'){if(e.target.closest('[data-act="stPrev"]'))return;stOpenPdf(b.dataset.val);return}
else if(a==='stPrev'){stPrev=stPrev===b.dataset.val?null:b.dataset.val}
else if(a==='stDel'){stConfirmDel(b.dataset.val,i);return}
else if(a==='qf')qf=b.dataset.val;
else if(a==='saveJ'){const t=v('jt'),imgs=JIMG,now=hm(':'),logIt=()=>{if(JM)moodsWrite([...moodsRead(),{d:TD(),t:now,m:JM,emos:JEMO.slice()}])};
 // No text or photos: only a mood check-in. Otherwise a journal entry, and the mood is logged too.
 if(!t&&!imgs.length){if(!JM){toast(JEMO.length?'Pick how you feel first':'Pick how you feel, or write something');return}logIt();JM=0;JEMO=[];emoOpen=false;jNew=false;toast(`Mood logged · ${tf(now)}`)}
 else{JIMG=[];const loc=v('jloc').replace(/\s+/g,' '),had=!!JM;logIt();
 jeNew([imgs.map(x=>`![](../../attachments/${x.name})`).join('\n'),t].filter(Boolean).join('\n\n'),loc);jNew=false;
 imgs.forEach(x=>{ATTURL[x.name]=x.url;saveAtt(x.name,x.blob).catch(e=>fail('Could not save a photo: '+e))});toast(had?'Saved to journal · mood logged':'Saved to journal')}}
else if(a==='addImg'){const f=document.createElement('input');f.type='file';f.accept='image/*';f.multiple=true;f.onchange=()=>addPhotos([...f.files]);f.click();return}
else if(a==='jimgDel'){JIMG.splice(i,1)}
else if(a==='lightbox'){const set=b.dataset.set.split('|');LB={set,i:Math.max(0,set.indexOf(b.dataset.att))};lbShow();return}
else if(a==='undoN')undoNote(-1);
else if(a==='redoN')undoNote(1);
else if(a==='editN'){edN=k;ND=null;addProp=false;if(nmode!=='templates'&&nmode!=='archive'&&!(nmode==='categories'&&selCat))nmode='notes';if(CFG.notesView!=='panel'||isTplKey(k))window.scrollTo(0,0)}
else if(a==='nmode'){nmode=b.dataset.val;edN=null;ND=null;q='';selCat=null;addProp=false;if(nmode!=='notes')tagF=null}
else if(a==='openCat'){view='notes';nmode='categories';selCat=b.dataset.v;window.scrollTo(0,0)}
else if(a==='catAll')selCat=null;
else if(a==='tmTab'){tmTab=b.dataset.val}
else if(a==='tmStart'){const m=parseFloat(b.dataset.val||String(v('tmmin')).replace(',','.'));if(!(m>0)){toast('Enter the minutes');return}const sec=Math.round(m*60);CFG.timers=[...(CFG.timers||[]),{id:Date.now().toString(36),label:b.dataset.val?'':v('tmlab'),total:sec,end:Date.now()+sec*1000}];saveCfg();try{if(!TAURI&&window.Notification&&Notification.permission==='default')Notification.requestPermission()}catch(e){}}
else if(a==='tmPause'){const t=(CFG.timers||[]).find(x=>x.id===b.dataset.val);if(t){if(t.end){t.left=tmLeft(t);t.end=null}else{t.end=Date.now()+tmLeft(t)*1000;delete t.left}saveCfg()}}
else if(a==='tmAgain'){const t=(CFG.timers||[]).find(x=>x.id===b.dataset.val);if(t){t.end=Date.now()+t.total*1000;delete t.left;saveCfg()}}
else if(a==='tmDel'){CFG.timers=(CFG.timers||[]).filter(x=>x.id!==b.dataset.val);saveCfg()}
else if(a==='alAdd'){const tm=v('altime');if(!/^\d{2}:\d{2}$/.test(tm)){toast('Pick a time');return}CFG.alarms=[...(CFG.alarms||[]),{id:Date.now().toString(36),time:tm,label:v('allab'),days:[],on:true,last:''}];saveCfg();toast('Alarm set for '+tf(tm))}
else if(a==='alDay'){const al=(CFG.alarms||[]).find(x=>x.id===b.dataset.val),dw=+b.dataset.d;if(al){const d=new Set(al.days||[]);d.has(dw)?d.delete(dw):d.add(dw);al.days=[...d];al.on=true;saveCfg()}}
else if(a==='alTog'){const al=(CFG.alarms||[]).find(x=>x.id===b.dataset.val);if(al){al.on=!al.on;if(al.on)al.last='';saveCfg()}}
else if(a==='alDel'){CFG.alarms=(CFG.alarms||[]).filter(x=>x.id!==b.dataset.val);saveCfg()}
else if(a==='prioPickT'){prioPick=!prioPick;prioSel=prioToday().slice()}
else if(a==='prioTog'){const k2=b.dataset.k;prioSel=prioSel.includes(k2)?prioSel.filter(x=>x!==k2):prioSel.length<3?[...prioSel,k2]:prioSel}
else if(a==='prioSave'){CFG.prio={d:TD(),ids:prioSel.slice(0,3)};saveCfg();prioPick=false;toast(prioSel.length?'Focus set for today':'Focus cleared')}
else if(a==='prioCancel'){prioPick=false}
else if(a==='prioMode'){if(CFG.focusRun)fsEnd('exit');else if(CFG.prioMode){CFG.prioMode=false;saveCfg()}else{CFG.prioMode=true;fsStart();saveCfg();toast('Focus started · the timer is running')}}
else if(a==='fsPause'){const r=CFG.focusRun;if(r){if(r.paused){r.at=Date.now();r.paused=false}else{r.acc=(r.acc||0)+Date.now()-r.at;r.paused=true}saveCfg()}}
else if(a==='qcOpen'){QC={text:'',type:'auto',f:{}};qcShow();return}
else if(a==='qcClose'){QC=null;qcShow();return}
else if(a==='qcType'){qcSync();const to=b.dataset.val;if(to!==QC.type){qcCarry(QC.type,to);QC.type=to}qcShow();return}
else if(a==='qcMood'){qcSync();const n=+b.dataset.n;QC.f.mood=QC.f.mood===n?0:n;qcShow();return}
else if(a==='qcSave'){qcSave();return}
else if(a==='ipAddT'){ipAdd=!ipAdd;ipQ='';if(ipAdd)pendingFocus='#ipq'}
else if(a==='ipStart'){const it=FS[b.dataset.k]&&colRead(b.dataset.k);if(it){colSetStatus(it,'doing');colPut(it);toast(`${it.title} · ${statLabel(it.type,'doing')}`);ipAdd=false;ipQ=''}}
else if(a==='ipWeb'){const q=ipQ.trim();ipAdd=false;ipQ='';view='collections';colSel=null;CD=null;colAdd=true;colSQ=q;colRes=null;window.scrollTo(0,0);render();setTimeout(()=>{const i=$('cols');if(i)i.value=q;colSearch()},30);return}
else if(a==='medDur'){medSetDur(+b.dataset.val)}
else if(a==='medFsStart'){medStartT();MEDFS=true;medFsShow();return}
else if(a==='medFsOpen'){if(!MT.run)medStartT();MEDFS=true;medFsShow();return}
else if(a==='medFsPause'){MT.run?medPause():medStartT();return}
else if(a==='medFsEnd'){medDone(false);return}
else if(a==='medFsMin'){MEDFS=false;medFsShow();render();return}
else if(a==='recapNav'){const t=TD(),cur=recapD&&recapD<=t?recapD:t,n=dAdd(cur,+b.dataset.val);recapD=n>t?t:n}
else if(a==='thNew'){const src=CFG.palette;THD={id:Date.now().toString(36),name:'My theme',light:themeColors(src,0),dark:themeColors(src,1)};thSide=document.documentElement.dataset.theme==='light'?'light':'dark'}
else if(a==='thEdit'){const t=(CFG.customThemes||[]).find(x=>'c-'+x.id===CFG.palette);if(t)THD=JSON.parse(JSON.stringify(t))}
else if(a==='thSide'){thSync();thSide=b.dataset.val}
else if(a==='thCopy'){thSync();const o=thSide==='light'?'dark':'light';THD[o]={...THD[thSide]};thSide=o;toast('Copied')}
else if(a==='thCancel'){THD=null}
else if(a==='thSave'){thSync();const t={id:THD.id,name:(THD.name||'').trim()||'My theme',light:THD.light,dark:THD.dark},l=(CFG.customThemes||[]).filter(x=>x.id!==t.id),i=(CFG.customThemes||[]).findIndex(x=>x.id===t.id);if(i>=0)l.splice(i,0,t);else l.push(t);CFG.customThemes=l;CFG.palette='c-'+t.id;themesSync();saveCfg();THD=null;apply();toast('Theme saved')}
else if(a==='thDel'){if(armed!=='th:'+THD.id){armed='th:'+THD.id;render();return}CFG.customThemes=(CFG.customThemes||[]).filter(x=>x.id!==THD.id);if(CFG.palette==='c-'+THD.id)CFG.palette='classic';themesSync();saveCfg();THD=null;armed=null;apply();toast('Theme deleted')}
else if(a==='thExport'){const t=(CFG.customThemes||[]).find(x=>'c-'+x.id===CFG.palette);if(t)dl(slug(t.name)+'.prodify-theme.json',JSON.stringify({prodifyTheme:1,name:t.name,light:t.light,dark:t.dark},null,2));return}
else if(a==='thImport'){const f=document.createElement('input');f.type='file';f.accept='.json,application/json';f.onchange=async()=>{try{const o=JSON.parse(await f.files[0].text()),ok=x=>x&&TCOLS.every(([k])=>/^#[0-9a-f]{6}$/i.test(x[k]||''));if(!o.prodifyTheme||!ok(o.light)||!ok(o.dark))throw 0;
  const t={id:Date.now().toString(36),name:String(o.name||'Imported theme').slice(0,40),light:Object.fromEntries(TCOLS.map(([k])=>[k,o.light[k]])),dark:Object.fromEntries(TCOLS.map(([k])=>[k,o.dark[k]]))};CFG.customThemes=[...(CFG.customThemes||[]),t];CFG.palette='c-'+t.id;themesSync();saveCfg();apply();render();toast(`Theme “${t.name}” imported`)}catch(e){toast('That isn’t a Prodify theme file')}};f.click();return}
else if(a==='goSub'){const v2=b.dataset.v,sb=b.dataset.sub||'';flushNote();hq='';view=v2;
 if(v2==='health'){hv=sb||'overview';wkSel=null;WK=null;exSel=null}else if(v2==='notes'){nmode=sb||'notes';edN=null;ND=null;selCat=null}else if(v2==='journal'){jtab=sb||'entries'}else if(v2==='files'){stTab=sb||'all';stQ='';stFolder=b.dataset.later?'@later':null}
 else if(v2==='calendar'&&sb){CFG.calView=sb;saveCfg()}else if(v2==='today'&&sb){tmTab=sb;setTimeout(()=>{const c=document.querySelector('.tmcard');if(c)c.scrollIntoView({block:'center',behavior:'smooth'})},60)}else if(v2==='tasks'){curList=null}else if(v2==='projects'){curP=null}
 window.scrollTo(0,0)}
else if(a==='goHealth'){view='health';hv=b.dataset.val||'overview';wkSel=null;WK=null;exSel=null;window.scrollTo(0,0)}
else if(a==='hGo'){view='habits';hday=TD();const id=k;setTimeout(()=>{const el=document.querySelector(`[data-act="editH"][data-k="${CSS.escape(id)}"]`),sec=el&&el.closest('section');if(sec){sec.scrollIntoView({block:'center',behavior:'smooth'});sec.classList.add('flash');setTimeout(()=>sec.classList.remove('flash'),1600)}},60)}
else if(a==='hMake'){hMake(b.dataset.val)}
else if(a==='hPreset'){const p=HPRESETS.find(x=>x[0]===b.dataset.val);if(p){const [link,name,goal,target,unit]=p;HD={...freshHD(),name,goal,link,target:target?String(target):'',unit:unit||'',period:'daily',pre:link};
 setTimeout(()=>{const el=document.querySelector('.hgoals');if(el)el.scrollIntoView({block:'center',behavior:'smooth'});const i=document.querySelector('[data-hd="target"]')||document.querySelector('[data-hd="name"]');if(i){i.focus({preventScroll:true});if(i.select)i.select()}},60)}}
else if(a==='catEditPage'){const n=b.dataset.v,bb=catBase(n,'notes')||{},nm=(allCats('notes').get(n.toLowerCase())||{name:n}).name;catEd={sc:'notes',orig:nm,name:nm,sym:bb.sym||'folder',emoji:bb.emoji||'📁'};icoPick=null;window.scrollTo(0,0)}
else if(a==='bkAutoT'){CFG.autoBackup=CFG.autoBackup===false;saveCfg()}
else if(a==='bkNow'){backupNow();return}
else if(a==='bkRestore'){const n=b.dataset.val;if(armed!=='bk:'+n){armed='bk:'+n;render();return}armed=null;backupRestore(n);return}
else if(a==='kbOpen'){KSH=true;kbShow();return}
else if(a==='kbClose'){KSH=false;kbShow();return}
else if(a==='cloudUrlSave'){const u=v('cloudurl').replace(/\/+$/,'');if(u&&!/^https?:\/\//.test(u)){toast('Use a full address, starting with https://');return}CFG.cloudUrl=u;CFG.cloud={...(CFG.cloud||{}),url:u};saveCfg();toast(u?'Server saved':'Server cleared')}
else if(a==='cloudStart'){const em=v('cloudemail');if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)){toast('Type your email');return}CFG.cloud={...(CFG.cloud||{}),url:cloudUrl(),email:em};saveCfg();cloudBusy=true;render();
 cloudJson('POST','/auth/start',{email:em}).then(r=>{CLOUDUI={step:'code',email:em,dev:r.devCode||''};cloudErr='';pendingFocus='#cloudcode'}).catch(e=>{cloudErr=e.message}).finally(()=>{cloudBusy=false;render()});return}
else if(a==='cloudCancel'){CLOUDUI=null}
else if(a==='cloudVerify'){const code=v('cloudcode');cloudBusy=true;render();
 cloudJson('POST','/auth/verify',{email:CLOUDUI.email,code,device:(TAURI?'Prodify app':'Prodify web')+' · '+(navigator.platform||'')}).then(r=>{CFG.cloud={url:cloudUrl(),email:CLOUDUI.email,token:r.token,me:r.me,seq:0};saveCfg();CS={base:{},rev:{},ids:{}};CLOUDUI=null;cloudErr='';toast('Signed in to Prodify Cloud');setTimeout(()=>cloudSync(),50)})
  .catch(e=>{cloudErr=e.message}).finally(()=>{cloudBusy=false;render()});return}
else if(a==='cloudNow'){cloudSync().then(ch=>{if(!cloudErr)toast(ch?'Synced · changes from your other devices are in':'Synced')});render();return}
else if(a==='cloudOut'){askConfirm({title:'Sign out of Prodify Cloud?',text:'This device stops syncing. Your data stays here and in the cloud, and you can sign in again at any time.',ok:'Sign out'}).then(ok=>{if(!ok)return;cloudSignOut().then(()=>{toast('Signed out of Prodify Cloud');render()})});return}
else if(a==='cloudJoin'){cloudBusy=true;render();cloudApi('GET','/obj/account').then(async r=>{if(!r.ok){toast('This cloud is empty. Create an account with encryption first, then sync.');return}const t=await r.text(),ac=accParse(t);cloudMismatch={text:t,name:ac&&ac.name};pendingFocus='#cloudpw'}).catch(e=>{cloudErr=e.message}).finally(()=>{cloudBusy=false;render()});return}
else if(a==='cloudAdopt'){const pw=($('cloudpw')||{}).value||'';cloudBusy=true;render();cloudAdopt(pw).then(ok=>{if(!ok){toast('Wrong password');return}toast('This device now uses your cloud account · syncing…');setTimeout(()=>cloudSync(),50)}).finally(()=>{cloudBusy=false;render()});return}
else if(a==='storeDb'){storeSwitch('db');return}
else if(a==='storeMd'){storeSwitch('md');return}
else if(a==='setGroup'){SETG=b.dataset.v||null;setQ='';window.scrollTo(0,0)}
else if(a==='userGo'){userSwitch(b.dataset.v);return}
else if(a==='userNew'){UADD={name:'',dir:''};pendingFocus='#uname'}
else if(a==='userCancel'){UADD=null}
else if(a==='userDir'){if(UADD)UADD.name=v('uname');TAURI.invoke('pick_folder',{title:'Choose a folder for this user'}).then(d=>{if(d&&UADD){UADD.dir=d;render()}}).catch(e=>toast('Could not open the folder picker: '+e));return}
else if(a==='userAdd'){const nm=v('uname');if(!nm){toast('Type their name');return}const id=userCreate(nm,UADD.dir);if(!id)return;UADD=null;toast(`Switching to ${nm}…`);userSwitch(id);return}
else if(a==='userDel'){const u=USERS.find(x=>x.id===b.dataset.v);if(!u)return;askConfirm({title:`Remove ${u.name}?`,text:TAURI?`They’re taken off this list. Their folder and files stay where they are (${u.dir}), so you can add them back later.`:'They’re taken off this list. Their data stays in this browser, so you can add them back later.',ok:'Remove'}).then(ok=>{if(!ok)return;USERS=USERS.filter(x=>x.id!==u.id);userSave();render();toast(`${u.name} removed from this list`)});return}
else if(a==='set'&&b.dataset.s==='u:ask'){store.set('prodify.ask',b.dataset.val==='on'?'1':'0')}
else if(a==='lockRec'){lockRec=!lockRec;lockShow();return}
else if(a==='accFreshSet'){accNameDraft=v('accname')||accNameDraft;accFresh=b.dataset.val==='1';render();return}
else if(a==='accFreshGo'){const nm=v('accname');if(!nm){toast('Type your name');return}accFresh=false;accNameDraft='';ACCUI=null;userFresh(nm,'settings');return}
else if(a==='accUi'){if(b.dataset.v==='create'){accFresh=false;accNameDraft=CFG.name||''}ACCUI=ACCUI===b.dataset.v?null:b.dataset.v;pendingFocus=ACCUI==='create'?'#accname':ACCUI==='pw'&&accViaRec?'#accpw':'#accpw0'}
else if(a==='accCancel'){ACCUI=null;accViaRec=false}
else if(a==='accEncTog'){accEncOn=!accEncOn;const sw=b;sw.classList.toggle('on',accEncOn);sw.setAttribute('aria-checked',accEncOn);return}
else if(a==='accCopyRk'){navigator.clipboard.writeText(ACCRK).then(()=>toast('Recovery key copied'),()=>toast('Couldn’t copy it. Select it and copy it by hand.'));return}
else if(a==='accRkDone'){ACCRK='';ACCUI=null}
else if(a==='accCreate'){const nm=v('accname'),p1=($('accpw')||{}).value||'',p2=($('accpw2')||{}).value||'';
 if(!nm){toast('Type your name');return}if(p1.length<8){toast('Use at least 8 characters for the password');return}if(p1!==p2){toast('The passwords don’t match');return}
 accBusy=true;render();accCreate(nm,p1,accEncOn).then(rk=>{ACCRK=rk;ACCUI='recovery';toast(accEncOn?'Account created · your data is encrypted':'Account created')}).catch(e=>toast('Could not create the account: '+(e&&e.message||e))).finally(()=>{accBusy=false;render()});return}
else if(['accEncGo','accRkGo','accDelGo','accPwGo'].includes(a)){const pw=($('accpw0')||{}).value||'',p1=($('accpw')||{}).value||'',p2=($('accpw2')||{}).value||'';
 if(a==='accPwGo'){if(p1.length<8){toast('Use at least 8 characters for the password');return}if(p1!==p2){toast('The passwords don’t match');return}}
 accBusy=true;render();(async()=>{if(!(a==='accPwGo'&&accViaRec)&&!await accKey(pw,false)){toast('Wrong password');return}
  if(a==='accEncGo'){const on=!ACCT.enc;toast(on?'Encrypting your data…':'Decrypting your data…');await accSetEnc(on);ACCUI=null;toast(on?'Your data is encrypted':'Your data is no longer encrypted')}
  else if(a==='accPwGo'){const old=ACCT.rkey,os=ACCT.rsalt;await accSeal(ACCT,p1,null);ACCT.rkey=old;ACCT.rsalt=os;FS[ACCK]=accText(ACCT);save();accViaRec=false;ACCUI=null;toast('Password changed')}
  else if(a==='accRkGo'){const rk=recNew();await accSeal(ACCT,pw,rk);FS[ACCK]=accText(ACCT);save();ACCRK=rk;ACCUI='recovery'}
  else if(a==='accDelGo'){await accRemove();ACCUI=null;PWLOCK=false;toast('Account removed')}})().catch(e=>toast('Something went wrong: '+(e&&e.message||e))).finally(()=>{accBusy=false;render()});return}
else if(a==='lockAsk'){lockSet=true;pendingFocus=CFG.lock&&CFG.lock.hash?'#lkold':'#lknew'}
else if(a==='lockCancel'){lockSet=false}
else if(a==='lockOn'){const p1=($('lknew')||{}).value||'',p2=($('lknew2')||{}).value||'';if(p1.length<4){toast('Use at least 4 characters');return}if(p1!==p2){toast('The passwords don’t match');return}
 const salt=b64(crypto.getRandomValues(new Uint8Array(16)));lockHash(p1,salt).then(h=>{CFG.lock={salt,hash:h,idle:0};saveCfg();lockSet=false;render();toast('Password lock is on')});return}
else if(a==='lockOff'){const p=($('lkold')||{}).value||'';lockCheck(p).then(ok=>{if(!ok){toast('Wrong password');return}delete CFG.lock;saveCfg();lockSet=false;render();toast('Password lock is off')});return}
else if(a==='lockIdle'){if(CFG.lock){CFG.lock.idle=+b.dataset.val;saveCfg()}}
else if(a==='lockNow'){PWLOCK=true;lockShow();return}
else if(a==='onbFreshSet'){onbAccSync();onbA().fresh=b.dataset.val==='1';onbShow();return}
else if(a==='onbFreshGo'){onbSave();CFG.onboarded=true;saveCfg();ONB=null;onbShow();userFresh(CFG.name||'New user','onb');return}
else if(a==='onbAcc'){onbAccSync();const A=onbA();A.mode=b.dataset.val;A.err='';onbShow();return}
else if(a==='onbPwT'){onbAccSync();const A=onbA();A.pw=!A.pw;onbShow();if(A.pw)setTimeout(()=>{const i=$('onbpw');if(i)i.focus()});return}
else if(a==='onbEncT'){onbAccSync();onbA().enc=!onbA().enc;onbShow();return}
else if(['onbAccNext','onbCloudStart','onbCloudVerify','onbCloudJoin','onbCloudCreate','onbCloudBack','onbRkDone'].includes(a)){onbAccSync();onbSave();const A=onbA(),nm=CFG.name||'Me';
 const pwOk=()=>{if(A.p1.length<8){A.err='Use at least 8 characters for the password';return false}if(A.p1!==A.p2){A.err='The passwords don’t match';return false}return true};
 const run=f=>{A.busy=true;A.err='';onbShow();f().catch(e=>{A.err=String(e&&e.message||e)}).finally(()=>{A.busy=false;onbShow()})};
 if(a==='onbRkDone'){ACCRK='';A.step=A.mode==='cloud'?'ready':null;if(A.mode==='cloud'){cloudSoon(200);onbShow()}else{ONB.i++;onbShow()}return}
 if(a==='onbCloudBack'){A.step=null;A.code='';onbShow();return}
 if(a==='onbAccNext'){if(!A.pw){ONB.i++;onbShow();return}if(!pwOk()){onbShow();return}run(async()=>{ACCRK=await accCreate(nm,A.p1,A.enc);A.p1=A.p2='';A.step='rk'});return}
 if(a==='onbCloudStart'){if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(A.email)){A.err='Type your email';onbShow();return}
  run(async()=>{CFG.cloud={...(CFG.cloud||{}),url:cloudUrl(),email:A.email};saveCfg();const r=await cloudJson('POST','/auth/start',{email:A.email});A.dev=r.devCode||'';A.step='code';setTimeout(()=>{const i=$('onbcode');if(i)i.focus()})});return}
 if(a==='onbCloudVerify')run(async()=>{const r=await cloudJson('POST','/auth/verify',{email:A.email,code:A.code,device:(TAURI?'Prodify app':'Prodify web')+' · '+(navigator.platform||'')});
  CFG.cloud={url:cloudUrl(),email:A.email,token:r.token,me:r.me,seq:0};saveCfg();CS={base:{},rev:{},ids:{}};
  const acc=await cloudApi('GET','/obj/account');if(acc.ok){const t=await acc.text();cloudMismatch={text:t,name:(accParse(t)||{}).name};A.step='join'}else A.step=ACCT&&ACCT.enc?'ready':'create'});
 if(a==='onbCloudJoin')run(async()=>{if(!await cloudAdopt(A.p1))throw new Error('Wrong password');A.p1='';A.step='ready';cloudSoon(100)});
 if(a==='onbCloudCreate'){if(!pwOk()){onbShow();return}run(async()=>{ACCRK=await accCreate(nm,A.p1,true);A.p1=A.p2='';A.step='rk'})}
 return}
else if(a==='onbNext'){onbSave();ONB.i++;onbShow();return}
else if(a==='onbGo'){onbSave();ONB.i=+b.dataset.val;onbShow();return}
else if(a==='onbPick'){const id=b.dataset.id,on=b.dataset.val==='on',cur=CFG.tabOff||[];CFG.tabOff=on?cur.filter(x=>x!==id):[...new Set([...cur,id])];saveCfg();ONB.i++;apply();render();onbShow();return}
else if(a==='onbDone'){onbSave();CFG.onboarded=true;saveCfg();ONB=null;onbShow();view='today';render();window.scrollTo(0,0);return}
else if(a==='onbStart'){ONB={i:0};onbShow();return}
else if(a==='aiMenu'){aiMenu=!aiMenu}
else if(a==='aiNote'){aiNote(b.dataset.val);return}
else if(a==='aiClose'){AIN=null}
else if(a==='aiSumAdd'){if(AIN&&FS[AIN.k]){const n=readNote(FS[AIN.k]);n.body=n.body.replace(/\s*$/,'')+`\n\n## Summary\n\n${AIN.text}\n`;FS[AIN.k]=writeNote(n);ND=null;AIN=null;toast('Summary added')}}
else if(a==='aiCat'){if(AIN&&FS[AIN.k]){const n=readNote(FS[AIN.k]),c=b.dataset.v;n.fm.categories=[...new Map([...(n.fm.categories||[]),c].map(x=>[String(x).toLowerCase(),x])).values()];FS[AIN.k]=writeNote(n);ND=null;AIN.items=AIN.items.filter(x=>x!==c);toast('Category added')}}
else if(a==='aiTasksAdd'){if(AIN){putTasks(tasks().concat(AIN.items.map(t=>({done:false,title:t,due:'',rem:'',proj:'',list:'',added:TD()}))));toast(`${AIN.items.length} task${AIN.items.length===1?'':'s'} added`);AIN=null}}
else if(a==='aiKeySave'){const kk=v('aikey');if(!kk){toast('Paste your API key first');return}CFG.aiKey=kk;saveCfg();toast('API key saved')}
else if(a==='aiKeyDel'){delete CFG.aiKey;saveCfg();toast('API key removed')}
else if(a==='aiTest'){const S=aiFn();if(!S)return;toast('Testing…');S('Reply with the single word: ready',{modelTier:'quick',cache:false}).then(r=>toast('Connected · '+String(r.text||'').trim().slice(0,30))).catch(e=>toast('AI: '+(e&&e.message||e)));return}
else if(a==='moodQUse'){const t=$('jt'),q2=b.dataset.v;if(t){const cur=t.value;t.value=(cur.trim()?cur.replace(/\s*$/,'')+'\n\n':'')+q2+'\n';t.focus();t.setSelectionRange(t.value.length,t.value.length)}return}
else if(a==='histT'){histOpen=!histOpen;histSel=null}
else if(a==='histSel'){histSel=b.dataset.k}
else if(a==='histRestore'){const hk=b.dataset.k;if(edN&&FS[hk]){flushNote&&flushNote();histSnap(edN,FS[edN]);const cur=FS[edN];FS[edN]=FS[hk];FS[histDir(edN)+hk.split('/').pop()]=cur;ND=null;histOpen=false;toast('Version restored (the current text was kept in history)')}}
else if(a==='dailyGo'){flushNote&&flushNote();dailyOpen(b.dataset.d)}
else if(a==='navBack'){if(!navBack())render();return}
else if(a==='wlBack'){flushNote&&flushNote();colSel=null;CD=null;curP=null;curList=null;wlReturn()}
else if(a==='wlGo'){const kd=b.dataset.kind,x=b.dataset.v;flushNote&&flushNote();
 if(kd==='note'||kd==='journal'){view='notes';nmode='notes';edN=x;ND=null}else if(kd==='project'){view='projects';curP=x;edP=false}else if(kd==='col'){view='collections';colSel=x;CD=null;colQ=''}else if(kd==='list'){view='tasks';curList=x;edL=false}window.scrollTo(0,0)}
else if(a==='wlNew'){const t=b.dataset.v;flushNote&&flushNote();const nk=noteKeyFor('notes/',t,TD());FS[nk]=`---\ncreated: ${TD()}\n---\n# ${t}\n\n`;WLC=null;view='notes';nmode='notes';edN=nk;ND=null;nView=false;nViewK=nk;pendingFocus='#nb';toast('Note created')}
else if(a==='openNote'){histOpen=false;view='notes';nmode='notes';edN=k;ND=null;window.scrollTo(0,0)}
else if(a==='tagGo'){view='notes';nmode='notes';tagF=b.dataset.v;edN=null;ND=null;window.scrollTo(0,0)}
else if(a==='tagClear')tagF=null;
else if(a==='npDel'){const n=draft(),p=b.dataset.p;if(Array.isArray(n.fm[p]))n.fm[p].splice(+b.dataset.i,1);noteChanged('now')}
else if(a==='npRm'){delete draft().fm[b.dataset.p];noteChanged('now')}
else if(a==='npNew'){addProp=true;npT='text';npNameDraft='';pendingFocus='#npName'}
else if(a==='npCancel'){addProp=false;npNameDraft=''}
else if(a==='npAdd'){const name=v('npName').replace(/:/g,'').trim(),t=npT,n=draft();if(!name)return;npNameDraft='';
 if(!(name in n.fm)){if(!LISTP.includes(name)){CFG.propTypes={...CFG.propTypes,[name]:t};saveCfg()}const ty=ptype(name,'');n.fm[name]=ty==='list'||ty==='tags'||ty==='categories'?[]:ty==='checkbox'?'false':''}
 addProp=false;noteChanged('now');pendingFocus=`[data-np="${CSS.escape(name)}"],[data-npadd="${CSS.escape(name)}"]`}
else if(a==='tplAdd'){const name=v('tplNew').replace(/[\/\\]/g,'-').replace(/^\.+/,'').trim();if(!name)return;const key='templates/'+name+'.md';
 if(FS[key]){toast('A template with that name already exists');return}FS[key]='---\ncreated: {{date}}\ntags:\ncategories:\n---\n';edN=key;ND=null}
else if(a==='tplStarter'){const k2='templates/Note.md';if(!FS[k2])FS[k2]='---\ncreated: {{date}}\ntags:\ncategories:\n---\n';if(!CFG.defaultTpl){CFG.defaultTpl=k2;saveCfg()}toast('Starter template added')}
else if(a==='tplDef'){CFG.defaultTpl=k;saveCfg()}
else if(a==='tplUse'){nmode='notes';edN=null;tplSel=k;ND=null;window.scrollTo(0,0);setTimeout(focusNew)}
else if(a==='nMode'){flushNote();nView=b.dataset.val==='view';if(!nView)setTimeout(()=>{const el=$('nb');if(el)el.focus()})}
else if(a==='setqClear'){setQ='';setTimeout(()=>{const n=$('setq');if(n)n.focus()})}
else if(a==='catNew'){const sc=b.dataset.sc||'notes';catEd=catEd&&!catEd.orig&&(catEd.sc||'notes')===sc?null:{sc,orig:null,name:'',sym:'folder',emoji:'📁'};icoPick=null;window.scrollTo(0,0);setTimeout(()=>{const n=$('catname');if(n)n.focus()})}
else if(a==='catSave'){const n=$('catname');if(n&&catEd)catEd.name=n.value;if(!catSave()){render();return}icoPick=null;save();toast('Category saved')}
else if(a==='catCancel'){catEd=null;if(icoPick==='catedit')icoPick=null}
else if(a==='qtopic'){const v2=b.dataset.val,cur=qTopics();CFG.focus=!v2?[]:cur.includes(v2)?cur.filter(x=>x!==v2):[...cur,v2];saveCfg()}
else if(a==='hdSet'){const f=b.dataset.f;HD[f]=b.dataset.val;if(f==='goal'){if(HD.goal==='times'&&!HD.target)HD.target='3';if(HD.goal==='avoid'&&!HD.amode)HD.amode='never'}}
else if(a==='hdStep'){HD.target=String(Math.max(1,Math.min(7,(parseInt(HD.target)||0)+(+b.dataset.val))))}
else if(a==='hdMore'){HD.more=!HD.more}
else if(a==='npType'){npT=b.dataset.val;npNameDraft=v('npName');pendingFocus='#npName'}
else if(a==='jCat'){const x=b.dataset.v;jCatF=jCatF&&jCatF.toLowerCase()===x.toLowerCase()?null:x;view='journal';jtab='entries'}
else if(a==='jcatDel'){const kk=b.dataset.k,x=b.dataset.v.toLowerCase();if(kk==='new')JC=JC.filter(c=>c.toLowerCase()!==x);else jSetCats(kk,jCats(kk).filter(c=>c.toLowerCase()!==x));save();redraw();return}
else if(a==='jNew'){jNew=!jNew;if(jNew)setTimeout(()=>{const t=$('jt');if(t)t.focus()})}
else if(a==='jNewCancel'){jNew=false;JM=0;JC=[];JIMG=[];JEMO=[];emoOpen=false}
else if(a==='jeEmo'){const x=b.dataset.v;JEMO=JEMO.includes(x)?JEMO.filter(y=>y!==x):[...JEMO,x];redraw();return}
else if(a==='emoOpenT'){emoOpen=true;redraw();return}
else if(a==='jeEmoE'){const kk=b.dataset.k,x=b.dataset.v;if(FS[kk]){const ta=$('jeb'),loc=$('jel'),keep={t:ta&&ta.value,l:loc&&loc.value},nn=readNote(FS[kk]),cur=Array.isArray(nn.fm.emotions)?nn.fm.emotions.map(String):[];const nx=cur.includes(x)?cur.filter(y=>y!==x):[...cur,x];if(nx.length)nn.fm.emotions=nx;else delete nn.fm.emotions;FS[kk]=writeNote(nn);save();render();if($('jeb')&&keep.t!=null)$('jeb').value=keep.t;if($('jel')&&keep.l!=null)$('jel').value=keep.l}return}
else if(a==='jmSet'){const n2=+b.dataset.n;JM=JM===n2?0:n2;redraw();return}
else if(a==='jeMood'){const kk=b.dataset.k,n2=+b.dataset.n;if(FS[kk]){const nn=readNote(FS[kk]);nn.fm.mood=String(+nn.fm.mood===n2?'':n2);if(!nn.fm.mood)delete nn.fm.mood;FS[kk]=writeNote(nn);save()}redraw();return}
else if(a==='jeEdit'){jeEd=b.dataset.k;setTimeout(()=>{const t=$('jeb');if(t){t.focus();t.setSelectionRange(t.value.length,t.value.length)}})}
else if(a==='jeCancel')jeEd=null
else if(a==='jeSave'){const kk=b.dataset.k;if(FS[kk]){const nn=readNote(FS[kk]),loc=v('jel').replace(/\s+/g,' ');if(loc)nn.fm.location=loc;else delete nn.fm.location;nn.body=($('jeb')||{value:''}).value.trim()+'\n';FS[kk]=writeNote(nn)}jeEd=null;toast('Entry saved')}
else if(a==='jeOpen'){view='notes';nmode='notes';edN=b.dataset.k;ND=null;nViewK=undefined;window.scrollTo(0,0)}
else if(a==='olink'){openLink(b.dataset.v);return}
else if(a==='sclr'){const f=b.dataset.for;if(f==='colq')colQ='';else if(f==='q')q='';else if(f==='qsearch')qs='';else if(f==='jq')jq='';else if(f==='stq')stQ='';else if(f==='ipq')ipQ='';else if(f==='hq'){hq='';if(HQP&&!HQP.files)HQP=null}render();const el=$(f);if(el)el.focus();return}
else if(a==='tcNew'){ccEd=null;tcEd={id:null,title:'',list:(userLists()[0]||{}).id||'all',when:'any',done:false,add:true,sort:'due',limit:'6'};homeEdit=true;view='today';window.scrollTo(0,0);setTimeout(()=>{const i=$('tcTitle');if(i)i.focus()})}
else if(a==='tcEdit'){const c=(CFG.taskCards||[]).find(x=>x.id===b.dataset.id);if(c){ccEd=null;tcEd={...c,limit:String(c.limit||6)};window.scrollTo(0,0)}}
else if(a==='tcSet'){const f=b.dataset.f,t=$('tcTitle');if(tcEd){if(t)tcEd.title=t.value;tcEd[f]=f==='done'||f==='add'?!!b.dataset.val:b.dataset.val}}
else if(a==='tcCancel'){tcEd=null}
else if(a==='tcSave'){const t=$('tcTitle');if(tcEd){if(t)tcEd.title=t.value.trim();const c={id:tcEd.id||Date.now().toString(36),title:tcEd.title,list:tcEd.list||'all',when:tcEd.when||'any',done:!!tcEd.done,add:tcEd.add!==false,sort:tcEd.sort||'due',limit:+tcEd.limit||6};
 const l=(CFG.taskCards||[]).filter(x=>x.id!==c.id),i=(CFG.taskCards||[]).findIndex(x=>x.id===c.id);if(i>=0)l.splice(i,0,c);else l.push(c);CFG.taskCards=l;CFG.homeOff=(CFG.homeOff||[]).filter(x=>x!=='tc:'+c.id);CFG.boardOff=(CFG.boardOff||[]).filter(x=>x!=='tc:'+c.id);saveCfg();tcEd=null;toast('Card saved')}}
else if(a==='tcDel'){if(!tcEd||!tcEd.id)return;if(armed!=='tc:'+tcEd.id){armed='tc:'+tcEd.id;render();return}const id=tcEd.id;CFG.taskCards=(CFG.taskCards||[]).filter(x=>x.id!==id);CFG.homeOrder=(CFG.homeOrder||[]).filter(x=>x!=='tc:'+id);CFG.homeOff=(CFG.homeOff||[]).filter(x=>x!=='tc:'+id);saveCfg();tcEd=null;armed=null;toast('Card deleted')}
else if(a==='tcView'){const c=(CFG.taskCards||[]).find(x=>x.id===b.dataset.id);if(c){view='tasks';curList=c.list||'all';edL=false;fromHome=true;window.scrollTo(0,0)}}
else if(a==='tcAdd'){const c=(CFG.taskCards||[]).find(x=>x.id===b.dataset.id),i=document.querySelector(`[data-tca="${CSS.escape(b.dataset.id)}"]`),tt=i&&i.value.trim();if(!c||!tt)return;
 {const n=nlTask(tt);putTasks(tasks().concat([{done:false,title:n.title,due:n.due||(c.list==='today'||c.when==='today'?TD():''),rem:n.rem,proj:n.proj,list:n.list||(SMART.includes(c.list)?'':c.list),rep:n.rep,pri:n.pri,added:TD()}]))}pendingFocus=`[data-tca="${CSS.escape(c.id)}"]`}
else if(a==='ccNew'){tcEd=null;ccEd={id:null,title:'',type:'all',status:'',fav:false,sort:'added',limit:'8'};homeEdit=true;view='today';setTimeout(()=>{const i=$('ccTitle');if(i)i.focus()})}
else if(a==='ccEdit'){const c=(CFG.colCards||[]).find(x=>x.id===b.dataset.id);if(c){tcEd=null;ccEd={...c,limit:String(c.limit||8)};window.scrollTo(0,0)}}
else if(a==='ccSet'){const f=b.dataset.f,t=$('ccTitle');if(t&&ccEd)ccEd.title=t.value;if(ccEd){ccEd[f]=f==='fav'?!!b.dataset.val:b.dataset.val;if(f==='type')ccEd.status=ccEd.status}}
else if(a==='ccCancel'){ccEd=null}
else if(a==='ccSave'){const t=$('ccTitle');if(ccEd){if(t)ccEd.title=t.value.trim();const c={id:ccEd.id||Date.now().toString(36),title:ccEd.title,type:ccEd.type||'all',status:ccEd.status||'',fav:!!ccEd.fav,sort:ccEd.sort||'added',limit:+ccEd.limit||8};
 const l=(CFG.colCards||[]).filter(x=>x.id!==c.id);const i=(CFG.colCards||[]).findIndex(x=>x.id===c.id);if(i>=0)l.splice(i,0,c);else l.push(c);CFG.colCards=l;CFG.homeOff=(CFG.homeOff||[]).filter(x=>x!=='cc:'+c.id);CFG.boardOff=(CFG.boardOff||[]).filter(x=>x!=='cc:'+c.id);saveCfg();ccEd=null;toast('Card saved')}}
else if(a==='ccDel'){if(!ccEd||!ccEd.id)return;if(armed!=='cc:'+ccEd.id){armed='cc:'+ccEd.id;render();return}const id=ccEd.id;CFG.colCards=(CFG.colCards||[]).filter(x=>x.id!==id);CFG.homeOrder=(CFG.homeOrder||[]).filter(x=>x!=='cc:'+id);CFG.homeOff=(CFG.homeOff||[]).filter(x=>x!=='cc:'+id);saveCfg();ccEd=null;armed=null;toast('Card deleted')}
else if(a==='ccView'){const c=(CFG.colCards||[]).find(x=>x.id===b.dataset.id);if(c){view='collections';colSel=null;CD=null;colAdd=false;colType=c.type||'all';colStat=c.status||'';colFav=!!c.fav;colQ='';if(c.sort&&c.sort!=='started'){colSort=CFG.colSort=c.sort;saveCfg()}window.scrollTo(0,0)}}
else if(a==='backHome'){view='today';fromHome=false;window.scrollTo(0,0)}
else if(a==='navAuto'){navAutoSet(!CFG.navAuto);return}
else if(a==='newN'){edN=null;ND=null;tplSel=null;addProp=false;setTimeout(focusNew)}
else if(a==='editJ')edJ=k;
else if(a==='saveJE'){FS[k]=$('je').value;edJ=null}
else if(a==='cancel'){hNew=false;if(view==='notes'&&nmode==='notes'&&edN)setTimeout(focusNew);edN=null;ND=null;tplSel=null;addProp=false;edJ=null;edT=null;ansQ=null;edS=null;addSubT=null;edH=null;HD=freshHD()}
else if(a==='delF'){noteDel(k);return}
else if(a==='addT'){if(!v('tt'))return;const n=nlTask(v('tt'));putTasks(tasks().concat([{done:false,title:n.title,due:v('td')||n.due,rem:v('tr').replace('T',' ')||n.rem,proj:v('tp')||n.proj,list:n.list||($('tl')?v('tl'):''),rep:n.rep,pri:n.pri,added:TD()}]));{const sm=nlSummary(n);if(sm)toast('Task added · '+sm)}if(view==='tasks'&&curList)pendingFocus='#tt'}
else if(a==='tog'){const ts=tasks(),t=ts[i];t.done=!t.done;t.doneOn=t.done?TD():'';if(t.done)t.doing=false;
 if(t.done&&t.rep){const base=t.due||TD(),nd=repNext(base<TD()&&t.rep!=='yearly'&&t.rep!=='monthly'?TD():base,t.rep);ts.push({...t,done:false,doneOn:'',doing:false,due:nd,rem:t.rem?`${nd} ${t.rem.slice(11)}`:'',added:TD(),subs:(t.subs||[]).map(x=>({...x,done:false}))});t.rep='';toast(`Next: ${fmt(nd)}`)}
 putTasks(ts)}
else if(a==='boardTog'){CFG.boards={...(CFG.boards||{})};const md=b.dataset.mode;if(md==='board')CFG.boards[b.dataset.val]=true;else if(md==='matrix')CFG.boards[b.dataset.val]='matrix';else delete CFG.boards[b.dataset.val];saveCfg()}
else if(a==='kMove'){kSet(i,b.dataset.val)}
else if(a==='delT'){if(CFG.confirmTask&&armed!=='task:'+i)armed='task:'+i;else{const ts=tasks();ts.splice(i,1);putTasks(ts);armed=null}}
else if(a==='set'&&!ONB&&b.dataset.s==='homeLayout'){homeLayoutSet(b.dataset.val);return}
else if(a==='set'&&ONB){const s2=b.dataset.s;let val=b.dataset.val;if(s2==='week'||s2==='size')val=+val;CFG[s2]=val;saveCfg();apply();render();onbShow();return}
else if(a==='set'&&b.dataset.s.startsWith('mir:')){const id=b.dataset.s.slice(4),cur=MIRC.map(x=>x[0]).filter(mirOn);CFG.mirWhat=b.dataset.val==='on'?[...new Set([...cur,id])]:cur.filter(x=>x!==id);saveCfg();mirReset()}
else if(a==='set'){const s=b.dataset.s;let val=b.dataset.val;if(s==='week'||s==='size'||(s==='homeCols'&&val!=='auto')||s==='healthCols'||s==='zoom')val=+val;if(typeof DEF[s]==='boolean')val=val==='on';CFG[s]=val;saveCfg();apply()}
else if(a==='resetCfg'){CFG={...DEF};saveCfg();apply()}
else if(a==='wipe'){if(armed==='wipe'){FS={};edN=edJ=curQ=null;try{localStorage.removeItem('daybook.v1')}catch(e){}armed=null;toast('All data erased')}else armed='wipe'}
else if(a==='delQ'){const key='q:'+nq(k);if(armed===key||!CFG.confirmQuestion){deleteQ(k);armed=null}else armed=key}
else if(a==='askGo'){ansQ=k;view='journal';jtab='questions';window.scrollTo(0,0)}
else if(a==='hOpen'){hday=b.dataset.d;view='habits';window.scrollTo(0,0)}
else if(a==='openPj'){curP=k;view='projects';window.scrollTo(0,0)}
else if(a==='hNew'){hNew=!hNew;edH=null;HD=freshHD();if(hNew)setTimeout(()=>{const i=document.querySelector('[data-hd="name"]');if(i)i.focus()})}
else if(a==='newH'){const n=(HD.name||'').trim();if(!n){toast('Give the habit a name');const i=document.querySelector('[data-hd="name"]');if(i)i.focus();return}hdApply();
 if(hdNeedsTarget()&&!(parseFloat(HD.target)>0)){toast('Enter how many');const i=document.querySelector('[data-hd="target"]');if(i)i.focus();return}
 let id=slug(n),c=2;while(FS['habits/'+id+'.md'])id=slug(n)+'-'+c++;

 putH({id,name:n,kind:HD.kind,period:HD.period,health:HD.health,link:HLINK[HD.link]?HD.link:'',symbol:HLINK[HD.link]?HLINK[HD.link].ico:'',emoji:HLINK[HD.link]?HLINK[HD.link].em:'',cmp:HD.cmp,target:parseFloat(HD.target)||0,unit:(HD.unit||'').trim(),after:HD.after||'',created:TD(),log:{}});HD=freshHD();hNew=false;hLinkSync()}
else if(a==='hPrev')hday=dAdd(hday,-1);
else if(a==='hNext'){if(hday<TD())hday=dAdd(hday,1)}
else if(a==='hToday')hday=TD();
else if(a==='hChk'){const x=getH(k),dy=b.dataset.d||hday;if(dy>TD())return;if(x.log[dy]==='yes')delete x.log[dy];else x.log[dy]='yes';putH(x)}
else if(a==='hSet'){const x=getH(k),val=b.dataset.val,dy=b.dataset.d||hday;if(x.log[dy]===val)delete x.log[dy];else x.log[dy]=val;putH(x)}
else if(a==='hLog'){const n=parseFloat(v('hv-'+k));if(isNaN(n)){toast('Enter a number.');return}const x=getH(k);x.log[b.dataset.d||hday]=String(n);putH(x)}
else if(a==='hClr'){const x=getH(k);delete x.log[b.dataset.d||hday];putH(x)}
else if(a==='editH'){const x=getH(k);HD={name:x.name,kind:x.kind,period:x.period,health:x.health,link:x.link||'',cmp:x.cmp,target:x.target?String(x.target):'',unit:x.unit,after:x.after||'',goal:hdGoalOf(x),amode:x.kind==='yesno'&&x.period!=='weekly'?'never':'limit',more:false};edH=k}
else if(a==='saveH'){const x=getH(k),n=(HD.name||'').trim();if(!n)return;hdApply();if(HD.kind!==x.kind){toast('An existing habit can’t switch between yes/no and amounts. Make a new habit instead.');return}if(hdNeedsTarget()&&!(parseFloat(HD.target)>0)){toast('Enter how many');return}x.name=n;x.health=HD.health;x.period=HD.period;x.link=HLINK[HD.link]?HD.link:'';if(x.kind==='number'||x.period==='weekly'){x.cmp=HD.cmp;x.target=parseFloat(HD.target)||0}if(x.kind==='number')x.unit=(HD.unit||'').trim();x.after=HD.after&&HD.after!==x.id&&!hChainOf(HD.after).includes(x.id)?HD.after:'';putH(x);edH=null;HD=freshHD();hLinkSync()}
else if(a==='delH'){if(armed==='habit:'+k){delete FS['habits/'+k+'.md'];armed=null}else armed='habit:'+k}
else if(a==='pin')setPinned(k,!isPinned(k));
else if(a==='homeEdit')homeEdit=!homeEdit;
else if(a==='icoPick'){icoPick=icoPick===b.dataset.id?null:b.dataset.id;pcat=0;pq=''}
else if(a==='icoDone'){icoPick=null;pq=''}
else if(a==='pcat'){pcat=+b.dataset.val;pq=''}
else if(a==='setIco')setIcon(b.dataset.id,'emoji',b.dataset.val);
else if(a==='wideSet'){const id=b.dataset.id,cur=(CFG.navWide||[]).filter(x=>x!==id);CFG.navWide=b.dataset.val==='2'?[...cur,id]:cur;saveCfg()}
else if(a==='wide'){const id=b.dataset.id,cur=CFG.navWide||[];CFG.navWide=cur.includes(id)?cur.filter(x=>x!==id):[...cur,id];saveCfg()}
else if(a==='setSym')setIcon(b.dataset.id,'symbol',b.dataset.val);
else if(a==='symDef')setIcon(b.dataset.id,'symbol',null);
else if(a==='icoDef')setIcon(b.dataset.id,'emoji',null);
else if(a==='tgl'){const g2=b.dataset.g,id=b.dataset.id,key=g2==='tab'?'tabOff':homeOffKey(),cur=g2==='tab'?(CFG.tabOff||[]):homeOff();if(g2==='tab'&&id==='settings')return;CFG[key]=cur.includes(id)?cur.filter(x=>x!==id):[...cur,id];saveCfg()}
else if(a==='mv'){const g2=b.dataset.g,id=b.dataset.id,o=orderOf(g2),i0=o.indexOf(id),i1=i0+(+b.dataset.dir);if(i0<0||i1<0||i1>=o.length)return;[o[i0],o[i1]]=[o[i1],o[i0]];setOrder(g2,o)}
else if(a==='expN'){expd.has(k)?expd.delete(k):expd.add(k)}
else if(a==='editT')edT=i;
else if(a==='subT')addSubT=i;
else if(a==='addS'){const n=v('sin');if(!n)return;const ts=tasks();ts[i].subs.push({done:false,title:n});putTasks(ts)}
else if(a==='togS'){const ts=tasks(),s=ts[i].subs[j];s.done=!s.done;putTasks(ts)}
else if(a==='editS')edS=i+'.'+j;
else if(a==='saveS'){const n=v('esn');if(!n)return;const ts=tasks();ts[i].subs[j].title=n;putTasks(ts);edS=null}
else if(a==='delS'){const ts=tasks();ts[i].subs.splice(j,1);putTasks(ts)}
else if(a==='showDone')showDone=!showDone;
else if(a==='tDet')tDet=!tDet;
else if(a==='fabAdd'){const i=$('tt');if(i){i.scrollIntoView({block:'center',behavior:'smooth'});i.focus()}return}
else if(a==='openList'){curList=b.dataset.val;edL=false;icoPick=null;window.scrollTo(0,0)}
else if(a==='closeList'){curList=null;edL=false;icoPick=null;if(wlFrom)wlReturn()}
else if(a==='editList'){edL=!edL;icoPick=null}
else if(a==='newList'){if(LD){LD=null;if(icoPick==='newlist')icoPick=null}else{LD={name:'',symbol:'list-bullets',emoji:'📋',color:LCOLORS[userLists().length%LCOLORS.length],pinned:'false'};curList=null;setTimeout(()=>{const n=$('ldname');if(n)n.focus()})}window.scrollTo(0,0)}
else if(a==='ldColor'){LD.color=b.dataset.val}
else if(a==='ldPin'){LD.pinned=LD.pinned==='true'?'false':'true'}
else if(a==='ldCancel'){LD=null;if(icoPick==='newlist')icoPick=null}
else if(a==='ldCreate'){let name=(($('ldname')||{}).value||'').trim()||'New list',k2=2;const base=name;while(allLists().some(l=>l.name===name))name=base+' '+k2++;let id=slug(name),c=2;while(SMART.includes(id)||FS[listKey(id)])id=slug(name)+'-'+c++;
 const n=userLists().length;putList({id,name,symbol:LD.symbol,emoji:LD.emoji,color:LD.color,pinned:LD.pinned,order:String(10+n)});LD=null;if(icoPick==='newlist')icoPick=null;curList=id;edL=false;window.scrollTo(0,0);toast('List created')}
else if(a==='lColor'){const l=getList(curList);l.color=b.dataset.val;putList(l)}
else if(a==='lPin'){const l=getList(curList);l.pinned=l.pinned==='true'?'false':'true';putList(l)}
else if(a==='delList'){const id=curList;if(armed==='list:'+id){putTasks(tasks().map(t=>t.list===id?{...t,list:''}:t));delete FS[listKey(id)];curList=null;edL=false;armed=null;toast('List deleted, its tasks are still in All')}else armed='list:'+id}
else if(a==='saveT'){const ts=tasks(),t=ts[i],ti=v('etit');if(!ti)return;t.title=ti;t.due=v('etd');t.rem=v('etr').replace('T',' ');t.proj=v('epj');if($('elst'))t.list=v('elst');t.rep=v('erep');t.pri=v('epri');if(t.rep&&!t.due)t.due=TD();putTasks(ts);edT=null}
else if(a==='rDone'){const ts=tasks();ts[i].done=true;ts[i].doneOn=TD();putTasks(ts)}
else if(a==='rOk'){FIRED.push(rkey(tasks()[i]));saveFired()}
else if(a==='rSnz'){const ts=tasks();ts[i].rem=stamp(new Date(Date.now()+600000));putTasks(ts)}
else if(a==='notif'){if(TAURI){toast('Desktop notifications are on');return}try{Notification.requestPermission().then(p=>{toast('Desktop notifications: '+p);render()})}catch(e){toast('Desktop notifications aren’t available in this view.')}return}
else if(a==='notesSearch'){view='notes';nmode='notes';q=hq.trim();edN=null;ND=null;window.scrollTo(0,0)}
else if(a==='listGo'){view='tasks';curList=b.dataset.val;edL=false;window.scrollTo(0,0)}
else if(a==='evGo'){view='calendar';sel=b.dataset.d;cm=pd(sel);cm.setDate(1);window.scrollTo(0,0)}
else if(a==='jGo'){view='journal';jtab='entries';window.scrollTo(0,0)}
else if(a==='qGo'){view='journal';jtab='questions';qs=hq.trim();window.scrollTo(0,0)}
else if(a==='tplGo'){view='notes';nmode='templates';edN=k;ND=null;window.scrollTo(0,0)}
else if(a==='cmdReset'){CFG.cmdKeys={};saveCfg()}
else if(a==='cmdPick'){hq='/'+cmdWords(CMDS.find(c=>c.id===b.dataset.val))[0]+' ';render();const i=$('hq');if(i){i.focus();i.setSelectionRange(hq.length,hq.length)}return}
else if(a==='newP'){const n=v('pnm');if(!n)return;let id=slug(n),c=2;while(FS['projects/'+id+'.md'])id=slug(n)+'-'+c++;putP({id,name:n,status:'active',created:TD(),desc:'',notes:[],symbol:PN.symbol,emoji:PN.emoji});PN={symbol:'',emoji:'',name:''};icoPick=null;if($('ptpl')&&v('ptpl'))ptApply(id,v('ptpl'));curP=id;pNew=false;pDone=false;pNoteNew=false}
else if(a==='revNav'){const t=TD(),base=revMonth||(+t.slice(8)<5?dAdd(t,-6).slice(0,7):t.slice(0,7)),d=new Date(+base.slice(0,4),+base.slice(5)-1+(+b.dataset.val),1);revMonth=`${d.getFullYear()}-${pad(d.getMonth()+1)}`}
else if(a==='hYearT'){hYear.has(k)?hYear.delete(k):hYear.add(k)}
else if(a==='msNewT'){msNew=!msNew;if(msNew)pendingFocus='#mst'}
else if(a==='msAdd'){const tt=v('mst'),dd=v('msd');if(!tt||!dd){toast('Add a name and a date');return}const p=getP(curP);p.ms=[...(p.ms||[]),{done:false,d:dd,t:tt}];putP(p);msNew=false}
else if(a==='msTog'){const p=getP(curP),m=(p.ms||[])[i];if(m){m.done=!m.done;putP(p)}}
else if(a==='msDel'){const p=getP(curP);(p.ms||[]).splice(i,1);putP(p)}
else if(a==='ptSave'){const p=getP(curP);ptSave(p);toast(`Template “${p.name}” saved`)}
else if(a==='pfLinkT'){pfLink=!pfLink;pfPick=false;if(pfLink)pendingFocus='#pflink'}
else if(a==='pfLinkAdd'){const u=v('pflink');if(!u)return;pfAddLink(curP,u);pfLink=false;return}
else if(a==='pfAdd'){pfPickFiles(curP,b.dataset.val);return}
else if(a==='pfPickT'){pfPick=!pfPick;pfLink=false;pfQ='';if(pfPick)pendingFocus='#pfq'}
else if(a==='pfToggle'){const[kd,ii]=b.dataset.val.split(':'),x=stRead(kd)[+ii];if(x){const p=getP(curP),key=pfKey({...x,k:kd});if((p.files||[]).some(f=>pfKey(f)===key)){p.files=p.files.filter(f=>pfKey(f)!==key);putP(p)}else pfAttach(curP,[{...x,k:kd}])}pendingFocus=null}
else if(a==='pfRemove'){const p=getP(curP);p.files=(p.files||[]).filter(f=>pfKey(f)!==b.dataset.val);putP(p);toast('Removed from the project (still in Storage)')}
else if(a==='pNewT'){pNew=!pNew;PN={symbol:'',emoji:'',name:''};if(icoPick==='newproj')icoPick=null;if(pNew)pendingFocus='#pnm'}
else if(a==='pDoneT'){pDone=!pDone}
else if(a==='pNoteT'){pNoteNew=!pNoteNew;if(pNoteNew)pendingFocus='#pnt'}
else if(a==='pColor'){const t=$('pen'),d=$('ped'),pv={n:t&&t.value,d:d&&d.value};pEdColor=b.dataset.val;setTimeout(()=>{if($('pen')&&pv.n!=null)$('pen').value=pv.n;if($('ped')&&pv.d!=null)$('ped').value=pv.d})}
else if(a==='openP'){pfLink=false;pfPick=false;pfQ='';curP=k;edP=false;pDone=false;pNoteNew=false;pEdColor=null;window.scrollTo(0,0)}
else if(a==='closeP'){curP=null;edP=false;edT=null;if(wlFrom)wlReturn()}
else if(a==='editP'){edP=!edP;pEdColor=null}
else if(a==='saveP'){const p=getP(curP),n=v('pen');if(!n)return;p.name=n;p.desc=$('ped')?$('ped').value.trim():p.desc;if(pEdColor)p.color=pEdColor;putP(p);edP=false;pEdColor=null;toast('Project saved')}
else if(a==='pStat'){const p=getP(curP),t=$('pen'),d=$('ped'),pv={n:t&&t.value,d:d&&d.value};p.status=p.status==='done'?'active':'done';putP(p);setTimeout(()=>{if($('pen')&&pv.n!=null)$('pen').value=pv.n;if($('ped')&&pv.d!=null)$('ped').value=pv.d})}
else if(a==='delP'){projDel(k||curP);return}
else if(a==='addPT'){if(!v('ptt'))return;const n=nlTask(v('ptt'));putTasks(tasks().concat([{done:false,title:n.title,due:v('ptd')||n.due,rem:n.rem,proj:curP,list:n.list,rep:n.rep,pri:n.pri,added:TD()}]));pendingFocus='#ptt'}
else if(a==='linkT'){if(v('lt')==='')return;const ts=tasks();ts[+v('lt')].proj=curP;putTasks(ts)}
else if(a==='newPN'){const t=v('pnt'),bd=$('pnb').value.trim();if(!t&&!bd)return;pNoteNew=false;const nk=noteKeyFor('notes/',t||bd,TD());FS[nk]=`---\ncreated: ${TD()}\n---\n# ${t||'Untitled'}\n\n${bd}\n`;const p=getP(curP);p.notes.push(nk);putP(p)}
else if(a==='linkN'){if(!v('ln'))return;const p=getP(curP);p.notes.push(v('ln'));putP(p)}
else if(a==='unlinkN'){const p=getP(curP);p.notes=p.notes.filter(x=>x!==k);putP(p)}
else if(a==='openN'){view='notes';edN=k;window.scrollTo(0,0)}
else if(a==='day')sel=b.dataset.d;
else if(a==='prev')cm.setMonth(cm.getMonth()-1);
else if(a==='next')cm.setMonth(cm.getMonth()+1);
else if(a==='calPrev'||a==='calNext'){const dir=a==='calNext'?1:-1,md=CFG.calView||'month';if(md==='month'){cm.setMonth(cm.getMonth()+dir)}else{sel=dAdd(sel,dir*(md==='week'?7:1));cm=pd(sel);cm.setDate(1)}}
else if(a==='calToday'){sel=TD();cm=pd(sel);cm.setDate(1);calTop=null}
else if(a==='evNew'){EV={i:null,date:b.dataset.d||sel,title:'',start:'',end:'',allDay:true};pendingFocus='#evt'}
else if(a==='evEdit'){if(i<0){bdOpen=true;window.scrollTo(0,0);return render()}const e=events()[i];if(e){EV={i:e.i,date:e.date,title:e.title,start:e.start,end:e.end,allDay:!e.start,rep:e.rep||'',every:e.every||1,days:(e.days||[]).slice()};sel=e.date;pendingFocus='#evt'}}
else if(a==='hcColor'){const r=b.getBoundingClientRect(),id=b.dataset.id;setTimeout(()=>openCtx('hc:'+id,r.left,r.bottom+6),0);return}
else if(a==='sndToggle'){sndPlay(!SND.on);if(view==='music')render();return}
else if(a==='radPick'){const id=b.dataset.val;CFG.radio=CFG.radio===id?'':id;sndSave();if(!CFG.radio){radioStop();sndPaint()}else if(!SND.on){SND.on=true;SNDS.forEach(([x])=>{if(sndVol(x)>0)sndStart(x)});radioStart()}else radioStart();if(view==='music')render();return}
else if(a==='sndPick'){const id=b.dataset.val,v=sndVol(id);CFG.sounds={...(CFG.sounds||{}),[id]:v>0?0:.5};sndSave();if(!SND.on&&v<=0)sndPlay(true);else sndLevel(id);sndPaint();if(view==='music')render();return}
else if(a==='npToggle'){npToggle();return}
else if(a==='npClear'){CFG.notifs=[];saveCfg();npShow();return}
else if(a==='npDel'){CFG.notifs=(CFG.notifs||[]).filter(x=>x.id!==b.dataset.k);saveCfg();npShow();return}
else if(a==='npGo'){const x=b.dataset.h==='1'?(CFG.notifs||[]).find(y=>y.id===b.dataset.k):npToday()[i];const g=x&&x.go;npToggle(false);if(g&&g.view){flushNote&&flushNote();view=g.view;if(g.list){curList=g.list;edL=false}hq='';window.scrollTo(0,0);render()}return}
else if(a==='trashRestore'){if(FS[k]){const nk=noteRestore(k);save();render();toast(`Restored to ${/^archive\//.test(nk)?'Archived':/^templates\//.test(nk)?'Templates':'Notes'}`)}return}
else if(a==='trashDel'){(async()=>{if(!FS[k])return;if(!await askConfirm({title:'Delete forever?',text:`“${wlPlain(noteTitle(k))}” will be deleted permanently. This can’t be undone.`}))return;delete FS[k];save();render();toast('Deleted permanently')})();return}
else if(a==='trashEmpty'){(async()=>{const ks=keys('trash/');if(!ks.length)return;if(!await askConfirm({title:'Empty Trash?',text:`${ks.length} note${ks.length===1?'':'s'} will be deleted permanently. This can’t be undone.`,ok:'Empty Trash'}))return;ks.forEach(x=>delete FS[x]);save();render();toast('Trash emptied')})();return}
else if(a==='homeLayout'){homeLayoutSet(b.dataset.val);return}
else if(a==='hbDel'){const bid=b.dataset.val,B=HB(),p=B.items[bid];if(!p)return;const isMsg=bid.startsWith('msg:'),id=bid.slice(4),txt=isMsg?boardMsgs()[id]:'';
 if(isMsg){const o=boardMsgs();delete o[id];boardMsgsWrite(o);save()}delete B.items[bid];saveCfg();render();
 toastAct(isMsg?'Message deleted':'Image removed from the board',[['Undo',()=>{if(isMsg){const o=boardMsgs();o[id]=txt||'';boardMsgsWrite(o);save()}HB().items[bid]=p;saveCfg();render()}]]);return}
else if(a==='hbAdd'){hbAdd(b.dataset.val);return}
else if(a==='wxSet'){view='settings';SETG='general';setQ='';render();setTimeout(()=>{const i=$('wcity');if(i){i.scrollIntoView({block:'center'});i.focus()}},50);return}
else if(a==='wxRetry'){wxLoad(true);return}
else if(a==='wxFind'){wxFind(v('wcity'));return}
else if(a==='hqSave'){hqSave();return}
else if(a==='hqCancel'){hqClear()}
else if(a==='hqUnstage'){if(HQP&&HQP.files){const x=HQP.files.splice(i,1)[0];if(x&&x.url)URL.revokeObjectURL(x.url);if(!HQP.files.length)HQP=null}}
else if(a==='hqOpenLink'){const u=stUrl(hq.trim());view='files';stTab='links';stQ=host(u);hq='';HQP=null;window.scrollTo(0,0)}
else if(a==='evDay'){evSync();const n=+b.dataset.n,cur=(EV.days||[]).length?EV.days.slice():[pd(EV.date||TD()).getDay()];EV.days=cur.includes(n)?cur.filter(x=>x!==n):[...cur,n];if(!EV.days.length)EV.days=[n]}
else if(a==='evAllDay'){evSync();EV.allDay=!EV.allDay;if(!EV.allDay&&!EV.start){EV.start='09:00';EV.end='10:00'}}
else if(a==='evCancel'){EV=null}
else if(a==='bdT'){bdOpen=!bdOpen;if(bdOpen)pendingFocus='#bdname'}
else if(a==='bdAdd'){const n=v('bdname'),d=v('bddate');if(!n||!d){toast('Add a name and a date');return}bdWrite([...bdays(),{m:d.slice(5,7),d:d.slice(8,10),name:n,y:$('bdnoy')&&$('bdnoy').checked?'':d.slice(0,4)}]);toast('Birthday saved');pendingFocus='#bdname'}
else if(a==='bdDel'){const l=bdays();l.splice(i,1);bdWrite(l)}
else if(a==='icsImp'){const f=document.createElement('input');f.type='file';f.accept='.ics,text/calendar';f.onchange=async()=>{try{const n=icsImport(await f.files[0].text());save();render();toast(n?`${n} event${n===1?'':'s'} imported`:'No new events in that file')}catch(e){toast('Could not read that calendar file')}};f.click();return}
else if(a==='evSave'){evSync();const ttl=(EV.title||'').trim();if(!ttl){toast('Give the event a title');pendingFocus='#evt';return}
 const st=EV.allDay?'':EV.start,en=EV.allDay||!st||!EV.end||mins(EV.end)<=mins(st)?'':EV.end,o={date:EV.date||sel,start:st,end:en,title:ttl.replace(/\n/g,' '),rep:EV.rep||'',every:EV.rep==='weekly'?EV.every||1:1,days:EV.rep==='weekly'?EV.days||[]:[]};
 const es=events();if(EV.i!=null&&es[EV.i])es[EV.i]={...es[EV.i],...o};else es.push(o);putEvents(es);sel=o.date;cm=pd(sel);cm.setDate(1);EV=null;toast('Event saved')}
else if(a==='evDel'){const es=events();if(EV&&EV.i!=null&&es[EV.i]){es.splice(EV.i,1);putEvents(es);toast('Event deleted')}EV=null}
else if(a==='addE'){if(!v('et'))return;const x=v('et').match(ETM);putEvents(events().concat([x?{date:sel,start:h5(x[1]),end:x[2]&&mins(h5(x[2]))>mins(h5(x[1]))?h5(x[2]):'',title:x[3]}:{date:sel,start:'',end:'',title:v('et')}]))}
else if(a==='delE'){const es=events();es.splice(i,1);putEvents(es);EV=null}
let dr={};if(a!=='nav')['jt','jloc','qa0','tt'].forEach(x=>{if($(x)&&$(x).value)dr[x]=$(x).value});
if(a==='saveJ'){delete dr.jt;delete dr.jloc}if(a==='addT')delete dr.tt;if(a==='saveQ')delete dr.qa0;
if(view!=='today')hq='';save();render();for(const x in dr)if($(x))$(x).value=dr[x];const f=$('sin')||$('esn');if(f)f.focus();if(pendingFocus){const el=document.querySelector(pendingFocus);pendingFocus=null;if(el)el.focus()}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&e.target.id==='sin'){addSubT=null;render();return}
 const ds=e.target.dataset||{};if(e.key==='Enter'&&ds.tca){e.preventDefault();const bt=document.querySelector(`[data-act="tcAdd"][data-id="${CSS.escape(ds.tca)}"]`);if(bt)bt.click();return}
 if(e.key==='Enter'&&ds.hv){e.preventDefault();const bt=document.querySelector('[data-act="hLog"][data-k="'+ds.hv+'"]');if(bt)bt.click();return}
 if(e.key==='Enter'&&ds.hd==='name'){e.preventDefault();const bt=document.querySelector('[data-act="newH"],[data-act="saveH"]');if(bt)bt.click();return}if(e.key==='Enter'&&(e.target.id==='tmmin'||e.target.id==='tmlab')){e.preventDefault();const bt=document.querySelector('.tmnew [data-act="tmStart"]');if(bt)bt.click();return}const M={mst:'msAdd',msd:'msAdd',altime:'alAdd',allab:'alAdd',evt:'evSave',tt:'addT',td:'addT',tr:'addT',ptt:'addPT',ptd:'addPT',pnm:'newP',et:'addE',etit:'saveT',etd:'saveT',etr:'saveT'};if(e.key==='Enter'&&M[e.target.id]){e.preventDefault();const bt=document.querySelector('[data-act="'+M[e.target.id]+'"]');if(bt)bt.click();return}if(e.key==='Enter'&&(e.target.id==='sin'||e.target.id==='esn')){e.preventDefault();const b=e.target.parentElement.querySelector('[data-act]');if(b)b.click()}});
document.addEventListener('input',e=>{const ds=e.target.dataset||{};
 if(ds.cmd!==undefined){const id=ds.cmd,words=parseWords(e.target.value),err=$('cmderr-'+id),clash=words.filter(w=>CMDS.some(c=>c.id!==id&&cmdWords(c).includes(w)));
  if(!words.length){if(err)err.textContent='Add at least one word.';return}
  if(clash.length){if(err)err.textContent=`Already used by another command: ${clash.join(', ')}`;return}
  if(err)err.textContent='';CFG.cmdKeys={...CFG.cmdKeys,[id]:words};saveCfg();return}
 if(e.target.id==='hq'){const was=!!hq.trim();hq=e.target.value;if(!!hq.trim()!==was)rerenderKeep();else{const r=$('hres');if(r){r.innerHTML=homeResults();hydrateImgs()}}return}
 if(e.target.id==='nb'&&ND){ND.body=e.target.value;noteChanged('type');return}
 if(e.target.id==='ntitle'&&ND){ND.title=e.target.value;noteChanged('type');return}
 if(ds.np!==undefined&&ND){const box=e.target.type==='checkbox';ND.fm[ds.np]=box?String(e.target.checked):e.target.value;if(box){noteChanged('now');rerenderKeep()}else noteChanged('type');return}
 if(ds.npadd!==undefined&&e.inputType==='insertReplacementText'){addChip(e.target);return}
 if(e.target.id==='ntpl'){ND=null;tplSel=e.target.value;render();focusNew();return}
 if(ds.pq!==undefined){pq=e.target.value;$('pgrid').innerHTML=pickGrid(e.target.dataset.pq);$('pgrid').scrollTop=0;
  document.querySelectorAll('.pcats button').forEach(x=>x.classList.toggle('on',!pq&&+x.dataset.val===pcat));return}
 if(e.target.dataset&&e.target.dataset.ico!==undefined){const id=e.target.dataset.ico;setIcon(id,'emoji',Array.from(e.target.value.replace(/\s/g,'')).slice(0,3).join(''));if(id.includes(':'))save();else renderNav();return}
 if(e.target.id==='ldname'&&LD){LD.name=e.target.value;return}
 if(e.target.id==='catname'&&catEd){catEd.name=e.target.value;return}
 if(e.target.id==='lname'&&curList){const l=getList(curList);l.name=e.target.value.trim()||l.name;putList(l);save();return}
 const hd=e.target.dataset&&e.target.dataset.hd;if(hd){HD[hd]=e.target.type==='checkbox'?e.target.checked:e.target.value;{const sm=$('hgsum');if(sm)sm.textContent=hdSummary()}if(e.target.tagName==='SELECT'){if((hd==='health'||hd==='kind'||hd==='period')&&(HD.kind==='number'||HD.period==='weekly'))HD.cmp=HD.health==='unhealthy'?'lessthan':'atleast';render()}return}
 if(e.target.id==='sname'){CFG.name=e.target.value;saveCfg();return}if(e.target.id==='qsearch'){qs=e.target.value;const p=qs.length;render();const el=$('qsearch');el.focus();el.setSelectionRange(p,p);return}if(e.target.id==='q'){q=e.target.value;const p=q.length;render();const el=$('q');el.focus();el.setSelectionRange(p,p)}});
/* Right-click menu. On notes: Pin / Unpin, Archive / Unarchive and Delete.
   On task lists (ctxK is "list:<id>"): Edit details, Pin / Unpin and Delete (not for the built-in lists). */
let ctxK=null,ctxArm=false;
const colCtx=()=>{const it=colRead(ctxK.slice(4)),t=ctype(it.type);
 return `<button role="menuitem" data-ctx="copen">Open</button><button role="menuitem" data-ctx="cfav">${it.fav?'Remove from favorites':'Add to favorites'}</button><p class="ctxlab">Status</p>${CSTAT.map((s,i)=>`<button role="menuitemradio" aria-checked="${it.status===s}" data-ctx="cstat" data-v="${s}"><span class="ctxchk">${it.status===s?'✓':''}</span>${t.st[i]}</button>`).join('')}
${fieldOn(it.type,'rating')?`<p class="ctxlab">Rating</p><div class="ctxstars" role="group" aria-label="Rating">${[1,2,3,4,5].map(n=>`<button class="star ${n<=it.rating?'on':''}" data-ctx="crate" data-v="${n}" aria-label="${n} star${n>1?'s':''}">★</button>`).join('')}</div>`:''}
<hr class="ctxhr"><button role="menuitem" data-ctx="ccover">${it.cover?'Change cover…':'Add cover…'}</button>${/^https?:\/\//.test(it.source)?`<button role="menuitem" data-ctx="clink">Open on ${esc(hostOf(it.source))}</button>`:''}<button role="menuitem" class="danger" data-ctx="cdel">Delete…</button>`};
// On a section in the sidebar (ctxK is "nav:<id>"): 1 col / 2 col (Cards layout), Change icon and Hide section.
const navCtx=()=>{const id=ctxK.slice(4),w=(CFG.navWide||[]).includes(id),cnt=!(CFG.navNoCount||[]).includes(id),col=secColor(id),own=!!(CFG.navColors||{})[id];
 return `${CFG.navLayout==='cards'?`<p class="ctxlab">Card width</p><button role="menuitemradio" aria-checked="${!w}" data-ctx="nwide" data-v="1"><span class="ctxchk">${w?'':'✓'}</span>1 col</button><button role="menuitemradio" aria-checked="${w}" data-ctx="nwide" data-v="2"><span class="ctxchk">${w?'✓':''}</span>2 col</button>`:''}${['cards','icons','grid'].includes(CFG.navLayout)?`
${navCount(id)!==''?`<button role="menuitemcheckbox" aria-checked="${cnt}" data-ctx="ncount"><span class="ctxchk">${cnt?'✓':''}</span>Show item count</button>`:''}
<p class="ctxlab">Color</p><div class="ctxsw">${LCOLORS.map(c=>`<button class="lsw ${col===c?'on':''}" data-ctx="ncolor" data-v="${c}" style="background:${c}" aria-label="Color ${c}" aria-pressed="${col===c}"></button>`).join('')}${swCustom(own&&!LCOLORS.includes(col)?col:'',`data-navcolor="${id}"`,'lsw')}</div>${own?'<button role="menuitem" data-ctx="ncolreset">Default color</button>':''}`:''}
<button role="menuitem" data-ctx="nicon">Change icon…</button><hr class="ctxhr">${layoutItems()}${CFG.navLayout!=='top'?`<hr class="ctxhr">${sidebarItems()}`:''}${id==='settings'?'':`<hr class="ctxhr"><button role="menuitem" class="danger" data-ctx="nhide">Turn off <span>${esc((tabList().find(t=>t[0]===id)||[0,"section"])[1])}</span></button>`}`};
// On a note category (ctxK is "cat:<name>"): Edit and Delete (it is removed from its notes; the notes stay).
let ctxCatSc='notes';
const catCtx=()=>{const n=ctxK.slice(4),e=allCats(ctxCatSc).get(n.toLowerCase()),c=e?e.keys.length:0,w=ctxCatSc==='journal'?'day':'note';
 return `<button role="menuitem" data-ctx="catedit">Edit category…</button><button role="menuitem" class="danger" data-ctx="catdel">${ctxArm?(c?`Click again to remove it from ${c} ${w}${c===1?'':'s'}`:'Click again to delete'):'Delete category'}</button>`};
// Layout choices offered in both sidebar menus.
const NAVLAYOUTS=[['side','Sidebar'],['cards','Cards'],['grid','Icon grid'],['icons','Icons'],['top','Top bar']];
const layoutItems=()=>`<p class="ctxlab">Layout</p>${NAVLAYOUTS.map(([v,l])=>`<button role="menuitemradio" aria-checked="${CFG.navLayout===v}" data-ctx="nlayout" data-v="${v}"><span class="ctxchk">${CFG.navLayout===v?'✓':''}</span>${l}</button>`).join('')}`;
// On the sidebar itself (ctxK is "navbar"): keep it shown or let it hide until hovered.
const sidebarItems=()=>`<p class="ctxlab">Sidebar</p><button role="menuitemradio" aria-checked="${!CFG.navAuto}" data-ctx="nbshow"><span class="ctxchk">${CFG.navAuto?'':'✓'}</span>Always show</button><button role="menuitemradio" aria-checked="${!!CFG.navAuto}" data-ctx="nbhide"><span class="ctxchk">${CFG.navAuto?'✓':''}</span>Hide, show on hover</button>`;
const navbarCtx=()=>`${layoutItems()}<hr class="ctxhr">${sidebarItems()}`;
/* On a task (ctxK is "task:<index>"): done, important (high priority), in progress, focus session, edit, subtask,
   due date, list and delete. */
const taskCtx=()=>{const t=tasks()[+ctxK.slice(5)];if(!t)return '';const d=TD(),pf=prioToday(),inF=pf.includes(tKey(t)),ck=on=>`<span class="ctxchk">${on?'✓':''}</span>`,ls=userLists();
 const pill=(a,v,l,on)=>`<button data-ctx="${a}" data-v="${v}" class="${on?'on':''}" aria-pressed="${on}">${l}</button>`;
 return `<button role="menuitem" data-ctx="tdone">${t.done?'Mark as not done':'Mark as done'}</button><button role="menuitem" data-ctx="timp">${t.pri==='high'?'Not important':'Mark as important'}</button>${t.done?'':`<button role="menuitem" data-ctx="tdoing">${t.doing?'Not in progress':'Mark as in progress'}</button><button role="menuitem" data-ctx="tfocus" ${!inF&&pf.length>=3?'disabled title="The focus session already has 3 tasks"':''}>${inF?'Remove from focus session':'Add to focus session'}</button>`}
<button role="menuitem" data-ctx="tedit">Edit…</button><button role="menuitem" data-ctx="tsub">Add a subtask</button>
<p class="ctxlab">Due</p><div class="ctxpills" role="group" aria-label="Due date">${pill('tdue',d,'Today',t.due===d)}${pill('tdue',dAdd(d,1),'Tomorrow',t.due===dAdd(d,1))}${pill('tdue',dAdd(d,7),'Next week',t.due===dAdd(d,7))}${pill('tdue','','None',!t.due)}</div>
${ls.length?`<p class="ctxlab">List</p>${[{id:'',name:'No list'},...ls].map(l=>`<button role="menuitemradio" aria-checked="${(t.list||'')===l.id}" data-ctx="tlist" data-v="${esc(l.id)}">${ck((t.list||'')===l.id)}<span data-notr>${esc(l.name)}</span></button>`).join('')}`:''}
<hr class="ctxhr"><button role="menuitem" class="danger" data-ctx="tdel">${ctxArm?'Click again to delete':'Delete task'}</button>`};
// Runs a task action through the normal click handler (so repeats, toasts and re-rendering work the same).
const runAct=(act,i)=>{const x=document.createElement('button');x.hidden=true;x.dataset.act=act;x.dataset.i=i;document.body.appendChild(x);x.click();x.remove()};
function taskCtxAct(i,a,v){const ts=tasks(),t=ts[i];if(!t){closeCtx();return}
 if(a==='tdel'&&!ctxArm){ctxArm=true;const m=$('ctx');m.innerHTML=ctxHTML();m.querySelector('[data-ctx="tdel"]').focus();return}
 closeCtx();
 if(a==='tdone'){runAct('tog',i);return}if(a==='tedit'){runAct('editT',i);return}if(a==='tsub'){runAct('subT',i);return}
 if(a==='tdoing'){t.doing=!t.doing;toast(t.doing?'In progress':'No longer in progress')}
 else if(a==='tfocus'){const ids=prioToday().slice(),k=tKey(t);CFG.prio={d:TD(),ids:ids.includes(k)?ids.filter(x=>x!==k):[...ids,k].slice(0,3)};saveCfg();toast(ids.includes(k)?'Removed from focus session':'Added to focus session');render();return}
 else if(a==='tdue'){const hadRep=!v&&!!t.rep;t.due=v;if(hadRep)t.rep='';toast(v?`Due ${v===TD()?'today':v===dAdd(TD(),1)?'tomorrow':fmt(v)}`:hadRep?'Due date removed · it no longer repeats':'Due date removed')}
 else if(a==='timp'){t.pri=t.pri==='high'?'':'high';toast(t.pri?'Marked as important':'No longer important')}
 else if(a==='tlist'){t.list=v;toast(v?`Moved to ${getList(v).name}`:'Removed from its list')}
 else if(a==='tdel'){ts.splice(i,1);toast('Task deleted')}
 putTasks(ts);save();render()}
/* On a project card (ctxK is "pj:<id>"): open, settings, icon, color, complete / active, delete. */
const projCtx=()=>{const p=getP(ctxK.slice(3)),c=pColor(p),own=/^#[0-9a-f]{6}$/i.test(p.color||'')&&!LCOLORS.includes(p.color)?p.color:'';
 return `<button role="menuitem" data-ctx="pjopen">Open</button><button role="menuitem" data-ctx="pjedit">Project settings</button><button role="menuitem" data-ctx="pjicon">Change icon…</button>
<p class="ctxlab">Color</p><div class="ctxsw">${LCOLORS.map(x=>`<button class="lsw ${c===x?'on':''}" data-ctx="pjcolor" data-v="${x}" style="background:${x}" aria-label="Color ${x}" aria-pressed="${c===x}"></button>`).join('')}${swCustom(own,`data-pcolor="${esc(p.id)}"`,'lsw')}</div>
<hr class="ctxhr"><button role="menuitem" data-ctx="pjdone">${p.status==='done'?'Mark as active':'Mark as complete'}</button><button role="menuitem" class="danger" data-ctx="pjdel">Delete project…</button>`};
// Deleting a project: its tasks lose the project and its notes stay where they are.
async function projDel(id){const p=getP(id);if(!FS['projects/'+id+'.md'])return;
 if(CFG.confirmProject!==false&&!await askConfirm({title:'Delete this project?',text:`“${p.name}” will be deleted. Its tasks and notes are kept.`}))return;
 putTasks(tasks().map(t=>t.proj===id?{...t,proj:''}:t));delete FS['projects/'+id+'.md'];if(curP===id){curP=null;edP=false}armed=null;save();render();toast('Project deleted')}
const ctxHTML=()=>ctxK==='navbar'?navbarCtx():ctxK.startsWith('pj:')?projCtx():ctxK.startsWith('bi:')?hbCtx():ctxK.startsWith('hc:')?homeCtx():ctxK.startsWith('task:')?taskCtx():ctxK.startsWith('st:')?stCtx():ctxK.startsWith('cat:')?catCtx():ctxK.startsWith('nav:')?navCtx():ctxK.startsWith('col:')?colCtx():ctxK.startsWith('list:')?(l=>`<button role="menuitem" data-ctx="ledit">Edit details</button><button role="menuitem" data-ctx="lpin">${l.pinned==='true'?'Unpin':'Pin'}</button>${SMART.includes(l.id)?'':`<button role="menuitem" class="danger" data-ctx="ldel">${ctxArm?'Click again to delete':'Delete list'}</button>`}`)(getList(ctxK.slice(5))):`<button role="menuitem" data-ctx="pin">${isPinned(ctxK)?'Unpin':'Pin'}</button><button role="menuitem" data-ctx="arch">${isArch(ctxK)?'Unarchive':'Archive'}</button><button role="menuitem" class="danger" data-ctx="del">${trashable(ctxK)?'Move to Trash…':'Delete…'}</button>`;
// Saves a copy of a Storage image or PDF, named after its title (the desktop app asks where to save it).
async function stDownload(x){const ext=(x.att.match(/\.[a-z0-9]+$/i)||[''])[0],name=((x.title||'').replace(/[\\/:*?"<>|]+/g,' ').trim()||'file')+ext;
 try{if(TAURI&&(ACCT||STORE_DB)){const u=await attPlain(x.att);if(u&&await TAURI.invoke('save_download',{name,data:u8b64(u)}))toast('Saved '+name);return}if(TAURI){if(await TAURI.invoke('export_attachment',{name:x.att,saveAs:name}))toast('Saved '+name);return}
  const u=await attPlain(x.att);if(!u){toast('That file is missing');return}await dl(name,new Blob([u],{type:attMime(x.att)}))}catch(e){if(e&&e.code==='declined')return;toast('Could not save: '+(e.message||e))}}
function stCtxAct(id,a){const[k,i]=id.split(':'),l=stRead(k),x=l[+i];if(!x){closeCtx();return}
 if(a==='stdel'){stConfirmDel(k,+i);return}
 closeCtx();
 if(a==='stopen'){if(k==='links')openLink(x.url);else if(k==='pdfs')stOpenPdf(x.att);else{const set=stRead('images').map(y=>y.att);LB={set,i:Math.max(0,set.indexOf(x.att))};lbShow()}return}
 if(a==='stdl'){stDownload(x);return}
 if(a==='stcopy'){try{navigator.clipboard.writeText(x.url).then(()=>toast('Link copied'))}catch(e){toast('Could not copy')}return}
 if(a==='stpin'){x.pin=!x.pin;stWrite(k,l);toast(x.pin?'Pinned to top':'Unpinned')}
 else if(a==='stfav'){x.fav=!x.fav;stWrite(k,l);toast(x.fav?'Added to favorites':'Removed from favorites')}
 else if(a==='stlater'){x.later=!x.later;stWrite(k,l);toast(x.later?'Added to Read later':'Marked as read')}
 else if(a==='stmove'){stMove=id;stRen=null;save();render();const r=$('stfold');if(r){r.focus();r.select()}return}
 else if(a==='stren'){stRen=id;save();render();const r=$('stren');if(r){r.focus();r.select()}return}
 else if(a==='stdel'){l.splice(+i,1);stWrite(k,l);if(stPrev===x.att)stPrev=null;toast(k==='links'?'Link deleted':k==='images'?'Image deleted':'PDF deleted')}
 save();render()}
const closeCtx=()=>{const m=$('ctx');if(m)m.hidden=true;ctxK=null;ctxArm=false};
function openCtx(k,x,y){ctxK=k;ctxArm=false;const m=$('ctx');m.innerHTML=ctxHTML();m.hidden=false;
 const r=m.getBoundingClientRect(),z=cz();m.style.left=Math.max(8,Math.min(x,innerWidth-r.width-8))/z+'px';m.style.top=Math.max(8,Math.min(y,innerHeight-r.height-8))/z+'px';m.tabIndex=-1;m.focus({preventScroll:true})}
document.addEventListener('contextmenu',e=>{const nb=e.target.closest&&e.target.closest('#nav .navb');if(nb){e.preventDefault();openCtx('nav:'+nb.dataset.v,e.clientX,e.clientY);return}
 const na=e.target.closest&&e.target.closest('#nav,#navgrip,#navedge');if(na&&CFG.navLayout!=='top'){e.preventDefault();openCtx('navbar',e.clientX,e.clientY);return}
 const cb=e.target.closest&&e.target.closest('[data-cat]');if(cb){e.preventDefault();ctxCatSc=cb.dataset.csc||'notes';openCtx('cat:'+cb.dataset.cat,e.clientX,e.clientY);return}
 const tk=e.target.closest&&e.target.closest('[data-tk]');if(tk&&!e.target.closest('input,textarea')){e.preventDefault();openCtx('task:'+tk.dataset.tk,e.clientX,e.clientY);return}
 const pjc=e.target.closest&&e.target.closest('[data-pk]');if(pjc){e.preventDefault();openCtx('pj:'+pjc.dataset.pk,e.clientX,e.clientY);return}
 const sk=e.target.closest&&e.target.closest('[data-stk]');if(sk){e.preventDefault();openCtx('st:'+sk.dataset.stk,e.clientX,e.clientY);return}
 const cc=e.target.closest&&e.target.closest('[data-colk]');if(cc&&FS[cc.dataset.colk]){e.preventDefault();openCtx('col:'+cc.dataset.colk,e.clientX,e.clientY);return}
 const bi=e.target.closest&&e.target.closest('#hboard .bitem:not(.bcard)');if(bi){if(e.target.closest('textarea'))return;e.preventDefault();openCtx('bi:'+bi.dataset.bid,e.clientX,e.clientY);return}
 const hc=view==='today'&&e.target.closest&&e.target.closest('section[data-dnd="home"]');if(hc&&!e.target.closest('input,textarea,a,[data-tk],[data-colk],[data-stk],[data-note]')){e.preventDefault();openCtx('hc:'+hc.dataset.id,e.clientX,e.clientY);return}
 const ll=e.target.closest&&e.target.closest('[data-list]');if(ll){e.preventDefault();openCtx('list:'+ll.dataset.list,e.clientX,e.clientY);return}
 const el=e.target.closest&&e.target.closest('[data-note]');if(!el||!FS[el.dataset.note]){closeCtx();return}
 if(el.matches('textarea,input')||e.target.closest('textarea,input'))return;e.preventDefault();openCtx(el.dataset.note,e.clientX,e.clientY)});
document.addEventListener('click',e=>{const c=e.target.closest&&e.target.closest('[data-ctx]');
 if(!c){if(ctxK&&!(e.target.closest&&e.target.closest('#ctx')))closeCtx();return}
 e.stopPropagation();flushNote();const k=ctxK;
 if((k==='navbar'||(k&&k.startsWith('nav:')))&&c.dataset.ctx==='nlayout'){closeCtx();CFG.navLayout=c.dataset.v;saveCfg();apply();render();return}
 if(k&&k.startsWith('st:')){stCtxAct(k.slice(3),c.dataset.ctx);return}
 if(k&&k.startsWith('task:')){taskCtxAct(+k.slice(5),c.dataset.ctx,c.dataset.v);return}
 if(k&&k.startsWith('pj:')){const id=k.slice(3),a=c.dataset.ctx,p=getP(id);closeCtx();
  const open=()=>{view='projects';curP=id;pfLink=false;pfPick=false;pfQ='';pDone=false;pNoteNew=false;pEdColor=null;edP=false;icoPick=null;window.scrollTo(0,0)};
  if(a==='pjopen')open();else if(a==='pjedit'){open();edP=true}else if(a==='pjicon'){open();edP=true;icoPick='proj:'+id;pcat=0;pq=''}
  else if(a==='pjcolor'){p.color=c.dataset.v;putP(p);save()}else if(a==='pjdone'){p.status=p.status==='done'?'active':'done';putP(p);save();toast(p.status==='done'?'Project completed':'Project is active again')}
  else if(a==='pjdel'){projDel(id);return}
  render();return}
 if(k&&k.startsWith('bi:')){hbCtxAct(k.slice(3),c.dataset.ctx,c.dataset.v);return}
 if(k&&k.startsWith('hc:')){const id=k.slice(3),a=c.dataset.ctx;closeCtx();const o={...(CFG.homeColors||{})};
  if(a==='hccol')o[id]=c.dataset.v;else if(a==='hcreset')delete o[id];
  else if(a==='hchide'){const hk=homeOffKey();CFG[hk]=[...new Set([...homeOff(),id])];saveCfg();render();toast(boardMode()?'Card hidden on the board. Bring it back from Customize Home':'Card hidden. Bring it back from Customize Home');return}
  else if(a==='hcedit'){homeEdit=true;render();return}
  CFG.homeColors=o;saveCfg();render();return}
 if(k==='navbar'){const a=c.dataset.ctx;closeCtx();if(a==='nbshow'&&CFG.navAuto)navAutoSet(false);if(a==='nbhide'&&!CFG.navAuto)navAutoSet(true);return}
 if(k&&k.startsWith('cat:')){const n=k.slice(4),a=c.dataset.ctx;
  if(a==='catedit'){closeCtx();const sc=ctxCatSc,b=catBase(n,sc)||{},nm=(allCats(sc).get(n.toLowerCase())||{name:n}).name;catEd={sc,orig:nm,name:nm,sym:b.sym||'folder',emoji:b.emoji||'📁'};icoPick=null;
   if(sc==='journal'){view='journal';jtab='entries';render();window.scrollTo(0,0);const i=$('catname');if(i){i.focus();i.select()}return}
   if(view!=='notes'||nmode!=='categories'){view='notes';nmode='categories';edN=null;ND=null}render();window.scrollTo(0,0);const i=$('catname');if(i){i.focus();i.select()}return}
  if(a==='catdel'){if(!ctxArm){ctxArm=true;$('ctx').innerHTML=ctxHTML();$('ctx').querySelector('.danger').focus();return}closeCtx();catDelete(n,ctxCatSc);save();render();toast('Category deleted')}
  return}
 if(k&&k.startsWith('nav:')){const id=k.slice(4),a=c.dataset.ctx;closeCtx();
  if(a==='nauto'){navAutoSet(!CFG.navAuto);return}
  if(a==='nbshow'){if(CFG.navAuto)navAutoSet(false);return}if(a==='nbhide'){if(!CFG.navAuto)navAutoSet(true);return}
  if(a==='ncount'){const cur=(CFG.navNoCount||[]).filter(x=>x!==id);CFG.navNoCount=cur.length===(CFG.navNoCount||[]).length?[...cur,id]:cur;saveCfg()}
  if(a==='ncolor'){CFG.navColors={...(CFG.navColors||{}),[id]:c.dataset.v};saveCfg()}
  if(a==='ncolreset'){const o={...(CFG.navColors||{})};delete o[id];CFG.navColors=o;saveCfg()}
  if(a==='nwide'){const cur=(CFG.navWide||[]).filter(x=>x!==id);CFG.navWide=c.dataset.v==='2'?[...cur,id]:cur;saveCfg()}
  if(a==='nicon'){view='settings';SETG='sections';setQ='';icoPick=id;render();const r=document.querySelector(`.drow [data-act="icoPick"][data-id="${id}"]`);if(r)r.scrollIntoView({block:'center'});return}
  if(a==='nhide'&&id!=='settings'){CFG.tabOff=[...(CFG.tabOff||[]).filter(x=>x!==id),id];saveCfg();toast('Section turned off everywhere. Turn it back on in Settings → Sections')}
  render();return}
 if(k&&k.startsWith('col:')){const ck=k.slice(4),a=c.dataset.ctx;if(!FS[ck]){closeCtx();return}const it=colRead(ck),fresh=()=>{if(CD&&CD.k===ck)CD=null};
  if(a==='cfav'){it.fav=!it.fav;colPut(it);fresh();closeCtx();save();render();toast(it.fav?'Added to favorites':'Removed from favorites');return}
  if(a==='copen'){closeCtx();colSel=ck;CD=null;colQ='';view='collections';render();window.scrollTo(0,0);return}
  if(a==='cstat'){colSetStatus(it,c.dataset.v);colPut(it);fresh();closeCtx();save();render();toast(statLabel(it.type,it.status));return}
  if(a==='crate'){it.rating=it.rating===+c.dataset.v?0:+c.dataset.v;rateDone(it);colPut(it);fresh();save();render();$('ctx').innerHTML=ctxHTML();return}
  if(a==='ccover'){closeCtx();pickCover(it);return}
  if(a==='clink'){closeCtx();openLink(it.source);return}
  if(a==='cdel'){colConfirmDel(ck);return}
  return}
 if(k&&k.startsWith('list:')){const l=getList(k.slice(5)),a=c.dataset.ctx;
  if(a==='ledit'){curList=l.id;edL=true;icoPick=null;view='tasks';closeCtx();render();window.scrollTo(0,0);const n=$('lname');if(n)n.focus();return}
  if(a==='lpin'){l.pinned=l.pinned==='true'?'false':'true';putList(l);closeCtx();save();render();toast(l.pinned==='true'?'List pinned':'List unpinned');return}
  if(a==='ldel'&&!SMART.includes(l.id)){if(!ctxArm){ctxArm=true;$('ctx').innerHTML=ctxHTML();$('ctx').querySelector('.danger').focus();return}
   putTasks(tasks().map(t=>t.list===l.id?{...t,list:''}:t));delete FS[listKey(l.id)];if(curList===l.id){curList=null;edL=false}closeCtx();save();render();toast('List deleted, its tasks are still in All')}
  return}
 if(!k||!FS[k]){closeCtx();return}
 if(c.dataset.ctx==='pin'){const was=isPinned(k);setPinned(k,!was);closeCtx();save();render();toast(was?'Note unpinned':'Note pinned');return}
 if(c.dataset.ctx==='arch'){const was=isArch(k);archiveNote(k);closeCtx();save();render();toast(was?'Note unarchived':'Note archived');return}
 if(c.dataset.ctx==='del'){closeCtx();noteDel(k)}},true);
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&ctxK)closeCtx()});
window.addEventListener('blur',closeCtx);window.addEventListener('resize',closeCtx);document.addEventListener('scroll',closeCtx,true);
/* Adding to a list property: Enter or comma adds what was typed; Backspace in an empty box removes the last item. */
function addChip(inp){const p=inp.dataset.npadd,n=draft();let vals=inp.value.split(',').map(x=>x.trim()).filter(Boolean);
 if(p==='categories')vals=vals.map(catName);if(p==='tags')vals=vals.map(x=>x.replace(/^#/,'').replace(/\s+/g,'-'));
 if(!Array.isArray(n.fm[p]))n.fm[p]=n.fm[p]?[String(n.fm[p])]:[];
 vals.forEach(x=>{if(x&&!n.fm[p].some(y=>y.toLowerCase()===x.toLowerCase()))n.fm[p].push(x)});noteChanged('now');
 pendingFocus=`[data-npadd="${CSS.escape(p)}"]`;render();const el=document.querySelector(pendingFocus);pendingFocus=null;if(el)el.focus()}
document.addEventListener('keydown',e=>{const ds=e.target.dataset||{};
 if(ds.npadd!==undefined){if(e.key==='Enter'||e.key===','){e.preventDefault();if(e.target.value.trim())addChip(e.target)}
  else if(e.key==='Backspace'&&!e.target.value){const n=draft(),l=n.fm[ds.npadd];if(Array.isArray(l)&&l.length){l.pop();noteChanged('now');pendingFocus=`[data-npadd="${CSS.escape(ds.npadd)}"]`;render();const el=document.querySelector(pendingFocus);pendingFocus=null;if(el)el.focus()}}return}
 if(e.target.id==='hq'){if(e.key==='Escape'&&HQP&&HQP.files){e.preventDefault();hqClear();rerenderKeep();return}if(e.key==='Enter'){e.preventDefault();const o=hqOffer();if(o&&o!=='had'){hqSave();return}if(hq.trim().startsWith('/')){if(!runCmd())toast('Unknown command. Type / to see them all.')}else{const f=document.querySelector('#hres .sres');if(f)f.click()}return}
  if(e.key==='Escape'){hq='';rerenderKeep();return}}
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();flushNote();if(view!=='today'){view='today';render()}const i=$('hq');if(i){i.focus();i.select()}return}
 if(e.key==='/'&&view==='today'&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)&&!e.target.isContentEditable){const i=$('hq');if(i)i.focus();return}
 if(e.target.id==='ntitle'&&e.key==='Enter'){e.preventDefault();const t=$('nb');if(t){t.focus();t.setSelectionRange(0,0)}return}
 if((e.ctrlKey||e.metaKey)&&e.target.closest&&e.target.closest('.neditor')){const k=e.key.toLowerCase();
  if(k==='z'||k==='y'){e.preventDefault();undoNote(k==='y'||e.shiftKey?1:-1);rerenderKeep();return}
  if(k==='s'){e.preventDefault();flushNote();noteStatus();return}}
 if(e.target.id==='npName'&&e.key==='Enter'){e.preventDefault();document.querySelector('[data-act=npAdd]').click()}
 if(e.target.id==='tplNew'&&e.key==='Enter'){e.preventDefault();document.querySelector('[data-act=tplAdd]').click()}});
/* Drag to reorder (sidebar sections, task lists, Settings → Sections and Home cards in Customize mode).
   Tracked with pointer events instead of HTML5 drag-and-drop, which doesn't start reliably inside app webviews.
   Moving 6 px after pressing picks the item up: a copy follows the pointer, the item itself becomes a shaded slot,
   and the other items move live to make room. Releasing saves the new order; Escape puts everything back. */
const clearOver=()=>document.querySelectorAll('.over').forEach(x=>x.classList.remove('over'));
const dndEl=(g,id)=>document.querySelector(`[data-dnd="${g}"][data-id="${CSS.escape(id)}"]`);
let drg=null,suppressClick=false;
document.addEventListener('pointerdown',e=>{if(e.button!==0||drg)return;const el=e.target.closest&&e.target.closest('[data-dnd]');
 if(!el||e.target.closest('input,textarea,select,.epick')||(el.dataset.dnd==='home'&&(!homeEdit||boardMode())))return;
 drg={el,g:el.dataset.dnd,id:el.dataset.id,x:e.clientX,y:e.clientY,started:false,lastT:null}});
// Moves the dragged item next to the one under the pointer (after it when moving forward, before it when moving back).
function dragOver(tg){const o=drg.order,si=o.indexOf(drg.id),ti=o.indexOf(tg.dataset.id);if(si<0||ti<0||si===ti)return;
 o.splice(si,1);o.splice(ti,0,drg.id);
 if(drg.g==='home')(si<ti?tg.after(drg.el):tg.before(drg.el));
 else{const par=drg.el.parentElement;o.forEach(id=>{const n=dndEl(drg.g,id);if(n&&n.parentElement===par)par.appendChild(n)});if(drg.g==='mtab'){const m=par.querySelector('[data-act="mMore"]');if(m)par.appendChild(m)}if(drg.g==='short')par.querySelectorAll('.shtile.off').forEach(x=>par.appendChild(x))}}
document.addEventListener('pointermove',e=>{if(!drg)return;
 // the button was released somewhere we didn't hear about (outside the window): finish the drag here
 if(e.pointerType==='mouse'&&e.buttons===0){endDrag(drg.started);return}
 const dx=e.clientX-drg.x,dy=e.clientY-drg.y;
 if(!drg.started){if(Math.hypot(dx,dy)<6)return;drg.started=true;const r=drg.el.getBoundingClientRect(),g=drg.el.cloneNode(true);
  g.classList.add('dragghost');Object.assign(g.style,{left:r.left+'px',top:r.top+'px',width:r.width+'px',height:r.height+'px'});
  // the copy stays in the same container so it keeps that container's card styling; it must not count as an item itself
  ['data-dnd','data-id','data-act','data-list','data-val','data-v','id'].forEach(a=>g.removeAttribute(a));g.setAttribute('aria-hidden','true');
  drg.el.parentElement.appendChild(g);drg.ghost=g;drg.order=orderOf(drg.g).filter(id=>dndEl(drg.g,id));
  drg.el.classList.add('dragph');document.body.classList.add('dragging')}
 drg.ghost.style.transform=`translate(${dx}px,${dy}px)`;e.preventDefault();
 dragAt(e.clientX,e.clientY)});
// Moves the dragged item to wherever the pointer is. After a move the item under the pointer changes,
// so it only moves again once the pointer reaches a different item.
function dragAt(x,y){const t=document.elementFromPoint(x,y),tg=t&&t.closest&&t.closest(`[data-dnd="${drg.g}"]`);
 if(drg.g==='home'&&CFG.homeFixed&&(!tg||tg===drg.el)){const col=t&&t.closest&&t.closest('.hgrid.hfixed>.hcol');if(col&&drg.el.parentElement!==col){col.appendChild(drg.el);drg.lastT=null;return}}
 if(!tg||tg===drg.el){drg.lastT=null;return}if(tg.dataset.id===drg.lastT)return;drg.lastT=tg.dataset.id;dragOver(tg)}
function endDrag(drop){if(!drg)return;const p=drg;drg=null;if(!p.started)return;
 p.ghost.remove();p.el.classList.remove('dragph');document.body.classList.remove('dragging');
 // the click that follows releasing the mouse must not also open the item
 suppressClick=true;setTimeout(()=>suppressClick=false,0);
 if(drop&&p.g==='home'&&CFG.homeFixed&&document.querySelector('.hgrid.hfixed')){const cols=[...document.querySelectorAll('.hgrid.hfixed>.hcol')],map={},seen=[];
  cols.forEach((c,i)=>c.querySelectorAll(':scope>[data-dnd="home"]').forEach(el=>{map[el.dataset.id]=i;seen.push(el.dataset.id)}));
  const rest=homeList().filter(id=>!seen.includes(id));CFG.homeColOf={...(CFG.homeColOf||{}),...map};CFG.homeOrder=[...seen,...rest];saveCfg()}
 else if(drop){const vis=new Set(p.order),it=p.order[Symbol.iterator](),full=orderOf(p.g),next=full.map(id=>vis.has(id)?it.next().value:id);
  if(next.join()!==full.join())setOrder(p.g,next)}
 redraw()}
// images (e.g. collection covers) start the browser's own image drag, which would cancel ours
// No native dragging of the app's own images, links or cards (reordering uses pointer events); text can still be
// dragged inside a text field. Drops are only for things coming from outside the app.
document.addEventListener('dragstart',e=>{const t=e.target;if(t&&t.closest&&t.closest('input,textarea,[contenteditable="true"]'))return;e.preventDefault()});
document.addEventListener('pointerup',e=>{if(drg&&drg.started)dragAt(e.clientX,e.clientY);endDrag(true)});document.addEventListener('pointercancel',()=>endDrag(false));window.addEventListener('blur',()=>endDrag(false));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&drg)endDrag(false)});
document.addEventListener('click',e=>{if(suppressClick){suppressClick=false;e.stopPropagation();e.preventDefault()}},true);
$('imp').addEventListener('change',async e=>{let n=0;
 for(const f of e.target.files){const t=await f.text(),nm=f.name.endsWith('.md')?f.name:f.name+'.md';
  if(nm==='tasks.md'){const have=new Set(tasks().map(x=>x.title+'|'+x.due));putTasks(tasks().concat(parseTasks(t).filter(x=>!have.has(x.title+'|'+x.due))))}
  else if(nm==='events.md'||nm==='questions.md'){const have=new Set((FS[nm]||'').split('\n')),add=t.split('\n').filter(l=>/^- /.test(l)&&!have.has(l));
   FS[nm]=(FS[nm]||({'tasks.md':'# Tasks\n\n','events.md':'# Events\n\n'}[nm]||'# Questions\n\n')).replace(/\n+$/,'')+'\n'+add.join('\n')+(add.length?'\n':'')}
  else if(/^---\nname: /.test(t)&&/\ntype: (yesno|number)/.test(t))FS['habits/'+nm]=t;
  else if(/^---\nname: /.test(t)&&/\nstatus: /.test(t))FS['projects/'+nm]=t;
  else FS[(/^\d{4}-\d{2}-\d{2}\.md$/.test(nm)?'journal/':'notes/')+nm]=t;
  n++}
 e.target.value='';save();render();toast(`Imported ${n} file${n===1?'':'s'}`)});
(function renameTimestampNotes(){if(LOCKED)return;let n=0;
 Object.keys(FS).filter(k=>/^(notes|archive)\/\d{4}-\d{2}-\d{2}-\d{4,6}(-\d+)?\.md$/.test(k)).forEach(k=>{const dir=k.slice(0,k.indexOf('/')+1),r=readNote(FS[k]),l=noteLines(k)[0]||'';
  renameNote(k,noteKeyFor(dir,l.replace(/^#+\s*/,''),createdOf(r.fm,k.slice(dir.length,dir.length+10))));n++});
 if(n)save()})();
// The Note template exists from the start (once: if it is deleted later it is not brought back) and is the default.
(function seedJournalTemplate(){if(LOCKED||CFG.jtplSeeded)return;if(!FS[JTPL]){FS[JTPL]='---\ncreated: {{date}}\ntime: {{time}}\nmood:\nlocation:\ncategories:\n---\n';save()}CFG.jtplSeeded=true;saveCfg()})();
(function seedNoteTemplate(){if(LOCKED||CFG.tplSeeded)return;const k='templates/Note.md';
 if(!keys('templates/').some(x=>x!==JTPL)){FS[k]='---\ncreated: {{date}}\ntags:\ncategories:\n---\n';if(!CFG.defaultTpl)CFG.defaultTpl=k;save()}
 CFG.tplSeeded=true;saveCfg()})();
(function(){if(!CFG.prompts)return;const u=allQ().find(x=>!x.a.length);if(u)curQ=u.q;else{const q=bankQ();if(q){issue(q);save()}}})();apply();try{trashPurge()}catch(e){}
if(!CFG.hcAuto){if(+CFG.homeCols===3)CFG.homeCols='auto';CFG.hcAuto=1;saveCfg()}
// The Write freely card merged into How are you feeling?: keep it shown if only Write freely was on.
if((CFG.homeOff||[]).includes('mood')&&!(CFG.homeOff||[]).includes('write')){CFG.homeOff=CFG.homeOff.filter(x=>x!=='mood');saveCfg()}
// The lock screen, user picker and setup open once the whole file has run (they use parts defined further down).
queueMicrotask(()=>{if(WHO)whoShow();else if(PWLOCK)lockShow();if(ONB_AUTO&&!CFG.onboarded){ONB={i:0};onbShow()}
// A fresh user just opened: carry on creating their account (in setup, or in Settings).
{let fr='';try{fr=sessionStorage.getItem('prodify.fresh')||'';sessionStorage.removeItem('prodify.fresh')}catch(e){}
 if(fr==='onb'){ONB={i:1};onbShow()}else if(fr==='settings'){view='settings';SETG='account';ACCUI='create';accFresh=false;accNameDraft=ME?ME.name:'';setTimeout(()=>{toast('This is your new, empty space. Create its account.');const i=$('accpw');if(i)i.focus()},300)}}});setInterval(showRem,15000);setTimeout(()=>{try{bdRemind()}catch(e){}try{bkAuto()}catch(e){}},2000);setInterval(()=>{try{bkAuto()}catch(e){}},3600000);setInterval(()=>{try{bdRemind()}catch(e){}},600000);try{if(window.claude&&claude.use){claude.use('downloads').then(d=>{DL=d}).catch(()=>{});claude.use('sample').then(s=>{SAMPLE=s;if(!qBusy)keepRender()}).catch(()=>{})}}catch(e){}
// First draw once the whole file has run, so every part (Settings' later sections included) is defined.
queueMicrotask(()=>render());
if(BOOT.error)fail('Could not read your files, so changes won’t be saved: '+BOOT.error);
// covers still stored as online links are saved for offline use shortly after start-up
setTimeout(colOfflineCovers,1500);

/* ---------- Styled dropdowns ----------
   Every <select> gets a button and a menu in the app's style (the system menu can't be styled). The real select
   stays in the page, hidden, and keeps its value; choosing an option sets it and fires input and change, so the
   code reading or listening to the select works unchanged. Add data-native to a select to keep the system menu. */
let dsOpen=null;
function dsLabel(sel){const o=sel.options[sel.selectedIndex];return o?o.textContent:''}
// A row of buttons that becomes a dropdown on phones (.segsel): picking an option clicks the matching button.
const segPick=(label,opts,cur)=>`<select data-segpick aria-label="${esc(label)}">${opts.map(([v,l])=>`<option value="${esc(v)}" ${String(cur)===String(v)?'selected':''}>${esc(l)}</option>`).join('')}</select>`;
document.addEventListener('change',e=>{const s=e.target;if(!s.matches||!s.matches('select[data-segpick]'))return;const b=s.closest('.segsel').querySelector(`.seg [data-val="${CSS.escape(s.value)}"]`);if(b)b.click()});
function dsEnhance(root){(root||document).querySelectorAll('select:not([data-native]):not(.dsel-src)').forEach(sel=>{
 const b=document.createElement('button');b.type='button';b.className='dsel';b.setAttribute('aria-haspopup','listbox');b.setAttribute('aria-expanded','false');
 const lab=sel.getAttribute('aria-label')||(sel.closest('label')&&sel.closest('label').textContent.trim())||'';if(lab)b.setAttribute('aria-label',lab);
 b.innerHTML=`<span class="dsl"></span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
 b.querySelector('.dsl').textContent=dsLabel(sel);if(sel.disabled)b.disabled=true;
 sel.classList.add('dsel-src');sel.tabIndex=-1;sel.setAttribute('aria-hidden','true');sel.after(b);b._sel=sel})}
function dsClose(){if(!dsOpen)return;dsOpen.menu.remove();dsOpen.btn.setAttribute('aria-expanded','false');dsOpen.btn.classList.remove('open');dsOpen=null}
function dsPlace(){if(!dsOpen)return;const r=dsOpen.btn.getBoundingClientRect(),m=dsOpen.menu;if(!document.body.contains(dsOpen.btn)){dsClose();return}
 m.style.minWidth=r.width+'px';const h=m.offsetHeight,below=innerHeight-r.bottom-8;
 m.style.left=Math.max(8,Math.min(r.left,innerWidth-m.offsetWidth-8))+'px';m.style.top=(below<h&&r.top>h?r.top-h-6:r.bottom+6)+'px'}
function dsOpenMenu(btn){dsClose();const sel=btn._sel,m=document.createElement('div');m.className='dmenu';m.setAttribute('role','listbox');
 let html='';for(const el of sel.children){if(el.tagName==='OPTGROUP'){html+=`<p class="dmlab">${esc(el.label)}</p>`;for(const o of el.children)html+=dsOpt(o,sel)}else html+=dsOpt(el,sel)}
 m.innerHTML=html;document.body.appendChild(m);dsOpen={btn,menu:m,sel,act:sel.selectedIndex};btn.setAttribute('aria-expanded','true');btn.classList.add('open');dsPlace();
 const cur=m.querySelector('.dmo.on');if(cur)cur.scrollIntoView({block:'nearest'});dsMark()}
const dsOpt=(o,sel)=>`<div class="dmo ${o.selected?'on':''} ${o.disabled?'off':''}" role="option" aria-selected="${o.selected}" data-i="${[...sel.options].indexOf(o)}"><span class="dmc">${o.selected?'✓':''}</span><span>${esc(o.textContent)}</span></div>`;
function dsMark(){if(!dsOpen)return;dsOpen.menu.querySelectorAll('.dmo').forEach(x=>x.classList.toggle('act',+x.dataset.i===dsOpen.act));const a=dsOpen.menu.querySelector('.dmo.act');if(a)a.scrollIntoView({block:'nearest'})}
function dsPick(i){const{sel,btn}=dsOpen;dsClose();if(i<0||sel.options[i].disabled)return;if(sel.selectedIndex!==i){sel.selectedIndex=i;btn.querySelector('.dsl').textContent=dsLabel(sel);
 sel.dispatchEvent(new Event('input',{bubbles:true}));sel.dispatchEvent(new Event('change',{bubbles:true}))}if(document.body.contains(btn))btn.focus()}
document.addEventListener('click',e=>{const b=e.target.closest&&e.target.closest('.dsel');if(b){e.preventDefault();e.stopPropagation();if(dsOpen&&dsOpen.btn===b)dsClose();else dsOpenMenu(b);return}
 const o=e.target.closest&&e.target.closest('.dmenu .dmo');if(o&&dsOpen){e.stopPropagation();dsPick(+o.dataset.i);return}
 if(dsOpen&&!(e.target.closest&&e.target.closest('.dmenu')))dsClose()},true);
document.addEventListener('keydown',e=>{const b=e.target.closest&&e.target.closest('.dsel');
 if(!dsOpen){if(b&&(e.key==='ArrowDown'||e.key==='ArrowUp'||e.key===' '||e.key==='Enter')){e.preventDefault();dsOpenMenu(b)}return}
 const n=dsOpen.sel.options.length,step=d=>{let i=dsOpen.act;for(let k=0;k<n;k++){i=(i+d+n)%n;if(!dsOpen.sel.options[i].disabled)break}dsOpen.act=i;dsMark()};
 if(e.key==='ArrowDown'){e.preventDefault();step(1)}else if(e.key==='ArrowUp'){e.preventDefault();step(-1)}
 else if(e.key==='Enter'||e.key===' '){e.preventDefault();dsPick(dsOpen.act)}else if(e.key==='Escape'||e.key==='Tab'){if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation()}const b2=dsOpen.btn;dsClose();if(e.key==='Escape')b2.focus()}
 else if(e.key.length===1){const k=fold(e.key),os=[...dsOpen.sel.options],i=os.findIndex((o,j)=>j>dsOpen.act&&fold(o.textContent).startsWith(k)),j=i>=0?i:os.findIndex(o=>fold(o.textContent).startsWith(k));if(j>=0){dsOpen.act=j;dsMark()}}},true);
document.addEventListener('scroll',e=>{if(dsOpen&&!dsOpen.menu.contains(e.target))dsPlace()},true);
window.addEventListener('resize',()=>dsPlace());
// enhance selects whenever the page changes
new MutationObserver(()=>{if(document.querySelector('select:not([data-native]):not(.dsel-src)'))dsEnhance()}).observe(document.body,{childList:true,subtree:true});
dsEnhance();

/* ---------- Auto-hide sidebar (like Zen Browser's compact mode) ----------
   With CFG.navAuto the sidebar sits off-screen; touching the left edge (#navedge) slides it in over the page,
   and it slides away shortly after the pointer leaves it or a section is opened. Ctrl+B switches the mode. */
let navHideT=null;
const navAutoOn=()=>{const ap=$('app');return !!ap&&ap.classList.contains('navauto')&&innerWidth>760};
function navShow(){if(!navAutoOn())return;clearTimeout(navHideT);$('app').classList.add('navshow')}
function navHide(delay){clearTimeout(navHideT);navHideT=setTimeout(()=>{if(navDrag||(ctxK&&ctxK.startsWith('nav'))||(drg&&drg.started))return;const ap=$('app');if(ap)ap.classList.remove('navshow')},delay==null?320:delay)}
function navAutoSet(on){CFG.navAuto=on;saveCfg();apply();render();if(on){toast('Sidebar hidden. Move the pointer to the left edge to show it (Ctrl+B to switch)');$('app').classList.add('navshow');navHide(1400)}else toast('Sidebar always shown')}
document.addEventListener('mouseover',e=>{if(!navAutoOn())return;const t=e.target;if(t.id==='navedge'||t.id==='navgrip'||(t.closest&&t.closest('#nav')))navShow()});
document.addEventListener('mouseout',e=>{if(!navAutoOn())return;const to=e.relatedTarget;if(e.target.closest&&e.target.closest('#nav,#navedge,#navgrip')&&!(to&&to.closest&&to.closest('#nav,#navedge,#navgrip,#ctx')))navHide()});
document.addEventListener('click',e=>{if(navAutoOn()&&e.target.closest&&e.target.closest('#nav [data-act="nav"]'))navHide(120)});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&!e.shiftKey&&!e.altKey&&e.key.toLowerCase()==='b'&&CFG.navLayout!=='top'&&!/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)&&!e.target.isContentEditable){e.preventDefault();navAutoSet(!CFG.navAuto)}});


/* ---------- Category and tag suggestions ----------
   Focusing or typing in a note's Categories or Tags property opens a menu of existing ones (best matches first,
   most-used next, with icons and note counts) plus "Create …" for something new. ↑↓ move, Enter or click adds. */
let csBox=null,csIn=null,csItems=[],csAct=0;
function csList(inp){const jk=inp.dataset.jcat,p=jk!==undefined?'categories':inp.dataset.npadd,raw=inp.value.trim().replace(/^#/,''),q=fold(raw);
 const cur=jk!==undefined?(jk==='new'?JC:jCats(jk)):(n=>Array.isArray(n.fm[p])?n.fm[p]:[])(draft()),have=new Set(cur.map(x=>x.toLowerCase()));
 const src=jk!==undefined||(p==='categories'&&isJE(edN))?[...allCats('journal').values()]:p==='categories'?[...allCats().values()]:[...propIndex('tags').values()];
 const items=src.filter(c=>!have.has(c.name.toLowerCase())&&(!q||fold(c.name).includes(q)))
  .sort((a,b)=>(fold(b.name).startsWith(q)-fold(a.name).startsWith(q))||(b.keys.length-a.keys.length)||alpha(a.name,b.name)).slice(0,8).map(c=>({name:c.name,n:c.keys.length}));
 if(raw&&!src.some(c=>fold(c.name)===q)&&!have.has(raw.toLowerCase()))items.push({name:p==='tags'?raw.replace(/\s+/g,'-'):raw,create:true});
 return items}
function csHide(){if(csBox)csBox.remove();csBox=null;csItems=[]}
function csDraw(){if(!csIn||!document.body.contains(csIn)||!csItems.length){csHide();return}
 if(!csBox){csBox=document.createElement('div');csBox.className='csug';csBox.setAttribute('role','listbox');document.body.appendChild(csBox);
  csBox.addEventListener('pointerdown',e=>{e.preventDefault();const o=e.target.closest('[data-csi]');if(o)csPick(+o.dataset.csi)})}
 const r=csIn.getBoundingClientRect(),jsc=csIn.dataset.jcat!==undefined,cat=jsc||csIn.dataset.npadd==='categories',q=fold(csIn.value.trim().replace(/^#/,''));
 csBox.style.left=Math.max(8,Math.min(r.left,innerWidth-268))+'px';csBox.style.top=(r.bottom+6)+'px';
 const hl=n=>{const i=q?fold(n).indexOf(q):-1;return i<0?esc(n):esc(n.slice(0,i))+'<b>'+esc(n.slice(i,i+q.length))+'</b>'+esc(n.slice(i+q.length))};
 csBox.innerHTML=(q?'':`<p class="cslab">${cat?'Categories':'Tags'}</p>`)+csItems.map((x,i)=>`<div class="cso ${i===csAct?'on':''} ${x.create?'new':''}" data-csi="${i}" role="option" aria-selected="${i===csAct}">
<span class="csi">${x.create?lineIco('M12 5v14M5 12h14'):cat?catIco(x.name,jsc?'journal':'notes'):'#'}</span><span class="csn">${x.create?`Create “${esc(x.name)}”`:hl(x.name)}</span>${x.create?'':`<span class="meta">${x.n||''}</span>`}</div>`).join('')}
function csShow(inp){csIn=inp;csItems=csList(inp);csAct=0;csDraw()}
function csPick(i){const x=csItems[i],inp=csIn;if(!x||!inp)return;
 if(inp.dataset.jcat!==undefined){const jk=inp.dataset.jcat;csHide();if(jk==='new')JC=[...JC,x.name];else{jSetCats(jk,[...jCats(jk),x.name]);save()}redraw();
  setTimeout(()=>{const el=document.querySelector(`[data-jcat="${CSS.escape(jk)}"]`);if(el){el.focus();csShow(el)}},0);return}
 const p=inp.dataset.npadd;inp.value=x.name;csHide();addChip(inp);
 setTimeout(()=>{const el=document.querySelector(`[data-npadd="${CSS.escape(p)}"]`);if(el){el.focus();csShow(el)}},0)}
const csFor=t=>t&&t.dataset&&(t.dataset.npadd==='categories'||t.dataset.npadd==='tags'||t.dataset.jcat!==undefined);
document.addEventListener('focusin',e=>{if(csFor(e.target))csShow(e.target)});
document.addEventListener('input',e=>{if(csFor(e.target))csShow(e.target)});
document.addEventListener('focusout',e=>{if(e.target===csIn)setTimeout(()=>{if(document.activeElement!==csIn)csHide()},120)});
document.addEventListener('scroll',()=>{if(csBox)csDraw()},true);
document.addEventListener('keydown',e=>{const jk=e.target.dataset&&e.target.dataset.jcat;if(jk!==undefined&&e.key==='Backspace'&&!e.target.value){const l=jk==='new'?JC:jCats(jk);if(l.length){e.preventDefault();if(jk==='new')JC=JC.slice(0,-1);else{jSetCats(jk,l.slice(0,-1));save()}redraw();const el=document.querySelector(`[data-jcat="${CSS.escape(jk)}"]`);if(el){el.focus();csShow(el)}}return}
 if(!csBox||e.target!==csIn)return;const n=csItems.length;
 if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();csAct=(csAct+(e.key==='ArrowDown'?1:n-1))%n;csDraw()}
 else if(e.key==='Enter'||(e.key==='Tab'&&csIn.value.trim())){e.preventDefault();e.stopImmediatePropagation();csPick(csAct)}
 else if(e.key==='Escape'){e.stopImmediatePropagation();csHide()}},true);
// Clickable rows (role="button" on a non-button) also work with Enter and Space.
document.addEventListener('keydown',e=>{const t=e.target;if((e.key==='Enter'||e.key===' ')&&t&&t.getAttribute&&t.getAttribute('role')==='button'&&t.tagName!=='BUTTON'&&t.dataset.act){e.preventDefault();t.click()}});


/* ---------- Interface language ----------
   With Settings → Language set to Español, interface text is swapped for the translations in i18n.js as it is drawn:
   text, placeholders, tooltips and labels in the page, menus and messages. User content is left alone. */
const I18N_SKIP='.md,.cnt,.ntitle,.rtt,.nli b,.ncard,.ccard>b,.ccard>.meta,.mini b,.lrl,.lcl,.ltitle,.cath,.catrn,.cattile .ntl,.csn,.sres b,.hlname,.q,.chip,.exo .t,.cso,.jcatpick .cattile,.mdcode,.crow .t,.hlrow .t b,.wkname,.exdet h2,.medrow,.rex,.tt,[data-notr]';
function i18nText(t){if(CFG.lang!=='es'||typeof I18N_ES==='undefined')return null;const s=t.trim();if(!s||!/[A-Za-z]/.test(s))return null;
 let r=I18N_ES[s];if(r===undefined)for(const[re,f]of I18N_ES_RX){if(re.test(s)){r=s.replace(re,f);break}}
 return r===undefined||r===s?null:t.replace(s,r)}
// the English originals of what was translated, so switching back to English restores text that is not redrawn
const I18N_ORIG=new WeakMap();
const i18nSetText=(n,r)=>{if(!I18N_ORIG.has(n))I18N_ORIG.set(n,n.nodeValue);n.nodeValue=r};
const i18nSetAttr=(e,a,r)=>{const o=I18N_ORIG.get(e)||{};if(!(a in o))o[a]=e.getAttribute(a);I18N_ORIG.set(e,o);e.setAttribute(a,r)};
function i18nRestore(root){const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode())if(I18N_ORIG.has(n)){n.nodeValue=I18N_ORIG.get(n);I18N_ORIG.delete(n)}
 root.querySelectorAll('*').forEach(e=>{const o=I18N_ORIG.get(e);if(o&&typeof o==='object'){for(const a in o)e.setAttribute(a,o[a]);I18N_ORIG.delete(e)}})}
function i18nRun(root){if(CFG.lang!=='es'||!root)return;
 if(root.nodeType===3){const p=root.parentElement;if(p&&!p.closest(I18N_SKIP)){const r=i18nText(root.nodeValue);if(r!==null)i18nSetText(root,r)}return}
 if(root.nodeType!==1)return;const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let n;const todo=[];while(n=w.nextNode())todo.push(n);
 for(const x of todo){const p=x.parentElement;if(!p||p.closest(I18N_SKIP)||p.closest('script,style'))continue;const r=i18nText(x.nodeValue);if(r!==null)i18nSetText(x,r)}
 const els=root.querySelectorAll?[root,...root.querySelectorAll('[placeholder],[title],[aria-label]')]:[];
 for(const e of els)for(const a of ['placeholder','title','aria-label']){const v=e.getAttribute&&e.getAttribute(a);if(v){const r=i18nText(v);if(r!==null)i18nSetAttr(e,a,r)}}}
new MutationObserver(ms=>{if(CFG.lang!=='es')return;for(const m of ms){if(m.type==='characterData')i18nRun(m.target);else m.addedNodes.forEach(i18nRun)}}).observe(document.body,{childList:true,subtree:true,characterData:true});
i18nRun(document.body);

/* ---------- live sync: pick up changes another device made to the folder (Syncthing, Dropbox…) ----------
   While the app is open it re-reads the folder every few seconds and when the window gets focus, and compares it
   with DISK (what it last read or wrote). A file only the other device changed is taken as is. A file both sides
   changed is merged line by line (base = DISK), so a task added on each device keeps both. Syncthing's
   ".sync-conflict-…" copies of shared list files (tasks.md, habits.md…) are merged back and removed. */
// For each line of a, the index of the matching line in b (longest common subsequence), or -1.
function lcsMap(a,b){const n=a.length,m=b.length,map=new Array(n).fill(-1);let p=0;while(p<n&&p<m&&a[p]===b[p]){map[p]=p;p++}
 let sa=n,sb=m;while(sa>p&&sb>p&&a[sa-1]===b[sb-1]){sa--;sb--;map[sa]=sb}
 const A=a.slice(p,sa),B=b.slice(p,sb),W=B.length+1,L=new Int32Array((A.length+1)*W);
 for(let i=A.length-1;i>=0;i--)for(let j=B.length-1;j>=0;j--)L[i*W+j]=A[i]===B[j]?L[(i+1)*W+j+1]+1:Math.max(L[(i+1)*W+j],L[i*W+j+1]);
 for(let i=0,j=0;i<A.length&&j<B.length;){if(A[i]===B[j]){map[p+i]=p+j;i++;j++}else if(L[(i+1)*W+j]>=L[i*W+j+1])i++;else j++}
 return map}
// Three-way merge by lines (base = the version both sides started from). Between lines all three share, a side that
// didn't touch a stretch takes the other side's version; when both changed it, mine stays and theirs is added after.
function merge3(base,mine,theirs){if(mine===base||mine===theirs)return theirs;if(theirs===base)return mine;
 const B=base.split('\n'),Mi=mine.split('\n'),Th=theirs.split('\n'),mm=lcsMap(B,Mi),tm=lcsMap(B,Th),out=[],eq=(x,y)=>x.length===y.length&&x.every((v,j)=>v===y[j]);
 for(let i=0,mi=0,ti=0;;){let k=i;while(k<B.length&&!(mm[k]>=mi&&tm[k]>=ti))k++;
  const mk=k<B.length?mm[k]:Mi.length,tk=k<B.length?tm[k]:Th.length,b=B.slice(i,k),m=Mi.slice(mi,mk),t=Th.slice(ti,tk);
  if(eq(m,b))out.push(...t);else if(eq(t,b)||eq(m,t))out.push(...m);else out.push(...m,...t.filter(l=>!m.includes(l)));
  if(k>=B.length)break;out.push(B[k]);i=k+1;mi=mk+1;ti=tk+1}
 return out.join('\n')}
const SC_RX=/^(.*)\.sync-conflict-\d{8}-\d{6}-[A-Z0-9]{7}\.md$/;
// Applies a fresh read of the folder. Returns true when anything visible changed.
function syncApply(disk){let changed=false,merged=0;const open=ND&&ND.k,col=CD&&CD.k,before=open?FS[open]:null;
 if(open&&disk[open]!==DISK[open])flushNote();// my typing goes into FS first, so it takes part in the merge
 const colCh=!!col&&disk[col]!==DISK[col];if(colCh)colFlush();
 for(const k of new Set([...Object.keys(disk),...Object.keys(DISK)])){const d=disk[k],b=DISK[k];if(d===b)continue;
  if(d===undefined){// removed on the other device: drop it here too, unless I changed it since
   if(FS[k]===b){delete FS[k];changed=true}delete DISK[k];continue}
  const m=FS[k];if(m===undefined&&b!==undefined){DISK[k]=d;continue}// I deleted it: my delete wins (save removes it)
  const out=m===undefined||m===b?d:merge3(b||'',m,d);if(m!==undefined&&m!==b&&m!==d)merged++;
  if(FS[k]!==out){FS[k]=out;changed=true}DISK[k]=d}
 // Syncthing kept both versions of a shared list file: fold the copy into the original and delete it.
 for(const k of Object.keys(FS)){const x=k.match(SC_RX);if(!x||k.includes('/'))continue;const o=x[1]+'.md';if(o===ACCK){delete FS[k];changed=true;continue}// keep this device's account file
  if(FS[o]!==undefined){FS[o]=merge3('',FS[o],FS[k]);merged++}delete FS[k];changed=true}
 if(open&&FS[open]!==before)ND=null;// the open note is rebuilt from the merged file
 if(open&&FS[open]===undefined){ND=null;if(edN===open)edN=null;if(nViewK===open)nViewK=null}// deleted on the other device
 if(colCh)CD=null;if(colSel&&FS[colSel]===undefined){colSel=null;CD=null}
 if(merged)toast(merged===1?'Merged a change from another device':`Merged ${merged} changes from another device`);
 return changed}
let syncBusy=false;
function syncPoll(){if(!TAURI||STORE_DB||LOCKED||PWLOCK||!ACCREADY||syncBusy||document.hidden||drg)return;syncBusy=true;
 // runs in the save queue, so it never reads the folder halfway through one of our own writes
 queue(async()=>{try{const b=await TAURI.invoke('load_all');if(syncApply(await rawToPlain(b.files||{}))){save();mirSoon();rerenderKeep()}}finally{syncBusy=false}},'changes from other devices')}
setInterval(syncPoll,3000);
mirSoon(4000);// the first copy after opening writes everything oncewindow.addEventListener('focus',()=>setTimeout(syncPoll,0));

/* ---------- back gesture ----------
   Android's back gesture (and a mouse's back button) only steps back through the page's history, and Prodify has
   none of its own, so one extra history entry stands in for the app's back. Pressing back closes whatever is open
   (a pop-up, menu, sheet, quick capture, the notification panel) or does what the page's back button does. On Home with
   nothing open the entry isn't put back, and a toast says the next press leaves the app. */
var inBack=false;// var: render() runs before this line on startup
function backArm(){try{if(!history.state||history.state.prodify!=='app')history.pushState({prodify:'app'},'')}catch(e){}}
function appBack(){
 if($('cfm')){const c=document.querySelector('#cfm [data-cfm="0"]');if(c){c.click();return true}}
 if(LB){LB=null;lbShow();return true}
 if(dsOpen){dsClose();return true}
 const cx=$('ctx');if(cx&&!cx.hidden){closeCtx();return true}
 if(mSheet){mSheet=mSheet==='edit'?'more':null;render();return true}
 if(QC){QC=null;qcShow();return true}
 if(NP){npToggle(false);return true}
 if(PWLOCK||WHO)return false;
 const b=document.querySelector('#main [data-act="navBack"],#main .backhome,#main .lnav .circ');
 if(b){b.click();return true}
 if(view!=='today'){view='today';render();window.scrollTo(0,0);return true}
 return false}
try{history.replaceState({prodify:'root'},'')}catch(e){}backArm();
window.addEventListener('popstate',()=>{inBack=true;let done=false;try{done=appBack()}finally{inBack=false}
 if(done)backArm();else toast('Press back again to exit')});

/* ---------- Prodify Cloud (Plus) ----------
   Syncs this user's data through the Prodify Cloud server (cloud/ in the repository). Everything is encrypted here
   first: each file is an object "r/<keyed hash of its name>" holding its encrypted name and text, photos and PDFs are
   "a/<name>" with encrypted bytes, and "account" is the account file (locked data key, nothing secret), which lets a
   new device unlock with the account's password. A round pulls what changed since the last one (merging like live
   sync, with the last synced version as the base), then pushes local changes "only if the cloud copy is still the
   one I last saw", so nothing is overwritten. Deletes travel as tombstones. CFG.cloud keeps the server, session and
   position; the bases are kept, encrypted, under the "prodify.cloudbase" setting. */
const CLOUD_DEFAULT='https://prodify-cloud.gaalpos.workers.dev';// Prodify Cloud (cloud/ in the repository); Settings → Account and data → Server can point elsewhere
const PLANL={free:'Free',basic:'Basic',pro:'Pro'};
let CS=null,cloudBusy=false,cloudTimer=null,CLOUDUI=null,cloudErr='',cloudFull=false,cloudMismatch=null;
const cloudUrl=()=>((CFG.cloud&&CFG.cloud.url)||CFG.cloudUrl||CLOUD_DEFAULT||'').replace(/\/+$/,'');
const cloudOn=()=>!!(CFG.cloud&&CFG.cloud.token&&cloudUrl());
const fmtBytes=n=>n>=1073741824?(n/1073741824).toFixed(n>=10737418240?0:1)+' GB':n>=1048576?(n/1048576).toFixed(n>=10485760?0:1)+' MB':Math.max(0,Math.round(n/1024))+' KB';
async function cloudApi(method,path,body,headers){const c=CFG.cloud||{},h={...(headers||{})};if(c.token)h.authorization='Bearer '+c.token;
 const r=await fetch(cloudUrl()+path,{method,headers:h,body});
 if(r.status===401&&c.token){CFG.cloud={url:c.url};saveCfg();CS=null;throw new Error('Your cloud session ended. Please sign in again.')}
 return r}
const cloudJson=async(method,path,obj)=>{const r=await cloudApi(method,path,obj===undefined?undefined:JSON.stringify(obj),obj===undefined?{}:{'content-type':'application/json'});const j=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(j.error||('Error '+r.status)),{status:r.status,body:j});return j};
// Sync bases (last synced text per file) and revisions, encrypted at rest with the data key.
async function csLoad(){if(CS)return CS;CS={base:{},rev:{},ids:{}};try{const raw=store.get('prodify.cloudbase'+USUF);if(raw&&DK)Object.assign(CS,JSON.parse(isEncT(raw)?await decText(raw):raw))}catch(e){}return CS}
async function csSave(){if(CS&&DK)store.set('prodify.cloudbase'+USUF,await encText(JSON.stringify(CS)))}
const cloudId=async k=>k===ACCK?'account':'r/'+await nameHash(k);
const attRefs=()=>[...new Set(Object.values(FS).flatMap(t=>[...String(t).matchAll(/attachments\/([^)\s"'<>]+)/g)].map(m=>decodeURIComponent(m[1]))))].filter(n=>/^[A-Za-z0-9._-]{1,200}$/.test(n));
function cloudSoon(ms){if(!cloudOn())return;clearTimeout(cloudTimer);cloudTimer=setTimeout(cloudSync,ms==null?3000:ms)}
// One round: pull, merge, push. Returns true when the data here changed.
async function cloudSync(){if(!cloudOn()||!ACCREADY||PWLOCK||WHO||!encOn()||cloudBusy||cloudMismatch)return false;cloudBusy=true;let changed=false,again=false;
 try{await csLoad();const was=JSON.stringify(Object.keys(FS).map(k=>[k,FS[k].length]));
  // 1. pull
  let since=CFG.cloud.seq||0,more=true;
  while(more){const r=await cloudJson('GET','/changes?since='+since);
   for(const it of r.items){const id=it.id;if(CS.rev[id]===it.rev)continue;
    if(id==='account'){const t=await (await cloudApi('GET','/obj/account')).text(),a=accParse(t);
     if(a&&a.kid&&ACCT.kid&&a.kid!==ACCT.kid){cloudMismatch={text:t,name:a.name};throw new Error('This cloud belongs to another Prodify account')}
     if(a&&t!==FS[ACCK]&&!it.deleted){FS[ACCK]=t;ACCT=a;changed=true}CS.base[ACCK]=t;CS.rev[id]=it.rev;continue}
    if(id.startsWith('a/')){if(!it.deleted){const u=new Uint8Array(await (await cloudApi('GET','/obj/'+encodeURIComponent(id))).arrayBuffer());await attWrite(id.slice(2),u);delete ATTURL[id.slice(2)]}CS.rev[id]=it.rev;continue}
    if(it.deleted){const k=CS.ids[id];if(k!==undefined){if(FS[k]===CS.base[k]){delete FS[k];changed=true}delete CS.base[k]}CS.rev[id]=it.rev;continue}
    const res=await cloudApi('GET','/obj/'+encodeURIComponent(id));if(!res.ok)continue;
    const d=await decText(await res.text()),i=d.indexOf('\n'),k=d.slice(0,i),t=d.slice(i+1),base=CS.base[k],mine=FS[k];
    if(mine===undefined){if(base===undefined){FS[k]=t;changed=true}}// a file deleted here stays deleted (the delete is pushed below)
    else{const out=merge3(base===undefined?'':base,mine,t);if(out!==mine){FS[k]=out;changed=true}}
    CS.base[k]=t;CS.rev[id]=it.rev;CS.ids[id]=k}
   since=r.seq;more=r.more;CFG.cloud.me=r.me}
  CFG.cloud.seq=since;
  // 2. push changed files, deletes and new attachments
  for(const k of Object.keys(FS)){if(FS[k]===CS.base[k])continue;const id=await cloudId(k),body=k===ACCK?FS[k]:await encText(k+'\n'+FS[k]);
   const r=await cloudApi('PUT','/obj/'+encodeURIComponent(id),body,{'if-match':String(CS.rev[id]||0)});
   if(r.status===409){again=true;continue}if(r.status===413){cloudFull=true;break}if(!r.ok)throw new Error('Upload failed ('+r.status+')');
   CS.rev[id]=(await r.json()).rev;CS.base[k]=FS[k];CS.ids[id]=k;cloudFull=false}
  for(const k of Object.keys(CS.base)){if(k in FS)continue;const id=await cloudId(k);
   const r=await cloudApi('DELETE','/obj/'+encodeURIComponent(id),undefined,{'if-match':String(CS.rev[id]||0)});
   if(r.status===409){again=true;continue}if(r.ok){CS.rev[id]=(await r.json()).rev;delete CS.base[k]}}
  if(!cloudFull)for(const n of attRefs()){const id='a/'+n;if(CS.rev[id])continue;let u;try{u=await attRead(n)}catch(e){continue}if(!u)continue;if(!isEncB(u))u=await encBytes(u);
   const r=await cloudApi('PUT','/obj/'+encodeURIComponent(id),u,{'if-match':'0'});if(r.status===409){CS.rev[id]=(await r.json().catch(()=>({}))).rev||1;continue}if(r.status===413){cloudFull=true;break}if(r.ok)CS.rev[id]=(await r.json()).rev}
  try{CFG.cloud.me=await cloudJson('GET','/me')}catch(e){}
  CFG.cloud.last=Date.now();cloudErr='';await csSave();saveCfg();
  if(changed){save();if(view!=='settings'||!document.activeElement||document.activeElement===document.body)rerenderKeep();else if(view==='settings')rerenderKeep()}
  else if(view==='settings')rerenderKeep();
  if(again)cloudSoon(500);return changed}
 catch(e){cloudErr=String(e&&e.message||e);if(view==='settings')rerenderKeep();return false}
 finally{cloudBusy=false}}
setInterval(()=>cloudSync(),60000);window.addEventListener('focus',()=>cloudSoon(300));
// Joining a cloud that belongs to another account: this device takes that account (its password unlocks it), and
// its own notes are re-encrypted with that account's key and merged into the cloud on the next round.
async function cloudAdopt(pw){const t=cloudMismatch&&cloudMismatch.text,a=accParse(t);if(!a)return false;const k=await accKey(pw,false,a)||await accKey(pw,true,a);if(!k)return false;
 DKRAW=k;DK=await aesKey(k);NHK=null;ACCT=a;FS[ACCK]=t;Object.keys(FS).forEach(x=>{if(x!==ACCK)NEEDW.add(x)});CS={base:{},rev:{},ids:{}};CFG.cloud.seq=0;cloudMismatch=null;save();await SQ;await accConvertExtra(true);return true}
async function cloudSignOut(){try{await cloudJson('POST','/auth/logout',{})}catch(e){}const url=CFG.cloud&&CFG.cloud.url;CFG.cloud={url};saveCfg();CS=null;store.set('prodify.cloudbase'+USUF,null);cloudErr='';cloudMismatch=null;cloudFull=false}
const cloudSection=()=>{const c=CFG.cloud||{},m=c.me,dis=cloudBusy?'disabled':'';
 const plans=`<div class="cplans">${[['free','Free','100 MB'],['basic','Basic','5 GB'],['pro','Pro','50 GB']].map(([id,l,sz])=>`<div class="cplan ${m&&m.plan===id?'on':''}"><b>${l}</b><span>${sz}</span>${m&&m.plan===id?'<span class="meta">Your plan</span>':id==='free'?'<span class="meta">Included</span>':'<span class="meta">Coming soon</span>'}</div>`).join('')}</div>`;
 const server=`<details class="cadv"><summary class="meta">Server</summary><div class="row" style="margin:6px 0 0"><input id="cloudurl" value="${esc(cloudUrl())}" placeholder="https://prodify-cloud.example.workers.dev" autocomplete="off" spellcheck="false" aria-label="Server address"><button class="g" data-act="cloudUrlSave">Save</button></div></details>`;
 if(!cloudOn())return `<section class="cloudsec"><h2>Prodify Cloud</h2><p class="meta" style="margin:0 0 10px">Sync your notes, journal, tasks and photos across your devices. Everything is encrypted on this device before it’s uploaded, names included, so nobody else can read it.</p>${plans}
${!cloudUrl()?'<p class="meta">Prodify Cloud isn’t available in this version yet.</p>'+server
 :CLOUDUI&&CLOUDUI.step==='code'?`<div class="accpanel"><p style="margin:0 0 6px">We sent a 6-digit code to <b data-notr>${esc(CLOUDUI.email)}</b>.</p>${CLOUDUI.dev?`<p class="meta" style="margin:0 0 6px">Test server: your code is <b data-notr>${esc(CLOUDUI.dev)}</b></p>`:''}<input id="cloudcode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" aria-label="Code"><div class="row"><button class="b" data-act="cloudVerify" ${dis}>Sign in</button><button class="g" data-act="cloudCancel">Back</button></div></div>`
 :`<div class="row" style="margin:0"><input id="cloudemail" type="email" value="${esc(c.email||'')}" placeholder="you@example.com" autocomplete="email" aria-label="Email"><button class="b" data-act="cloudStart" ${dis}>Send me a code</button></div><p class="meta" style="margin:6px 0 0">No password: we email you a sign-in code. Free includes 100 MB.</p>${server}`}${cloudErr?`<p class="meta mirerr">${esc(cloudErr)}</p>`:''}</section>`;
 const need=!ACCT?'Cloud sync needs a local account with encryption. Create one in Account above, or, if this cloud already has your data, enter its password below.':!ACCT.enc?'Cloud sync needs encryption: turn on “Encrypt my data” in Account above.':'';
 const pct=m?Math.min(100,Math.round(m.used/m.quota*100)):0;
 return `<section class="cloudsec"><h2>Prodify Cloud</h2><div class="acchead"><span class="accav">${lineIco('M7 18h10a4 4 0 0 0 .6-7.96A6 6 0 0 0 6.1 9.3 4.5 4.5 0 0 0 7 18z')}</span><div class="accwho"><b data-notr>${esc(c.email||'')}</b><span class="meta">${m?PLANL[m.plan]||'Free':''} plan · ${cloudBusy?'Syncing…':c.last?'Last synced '+tf((d=>pad(d.getHours())+':'+pad(d.getMinutes()))(new Date(c.last))):'Not synced yet'}</span></div><button class="g" data-act="cloudNow" ${dis||(need?'disabled':'')}>Sync now</button></div>
${m?`<div class="cuse"><span style="width:${pct}%"></span></div><p class="meta" style="margin:4px 0 10px">${fmtBytes(m.used)} of ${fmtBytes(m.quota)} used${cloudFull?' · <b>Your cloud storage is full.</b> New changes stay on this device.':''}</p>`:''}
${cloudMismatch?`<div class="accpanel"><p style="margin:0 0 6px">This cloud belongs to another Prodify account${cloudMismatch.name?` (<b data-notr>${esc(cloudMismatch.name)}</b>)`:''}. Enter its password to use it here: your notes on this device are encrypted with that account and merged into the cloud.</p><input type="password" id="cloudpw" autocomplete="current-password" aria-label="That account’s password"><div class="row"><button class="b" data-act="cloudAdopt" ${dis}>Use this cloud</button><button class="x" data-act="cloudOut">Sign out</button></div></div>`
 :need?`<p class="meta">${need}</p>${!ACCT?`<div class="row" style="margin:6px 0 0"><button class="g" data-act="cloudJoin" ${dis}>This cloud has my data</button></div>`:''}`:''}
${plans}${cloudErr&&!cloudMismatch?`<p class="meta mirerr">${esc(cloudErr)}</p>`:''}<div class="row" style="margin-top:10px"><button class="x" data-act="cloudOut">Sign out</button></div></section>`};

cloudSoon(2500);// first round shortly after opening (skipped while locked)
