// Jasper's Sec — all pages render from /data/*.json. Edit the JSON, not this file.
const $=(s,r=document)=>r.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const url=u=>/^https?:\/\//i.test(u||'')?esc(u):'#';
const load=async p=>{try{const r=await fetch(p,{cache:'no-cache'});if(!r.ok)throw 0;return await r.json()}catch{return null}};
const ago=iso=>{const m=(Date.now()-new Date(iso))/6e4;return isNaN(m)?'never':m<60?`${Math.round(m)}m ago`:m<1440?`${Math.round(m/60)}h ago`:`${Math.round(m/1440)}d ago`};
const tags=a=>(a||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
const empty=m=>`<li class="empty">${m}</li>`;
function md(t){const inl=s=>esc(s).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
 let o='',code=0,li=0;for(const l of (t||'').split('\n')){
  if(l.startsWith('```')){o+=code?'</code></pre>':'<pre><code>';code=!code;continue}
  if(code){o+=esc(l)+'\n';continue}
  const h=l.match(/^(#{1,3})\s+(.*)/),m=l.match(/^[-*]\s+(.*)/);
  if(li&&!m){o+='</ul>';li=0}
  if(h)o+=`<h${h[1].length+1}>${inl(h[2])}</h${h[1].length+1}>`;
  else if(m){if(!li){o+='<ul>';li=1}o+=`<li>${inl(m[1])}</li>`}
  else if(l.trim())o+=`<p>${inl(l)}</p>`}
 return o+(li?'</ul>':'')+(code?'</code></pre>':'')}
const feedRow=i=>`<li class="item"><time>${esc((i.date||'').slice(0,10))}</time><div><a href="${url(i.url)}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a><div class="meta"><span class="tag k-${esc(i.kind)}">${esc(i.source_name)}</span>${tags((i.tags||[]).slice(0,3))}</div>${i.summary?`<p>${esc(i.summary)}</p>`:''}</div></li>`;
const repRow=r=>`<li class="item"><time>${esc(r.date)}</time><div><a href="reports.html?id=${encodeURIComponent(r.id)}">${esc(r.title)}</a><div class="meta"><span class="tag k-vuln">${esc(r.type)}</span>${tags(r.tags)}</div>${r.summary?`<p>${esc(r.summary)}</p>`:''}</div></li>`;
const byDate=a=>[...a].sort((x,y)=>String(y.date).localeCompare(String(x.date)));
const P={};

P.home=async s=>{const[f,r,p]=await Promise.all([load('data/feeds.json'),load('data/reports.json'),load('data/projects.json')]);
 const it=f?.items||[],kev=it.filter(i=>i.source==='kev').slice(0,6),news=it.filter(i=>i.kind==='news').slice(0,8),src=f?.sources||[],ok=src.filter(x=>x.ok).length;
 $('#app').innerHTML=`<section class="hero"><div><span class="live"><i class="dot ${f?'':'off'}"></i>${f?`feeds updated ${ago(f.updated)} · ${ok}/${src.length} sources`:'feeds not fetched yet'}</span><h1>${esc(s.name)}</h1><p>${esc(s.tagline)}</p><a class="btn pri" href="feeds.html">Open live feeds</a> <a class="btn" href="reports.html">Read reports</a></div>
 <div class="card"><h2>Exploited now · CISA KEV</h2><ul class="list">${kev.length?kev.map(i=>`<li class="item"><div><a href="${url(i.url)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(i.cve||i.title.split(' ')[0])}</a><div class="meta">${tags(i.tags)}</div></div><time style="text-align:right;flex:1">${esc((i.date||'').slice(5,10))}</time></li>`).join(''):empty('Run <code>tools/update_feeds.py</code> to fill this.')}</ul></div></section>
 <div class="stats"><div><b>${(r||[]).length}</b><span>Reports</span></div><div><b>${it.length}</b><span>Feed items</span></div><div><b>${ok}</b><span>Live sources</span></div><div><b>${it.filter(i=>i.kind==='vuln').length}</b><span>Vulnerabilities</span></div></div>
 <div class="grid g2"><div class="card"><h2>Latest reports <a href="reports.html">All reports</a></h2><ul class="list">${(r||[]).length?byDate(r).slice(0,5).map(repRow).join(''):empty('No reports yet.')}</ul></div>
 <div class="card"><h2>Projects <a href="projects.html">All</a></h2><ul class="list">${(p||[]).slice(0,4).map(x=>`<li class="item"><div><b>${esc(x.name)}</b><div class="meta"><span class="tag">${esc(x.status)}</span></div></div></li>`).join('')||empty('No projects yet.')}</ul></div></div>
 <div class="card" style="margin-top:1.25rem"><h2>Headlines <a href="feeds.html">All feeds</a></h2><ul class="list">${news.length?news.map(feedRow).join(''):empty('No headlines yet.')}</ul></div>`};

P.feeds=async()=>{const f=await load('data/feeds.json');
 if(!f){$('#app').innerHTML='<div class="card pad">No <code>data/feeds.json</code> yet. Run <code>python3 tools/update_feeds.py</code>.</div>';return}
 const st={k:'',s:'',q:''},kinds=[['','All'],['news','News'],['vuln','Vulns'],['ioc','IOCs']];
 $('#app').innerHTML=`<h1 style="margin-top:0">Live feeds</h1><div class="tools" id="tb">${kinds.map(([k,n])=>`<button data-k="${k}" class="${k?'':'on'}">${n}</button>`).join('')}<select id="src"><option value="">All sources</option>${f.sources.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join('')}</select><input id="q" type="search" placeholder="Search CVE, actor, malware, vendor" style="flex:1;min-width:14rem"></div><div class="card"><ul class="list" id="ls"></ul><details><summary>Source health · updated ${ago(f.updated)}</summary><table><tr><th>Source</th><th>Status</th><th>Items</th><th>Note</th></tr>${f.sources.map(x=>`<tr><td>${esc(x.name)}</td><td class="${x.ok?'st-ok':'st-bad'}">${x.ok?'ok':'failed'}</td><td>${x.count}</td><td>${esc(x.error||'')}</td></tr>`).join('')}</table></details></div>`;
 const draw=()=>{const l=f.items.filter(i=>(!st.k||i.kind===st.k)&&(!st.s||i.source===st.s)&&(!st.q||(i.title+' '+i.summary+' '+(i.tags||[]).join(' ')).toLowerCase().includes(st.q)));$('#ls').innerHTML=l.length?l.slice(0,150).map(feedRow).join(''):empty('Nothing matches.')};
 $('#tb').onclick=e=>{const b=e.target.closest('button[data-k]');if(!b)return;st.k=b.dataset.k;document.querySelectorAll('#tb button').forEach(x=>x.classList.toggle('on',x===b));draw()};
 $('#src').onchange=e=>{st.s=e.target.value;draw()};$('#q').oninput=e=>{st.q=e.target.value.toLowerCase();draw()};draw()};

P.reports=async()=>{const r=byDate(await load('data/reports.json')||[]),id=new URLSearchParams(location.search).get('id');
 if(id){const x=r.find(a=>a.id===id);$('#app').innerHTML=x?`<article class="art"><a href="reports.html" class="mut">← All reports</a><h1>${esc(x.title)}</h1><div class="meta"><time class="mut">${esc(x.date)}</time><span class="tag k-vuln">${esc(x.type)}</span>${tags(x.tags)}</div>${md(x.body)}</article>`:'<p>Report not found. <a href="reports.html">Back to reports</a></p>';if(x)document.title=x.title;return}
 const types=[...new Set(r.map(x=>x.type))];
 $('#app').innerHTML=`<h1 style="margin-top:0">Reports</h1><div class="tools"><select id="t"><option value="">All types</option>${types.map(t=>`<option>${esc(t)}</option>`).join('')}</select><input id="q" type="search" placeholder="Search reports" style="flex:1;min-width:14rem"></div><div class="card"><ul class="list" id="ls"></ul></div>`;
 const draw=()=>{const t=$('#t').value,q=$('#q').value.toLowerCase(),l=r.filter(x=>(!t||x.type===t)&&(!q||(x.title+x.summary+x.body+(x.tags||[]).join(' ')).toLowerCase().includes(q)));$('#ls').innerHTML=l.length?l.map(repRow).join(''):empty('No reports match.')};
 $('#t').onchange=draw;$('#q').oninput=draw;draw()};

P.detections=async()=>{const d=await load('data/detections.json')||[],st={t:'sigma',q:''};
 $('#app').innerHTML=`<h1 style="margin-top:0">Detections</h1><div class="tools" id="tb">${['sigma','yara','spl'].map(t=>`<button data-t="${t}" class="${t==='sigma'?'on':''}">${t==='spl'?'Splunk SPL':t[0].toUpperCase()+t.slice(1)}</button>`).join('')}<input id="q" type="search" placeholder="Search technique, tactic, title" style="flex:1;min-width:14rem"></div><div class="grid" id="ls"></div><p class="mut" style="font-size:.85rem">Rules are provided as-is for defensive use. Test and tune before production.</p>`;
 const draw=()=>{const l=d.filter(x=>x.type===st.t&&(!st.q||JSON.stringify(x).toLowerCase().includes(st.q)));$('#ls').innerHTML=l.length?l.map(x=>`<div class="card pad"><b>${esc(x.title)}</b><div class="meta">${tags([x.tactic,x.technique].filter(Boolean))}</div><p class="mut" style="margin:.5rem 0 0">${esc(x.desc)}</p><button data-c style="float:right;margin-top:.5rem">Copy</button><pre>${esc(x.rule)}</pre></div>`).join(''):'<div class="card empty">No rules here yet. Add some in data/detections.json.</div>'};
 $('#tb').onclick=e=>{const b=e.target.closest('button[data-t]');if(!b)return;st.t=b.dataset.t;document.querySelectorAll('#tb button').forEach(x=>x.classList.toggle('on',x===b));draw()};
 $('#q').oninput=e=>{st.q=e.target.value.toLowerCase();draw()};
 $('#ls').onclick=e=>{const b=e.target.closest('[data-c]');if(b){navigator.clipboard.writeText(b.parentNode.querySelector('pre').textContent);b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)}};draw()};

P.projects=async()=>{const p=await load('data/projects.json')||[];
 $('#app').innerHTML=`<h1 style="margin-top:0">Projects</h1><div class="grid g3">${p.map(x=>`<div class="card proj"><h3>${x.url?`<a href="${url(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.name)}</a>`:esc(x.name)}<span class="tag">${esc(x.status)}</span></h3><p>${esc(x.desc)}</p><div class="meta">${tags(x.stack)}</div></div>`).join('')||'<div class="card empty">No projects yet.</div>'}</div>`};

P.about=async s=>{const a=s.about||{};
 $('#app').innerHTML=`<div class="art"><h1>About</h1>${md(a.intro)}<h2>Focus</h2><div class="grid g3">${(a.focus||[]).map(x=>`<div class="card proj"><h3>${esc(x.t)}</h3><p style="margin:0">${esc(x.d)}</p></div>`).join('')}</div>${a.contact?`<h2>Contact</h2>${md(a.contact)}`:''}<p class="mut" style="margin-top:2rem">${esc(s.disclaimer||'')}</p></div>`};

(async()=>{const s=await load('data/site.json');
 if(!s){$('#app').innerHTML='<div class="card pad">Could not load <code>data/site.json</code>. Serve this folder over HTTP: <code>python3 -m http.server 8000</code></div>';return}
 const pg=document.body.dataset.page,cur=location.pathname.split('/').pop()||'index.html';document.title=s.name;
 $('#top').innerHTML=`<header class="bar"><div class="in"><a class="brand" href="index.html"><img src="${url(s.logo)}" alt=""><span>${esc(s.name)}</span></a><nav aria-label="Main">${s.nav.map(([n,h])=>`<a href="${esc(h)}" class="${h===cur?'on':''}">${esc(n)}</a>`).join('')}</nav></div></header>`;
 $('#foot').innerHTML=`<footer><div class="in"><span>© ${new Date().getFullYear()} ${esc(s.name)}</span><span>${(s.links||[]).filter(l=>l.url).map(l=>`<a href="${url(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.label)}</a>`).join(' · ')}</span><span>${esc(s.disclaimer||'')}</span></div></footer>`;
 await P[pg]?.(s)})();
