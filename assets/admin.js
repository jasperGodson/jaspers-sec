const $=s=>document.querySelector(s),msg=m=>$('#msg').textContent=m;
async function open_(){try{const r=await fetch(`data/${$('#f').value}.json`,{cache:'no-cache'});$('#t').value=JSON.stringify(await r.json(),null,2);msg('Loaded')}catch{msg('Could not load. Serve over HTTP: python3 -m http.server 8000')}}
const valid=()=>{try{return JSON.parse($('#t').value)}catch(e){msg('Invalid JSON: '+e.message);return null}};
$('#f').onchange=open;
$('#chk').onclick=()=>{if(valid())msg('Valid JSON')};
$('#new').onclick=()=>{const a=valid();if(!a)return;if($('#f').value!=='reports'||!Array.isArray(a))return msg('Switch to reports first');
 const t=prompt('Report title');if(!t)return;a.unshift({id:t.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,80),title:t,date:new Date().toISOString().slice(0,10),type:'Intel Report',tags:[],summary:'',body:'## Summary\n\n## Key findings\n\n- \n\n## Indicators\n\n## Sources\n\n- '});
 $('#t').value=JSON.stringify(a,null,2);msg('Added at the top. Fill it in, then download.')};
$('#dl').onclick=()=>{const a=valid();if(!a)return;const l=document.createElement('a');l.href=URL.createObjectURL(new Blob([JSON.stringify(a,null,2)],{type:'application/json'}));l.download=$('#f').value+'.json';l.click();msg('Downloaded '+l.download)};
open();
