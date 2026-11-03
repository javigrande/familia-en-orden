import { buildPushPayload } from '@block65/webcrypto-web-push';

const TZ = 'Europe/Madrid';
const dateFmt = new Intl.DateTimeFormat('en-CA', {timeZone: TZ, year:'numeric', month:'2-digit', day:'2-digit'});
const timeFmt = new Intl.DateTimeFormat('en-GB',{timeZone: TZ,hour:'2-digit',minute:'2-digit',hourCycle:'h23'});
const today = (d=new Date()) => dateFmt.format(d);
const nowTime = (d=new Date()) => timeFmt.format(d);
const weekday = day => new Date(`${day}T12:00:00Z`).getUTCDay();
const enc = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');
const randomHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
async function hashPin(pin,salt){const key=await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:180000,hash:'SHA-256'},key,256));}
const fail = (error,status=400) => new Response(JSON.stringify({error}),{status,headers:{'content-type':'application/json; charset=utf-8'}});
const json = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8'}});
function cors(req,env,res){const origin=req.headers.get('Origin');const allow=(env.ALLOWED_ORIGIN||'').split(',').map(s=>s.trim()); const headers=new Headers(res.headers);if(origin&&allow.includes(origin)){headers.set('Access-Control-Allow-Origin',origin);headers.set('Vary','Origin');headers.set('Access-Control-Allow-Headers','authorization, content-type, x-setup-key');headers.set('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS');}return new Response(res.body,{status:res.status,headers});}
async function payload(req){try{return await req.json();}catch{throw new Error('JSON incorrecto');}}
function validateDay(s){if(!/^\d{4}-\d{2}-\d{2}$/.test(s)||new Date(s+'T12:00:00Z').toISOString().slice(0,10)!==s)throw new Error('Fecha no válida');return s;}
async function auth(req,env){const token=(req.headers.get('authorization')||'').replace(/^Bearer /i,'');if(!/^[a-f0-9]{64}$/.test(token))return null;return env.DB.prepare(`SELECT m.id,m.name,m.is_admin FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>datetime('now')`).bind(await sha256(token)).first();}
async function audit(env,actor,action,details){await env.DB.prepare('INSERT INTO audit(actor_id,action,details) VALUES (?,?,?)').bind(actor,action,JSON.stringify(details)).run();}
async function materialize(env,day){validateDay(day);const dow=String(weekday(day));await env.DB.prepare(`INSERT OR IGNORE INTO occurrences(task_id,day,assigned_to) SELECT id,?,assigned_to FROM tasks WHERE active=1 AND start_date<=? AND (end_date IS NULL OR end_date>=?) AND (','||weekdays||',') LIKE ?`).bind(day,day,day,`%,${dow},%`).run();}
async function rows(env,day){return (await env.DB.prepare(`SELECT o.*,t.title,t.description,t.at_time,t.reminder_minutes,t.points,m.name AS assignee,c.name AS completer FROM occurrences o JOIN tasks t ON t.id=o.task_id JOIN members m ON m.id=o.assigned_to LEFT JOIN members c ON c.id=o.completed_by WHERE o.day=? ORDER BY t.at_time,t.id`).bind(day).all()).results;}
function stats(occ,members){return members.map(m=>{const mine=occ.filter(o=>o.assigned_to===m.id);const done=mine.filter(o=>o.status==='done'&&o.completed_by===m.id);const covered=mine.filter(o=>o.status==='done'&&o.completed_by!==m.id);const helped=occ.filter(o=>o.completed_by===m.id&&o.assigned_to!==m.id);const assignedPoints=mine.reduce((a,o)=>a+o.points,0);const ownPoints=done.reduce((a,o)=>a+o.points,0);const bonus=helped.reduce((a,o)=>a+Math.ceil(o.points/2),0);return {id:m.id,name:m.name,assigned:mine.length,done:done.length,covered:covered.length,helped:helped.length,pending:mine.filter(o=>o.status==='pending').length,percent:assignedPoints?Math.round(ownPoints/assignedPoints*100):null,points:ownPoints+bonus};});}
async function api(req,env){const url=new URL(req.url),path=url.pathname.replace(/\/$/,'');
 if(path==='/api/health')return json({ok:true,app:'Familia en Orden',today:today()});
 if(path==='/api/bootstrap'&&req.method==='POST'){
   if(!env.SETUP_KEY||req.headers.get('x-setup-key')!==env.SETUP_KEY)return fail('Clave de instalación incorrecta',403);
   const count=await env.DB.prepare('SELECT COUNT(*) n FROM members').first();if(count.n)return fail('La familia ya está configurada',409);
   const data=await payload(req);if(!Array.isArray(data.pins)||data.pins.length!==4||data.pins.some(p=>!/^[0-9]{4,12}$/.test(String(p))))return fail('Necesitas cuatro PIN de 4 a 12 cifras');
   const names=['Papá','Mamá','Javi','Jorge'];for(let i=0;i<4;i++){const salt=randomHex(16);await env.DB.prepare('INSERT INTO members(id,name,pin_salt,pin_hash,is_admin) VALUES(?,?,?,?,?)').bind(i+1,names[i],salt,await hashPin(String(data.pins[i]),salt),i<2?1:0).run();}return json({ok:true,members:names});
 }
 if(path==='/api/login'&&req.method==='POST'){
   const data=await payload(req);const name=String(data.name||'');const pin=String(data.pin||'');if(!/^[0-9]{4,12}$/.test(pin))return fail('Credenciales incorrectas',401);
   const m=await env.DB.prepare('SELECT * FROM members WHERE name=?').bind(name).first();if(!m||await hashPin(pin,m.pin_salt)!==m.pin_hash)return fail('Credenciales incorrectas',401);
   const token=randomHex(32);await env.DB.prepare(`INSERT INTO sessions(token_hash,member_id,expires_at) VALUES(?,?,datetime('now','+30 days'))`).bind(await sha256(token),m.id).run();return json({token,member:{id:m.id,name:m.name,is_admin:m.is_admin}});
 }
 const me=await auth(req,env);if(!me)return fail('Sesión no válida. Inicia sesión.',401);
 if(path==='/api/me')return json(me);
 if(path==='/api/logout'&&req.method==='POST'){const token=req.headers.get('authorization').slice(7);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();return json({ok:true});}
 if(path==='/api/members'&&req.method==='GET'){return json((await env.DB.prepare('SELECT id,name,is_admin FROM members ORDER BY id').all()).results);}
 if(path==='/api/dashboard'&&req.method==='GET'){
   const day=validateDay(url.searchParams.get('day')||today());await materialize(env,day);const all=await rows(env,day);const members=(await env.DB.prepare('SELECT id,name FROM members ORDER BY id').all()).results;
   const start=url.searchParams.get('from')||day.slice(0,8)+'01';validateDay(start);if(start>day)return fail('Periodo de estadísticas incorrecto');
   const history=(await env.DB.prepare(`SELECT o.assigned_to,o.completed_by,o.status,t.points FROM occurrences o JOIN tasks t ON o.task_id=t.id WHERE o.day BETWEEN ? AND ?`).bind(start,day).all()).results;
   return json({day,now:nowTime(),me,occurrences:all,stats:stats(history,members),members});
 }
 if(path==='/api/tasks'&&req.method==='GET'){return json((await env.DB.prepare('SELECT * FROM tasks ORDER BY active DESC,id DESC').all()).results);}
 if(path==='/api/tasks'&&req.method==='POST'){
   if(!me.is_admin)return fail('Solo Papá y Mamá pueden administrar las tareas',403);
   const b=await payload(req);const title=String(b.title||'').trim().slice(0,100),description=String(b.description||'').trim().slice(0,500);const assigned=Number(b.assigned_to),points=Number(b.points),reminder=Number(b.reminder_minutes??30),start=validateDay(b.start_date||today());const end=b.end_date?validateDay(b.end_date):null;
   if(!title||![1,2,3,4].includes(assigned)||!Number.isInteger(points)||points<1||points>100||!Number.isInteger(reminder)||reminder<0||reminder>240||!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(String(b.at_time)))return fail('Revisa los datos de la tarea');
   const days=[...new Set((b.weekdays||[]).map(Number))].sort();if(!days.length||days.some(d=>!Number.isInteger(d)||d<0||d>6)||end&&end<start)return fail('Días o fechas incorrectos');
   const result=await env.DB.prepare('INSERT INTO tasks(title,description,assigned_to,weekdays,start_date,end_date,at_time,reminder_minutes,points,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(title,description,assigned,days.join(','),start,end,b.at_time,reminder,points,me.id).run();await audit(env,me.id,'create_task',{taskId:result.meta.last_row_id,title});await materialize(env,today());return json({ok:true,id:result.meta.last_row_id},201);
 }
 const tm=path.match(/^\/api\/tasks\/(\d+)$/);
 if(tm&&req.method==='PATCH'){
   if(!me.is_admin)return fail('Sin permiso',403);const id=Number(tm[1]),b=await payload(req);if(typeof b.active!=='boolean')return fail('Solo se admite activar o archivar');const old=await env.DB.prepare('SELECT id FROM tasks WHERE id=?').bind(id).first();if(!old)return fail('Tarea inexistente',404);await env.DB.prepare('UPDATE tasks SET active=? WHERE id=?').bind(b.active?1:0,id).run();await audit(env,me.id,'task_active',{id,active:b.active});return json({ok:true});
 }
 const om=path.match(/^\/api\/occurrences\/(\d+)\/(complete|undo)$/);
 if(om&&req.method==='POST'){
   const id=Number(om[1]),o=await env.DB.prepare('SELECT * FROM occurrences WHERE id=?').bind(id).first();if(!o)return fail('Tarea inexistente',404);if(o.day>today())return fail('No se pueden marcar tareas futuras');const b=await payload(req);const isAdmin=!!me.is_admin;
   if(om[2]==='complete'){
     const completedBy=Number(b.completed_by||me.id);if(completedBy!==me.id&&!isAdmin)return fail('No puedes confirmar acciones de otra persona',403);
     if(o.assigned_to!==me.id&&completedBy!==me.id&&!isAdmin)return fail('Sin permiso',403);
     if(o.status==='done')return fail('Ya está completada',409);
     await env.DB.prepare(`UPDATE occurrences SET status='done',completed_by=?,completed_at=datetime('now') WHERE id=? AND status='pending'`).bind(completedBy,id).run();await audit(env,me.id,'complete',{occurrence:id,completedBy,assignedTo:o.assigned_to});return json({ok:true});
   }
   if(o.status!=='done')return fail('La tarea no está completada',409);
   if(o.completed_by!==me.id&&!isAdmin)return fail('Solo quien la completó o un administrador puede corregirla',403);
   await env.DB.prepare(`UPDATE occurrences SET status='pending',completed_by=NULL,completed_at=NULL WHERE id=?`).bind(id).run();await audit(env,me.id,'undo',{occurrence:id});return json({ok:true});
 }
 if(path==='/api/push/public-key'&&req.method==='GET')return json({publicKey:env.VAPID_PUBLIC_KEY||''});
 if(path==='/api/push/subscribe'&&req.method==='POST'){
   const b=await payload(req),sub=b.subscription;if(!sub||typeof sub.endpoint!=='string'||!sub.endpoint.startsWith('https://')||!sub.keys?.p256dh||!sub.keys?.auth)return fail('Suscripción push incorrecta');
   await env.DB.prepare(`INSERT INTO push_subscriptions(member_id,endpoint,subscription_json) VALUES (?,?,?) ON CONFLICT(endpoint) DO UPDATE SET member_id=excluded.member_id,subscription_json=excluded.subscription_json`).bind(me.id,sub.endpoint,JSON.stringify(sub)).run();return json({ok:true});
 }
 if(path==='/api/push/unsubscribe'&&req.method==='POST'){const b=await payload(req);await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint=? AND member_id=?').bind(String(b.endpoint||''),me.id).run();return json({ok:true});}
 if(path==='/api/settings/pin'&&req.method==='POST'){const b=await payload(req);if(!/^[0-9]{4,12}$/.test(String(b.pin||'')))return fail('El PIN debe tener entre 4 y 12 cifras');const salt=randomHex(16);await env.DB.prepare('UPDATE members SET pin_salt=?,pin_hash=? WHERE id=?').bind(salt,await hashPin(String(b.pin),salt),me.id).run();await env.DB.prepare('DELETE FROM sessions WHERE member_id=?').bind(me.id).run();return json({ok:true});}
 return fail('Ruta no encontrada',404);
}
async function sendPush(env,memberId,text){if(!env.VAPID_PUBLIC_KEY||!env.VAPID_PRIVATE_KEY)return;const subs=(await env.DB.prepare('SELECT * FROM push_subscriptions WHERE member_id=?').bind(memberId).all()).results;for(const sub of subs){try{const request=await buildPushPayload({data:JSON.stringify({title:'Familia en Orden 🏠',body:text,url:'/'}),options:{ttl:3600}},JSON.parse(sub.subscription_json),{subject:env.VAPID_SUBJECT,publicKey:env.VAPID_PUBLIC_KEY,privateKey:env.VAPID_PRIVATE_KEY});const res=await fetch(sub.endpoint,request);if([404,410].includes(res.status))await env.DB.prepare('DELETE FROM push_subscriptions WHERE id=?').bind(sub.id).run();if(!res.ok)console.log('Push status',res.status);}catch(e){console.log('Push error',String(e));}}}
async function scheduled(env){const day=today();await materialize(env,day);const list=await rows(env,day);const now=nowTime();const mins=s=>Number(s.slice(0,2))*60+Number(s.slice(3));for(const o of list){if(o.status!=='pending')continue;const age=mins(now)-mins(o.at_time);const kind=age>=0&&age<6?'due':age>=o.reminder_minutes&&age<o.reminder_minutes+6?'late':null;if(!kind)continue;const result=await env.DB.prepare('INSERT OR IGNORE INTO notification_log(occurrence_id,kind) VALUES (?,?)').bind(o.id,kind).run();if(result.meta.changes>0)await sendPush(env,o.assigned_to,kind==='due'?`Te toca: ${o.title}`:`Sigue pendiente: ${o.title}`);}}
export default {async fetch(req,env){if(req.method==='OPTIONS'){return cors(req,env,new Response(null,{status:204}));}try{return cors(req,env,await api(req,env));}catch(e){console.error(e);return cors(req,env,fail(e?.message||'Error interno',/^(JSON|Fecha|Días)/.test(e?.message||'')?400:500));}},async scheduled(_event,env,ctx){ctx.waitUntil(scheduled(env));}};
