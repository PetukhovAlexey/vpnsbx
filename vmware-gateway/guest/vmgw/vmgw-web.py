#!/usr/bin/python3 -I
"""vmgw-web: web panel of the gateway. Runs as the unprivileged user vmgw-web and
talks to the controller only through `sudo -n /usr/local/sbin/vmgw api`."""
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import socketserver
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

CONFIG = json.load(open('/etc/vmgw/config.json'))
PORT = int(CONFIG['panel_port'])
ALLOWED = [ipaddress.ip_network(n) for n in [CONFIG['mgmt_net']] + CONFIG.get('admin_nets', [])]
PASSFILE = '/etc/vmgw/panel.pass'
CTL = ['sudo', '-n', '/usr/local/sbin/vmgw', 'api']
MAX_BODY = 3 * 1024 * 1024
SESSION_TTL = 12 * 3600
SESSIONS = {}
LOCK = threading.Lock()
ACTION_LOCK = threading.Lock()
FAILS = []

PAGE = '''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Шлюз VMware</title><link rel="stylesheet" href="/app.css"></head>
<body><main>
<header><h1>Шлюз VMware</h1><span id="router"></span><button id="logout" hidden>Выйти</button></header>
<section class="card" id="login" hidden><h2>Вход</h2>
<form id="loginForm" class="row"><input type="password" id="pw" placeholder="Пароль панели" autocomplete="current-password"><button>Войти</button></form>
</section>
<div id="app" hidden>
<section class="card"><h2>Хосты</h2>
<p class="hint">ВМ сегмента свободно общаются между собой и с хостом Windows. В интернет каждая выходит только через свой профиль: нет профиля или туннель не работает — интернета нет.</p>
<table><thead><tr><th>Хост</th><th>IP / MAC</th><th>Политика</th><th>Домашняя сеть</th><th>Пробросы</th><th></th></tr></thead><tbody id="hosts"></tbody></table>
<h3>ВМ без профиля (интернета нет)</h3><div id="unknown" class="hint">—</div>
<form id="hostForm" class="row"><input id="hName" placeholder="имя (латиница)" pattern="[a-z0-9][a-z0-9-]{0,30}" required><input id="hMac" placeholder="MAC 00:50:56:.." required><input id="hIp" placeholder="IP (необязательно)"><button>Добавить хост</button></form>
</section>
<section class="card"><h2>Туннели</h2>
<p class="hint">Туннель поднимается, когда хотя бы один хост выбрал его профиль.</p>
<table><thead><tr><th>Интерфейс</th><th>Профиль</th><th>Сервер</th><th>Рукопожатие</th><th>Трафик</th><th>Хосты</th><th></th></tr></thead><tbody id="tunnels"></tbody></table>
<div class="row"><button data-act="restart">Перезапустить все туннели</button></div>
</section>
<section class="card"><h2>Транспорт туннелей</h2>
<dl id="corp"></dl>
<div class="row"><button id="corpOn">Через корпоративный VPN</button><button id="corpOff">Напрямую через WAN</button></div>
<details><summary>Корпоративный профиль и учётные данные</summary>
<div class="row"><input type="file" id="corpFile" accept=".ovpn,.conf"><button id="corpUpload">Загрузить .ovpn</button></div>
<form id="corpAuth" class="row"><input id="cLogin" placeholder="логин" autocomplete="off"><input id="cPass" type="password" placeholder="пароль" autocomplete="new-password"><button>Сохранить</button></form>
</details></section>
<section class="card"><h2>Профили AmneziaWG</h2>
<table><thead><tr><th>Профиль</th><th>Туннель</th><th>Сервер</th><th>Адрес</th><th>Хосты</th><th></th></tr></thead><tbody id="profiles"></tbody></table>
<div class="row"><input type="file" id="file" accept=".vpn,.conf"><button id="uploadBtn">Загрузить профиль</button></div>
</section>
<section class="card"><h2>Проброс портов</h2>
<p class="hint">Подключение к <b id="mgmtIp"></b>:ВНЕШНИЙ_ПОРТ с хоста Windows попадает на хост:ПОРТ.</p>
<table><thead><tr><th>Протокол</th><th>Внешний порт</th><th>Хост</th><th>Порт хоста</th><th>Откуда</th><th></th></tr></thead><tbody id="forwards"></tbody></table>
<form id="fwdForm" class="row"><select id="fProto"><option>tcp</option><option>udp</option></select><input id="fPort" type="number" min="1" max="65535" placeholder="внешний порт" required><select id="fHost"></select><input id="fTo" type="number" min="1" max="65535" placeholder="порт хоста" required><select id="fSrc"><option value="mgmt">только хост Windows</option><option value="local">+ локальные сети</option></select><button>Добавить</button></form>
</section>
<section class="card"><h2>Журнал</h2><pre id="log"></pre></section>
</div></main><script src="/app.js"></script></body></html>
'''

CSS = '''
:root{color-scheme:light dark;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--line:#8884}
body{font:15px/1.45 system-ui,sans-serif;margin:0;padding:24px}
main{max-width:1100px;margin:auto}
header{display:flex;gap:16px;align-items:baseline;margin-bottom:16px}header h1{font-size:22px;margin:0}
#router{opacity:.7;flex:1}
h2{font-size:17px;margin:0 0 8px}h3{font-size:15px;margin:16px 0 6px}
.card{border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.hint{opacity:.75;margin:0 0 10px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 12px}dt{opacity:.7}dd{margin:0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
button,input,select{font:inherit;padding:5px 10px;border-radius:6px;border:1px solid var(--line);background:transparent;color:inherit}
button{cursor:pointer}button:hover{background:#8882}button:disabled{opacity:.45;cursor:default}
button.danger{border-color:var(--bad);color:var(--bad)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
td.actions{white-space:nowrap;text-align:right}td.actions button{margin-left:4px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}
small{opacity:.7}
pre{margin:0;max-height:220px;overflow:auto;font-size:13px;white-space:pre-wrap}
details{margin-top:12px}
'''

JS = r'''
let busy=false,S=null;
const $=s=>document.querySelector(s);
function log(t){const p=$('#log');p.textContent=new Date().toLocaleTimeString()+'  '+t+'\n'+p.textContent}
function el(tag,text,cls){const e=document.createElement(tag);if(text!=null)e.textContent=text;if(cls)e.className=cls;return e}
async function api(path,body){
 const opt={headers:{'X-VMGW':'1'},credentials:'same-origin'};
 if(body){opt.method='POST';opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body)}
 const r=await fetch(path,opt);
 if(r.status===401){showLogin();throw new Error('Нужен вход')}
 return r.json().catch(()=>({ok:false,output:'HTTP '+r.status}))}
function bytes(n){const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]}
function age(s){if(s==null)return null;if(s<120)return s+' с назад';if(s<7200)return Math.round(s/60)+' мин назад';return Math.round(s/3600)+' ч назад'}
function setBusy(b){busy=b;document.querySelectorAll('#app button,#app select,#app input').forEach(x=>x.disabled=b)}
async function act(body,label){
 if(busy)return;setBusy(true);log(label+'…');
 try{const j=await api('/api/action',body);log((j.ok?'OK: ':'Ошибка: ')+(j.output||''))}catch(e){log('Ошибка: '+e.message)}
 setBusy(false);refresh()}
function btn(text,body,label,cls,confirmText){const b=el('button',text,cls);b.disabled=busy;b.onclick=()=>{if(confirmText&&!confirm(confirmText))return;act(body,label)};return b}
function showLogin(){$('#app').hidden=true;$('#logout').hidden=true;$('#login').hidden=false;$('#pw').focus()}
function policySelect(h){
 const s=el('select');
 const add=(v,t)=>{const o=el('option',t);o.value=v;s.append(o)};
 add('blocked','без интернета');
 for(const p of S.profiles)if(p.valid)add('tunnel:'+p.name,'туннель: '+p.name);
 add('direct','напрямую через WAN (без VPN)');
 s.value=h.mode==='tunnel'?'tunnel:'+h.profile:h.mode;
 s.onchange=()=>{const v=s.value;
  if(v==='direct'&&!confirm('Хост '+h.name+' будет выходить в интернет напрямую, без VPN. Продолжить?')){s.value=h.mode==='tunnel'?'tunnel:'+h.profile:h.mode;return}
  const body=v.startsWith('tunnel:')?{action:'host-set',name:h.name,mode:'tunnel',profile:v.slice(7)}:{action:'host-set',name:h.name,mode:v};
  act(body,'Политика '+h.name+' → '+s.options[s.selectedIndex].text)};
 return s}
function render(){
 const r=S.router;
 $('#router').textContent='управление '+r.mgmt_addr+' · ssh :'+r.ssh_port+' · WAN '+(r.wan.address||'нет адреса')+' → '+(r.wan.gateway||'нет шлюза');
 $('#mgmtIp').textContent=r.mgmt_addr;
 const hb=$('#hosts');hb.replaceChildren();
 for(const h of S.hosts){
  const tr=el('tr');
  const n=el('td');n.append(el('div',h.name,h.online?'ok':''));if(h.hostname)n.append(el('small',h.hostname));tr.append(n);
  const a=el('td');a.append(el('div',h.ip));a.append(el('small',h.mac));tr.append(a);
  const p=el('td');p.append(policySelect(h));tr.append(p);
  const l=el('td');const cb=el('input');cb.type='checkbox';cb.checked=!!h.local;cb.disabled=busy;
  cb.onchange=()=>act({action:'host-set',name:h.name,local:cb.checked},'Домашняя сеть '+h.name+': '+(cb.checked?'да':'нет'));l.append(cb);tr.append(l);
  tr.append(el('td',h.forwards.map(f=>f.proto+' '+f.port+'→'+f.to_port).join(', ')||'—'));
  const t=el('td',null,'actions');t.append(btn('Удалить',{action:'host-del',name:h.name},'Удаление '+h.name,'danger','Удалить хост '+h.name+' и его пробросы?'));tr.append(t);
  hb.append(tr)}
 if(!S.hosts.length){const tr=el('tr');const td=el('td','Хостов нет. Включите ВМ в LAN-сегменте — она появится ниже.');td.colSpan=6;tr.append(td);hb.append(tr)}
 const u=$('#unknown');u.replaceChildren();
 if(!S.unknown.length)u.textContent='Все ВМ сегмента зарегистрированы.';
 for(const d of S.unknown){const row=el('div',null,'row');row.append(el('span',d.ip+'  '+d.mac+(d.hostname?'  '+d.hostname:'')+'  — без интернета'));
  const b=el('button','Добавить как хост');b.onclick=()=>{$('#hMac').value=d.mac;$('#hName').value=(d.hostname||'').toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,31);$('#hName').focus()};row.append(b);u.append(row)}
 const tb=$('#tunnels');tb.replaceChildren();
 for(const t of S.tunnels){const tr=el('tr');
  tr.append(el('td',t.dev));tr.append(el('td',t.profile));tr.append(el('td',t.endpoint||'—'));
  const a=age(t.handshake_age);tr.append(el('td',t.up?(a||'не было'):'не поднят',t.up&&t.handshake_age!=null&&t.handshake_age<180?'ok':'bad'));
  tr.append(el('td','↓ '+bytes(t.rx)+'  ↑ '+bytes(t.tx)));tr.append(el('td',t.hosts.join(', ')||'—'));
  const c=el('td',null,'actions');c.append(btn('Перезапустить',{action:'restart',profile:t.profile},'Перезапуск '+t.profile));tr.append(c);tb.append(tr)}
 if(!S.tunnels.length){const tr=el('tr');const td=el('td','Нет активных туннелей.');td.colSpan=7;tr.append(td);tb.append(tr)}
 const c=S.corporate,d=$('#corp');d.replaceChildren();
 const add=(k,v,cls)=>{d.append(el('dt',k));d.append(el('dd',v,cls))};
 add('Режим',c.enabled?'через корпоративный VPN':'напрямую через WAN',c.enabled?(c.address?'ok':'bad'):'');
 add('Профиль',c.profile?(c.error?'ошибка: '+c.error:'загружен'+(c.needs_auth?(c.auth?', логин сохранён':', нужен логин/пароль'):'')):'не загружен',c.error?'bad':'');
 if(c.enabled)add('OpenVPN',c.service+(c.address?', адрес '+c.address:', нет адреса — туннели хостов без выхода'),c.address?'ok':'bad');
 $('#corpOn').disabled=busy||!c.profile||c.enabled;$('#corpOff').disabled=busy||!c.enabled;
 const pb=$('#profiles');pb.replaceChildren();
 for(const p of S.profiles){const tr=el('tr');
  tr.append(el('td',p.name));tr.append(el('td','awg'+p.id));
  tr.append(p.valid?el('td',p.endpoint):el('td',p.error||'ошибка','bad'));tr.append(el('td',p.address||'—'));
  tr.append(el('td',p.used_by.join(', ')||'—'));
  const a=el('td',null,'actions');if(!p.used_by.length)a.append(btn('Удалить',{action:'profile-delete',name:p.name},'Удаление '+p.name,'danger','Удалить профиль '+p.name+'?'));tr.append(a);pb.append(tr)}
 const fb=$('#forwards');fb.replaceChildren();
 for(const f of S.forwards){const tr=el('tr');
  [f.proto,f.port,f.host,f.to_port,f.source==='local'?'хост Windows + локальные сети':'только хост Windows'].forEach(x=>tr.append(el('td',String(x))));
  const a=el('td',null,'actions');a.append(btn('Удалить',{action:'fwd-del',proto:f.proto,port:f.port},'Удаление проброса '+f.proto+' '+f.port,'danger'));tr.append(a);fb.append(tr)}
 const fh=$('#fHost'),cur=fh.value;fh.replaceChildren();for(const h of S.hosts){const o=el('option',h.name);o.value=h.name;fh.append(o)}if(cur)fh.value=cur;
 setBusy(busy)}
async function refresh(){
 try{const j=await api('/api/status');if(!j.ok){log('Ошибка: '+j.output);return}
  S=j.data;$('#login').hidden=true;$('#app').hidden=false;$('#logout').hidden=false;render()}
 catch(e){}}
$('#loginForm').onsubmit=async e=>{e.preventDefault();
 const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-VMGW':'1'},body:JSON.stringify({password:$('#pw').value})});
 $('#pw').value='';const j=await r.json().catch(()=>({}));if(r.ok)refresh();else alert(j.output||'Ошибка входа')};
$('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST',headers:{'X-VMGW':'1'}});showLogin()};
document.querySelectorAll('button[data-act]').forEach(b=>b.onclick=()=>act({action:b.dataset.act},b.textContent));
$('#hostForm').onsubmit=e=>{e.preventDefault();act({action:'host-add',name:$('#hName').value.trim(),mac:$('#hMac').value.trim(),ip:$('#hIp').value.trim()},'Добавление хоста '+$('#hName').value).then(()=>{$('#hostForm').reset()})};
$('#fwdForm').onsubmit=e=>{e.preventDefault();act({action:'fwd-add',proto:$('#fProto').value,port:+$('#fPort').value,host:$('#fHost').value,to_port:+$('#fTo').value,source:$('#fSrc').value},'Проброс '+$('#fPort').value+' → '+$('#fHost').value+':'+$('#fTo').value)};
function readFile(input,cb){const f=input.files[0];if(!f){log('Выберите файл');return}const r=new FileReader();r.onload=()=>cb(f,r.result);r.readAsText(f)}
$('#uploadBtn').onclick=()=>readFile($('#file'),(f,data)=>act({action:'import',name:f.name,data},'Загрузка '+f.name).then(()=>{$('#file').value=''}));
$('#corpUpload').onclick=()=>readFile($('#corpFile'),(f,data)=>act({action:'corp-import',data},'Загрузка корпоративного профиля').then(()=>{$('#corpFile').value=''}));
$('#corpAuth').onsubmit=e=>{e.preventDefault();act({action:'corp-credentials',login:$('#cLogin').value,password:$('#cPass').value},'Сохранение учётных данных').then(()=>{$('#corpAuth').reset()})};
$('#corpOn').onclick=()=>{if(confirm('Все туннели хостов пойдут через корпоративный VPN. Если он не подключится, хосты останутся без интернета. Продолжить?'))act({action:'corp-set',enabled:true},'Включение корпоративного транспорта')};
$('#corpOff').onclick=()=>act({action:'corp-set',enabled:false},'Выключение корпоративного транспорта');
refresh();setInterval(()=>{if(!busy&&!$('#app').hidden)refresh()},5000);
'''


def ctl(req, timeout=180):
    try:
        p = subprocess.run(CTL, input=json.dumps(req).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'output': 'Таймаут'}
    try:
        return json.loads(p.stdout.decode())
    except ValueError:
        err = p.stderr.decode(errors='replace').strip().splitlines()
        return {'ok': False, 'output': err[-1] if err else 'Контроллер недоступен (sudo?)'}


def check_password(pw):
    try:
        algo, it, salt, digest = open(PASSFILE).read().strip().split('$')
    except (OSError, ValueError):
        return False
    if algo != 'pbkdf2_sha256':
        return False
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), base64.b64decode(salt), int(it))
    return hmac.compare_digest(dk, base64.b64decode(digest))


class Handler(BaseHTTPRequestHandler):
    server_version = 'vmgw-web'
    sys_version = ''

    def allowed(self):
        try:
            ip = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        if not any(ip in n for n in ALLOWED):
            return False
        # Host must be an IP literal with our port: protects against DNS rebinding.
        h, _, port = self.headers.get('Host', '').rpartition(':')
        if port != str(PORT):
            return False
        try:
            ipaddress.ip_address(h)
        except ValueError:
            return False
        return True

    def send(self, code, body, ctype, cookie=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
        if cookie is not None:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def json(self, code, obj, cookie=None):
        self.send(code, json.dumps(obj, ensure_ascii=False), 'application/json; charset=utf-8', cookie)

    def session(self):
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'vmgw':
                with LOCK:
                    exp = SESSIONS.get(v)
                    if exp and exp > time.time():
                        return v
                    SESSIONS.pop(v, None)
        return None

    def api_ok(self):
        # A custom header cannot be sent cross-origin without a CORS preflight we never answer.
        if self.headers.get('X-VMGW') != '1':
            self.json(403, {'ok': False, 'output': 'Bad request'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != 'http://' + self.headers.get('Host', ''):
            self.json(403, {'ok': False, 'output': 'Bad origin'})
            return False
        return True

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return None
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return None
        if not 0 < length <= MAX_BODY:
            return None
        try:
            obj = json.loads(self.rfile.read(length).decode())
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def do_GET(self):
        if not self.allowed():
            return self.send(403, 'Forbidden', 'text/plain; charset=utf-8')
        path = self.path.split('?', 1)[0]
        if path == '/':
            return self.send(200, PAGE, 'text/html; charset=utf-8')
        if path == '/app.css':
            return self.send(200, CSS, 'text/css; charset=utf-8')
        if path == '/app.js':
            return self.send(200, JS, 'application/javascript; charset=utf-8')
        if path == '/api/status':
            if not self.api_ok():
                return
            if not self.session():
                return self.json(401, {'ok': False, 'output': 'Нужен вход'})
            return self.json(200, ctl({'action': 'status'}, timeout=30))
        self.send(404, 'Not found', 'text/plain; charset=utf-8')

    def do_POST(self):
        if not self.allowed():
            return self.send(403, 'Forbidden', 'text/plain; charset=utf-8')
        if not self.api_ok():
            return
        path = self.path.split('?', 1)[0]
        req = self.body()
        if path == '/api/logout':
            s = self.session()
            with LOCK:
                SESSIONS.pop(s, None)
            return self.json(200, {'ok': True}, 'vmgw=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict')
        if req is None:
            return self.json(400, {'ok': False, 'output': 'Нужен JSON'})
        if path == '/api/login':
            now = time.time()
            with LOCK:
                FAILS[:] = [t for t in FAILS if t > now - 600]
                locked = len(FAILS) >= 10
            if locked:
                return self.json(429, {'ok': False, 'output': 'Слишком много попыток, подождите 10 минут'})
            pw = req.get('password')
            if isinstance(pw, str) and check_password(pw):
                token = secrets.token_urlsafe(32)
                with LOCK:
                    SESSIONS[token] = now + SESSION_TTL
                return self.json(200, {'ok': True}, 'vmgw=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict' % (token, SESSION_TTL))
            time.sleep(1)
            with LOCK:
                FAILS.append(now)
            sys.stderr.write('%s login failed\n' % self.client_address[0])
            return self.json(403, {'ok': False, 'output': 'Неверный пароль'})
        if path != '/api/action':
            return self.json(404, {'ok': False, 'output': 'Not found'})
        if not self.session():
            return self.json(401, {'ok': False, 'output': 'Нужен вход'})
        if req.get('action') == 'status':
            return self.json(400, {'ok': False, 'output': 'Bad action'})
        if not ACTION_LOCK.acquire(blocking=False):
            return self.json(409, {'ok': False, 'output': 'Выполняется другая операция'})
        try:
            res = ctl(req)
        finally:
            ACTION_LOCK.release()
        sys.stderr.write('%s action=%s ok=%s\n' % (self.client_address[0], str(req.get('action'))[:20], res.get('ok')))
        self.json(200 if res.get('ok') else 500, {'ok': res.get('ok'), 'output': res.get('output', '')})

    def log_message(self, fmt, *args):
        pass


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == '__main__':
    Server(('0.0.0.0', PORT), Handler).serve_forever()
