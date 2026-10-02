"""
Vortex.AI — asistente de IA completo en Python (Flask + SQLite + Claude).

Ejecutar:
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY="tu_clave"
    python app.py            ->  http://localhost:5000

Opcional (login social):
    GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
    FACEBOOK_CLIENT_ID / FACEBOOK_CLIENT_SECRET
"""
import json, os, secrets, sqlite3
from functools import wraps

import anthropic
from authlib.integrations.flask_client import OAuth
from flask import Flask, Response, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

MODEL = os.getenv("IA_MODELO", "claude-sonnet-5-5")
DB = "vortex.db"
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "cambia-esto-en-produccion")
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024
client = anthropic.Anthropic()
oauth, SOCIAL = OAuth(app), set()

if os.getenv("GOOGLE_CLIENT_ID"):
    oauth.register("google", client_id=os.getenv("GOOGLE_CLIENT_ID"), client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                   server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                   client_kwargs={"scope": "openid email profile"})
    SOCIAL.add("google")
if os.getenv("FACEBOOK_CLIENT_ID"):
    oauth.register("facebook", client_id=os.getenv("FACEBOOK_CLIENT_ID"), client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
                   access_token_url="https://graph.facebook.com/oauth/access_token",
                   authorize_url="https://www.facebook.com/dialog/oauth",
                   api_base_url="https://graph.facebook.com/", client_kwargs={"scope": "email"})
    SOCIAL.add("facebook")

SYSTEM = """Eres Vortex.AI, un asistente elegante, amable y muy claro. Hablas cualquier idioma y respondes en el del usuario.
Traduces con naturalidad. Explicas paso a paso con ejemplos y, cuando ayude, añades una ilustración sencilla como bloque ```svg
(con viewBox, sin scripts). Si piden una imagen, créala como SVG. Sabes crear juegos (HTML/JS o Python), código Python, proyectos
Arduino, guiones de podcast y resolver problemas complejos razonando con rigor. En datos factuales cita fuentes fiables y admite
cuando no estés seguro. En conversaciones con varias personas, cada mensaje empieza con el nombre de quien lo escribe."""

# ------------------------------- Base de datos -------------------------------

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def cerrar(_):
    if "db" in g:
        g.db.close()

def init():
    with sqlite3.connect(DB) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, name TEXT);
        CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, title TEXT, token TEXT);
        CREATE TABLE IF NOT EXISTS members(chat_id INTEGER, user_id INTEGER, UNIQUE(chat_id,user_id));
        CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, chat_id INTEGER, role TEXT, name TEXT, text TEXT);""")

def me():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not me():
            return jsonify(error="Inicia sesión"), 401
        return f(*a, **k)
    return w

def es_miembro(cid):
    return db().execute("SELECT 1 FROM members WHERE chat_id=? AND user_id=?", (cid, session["uid"])).fetchone()

def claude(messages, system=SYSTEM, max_tokens=2500):
    r = client.messages.create(model=MODEL, max_tokens=max_tokens, system=system, messages=messages)
    return "".join(b.text for b in r.content if b.type == "text")

# ------------------------------ Cuentas y login ------------------------------

@app.post("/api/register")
def register():
    d = request.json
    email, pw = d.get("email", "").strip().lower(), d.get("pw", "")
    if "@" not in email or len(pw) < 6:
        return jsonify(error="Correo válido y contraseña de 6+ caracteres")
    if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="Ese correo ya existe")
    cur = db().execute("INSERT INTO users(email,pw) VALUES(?,?)", (email, generate_password_hash(pw)))
    db().commit()
    session["uid"] = cur.lastrowid
    return jsonify(ok=1)

@app.post("/api/login")
def login():
    d = request.json
    u = db().execute("SELECT * FROM users WHERE email=?", (d.get("email", "").strip().lower(),)).fetchone()
    if not u or not u["pw"] or not check_password_hash(u["pw"], d.get("pw", "")):
        return jsonify(error="Datos incorrectos")
    session["uid"] = u["id"]
    return jsonify(ok=1)

@app.post("/api/name")
@login_required
def set_name():
    db().execute("UPDATE users SET name=? WHERE id=?", (request.json.get("name", "").strip()[:40], session["uid"]))
    db().commit()
    return jsonify(ok=1)

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.get("/login/<p>")
def social(p):
    if p not in SOCIAL:
        return "Proveedor no configurado: define sus variables de entorno.", 400
    return oauth.create_client(p).authorize_redirect(url_for("callback", p=p, _external=True))

@app.get("/auth/<p>")
def callback(p):
    c = oauth.create_client(p)
    tok = c.authorize_access_token()
    info = tok.get("userinfo") or c.get("me?fields=id,name,email").json()
    email = (info.get("email") or f"{p}:{info.get('id') or info.get('sub')}").lower()
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        cur = db().execute("INSERT INTO users(email,name) VALUES(?,?)", (email, (info.get("name") or "").split(" ")[0] or None))
        db().commit()
        session["uid"] = cur.lastrowid
    else:
        session["uid"] = u["id"]
    return redirect("/")

# ---------------------------------- Chats ------------------------------------

@app.get("/api/chats")
@login_required
def chats():
    rows = db().execute("SELECT c.id,c.title FROM chats c JOIN members m ON m.chat_id=c.id WHERE m.user_id=? ORDER BY c.id DESC",
                        (session["uid"],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/chats/<int:cid>")
@login_required
def mensajes(cid):
    if not es_miembro(cid):
        return jsonify([]), 403
    rows = db().execute("SELECT role,name,text FROM msgs WHERE chat_id=? ORDER BY id", (cid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/chat")
@login_required
def chat():
    d, u = request.json, me()
    text, cid, archivos = (d.get("text") or "").strip(), d.get("chat_id"), d.get("files", [])
    if cid and not es_miembro(cid):
        return jsonify(error="No tienes acceso a esta conversación"), 403
    hist = []
    if cid:
        rows = db().execute("SELECT role,name,text FROM msgs WHERE chat_id=? ORDER BY id DESC LIMIT 30", (cid,)).fetchall()[::-1]
        hist = [{"role": r["role"], "content": (f"{r['name']}: " if r["role"] == "user" else "") + r["text"]} for r in rows]
    content = []
    for f in archivos:
        if f.get("img"):
            content.append({"type": "image", "source": {"type": "base64", "media_type": f["type"], "data": f["d"]}})
        else:
            content.append({"type": "text", "text": f"Archivo {f['name']}" + (f":\n{f['d']}" if f.get("d") else " (sin contenido legible)")})
    content.append({"type": "text", "text": f"{u['name']}: {text or 'Analiza lo adjunto'}"})
    try:
        respuesta = claude(hist + [{"role": "user", "content": content}])
    except anthropic.APIError as e:
        return jsonify(error=str(e))
    nuevo = not cid
    if nuevo:
        titulo = text[:30] or "Adjuntos"
        try:
            titulo = claude([{"role": "user", "content": "Resume en máximo 5 palabras, sin comillas, el tema de: " + text}],
                            "Responde solo con el título.", 30)[:50]
        except anthropic.APIError:
            pass
        cid = db().execute("INSERT INTO chats(title,token) VALUES(?,?)", (titulo, secrets.token_urlsafe(12))).lastrowid
        db().execute("INSERT INTO members VALUES(?,?)", (cid, u["id"]))
    guardado = text + (f"\n[Adjuntos: {', '.join(f['name'] for f in archivos)}]" if archivos else "")
    db().execute("INSERT INTO msgs(chat_id,role,name,text) VALUES(?,?,?,?)", (cid, "user", u["name"], guardado))
    db().execute("INSERT INTO msgs(chat_id,role,name,text) VALUES(?,?,?,?)", (cid, "assistant", "Vortex", respuesta))
    db().commit()
    return jsonify(chat_id=cid)

@app.get("/api/invite/<int:cid>")
@login_required
def invitar(cid):
    if not es_miembro(cid):
        return jsonify(error="Sin acceso"), 403
    t = db().execute("SELECT token FROM chats WHERE id=?", (cid,)).fetchone()["token"]
    return jsonify(url=url_for("unirse", token=t, _external=True))

@app.get("/join/<token>")
def unirse(token):
    session["join"] = token
    return redirect("/")

# --------------------------------- Arduino -----------------------------------

@app.post("/api/arduino")
@login_required
def arduino():
    """Envía texto al Arduino conectado al equipo donde corre el servidor (pyserial)."""
    import serial
    d = request.json
    try:
        with serial.Serial(d["port"], int(d.get("baud", 9600)), timeout=2) as s:
            s.write((d["text"] + "\n").encode())
            return jsonify(reply=s.readline().decode(errors="ignore").strip())
    except Exception as e:
        return jsonify(error=str(e))

# ----------------------------------- Web -------------------------------------

@app.get("/")
def index():
    u = me()
    if u and session.get("join"):
        c = db().execute("SELECT id FROM chats WHERE token=?", (session.pop("join"),)).fetchone()
        if c:
            db().execute("INSERT OR IGNORE INTO members VALUES(?,?)", (c["id"], u["id"]))
            db().commit()
    datos = {"email": u["email"], "name": u["name"], "social": sorted(SOCIAL)} if u else {"social": sorted(SOCIAL)}
    html = PAGINA.replace("__ME__", json.dumps(datos).replace("</", "<\\/"))
    return Response(html, mimetype="text/html")

PAGINA = r"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vortex.AI</title>
<style>
:root{--bg:#0a0f1e;--p:#111a33;--g:#c9a24b;--t:#f3ecdc;--m:#9aa3bd}*{box-sizing:border-box}
body{margin:0;height:100vh;background:radial-gradient(circle at 20% 0,#16224a,var(--bg) 60%);color:var(--t);font-family:Georgia,'Times New Roman',serif}
button,input,textarea{font:inherit;color:inherit}button{cursor:pointer;background:transparent;border:3px solid var(--g);padding:8px 14px}button:hover{background:var(--g);color:var(--bg)}
input,textarea{background:#0c1328;border:3px solid #2a3560;padding:10px;width:100%;outline:0}input:focus,textarea:focus{border-color:var(--g)}
.hide{display:none!important}.center{height:100%;display:flex;align-items:center;justify-content:center}
.card{border:3px solid var(--g);background:var(--p);padding:28px;width:min(400px,92vw);display:grid;gap:12px;text-align:center}
.lg{width:64px;height:64px;margin:auto}.brand{font-size:30px;letter-spacing:3px}.brand b{color:var(--g)}
#app{height:100%;display:flex}#side{width:260px;border-right:3px solid var(--g);background:var(--p);padding:14px;display:flex;flex-direction:column;gap:8px}
#list{flex:1;overflow:auto;display:grid;gap:6px;align-content:start}#list div{padding:8px;border:2px solid #2a3560;cursor:pointer;font-size:14px}#list div:hover,#list .on{border-color:var(--g)}
#main{flex:1;display:flex;flex-direction:column;min-width:0}#msgs{flex:1;overflow:auto;padding:24px;display:grid;gap:14px;align-content:start}
.m{max-width:760px;padding:12px 16px;border:3px solid #2a3560;line-height:1.55;overflow-wrap:anywhere}.u{justify-self:end;border-color:var(--g)}
.m pre{background:#070b17;padding:10px;overflow:auto;border-left:4px solid var(--g)}.m img{max-width:100%;background:#fff;padding:6px}.m button{padding:2px 8px;font-size:13px;margin-top:6px}
.chips{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-top:18px}
#bar{border-top:3px solid var(--g);padding:12px;display:flex;gap:8px;align-items:flex-end;background:var(--p)}#bar textarea{resize:none;height:48px}
#mic.on{background:#b3261e;border-color:#b3261e}#log{font-size:12px;color:var(--m);padding:2px 14px}@media(max-width:700px){#side{display:none}}
</style></head><body>
<svg style="display:none"><symbol id="lg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="29" fill="none" stroke="#c9a24b" stroke-width="3"/><path d="M32 32a4 4 0 0 1 8 0a9 9 0 0 1-18 0a15 15 0 0 1 30 0a21 21 0 0 1-42 0" fill="none" stroke="#c9a24b" stroke-width="4" stroke-linecap="round"/></symbol></svg>
<div id="auth" class="center hide"><div class="card"><svg class="lg"><use href="#lg"/></svg><div class="brand">Vortex<b>.AI</b></div>
<input id="em" type="email" placeholder="Correo electrónico"><input id="pw" type="password" placeholder="Contraseña (mín. 6)"><div id="err" style="color:#ff8a80;min-height:18px"></div>
<button onclick="auth(0)">Entrar</button><button onclick="auth(1)">Crear cuenta</button>
<button onclick="location='/login/google'">Continuar con Google</button><button onclick="location='/login/facebook'">Continuar con Facebook</button></div></div>
<div id="name" class="center hide"><div class="card"><svg class="lg"><use href="#lg"/></svg><div class="brand">Vortex<b>.AI</b></div><p>¿Cómo te llamas?</p>
<input id="nm" placeholder="Tu nombre" onkeydown="if(event.key=='Enter')setName()"><button onclick="setName()">Continuar</button></div></div>
<div id="app" class="hide"><div id="side"><div class="brand" style="font-size:22px;display:flex;align-items:center;gap:8px"><svg class="lg" style="width:34px;height:34px;margin:0"><use href="#lg"/></svg><span>Vortex<b>.AI</b></span></div>
<button onclick="newChat()">+ Nueva conversación</button><div id="list"></div><button onclick="invite()">Invitar a esta conversación</button><button onclick="location='/logout'">Salir</button></div>
<div id="main"><div id="msgs"></div><div id="log"></div><div id="bar"><button onclick="$('#fi').click()" title="Adjuntar">📎</button><input id="fi" type="file" multiple class="hide" onchange="attach(this.files)">
<button id="mic" onclick="mic()" title="Dictar">🎤</button><textarea id="in" placeholder="Escribe tu mensaje…" onkeydown="if(event.key=='Enter'&&!event.shiftKey){event.preventDefault();send()}"></textarea>
<button onclick="toArd()">→ Arduino</button><button onclick="send()">Enviar</button></div></div></div>
<script>
const ME=__ME__,$=s=>document.querySelector(s);let cur=null,files=[],busy=0,M=[],port=null;
const api=(u,b)=>fetch(u,{method:b?'POST':'GET',headers:{'content-type':'application/json'},body:b?JSON.stringify(b):undefined}).then(r=>r.json());
const esc=s=>s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const show=id=>['auth','name','app'].forEach(x=>$('#'+x).classList.toggle('hide',x!=id));
if(!ME.email)show('auth');else if(!ME.name)show('name');else{show('app');list();draw();setInterval(()=>cur&&!busy&&open(cur),6000)}
async function auth(r){const x=await api(r?'/api/register':'/api/login',{email:$('#em').value,pw:$('#pw').value});x.error?$('#err').textContent=x.error:location.reload()}
async function setName(){await api('/api/name',{name:$('#nm').value});location.reload()}
async function list(){const c=await api('/api/chats');$('#list').innerHTML='';c.forEach(x=>{const d=document.createElement('div');d.textContent=x.title;d.className=x.id==cur?'on':'';d.onclick=()=>open(x.id);$('#list').append(d)})}
async function open(id){const m=await api('/api/chats/'+id);if(id==cur&&m.length==M.length)return;cur=id;M=m;draw();list()}
function newChat(){cur=null;M=[];draw();list()}
function md(t){return t.split(/```/).map((p,i)=>{if(i%2==0)return esc(p).replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/\n/g,'<br>');const n=p.indexOf('\n'),l=p.slice(0,n).trim(),c=p.slice(n+1);
 return l=='svg'?`<img src="data:image/svg+xml;utf8,${encodeURIComponent(c)}">`:`<pre><code>${esc(c)}</code></pre>`}).join('')}
function draw(){const b=$('#msgs');b.innerHTML='';
 if(!M.length){b.innerHTML=`<div style="text-align:center;margin:auto;padding-top:8vh"><svg class="lg" style="width:84px;height:84px"><use href="#lg"/></svg><h1 style="font-weight:400">¿En qué puedo ayudarte, ${esc(ME.name||'')}?</h1><div class="chips">${[['Explicarme algo','Explícame '],['Traducir','Traduce al inglés: '],['Diseñar','Ayúdame a diseñar '],['Escribir podcasts','Escribe un guion de podcast sobre '],['Inventar juegos','Invéntame un juego y prográmalo: '],['Otro tema','']].map(([a,c])=>`<button onclick="$('#in').value='${c}';$('#in').focus()">${a}</button>`).join('')}</div></div>`;return}
 M.forEach((m,i)=>{const d=document.createElement('div'),u=m.role=='user';d.className='m '+(u?'u':'');d.innerHTML=(u&&m.name?`<small style="color:var(--g)">${esc(m.name)}</small><br>`:'')+md(m.text)+(u?'':`<br><button onclick="say(${i})">🔊 Escuchar</button>`);b.append(d)});b.scrollTop=1e9}
async function send(){const t=$('#in').value.trim();if(!t&&!files.length)return;busy=1;M.push({role:'user',name:ME.name,text:t});draw();const f=files;files=[];$('#in').value='';$('#log').textContent='Pensando…';
 const r=await api('/api/chat',{chat_id:cur,text:t,files:f});busy=0;$('#log').textContent='';if(r.error){M.push({role:'assistant',text:'⚠️ '+r.error});draw();return}cur=null;open(r.chat_id)}
function attach(fl){[...fl].forEach(f=>{const r=new FileReader(),img=/^image\/(png|jpeg|gif|webp)$/.test(f.type),txt=f.type.startsWith('text/')||/\.(py|js|json|csv|md|ino|html|css|txt)$/.test(f.name);
 r.onload=()=>{files.push({name:f.name,type:f.type,img,d:img?r.result.split(',')[1]:r.result.slice(0,60000)});$('#log').textContent='Adjuntos: '+files.map(x=>x.name)};
 if(img)r.readAsDataURL(f);else if(txt)r.readAsText(f);else files.push({name:f.name,type:f.type})})}
function mic(){const R=window.SpeechRecognition||window.webkitSpeechRecognition;if(!R)return alert('Usa Chrome o Edge para dictar.');const r=new R(),b=$('#mic'),base=$('#in').value;r.lang=navigator.language;r.interimResults=true;b.classList.add('on');
 r.onresult=e=>$('#in').value=(base+' '+[...e.results].map(x=>x[0].transcript).join('')).trim();r.onend=()=>b.classList.remove('on');r.start()}
function say(i){speechSynthesis.cancel();speechSynthesis.speak(new SpeechSynthesisUtterance(M[i].text.replace(/```[\s\S]*?```/g,'').replace(/[*#`]/g,'')))}
async function invite(){if(!cur)return alert('Abre una conversación primero.');const r=await api('/api/invite/'+cur);navigator.clipboard.writeText(r.url);alert('Enlace copiado: '+r.url)}
async function toArd(){port=port||prompt('Puerto del Arduino (COM3, /dev/ttyUSB0…)');if(!port)return;const r=await api('/api/arduino',{port,text:$('#in').value});$('#in').value='';$('#log').textContent=r.error?'Arduino: '+r.error:'Arduino respondió: '+r.reply}
</script></body></html>"""

if __name__ == "__main__":
    init()
    app.run(debug=True)
