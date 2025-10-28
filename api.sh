#!/bin/bash
# ZI One-Time Key API (Login + Modern UI) — single-file installer
# Install:
#   sudo bash api.sh --install --secret="changeme" --port=8088 [--user=NAME --pass=PASS]
# Manage:
#   sudo bash api.sh --status | --logs | --restart | --uninstall
set -euo pipefail

# ===== Defaults =====
SECRET="changeme"                       # X-Admin-Secret (for /api/generate)
PORT="8088"                             # Web/API port
DB="/var/lib/upkapi/keys.db"            # SQLite DB
BIND="0.0.0.0"                          # Bind address
APPDIR="/opt/zi-keyapi"                 # App dir
ENVF="/etc/default/zi-keyapi"           # Environment file used by systemd
UNIT="/etc/systemd/system/zi-keyapi.service"
LOGO_URL="https://raw.githubusercontent.com/Upk123/upkvip-ziscript/refs/heads/main/20251018_231111.png"

# ===== Parse args =====
ACTION=""
CLI_USER=""; CLI_PASS=""
for a in "$@"; do
  case "$a" in
    --install) ACTION="install" ;;
    --uninstall) ACTION="uninstall" ;;
    --restart) ACTION="restart" ;;
    --status) ACTION="status" ;;
    --logs) ACTION="logs" ;;
    --secret=*) SECRET="${a#*=}" ;;
    --port=*)   PORT="${a#*=}" ;;
    --db=*)     DB="${a#*=}" ;;
    --bind=*)   BIND="${a#*=}" ;;
    --user=*)   CLI_USER="${a#*=}" ;;
    --pass=*)   CLI_PASS="${a#*=}" ;;
    *) ;;
  esac
done
[ -z "${ACTION}" ] && ACTION="install"

say(){ echo -e "$*"; }
ok(){ say "\e[1;32m$*\e[0m"; }
info(){ say "\e[1;36m$*\e[0m"; }

ask_credentials() {
  if [ -n "${CLI_USER}" ] && [ -n "${CLI_PASS}" ]; then
    ADMIN_USER="$CLI_USER"; ADMIN_PASS="$CLI_PASS"
    say "\n\033[1;33m🔐 Admin Login (from flags)\033[0m"
    say "Admin Username: $ADMIN_USER"
    return
  fi
  say "\n\033[1;33m🔐 Admin Login သတ်မှတ်ပါ\033[0m"
  while :; do
    read -rp "Admin Username: " ADMIN_USER
    [ -n "${ADMIN_USER:-}" ] && break
  done
  while :; do
    if [ -t 0 ]; then read -rsp "Admin Password: " ADMIN_PASS; echo; else read -rp "Admin Password (visible): " ADMIN_PASS; fi
    [ -n "${ADMIN_PASS:-}" ] && break
  done
}

install_pkgs() {
  apt-get update -y >/dev/null
  apt-get install -y python3 python3-flask sqlite3 curl ca-certificates >/dev/null
}

write_app_py() {
  mkdir -p "$APPDIR" "$(dirname "$DB")"
  cat >"$APPDIR/app.py" <<'PY'
import os, sqlite3, uuid, datetime
from flask import Flask, request, jsonify, g, session, redirect, url_for, render_template_string

# ==== ENV ====
ADMIN_SECRET = os.environ.get("ADMIN_SECRET","changeme")     # header X-Admin-Secret
DB_PATH      = os.environ.get("DB_PATH","/var/lib/upkapi/keys.db")
BIND         = os.environ.get("BIND","0.0.0.0")
PORT         = int(os.environ.get("PORT","8088"))
LOGIN_USER   = os.environ.get("ADMIN_USER","admin")
LOGIN_PASS   = os.environ.get("ADMIN_PASS","pass")
APP_KEY      = os.environ.get("APP_SECRET_KEY","supersecret")
LOGO_URL     = os.environ.get("LOGO_URL","")

app = Flask(__name__)
app.secret_key = APP_KEY

# ==== DB ====
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        g.db.execute("""CREATE TABLE IF NOT EXISTS keys(
            id TEXT PRIMARY KEY,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP,
            used_at TIMESTAMP,
            used_ip TEXT,
            note TEXT
        )""")
        g.db.commit()
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None: db.close()

# ==== API (Flask 1.x/2.x compatible) ====
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

def is_admin(req):
    return req.headers.get("X-Admin-Secret","") == ADMIN_SECRET

@app.route("/api/generate", methods=["POST"])
def generate():
    if not is_admin(request):
        return jsonify({"ok":False, "error":"unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    hours = data.get("expires_in_hours", 24)
    note  = data.get("note")
    key_id = uuid.uuid4().hex
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(hours=int(hours)) if hours else None
    db = get_db()
    db.execute("INSERT INTO keys(id,created_at,expires_at,used_at,used_ip,note) VALUES(?,?,?,?,?,?)",
               (key_id, now, exp, None, None, note))
    db.commit()
    return jsonify({"ok": True, "key": key_id, "expires_at": exp.isoformat() if exp else None, "note": note})

@app.route("/api/consume", methods=["POST"])
def consume():
    data = request.get_json(silent=True) or {}
    key_id = data.get("key")
    if not key_id:
        return jsonify({"ok":False, "error":"missing_key"}), 400
    db=get_db()
    row = db.execute("SELECT id, expires_at, used_at FROM keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        return jsonify({"ok":False, "error":"invalid"}), 400
    _, expires_at, used_at = row
    now = datetime.datetime.utcnow()
    if used_at is not None:
        return jsonify({"ok":False, "error":"already_used"}), 409
    if expires_at is not None:
        if isinstance(expires_at, str):
            expires_at = datetime.datetime.fromisoformat(expires_at)
        if now > expires_at:
            return jsonify({"ok":False, "error":"expired"}), 410
    db.execute("UPDATE keys SET used_at=?, used_ip=? WHERE id=? AND used_at IS NULL",
               (now, request.remote_addr, key_id))
    db.commit()
    return jsonify({"ok":True,"msg":"consumed"})

# ==== UI ====
LOGIN_HTML = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>🔐 Login</title>
<style>
:root{--bg:#0b1020;--card:rgba(255,255,255,.08);--bd:rgba(255,255,255,.15);--fg:#fff;--brand:#3b82f6;--brand2:#1e40af}
@media (prefers-color-scheme: light){:root{--bg:#f6f7fb;--card:#fff;--bd:#e5e7eb;--fg:#0f172a}}
*{box-sizing:border-box} html,body{margin:0;background:var(--bg);color:var(--fg)}
body{display:grid;place-items:center;min-height:100vh;font-family:system-ui,Segoe UI,Roboto,"Noto Sans Myanmar",sans-serif}
.card{width:min(92vw,380px);background:var(--card);border:1px solid var(--bd);border-radius:20px;padding:22px;box-shadow:0 12px 40px rgba(0,0,0,.35);text-align:center}
.logo{width:110px;height:110px;border-radius:22px;object-fit:cover;display:block;margin:6px auto 12px;box-shadow:0 8px 26px rgba(0,0,0,.35)}
h2{margin:0 0 16px;font-size:1.35rem}
input{width:100%;height:46px;border:1px solid var(--bd);border-radius:12px;padding:10px;margin:8px 0;background:transparent;color:inherit;font-size:1rem}
button{width:100%;height:48px;border:0;border-radius:12px;background:linear-gradient(180deg,var(--brand),var(--brand2));color:#fff;font-weight:800;margin-top:6px}
.err{color:#f87171;margin-bottom:8px}
</style></head>
<body>
  <div class="card">
    <img class="logo" src="{{ logo }}">
    <h2>Admin Login</h2>
    {% if error %}<div class="err">{{error}}</div>{% endif %}
    <form method="post">
      <input name="username" placeholder="Username" required>
      <input name="password" type="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</body></html>
"""

ADMIN_HTML = """
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>🔑 One-Time Key</title>
<style>
:root{--bg:#0b1020;--card:rgba(255,255,255,.06);--bd:rgba(255,255,255,.15);--fg:#e8eefc;--ring:rgba(91,140,255,.35);--brand:#5b8cff;--brand2:#3e64ff}
@media (prefers-color-scheme: light){:root{--bg:#f7f8fb;--card:#fff;--bd:#e5e7eb;--fg:#0f172a;--ring:rgba(37,99,235,.25);--brand:#2563eb;--brand2:#1e40af}}
*{box-sizing:border-box} html,body{margin:0;background:var(--bg);color:var(--fg)}
body{min-height:100vh;display:grid;align-items:start;justify-items:center;font-family:system-ui,Segoe UI,Roboto,"Noto Sans Myanmar",sans-serif}
.wrap{padding:14px;width:100%}
.card{width:min(92vw,430px);background:var(--card);border:1px solid var(--bd);border-radius:22px;padding:18px 16px;box-shadow:0 20px 60px rgba(0,0,0,.25);backdrop-filter:blur(10px);margin:12px auto}
.logo{display:block;margin:6px auto 10px;height:110px;width:110px;border-radius:24px;object-fit:cover;box-shadow:0 8px 30px rgba(0,0,0,.35)}
h1{text-align:center;font-size:1.35rem;margin:0 0 12px;font-weight:800}
label{display:block;font-size:.95rem;margin:10px 6px 6px;opacity:.9}
input{width:100%;height:48px;border:1px solid var(--bd);background:transparent;color:inherit;padding:12px;border-radius:14px;font-size:1rem;outline:none}
input:focus{border-color:var(--brand);box-shadow:0 0 0 5px var(--ring)}
.row{display:flex;gap:10px}.row>*{flex:1}
.btn{width:100%;height:52px;margin-top:14px;border:0;border-radius:14px;background:linear-gradient(180deg,var(--brand),var(--brand2));color:#fff;font-weight:800;font-size:1.08rem}
.result{margin-top:12px;border:1px dashed var(--bd);border-radius:14px;padding:8px}
.resline{display:flex;gap:8px;align-items:center}
.resline input{flex:1;height:46px}
.copy{height:46px;padding:0 18px;border-radius:12px;border:1px solid var(--bd);background:rgba(255,255,255,.08);color:inherit;font-weight:700}
.topnav{max-width:430px;margin:10px auto 0;text-align:right;padding:0 8px}
.topnav a{color:inherit;opacity:.8;text-decoration:none}
</style></head>
<body>
<div class="wrap">
  <div class="topnav"><a href="/logout">Logout</a></div>
  <div class="card">
    <img class="logo" src="{{ logo }}">
    <h1>🔑 Generate One-Time Key</h1>

    <label>Admin Secret</label>
    <input id="sec" type="password" placeholder="X-Admin-Secret" autocomplete="current-password">

    <div class="row">
      <div>
        <label>Expires (hours)</label>
        <input id="hrs" type="number" inputmode="numeric" min="0" step="1" placeholder="0 = no expire">
      </div>
      <div>
        <label>Note</label>
        <input id="note" type="text" placeholder="optional">
      </div>
    </div>

    <div class="result">
      <div class="resline">
        <input id="keybox" type="text" placeholder="Ready." readonly>
        <button class="copy" onclick="copyKey()">Copy</button>
      </div>
    </div>

    <button class="btn" onclick="gen()">Generate</button>
  </div>
</div>

<script>
async function gen(){
  const sec=document.getElementById('sec').value.trim();
  const hrs=document.getElementById('hrs').value.trim();
  const note=document.getElementById('note').value.trim();
  const body={};
  if(hrs!=="" && !isNaN(parseInt(hrs))) body.expires_in_hours=parseInt(hrs);
  if(note!=="") body.note=note;

  const r=await fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Secret':sec},body:JSON.stringify(body)});
  const text=await r.text();
  try{ const j=JSON.parse(text); document.getElementById('keybox').value=j.key||text; }
  catch(e){ document.getElementById('keybox').value=text; }
}
async function copyKey(){
  const v=document.getElementById('keybox').value; if(!v) return;
  try{ await navigator.clipboard.writeText(v); }catch(e){}
}
</script>
</body></html>
"""

@app.route("/")
def root():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if u == LOGIN_USER and p == LOGIN_PASS:
            session["auth"] = True
            return redirect(url_for("admin"))
        return render_template_string(LOGIN_HTML, error="Invalid credentials", logo=LOGO_URL)
    return render_template_string(LOGIN_HTML, error=None, logo=LOGO_URL)

@app.route("/logout", methods=["GET"])
def logout():
    session.pop("auth", None)
    return redirect(url_for("login"))

@app.before_request
def guard():
    if request.path.startswith("/admin") and session.get("auth") != True:
        return redirect(url_for("login"))

@app.route("/admin", methods=["GET"])
def admin():
    return render_template_string(ADMIN_HTML, logo=LOGO_URL)

if __name__ == "__main__":
    app.run(host=BIND, port=PORT)
PY
  chmod 644 "$APPDIR/app.py"
}

write_unit() {
  cat >"$UNIT" <<EOF
[Unit]
Description=ZI One-Time Key API
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=-$ENVF
WorkingDirectory=$APPDIR
ExecStart=/usr/bin/python3 $APPDIR/app.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

write_env() {
  mkdir -p "$(dirname "$ENVF")" "$(dirname "$DB")"
  APPKEY=$(uuidgen 2>/dev/null || echo "key-$(date +%s)")
  cat >"$ENVF" <<EOF
ADMIN_SECRET=$SECRET
PORT=$PORT
DB_PATH=$DB
BIND=$BIND
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
APP_SECRET_KEY=$APPKEY
LOGO_URL=$LOGO_URL
EOF
  chmod 600 "$ENVF"
}

start_service() {
  systemctl daemon-reload
  systemctl enable --now zi-keyapi.service
}

# ===== Actions =====
case "$ACTION" in
  install)
    ask_credentials
    info "📦 Installing ZI One-Time Key API…"
    install_pkgs
    write_app_py
    write_env
    write_unit
    if command -v ufw >/dev/null 2>&1; then ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true; fi
    start_service
    sleep 1
    IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ok "✅ Installation complete!"
    echo "Root URL    : http://${IP:-<SERVER_IP>}:${PORT}/"
    echo "Admin Login : http://${IP:-<SERVER_IP>}:${PORT}/login"
    echo "Admin Panel : http://${IP:-<SERVER_IP>}:${PORT}/admin   (login first)"
    echo "Health      : curl -s http://127.0.0.1:${PORT}/api/health"
    ;;
  restart)
    systemctl restart zi-keyapi.service && ok "restarted."
    ;;
  status)
    systemctl --no-pager -l status zi-keyapi.service
    ;;
  logs)
    journalctl -u zi-keyapi.service -n 200 --no-pager
    ;;
  uninstall)
    systemctl disable --now zi-keyapi.service 2>/dev/null || true
    rm -f "$UNIT" "$ENVF"
    systemctl daemon-reload
    ok "Removed service. App dir kept at $APPDIR"
    ;;
  *)
    echo "Usage: --install [--secret=.. --port=.. --user=.. --pass=..] | --status | --logs | --restart | --uninstall"
    exit 1
    ;;
esac