#!/bin/bash
# ZIVPN UDP Server + Web UI (Myanmar, One-Device Lock + Edit UI)
# Authors: Zahid Islam (udp-zivpn) + UPK tweaks + DEV-U PHOE KAUNT UI polish (+ device lock by bind_ip)
# Features:
#  - One-time key gate (POST /api/consume on KEY_API_URL)
#  - apt-guard, packages
#  - ZIVPN binary fetch + config
#  - Flask Web UI (Android-friendly) with:
#      * Total accounts count
#      * Per-user ✏️ Edit page
#      * One-device limit (bind_ip) -> iptables INPUT rules (ACCEPT for bind_ip, DROP for others)
#      * "Lock now"/"Clear" buttons + Auto-Lock from conntrack
#  - UFW/iptables NAT, sysctl forward
#  - systemd services: zivpn.service, zivpn-web.service

set -euo pipefail

B="\e[1;34m"; G="\e[1;32m"; Y="\e[1;33m"; R="\e[1;31m"; C="\e[1;36m"; Z="\e[0m"
LINE="${B}────────────────────────────────────────────────────────${Z}"
say(){ echo -e "$1"; }

echo -e "\n$LINE\n${G}🌟 ZIVPN UDP Server + Web UI ကို KyawGyi မှ ပြန်တည်းဖြတ်ပြီးသွင်းနေပါတယ်${Z}\n$LINE"

# ===== Root check =====
if [ "$(id -u)" -ne 0 ]; then echo -e "${R}❌ root လိုပါသည် (sudo -i)${Z}"; exit 1; fi
export DEBIAN_FRONTEND=noninteractive

# =====================================================================
#                   ONE-TIME KEY GATE (MANDATORY)
# =====================================================================
KEY_API_URL="http://43.228.86.36:8088"   # <- မိမိ API URL ဖြစ်အောင် ပြင်နိုင်

consume_one_time_key() {
  local _key="$1"
  local _url="${KEY_API_URL%/}/api/consume"
  if ! command -v curl >/dev/null 2>&1; then
    echo -e "${R}❌ curl မရှိ — apt-get install -y curl${Z}"
    exit 2
  fi
  echo -ે "${Y}🔑 One-time key စစ်ဆေးနေပါတယ်...${Z}"
  local resp
  resp=$(curl -fsS -X POST "$_url" -H 'Content-Type: application/json' -d "{\"key\":\"${_key}\"}" 2>&1) || {
    echo -e "${R}❌ Key server ချိတ်ဆက်မရ:${Z} $resp"; exit 2; }
  if echo "$resp" | grep -q '"ok":\s*true'; then
    echo -e "${G}✅ Key မှန် (consumed) — ဆက်လုပ်မယ်${Z}"; return 0
  else
    echo -e "${R}❌ Key မမှန်/ပြီးသုံးပြီး:${Z} $resp"; return 1
  fi
}
while :; do
  echo -ne "${C}Enter one-time key: ${Z}"; read -r -s ONE_TIME_KEY; echo
  [ -z "${ONE_TIME_KEY:-}" ] && { echo -e "${Y}⚠️ key မထည့်ရသေး — ထပ်ထည့်ပါ${Z}"; continue; }
  consume_one_time_key "$ONE_TIME_KEY" && break || echo -e "${Y}🔁 ထပ်စမ်းပါ (UI မှ key အသစ်ထုတ်နိုင်)${Z}"
done

# ===== apt guards =====
wait_for_apt() {
  echo -e "${Y}⏳ apt ပိတ်မချင်း စောင့်နေ...${Z}"
  for _ in $(seq 1 60); do
    if pgrep -x apt-get >/dev/null || pgrep -x apt >/dev/null || pgrep -f 'apt.systemd.daily' >/dev/null || pgrep -x unattended-upgrade >/dev/null; then
      sleep 5
    else
      return 0
    fi
  done
  echo -e "${Y}⚠️ apt timers ကို ယာယီရပ်...${Z}"
  systemctl stop --now unattended-upgrades.service 2>/dev/null || true
  systemctl stop --now apt-daily.service apt-daily.timer 2>/dev/null || true
  systemctl stop --now apt-daily-upgrade.service apt-daily-upgrade.timer 2>/dev/null || true
}
apt_guard_start(){ wait_for_apt; CNF_CONF="/etc/apt/apt.conf.d/50command-not-found"; if [ -f "$CNF_CONF" ]; then mv "$CNF_CONF" "${CNF_CONF}.disabled"; CNF_DISABLED=1; else CNF_DISABLED=0; fi; }
apt_guard_end(){
  dpkg --configure -a >/dev/null 2>&1 || true
  apt-get -f install -y >/dev/null 2>&1 || true
  if [ "${CNF_DISABLED:-0}" = "1" ] && [ -f "${CNF_CONF}.disabled" ]; then mv "${CNF_CONF}.disabled" "$CNF_CONF"; fi
}

# ===== Packages =====
say "${Y}📦 Packages တင်နေ...${Z}"
apt_guard_start
apt-get update -y -o APT::Update::Post-Invoke::= >/dev/null
apt-get install -y curl ufw jq python3 python3-flask python3-apt iproute2 conntrack ca-certificates openssl >/dev/null || true
apt_guard_end

# stop old services to avoid text busy
systemctl stop zivpn.service 2>/dev/null || true
systemctl stop zivpn-web.service 2>/dev/null || true

# ===== Paths =====
BIN="/usr/local/bin/zivpn"
CFG="/etc/zivpn/config.json"
USERS="/etc/zivpn/users.json"
ENVF="/etc/zivpn/web.env"
mkdir -p /etc/zivpn

# ===== Download ZIVPN binary =====
say "${Y}⬇️ ZIVPN binary ဒေါင်းနေ...${Z}"
PRIMARY_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
FALLBACK_URL="https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64"
TMP_BIN="$(mktemp)"
if ! curl -fsSL -o "$TMP_BIN" "$PRIMARY_URL"; then
  echo -e "${Y}Primary မရ — latest ဆက်စမ်း...${Z}"
  curl -fSL -o "$TMP_BIN" "$FALLBACK_URL"
fi
install -m 0755 "$TMP_BIN" "$BIN"; rm -f "$TMP_BIN"

# ===== Base config =====
if [ ! -f "$CFG" ]; then
  say "${Y}🧩 config.json ဖန်တီးနေ...${Z}"
  curl -fsSL -o "$CFG" "https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json" || echo '{}' > "$CFG"
fi

# ===== Certs =====
if [ ! -f /etc/zivpn/zivpn.crt ] || [ ! -f /etc/zivpn/zivpn.key ]; then
  say "${Y}🔐 SSL စိတျဖိုင် ဖန်တီးနေ...${Z}"
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=MM/ST=Yangon/L=Yangon/O=UPK/OU=Net/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1
fi

# ===== Web Admin (Login UI credentials) =====
say "${Y}🔒 Web Admin Login UI ထည့်မလား? (လစ်: မဖိတ်)${Z}"
read -r -p "Web Admin Username (Enter=disable): " WEB_USER
if [ -n "${WEB_USER:-}" ]; then
  read -r -s -p "Web Admin Password: " WEB_PASS; echo
  if command -v openssl >/dev/null 2>&1; then WEB_SECRET="$(openssl rand -hex 32)"; else WEB_SECRET="$(python3 - <<'PY'\nimport secrets;print(secrets.token_hex(32))\nPY\n)"; fi
  { echo "WEB_ADMIN_USER=${WEB_USER}"; echo "WEB_ADMIN_PASSWORD=${WEB_PASS}"; echo "WEB_SECRET=${WEB_SECRET}"; } > "$ENVF"
  chmod 600 "$ENVF"; say "${G}✅ Web login UI ဖွင့်ထားသည်${Z}"
else
  rm -f "$ENVF" 2>/dev/null || true
  say "${Y}ℹ️ Web login UI မဖွင့်ထားပါ (dev mode)${Z}"
fi

# ===== Ask initial VPN passwords =====
say "${G}🔏 VPN Password List (ကော်မာဖြင့်ခွဲ) eg: upkvip,alice,pass1${Z}"
read -r -p "Passwords (Enter=zi): " input_pw
if [ -z "${input_pw:-}" ]; then PW_LIST='["zi"]'; else
  PW_LIST=$(echo "$input_pw" | awk -F',' '{printf("["); for(i=1;i<=NF;i++){gsub(/^ *| *$/,"",$i); printf("%s\"%s\"", (i>1?",":""), $i)}; printf("]")}'); fi

# ===== Update config.json =====
if jq . >/dev/null 2>&1 <<<'{}'; then
  TMP=$(mktemp)
  jq --argjson pw "$PW_LIST" '
    .auth.mode = "passwords" |
    .auth.config = $pw |
    .listen = (."listen" // ":5667") |
    .cert = "/etc/zivpn/zivpn.crt" |
    .key  = "/etc/zivpn/zivpn.key" |
    .obfs = (."obfs" // "zivpn")
  ' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
fi
[ -f "$USERS" ] || echo "[]" > "$USERS"
chmod 644 "$CFG" "$USERS"

# ===== systemd: ZIVPN =====
say "${Y}🧰 systemd service (zivpn) သွင်းနေ...${Z}"
cat >/etc/systemd/system/zivpn.service <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# ===== Web Panel (Flask + Android UI + One-Device Lock) =====
say "${Y}🖥️ Web Panel (Flask) ထည့်နေ...${Z}"
cat >/etc/zivpn/web.py <<'PY'
from flask import Flask, jsonify, render_template_string, request, redirect, url_for, session, make_response
import json, subprocess, os, tempfile, hmac, re
from datetime import datetime, timedelta

USERS_FILE = "/etc/zivpn/users.json"
CONFIG_FILE = "/etc/zivpn/config.json"
LISTEN_FALLBACK = "5667"
RECENT_SECONDS = 120

LOGO_URL = "https://raw.githubusercontent.com/Upk123/upkvip-ziscript/refs/heads/main/20251018_231111.png"

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET","dev-secret-change-me")
ADMIN_USER = os.environ.get("WEB_ADMIN_USER","").strip()
ADMIN_PASS = os.environ.get("WEB_ADMIN_PASSWORD","").strip()

def read_json(path, default):
  try:
    with open(path,"r") as f: return json.load(f)
  except Exception:
    return default

def write_json_atomic(path, data):
  d=json.dumps(data, ensure_ascii=False, indent=2)
  dirn=os.path.dirname(path); os.makedirs(dirn, exist_ok=True)
  fd,tmp=tempfile.mkstemp(prefix=".tmp-", dir=dirn)
  try:
    with os.fdopen(fd,"w") as f: f.write(d)
    os.replace(tmp,path)
  finally:
    try: os.remove(tmp)
    except: pass

def load_users():
  v=read_json(USERS_FILE,[])
  out=[]
  for u in v:
    out.append({"user":u.get("user",""),
                "password":u.get("password",""),
                "expires":u.get("expires",""),
                "port":str(u.get("port","")) if u.get("port","")!="" else "",
                "bind_ip":u.get("bind_ip","")})
  return out

def save_users(users): write_json_atomic(USERS_FILE, users)

def shell(cmd):
  return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def get_listen_port_from_config():
  cfg=read_json(CONFIG_FILE,{})
  listen=str(cfg.get("listen","")).strip()
  m=re.search(r":(\d+)$", listen) if listen else None
  return (m.group(1) if m else LISTEN_FALLBACK)

def get_udp_listen_ports():
  out=shell("ss -uHln").stdout
  return set(re.findall(r":(\d+)\s", out))

def pick_free_port():
  used={str(u.get("port","")) for u in load_users() if str(u.get("port",""))}
  used |= get_udp_listen_ports()
  for p in range(6000,20000):
    if str(p) not in used: return str(p)
  return ""

def has_recent_udp_activity_for_port(port):
  if not port: return False
  out=shell(f"conntrack -L -p udp 2>/dev/null | grep -w 'dport={port}' | head -n1 || true").stdout
  return bool(out.strip())

def first_recent_src_ip(port):
  if not port: return ""
  out=shell(f"conntrack -L -p udp 2>/dev/null | awk \"/dport={port}\\b/ {{for(i=1;i<=NF;i++) if($i~/src=/){{split($i,a,'='); print a[2]; exit}}}}\"").stdout.strip()
  return out if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", out) else ""

def status_for_user(u, active_ports, listen_port):
  port=str(u.get("port",""))
  check_port=port if port else listen_port
  if has_recent_udp_activity_for_port(check_port): return "Online"
  if check_port in active_ports: return "Offline"
  return "Unknown"

def _ipt(cmd): return shell(cmd)

def ensure_limit_rules(port, ip):
  if not (port and ip): return
  _ipt(f"iptables -C INPUT -p udp --dport {port} -s {ip} -j ACCEPT 2>/dev/null") or _ipt(f"iptables -I INPUT -p udp --dport {port} -s {ip} -j ACCEPT")
  _ipt(f"iptables -C INPUT -p udp --dport {port} ! -s {ip} -j DROP 2>/dev/null") or _ipt(f"iptables -I INPUT -p udp --dport {port} ! -s {ip} -j DROP")

def remove_limit_rules(port):
  if not port: return
  for _ in range(10):
    chk=_ipt(f"iptables -S INPUT | grep -E \"-p udp .* --dport {port}\\b .* (-j DROP|-j ACCEPT)\" | head -n1 || true").stdout.strip()
    if not chk: break
    rule=chk.replace("-A","").strip()
    _ipt(f"iptables -D INPUT {rule}")

def apply_device_limits(users):
  for u in users:
    port=str(u.get("port","") or "")
    ip=(u.get("bind_ip","") or "").strip()
    if port and ip:
      ensure_limit_rules(port, ip)
    elif port and not ip:
      remove_limit_rules(port)

def login_enabled(): return bool(ADMIN_USER and ADMIN_PASS)
def is_authed(): return session.get("auth") == True
def require_login():
  if login_enabled() and not is_authed():
    return False
  return True

def sync_config_passwords(mode="mirror"):
  cfg=read_json(CONFIG_FILE,{})
  users=load_users()
  users_pw=sorted({str(u["password"]) for u in users if u.get("password")})
  if mode=="merge":
    old=[]
    if isinstance(cfg.get("auth",{}).get("config",None), list):
      old=list(map(str, cfg["auth"]["config"]))
    new_pw=sorted(set(old)|set(users_pw))
  else:
    new_pw=users_pw
  if not isinstance(cfg.get("auth"),dict): cfg["auth"]={}
  cfg["auth"]["mode"]="passwords"
  cfg["auth"]["config"]=new_pw
  cfg["listen"]=cfg.get("listen") or ":5667"
  cfg["cert"]=cfg.get("cert") or "/etc/zivpn/zivpn.crt"
  cfg["key"]=cfg.get("key") or "/etc/zivpn/zivpn.key"
  cfg["obfs"]=cfg.get("obfs") or "zivpn"
  write_json_atomic(CONFIG_FILE,cfg)
  shell("systemctl restart zivpn.service")

HTML = """<!doctype html>
<html lang="my"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta http-equiv="refresh" content="120">
<title>ZIVPN User Panel</title>
<style>
 :root{
  --bg:#0b0f14; --fg:#e6edf3; --muted:#a0abb7; --card:#111823; --bd:#1f2a37;
  --ok:#22c55e; --bad:#ef4444; --unk:#9ca3af; --btn:#0d141d; --btnbd:#334155;
 }
 html,body{background:var(--bg);color:var(--fg)}
 body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:0;padding:16px}
 header{position:sticky;top:0;background:var(--bg);padding:10px 0 12px;z-index:10}
 .wrap{max-width:1000px;margin:0 auto}
 .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
 h1{margin:0;font-size:20px;font-weight:700}
 .sub{color:var(--muted);font-size:13px}
 .btn{padding:10px 14px;border-radius:999px;border:1px solid var(--btnbd);
      background:var(--btn);color:var(--fg);text-decoration:none;cursor:pointer}
 table{border-collapse:collapse;width:100%}
 th,td{border:1px solid var(--bd);padding:10px;text-align:left}
 th{background:var(--card);font-size:13px}
 td{font-size:14px}
 .pill{display:inline-block;padding:4px 10px;border-radius:999px}
 .ok{color:var(--bg);background:var(--ok)}
 .bad{color:var(--bg);background:var(--bad)}
 .unk{color:var(--bg);background:var(--unk)}
 .muted{color:var(--muted)}
 .box{margin:14px 0;padding:12px;border:1px solid var(--bd);border-radius:14px;background:var(--card)}
 label{display:block;margin:6px 0 3px;font-size:13px;color:var(--muted)}
 input{width:100%;max-width:420px;padding:11px 12px;border:1px solid var(--bd);border-radius:12px;background:#0a1220;color:var(--fg)}
 .actions{display:flex;gap:6px;flex-wrap:wrap}
 .tag{font-size:12px;color:var(--muted)}
 .count{font-weight:600}
 .edit-row{background:#0d1624}
 .form-inline{display:flex;gap:10px;flex-wrap:wrap}
 .form-inline > div{min-width:180px;flex:1}
 @media (max-width:480px){ body{padding:12px} th,td{font-size:13px} .btn{padding:10px 12px} }
</style></head><body>
<header>
 <div class="wrap row">
   <img src="{{ logo }}" alt="DEV-U PHOE KAUNT" style="height:40px;width:auto;border-radius:10px">
   <div style="flex:1">
     <h1>DEV-U PHOE KAUNT</h1>
     <div class="sub">ZIVPN User Panel • Total: <span class="count">{{ total }}</span></div>
   </div>
   <div class="row">
     <a class="btn" href="https://m.me/upkvpnfastvpn" target="_blank" rel="noopener">💬 Messenger</a>
     {% if authed %}<a class="btn" href="/logout">Logout</a>{% endif %}
   </div>
 </div>
</header>

<div class="wrap">
{% if not authed %}
  <div class="box" style="max-width:440px;margin:40px auto">
    {% if err %}<div style="color:var(--bad);margin-bottom:8px">{{err}}</div>{% endif %}
    <form method="post" action="/login">
      <label>Username</label><input name="u" autofocus required>
      <label style="margin-top:8px">Password</label><input name="p" type="password" required>
      <button class="btn" type="submit" style="margin-top:12px;width:100%">Login</button>
    </form>
  </div>
{% else %}

<div class="box">
  <h3 style="margin:4px 0 8px">➕ အသုံးပြုသူ အသစ်ထည့်ရန်</h3>
  {% if msg %}<div style="color:var(--ok);margin:6px 0">{{msg}}</div>{% endif %}
  {% if err %}<div style="color:var(--bad);margin:6px 0">{{err}}</div>{% endif %}
  <form method="post" action="/add" class="form-inline">
    <div><label>👤 User</label><input name="user" required></div>
    <div><label>🔑 Password</label><input name="password" required></div>
    <div><label>⏰ Expires</label><input name="expires" placeholder="2025-12-31 or 30"></div>
    <div><label>🔌 UDP Port</label><input name="port" placeholder="auto"></div>
    <div><label>📱 Bind IP (1 device)</label><input name="bind_ip" placeholder="auto when online…"></div>
    <div style="align-self:end"><button class="btn" type="submit">Save + Sync</button></div>
  </form>
</div>

<table>
  <tr>
    <th>👤 User</th><th>🔑 Password</th><th>⏰ Expires</th>
    <th>🔌 Port</th><th>📱 Bind IP</th><th>🔎 Status</th><th>✏️ Edit</th><th>🗑️ Delete</th>
  </tr>
  {% for u in users %}
  <tr class="{% if u.expires and u.expires < today %}edit-row{% endif %}">
    <td class="usercell">{{u.user}}</td>
    <td>{{u.password}}</td>
    <td>{% if u.expires %}{{u.expires}}{% else %}<span class="muted">—</span>{% endif %}</td>
    <td>{% if u.port %}{{u.port}}{% else %}<span class="muted">—</span>{% endif %}</td>
    <td>
      {% if u.bind_ip %}<span class="tag">{{u.bind_ip}}</span>{% else %}<span class="muted">—</span>{% endif %}
      <form style="display:inline" method="post" action="/lock">
        <input type="hidden" name="user" value="{{u.user}}">
        <button class="btn" name="op" value="lock" title="Lock to current IP">Lock now</button>
        <button class="btn" name="op" value="clear" title="Clear lock">Clear</button>
      </form>
    </td>
    <td>
      {% if u.status == "Online" %}<span class="pill ok">Online</span>
      {% elif u.status == "Offline" %}<span class="pill bad">Offline</span>
      {% else %}<span class="pill unk">Unknown</span>
      {% endif %}
    </td>
    <td>
      <form method="get" action="/edit" style="display:inline">
        <input type="hidden" name="user" value="{{u.user}}">
        <button class="btn" type="submit">Edit</button>
      </form>
    </td>
    <td>
      <form class="delform" method="post" action="/delete" onsubmit="return confirm('ဖျက်မလား?')">
        <input type="hidden" name="user" value="{{u.user}}">
        <button type="submit" class="btn" style="border-color:#3b1d1d;background:#2a0f0f">Delete</button>
      </form>
    </td>
  </tr>
  {% endfor %}
</table>

{% endif %}
</div>
</body></html>
"""

def build_view(msg="", err=""):
  if not require_login():
    return render_template_string(HTML, authed=False, logo=LOGO_URL, err=session.pop("login_err", None))
  users=load_users()
  changed=False
  for u in users:
    if u.get("port") and not u.get("bind_ip"):
      ip=first_recent_src_ip(u["port"])
      if ip:
        u["bind_ip"]=ip
        changed=True
  if changed: save_users(users)
  apply_device_limits(users)
  active=get_udp_listen_ports()
  listen_port=get_listen_port_from_config()
  view=[]
  for u in users:
    view.append(type("U",(),{
      "user":u.get("user",""),
      "password":u.get("password",""),
      "expires":u.get("expires",""),
      "port":u.get("port",""),
      "bind_ip":u.get("bind_ip",""),
      "status":status_for_user(u,active,listen_port)
    }))
  view.sort(key=lambda x:(x.user or "").lower())
  today=datetime.now().strftime("%Y-%m-%d")
  return render_template_string(HTML, authed=True, logo=LOGO_URL, users=view, msg=msg, err=err, today=today, total=len(view))

@app.route("/login", methods=["GET","POST"])
def login():
  if not login_enabled(): return redirect(url_for('index'))
  if request.method=="POST":
    u=(request.form.get("u") or "").strip()
    p=(request.form.get("p") or "").strip()
    if hmac.compare_digest(u, ADMIN_USER) and hmac.compare_digest(p, ADMIN_PASS):
      session["auth"]=True; return redirect(url_for('index'))
    session["auth"]=False; session["login_err"]="မှန်ကန်မှုမရှိပါ (username/password)"; return redirect(url_for('login'))
  return render_template_string(HTML, authed=False, logo=LOGO_URL, err=session.pop("login_err", None))

@app.route("/logout", methods=["GET"])
def logout():
  session.pop("auth", None)
  return redirect(url_for('login') if login_enabled() else url_for('index'))

@app.route("/", methods=["GET"])
def index(): return build_view()

@app.route("/add", methods=["POST"])
def add_user():
  if not require_login(): return redirect(url_for('login'))
  user=(request.form.get("user") or "").strip()
  password=(request.form.get("password") or "").strip()
  expires=(request.form.get("expires") or "").strip()
  port=(request.form.get("port") or "").strip()
  bind_ip=(request.form.get("bind_ip") or "").strip()

  if expires.isdigit():
    expires=(datetime.now() + timedelta(days=int(expires))).strftime("%Y-%m-%d")

  if not user or not password:
    return build_view(err="User နှင့် Password လိုအပ်သည်")
  if expires:
    try: datetime.strptime(expires,"%Y-%m-%d")
    except ValueError: return build_view(err="Expires format မမှန်ပါ (YYYY-MM-DD)")
  if port:
    if not re.fullmatch(r"\d{2,5}",port) or not (6000 <= int(port) <= 19999):
      return build_view(err="Port အကွာအဝေး 6000-19999")
  else:
    port=pick_free_port()

  users=load_users(); replaced=False
  for u in users:
    if u.get("user","").lower()==user.lower():
      u.update({"password":password,"expires":expires,"port":port,"bind_ip":bind_ip}); replaced=True; break
  if not replaced:
    users.append({"user":user,"password":password,"expires":expires,"port":port,"bind_ip":bind_ip})
  save_users(users); sync_config_passwords()
  return build_view(msg="Saved & Synced")

@app.route("/edit", methods=["GET","POST"])
def edit_user():
  if not require_login(): return redirect(url_for('login'))
  if request.method=="GET":
    q=(request.args.get("user") or "").strip().lower()
    users=load_users(); target=[u for u in users if u.get("user","").lower()==q]
    if not target: return build_view(err="မတွေ့ပါ")
    u=target[0]
    frm=f"""<div class='wrap box'>
    <h3 style='margin:0 0 10px'>✏️ Edit: {u.get('user')}</h3>
    <form method='post' action='/edit' class='form-inline'>
      <input type='hidden' name='orig' value='{u.get('user')}'>
      <div><label>👤 User</label><input name='user' value='{u.get('user')}' required></div>
      <div><label>🔑 Password</label><input name='password' value='{u.get('password')}' required></div>
      <div><label>⏰ Expires</label><input name='expires' value='{u.get('expires','')}' placeholder='2025-12-31 or 30'></div>
      <div><label>🔌 UDP Port</label><input name='port' value='{u.get('port','')}'></div>
      <div><label>📱 Bind IP</label><input name='bind_ip' value='{u.get('bind_ip','')}' placeholder='blank = no lock'></div>
      <div style='align-self:end'><button class='btn' type='submit'>Save</button>
      <a class='btn' href='/' style='margin-left:6px'>Cancel</a></div>
    </form></div>"""
    base=build_view()
    return base.replace("</div>\n</body>","</div>"+frm+"</body>")
  orig=(request.form.get("orig") or "").strip().lower()
  user=(request.form.get("user") or "").strip()
  password=(request.form.get("password") or "").strip()
  expires=(request.form.get("expires") or "").strip()
  port=(request.form.get("port") or "").strip()
  bind_ip=(request.form.get("bind_ip") or "").strip()
  if expires.isdigit():
    expires=(datetime.now() + timedelta(days=int(expires))).strftime("%Y-%m-%d")
  if not user or not password: return build_view(err="User/Password လိုအပ်")
  if port and (not re.fullmatch(r"\d{2,5}",port) or not (6000<=int(port)<=19999)):
    return build_view(err="Port အကွာအဝေး 6000-19999")

  users=load_users(); found=False
  for u in users:
    if u.get("user","").lower()==orig:
      old_port=u.get("port",""); old_ip=u.get("bind_ip","")
      if old_port and (str(old_port)!=str(port) or old_ip!=bind_ip):
        remove_limit_rules(old_port)
      u.update({"user":user,"password":password,"expires":expires,"port":port,"bind_ip":bind_ip})
      found=True; break
  if not found: return build_view(err="မတွေ့ပါ")
  save_users(users); sync_config_passwords()
  return redirect(url_for('index'))

@app.route("/lock", methods=["POST"])
def lock_now():
  if not require_login(): return redirect(url_for('login'))
  user=(request.form.get("user") or "").strip().lower()
  op=(request.form.get("op") or "").strip()
  users=load_users()
  for u in users:
    if u.get("user","").lower()==user:
      port=u.get("port","")
      if op=="clear":
        u["bind_ip"]=""
        save_users(users); apply_device_limits(users)
        return build_view(msg=f"Cleared lock for {u['user']}")
      ip=first_recent_src_ip(port)
      if not ip:
        return build_view(err="လက်ရှိ UDP traffic မတွေ့ — client ချိတ်ပြီး Lock now ကိုပြန်နှိပ်ပါ")
      u["bind_ip"]=ip
      save_users(users); apply_device_limits(users)
      return build_view(msg=f"Locked {u['user']} to {ip}")
  return build_view(err="မတွေ့ပါ")

@app.route("/delete", methods=["POST"])
def delete_user_html():
  if not require_login(): return redirect(url_for('login'))
  user = (request.form.get("user") or "").strip()
  if not user: return build_view(err="User လိုအပ်သည်")
  remain=[]; removed=None
  for u in load_users():
    if u.get("user","").lower()==user.lower():
      removed=u
    else:
      remain.append(u)
  if removed and removed.get("port"): remove_limit_rules(removed.get("port"))
  save_users(remain); sync_config_passwords(mode="mirror")
  return build_view(msg=f"Deleted: {user}")

@app.route("/api/users", methods=["GET","POST"])
def api_users():
  if not require_login():
    return make_response(jsonify({"ok": False, "err":"login required"}), 401)
  if request.method=="GET":
    users=load_users(); active=get_udp_listen_ports(); listen_port=get_listen_port_from_config()
    for u in users: u["status"]=status_for_user(u,active,listen_port)
    return jsonify(users)
  data=request.get_json(silent=True) or {}
  user=(data.get("user") or "").strip()
  password=(data.get("password") or "").strip()
  expires=(data.get("expires") or "").strip()
  port=str(data.get("port") or "").strip()
  bind_ip=str(data.get("bind_ip") or "").strip()
  if expires.isdigit(): expires=(datetime.now()+timedelta(days=int(expires))).strftime("%Y-%m-%d")
  if not user or not password: return jsonify({"ok":False,"err":"user/password required"}),400
  if port and (not re.fullmatch(r"\d{2,5}",port) or not (6000<=int(port)<=19999)):
    return jsonify({"ok":False,"err":"invalid port"}),400
  if not port: port=pick_free_port()
  users=load_users(); replaced=False
  for u in users:
    if u.get("user","").lower()==user.lower():
      if u.get("port") and (u.get("port")!=port or u.get("bind_ip","")!=bind_ip):
        remove_limit_rules(u.get("port"))
      u.update({"password":password,"expires":expires,"port":port,"bind_ip":bind_ip}); replaced=True; break
  if not replaced:
    users.append({"user":user,"password":password,"expires":expires,"port":port,"bind_ip":bind_ip})
  save_users(users); sync_config_passwords(); apply_device_limits(users)
  return jsonify({"ok":True})

@app.route("/favicon.ico", methods=["GET"])
def favicon(): return ("",204)

@app.errorhandler(405)
def handle_405(e): return redirect(url_for('index'))

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8080)
PY
chmod 644 /etc/zivpn/web.py

# ===== Web systemd =====
cat >/etc/systemd/system/zivpn-web.service <<'EOF'
[Unit]
Description=ZIVPN Web Panel
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/zivpn/web.env
ExecStart=/usr/bin/python3 /etc/zivpn/web.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ===== Networking: forwarding + DNAT + MASQ + UFW =====
echo -e "${Y}🌐 UDP/DNAT + UFW + sysctl ဖွင့်နေ...${Z}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

IFACE=$(ip -4 route ls | awk '/default/ {print $5; exit}') || true
[ -n "${IFACE:-}" ] || IFACE=eth0
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -I PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -I POSTROUTING -o "$IFACE" -j MASQUERADE

ufw allow 5667/udp >/dev/null 2>&1 || true
ufw allow 6000:19999/udp >/dev/null 2>&1 || true
ufw allow 8080/tcp >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

# ===== CRLF sanitize =====
sed -i 's/\r$//' /etc/zivpn/web.py /etc/systemd/system/zivpn.service /etc/systemd/system/zivpn-web.service || true

# ===== Enable services =====
systemctl daemon-reload
systemctl enable --now zivpn.service
systemctl enable --now zivpn-web.service

IP=$(hostname -I | awk '{print $1}')
echo -e "\n$LINE\n${G}✅ Done${Z}"
echo -e "${C}Web Panel   :${Z} ${Y}http://$IP:8080${Z}"
echo -e "${C}users.json  :${Z} ${Y}/etc/zivpn/users.json${Z}"
echo -e "${C}config.json :${Z} ${Y}/etc/zivpn/config.json${Z}"
echo -e "${C}Services    :${Z} ${Y}systemctl status|restart zivpn  •  systemctl status|restart zivpn-web${Z}"
echo -e "$LINE"
