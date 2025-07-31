import os
import json
import time
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, session, url_for, jsonify
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]
GUILD_ID = os.environ["GUILD_ID"]
REQUIRED_ROLE = os.environ["REQUIRED_ROLE_ID"]

DATA_FILE = "data.json"

def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "bans": [],
            "notes": [],
            "visits": 0,
            "audit_logs": [],
            "user_actions": {},
            "flags": []
        }

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def log_action(data, actor, action_type, details=""):
    entry = {
        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "action": action_type,
        "details": details
    }
    data["audit_logs"].insert(0, entry)  # newest first
    # Keep audit logs max 1000 entries
    if len(data["audit_logs"]) > 1000:
        data["audit_logs"] = data["audit_logs"][:1000]

def increment_user_action(data, user_id, action):
    if user_id not in data["user_actions"]:
        data["user_actions"][user_id] = {}
    data["user_actions"][user_id][action] = data["user_actions"][user_id].get(action, 0) + 1

def check_rate_limit(session, limit=10):
    # Simple session-based rate limiting for abuse protection
    timestamps = session.get("timestamps", [])
    now = time.time()
    timestamps = [t for t in timestamps if now - t < 60]  # last 60 sec
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    session["timestamps"] = timestamps
    return True

def user_has_role(user_roles):
    return REQUIRED_ROLE in user_roles

@app.route("/")
def index():
    user = session.get("user")
    data = load_data()
    data["visits"] += 1
    save_data(data)

    if not user:
        login_url = (
            f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}"
            f"&redirect_uri={REDIRECT_URI}&response_type=code"
            f"&scope=identify%20guilds"
        )
        return render_template_string(
            open("template.html").read(),
            logged_in=False,
            login_url=login_url,
            data=data
        )

    # Optionally fetch fresh member count from Discord (simplified - you could cache)
    # For now, just send stored server_info
    return render_template_string(
        open("template.html").read(),
        logged_in=True,
        user=user,
        data=data
    )

@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return redirect("/")

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "scope": "identify guilds"
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_res = requests.post("https://discord.com/api/oauth2/token", data=payload, headers=headers)
    if token_res.status_code != 200:
        return "OAuth2 token error", 400
    access_token = token_res.json().get("access_token")

    user_res = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {access_token}"})
    user = user_res.json()

    guilds_res = requests.get("https://discord.com/api/users/@me/guilds", headers={"Authorization": f"Bearer {access_token}"})
    guilds = guilds_res.json()
    if not any(g["id"] == GUILD_ID for g in guilds):
        return "Not in the required server.", 403

    # Get member roles to check permissions
    member_res = requests.get(
        f"https://discord.com/api/users/@me/guilds/{GUILD_ID}/member",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    member = member_res.json()
    roles = member.get("roles", [])
    if REQUIRED_ROLE not in roles:
        return "You lack the required role.", 403

    session["user"] = {
        "id": user["id"],
        "username": user["username"],
        "discriminator": user["discriminator"],
        "avatar": user["avatar"],
        "roles": roles
    }

    data = load_data()
    log_action(data, user["username"], "login", "User logged in")
    increment_user_action(data, user["id"], "login")
    save_data(data)

    return redirect("/")

@app.route("/logout")
def logout():
    user = session.get("user")
    data = load_data()
    if user:
        log_action(data, user["username"], "logout", "User logged out")
        save_data(data)

    session.clear()
    return redirect("/")

@app.route("/api/ban", methods=["POST"])
def api_ban():
    if not session.get("user"):
        return {"error": "Unauthorized"}, 403
    if not check_rate_limit(session):
        return {"error": "Rate limit exceeded"}, 429

    user = session["user"]
    data = load_data()

    if REQUIRED_ROLE not in user.get("roles", []):
        return {"error": "Insufficient role"}, 403

    ban_data = request.json
    ban_id = ban_data.get("id")
    reason = ban_data.get("reason", "No reason provided")
    if not ban_id:
        return {"error": "No ban id provided"}, 400

    if ban_id in data["bans"]:
        return {"error": "User already banned"}, 400

    data["bans"].append({"id": ban_id, "reason": reason, "by": user["username"], "timestamp": int(time.time())})
    log_action(data, user["username"], "ban", f"Banned {ban_id} for: {reason}")
    increment_user_action(data, user["id"], "ban")
    save_data(data)
    return {"success": True, "bans": data["bans"]}

@app.route("/api/unban", methods=["POST"])
def api_unban():
    if not session.get("user"):
        return {"error": "Unauthorized"}, 403
    if not check_rate_limit(session):
        return {"error": "Rate limit exceeded"}, 429

    user = session["user"]
    data = load_data()

    if REQUIRED_ROLE not in user.get("roles", []):
        return {"error": "Insufficient role"}, 403

    unban_data = request.json
    unban_id = unban_data.get("id")
    if not unban_id:
        return {"error": "No unban id provided"}, 400

    bans_before = len(data["bans"])
    data["bans"] = [b for b in data["bans"] if b["id"] != unban_id]
    if len(data["bans"]) == bans_before:
        return {"error": "User not found in bans"}, 400

    log_action(data, user["username"], "unban", f"Unbanned {unban_id}")
    increment_user_action(data, user["id"], "unban")
    save_data(data)
    return {"success": True, "bans": data["bans"]}

@app.route("/api/audit_logs")
def api_audit_logs():
    if not session.get("user"):
        return {"error": "Unauthorized"}, 403
    user = session["user"]
    data = load_data()

    if REQUIRED_ROLE not in user.get("roles", []):
        return {"error": "Insufficient role"}, 403

    return jsonify(data["audit_logs"])

@app.route("/api/user_actions")
def api_user_actions():
    if not session.get("user"):
        return {"error": "Unauthorized"}, 403
    user = session["user"]
    data = load_data()

    if REQUIRED_ROLE not in user.get("roles", []):
        return {"error": "Insufficient role"}, 403

    return jsonify(data["user_actions"])

@app.route("/api/flags")
def api_flags():
    if not session.get("user"):
        return {"error": "Unauthorized"}, 403
    user = session["user"]
    data = load_data()

    if REQUIRED_ROLE not in user.get("roles", []):
        return {"error": "Insufficient role"}, 403

    return jsonify(data["flags"])

# You can add endpoints for creating flags, notes, reports, etc. similarly.
