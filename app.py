from flask import Flask, request, redirect, session, jsonify, render_template_string
import json
import os
import requests

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
GUILD_ID = os.getenv("DISCORD_GUILD_ID")

def load_data():
    with open("data.json", "r") as f:
        return json.load(f)

def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f, indent=2)

@app.route("/")
def index():
    if not session.get("user"):
        login_url = (
            f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}"
            f"&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify"
        )
        return render_template_string(open("index.html", "r").read(), login_url=login_url, user=None)
    else:
        user = session["user"]
        data = load_data()
        return render_template_string(open("index.html", "r").read(), login_url=None, user=user, data=data)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return redirect("/")
    
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': 'identify'
    }

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post('https://discord.com/api/oauth2/token', data=payload, headers=headers)
    r.raise_for_status()
    tokens = r.json()

    user = requests.get('https://discord.com/api/users/@me', headers={
        'Authorization': f'Bearer {tokens["access_token"]}'
    }).json()

    session["user"] = {
        "id": user["id"],
        "username": user["username"],
        "avatar": user["avatar"]
    }
    return redirect("/")

@app.route("/api/ban", methods=["POST"])
def ban_user():
    data = load_data()
    user_id = request.form.get("user_id")
    reason = request.form.get("reason", "No reason provided.")
    if not user_id:
        return "Missing user ID", 400
    data["banned_users"].append({"id": user_id, "reason": reason})
    save_data(data)
    return "User banned!", 200

@app.route("/api/logs")
def get_logs():
    data = load_data()
    return jsonify(data.get("logs", []))

@app.route("/api/server-info")
def server_info():
    data = load_data()
    return jsonify(data.get("server_info", {}))

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
