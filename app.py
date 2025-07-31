import os
from flask import Flask, redirect, request, session, url_for, jsonify, send_from_directory
import requests
import json

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'supersecretkey')

DISCORD_API_BASE = 'https://discord.com/api'
OAUTH_SCOPES = 'identify guilds'

# Read config from environment variables
CLIENT_ID = os.getenv('CLIENT_ID', 'YOUR_DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', 'YOUR_DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/callback')
GUILD_ID = os.getenv('GUILD_ID', 'YOUR_GUILD_ID')
REQUIRED_ROLE_ID = os.getenv('REQUIRED_ROLE_ID', 'YOUR_MOD_ROLE_ID')

DATA_DIR = '.'

def load_json(filename):
    try:
        with open(f'{DATA_DIR}/{filename}', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_json(filename, data):
    with open(f'{DATA_DIR}/{filename}', 'w') as f:
        json.dump(data, f, indent=4)

def user_in_guild_with_role(user_guilds, guild_id, role_id, access_token):
    guild = next((g for g in user_guilds if g['id'] == guild_id), None)
    if not guild:
        return False

    headers = {'Authorization': f'Bearer {access_token}'}
    member_resp = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds/{guild_id}/member', headers=headers)
    if member_resp.status_code != 200:
        return False
    member = member_resp.json()
    return role_id in member.get('roles', [])

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    access_token = session.get('access_token')
    if not user_in_guild_with_role(user['guilds'], GUILD_ID, REQUIRED_ROLE_ID, access_token):
        return "Access denied: You must be in the server and have the required role.", 403
    return send_from_directory('.', 'index.html')

@app.route('/login')
def login():
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': OAUTH_SCOPES
    }
    url = f"{DISCORD_API_BASE}/oauth2/authorize?" + '&'.join(f"{k}={v}" for k,v in params.items())
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "No code provided", 400

    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': OAUTH_SCOPES
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_resp = requests.post(f'{DISCORD_API_BASE}/oauth2/token', data=data, headers=headers)
    if token_resp.status_code != 200:
        return f"Failed to get token: {token_resp.text}", 400
    token_json = token_resp.json()
    access_token = token_json['access_token']

    headers = {'Authorization': f'Bearer {access_token}'}
    user_resp = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=headers)
    guilds_resp = requests.get(f'{DISCORD_API_BASE}/users/@me/guilds', headers=headers)
    if user_resp.status_code != 200 or guilds_resp.status_code != 200:
        return "Failed to get user data", 400
    user_data = user_resp.json()
    guilds_data = guilds_resp.json()

    session['user'] = {
        'id': user_data['id'],
        'username': f"{user_data['username']}#{user_data['discriminator']}",
        'avatar': user_data['avatar'],
        'guilds': guilds_data
    }
    session['access_token'] = access_token

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/api/server-info')
def server_info():
    data = load_json('server_info.json')
    if not data:
        data = {
            "name": "Example Server",
            "icon_url": "https://cdn.discordapp.com/icons/123456789012345678/abcdef1234567890.webp",
            "member_count": 1200,
            "online_count": 250,
            "channels": 45,
            "roles": 30,
            "created_at": "2018-04-12T15:30:00"
        }
    return jsonify(data)

@app.route('/api/bans')
def get_bans():
    bans = load_json('bans.json')
    return jsonify(bans)

@app.route('/api/staff-actions')
def get_staff_actions():
    logs = load_json('actions.json')
    return jsonify(logs)

if __name__ == '__main__':
    app.run(debug=True)