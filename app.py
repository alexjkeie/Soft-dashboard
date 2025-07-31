from flask import Flask, render_template_string, request, jsonify
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')  # for session (if needed later)

# Read index.html from same directory
with open("index.html", encoding="utf-8") as f:
    html_template = f.read()

# Load data from JSON
def load_data():
    with open('data.json', encoding='utf-8') as f:
        return json.load(f)

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/api/server-info')
def server_info():
    data = load_data()
    return jsonify(data.get("server_info", {}))

@app.route('/api/ban-list')
def ban_list():
    data = load_data()
    return jsonify({"bans": data.get("ban_list", [])})

@app.route('/api/audit-logs')
def audit_logs():
    data = load_data()
    return jsonify({"logs": data.get("audit_logs", [])})

@app.route('/api/analytics')
def analytics():
    data = load_data()
    return jsonify({"analytics": data.get("user_behavior", {})})

@app.route('/api/security-tools')
def security_tools():
    data = load_data()
    return jsonify({"tools": data.get("security_tools", {})})

if __name__ == '__main__':
    app.run(debug=True)
