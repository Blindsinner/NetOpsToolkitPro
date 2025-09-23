# tracker_server.py
from flask import Flask, request, redirect
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
log_file = Path("logs/clicks.log")
log_file.parent.mkdir(parents=True, exist_ok=True)

@app.route("/click")
def click():
    uid = request.args.get("id", "unknown")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write_text(
        f"{timestamp} | ID: {uid} | IP: {ip} | UA: {ua}\n",
        encoding="utf-8",
        append=True
    )
    return redirect("/landing", code=302)

@app.route("/landing")
def landing():
    return """<html><body><h2>✅ You are now signed in!</h2><p>(This is a simulation.)</p></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
