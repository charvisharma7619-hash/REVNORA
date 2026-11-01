from flask import Flask, jsonify
from workers import wsgi

app = Flask(__name__)

@app.get("/")
def health():
    return jsonify({"ok": True, "service": "revnora-backend", "status": "deployed"})

@app.get("/api/db-check")
def db_check():
    from flask import request
    db = request.environ["workers.env"].DB
    from pyodide.ffi import run_sync
    result = run_sync(db.prepare("SELECT 1 AS ok").run())
    return jsonify({"ok": True, "database": "connected", "result": result})

Default = wsgi.entrypoint(app)
