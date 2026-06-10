"""
Android Security Auditor - Web Server
Run: python server.py
Then open: http://localhost:5000
"""

import json
import threading
from flask import Flask, render_template, jsonify, Response, stream_with_context
from audit_engine import run_full_audit, check_device_connected, generate_ai_review, is_ai_enabled

app = Flask(__name__)

# Global state
audit_result = None
audit_running = False
audit_progress = []
ai_review_result = None
ai_review_running = False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report")
def report():
    return render_template("report.html")


@app.route("/api/check-device")
def check_device():
    result = check_device_connected()
    return jsonify(result)


@app.route("/api/start-audit")
def start_audit():
    global audit_result, audit_running, audit_progress, ai_review_result, ai_review_running
    if audit_running:
        return jsonify({"status": "already_running"})
    audit_result = None
    ai_review_result = None
    ai_review_running = False
    audit_progress = []
    audit_running = True

    def run():
        global audit_result, audit_running
        def cb(msg):
            audit_progress.append(msg)
        try:
            audit_result = run_full_audit(progress_callback=cb)
        except Exception as e:
            audit_result = {"error": str(e)}
        audit_running = False
        audit_progress.append("__DONE__")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/progress")
def progress():
    def generate():
        idx = 0
        import time
        while True:
            if idx < len(audit_progress):
                msg = audit_progress[idx]
                idx += 1
                yield f"data: {json.dumps({'msg': msg})}\n\n"
                if msg == "__DONE__":
                    break
            else:
                time.sleep(0.3)
    return Response(stream_with_context(generate()),
                    content_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/result")
def result():
    if audit_result is None:
        return jsonify({"status": "not_ready"})
    return jsonify({"status": "ready", "data": audit_result})


@app.route("/api/ai-review")
def ai_review():
    global ai_review_result, ai_review_running
    if audit_result is None:
        return jsonify({"status": "not_ready", "error": "Run an audit first."})
    if ai_review_running:
        return jsonify({"status": "running"})
    if ai_review_result is not None:
        return jsonify({"status": "ready", "data": ai_review_result})

    ai_review_running = True
    try:
        ai_review_result = generate_ai_review(audit_result)
    finally:
        ai_review_running = False
    return jsonify({"status": "ready", "data": ai_review_result})


@app.route("/api/status")
def status():
    return jsonify({
        "running": audit_running,
        "has_result": audit_result is not None,
        "progress_count": len(audit_progress),
        "ai_enabled": is_ai_enabled(),
        "ai_review_ready": ai_review_result is not None,
        "ai_review_running": ai_review_running,
    })


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  🤖  Android Security Auditor")
    print("="*55)
    print("  Open your browser: http://localhost:5000")
    print("  Connect your Android via USB with ADB enabled")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
