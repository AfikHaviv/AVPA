"""Flask UI: enter a CVE ID, watch each pipeline stage run, inspect its output."""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from cve_pipeline.config import get_settings
from cve_pipeline.exploit_runner import available_cve_ids, run_eternalblue_via_msf_rpc, run_vsftpd_backdoor
from cve_pipeline.net_guard import UnauthorizedTargetError
from cve_pipeline.pipeline import run_pipeline

app = Flask(__name__)
app.secret_key = get_settings().flask_secret_key


@app.get("/")
def index():
    return render_template("index.html", live_cve_ids=available_cve_ids())


@app.post("/api/run")
def api_run():
    cve_id = (request.get_json(silent=True) or {}).get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "cve_id is required"}), 400
    try:
        result = run_pipeline(cve_id)
    except Exception as exc:  # noqa: BLE001 - surface any pipeline failure to the UI
        return jsonify({"error": str(exc)}), 502
    return jsonify(result.as_dict())


@app.post("/api/execute")
def api_execute():
    """Real execution against a lab target the caller explicitly names and
    confirms authorization for. Never triggered automatically by /api/run.
    """
    body = request.get_json(silent=True) or {}
    cve_id = (body.get("cve_id") or "").strip().upper()
    target = (body.get("target") or "").strip()
    confirmed = bool(body.get("confirmed"))

    if cve_id not in available_cve_ids():
        return jsonify({"error": f"no live runner registered for {cve_id or '(empty)'}"}), 400
    if not target:
        return jsonify({"error": "target is required"}), 400

    settings = get_settings()
    try:
        if cve_id == "CVE-2011-2523":
            result = run_vsftpd_backdoor(target, confirmed=confirmed)
        else:
            lhost = (body.get("lhost") or "").strip()
            if not lhost:
                return jsonify({"error": "lhost is required for CVE-2017-0144"}), 400
            result = run_eternalblue_via_msf_rpc(
                target,
                lhost,
                confirmed=confirmed,
                rpc_host=settings.msf_rpc_host,
                rpc_port=settings.msf_rpc_port,
                rpc_password=settings.msf_rpc_password,
                ssl=settings.msf_rpc_ssl,
            )
    except UnauthorizedTargetError as exc:
        return jsonify({"error": str(exc)}), 403

    return jsonify(result.as_dict())


def main() -> None:
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
