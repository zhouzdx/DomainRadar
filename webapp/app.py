"""DomainRadar web UI - Flask + Server-Sent Events for live scan progress."""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict

from flask import Flask, Response, jsonify, render_template, request

# Make the parent ``domainradar`` package importable when running ``python webapp/app.py``.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from domainradar.scanner import Scanner  # noqa: E402
from domainradar.sources import (  # noqa: E402
    AlienVaultSource,
    AnubisSource,
    BruteForceSource,
    CrtShSource,
    HackerTargetSource,
    RapidDNSSource,
)
from domainradar.sources.base import normalize  # noqa: E402


app = Flask(__name__, template_folder=str(_HERE / "templates"), static_folder=str(_HERE / "static"))

# Cache the most recent completed scan per session so the UI can re-render after refresh.
_RESULT_CACHE: Dict[str, dict] = {}


def _sse(event_type: str, data) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _build_sources(use_bruteforce: bool):
    sources = [
        CrtShSource(),
        HackerTargetSource(),
        RapidDNSSource(),
        AnubisSource(),
        AlienVaultSource(),
    ]
    if use_bruteforce:
        sources.append(BruteForceSource(threads=80))
    return sources


def _stream_scan(domain: str, use_bruteforce: bool, do_resolve: bool):
    """Generator that yields SSE events for a single scan run."""
    q: "queue.Queue[tuple]" = queue.Queue()

    def progress_cb(event: str, payload):
        q.put((event, payload))

    sources = _build_sources(use_bruteforce)
    scanner = Scanner(
        sources=sources,
        resolve=do_resolve,
        resolve_threads=80,
        progress_cb=progress_cb,
    )

    state = {"result": None, "error": None}

    def worker():
        try:
            state["result"] = scanner.scan(domain)
        except Exception as e:  # noqa: BLE001
            state["error"] = str(e)
        finally:
            q.put(("__done__", None))

    job_id = uuid.uuid4().hex
    started = time.time()

    threading.Thread(target=worker, daemon=True).start()

    yield _sse(
        "start",
        {
            "job_id": job_id,
            "domain": domain,
            "sources": [s.name for s in sources],
            "resolve": do_resolve,
        },
    )

    # Keepalive ping every few seconds so proxies / browsers don't drop the connection.
    last_ping = time.time()
    while True:
        try:
            event, payload = q.get(timeout=1.0)
        except queue.Empty:
            if time.time() - last_ping > 5:
                yield ": ping\n\n"
                last_ping = time.time()
            continue
        if event == "__done__":
            break
        yield _sse(event, payload)
        last_ping = time.time()

    if state["error"]:
        yield _sse("error", {"message": state["error"]})
        return

    result = state["result"]
    elapsed = time.time() - started
    final = {
        "job_id": job_id,
        "domain": result.domain,
        "elapsed": round(elapsed, 2),
        "total": len(result.subdomains),
        "alive": len(result.alive),
        "subdomains": result.sorted_subdomains(),
        "per_source": {k: sorted(v) for k, v in result.per_source.items()},
        "resolved": result.resolved,
    }
    _RESULT_CACHE[job_id] = final
    # Trim cache to last 20 jobs.
    if len(_RESULT_CACHE) > 20:
        for old_key in list(_RESULT_CACHE)[:-20]:
            _RESULT_CACHE.pop(old_key, None)

    yield _sse("complete", final)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan")
def api_scan():
    raw_domain = request.args.get("domain", "")
    domain = normalize(raw_domain)
    if not domain or "." not in domain:
        return jsonify({"error": f"invalid domain: {raw_domain!r}"}), 400

    use_bruteforce = request.args.get("bruteforce", "0") == "1"
    do_resolve = request.args.get("resolve", "1") != "0"

    return Response(
        _stream_scan(domain, use_bruteforce, do_resolve),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/result/<job_id>")
def api_result(job_id: str):
    data = _RESULT_CACHE.get(job_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/result/<job_id>/download/<fmt>")
def api_download(job_id: str, fmt: str):
    data = _RESULT_CACHE.get(job_id)
    if not data:
        return jsonify({"error": "not found"}), 404

    domain = data["domain"]
    if fmt == "txt":
        body = "\n".join(data["subdomains"]) + "\n"
        return Response(
            body,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{domain}.txt"'},
        )
    if fmt == "alive":
        lines = []
        for host, ips in sorted((data.get("resolved") or {}).items()):
            if ips:
                lines.append(f"{host}\t{','.join(ips)}")
        body = "\n".join(lines) + ("\n" if lines else "")
        return Response(
            body,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{domain}.alive.txt"'},
        )
    if fmt == "json":
        return Response(
            json.dumps(data, ensure_ascii=False, indent=2),
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{domain}.json"'},
        )
    return jsonify({"error": "unknown format"}), 400


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


def main():
    import argparse

    parser = argparse.ArgumentParser(description="DomainRadar web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
