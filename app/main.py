"""Secure Notes API.

Security controls built in:
  * API-key authentication; keys are stored only as SHA-256 hashes and compared in constant time
  * Strict input validation with pydantic (unknown fields rejected, length limits)
  * Per-key rate limiting and a request body size cap
  * Security headers on every response (CSP, HSTS, nosniff, frame-deny, referrer policy)
  * Tenant isolation: every query is scoped to the caller
  * Structured JSON logs with a request ID; secrets are never logged
  * Errors return generic messages, never stack traces
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict

from flask import Flask, g, jsonify, request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from werkzeug.exceptions import HTTPException

from .db import NoteStore


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=5000)


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def load_api_keys(raw: str) -> dict[str, str]:
    """Parse API_KEY_HASHES="alice:<sha256>,bob:<sha256>" into {hash: owner}."""
    keys = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        owner, _, digest = item.partition(":")
        if owner and len(digest) == 64:
            keys[digest.lower()] = owner
    return keys


class RateLimiter:
    """Fixed-window limiter: `limit` requests per `window` seconds per key."""

    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits[key] if now - t < self.window]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname, "msg": record.getMessage()}
        entry.update(getattr(record, "extra_fields", {}))
        return json.dumps(entry)


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    cfg = {
        "DB_PATH": os.environ.get("DB_PATH", "notes.db"),
        "API_KEY_HASHES": os.environ.get("API_KEY_HASHES", ""),
        "RATE_LIMIT_PER_MIN": int(os.environ.get("RATE_LIMIT_PER_MIN", "60")),
        "MAX_CONTENT_LENGTH": 16 * 1024,
    }
    cfg.update(config or {})
    app.config["MAX_CONTENT_LENGTH"] = cfg["MAX_CONTENT_LENGTH"]

    store = NoteStore(cfg["DB_PATH"])
    api_keys = load_api_keys(cfg["API_KEY_HASHES"])
    limiter = RateLimiter(cfg["RATE_LIMIT_PER_MIN"])
    metrics = defaultdict(int)

    log = logging.getLogger("notes")
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(JsonFormatter())
        log.addHandler(h)
        log.setLevel(logging.INFO)

    def error(status: int, message: str):
        return jsonify({"error": message, "request_id": g.get("request_id")}), status

    def authenticate() -> str | None:
        key = request.headers.get("X-API-Key", "")
        if not key:
            return None
        digest = hash_key(key)
        for stored, owner in api_keys.items():
            if hmac.compare_digest(stored, digest):
                return owner
        return None

    @app.before_request
    def before():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.start = time.perf_counter()
        g.owner = None
        if request.path.startswith("/api/"):
            owner = authenticate()
            if owner is None:
                metrics["auth_failures"] += 1
                return error(401, "invalid or missing API key")
            if not limiter.allow(owner):
                metrics["rate_limited"] += 1
                return error(429, "rate limit exceeded")
            g.owner = owner

    @app.after_request
    def after(resp):
        resp.headers.update(SECURITY_HEADERS)
        resp.headers["X-Request-ID"] = g.get("request_id", "")
        metrics["requests"] += 1
        metrics[f"status_{resp.status_code // 100}xx"] += 1
        log.info("request", extra={"extra_fields": {
            "request_id": g.get("request_id"), "method": request.method, "path": request.path,
            "status": resp.status_code, "owner": g.get("owner"),
            "duration_ms": round((time.perf_counter() - g.get("start", time.perf_counter())) * 1000, 2),
            "client_ip": request.remote_addr,
        }})
        return resp

    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        return error(e.code or 500, e.name)

    @app.errorhandler(Exception)
    def unhandled(e: Exception):
        log.error("unhandled error", extra={"extra_fields": {"request_id": g.get("request_id"),
                                                              "error": type(e).__name__}})
        return error(500, "internal server error")

    # ------------------------------------------------------------------ routes

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        ready = store.ping() and bool(api_keys)
        return (jsonify(status="ready"), 200) if ready else (jsonify(status="not ready"), 503)

    @app.get("/metrics")
    def metrics_view():
        lines = [f"notes_{k}_total {v}" for k, v in sorted(metrics.items())]
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}

    @app.post("/api/v1/notes")
    def create_note():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error(400, "JSON object body required")
        try:
            note = NoteIn.model_validate(payload)
        except ValidationError as e:
            fields = sorted({".".join(map(str, err["loc"])) for err in e.errors()})
            return error(422, f"invalid fields: {', '.join(fields)}")
        return jsonify(store.create(g.owner, note.title, note.body)), 201

    @app.get("/api/v1/notes")
    def list_notes():
        try:
            limit = min(max(int(request.args.get("limit", 50)), 1), 100)
        except ValueError:
            return error(400, "limit must be an integer")
        return jsonify(store.list(g.owner, limit))

    @app.get("/api/v1/notes/<int:note_id>")
    def get_note(note_id: int):
        note = store.get(g.owner, note_id)
        return jsonify(note) if note else error(404, "not found")

    @app.delete("/api/v1/notes/<int:note_id>")
    def delete_note(note_id: int):
        return ("", 204) if store.delete(g.owner, note_id) else error(404, "not found")

    return app
