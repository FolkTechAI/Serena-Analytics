"""
Serena Analytics API
Receives anonymous usage events from Serena installs, serves aggregated metrics.
Deploy to Railway alongside the subscription API.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import sqlite3
import json
import os

app = FastAPI(title="Serena Analytics", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# --- Database ---

DB_PATH = os.environ.get("ANALYTICS_DB_PATH", "/data/analytics.db")

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            properties TEXT DEFAULT '{}',
            app_version TEXT,
            install_id TEXT,
            received_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event ON events(event)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_install_id ON events(install_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")

    # Crash reports table — stores rich diagnostics from MetricKit + signal handlers
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crash_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            install_id TEXT NOT NULL,
            app_version TEXT,
            timestamp TEXT NOT NULL,
            received_at TEXT DEFAULT (datetime('now')),
            source TEXT DEFAULT 'unknown',
            termination_reason TEXT,
            exception_type TEXT,
            signal TEXT,
            error_message TEXT,
            stack_trace TEXT,
            hang_duration_ms REAL,
            os_version TEXT,
            mac_model TEXT,
            memory_mb REAL,
            properties TEXT DEFAULT '{}'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crash_install ON crash_reports(install_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crash_timestamp ON crash_reports(timestamp)")

    conn.commit()
    conn.close()

init_db()

# --- Models ---

class AnalyticsEvent(BaseModel):
    event: str
    timestamp: str
    properties: dict = {}
    app_version: Optional[str] = "unknown"
    install_id: Optional[str] = "unknown"
    synced: Optional[bool] = False

class CrashReport(BaseModel):
    install_id: str
    app_version: Optional[str] = "unknown"
    timestamp: str
    source: str = "unknown"  # "metrickit", "signal_handler", "exception_handler", "clean_exit_check"
    termination_reason: Optional[str] = None
    exception_type: Optional[str] = None
    signal: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    hang_duration_ms: Optional[float] = None
    os_version: Optional[str] = None
    mac_model: Optional[str] = None
    memory_mb: Optional[float] = None
    properties: dict = {}

# --- Auth ---

API_KEY = os.environ.get("ANALYTICS_API_KEY", "serena-analytics-2026")

def verify_key(request: Request):
    key = request.headers.get("X-Analytics-Key", "")
    if key != API_KEY and API_KEY != "serena-analytics-2026":
        raise HTTPException(status_code=401, detail="Invalid API key")

# --- Routes ---

@app.get("/health")
def health():
    return {"status": "ok", "service": "serena-analytics"}

@app.post("/events")
async def receive_events(request: Request):
    """Receive a batch of analytics events from a Serena install."""
    verify_key(request)

    body = await request.json()

    # Accept both single event and array of events
    events = body if isinstance(body, list) else [body]

    conn = get_db()
    inserted = 0
    for raw in events:
        try:
            ev = AnalyticsEvent(**raw)
            conn.execute(
                "INSERT INTO events (event, timestamp, properties, app_version, install_id) VALUES (?, ?, ?, ?, ?)",
                (ev.event, ev.timestamp, json.dumps(ev.properties), ev.app_version, ev.install_id)
            )
            inserted += 1
        except Exception:
            continue  # Skip malformed events

    conn.commit()
    conn.close()
    return {"received": inserted}

@app.post("/api/event")
async def receive_single_event(request: Request):
    """Receive a single analytics event from a Serena install (used by AnalyticsClient)."""
    body = await request.json()
    try:
        ev = AnalyticsEvent(**body)
        conn = get_db()
        conn.execute(
            "INSERT INTO events (event, timestamp, properties, app_version, install_id) VALUES (?, ?, ?, ?, ?)",
            (ev.event, ev.timestamp, json.dumps(ev.properties), ev.app_version, ev.install_id)
        )
        conn.commit()
        conn.close()
        return {"received": 1}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/crash-report")
async def receive_crash_report(request: Request):
    """Receive a rich crash report with stack traces from MetricKit or signal handlers."""
    body = await request.json()

    # Accept single or batch
    reports = body if isinstance(body, list) else [body]

    conn = get_db()
    inserted = 0
    for raw in reports:
        try:
            cr = CrashReport(**raw)
            conn.execute(
                """INSERT INTO crash_reports
                   (install_id, app_version, timestamp, source, termination_reason,
                    exception_type, signal, error_message, stack_trace, hang_duration_ms,
                    os_version, mac_model, memory_mb, properties)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cr.install_id, cr.app_version, cr.timestamp, cr.source,
                 cr.termination_reason, cr.exception_type, cr.signal,
                 cr.error_message, cr.stack_trace, cr.hang_duration_ms,
                 cr.os_version, cr.mac_model, cr.memory_mb,
                 json.dumps(cr.properties))
            )
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    return {"received": inserted}


@app.get("/api/crash-reports")
def query_crash_reports(range: str = "7d", install_id: str = None, source: str = None):
    """Query rich crash reports with stack traces and diagnostics."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 7)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    query = "SELECT * FROM crash_reports WHERE timestamp>=?"
    params = [since]
    if install_id:
        query += " AND install_id=?"
        params.append(install_id)
    if source:
        query += " AND source=?"
        params.append(source)
    query += " ORDER BY timestamp DESC LIMIT 200"

    rows = conn.execute(query, params).fetchall()

    reports = []
    by_source = {}
    by_exception = {}
    by_signal = {}
    by_install = {}

    for r in rows:
        report = {
            "id": r["id"],
            "install_id": r["install_id"],
            "app_version": r["app_version"],
            "timestamp": r["timestamp"],
            "received_at": r["received_at"],
            "source": r["source"],
            "termination_reason": r["termination_reason"],
            "exception_type": r["exception_type"],
            "signal": r["signal"],
            "error_message": r["error_message"],
            "stack_trace": r["stack_trace"],
            "hang_duration_ms": r["hang_duration_ms"],
            "os_version": r["os_version"],
            "mac_model": r["mac_model"],
            "memory_mb": r["memory_mb"],
            "properties": json.loads(r["properties"]) if r["properties"] else {},
        }
        reports.append(report)

        # Aggregations
        src = r["source"] or "unknown"
        by_source[src] = by_source.get(src, 0) + 1

        exc = r["exception_type"] or "none"
        by_exception[exc] = by_exception.get(exc, 0) + 1

        sig = r["signal"] or "none"
        by_signal[sig] = by_signal.get(sig, 0) + 1

        iid = r["install_id"] or "unknown"
        by_install[iid] = by_install.get(iid, 0) + 1

    conn.close()
    return {
        "range": range,
        "total": len(reports),
        "by_source": dict(sorted(by_source.items(), key=lambda x: x[1], reverse=True)),
        "by_exception_type": dict(sorted(by_exception.items(), key=lambda x: x[1], reverse=True)),
        "by_signal": dict(sorted(by_signal.items(), key=lambda x: x[1], reverse=True)),
        "by_install": by_install,
        "reports": reports,
    }


@app.get("/api/tool-failures")
def tool_failures(range: str = "7d", install_id: str = None):
    """Return detailed tool failure events with full error context."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 7)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    query = "SELECT * FROM events WHERE event='tool_failed' AND timestamp>=?"
    params = [since]
    if install_id:
        query += " AND install_id=?"
        params.append(install_id)
    query += " ORDER BY timestamp DESC LIMIT 500"

    rows = conn.execute(query, params).fetchall()

    failures = []
    tool_error_map = {}  # tool -> {error -> count}
    for r in rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        tool = props.get("tool", "unknown")
        error = props.get("error", "unknown")
        failures.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "install_id": r["install_id"],
            "app_version": r["app_version"],
            "tool": tool,
            "action": props.get("action", "unknown"),
            "error": error,
            "error_code": props.get("error_code"),
            "duration_ms": props.get("duration_ms", 0),
            "params": props.get("params", {}),
            "user_message": props.get("user_message"),
            "stack_context": props.get("stack_context"),
            "memory_mb": props.get("memory_mb"),
            "recovery_attempted": props.get("recovery_attempted", False),
        })
        if tool not in tool_error_map:
            tool_error_map[tool] = {}
        tool_error_map[tool][error] = tool_error_map[tool].get(error, 0) + 1

    conn.close()
    return {
        "range": range,
        "total_failures": len(failures),
        "by_tool": {t: dict(sorted(errs.items(), key=lambda x: x[1], reverse=True))
                    for t, errs in sorted(tool_error_map.items(), key=lambda x: sum(x[1].values()), reverse=True)},
        "failures": failures,
    }


@app.get("/api/applescript-errors")
def applescript_errors(range: str = "7d"):
    """Return AppleScript-specific errors with sandbox/permission diagnostics."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 7)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    rows = conn.execute(
        "SELECT * FROM events WHERE event='applescript_error' AND timestamp>=? ORDER BY timestamp DESC LIMIT 500",
        (since,)
    ).fetchall()

    errors = []
    app_error_map = {}  # target_app -> {error_message -> count}
    for r in rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        target = props.get("target_app", "unknown")
        msg = props.get("error_message", "unknown")
        errors.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "install_id": r["install_id"],
            "app_version": r["app_version"],
            "target_app": target,
            "script_action": props.get("script_action", "unknown"),
            "error_message": msg,
            "error_number": props.get("error_number"),
            "automation_permission": props.get("automation_permission"),
            "app_was_running": props.get("app_was_running"),
            "sandbox_active": props.get("sandbox_active"),
            "os_version": props.get("os_version"),
            "device_model": props.get("device_model"),
        })
        if target not in app_error_map:
            app_error_map[target] = {}
        app_error_map[target][msg] = app_error_map[target].get(msg, 0) + 1

    conn.close()
    return {
        "range": range,
        "total_errors": len(errors),
        "by_app": app_error_map,
        "errors": errors,
    }


@app.get("/api/health-report")
def health_report(range: str = "1d"):
    """Comprehensive health report: errors, crashes, tool failures, performance — everything at a glance."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 1)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    # Count each error-type event
    error_events = ["crash_detected", "tool_failed", "applescript_error"]
    counts = {}
    for ev in error_events:
        counts[ev] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE event=? AND timestamp>=?", (ev, since)
        ).fetchone()[0]

    # Recent errors (last 20 across all error types)
    placeholders = ",".join(["?" for _ in error_events])
    rows = conn.execute(
        f"SELECT * FROM events WHERE event IN ({placeholders}) AND timestamp>=? ORDER BY timestamp DESC LIMIT 20",
        (*error_events, since)
    ).fetchall()

    recent = []
    for r in rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        recent.append({
            "event": r["event"],
            "timestamp": r["timestamp"],
            "install_id": r["install_id"],
            "error": props.get("error") or props.get("error_message", "unknown"),
            "tool": props.get("tool") or props.get("target_app", ""),
            "action": props.get("action") or props.get("script_action", ""),
            "os_version": props.get("os_version", ""),
            "device_model": props.get("device_model", ""),
        })

    # Affected installs
    affected = conn.execute(
        f"SELECT COUNT(DISTINCT install_id) FROM events WHERE event IN ({placeholders}) AND timestamp>=?",
        (*error_events, since)
    ).fetchone()[0]

    conn.close()
    return {
        "range": range,
        "since": since,
        "error_counts": counts,
        "total_errors": sum(counts.values()),
        "affected_installs": affected,
        "recent_errors": recent,
    }


@app.delete("/api/clear")
def clear_events(event_type: str = None, before: str = None, install_id: str = None):
    """Clear old events from the database.
    - event_type: clear specific event type (e.g. 'crash_detected', 'tool_failed') or 'all' for everything
    - before: clear events before this ISO date (e.g. '2026-02-15')
    - install_id: clear only for a specific install
    If no filters provided, returns error to prevent accidental wipe.
    """
    if not event_type and not before and not install_id:
        raise HTTPException(status_code=400, detail="Provide at least one filter: event_type, before, or install_id. Use event_type=all&before=<date> to clear everything before a date.")

    conn = get_db()
    conditions = []
    params = []

    if event_type and event_type != "all":
        conditions.append("event=?")
        params.append(event_type)

    if before:
        conditions.append("timestamp<?")
        params.append(before)

    if install_id:
        conditions.append("install_id=?")
        params.append(install_id)

    where = " AND ".join(conditions) if conditions else "1=1"

    # Count before delete
    count = conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]

    if count == 0:
        conn.close()
        return {"cleared": 0, "message": "No matching events found"}

    conn.execute(f"DELETE FROM events WHERE {where}", params)
    conn.commit()
    conn.close()
    return {"cleared": count, "filters": {"event_type": event_type, "before": before, "install_id": install_id}}


@app.delete("/api/clear/crashes")
def clear_crashes(before: str = None):
    """Quick shortcut to clear all crash events, optionally before a date."""
    conn = get_db()
    if before:
        count = conn.execute("SELECT COUNT(*) FROM events WHERE event='crash_detected' AND timestamp<?", (before,)).fetchone()[0]
        conn.execute("DELETE FROM events WHERE event='crash_detected' AND timestamp<?", (before,))
    else:
        count = conn.execute("SELECT COUNT(*) FROM events WHERE event='crash_detected'").fetchone()[0]
        conn.execute("DELETE FROM events WHERE event='crash_detected'")
    conn.commit()
    conn.close()
    return {"cleared": count, "event_type": "crash_detected"}


@app.delete("/api/clear/errors")
def clear_all_errors(before: str = None):
    """Clear all error-type events (crashes, tool failures, applescript errors)."""
    error_types = ("crash_detected", "tool_failed", "applescript_error")
    conn = get_db()
    placeholders = ",".join(["?" for _ in error_types])
    if before:
        count = conn.execute(f"SELECT COUNT(*) FROM events WHERE event IN ({placeholders}) AND timestamp<?", (*error_types, before)).fetchone()[0]
        conn.execute(f"DELETE FROM events WHERE event IN ({placeholders}) AND timestamp<?", (*error_types, before))
    else:
        count = conn.execute(f"SELECT COUNT(*) FROM events WHERE event IN ({placeholders})", error_types).fetchone()[0]
        conn.execute(f"DELETE FROM events WHERE event IN ({placeholders})", error_types)
    conn.commit()
    conn.close()
    return {"cleared": count, "event_types": list(error_types)}


@app.get("/api/crashes")
def crashes(range: str = "all", install_id: str = None):
    """Return detailed crash events with full properties."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 9999)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    if install_id:
        rows = conn.execute(
            "SELECT * FROM events WHERE event='crash_detected' AND timestamp>=? AND install_id=? ORDER BY timestamp DESC",
            (since, install_id)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events WHERE event='crash_detected' AND timestamp>=? ORDER BY timestamp DESC",
            (since,)
        ).fetchall()

    crashes = []
    for r in rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        crashes.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "install_id": r["install_id"],
            "app_version": r["app_version"],
            "received_at": r["received_at"],
            "error": props.get("error", "unknown"),
            "stack_trace": props.get("stack_trace", None),
            "context": props.get("context", None),
            "view": props.get("view", None),
            "properties": props,
        })

    # Summary by error type
    error_counts = {}
    for c in crashes:
        err = c["error"]
        error_counts[err] = error_counts.get(err, 0) + 1
    error_counts = dict(sorted(error_counts.items(), key=lambda x: x[1], reverse=True))

    # Summary by install
    install_counts = {}
    for c in crashes:
        iid = c["install_id"]
        install_counts[iid] = install_counts.get(iid, 0) + 1

    conn.close()
    return {
        "range": range,
        "total_crashes": len(crashes),
        "by_error": error_counts,
        "by_install": install_counts,
        "crashes": crashes,
    }


@app.get("/api/funnel")
def onboarding_funnel(range: str = "all"):
    """Onboarding funnel — shows conversion at each stage from app launch to first message.
    Each stage shows unique installs that reached it, plus drop-off from previous stage.
    """
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 9999)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    # Funnel stages in order
    stages = [
        ("app_launched", "App Launched"),
        ("setup_started", "Setup Wizard Started"),
        ("setup_completed", "Setup Completed"),
        ("onboarding_started", "Onboarding Started"),
        ("onboarding_completed", "Onboarding Completed"),
        ("first_message_sent", "First Message Sent"),
    ]

    funnel = []
    prev_count = None
    for event_name, label in stages:
        count = conn.execute(
            "SELECT COUNT(DISTINCT install_id) FROM events WHERE event=? AND timestamp>=?",
            (event_name, since)
        ).fetchone()[0]
        drop_off = None
        conversion = None
        if prev_count is not None and prev_count > 0:
            drop_off = prev_count - count
            conversion = round(count / prev_count, 3)
        funnel.append({
            "stage": event_name,
            "label": label,
            "unique_installs": count,
            "drop_off": drop_off,
            "conversion_from_previous": conversion,
        })
        prev_count = count

    # Overall conversion: app_launched → first_message_sent
    total_launched = funnel[0]["unique_installs"] if funnel else 0
    total_completed = funnel[-1]["unique_installs"] if funnel else 0
    overall_rate = round(total_completed / total_launched, 3) if total_launched > 0 else 0

    # Setup step breakdown (which steps fail?)
    step_rows = conn.execute(
        "SELECT properties FROM events WHERE event='setup_step_completed' AND timestamp>=?",
        (since,)
    ).fetchall()
    step_results = {}
    for r in step_rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        step = props.get("step", "unknown")
        success = props.get("success", True)
        if step not in step_results:
            step_results[step] = {"success": 0, "failed": 0}
        step_results[step]["success" if success else "failed"] += 1

    # Model download breakdown
    dl_rows = conn.execute(
        "SELECT properties FROM events WHERE event='setup_model_download' AND timestamp>=?",
        (since,)
    ).fetchall()
    download_stats = {"started": 0, "completed": 0, "failed": 0, "already_exists": 0, "methods": {}}
    for r in dl_rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        status = props.get("status", "unknown")
        if status in download_stats:
            download_stats[status] += 1
        method = props.get("download_method")
        if method:
            download_stats["methods"][method] = download_stats["methods"].get(method, 0) + 1

    # Onboarding page reach (which pages do people see?)
    page_rows = conn.execute(
        "SELECT properties FROM events WHERE event='onboarding_page_viewed' AND timestamp>=?",
        (since,)
    ).fetchall()
    page_reach = {}
    for r in page_rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        page = props.get("page", "unknown")
        page_reach[page] = page_reach.get(page, 0) + 1

    # Onboarding preferences (what do completers choose?)
    pref_rows = conn.execute(
        "SELECT properties FROM events WHERE event='onboarding_completed' AND timestamp>=?",
        (since,)
    ).fetchall()
    pref_stats = {"voice_enabled": 0, "passcode_enabled": 0, "total": len(pref_rows)}
    for r in pref_rows:
        props = json.loads(r["properties"]) if r["properties"] else {}
        if props.get("voice_enabled"): pref_stats["voice_enabled"] += 1
        if props.get("passcode_enabled"): pref_stats["passcode_enabled"] += 1

    conn.close()
    return {
        "range": range,
        "funnel": funnel,
        "overall_conversion": overall_rate,
        "setup_steps": step_results,
        "model_download": download_stats,
        "onboarding_pages": page_reach,
        "onboarding_preferences": pref_stats,
    }


@app.get("/api/events")
def query_events(event: str, range: str = "7d", limit: int = 100):
    """Query raw events by type. Use for debugging any event category."""
    conn = get_db()
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 7)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    rows = conn.execute(
        "SELECT * FROM events WHERE event=? AND timestamp>=? ORDER BY timestamp DESC LIMIT ?",
        (event, since, min(limit, 500))
    ).fetchall()

    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "event": r["event"],
            "timestamp": r["timestamp"],
            "install_id": r["install_id"],
            "app_version": r["app_version"],
            "received_at": r["received_at"],
            "properties": json.loads(r["properties"]) if r["properties"] else {},
        })

    conn.close()
    return {"event": event, "range": range, "count": len(events), "events": events}


@app.get("/api/events/types")
def event_types():
    """List all distinct event types and their counts."""
    conn = get_db()
    rows = conn.execute(
        "SELECT event, COUNT(*) as cnt FROM events GROUP BY event ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return {"types": {r["event"]: r["cnt"] for r in rows}}


@app.get("/api/dashboard")
def dashboard(range: str = "7d"):
    """Return aggregated dashboard metrics as JSON.
    ?range=1d, 7d, 30d, all
    """
    conn = get_db()

    # Determine time window
    range_days = {"1d": 1, "7d": 7, "30d": 30, "all": 9999}.get(range, 7)
    since = (datetime.utcnow() - timedelta(days=range_days)).isoformat()

    def count(event_name, extra=""):
        q = f"SELECT COUNT(*) FROM events WHERE event=? AND timestamp>=? {extra}"
        return conn.execute(q, (event_name, since)).fetchone()[0]

    def count_unique(event_name, col="install_id"):
        return conn.execute(
            f"SELECT COUNT(DISTINCT {col}) FROM events WHERE event=? AND timestamp>=?",
            (event_name, since)
        ).fetchone()[0]

    # --- Core Metrics ---
    total_installs = conn.execute(
        "SELECT COUNT(DISTINCT install_id) FROM events WHERE event='app_launched'"
    ).fetchone()[0]

    dau = count_unique("daily_active")
    wau = count_unique("weekly_active")

    # Session duration
    rows = conn.execute(
        "SELECT properties FROM events WHERE event='session_end' AND timestamp>=?", (since,)
    ).fetchall()
    durations = []
    for r in rows:
        try:
            d = json.loads(r["properties"]).get("duration_seconds", 0)
            if d: durations.append(d)
        except Exception:
            pass
    avg_session = round(sum(durations) / len(durations), 1) if durations else 0

    # --- Revenue ---
    trial_started = count("trial_started")
    trial_expired = count("trial_expired")
    trial_converted = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event='trial_expired' AND timestamp>=? AND json_extract(properties, '$.converted')=1",
        (since,)
    ).fetchone()[0]
    trial_rate = round(trial_converted / trial_expired, 3) if trial_expired > 0 else 0

    sub_started = count("subscription_started")
    sub_cancelled = count("subscription_cancelled")
    active_subs = max(0, conn.execute(
        "SELECT COUNT(DISTINCT install_id) FROM events WHERE event='subscription_started'"
    ).fetchone()[0] - conn.execute(
        "SELECT COUNT(DISTINCT install_id) FROM events WHERE event='subscription_cancelled'"
    ).fetchone()[0])
    mrr = active_subs * 20.0
    churn_rate = round(sub_cancelled / sub_started, 3) if sub_started > 0 else 0

    # --- Tool Usage ---
    tool_rows = conn.execute(
        "SELECT properties FROM events WHERE event='tool_call_executed' AND timestamp>=?", (since,)
    ).fetchall()
    tool_usage = {}
    for r in tool_rows:
        try:
            tool = json.loads(r["properties"]).get("tool", "unknown")
            tool_usage[tool] = tool_usage.get(tool, 0) + 1
        except Exception:
            pass
    # Sort descending
    tool_usage = dict(sorted(tool_usage.items(), key=lambda x: x[1], reverse=True))

    # --- Paywall ---
    paywall_shown = count("paywall_shown")
    paywall_converted = count("paywall_converted")
    paywall_rate = round(paywall_converted / paywall_shown, 3) if paywall_shown > 0 else 0

    # Top paywall trigger
    pw_rows = conn.execute(
        "SELECT properties FROM events WHERE event='paywall_shown' AND timestamp>=?", (since,)
    ).fetchall()
    pw_triggers = {}
    for r in pw_rows:
        try:
            f = json.loads(r["properties"]).get("feature", "unknown")
            pw_triggers[f] = pw_triggers.get(f, 0) + 1
        except Exception:
            pass
    top_trigger = max(pw_triggers, key=pw_triggers.get) if pw_triggers else "none"

    # --- Performance ---
    llm_rows = conn.execute(
        "SELECT properties FROM events WHERE event='llm_response_time_ms' AND timestamp>=?", (since,)
    ).fetchall()
    llm_times = []
    for r in llm_rows:
        try:
            v = json.loads(r["properties"]).get("value", 0)
            if v: llm_times.append(v)
        except Exception:
            pass
    avg_llm = round(sum(llm_times) / len(llm_times), 1) if llm_times else 0

    rtai_rows = conn.execute(
        "SELECT properties FROM events WHERE event='rtai_response_time_ms' AND timestamp>=?", (since,)
    ).fetchall()
    rtai_times = []
    for r in rtai_rows:
        try:
            v = json.loads(r["properties"]).get("value", 0)
            if v: rtai_times.append(v)
        except Exception:
            pass
    avg_rtai = round(sum(rtai_times) / len(rtai_times), 1) if rtai_times else 0

    # --- TCA ---
    tca_triggered = count("tca_triggered")
    tca_engaged = count("tca_engaged")
    tca_rate = round(tca_engaged / tca_triggered, 3) if tca_triggered > 0 else 0

    # --- Crashes & Errors ---
    crashes = count("crash_detected")
    tool_failures_count = count("tool_failed")
    applescript_errors_count = count("applescript_error")

    # Rich crash reports (from MetricKit/signal handlers)
    rich_crashes = conn.execute(
        "SELECT COUNT(*) FROM crash_reports WHERE timestamp>=?", (since,)
    ).fetchone()[0]
    crash_with_traces = conn.execute(
        "SELECT COUNT(*) FROM crash_reports WHERE timestamp>=? AND stack_trace IS NOT NULL AND stack_trace != ''",
        (since,)
    ).fetchone()[0]
    hang_reports = conn.execute(
        "SELECT COUNT(*) FROM crash_reports WHERE timestamp>=? AND hang_duration_ms IS NOT NULL",
        (since,)
    ).fetchone()[0]

    # Also count tool_used events (from new AnalyticsClient)
    tool_used_rows = conn.execute(
        "SELECT properties FROM events WHERE event='tool_used' AND timestamp>=?", (since,)
    ).fetchall()
    for r in tool_used_rows:
        try:
            tool = json.loads(r["properties"]).get("tool", "unknown")
            tool_usage[tool] = tool_usage.get(tool, 0) + 1
        except Exception:
            pass
    tool_usage = dict(sorted(tool_usage.items(), key=lambda x: x[1], reverse=True))

    # --- Active Trials ---
    active_trials = max(0, conn.execute(
        "SELECT COUNT(DISTINCT install_id) FROM events WHERE event='trial_started'"
    ).fetchone()[0] - conn.execute(
        "SELECT COUNT(DISTINCT install_id) FROM events WHERE event='trial_expired'"
    ).fetchone()[0])

    # --- Free Limit Hits ---
    free_limit_hits = count("free_limit_hit")

    # --- Version Breakdown ---
    version_rows = conn.execute(
        "SELECT app_version, COUNT(DISTINCT install_id) as cnt FROM events WHERE event='app_launched' AND timestamp>=? GROUP BY app_version ORDER BY cnt DESC",
        (since,)
    ).fetchall()
    versions = {r["app_version"]: r["cnt"] for r in version_rows}

    conn.close()

    return {
        "range": range,
        "generated_at": datetime.utcnow().isoformat(),
        "revenue": {
            "mrr": mrr,
            "active_subscriptions": active_subs,
            "trial_started": trial_started,
            "trial_expired": trial_expired,
            "trial_conversion_rate": trial_rate,
            "churn_rate": churn_rate,
            "active_trials": active_trials,
        },
        "engagement": {
            "total_installs": total_installs,
            "dau": dau,
            "wau": wau,
            "avg_session_seconds": avg_session,
            "free_limit_hits": free_limit_hits,
        },
        "tools": {
            "usage": tool_usage,
            "total_calls": sum(tool_usage.values()),
        },
        "paywall": {
            "shown": paywall_shown,
            "converted": paywall_converted,
            "conversion_rate": paywall_rate,
            "top_trigger": top_trigger,
        },
        "performance": {
            "avg_llm_response_ms": avg_llm,
            "avg_rtai_response_ms": avg_rtai,
            "crash_count": crashes,
            "rich_crash_reports": rich_crashes,
            "crashes_with_stack_trace": crash_with_traces,
            "hang_reports": hang_reports,
            "tool_failures": tool_failures_count,
            "applescript_errors": applescript_errors_count,
        },
        "tca": {
            "triggered": tca_triggered,
            "engaged": tca_engaged,
            "engagement_rate": tca_rate,
        },
        "versions": versions,
    }


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_html(range: str = "7d"):
    """HTML dashboard - fallback for browser viewing."""
    data = dashboard(range=range)
    r = data["revenue"]
    e = data["engagement"]
    t = data["tools"]
    p = data["paywall"]
    perf = data["performance"]
    tca = data["tca"]

    # Get funnel data for this range
    funnel_data = onboarding_funnel(range=range)

    tool_rows = "".join(
        f"<tr><td>{name}</td><td>{count}</td></tr>"
        for name, count in t["usage"].items()
    ) or "<tr><td colspan='2'>No data yet</td></tr>"

    version_rows = "".join(
        f"<tr><td>{v}</td><td>{c}</td></tr>"
        for v, c in data["versions"].items()
    ) or "<tr><td colspan='2'>No data yet</td></tr>"

    # Build funnel rows
    funnel_rows = ""
    for stage in funnel_data["funnel"]:
        conv_text = f"{stage['conversion_from_previous']*100:.0f}%" if stage['conversion_from_previous'] is not None else "-"
        drop_text = str(stage['drop_off']) if stage['drop_off'] is not None else "-"
        bar_width = 0
        if funnel_data["funnel"][0]["unique_installs"] > 0:
            bar_width = int(stage["unique_installs"] / funnel_data["funnel"][0]["unique_installs"] * 100)
        funnel_rows += f"""<tr>
            <td>{stage['label']}</td>
            <td><div style="background:#1e40af;height:20px;width:{bar_width}%;border-radius:4px;min-width:2px"></div></td>
            <td style="text-align:right;font-weight:700">{stage['unique_installs']}</td>
            <td style="text-align:right;color:#94a3b8">{conv_text}</td>
            <td style="text-align:right;color:#ef4444">{drop_text}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Serena Analytics</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
  h1 {{ color: #0ea5e9; font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 16px; border: 1px solid #334155; }}
  .card .label {{ color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .card .value {{ font-size: 28px; font-weight: 700; color: #f1f5f9; margin-top: 4px; }}
  .card .value.green {{ color: #22c55e; }}
  .card .value.blue {{ color: #0ea5e9; }}
  .section {{ margin-bottom: 24px; }}
  .section h2 {{ font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 13px; }}
  td:last-child {{ text-align: right; font-weight: 600; }}
  .range {{ margin-bottom: 16px; }}
  .range a {{ color: #64748b; text-decoration: none; margin-right: 12px; font-size: 13px; }}
  .range a.active, .range a:hover {{ color: #0ea5e9; }}
</style></head><body>
<h1>Serena Analytics</h1>
<div class="subtitle">Generated {data['generated_at'][:19]} UTC</div>

<div class="range">
  <a href="?range=1d" {'class="active"' if range=='1d' else ''}>Today</a>
  <a href="?range=7d" {'class="active"' if range=='7d' else ''}>7 Days</a>
  <a href="?range=30d" {'class="active"' if range=='30d' else ''}>30 Days</a>
  <a href="?range=all" {'class="active"' if range=='all' else ''}>All Time</a>
</div>

<div class="grid">
  <div class="card"><div class="label">MRR</div><div class="value green">${r['mrr']:.0f}</div></div>
  <div class="card"><div class="label">Active Subs</div><div class="value">{r['active_subscriptions']}</div></div>
  <div class="card"><div class="label">Total Installs</div><div class="value blue">{e['total_installs']}</div></div>
  <div class="card"><div class="label">Active Trials</div><div class="value">{r['active_trials']}</div></div>
  <div class="card"><div class="label">DAU / WAU</div><div class="value">{e['dau']} / {e['wau']}</div></div>
  <div class="card"><div class="label">Avg Session</div><div class="value">{e['avg_session_seconds']:.0f}s</div></div>
  <div class="card"><div class="label">Trial &rarr; Paid</div><div class="value">{r['trial_conversion_rate']*100:.1f}%</div></div>
  <div class="card"><div class="label">Churn Rate</div><div class="value">{r['churn_rate']*100:.1f}%</div></div>
  <div class="card"><div class="label">Paywall &rarr; Paid</div><div class="value">{p['conversion_rate']*100:.1f}%</div></div>
  <div class="card"><div class="label">Free Limit Hits</div><div class="value">{e['free_limit_hits']}</div></div>
  <div class="card"><div class="label">Avg LLM Response</div><div class="value">{perf['avg_llm_response_ms']:.0f}ms</div></div>
  <div class="card"><div class="label">Crashes</div><div class="value">{perf['crash_count']}</div></div>
  <div class="card"><div class="label">Tool Failures</div><div class="value">{perf['tool_failures']}</div></div>
  <div class="card"><div class="label">AppleScript Errors</div><div class="value">{perf['applescript_errors']}</div></div>
</div>

<div class="section"><h2>Onboarding Funnel (Overall: {funnel_data['overall_conversion']*100:.0f}%)</h2>
<div class="card"><table>
<tr><td style="color:#94a3b8;font-size:11px">STAGE</td><td style="color:#94a3b8;font-size:11px"></td><td style="color:#94a3b8;font-size:11px;text-align:right">INSTALLS</td><td style="color:#94a3b8;font-size:11px;text-align:right">CONV %</td><td style="color:#94a3b8;font-size:11px;text-align:right">DROP OFF</td></tr>
{funnel_rows}
</table></div></div>

<div class="section"><h2>Tool Usage ({t['total_calls']} total)</h2>
<div class="card"><table>{tool_rows}</table></div></div>

<div class="section"><h2>TCA Proactive AI</h2>
<div class="grid">
  <div class="card"><div class="label">Triggered</div><div class="value">{tca['triggered']}</div></div>
  <div class="card"><div class="label">Engaged</div><div class="value">{tca['engaged']}</div></div>
  <div class="card"><div class="label">Engagement Rate</div><div class="value">{tca['engagement_rate']*100:.1f}%</div></div>
</div></div>

<div class="section"><h2>App Versions</h2>
<div class="card"><table>{version_rows}</table></div></div>

</body></html>"""
    return HTMLResponse(content=html)
