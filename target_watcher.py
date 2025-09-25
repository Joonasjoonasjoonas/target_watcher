#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import socket
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

import requests

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv("target_watcher.env", override=True)
except Exception as e:
    print(f"Warning: Could not load .env file: {e}", file=sys.stderr)

# ----------------------
# Config from environment
# ----------------------
URL = os.getenv("TARGETS_URL")
if not URL:
    print("ERROR: Set TARGETS_URL in environment file", file=sys.stderr)
    sys.exit(2)

STATE_FILE = Path(os.getenv("STATE_FILE", str(Path(__file__).with_name("seen.json"))))

MONITORED_HOSTS = [
    h.strip().lower()
    for h in os.getenv("MONITORED_HOSTS", "").split(",")
    if h.strip()
]

USE_STATE = os.getenv("USE_STATE", "0") == "1"  # 1 = use seen.json (default), 0 = stateless

# Slack
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "").strip()
SLACK_SUMMARY_ONLY = os.getenv("SLACK_SUMMARY_ONLY", "1") == "1"
SLACK_EXAMPLES_PER_HOST = int(os.getenv("SLACK_EXAMPLES_PER_HOST", "2"))
SLACK_MAX_HOSTS = int(os.getenv("SLACK_MAX_HOSTS", "10"))
SLACK_SUPPRESS_EMPTY = os.getenv("SLACK_SUPPRESS_EMPTY", "1") == "1"
SLACK_TITLE = os.getenv("SLACK_TITLE", "Target watcher")

# Email (optional – skip if only using Slack)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
EMAIL_TO = os.getenv("EMAIL_TO", "").strip()  


# ----------------------
# State handling
# ----------------------
def load_state() -> Dict[str, Any]:
    if not USE_STATE:
        # Stateless mode: behave as if nothing has been seen
        return {"seen_request_ids": {}}
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen_request_ids": {}}

def save_state(state: Dict[str, Any]) -> None:
    if not USE_STATE:
        return  # Stateless mode: don't persist anything
    seen = state.get("seen_request_ids", {})
    if len(seen) > 50000:
        for k in list(seen.keys())[:10000]:
            del seen[k]
        state["seen_request_ids"] = seen
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


# ----------------------
# Helpers
# ----------------------
def normalize_host(h: str) -> str:
    h = (h or "").lower().strip()
    if h.startswith("www."):
        h = h[4:]
    return h


def host_matches(monitored: List[str], host: str) -> bool:
    """Suffix match: sub.example.com matches 'example.com'."""
    host = normalize_host(host)
    for m in monitored:
        m = normalize_host(m)
        if host == m or host.endswith("." + m):
            return True
    return False


def fetch_targets(url: str) -> List[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("targets", [])
    except requests.RequestException as e:
        error_msg = f"Failed to fetch targets from {url}: {str(e)}"
        print(f"ERROR: {error_msg}", file=sys.stderr)
        # Try to notify via Slack about the error
        if SLACK_WEBHOOK:
            try:
                text = (
                    ":warning: Target Watcher Error :warning:\n\n"
                    f"*{SLACK_TITLE}*: {error_msg}\n"
                    f"_host: {socket.gethostname()}_"
                )
                requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=15)
            except Exception as slack_e:
                print(f"ERROR: Failed to send error notification to Slack: {slack_e}", file=sys.stderr)
        raise  # Re-raise the original exception


def format_hits(hits: List[Dict[str, Any]]) -> str:
    """Verbose list of hits (used if SLACK_SUMMARY_ONLY=0)."""
    lines = []
    for t in hits:
        host = t.get("host")
        path = t.get("path", "")
        method = t.get("method", "") or t.get("type", "")
        typ = t.get("type", "")
        port = t.get("port", "")
        rid = t.get("request_id", "")
        lines.append(f"- {host}  {method or typ} {path or ''} (port {port})  request_id={rid}")
    return "\n".join(lines)


def summarize_hits_by_host(hits: List[Dict[str, Any]]):
    groups = defaultdict(lambda: {"count": 0, "examples": []})
    for t in hits:
        host = normalize_host(t.get("host", ""))
        method = (t.get("method") or t.get("type") or "").upper()
        path = t.get("path") or ""
        ex = (method + " " + path).strip()
        groups[host]["count"] += 1
        if ex and len(groups[host]["examples"]) < SLACK_EXAMPLES_PER_HOST:
            groups[host]["examples"].append(ex)
    return groups


def format_compact_slack(hits: List[Dict[str, Any]], url: str) -> str:
    groups = summarize_hits_by_host(hits)
    total = sum(g["count"] for g in groups.values())
    unique_hosts = len(groups)
    lines = [
    ":rotating_light: Oh noes, we might be under attack soon! :rotating_light:",
    f"*{SLACK_TITLE}:* {total} new hits / {unique_hosts} hosts\n{url}"
    ]

    items = sorted(groups.items(), key=lambda kv: kv[1]["count"], reverse=True)
    shown = 0
    for host, info in items:
        if shown >= SLACK_MAX_HOSTS:
            break
        examples = info["examples"]
        ex_str = ", ".join(examples) if examples else ""
        if ex_str:
            lines.append(f"• *{host}* — {info['count']} hits (e.g. {ex_str})")
        else:
            lines.append(f"• *{host}* — {info['count']} hits")
        shown += 1

    if unique_hosts > shown:
        lines.append(f"…and {unique_hosts - shown} more hosts.")
    return "\n".join(lines)


# ----------------------
# Notifications
# ----------------------
def notify_slack(hits: List[Dict[str, Any]]) -> None:
    if not SLACK_WEBHOOK:
        return
    if not hits and SLACK_SUPPRESS_EMPTY:
        return
    try:
        if SLACK_SUMMARY_ONLY:
            text = format_compact_slack(hits, URL or "")
        else:
            hostname = socket.gethostname()
            text = (
            ":rotating_light: Oh noes, we might be under attack soon! :rotating_light:\n\n"
        f"*{SLACK_TITLE}:* {len(hits)} new match(es) on `{URL}`\n"
        f"_host: {hostname}_\n\n"
        f"{format_hits(hits)}"
    )
        requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=15).raise_for_status()
    except Exception as e:
        print(f"Slack notify failed: {e}", file=sys.stderr)


def notify_email(hits: List[Dict[str, Any]]) -> None:
    if not (SMTP_HOST and EMAIL_FROM and EMAIL_TO):
        return
    from email.message import EmailMessage
    import smtplib

    subject = f"[watcher] {len(hits)} new match(es)"
    body = (
        f"{len(hits)} new match(es) found while checking {URL}\n\n"
        f"Monitored hosts: {', '.join(MONITORED_HOSTS)}\n\n"
        f"{format_hits(hits)}\n"
    )
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        print(f"Email notify failed: {e}", file=sys.stderr)


# ----------------------
# Main
# ----------------------
def main():
    if not MONITORED_HOSTS:
        print("ERROR: Set MONITORED_HOSTS (e.g. MONITORED_HOSTS='op.fi,kela.fi')", file=sys.stderr)
        sys.exit(2)

    state = load_state()
    seen = state.setdefault("seen_request_ids", {})

    targets = fetch_targets(URL)
    hits = []

    for t in targets:
        if not isinstance(t, dict):
            continue
        host = t.get("host")
        rid = t.get("request_id") or f"{host}:{t.get('path','')}:{t.get('type','')}:{t.get('method','')}"
        if host and host_matches(MONITORED_HOSTS, host):
            if rid not in seen:
                hits.append(t)
                seen[rid] = True

    if hits:
        notify_slack(hits)
        notify_email(hits)
        print(f"Found {len(hits)} new matches.")
        save_state(state)
    else:
        print("No new matches.")
        if not SLACK_SUPPRESS_EMPTY:
            notify_slack([])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
