#!/usr/bin/env python3
"""hermes-grokbot-bridge — let a Hermes agent task a Grok Bot with no open ports.

    Hermes agent ──► this bridge ──HTTPS POST (routine webhook)──► Grok Bot routine
         ▲                                                              │
         └──── bridge reads your mailbox over IMAP (read-only) ◄── Bot emails the result

Downlink: one outbound HTTPS POST to a Grok Bot routine's webhook trigger
          (Authorization: Bearer <key>, the documented Grok Bot form), or a Standard-Webhooks
          signed POST (the Grok automations form).
Uplink:   the Bot emails your agent's mailbox with "[A2A:<task_id>]" in the subject and the
          one-time reply_token in the body. The bridge accepts a reply only if the From address,
          a DKIM pass for the Bot's mail domain stamped by YOUR mail provider, the open task id
          and the token all check out.

Two ways to run it (same task store, same checks):
  serve   A2A JSON-RPC server on 127.0.0.1 for a local Hermes install (a2a_call / a2a_agents).
  send / check / list / cancel
          plain CLI for hosted Hermes or any agent that has a terminal but cannot reach a
          loopback daemon. No background process needed.

Tasking is one-way. Results are untrusted research text. Stdlib only, Python 3.9+.
Config: one JSON file (chmod 600), path from $BRIDGE_CONFIG or
~/.config/hermes-grokbot-bridge/bridge.json. See README.md.
"""
from __future__ import annotations

import argparse
import base64
import email
import email.policy
import email.utils
import hashlib
import hmac
import imaplib
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
HOST = "127.0.0.1"  # loopback only, not configurable on purpose
CONFIG_PATH = os.environ.get(
    "BRIDGE_CONFIG", os.path.expanduser("~/.config/hermes-grokbot-bridge/bridge.json"))
MAX_RESULT_CHARS = 200_000

# Mail-provider presets. authserv_id = the first token of the Authentication-Results (A-R)
# header YOUR provider stamps. A sender can put a fake A-R header in its own message, so the
# bridge must only read the one your provider added. Providers differ in where they put it:
#   ar_trust="above_border": trust matching A-R headers above the border hop, i.e. the first
#       Received header whose "from" host is not in internal_received (Fastmail: its A-R
#       headers sit above that line and may be split across several headers).
#   ar_trust="first": trust only the topmost matching A-R header (Gmail: one A-R header,
#       placed just below the border Received/Received-SPF lines but above every header
#       that came with the message).
# Check your own provider with `grokbot_bridge.py verify-mail <saved .eml>` before relying on it.
PRESETS = {
    "fastmail": {"imap_host": "imap.fastmail.com", "imap_port": 993,
                 "authserv_id": "messagingengine.com", "ar_trust": "above_border",
                 "internal_received": r"(messagingengine\.com|\.internal|^phl-|^mailmx|^localhost)"},
    "gmail": {"imap_host": "imap.gmail.com", "imap_port": 993,
              "authserv_id": "mx.google.com", "ar_trust": "first",
              "internal_received": r"(\.google\.com\.?$|^localhost)"},
}

W, C, F, X, IR = ("TASK_STATE_WORKING", "TASK_STATE_COMPLETED", "TASK_STATE_FAILED",
                  "TASK_STATE_CANCELED", "TASK_STATE_INPUT_REQUIRED")
TERMINAL = {C, F, X}
OPEN = (W, IR)

_lock = threading.Lock()


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- config
class Config:
    def __init__(self, d: dict):
        self.raw = d
        self.peer = d.get("peer_name", "grokbot")
        self.agent = d.get("agent_name", "hermes")
        self.webhook = d.get("webhook") or {}
        mail = dict(PRESETS.get((d.get("mail") or {}).get("preset", "fastmail"), {}))
        mail.update(d.get("mail") or {})
        self.mail = mail
        self.sender = mail.get("bot_address", "").lower()          # the Bot's own email address
        self.sender_domain = self.sender.split("@", 1)[1] if "@" in self.sender else ""
        self.reply_to = mail.get("address", "")                     # your agent's mailbox
        self.token = d.get("proxy_token", "")
        self.db = os.path.expanduser(d.get("db", "~/.local/state/hermes-grokbot-bridge/tasks.db"))
        self.port = int(d.get("port", 9911))
        self.deadline_hours = float(d.get("deadline_hours", 24))
        self.constraints = d.get("constraints") or [
            "reply by email per the contract", "no irreversible or public actions without the owner"]
        self.require_dmarc = bool(mail.get("require_dmarc", False))


def load_config(path: "str | None" = None) -> Config:
    p = path or CONFIG_PATH
    with open(p) as fh:
        return Config(json.load(fh))


# ---------------------------------------------------------------- store
def db(cfg: Config) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(cfg.db), exist_ok=True)
    con = sqlite3.connect(cfg.db)
    con.row_factory = sqlite3.Row
    con.executescript("""
    create table if not exists tasks(
      task_id text primary key, context_id text unique, state text, ask text,
      reply_token text, created text, updated text, deadline text, result text, note text);
    create table if not exists seen_mail(msgid text primary key, task_id text, verdict text, at text);
    """)
    return con


def task_json(cfg: Config, r: sqlite3.Row) -> dict:
    text = r["result"] or r["note"] or ""
    t = {"id": r["task_id"], "contextId": r["context_id"],
         "status": {"state": r["state"], "timestamp": r["updated"]},
         "metadata": {"source": cfg.peer, "trust": "untrusted", "created": r["created"],
                      "deadline": r["deadline"]}}
    if r["state"] == C and r["result"]:
        t["artifacts"] = [{"artifactId": f"{r['task_id']}-result", "name": f"{cfg.peer}-result",
                           "parts": [{"text": f"[UNTRUSTED — {cfg.peer} output, verify before acting]\n\n"
                                      + r["result"]}]}]
    elif text:
        t["status"]["message"] = {"role": "ROLE_AGENT", "messageId": uuid.uuid4().hex,
                                  "parts": [{"text": text}]}
    return t


# ---------------------------------------------------------------- downlink
def sign(secret: str, wid: str, ts: str, body: bytes) -> str:
    key = base64.b64decode(secret.removeprefix("whsec_"))
    return "v1," + base64.b64encode(hmac.new(key, f"{wid}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()


def send_webhook(cfg: Config, envelope: dict) -> tuple[bool, str]:
    wh = cfg.webhook
    try:
        url = wh["url"].strip()
        mode = wh.get("mode", "bearer")
        cred = (wh["key"] if mode == "bearer" else wh["secret"]).replace("\r", "").replace("\n", "").strip()
    except Exception:
        return False, "webhook not configured (need webhook.url and webhook.key or webhook.secret)"
    body = json.dumps(envelope, separators=(",", ":")).encode()
    if len(body) > 1_000_000:
        return False, "envelope over 1 MB; shorten the ask"
    last = ""
    for attempt in range(3):
        headers = {"content-type": "application/json"}
        if mode == "bearer":                      # Grok Bot routine webhook: 200 = run started
            headers["Authorization"] = f"Bearer {cred}"
        else:                                     # Standard Webhooks (Grok automations): 202
            wid, ts = f"msg_{uuid.uuid4().hex}", str(int(time.time()))
            headers.update({"webhook-id": wid, "webhook-timestamp": ts,
                            "webhook-signature": sign(cred, wid, ts, body)})
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.status in (200, 202):
                    return True, f"webhook accepted ({r.status})"
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in (429, 503):
                break
        except Exception as e:  # network
            last = type(e).__name__
        time.sleep(2 ** attempt)
    return False, f"webhook failed: {last}"


# ---------------------------------------------------------------- uplink
# The tag before the colon is cosmetic ([A2A:...], [GM:...]); the task id, the one-time token and the
# DKIM-checked sender are what authenticate a reply.
SUBJ_RE = re.compile(r"\[[A-Za-z0-9_-]{1,12}:(a2a-\d{8}-[0-9a-f]{6})\]")
TOKEN_RE = re.compile(r"^\s*reply_token:\s*([0-9a-f]{32})\s*$", re.M)
STATUS_RE = re.compile(r"^\s*status:\s*(done|failed|input-required)\s*$", re.M)
DKIM_RE = re.compile(r"dkim=pass[^;]*?header\.(?:d=|i=@?)([a-z0-9.-]+)")


def auth_ok(cfg: Config, msg) -> tuple[bool, str]:
    """From must be the Bot's address, and an Authentication-Results header stamped by YOUR
    provider, above the border Received hop, must show a DKIM pass aligned to the Bot's domain."""
    frm = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    if not cfg.sender or frm != cfg.sender:
        return False, f"from={frm}"
    authserv = cfg.mail["authserv_id"].lower()
    mode = cfg.mail.get("ar_trust", "above_border")
    internal = re.compile(cfg.mail.get("internal_received", r"^$"))
    ars = []
    for k, v in msg.items():
        lk = k.lower()
        if lk == "received" and mode == "above_border":
            m = re.match(r"\s*from\s+(\S+)", str(v))
            host = (m.group(1) if m else "").lower()
            if host and not internal.search(host):
                break                                        # border hop: stop trusting
        elif lk == "authentication-results":
            serv = str(v).split(";")[0].strip().lower()
            if serv == authserv or serv.endswith("." + authserv):
                ars.append(re.sub(r"\s+", " ", str(v)).lower())
                if mode == "first":
                    break                                    # only the provider's own, topmost
    if not ars:
        return False, f"no {authserv} Authentication-Results in the trusted position"
    ar = " ".join(ars)
    sd = cfg.sender_domain
    if not any(d == sd or d.endswith("." + sd) or sd.endswith("." + d) for d in DKIM_RE.findall(ar)):
        return False, "no aligned dkim pass"
    if re.search(r"dmarc=(fail|quarantine|reject)", ar):
        return False, "dmarc fail"
    if cfg.require_dmarc and "dmarc=pass" not in ar:
        return False, "dmarc not pass"
    return True, "ok"


def body_text(msg) -> str:
    part = msg.get_body(preferencelist=("plain",)) or msg.get_body(preferencelist=("html",))
    if not part:
        return ""
    txt = part.get_content()
    if part.get_content_type() == "text/html":
        txt = re.sub(r"<[^>]+>", "", txt)
    return txt.replace("\r\n", "\n")


def apply_reply(cfg: Config, con: sqlite3.Connection, msg) -> str:
    """Match one parsed email against open tasks. Returns a verdict string."""
    mid = msg.get("Message-ID", "") or hashlib.sha256(bytes(msg)).hexdigest()
    if con.execute("select 1 from seen_mail where msgid=?", (mid,)).fetchone():
        return "dup"
    verdict, tid = "ignored", None
    ok, why = auth_ok(cfg, msg)
    m = SUBJ_RE.search(msg.get("Subject", ""))
    if not ok:
        verdict = f"auth-fail:{why}"
    elif not m:
        verdict = "no-task-id"
    else:
        tid = m.group(1)
        row = con.execute("select * from tasks where task_id=?", (tid,)).fetchone()
        text = body_text(msg)
        tok, st = TOKEN_RE.search(text), STATUS_RE.search(text)
        if not row:
            verdict = "unknown-task"
        elif row["state"] in TERMINAL:
            verdict = "task-closed"
        elif not tok or not hmac.compare_digest(tok.group(1), row["reply_token"] or ""):
            verdict = "bad-token"
        else:
            result = text.split("\n---\n", 1)[1].strip() if "\n---\n" in text else text
            result = result[:MAX_RESULT_CHARS]
            status = st.group(1) if st else "done"
            state = {"done": C, "failed": F, "input-required": IR}[status]
            con.execute("update tasks set state=?, result=?, note=?, updated=?, reply_token=? where task_id=?",
                        (state, result if state == C else None, None if state == C else result,
                         now_iso(), None, tid))  # token is one-time
            verdict = f"applied:{status}"
    con.execute("insert into seen_mail values(?,?,?,?)", (mid, tid, verdict, now_iso()))
    con.commit()
    return verdict


def sweep_deadlines(con: sqlite3.Connection) -> int:
    n = con.execute("update tasks set state=?, reply_token=null, note=?, updated=? "
                    "where state in (?,?) and deadline is not null and deadline < ?",
                    (F, "deadline passed with no verified reply", now_iso(), W, IR, now_iso())).rowcount
    con.commit()
    return n


def poll_mail(cfg: Config, con: sqlite3.Connection) -> list[str]:
    """On-demand IMAP check; read-only (EXAMINE + BODY.PEEK, never flags/moves/deletes)."""
    sweep_deadlines(con)
    if not con.execute("select 1 from tasks where state in (?,?)", OPEN).fetchone():
        return []
    im = None
    try:
        im = imaplib.IMAP4_SSL(cfg.mail["imap_host"], int(cfg.mail.get("imap_port", 993)), timeout=30)
        im.login(cfg.mail["address"], cfg.mail["password"])
        im.select(cfg.mail.get("folder", "INBOX"), readonly=True)
        oldest = con.execute("select min(created) from tasks where state in (?,?)", OPEN).fetchone()[0]
        # IMAP SINCE is a date in the server's own time zone, not UTC: back off a day.
        since = (datetime.strptime(oldest[:10], "%Y-%m-%d") - timedelta(days=1)).strftime("%d-%b-%Y")
        _, data = im.uid("search", None, "FROM", f'"{cfg.sender}"', "SINCE", since)
        out = []
        for uid in (data[0] or b"").split():
            _, d = im.uid("fetch", uid, "(BODY.PEEK[])")
            raw = next((x[1] for x in d if isinstance(x, tuple)), None)
            if raw:
                out.append(apply_reply(cfg, con, email.message_from_bytes(raw, policy=email.policy.default)))
        return out
    except Exception as e:
        return [f"imap-error:{type(e).__name__}"]
    finally:
        if im is not None:
            try:
                im.logout()
            except Exception:
                pass


# ---------------------------------------------------------------- task ops
def dispatch(cfg: Config, con, tid: str, ask: str, tok: str, follow_up: bool = False):
    row = con.execute("select deadline from tasks where task_id=?", (tid,)).fetchone()
    env = {"v": 1, "task_id": tid, "reply_token": tok, "from": cfg.agent, "ask": ask,
           "constraints": cfg.constraints, "deadline": row["deadline"], "reply_to": cfg.reply_to,
           "reply_subject": f"[A2A:{tid}] <short title>", "follow_up": follow_up}
    ok, info = send_webhook(cfg, env)
    con.execute("update tasks set state=?, note=?, updated=? where task_id=?",
                (W if ok else F, f"Dispatched to {cfg.peer} ({info}); not answered yet. "
                 "Ask again with the same context_id." if ok else info, now_iso(), tid))
    con.commit()


def new_task(cfg: Config, con, context_id: str, ask: str) -> sqlite3.Row:
    tid = f"a2a-{now():%Y%m%d}-{secrets.token_hex(3)}"
    tok = secrets.token_hex(16)
    deadline = (now() + timedelta(hours=cfg.deadline_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    con.execute("insert into tasks values(?,?,?,?,?,?,?,?,?,?)",
                (tid, context_id, W, ask, tok, now_iso(), now_iso(), deadline, None, None))
    con.commit()
    dispatch(cfg, con, tid, ask, tok)
    return con.execute("select * from tasks where task_id=?", (tid,)).fetchone()


def send_or_poll(cfg: Config, text: str, ctx: str = "") -> dict:
    ctx = ctx or f"ctx-{uuid.uuid4().hex[:16]}"
    with _lock:
        con = db(cfg)
        row = con.execute("select * from tasks where context_id=?", (ctx,)).fetchone()
        if row is None:
            if not text.strip():
                raise ValueError("empty message")
            row = new_task(cfg, con, ctx, text)
        else:
            poll_mail(cfg, con)
            row = con.execute("select * from tasks where context_id=?", (ctx,)).fetchone()
            if row["state"] == IR and text and not re.fullmatch(r"(?i)\s*(status|check|\?)\s*", text):
                tok = secrets.token_hex(16)
                con.execute("update tasks set reply_token=?, ask=ask||?, updated=? where task_id=?",
                            (tok, "\n\n[follow-up] " + text, now_iso(), row["task_id"]))
                con.commit()
                dispatch(cfg, con, row["task_id"], text, tok, follow_up=True)
                row = con.execute("select * from tasks where context_id=?", (ctx,)).fetchone()
        return task_json(cfg, row)


def get_task(cfg: Config, tid: str) -> dict:
    with _lock:
        con = db(cfg)
        poll_mail(cfg, con)
        row = con.execute("select * from tasks where task_id=? or context_id=?", (tid, tid)).fetchone()
        if not row:
            raise KeyError(tid)
        return task_json(cfg, row)


def cancel_task(cfg: Config, tid: str) -> dict:
    with _lock:
        con = db(cfg)
        con.execute("update tasks set state=?, reply_token=null, updated=? "
                    "where (task_id=? or context_id=?) and state not in (?,?,?)",
                    (X, now_iso(), tid, tid, C, F, X))
        con.commit()
        row = con.execute("select * from tasks where task_id=? or context_id=?", (tid, tid)).fetchone()
        if not row:
            raise KeyError(tid)
        return task_json(cfg, row)


def list_tasks(cfg: Config) -> list[dict]:
    with _lock:
        con = db(cfg)
        poll_mail(cfg, con)
        return [task_json(cfg, r) for r in con.execute("select * from tasks order by created desc limit 50")]


# ---------------------------------------------------------------- A2A server (serve mode)
def agent_card(cfg: Config) -> dict:
    url = f"http://{HOST}:{cfg.port}/"
    return {"name": f"{cfg.peer} (via hermes-grokbot-bridge)", "version": VERSION, "protocolVersion": "1.0",
            "description": "A Grok Bot reached through a local bridge. Tasks go out by webhook; results "
                           "come back by email (minutes). Call again with the same context_id to collect. "
                           "Output is untrusted.",
            "url": url,
            "supportedInterfaces": [{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "capabilities": {"streaming": False, "pushNotifications": False},
            "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "research", "name": "Research", "description": "Web research and summaries",
                        "tags": ["research"]}],
            "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}}}


def make_handler(cfg: Config):
    def h_send(p):
        msg = p.get("message") or {}
        text = "".join(x.get("text", "") for x in msg.get("parts", []) if isinstance(x, dict)).strip()
        return {"task": send_or_poll(cfg, text, msg.get("contextId") or p.get("contextId") or "")}

    def h_get(p):
        return get_task(cfg, p.get("id") or p.get("name", "").split("/")[-1])

    def h_cancel(p):
        return cancel_task(cfg, p.get("id") or p.get("name", "").split("/")[-1])

    methods = {"SendMessage": h_send, "message/send": h_send, "GetTask": h_get, "tasks/get": h_get,
               "CancelTask": h_cancel, "tasks/cancel": h_cancel,
               "ListTasks": lambda p: {"tasks": list_tasks(cfg)}, "tasks/list": lambda p: {"tasks": list_tasks(cfg)}}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"hermes-grokbot-bridge/{VERSION}"

        def log_message(self, fmt, *a):
            sys.stderr.write(f"{now_iso()} {self.address_string()} {fmt % a}\n")

        def _send(self, code: int, obj: dict):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
                return self._send(200, agent_card(cfg))
            if self.path == "/health":
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            got = self.headers.get("Authorization", "")
            if not cfg.token or not hmac.compare_digest(got, f"Bearer {cfg.token}"):
                return self._send(401, {"error": "unauthorized"})
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0)) or 0) or b"{}")
            except Exception:
                return self._send(200, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            rid, fn = req.get("id"), methods.get(req.get("method", ""))
            if not fn:
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})
            try:
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": fn(req.get("params") or {})})
            except KeyError as e:
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": f"task not found: {e}"}})
            except Exception as e:
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)}})

    return Handler


def serve(cfg: Config):
    if not cfg.token or len(cfg.token) < 24:
        sys.exit("serve mode needs proxy_token (24+ chars) in the config")
    db(cfg).close()
    srv = ThreadingHTTPServer((HOST, cfg.port), make_handler(cfg))
    sys.stderr.write(f"hermes-grokbot-bridge {VERSION} on http://{HOST}:{cfg.port}/ db={cfg.db}\n")
    srv.serve_forever()


# ---------------------------------------------------------------- CLI
def _print_task(t: dict):
    st = t["status"]["state"].replace("TASK_STATE_", "").lower()
    print(f"task {t['id']}  context {t['contextId']}  state {st}")
    if t.get("artifacts"):
        print(t["artifacts"][0]["parts"][0]["text"])
    elif t["status"].get("message"):
        print(t["status"]["message"]["parts"][0]["text"])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="grokbot_bridge.py", description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None, help="config JSON (default $BRIDGE_CONFIG or ~/.config/...)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="A2A JSON-RPC server on 127.0.0.1 (local Hermes)")
    s = sub.add_parser("send", help="dispatch a task; prints task id and context id")
    s.add_argument("text", nargs="?", default="")
    s.add_argument("--file", help="read the ask from a file (recommended for long briefs)")
    c = sub.add_parser("check", help="poll mail once and print the task's state/result")
    c.add_argument("id", help="task id or context id")
    x = sub.add_parser("cancel", help="cancel an open task")
    x.add_argument("id")
    sub.add_parser("list", help="poll mail once and list recent tasks")
    v = sub.add_parser("verify-mail", help="run the sender checks on a saved raw message (.eml)")
    v.add_argument("eml")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    if a.cmd == "verify-mail":
        with open(a.eml, "rb") as fh:
            msg = email.message_from_bytes(fh.read(), policy=email.policy.default)
        ok, why = auth_ok(cfg, msg)
        print(("PASS" if ok else "FAIL") + f": {why}")
        return 0 if ok else 1
    if a.cmd == "serve":
        return serve(cfg)
    if a.cmd == "send":
        text = open(a.file).read() if a.file else a.text
        _print_task(send_or_poll(cfg, text))
    elif a.cmd == "check":
        _print_task(get_task(cfg, a.id))
    elif a.cmd == "cancel":
        _print_task(cancel_task(cfg, a.id))
    elif a.cmd == "list":
        for t in list_tasks(cfg):
            print(f"{t['id']}  {t['status']['state'].replace('TASK_STATE_', '').lower():16} {t['metadata']['created']}")


if __name__ == "__main__":
    main()
