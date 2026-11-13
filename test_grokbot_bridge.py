"""Tests for hermes-grokbot-bridge. Run: python3 -m unittest -v test_grokbot_bridge
Hermetic: a mock webhook receiver, synthetic mail headers, no network, no real mailbox."""
import base64, email, email.policy, hashlib, hmac, io, json, os, sqlite3, sys, tempfile, threading, time
import unittest, urllib.error, urllib.request
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grokbot_bridge as b  # noqa: E402

TMP = tempfile.mkdtemp()
SECRET = "whsec_" + base64.b64encode(b"k" * 32).decode()
BOT = "mybot@mail.grokbot.com"
RECEIVED = []


class Hook(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        if self.headers.get("Authorization"):
            ok = self.headers["Authorization"] == "Bearer testkey"
            RECEIVED.append((ok, json.loads(body)))
            self.send_response(200 if ok else 401); self.end_headers(); return
        wid, ts, sig = self.headers["webhook-id"], self.headers["webhook-timestamp"], self.headers["webhook-signature"]
        key = base64.b64decode(SECRET.removeprefix("whsec_"))
        want = "v1," + base64.b64encode(hmac.new(key, f"{wid}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
        ok = hmac.compare_digest(want, sig) and abs(time.time() - int(ts)) < 300
        RECEIVED.append((ok, json.loads(body)))
        self.send_response(202 if ok else 401); self.end_headers()


def make_cfg(hook_port, preset="fastmail", mode="bearer", **extra):
    wh = {"mode": mode, "url": f"http://127.0.0.1:{hook_port}/"}
    wh.update({"key": "testkey\n"} if mode == "bearer" else {"secret": SECRET})
    d = {"peer_name": "grokbot", "agent_name": "tester", "webhook": wh,
         "mail": {"preset": preset, "address": "agent@example.com", "password": "x", "bot_address": BOT,
                  "imap_host": "127.0.0.1", "imap_port": 9},   # closed port: never touch a real server
         "proxy_token": "t" * 32, "db": f"{TMP}/{preset}-{mode}.db", "port": 19912}
    d.update(extra)
    return b.Config(d)


def fastmail_msg(frm, subject, body, forged_only=False, dkim_d="mail.grokbot.com"):
    top = "" if forged_only else (
        f"Authentication-Results: phl-mx-02.messagingengine.com; dkim=pass (2048-bit rsa key sha256) "
        f"header.d={dkim_d} header.i=@{dkim_d}\n")
    forged = ("Authentication-Results: phl-mx-02.messagingengine.com; dkim=pass header.d=mail.grokbot.com; dmarc=pass\n"
              if forged_only else "")
    raw = (f"Received: from phl-mx-02 ([10.202.2.201]) by phl-compute-06.internal (LMTPProxy)\n{top}"
           "Received: from a9-33.smtp-out.amazonses.com (a9-33.smtp-out.amazonses.com [54.240.9.33]) by phl-mx-02.messagingengine.com\n"
           f"{forged}From: Bot <{frm}>\nTo: agent@example.com\nSubject: {subject}\n"
           f"Message-ID: <{os.urandom(6).hex()}@x>\nContent-Type: text/plain; charset=utf-8\n\n{body}")
    return email.message_from_string(raw, policy=email.policy.default)


def gmail_msg(frm, subject, body, real_dkim="pass", dkim_d="mail.grokbot.com", forged_below=False):
    """Modelled on Gmail's layout: border Received, Received-SPF, then Gmail's single A-R header,
    then the headers that came with the message (where a forged A-R would sit)."""
    forged = ("Authentication-Results: mx.google.com; dkim=pass header.i=@mail.grokbot.com header.s=x; "
              "dmarc=pass header.from=mail.grokbot.com\n" if forged_below else "")
    raw = ("Delivered-To: agent@example.com\n"
           "Received: by 2002:a05:6a10:aa:b0:5a1:1 with SMTP id x;\n        Fri, 13 Nov 2026 10:00:00 -0800 (PST)\n"
           "ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@mail.grokbot.com\n"
           "Return-Path: <010001@amazonses.com>\n"
           "Received: from a9-33.smtp-out.amazonses.com (a9-33.smtp-out.amazonses.com. [54.240.9.33])\n"
           "        by mx.google.com with ESMTPS id y;\n        Fri, 13 Nov 2026 10:00:00 -0800 (PST)\n"
           "Received-SPF: pass (google.com: domain of x@amazonses.com designates 54.240.9.33 as permitted sender)\n"
           f"Authentication-Results: mx.google.com;\n       dkim={real_dkim} header.i=@{dkim_d} header.s=sel header.b=abc;\n"
           "       dkim=pass header.i=@amazonses.com header.s=ug7 header.b=def;\n"
           "       spf=pass smtp.mailfrom=x@amazonses.com;\n"
           "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.grokbot.com\n"
           f"{forged}From: Bot <{frm}>\nTo: agent@example.com\nSubject: {subject}\n"
           f"Message-ID: <{os.urandom(6).hex()}@x>\nContent-Type: text/plain; charset=utf-8\n\n{body}")
    return email.message_from_string(raw, policy=email.policy.default)


def rpc(port, method, params, token="t" * 32):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", method="POST",
                                 data=json.dumps({"jsonrpc": "2.0", "id": "1", "method": method, "params": params}).encode(),
                                 headers={"content-type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hook = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
        threading.Thread(target=hook.serve_forever, daemon=True).start()
        cls.hp = hook.server_address[1]
        cls.cfg = make_cfg(cls.hp)
        srv = ThreadingHTTPServer((b.HOST, cls.cfg.port), b.make_handler(cls.cfg))
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def send(self, ctx, text):
        return rpc(self.cfg.port, "SendMessage", {"message": {"role": "ROLE_USER", "contextId": ctx, "messageId": "m",
                                                              "parts": [{"text": text}]}})["result"]["task"]

    def test_card_and_auth(self):
        card = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.cfg.port}/.well-known/agent-card.json").read())
        self.assertIn("grokbot", card["name"])
        with self.assertRaises(urllib.error.HTTPError) as e:
            rpc(self.cfg.port, "ListTasks", {}, token="wrong")
        self.assertEqual(e.exception.code, 401)

    def test_bind_is_loopback(self):
        self.assertEqual(b.HOST, "127.0.0.1")

    def test_round_trip_fastmail(self):
        t = self.send("ctx-rt", "echo pineapple")
        self.assertEqual(t["status"]["state"], b.W)
        ok, env = RECEIVED[-1]
        self.assertTrue(ok, "bearer must match (trailing newline stripped)")
        self.assertEqual(env["task_id"], t["id"]); self.assertEqual(env["from"], "tester")
        self.assertTrue(env["deadline"].endswith("Z"))
        tok, tid, cfg, con = env["reply_token"], t["id"], self.cfg, b.db(self.cfg)
        self.assertEqual(b.apply_reply(cfg, con, fastmail_msg(BOT, f"[A2A:{tid}] x", "reply_token: " + "0" * 32 + "\n---\nfake")), "bad-token")
        self.assertTrue(b.apply_reply(cfg, con, fastmail_msg("evil@mail.grokbot.com", f"[A2A:{tid}] x", f"reply_token: {tok}\n---\nf")).startswith("auth-fail:from"))
        self.assertTrue(b.apply_reply(cfg, con, fastmail_msg(BOT, f"[A2A:{tid}] x", f"reply_token: {tok}\n---\nf", forged_only=True)).startswith("auth-fail"))
        self.assertTrue(b.apply_reply(cfg, con, fastmail_msg(BOT, f"[A2A:{tid}] x", f"reply_token: {tok}\n---\nf", dkim_d="evil.com")).startswith("auth-fail"))
        good = fastmail_msg(BOT, f"[A2A:{tid}] pineapple", f"reply_token: {tok}\nstatus: done\n---\npineapple 2026-11-13")
        self.assertEqual(b.apply_reply(cfg, con, good), "applied:done")
        self.assertEqual(b.apply_reply(cfg, con, good), "dup")
        self.assertEqual(b.apply_reply(cfg, con, fastmail_msg(BOT, f"[A2A:{tid}] again", f"reply_token: {tok}\n---\nx")), "task-closed")
        done = self.send("ctx-rt", "status")
        self.assertEqual(done["status"]["state"], b.C)
        txt = done["artifacts"][0]["parts"][0]["text"]
        self.assertIn("UNTRUSTED", txt); self.assertIn("pineapple 2026-11-13", txt)

    def test_gmail_preset(self):
        cfg = make_cfg(self.hp, preset="gmail")
        self.assertEqual(b.PRESETS["gmail"]["imap_host"], "imap.gmail.com")
        self.assertEqual(cfg.mail["authserv_id"], "mx.google.com")
        self.assertEqual(b.auth_ok(cfg, gmail_msg(BOT, "s", "b")), (True, "ok"))
        # real Gmail verdict says fail; a forged pass placed below it must not win
        self.assertFalse(b.auth_ok(cfg, gmail_msg(BOT, "s", "b", real_dkim="fail", forged_below=True))[0])
        # only the ESP's own domain signed (no Bot-domain DKIM) -> reject
        self.assertFalse(b.auth_ok(cfg, gmail_msg(BOT, "s", "b", dkim_d="other.example"))[0])
        self.assertFalse(b.auth_ok(cfg, gmail_msg("x@evil.com", "s", "b"))[0])
        # the Fastmail rule would wrongly reject Gmail's layout: presets are not interchangeable
        self.assertFalse(b.auth_ok(make_cfg(self.hp), gmail_msg(BOT, "s", "b"))[0])

    def test_input_required_followup(self):
        t = self.send("ctx-ir", "research X")
        tok = RECEIVED[-1][1]["reply_token"]
        con = b.db(self.cfg)
        self.assertEqual(b.apply_reply(self.cfg, con, fastmail_msg(BOT, f"[A2A:{t['id']}] q", f"reply_token: {tok}\nstatus: input-required\n---\nWhich X?")), "applied:input-required")
        n = len(RECEIVED)
        t3 = self.send("ctx-ir", "The X in Twitter")
        self.assertEqual(len(RECEIVED), n + 1); ok, env = RECEIVED[-1]
        self.assertTrue(ok and env["follow_up"] and env["task_id"] == t["id"] and env["reply_token"] != tok)
        self.assertEqual(t3["status"]["state"], b.W)

    def test_poll_reports_imap_error_not_crash(self):
        con = b.db(self.cfg)
        b.send_or_poll(self.cfg, "needs a poll", "ctx-imap")
        self.assertEqual(b.poll_mail(self.cfg, con), ["imap-error:ConnectionRefusedError"])

    def test_deadline_sweep(self):
        cfg = make_cfg(self.hp, deadline_hours=-1, db=f"{TMP}/deadline.db")
        t = b.send_or_poll(cfg, "slow job")
        self.assertEqual(t["status"]["state"], b.W)
        con = b.db(cfg)
        self.assertEqual(b.sweep_deadlines(con), 1)
        row = con.execute("select state, reply_token, note from tasks where task_id=?", (t["id"],)).fetchone()
        self.assertEqual(row["state"], b.F); self.assertIsNone(row["reply_token"]); self.assertIn("deadline", row["note"])

    def test_standard_webhooks_mode(self):
        cfg = make_cfg(self.hp, mode="standard-webhooks")
        t = b.send_or_poll(cfg, "signed")
        self.assertEqual(t["status"]["state"], b.W); self.assertTrue(RECEIVED[-1][0])

    def test_webhook_missing_fails_task(self):
        cfg = make_cfg(self.hp, webhook={}, db=f"{TMP}/nowh.db")
        self.assertEqual(b.send_or_poll(cfg, "x")["status"]["state"], b.F)

    def test_cli_send_check_cancel_verify(self):
        cfgp = f"{TMP}/cli.json"
        with open(cfgp, "w") as fh: json.dump({"webhook": {"mode": "bearer", "url": f"http://127.0.0.1:{self.hp}/", "key": "testkey"},
                   "mail": {"preset": "gmail", "address": "a@example.com", "password": "x", "bot_address": BOT,
                            "imap_host": "127.0.0.1", "imap_port": 9},
                   "db": f"{TMP}/cli.db"}, fh)
        out = io.StringIO()
        with redirect_stdout(out):
            b.main(["--config", cfgp, "send", "hello from cli"])
        line = out.getvalue().split("\n")[0]
        self.assertIn("state working", line)
        tid = line.split()[1]
        out = io.StringIO()
        with redirect_stdout(out):
            b.main(["--config", cfgp, "cancel", tid])
        self.assertIn("state canceled", out.getvalue())
        eml = f"{TMP}/m.eml"
        with open(eml, "wb") as fh:
            fh.write(bytes(gmail_msg(BOT, "s", "b")))
        out = io.StringIO()
        with redirect_stdout(out):
            rc = b.main(["--config", cfgp, "verify-mail", eml])
        self.assertEqual(rc, 0); self.assertIn("PASS", out.getvalue())

    def test_hermes_client_parses_response(self):
        sys.path.insert(0, os.path.expanduser("~/.hermes/hermes-agent"))
        try:
            from plugins.platforms.a2a import tools as at
        except Exception as e:
            self.skipTest(f"hermes not importable: {e}")
        t = self.send("ctx-h", "hello")
        self.assertIn("Dispatched to grokbot", at._reply_text_from_result({"task": t}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
