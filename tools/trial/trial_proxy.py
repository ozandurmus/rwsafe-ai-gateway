#!/usr/bin/env python3
"""The local trial's stand-in for the corporate proxy: a chat page whose prompts go through the real ICAP engine.

On every send it builds the HTTP request an AI vendor would receive after the proxy decrypted it (the OpenAI chat
completions API: ``POST https://api.openai.com/v1/chat/completions`` with its JSON shape; the openai platform row of
policy/registry-seed.yaml), sends it to the ICAP engine as REQMOD with synthetic identity headers, and acts on the answer
the way the proxy would:

    204 No Content          forward the original body to the fake provider (mock_ai.py)
    200 with a request      forward the rewritten body (the engine replaced sensitive spans with class tokens)
    200 with a response     forward nothing; show the block answer the engine returned
    anything else / error   forward nothing (fail closed)

The page shows what was typed, the decision and what reached the provider side by side. Every address this program
connects to or listens on is 127.0.0.1, checked in code before each connection (``require_loopback``). Example prompts
carry synthetic identifiers generated at start (a checksum-valid identity number, a valid TR account number, a
secret-shaped key); none is written to disk.

Usage:
    python3 tools/trial/trial_proxy.py --mock-port PORT [--port 8765] [--icap-port 1344]
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import random
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "icap"))
from replay import Reader, chunk  # noqa: E402  (the repository's ICAP client, tools/icap/replay.py)

LOOPBACK = "127.0.0.1"
VENDOR_HOST = "api.openai.com"
VENDOR_PATH = "/v1/chat/completions"
VENDOR_MODEL = "gpt-4o-mini"
ICAP_SERVICE = "reqmod-ai"
MAX_PROMPT = 16 * 1024
TIMEOUT = 15

CLASS_NAMES = {
    "TCKN": "kimlik numarası",
    "TR_IBAN": "banka hesap numarası",
    "IBAN": "banka hesap numarası",
    "PAYMENT_CARD": "ödeme kartı numarası",
    "SECRET": "gizli anahtar veya parola",
}
REASON_NAMES = {
    "secret": "gizli anahtar veya parola",
    "customer_data": "müşteri verisi",
    "special_category": "özel nitelikli kişisel veri",
    "internal_identity": "kurum içi kimlik bilgisi",
}


class LoopbackOnly(Exception):
    """Raised before any connection to, or listening on, an address other than 127.0.0.1."""


def require_loopback(host: str) -> str:
    if host != LOOPBACK:
        raise LoopbackOnly(f"refusing a non-loopback address; the trial talks to {LOOPBACK} only")
    return host


# ---- synthetic values (built at runtime, never literal; AGENTS.md 4.5) ----

def synthetic_tckn(rng: random.Random) -> str:
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append(((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


def synthetic_tr_iban(rng: random.Random) -> str:
    bban = "".join(str(rng.randint(0, 9)) for _ in range(5)) + "0" + "".join(str(rng.randint(0, 9)) for _ in range(16))
    check = 98 - int(bban + "2927" + "00") % 97
    return "T" + "R" + f"{check:02d}" + bban


def synthetic_cloud_key(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "AK" + "IA" + "".join(rng.choice(alphabet) for _ in range(16))


def examples(rng: random.Random) -> list[dict]:
    return [
        {"label": "Sade bir soru",
         "prompt": "Merhaba, bana bahar üzerine kısa bir şiir yazar mısın?"},
        {"label": "Kimlik numarası içeren soru",
         "prompt": f"Müşterimiz {synthetic_tckn(rng)} kimlik numarasıyla kart ücretlerini soruyor, nasıl yanıtlayayım?"},
        {"label": "Banka hesap numarası içeren soru",
         "prompt": f"{synthetic_tr_iban(rng)} hesabına yapılan havale neden gecikmiş olabilir?"},
        {"label": "Gizli anahtar içeren soru",
         "prompt": f"Bu erişim anahtarıyla dağıtım neden başarısız oluyor: {synthetic_cloud_key(rng)}"},
    ]


# ---- the proxy step ----

def vendor_request(prompt: str, browser: bool) -> tuple[bytes, bytes]:
    """The decrypted HTTPS request as the proxy hands it to ICAP: absolute-form target, the vendor's JSON body."""
    body = json.dumps({"model": VENDOR_MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
                      ensure_ascii=False).encode("utf-8")
    accept = "text/html,application/xhtml+xml" if browser else "application/json"
    head = (f"POST https://{VENDOR_HOST}{VENDOR_PATH} HTTP/1.1\r\n"
            f"Host: {VENDOR_HOST}\r\n"
            "Content-Type: application/json\r\n"
            f"Accept: {accept}\r\n"
            "User-Agent: rwsafe-trial/1 (synthetic)\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode("latin-1"), body


def reqmod(icap_host: str, icap_port: int, user: str, head: bytes, body: bytes) -> tuple[int, str, bytes]:
    require_loopback(icap_host)
    claim = base64.b64encode(user.encode("utf-8")).decode("ascii")
    frame = (f"REQMOD icap://{icap_host}:{icap_port}/{ICAP_SERVICE} ICAP/1.0\r\n"
             f"Host: {icap_host}:{icap_port}\r\n"
             f"Encapsulated: req-hdr=0, req-body={len(head)}\r\n"
             "Allow: 204\r\n"
             f"X-Client-IP: {LOOPBACK}\r\n"
             f"X-Authenticated-User: {claim}\r\n\r\n").encode("latin-1") + head + chunk(body) + b"0\r\n\r\n"
    with socket.create_connection((icap_host, icap_port), timeout=TIMEOUT) as s:
        s.sendall(frame)
        return Reader(s).response()


def header(http_head: str, name: str) -> str | None:
    prefix = name.lower() + ":"
    for line in http_head.split("\r\n")[1:]:
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


class Trial:
    def __init__(self, icap_host: str, icap_port: int, mock_host: str, mock_port: int, user: str,
                 admin_url: str = "http://127.0.0.1:5173"):
        self.admin_url = admin_url.rstrip("/")
        self.icap_host = require_loopback(icap_host)
        self.icap_port = icap_port
        self.mock_host = require_loopback(mock_host)
        self.mock_port = mock_port
        self.user = user

    def forward(self, body: bytes) -> tuple[str, str]:
        """Sends the body to the fake provider; returns its reply text and the body it was given."""
        conn = http.client.HTTPConnection(require_loopback(self.mock_host), self.mock_port, timeout=TIMEOUT)
        try:
            conn.request("POST", VENDOR_PATH, body=body, headers={"Content-Type": "application/json"})
            answer = conn.getresponse()
            data = answer.read()
        finally:
            conn.close()
        try:
            reply = json.loads(data)["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            reply = f"(sağlayıcı yanıtı okunamadı, durum {answer.status})"
        return reply, body.decode("utf-8", "replace")

    def send(self, prompt: str, browser: bool = False) -> dict:
        head, body = vendor_request(prompt, browser)
        result = {
            "written": prompt,
            "request": {"method": "POST", "url": f"https://{VENDOR_HOST}{VENDOR_PATH}",
                        "body": body.decode("utf-8")},
            "decision": {}, "provider": {"reached": False, "body": None, "reply": None}, "blockPage": None,
        }
        try:
            status, http_head, out = reqmod(self.icap_host, self.icap_port, self.user, head, body)
        except (OSError, ValueError, ConnectionError) as e:
            result["decision"] = {"kind": "error", "title": "Karar alınamadı",
                                  "detail": "Denetim motoruna ulaşılamadı; istek sağlayıcıya gönderilmedi "
                                            f"({type(e).__name__}).", "icapStatus": None}
            return result
        decision = result["decision"]
        decision["icapStatus"] = status
        if status == 204 or (status == 200 and http_head.startswith("POST ") and out == body):
            decision.update(kind="allow", title="İzin verildi",
                            detail="Metinde hassas bilgi bulunmadı; istek değiştirilmeden gönderildi.")
            forwarded = body
        elif status == 200 and http_head.startswith("POST "):
            classes = sorted(set(re.findall(r"\[REDACTED:([A-Z_]+)\]", out.decode("utf-8", "replace"))))
            names = sorted({CLASS_NAMES.get(c, c) for c in classes})
            decision.update(kind="masked", title="Maskelendi", classes=classes,
                            detail=("Şu bilgiler maskelendi: " + ", ".join(names) + ".") if names
                            else "İstek denetim motorunca değiştirildi.")
            forwarded = out
        elif status == 200 and http_head.startswith("HTTP/"):
            reason = header(http_head, "X-RWSAFE-Reason")
            ref = header(http_head, "X-RWSAFE-Ref")
            reason_name = REASON_NAMES.get(reason or "", reason or "politika")
            decision.update(kind="blocked", title="Engellendi", reason=reason, ref=ref,
                            adminUrl=f"{self.admin_url}/traffic/{ref}" if ref else None,
                            detail=f"Gerekçe: {reason_name}. İstek sağlayıcıya gönderilmedi."
                                   + (f" Kayıt numarası: {ref}" if ref else ""))
            parts = http_head.split(" ", 2)
            result["blockPage"] = {"httpStatus": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                                   "contentType": header(http_head, "Content-Type") or "",
                                   "body": out.decode("utf-8", "replace")}
            return result
        else:
            decision.update(kind="error", title="Karar alınamadı",
                            detail=f"Denetim motoru beklenmeyen bir yanıt verdi (durum {status}); "
                                   "istek sağlayıcıya gönderilmedi.")
            return result
        try:
            reply, reached = self.forward(forwarded)
        except OSError as e:
            result["provider"] = {"reached": False, "body": None,
                                  "reply": f"Sahte sağlayıcıya ulaşılamadı ({type(e).__name__})."}
            return result
        result["provider"] = {"reached": True, "body": reached, "reply": reply}
        return result


# ---- the page ----

PAGE = """<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rwsafe yerel deneme</title>
<style>
:root { --bg:#f6f7f9; --card:#fff; --ink:#1d2330; --muted:#5b6475; --line:#d9dde5;
        --ok:#1f7a3a; --warn:#9a5b00; --bad:#b3261e; --accent:#2b5cd6; }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; background:var(--bg); color:var(--ink); }
main { max-width:1200px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; }
p.lead { color:var(--muted); margin:0 0 20px; }
section.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:16px; }
textarea { width:100%; min-height:90px; font:inherit; padding:10px; border:1px solid var(--line); border-radius:8px; }
.row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-top:10px; }
button { font:inherit; border-radius:8px; border:1px solid var(--line); background:#fff; padding:7px 12px; cursor:pointer; }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; padding:8px 20px; }
button:disabled { opacity:.6; cursor:wait; }
.examples { display:flex; gap:8px; flex-wrap:wrap; }
.grid { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:12px; }
@media (max-width: 860px) { .grid { grid-template-columns:1fr; } }
.col h3 { font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:0 0 6px; }
.box { border:1px solid var(--line); border-radius:8px; padding:10px; min-height:60px; white-space:pre-wrap; word-break:break-word; }
.badge { display:inline-block; font-weight:600; padding:2px 10px; border-radius:999px; color:#fff; margin-bottom:6px; }
.allow { background:var(--ok); } .masked { background:var(--warn); } .blocked, .error { background:var(--bad); }
details { margin-top:8px; color:var(--muted); }
pre { white-space:pre-wrap; word-break:break-word; background:#f1f3f6; padding:8px; border-radius:6px; font-size:12px; }
iframe { width:100%; height:360px; border:1px solid var(--line); border-radius:8px; background:#fff; }
.muted { color:var(--muted); }
</style>
</head>
<body>
<main>
<h1>rwsafe yerel deneme</h1>
<p class="lead">Bir yapay zekâ sohbetine yazar gibi bir metin yazın. Metin, kurumsal vekil sunucunun yapacağı gibi
denetim motoruna gönderilir; motorun kararı ve sahte sağlayıcıya ulaşan metin yan yana gösterilir. Gerçek bir
sağlayıcıya hiçbir şey gönderilmez.</p>
<section class="card">
  <textarea id="prompt" placeholder="Metninizi buraya yazın"></textarea>
  <div class="row">
    <button id="send" class="primary">Gönder</button>
    <label><input type="checkbox" id="browser"> Tarayıcı isteği gibi gönder (engelleme sayfasını görmek için)</label>
  </div>
  <div class="row"><span class="muted">Örnekler (değerler her başlatmada yeniden üretilen sahte değerlerdir):</span></div>
  <div class="row examples" id="examples"></div>
</section>
<div id="results"></div>
</main>
<script src="/app.js"></script>
</body>
</html>
"""

APP_JS = r"""
'use strict';
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function column(title, children) {
  const c = el('div', 'col');
  c.appendChild(el('h3', null, title));
  const box = el('div', 'box');
  children.forEach((ch) => box.appendChild(ch));
  c.appendChild(box);
  return c;
}
function details(summary, text) {
  const d = el('details');
  d.appendChild(el('summary', null, summary));
  d.appendChild(el('pre', null, text));
  return d;
}
function render(r) {
  const card = el('section', 'card');
  const grid = el('div', 'grid');
  grid.appendChild(column('Sizin yazdığınız', [el('div', null, r.written),
    details('Sağlayıcıya gidecek istek (vekil sunucunun gördüğü)', r.request.method + ' ' + r.request.url + '\n\n' + r.request.body)]));
  const d = r.decision;
  const decision = [el('span', 'badge ' + d.kind, d.title), el('div', null, d.detail)];
  if (d.icapStatus !== null && d.icapStatus !== undefined) {
    decision.push(el('div', 'muted', 'Denetim motoru yanıt durumu: ' + d.icapStatus));
  }
  if (d.adminUrl) {
    const a = el('a', null, 'Bu kararı yönetim arayüzünde aç');
    a.href = d.adminUrl;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    decision.push(a);
  }
  grid.appendChild(column('Karar', decision));
  const p = r.provider;
  const provider = [];
  if (p.reached) {
    provider.push(el('div', null, p.reply));
    provider.push(details('Sağlayıcıya ulaşan istek gövdesi', p.body));
  } else {
    provider.push(el('div', null, p.reply || 'Sağlayıcıya hiçbir şey gönderilmedi.'));
  }
  grid.appendChild(column('Sağlayıcıya ulaşan', provider));
  card.appendChild(grid);
  if (r.blockPage) {
    const b = r.blockPage;
    card.appendChild(el('h3', null, 'Kullanıcıya gösterilen engelleme yanıtı (durum ' + b.httpStatus + ')'));
    if (b.contentType.toLowerCase().startsWith('text/html')) {
      const f = document.createElement('iframe');
      f.setAttribute('sandbox', '');
      f.setAttribute('title', 'Engelleme sayfası');
      f.srcdoc = b.body;
      card.appendChild(f);
    } else {
      card.appendChild(el('pre', null, b.body));
    }
  }
  $('results').prepend(card);
}
async function send() {
  const prompt = $('prompt').value;
  if (!prompt.trim()) return;
  $('send').disabled = true;
  try {
    const res = await fetch('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: prompt, browser: $('browser').checked }) });
    const r = await res.json();
    if (!res.ok) { alert(r.error || ('Hata: ' + res.status)); return; }
    render(r);
  } catch (e) {
    alert('Deneme sunucusuna ulaşılamadı: ' + e);
  } finally {
    $('send').disabled = false;
  }
}
async function loadExamples() {
  const res = await fetch('/api/examples');
  const list = await res.json();
  list.forEach((x) => {
    const b = el('button', null, x.label);
    b.title = x.prompt;
    b.addEventListener('click', () => { $('prompt').value = x.prompt; $('prompt').focus(); });
    $('examples').appendChild(b);
  });
}
$('send').addEventListener('click', send);
$('prompt').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) send(); });
loadExamples();
"""

CSP = ("default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src data:; "
       "frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class TrialServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, trial: Trial, example_list: list[dict]):
        super().__init__((require_loopback(LOOPBACK), port), Handler)
        self.trial = trial
        self.examples = example_list

    @property
    def port(self) -> int:
        return self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    server: TrialServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        # Method, path and status only; a prompt never reaches the log.
        sys.stderr.write("trial_proxy: %s\n" % (fmt % args))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _same_origin(self) -> bool:
        """Only this page may call the API: the Host is the loopback listener and a sent Origin matches it."""
        allowed = {f"{LOOPBACK}:{self.server.port}", f"localhost:{self.server.port}"}
        if self.headers.get("Host") not in allowed:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {"http://" + a for a in allowed}

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/app.js":
            self._send(200, APP_JS.encode("utf-8"), "text/javascript; charset=utf-8")
        elif self.path == "/api/examples" and self._same_origin():
            self._json(200, self.server.examples)
        elif self.path == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
        else:
            self._json(404, {"error": "Bulunamadı."})

    def do_POST(self) -> None:
        if self.path != "/api/send":
            self._json(404, {"error": "Bulunamadı."})
            return
        if not self._same_origin() or not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._json(403, {"error": "Bu istek yalnızca deneme sayfasından gönderilebilir."})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4 * MAX_PROMPT:
            self._json(400, {"error": "Metin boş ya da çok uzun."})
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            prompt = data["prompt"]
            browser = bool(data.get("browser", False))
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "İstek okunamadı."})
            return
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT:
            self._json(400, {"error": "Metin boş ya da çok uzun."})
            return
        self._json(200, self.server.trial.send(prompt, browser))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--icap-host", default=LOOPBACK)
    ap.add_argument("--icap-port", type=int, default=1344)
    ap.add_argument("--mock-host", default=LOOPBACK)
    ap.add_argument("--mock-port", type=int, required=True)
    ap.add_argument("--user", default="SYNTHETIC\\trial-user", help="the synthetic X-Authenticated-User claim")
    ap.add_argument("--admin-url", default="http://127.0.0.1:5173", help="the admin UI, for the event links")
    a = ap.parse_args()
    try:
        trial = Trial(a.icap_host, a.icap_port, a.mock_host, a.mock_port, a.user, a.admin_url)
    except LoopbackOnly as e:
        sys.stderr.write(f"trial_proxy: {e}\n")
        return 2
    server = TrialServer(a.port, trial, examples(random.SystemRandom()))
    sys.stderr.write(f"trial_proxy: listening on http://{LOOPBACK}:{server.port}/\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
