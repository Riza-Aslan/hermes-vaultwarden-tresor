#!/usr/bin/env python3
"""Tresordienst – Sidecar der WebUI-Erweiterung „Tresor“.

Zeigt und pflegt eine Vaultwarden-Sammlung (VW_SAMMLUNG) über ein Dienstkonto
(VW_EMAIL) - dasselbe Konto wie beim Agenten-Plugin vaultwarden-zugang.

Lauscht nur auf 127.0.0.1:17831. Der Browser erreicht ihn ausschließlich
über den Proxy der WebUI (/api/extensions/tresor/sidecar/…), der nur
angemeldete Browser-Anfragen durchlässt und das Token aus
~/.hermes/webui/sidecar-auth/tresor.token mitschickt (token-v1).

Grundsätze:
  * Liste und Detail enthalten KEINE Geheimnisse. Passwort, privater
    Schlüssel und verborgene Felder kommen einzeln über /api/geheim – nur
    wenn im Browser „Anzeigen“ oder „Kopieren“ gedrückt wird.
  * Schreiben baut den Eintrag aus seiner entschlüsselten Fassung neu auf und
    behält alles, was nicht geändert wurde (alle URIs, TOTP, Feldtypen,
    Passwortverlauf, SSH-Schlüssel).
  * Löschen = Papierkorb von Vaultwarden (wiederherstellbar).
  * Nichts wird protokolliert, was einen Wert enthält.
"""
import datetime
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLUGIN = os.path.expanduser("~/.hermes/plugins/vaultwarden-zugang")
sys.path.insert(0, PLUGIN)

HOST, PORT = "127.0.0.1", 17831
TOKEN_DATEI = os.path.expanduser("~/.hermes/webui/sidecar-auth/tresor.token")
ENV = os.path.expanduser("~/.hermes/.env")
FRISCH_S = 30          # so lange gilt ein Abgleich, bevor die Liste neu holt

TYPEN = {1: "login", 2: "notiz", 3: "karte", 4: "identitaet", 5: "ssh"}

_lock = threading.RLock()
_z = {"s": None, "vw": None, "stand": 0.0}


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


class Fehler(Exception):
    def __init__(self, text, status=400):
        super().__init__(text)
        self.status = status


# ---------------------------------------------------------------------------
# Vaultwarden
# ---------------------------------------------------------------------------

def _env_laden():
    """VW_*-Variablen aus ~/.hermes/.env in diesen Prozess uebernehmen (schon Gesetztes bleibt)."""
    try:
        with open(ENV, encoding="utf-8") as fh:
            for z in fh:
                z = z.strip()
                if not z.startswith("VW_") or "=" not in z:
                    continue
                k, w = z.split("=", 1)
                w = w.strip()
                if len(w) >= 2 and w[0] == w[-1] and w[0] in "\"'":
                    w = w[1:-1]
                os.environ.setdefault(k.strip(), w)
    except OSError:
        pass
    if not os.environ.get("VW_PASSWORT"):
        raise Fehler("VW_PASSWORT fehlt in ~/.hermes/.env", 500)


def sitzung(frisch=False):
    """Angemeldete Sitzung mit aktuellem Abgleich (höchstens FRISCH_S alt)."""
    with _lock:
        if _z["s"] is None:
            _env_laden()   # nur in diesem Prozess
            import vw_zugang as vw
            _z["vw"] = vw
            _z["s"] = vw.Sitzung()
            _z["stand"] = 0.0
        if frisch or time.time() - _z["stand"] > FRISCH_S:
            try:
                _z["s"].sync(frisch=True)
            except Exception:
                _z["s"] = None
                raise
            _z["stand"] = time.time()
        return _z["vw"], _z["s"]


def veraltet():
    with _lock:
        _z["stand"] = 0.0


def sammlung(s):
    name = os.environ.get("VW_SAMMLUNG", "Hermes")
    for c in s.sammlungen():
        if c["name"] == name:
            return c
    raise Fehler("Sammlung „%s“ ist dem Dienstkonto nicht zugewiesen." % name, 500)


def _roh(s, cid):
    for c in s.sync().get("ciphers") or []:
        if c["id"] == cid and not c.get("deletedDate"):
            return c
    raise Fehler("Eintrag nicht gefunden (vielleicht gerade geändert oder gelöscht).", 404)


def _k(s, c):
    return lambda x: s.klar(x, eintrag=c) if x else ""


def _felder(s, c):
    k = _k(s, c)
    aus = []
    for f in c.get("fields") or []:
        aus.append({"name": k(f.get("name")), "wert": k(f.get("value")), "typ": f.get("type") or 0,
                    "linkedId": f.get("linkedId")})
    return aus


def _kennung(felder):
    for f in felder:
        if f["name"] == "kennung":
            return f["wert"]
    return ""


def kurz(s, c):
    k = _k(s, c)
    felder = _felder(s, c)
    login = c.get("login") or {}
    uris = [k(u.get("uri")) for u in (login.get("uris") or []) if u.get("uri")]
    name = k(c.get("name"))
    return {
        "id": c["id"], "name": name, "typ": TYPEN.get(c.get("type"), "?"),
        "gruppe": name.split(":", 1)[0].strip() if ":" in name else "Sonstiges",
        "kennung": _kennung(felder), "user": k(login.get("username")),
        "uri": uris[0] if uris else "", "geaendert": c.get("revisionDate"),
        "favorit": bool(c.get("favorite")),
    }


def detail(s, c):
    k = _k(s, c)
    d = kurz(s, c)
    login = c.get("login") or {}
    ssh = c.get("sshKey") or {}
    d.update({
        "notiz": k(c.get("notes")),
        "uris": [k(u.get("uri")) for u in (login.get("uris") or []) if u.get("uri")],
        "hat_pw": bool(login.get("password")), "hat_totp": bool(login.get("totp")),
        "ssh_pub": k(ssh.get("publicKey")), "ssh_fp": k(ssh.get("keyFingerprint")),
        "hat_priv": bool(ssh.get("privateKey")),
        "pw_verlauf": len(c.get("passwordHistory") or []),
        "erstellt": c.get("creationDate"),
        "felder": [{"name": f["name"], "verborgen": f["typ"] == 1,
                    "wert": "" if f["typ"] == 1 else f["wert"]} for f in _felder(s, c) if f["name"] != "kennung"],
    })
    return d


def geheim(s, c, feld):
    k = _k(s, c)
    if feld == "pw":
        return k((c.get("login") or {}).get("password"))
    if feld == "priv":
        return k((c.get("sshKey") or {}).get("privateKey"))
    if feld == "totp":
        return k((c.get("login") or {}).get("totp"))
    if feld.startswith("feld:"):
        name = feld[5:]
        for f in _felder(s, c):
            if f["name"] == name:
                return f["wert"]
    raise Fehler("Unbekanntes Feld.", 404)


# ---------------------------------------------------------------------------
# Schreiben
# ---------------------------------------------------------------------------

def _kennung_aus(name):
    t = name.lower()
    for a, b in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        t = t.replace(a, b)
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-")[:60]


def ssh_erzeugen(kommentar):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", kommentar or "hermes", "-f", p],
                       check=True, capture_output=True)
        priv = open(p).read()
        pub = open(p + ".pub").read().strip()
        fp = subprocess.run(["ssh-keygen", "-lf", p + ".pub"], capture_output=True, text=True).stdout.split()[1]
    return priv, pub, fp


def ssh_aus_priv(priv):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "k")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(priv if priv.endswith("\n") else priv + "\n")
        r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", p], capture_output=True, text=True)
        if r.returncode != 0:
            raise Fehler("Das ist kein lesbarer privater Schlüssel (oder er hat eine Passphrase).")
        pub = r.stdout.strip()
        open(p + ".pub", "w").write(pub + "\n")
        fp = subprocess.run(["ssh-keygen", "-lf", p + ".pub"], capture_output=True, text=True).stdout.split()[1]
    return pub, fp


def speichern(daten):
    """Anlegen (ohne id) oder ändern (mit id).

    Geheime Werte: None = unverändert lassen, "" = leeren, sonst setzen.
    """
    vw, s = sitzung(frisch=True)
    sam = sammlung(s)
    if sam["readOnly"]:
        raise Fehler("Die Sammlung ist nur lesbar.", 403)
    org = sam["organizationId"]
    key = s.schluessel_fuer(org)

    def enc(t):
        return vw.enc_string(t.encode(), key) if t else None

    cid = daten.get("id") or None
    alt = _roh(s, cid) if cid else None
    k = _k(s, alt) if alt else (lambda x: "")
    typ_name = daten.get("typ") or (TYPEN.get(alt.get("type")) if alt else "login")
    if alt and TYPEN.get(alt.get("type")) != typ_name:
        raise Fehler("Die Art eines Eintrags lässt sich nicht ändern.")
    if typ_name not in ("login", "notiz", "ssh"):
        raise Fehler("Diese Eintragsart wird hier nicht bearbeitet – bitte in Vaultwarden selbst.")

    name = (daten.get("name") or "").strip()
    if not name:
        raise Fehler("Name fehlt.")
    kennung = (daten.get("kennung") or "").strip() or _kennung_aus(name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", kennung):
        raise Fehler("Kennung: nur Buchstaben, Ziffern, Punkt, Bindestrich, Unterstrich.")
    for c in s.sync().get("ciphers") or []:
        if c.get("deletedDate") or c["id"] == cid:
            continue
        if _kennung(_felder(s, c)).lower() == kennung.lower():
            raise Fehler("Die Kennung „%s“ hat schon „%s“." % (kennung, s.klar(c.get("name"), eintrag=c)))

    # Zusatzfelder: alte Werte behalten, wo der Browser keinen neuen schickt
    alte_felder = {f["name"]: f for f in _felder(s, alt)} if alt else {}
    felder = [{"type": 0, "name": enc("kennung"), "value": enc(kennung), "linkedId": None}]
    namen = set()
    for f in daten.get("felder") or []:
        n = (f.get("name") or "").strip()
        if not n or n == "kennung" or n in namen:
            continue
        namen.add(n)
        verborgen = bool(f.get("verborgen"))
        wert = f.get("wert")
        if wert is None:
            wert = (alte_felder.get(n) or {}).get("wert", "")
        typ = 1 if verborgen else 0
        if n in alte_felder and alte_felder[n]["typ"] not in (0, 1):
            typ = alte_felder[n]["typ"]          # Boolean/verknüpft unverändert lassen
        felder.append({"type": typ, "name": enc(n), "value": enc(wert),
                       "linkedId": (alte_felder.get(n) or {}).get("linkedId")})

    c = {
        "type": {"login": 1, "notiz": 2, "ssh": 5}[typ_name],
        "organizationId": org, "encryptedFor": s.sync()["profile"]["id"],
        "name": enc(name), "notes": enc((daten.get("notiz") or "").rstrip()),
        "favorite": bool(alt.get("favorite")) if alt else False,
        "reprompt": alt.get("reprompt", 0) if alt else 0, "folderId": None,
        "fields": felder,
    }

    if typ_name == "login":
        L_alt = (alt or {}).get("login") or {}
        L = daten.get("login") or {}
        pw_alt = k(L_alt.get("password"))
        pw = L.get("pw")
        pw = pw_alt if pw is None else pw
        uri_alt = {k(u.get("uri")): u.get("match") for u in (L_alt.get("uris") or []) if u.get("uri")}
        uris = [u.strip() for u in (L.get("uris") if L.get("uris") is not None else list(uri_alt)) if u and u.strip()]
        verlauf = [{"password": enc(k(h.get("password"))), "lastUsedDate": h.get("lastUsedDate")}
                   for h in ((alt or {}).get("passwordHistory") or []) if h.get("password")]
        if alt and pw_alt and pw != pw_alt:
            verlauf.insert(0, {"password": enc(pw_alt),
                               "lastUsedDate": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")})
        c["passwordHistory"] = verlauf[:5] or None
        c["login"] = {
            "username": enc((L.get("user") if L.get("user") is not None else k(L_alt.get("username"))) or ""),
            "password": enc(pw or ""),
            "totp": enc(k(L_alt.get("totp"))),
            "uris": [{"uri": enc(u), "match": uri_alt.get(u)} for u in uris] or None,
            "passwordRevisionDate": L_alt.get("passwordRevisionDate"),
        }
    elif typ_name == "notiz":
        c["secureNote"] = {"type": 0}
    else:
        S_alt = (alt or {}).get("sshKey") or {}
        S = daten.get("ssh") or {}
        if S.get("erzeugen"):
            priv, pub, fp = ssh_erzeugen(S.get("kommentar") or kennung)
        elif S.get("priv"):
            priv = S["priv"].replace("\r\n", "\n")
            pub, fp = ssh_aus_priv(priv)
        elif alt and S_alt.get("privateKey"):
            priv, pub, fp = k(S_alt.get("privateKey")), k(S_alt.get("publicKey")), k(S_alt.get("keyFingerprint"))
        else:
            raise Fehler("Ein SSH-Eintrag braucht einen privaten Schlüssel – einfügen oder „neu erzeugen“.")
        if not priv.endswith("\n"):
            priv += "\n"
        c["sshKey"] = {"privateKey": enc(priv), "publicKey": enc(pub), "keyFingerprint": enc(fp)}

    if alt:
        code, a = vw.ruf("/api/ciphers/" + cid, c, token=s.token, methode="PUT")
        aktion = "geändert"
    else:
        code, a = vw.ruf("/api/ciphers/create", {"cipher": c, "collectionIds": [sam["id"]]}, token=s.token)
        aktion = "angelegt"
    if code != 200:
        raise Fehler("Vaultwarden lehnt ab (%s): %s" % (code, json.dumps(a, ensure_ascii=False)[:240]), 502)
    neu_id = a.get("id") or a.get("Id") or cid
    veraltet()
    log("Eintrag %s: %s" % (aktion, neu_id))
    return {"ok": True, "id": neu_id, "aktion": aktion}


def papierkorb(cid):
    vw, s = sitzung(frisch=True)
    _roh(s, cid)
    code, a = vw.ruf("/api/ciphers/%s/delete" % cid, None, token=s.token, methode="PUT")
    if code not in (200, 204):
        raise Fehler("Vaultwarden lehnt ab (%s): %s" % (code, json.dumps(a, ensure_ascii=False)[:200]), 502)
    veraltet()
    log("Eintrag in den Papierkorb: %s" % cid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _token():
    try:
        with open(TOKEN_DATEI, encoding="utf-8") as fh:
            t = fh.read().strip()
        return t if re.fullmatch(r"[A-Za-z0-9_-]{16,256}", t) else None
    except OSError:
        return None


class H(BaseHTTPRequestHandler):
    server_version = "Tresordienst"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _json(self, daten, status=200):
        roh = json.dumps(daten, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(roh)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(roh)

    def _erlaubt(self):
        soll = _token()
        if soll is None:
            self._json({"fehler": "Token der WebUI fehlt – Proxy-Freigabe erteilen."}, 503)
            return False
        if not hmac.compare_digest(self.headers.get("X-Hermes-Sidecar-Token", "").encode(), soll.encode()):
            self._json({"fehler": "Nicht berechtigt."}, 401)
            return False
        return True

    def _fehlerbehandlung(self, fn):
        try:
            return fn()
        except Fehler as exc:
            return self._json({"fehler": str(exc)}, exc.status)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            return self._json({"fehler": "%s: %s" % (type(exc).__name__, str(exc)[:200])}, 500)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/health":
            return self._json({"ok": True, "dienst": "tresor"})
        if not self._erlaubt():
            return

        def los():
            if url.path == "/api/liste":
                vw, s = sitzung(frisch=q.get("frisch") == "1")
                sam = sammlung(s)
                eintraege = [kurz(s, c) for c in s.sync().get("ciphers") or []
                             if not c.get("deletedDate") and sam["id"] in (c.get("collectionIds") or [])]
                eintraege.sort(key=lambda e: e["name"].lower())
                return self._json({"eintraege": eintraege, "sammlung": sam["name"], "schreibbar": not sam["readOnly"],
                                   "konto": s.email, "server": vw.BASIS, "stand": _z["stand"]})
            if url.path == "/api/eintrag":
                vw, s = sitzung()
                return self._json(detail(s, _roh(s, q.get("id", ""))))
            if url.path == "/api/geheim":
                vw, s = sitzung()
                return self._json({"wert": geheim(s, _roh(s, q.get("id", "")), q.get("feld", ""))})
            return self._json({"fehler": "Unbekannt."}, 404)
        return self._fehlerbehandlung(los)

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        if not self._erlaubt():
            return

        def los():
            n = int(self.headers.get("Content-Length") or 0)
            if n > 256 * 1024:
                raise Fehler("Anfrage zu groß.", 413)
            try:
                daten = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                raise Fehler("Kein gültiges JSON.")
            if url.path == "/api/speichern":
                return self._json(speichern(daten))
            if url.path == "/api/papierkorb":
                return self._json(papierkorb(str(daten.get("id", ""))))
            return self._json({"fehler": "Unbekannt."}, 404)
        return self._fehlerbehandlung(los)


def main():
    os.umask(0o077)
    srv = ThreadingHTTPServer((HOST, PORT), H)
    srv.daemon_threads = True
    log("Tresordienst lauscht auf %s:%d" % (HOST, PORT))
    srv.serve_forever()


if __name__ == "__main__":
    main()
