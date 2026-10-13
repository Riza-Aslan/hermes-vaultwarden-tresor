#!/usr/bin/env python3
"""Vaultwarden-Client fuer Hermes — nur Standardbibliothek und openssl.

Bitwarden legt alle Schluessel im Browser an; der Server sieht nie das
Hauptpasswort. Wer sich ohne Browser anmelden will, muss dieselbe Ableitung
von Hand nachbauen:

    masterKey          = PBKDF2-SHA256(passwort, email, iterationen, 32)
    masterPasswordHash = PBKDF2-SHA256(masterKey, passwort, 1, 32)   -> das sieht der Server
    stretched          = HKDF-Expand(masterKey, "enc") || HKDF-Expand(masterKey, "mac")

    userKey            = 64 zufaellige Bytes  (32 enc + 32 mac)
    userSymmetricKey   = AES-256-CBC(userKey, stretched) mit HMAC darueber
    RSA-2048-Paar      = fuer das Teilen in Organisationen;
                         der private Teil wird mit userKey verschluesselt

Das Format der verschluesselten Felder ist Bitwardens "EncString" vom Typ 2:

    2.<iv b64>|<chiffrat b64>|<hmac b64>

AES kann die Standardbibliothek nicht - dafuer wird openssl aufgerufen, so
wie es ueblich ist. Schluessel und IV gehen dabei als Hex auf der
Befehlszeile; das ist hier vertretbar, weil beide in diesem Moment erst
entstehen und der Prozess niemandem sonst gehoert. Das Hauptpasswort selbst
laeuft nie ueber argv.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Serveradresse der Vaultwarden-Instanz, z. B. https://vault.example.org
BASIS = os.environ.get("VW_BASIS", "").rstrip("/")
KDF_PBKDF2 = 0
ITERATIONEN = 600_000

# TLS wird standardmaessig geprueft. Hinter einer eigenen CA (Heimnetz):
#   VW_CA_FILE=/pfad/zur/ca.pem    -> diese CA zusaetzlich vertrauen (empfohlen)
#   VW_TLS_RELAXED=1               -> Kette und Hostname weiter pruefen, aber ohne das
#                                     strikte X.509-Flag von Python 3.13 (hilft bei
#                                     selbst erzeugten CAs, deren Zertifikat z. B.
#                                     "Basic Constraints not critical" meldet)
#   VW_TLS_INSECURE=1              -> Pruefung ganz abschalten (nur im Notfall)
if os.environ.get("VW_TLS_INSECURE") == "1":
    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
else:
    _ctx = ssl.create_default_context(cafile=os.environ.get("VW_CA_FILE") or None)
    if os.environ.get("VW_TLS_RELAXED") == "1" and hasattr(ssl, "VERIFY_X509_STRICT"):
        _ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT


class VwFehler(Exception):
    pass


# ---------------------------------------------------------------- Werkzeug

def b64(roh):
    return base64.b64encode(roh).decode()


def hkdf_expand(prk, info, laenge=32):
    """HKDF-Expand nach RFC 5869. Extract entfaellt: masterKey ist schon 32 Byte."""
    aus, block, zaehler = b"", b"", 1
    while len(aus) < laenge:
        block = hmac.new(prk, block + info.encode() + bytes([zaehler]), hashlib.sha256).digest()
        aus += block
        zaehler += 1
    return aus[:laenge]


def aes_cbc(klartext, schluessel, iv, entschluesseln=False):
    befehl = ["openssl", "enc", "-aes-256-cbc",
              "-K", schluessel.hex(), "-iv", iv.hex()]
    if entschluesseln:
        befehl.append("-d")
    p = subprocess.run(befehl, input=klartext, capture_output=True)
    if p.returncode != 0:
        raise VwFehler("openssl: %s" % p.stderr.decode()[:200])
    return p.stdout


def enc_string(klartext, schluessel64):
    """Bitwardens EncString Typ 2: AES-256-CBC, danach HMAC ueber IV und Chiffrat."""
    enc, mac = schluessel64[:32], schluessel64[32:64]
    iv = os.urandom(16)
    chiffrat = aes_cbc(klartext, enc, iv)
    marke = hmac.new(mac, iv + chiffrat, hashlib.sha256).digest()
    return "2.%s|%s|%s" % (b64(iv), b64(chiffrat), b64(marke))


def dec_string(text, schluessel64):
    if not text.startswith("2."):
        raise VwFehler("Unerwarteter EncString-Typ: %s" % text[:4])
    iv_b, ct_b, mac_b = text[2:].split("|")
    iv, ct, marke = base64.b64decode(iv_b), base64.b64decode(ct_b), base64.b64decode(mac_b)
    enc, mac = schluessel64[:32], schluessel64[32:64]
    erwartet = hmac.new(mac, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(marke, erwartet):
        raise VwFehler("HMAC passt nicht - falscher Schluessel oder veraendert.")
    return aes_cbc(ct, enc, iv, entschluesseln=True)


# ------------------------------------------------------------- Ableitungen

def leite_ab(email, passwort, iterationen=ITERATIONEN):
    email = email.strip().lower()
    pw = passwort.encode()
    master = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), iterationen, 32)
    # Was der Server zu sehen bekommt. Aus ihm laesst sich das Passwort nicht
    # zurueckrechnen - und der Hauptschluessel schon gar nicht.
    hash_fuer_server = b64(hashlib.pbkdf2_hmac("sha256", master, pw, 1, 32))
    gedehnt = hkdf_expand(master, "enc") + hkdf_expand(master, "mac")
    return {"master": master, "hash": hash_fuer_server, "gedehnt": gedehnt}


def rsa_entschluessele(chiffrat, priv_der):
    """EncString Typ 4: RSA-2048 mit OAEP und SHA-1 — so verpackt Bitwarden
    den Organisationsschluessel fuer jedes einzelne Mitglied."""
    with tempfile.TemporaryDirectory() as ordner:
        pfad = os.path.join(ordner, "k.der")
        fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(priv_der)
        p = subprocess.run(
            ["openssl", "pkeyutl", "-decrypt", "-inkey", pfad, "-keyform", "DER",
             "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha1"],
            input=chiffrat, capture_output=True)
        if p.returncode != 0:
            raise VwFehler("RSA: %s" % p.stderr.decode()[:200])
        return p.stdout


def oeffne_typ4(text, priv_der):
    if not text.startswith("4."):
        raise VwFehler("Unerwarteter EncString-Typ: %s" % text[:4])
    return rsa_entschluessele(base64.b64decode(text[2:]), priv_der)


def rsa_paar():
    """2048-Bit-Paar. privat als PKCS8-DER, oeffentlich als SPKI-DER."""
    with tempfile.TemporaryDirectory() as ordner:
        priv = os.path.join(ordner, "p.der")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048",
                        "-outform", "DER", "-out", priv],
                       check=True, capture_output=True)
        os.chmod(priv, 0o600)
        oeff = subprocess.run(["openssl", "pkey", "-in", priv, "-inform", "DER",
                               "-pubout", "-outform", "DER"],
                              check=True, capture_output=True).stdout
        with open(priv, "rb") as fh:
            return fh.read(), oeff


# ------------------------------------------------------------------ HTTP

def ruf(pfad, daten=None, token=None, form=False, methode=None):
    if not BASIS:
        raise VwFehler("VW_BASIS fehlt (Adresse der Vaultwarden-Instanz).")
    kopf = {"Accept": "application/json",
            "Bitwarden-Client-Name": "hermes",
            "Bitwarden-Client-Version": "2026.6.0"}
    if token:
        kopf["Authorization"] = "Bearer " + token

    if form:
        rumpf = urllib.parse.urlencode(daten).encode()
        kopf["Content-Type"] = "application/x-www-form-urlencoded"
    elif daten is not None:
        rumpf = json.dumps(daten).encode()
        kopf["Content-Type"] = "application/json"
    else:
        rumpf = None

    anfrage = urllib.request.Request(BASIS + pfad, data=rumpf, headers=kopf,
                                     method=methode or ("POST" if rumpf is not None else "GET"))
    try:
        with urllib.request.urlopen(anfrage, context=_ctx, timeout=60) as a:
            roh = a.read()
            return a.status, (json.loads(roh) if roh.strip() else {})
    except urllib.error.HTTPError as e:
        roh = e.read()
        try:
            return e.code, json.loads(roh)
        except ValueError:
            return e.code, {"roh": roh.decode("utf-8", "replace")[:400]}


# ------------------------------------------------------------- Sitzung

EMAIL = os.environ.get("VW_EMAIL", "")


SITZUNGSDATEI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sitzung.json")


def _lade_sitzungsdatei():
    try:
        with open(SITZUNGSDATEI, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _schreibe_sitzungsdatei(daten):
    tmp = SITZUNGSDATEI + ".neu"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(daten, fh, indent=1)
    os.replace(tmp, SITZUNGSDATEI)


def geraetekennung():
    """Eine feste Kennung fuer diese Maschine.

    Wurde hier frueher je Aufruf eine neue gewuerfelt - mit der Folge, dass
    Vaultwarden jedes Mal ein fremdes Geraet sah und brav eine Mail
    "New Device Logged In" schickte. Nach dreissig Stueck in einem Nachmittag
    war klar, dass das kein Schoenheitsfehler ist.
    """
    daten = _lade_sitzungsdatei()
    if not daten.get("geraet"):
        import uuid
        daten["geraet"] = str(uuid.uuid4())
        _schreibe_sitzungsdatei(daten)
    return daten["geraet"]


class Sitzung:
    """Angemeldet, mit allen Schluesseln griffbereit.

    Das Hauptpasswort kommt aus der Umgebung (VW_PASSWORT), nie aus der
    Befehlszeile.

    Es wird auch dann gebraucht, wenn noch ein gueltiger Zugang vorliegt: der
    Server kennt den Hauptschluessel nicht, entschluesselt wird ausschliesslich
    hier. Der zwischengespeicherte Zugang erspart nur den Anmeldevorgang -
    nicht das Passwort.
    """

    def __init__(self, email=None, passwort=None, neu=False):
        self.email = email or EMAIL
        if not self.email:
            raise VwFehler("VW_EMAIL fehlt (Konto der Vaultwarden-Instanz).")
        pw = passwort or os.environ.get("VW_PASSWORT")
        if not pw:
            raise VwFehler("VW_PASSWORT fehlt (Hauptpasswort des Kontos, nur ueber die Umgebung).")

        ab = leite_ab(self.email, pw)
        self._ab = ab
        self.token = None
        vorrat = _lade_sitzungsdatei()

        # 1. Noch gueltiger Zugang? Dann gar nicht erst anmelden.
        if not neu and vorrat.get("token") and vorrat.get("gueltig_bis", 0) > time.time() + 60:
            self.token = vorrat["token"]
            self._schluessel_aus(vorrat)

        # 2. Sonst mit dem Erneuerungsschein - auch das ist kein neues Geraet.
        if self.token is None and not neu and vorrat.get("erneuerung"):
            code, a = ruf("/identity/connect/token", {
                "grant_type": "refresh_token", "client_id": "web",
                "refresh_token": vorrat["erneuerung"]}, form=True)
            if code == 200:
                self._merke(a, ab)

        # 3. Erst dann das Passwort.
        if self.token is None:
            code, a = ruf("/identity/connect/token", {
                "grant_type": "password", "username": self.email,
                "password": ab["hash"], "scope": "api offline_access",
                "client_id": "web", "deviceType": "9",
                "deviceIdentifier": geraetekennung(), "deviceName": "hermes"}, form=True)
            if code != 200:
                raise VwFehler("Anmeldung gescheitert (%s): %s" % (code, json.dumps(a)[:200]))
            self._merke(a, ab)

        # Sitzungszustand, kein Anmeldezustand: das muss auch dann stehen,
        # wenn der Zugang aus dem Vorrat kam und gar nicht angemeldet wurde.
        self._sync = None
        self._orgkeys = {}
        self._eintragskeys = {}

    def _schluessel_aus(self, vorrat):
        """Die verschluesselten Schluessel liegen im Vorrat - aufmachen kann sie
        nur das Hauptpasswort. Genau so soll es sein."""
        try:
            self.userkey = dec_string(vorrat["key"], self._ab["gedehnt"])
            self.privkey = dec_string(vorrat["privkey"], self.userkey)
        except (KeyError, VwFehler):
            self.token = None

    def _merke(self, antwort, ab):
        token = antwort["access_token"]
        if "Key" in antwort:
            self.userkey = dec_string(antwort["Key"], ab["gedehnt"])
            self.privkey = dec_string(antwort["PrivateKey"], self.userkey)
        else:
            # Der Erneuerungsschein bringt die Schluessel nicht mit - Vaultwarden
            # liefert Key/PrivateKey nur beim Passwort-Grant. Sie liegen
            # verschluesselt im Vorrat; fehlen sie auch dort, bleibt token auf
            # None und Schritt 3 meldet mit dem Passwort an. Ohne diesen Zweig
            # stirbt jeder Aufruf nach Ablauf der Sitzung an KeyError: Key.
            self.token = token
            self._schluessel_aus(_lade_sitzungsdatei())
            if self.token is None:
                return
        self.token = token
        vorrat = _lade_sitzungsdatei()
        vorrat.update({
            "token": self.token,
            "erneuerung": antwort.get("refresh_token") or vorrat.get("erneuerung"),
            "gueltig_bis": time.time() + int(antwort.get("expires_in", 3600)),
            # Verschluesselt, wie sie vom Server kommen - ohne das Hauptpasswort
            # nuetzen sie niemandem etwas.
            # Beim Erneuerungsschein fehlen sie in der Antwort - dann
            # bleiben die aus dem Vorrat stehen, sie aendern sich ja nicht.
            "key": antwort.get("Key") or vorrat.get("key"),
            "privkey": antwort.get("PrivateKey") or vorrat.get("privkey"),
        })
        _schreibe_sitzungsdatei(vorrat)
        self._eintragskeys = {}

    def sync(self, frisch=False):
        if self._sync is None or frisch:
            code, s = ruf("/api/sync?excludeDomains=true", token=self.token)
            if code == 401:
                # Zugang doch nicht mehr gut - einmal frisch anmelden und
                # weitermachen, statt den Aufruf scheitern zu lassen.
                neue = Sitzung(self.email, os.environ.get("VW_PASSWORT"), neu=True)
                self.token, self.userkey, self.privkey = (
                    neue.token, neue.userkey, neue.privkey)
                code, s = ruf("/api/sync?excludeDomains=true", token=self.token)
            if code != 200:
                raise VwFehler("Abgleich gescheitert: %s" % code)
            self._sync = s
            for o in s["profile"].get("organizations") or []:
                if o.get("key"):
                    self._orgkeys[o["id"]] = oeffne_typ4(o["key"], self.privkey)
        return self._sync

    def schluessel_fuer(self, org_id):
        """Der Organisationsschluessel - oder der eigene, wenn es keine Organisation ist."""
        if not org_id:
            return self.userkey
        return self._orgkeys.get(org_id) or self.userkey

    def eintrags_schluessel(self, eintrag):
        """
        Der Schluessel, mit dem die Felder *dieses* Eintrags verschluesselt sind.

        Neuere Bitwarden-Clients geben jedem Eintrag einen eigenen Schluessel und
        legen nur diesen mit dem Organisations- oder Kontoschluessel ab. Wer das
        nicht beachtet, bekommt beim Teilen aus einem persoenlichen Tresor
        ploetzlich "HMAC passt nicht" - die Felder haengen dann am Eintrags-
        schluessel, nicht am Organisationsschluessel.
        """
        aussen = self.schluessel_fuer(eintrag.get("organizationId"))
        eigener = eintrag.get("key")
        if not eigener:
            return aussen
        merker = self._eintragskeys.get(eintrag["id"])
        if merker is None:
            merker = dec_string(eigener, aussen)
            self._eintragskeys[eintrag["id"]] = merker
        return merker

    def klar(self, text, org_id=None, eintrag=None):
        if not text:
            return ""
        schluessel = self.eintrags_schluessel(eintrag) if eintrag else self.schluessel_fuer(org_id)
        return dec_string(text, schluessel).decode("utf-8", "replace")

    def sammlungen(self):
        aus = []
        for c in self.sync().get("collections") or []:
            aus.append({"id": c["id"], "organizationId": c["organizationId"],
                        "name": self.klar(c["name"], c["organizationId"]),
                        "readOnly": c.get("readOnly", False)})
        return aus

    def eintraege(self):
        aus = []
        for c in self.sync().get("ciphers") or []:
            org = c.get("organizationId")
            aus.append({
                "id": c["id"], "organizationId": org, "type": c.get("type"),
                "name": self.klar(c.get("name"), eintrag=c),
                "collectionIds": c.get("collectionIds") or [],
                "roh": c,
            })
        return aus


# ------------------------------------------------------------ Befehlszeile

HILFE = """Vaultwarden-Zugang fuer Hermes.

  vw_zugang.py lage [--neu-anmelden]   Konto, Organisation, Sammlungen, Anzahl
  vw_zugang.py liste                   Eintraege - nur Namen, nie Werte
  vw_zugang.py env NAME[=VAR] [...] -- BEFEHL [ARGS]
                                       Werte in die Umgebung eines Befehls reichen.
                                       NAME = Kennung (Feld "kennung") oder Anzeigename.
                                       NAME.user / NAME.uri / NAME.<feld> holt statt
                                       des Passworts den Benutzer, die erste URI oder
                                       ein Zusatzfeld. Bei SSH-Eintraegen ist der Wert
                                       der private Schluessel.

Es gibt bewusst keinen Befehl, der einen Wert ausgibt. Ansehen geht im Browser.

Noetig in der Umgebung: VW_BASIS, VW_EMAIL, VW_PASSWORT
Optional:               VW_CA_FILE (eigene CA), VW_TLS_INSECURE=1
"""


def _feld(s, eintrag, feldname):
    """Wert eines benutzerdefinierten Feldes, entschluesselt."""
    roh = eintrag.get("roh", eintrag)
    for f in (roh.get("fields") or []):
        if s.klar(f.get("name"), eintrag=roh) == feldname:
            return s.klar(f.get("value"), eintrag=roh)
    return None


def wert_von(s, eintrag):
    """Den Wert eines Eintrags herausholen - exakt, ohne zu raten."""
    roh = eintrag.get("roh", eintrag)
    if roh.get("type") == 5 and roh.get("sshKey"):
        # Eintragstyp SSH-Schluessel: der private Schluessel ist der Wert.
        wert = s.klar(roh["sshKey"].get("privateKey"), eintrag=roh)
        return wert if wert.endswith("\n") else wert + "\n"
    if roh.get("login") and roh["login"].get("password"):
        return s.klar(roh["login"]["password"], eintrag=roh)

    notiz = s.klar(roh.get("notes"), eintrag=roh)
    laenge = _feld(s, eintrag, "laenge")
    if laenge and laenge.isdigit():
        return notiz[:int(laenge)]
    # Aelterer Eintrag ohne Laengenangabe: dann bleibt nur die Leerzeile,
    # und ein abschliessender Umbruch kann dabei verlorengehen.
    return notiz.split("\n\n")[0]


def env_befehl(s, argv):
    if "--" not in argv:
        raise VwFehler("Aufbau: vw_zugang.py env NAME[=VAR] ... -- BEFEHL")
    schnitt = argv.index("--")
    wuensche, befehl = argv[:schnitt], argv[schnitt + 1:]
    if not befehl:
        raise VwFehler("Kein Befehl nach --.")

    nach_kennung = {}
    nach_namen = {}
    for e in s.eintraege():
        for feldname in ("kennung", "tresor-name"):
            kn = _feld(s, e["roh"], feldname)
            if kn:
                nach_kennung.setdefault(kn.lower(), e)
        nach_namen[e["name"].lower()] = e

    umgebung = dict(os.environ)
    umgebung.pop("VW_PASSWORT", None)      # gehoert nicht weitergereicht
    for wunsch in wuensche:
        name, _, var = wunsch.partition("=")
        # NAME.feld holt statt des Passworts ein Feld: .user, .uri oder ein
        # benutzerdefiniertes Feld (z. B. mein-eintrag.MEIN_FELD).
        teil = None
        if name.lower() not in nach_kennung and name.lower() not in nach_namen and "." in name:
            name, _, teil = name.partition(".")
        var = var or re.sub(r"[^A-Z0-9_]", "_", (name + ("_" + teil if teil else "")).upper())
        e = nach_kennung.get(name.lower()) or nach_namen.get(name.lower())
        if not e:
            raise VwFehler("„%s“ gibt es hier nicht." % name)
        roh = e["roh"]
        if teil is None:
            wert = wert_von(s, roh)
        elif teil == "user":
            wert = s.klar((roh.get("login") or {}).get("username"), eintrag=roh)
        elif teil == "uri":
            uris = (roh.get("login") or {}).get("uris") or []
            wert = s.klar(uris[0]["uri"], eintrag=roh) if uris else None
        else:
            wert = _feld(s, roh, teil)
        if not wert:
            raise VwFehler("„%s“ hat keinen verwertbaren Wert." % wunsch.partition("=")[0])
        umgebung[var] = wert

    return subprocess.call(befehl, env=umgebung)


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "hilfe"):
        print(HILFE)
        return 1
    befehl, rest = argv[0], argv[1:]
    try:
        s = Sitzung(neu="--neu-anmelden" in rest)
        if befehl == "lage":
            p = s.sync()["profile"]
            print("Konto      :", p["email"])
            for o in p.get("organizations") or []:
                print("Organisation: %s  (Rolle %s, Status %s)"
                      % (o["name"], o["type"], o["status"]))
            print("Sammlungen :")
            for c in s.sammlungen() or [{"name": "(keine zugewiesen)", "id": "", "readOnly": ""}]:
                print("  %-38s %s %s" % (c["name"], c["id"], "nur lesbar" if c["readOnly"] else ""))
            print("Einträge   :", len(s.eintraege()))

        elif befehl == "liste":
            for e in sorted(s.eintraege(), key=lambda x: x["name"].lower()):
                kn = _feld(s, e["roh"], "kennung") or _feld(s, e["roh"], "tresor-name")
                typ = {1: "Login", 2: "Notiz", 5: "SSH"}.get(e["type"], str(e["type"]))
                print("  %-58s %-6s %s" % (e["name"], typ, kn or ""))

        elif befehl == "env":
            return env_befehl(s, rest)

        else:
            raise VwFehler("Unbekannter Befehl: %s" % befehl)

    except VwFehler as exc:
        print("Fehler: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
