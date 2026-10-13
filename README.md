# hermes-vaultwarden-tresor

Vaultwarden für [Hermes Agent](https://github.com/NousResearch/hermes-agent) und die
[hermes-webui](https://github.com/nesquena/hermes-webui) — in zwei Teilen, die zusammen oder einzeln laufen:

| Teil | Was er tut |
|---|---|
| **`plugin/vaultwarden-zugang`** | Agenten-Plugin: Hermes holt einzelne Einträge zur Laufzeit und reicht sie **nur in die Umgebung eines Unterbefehls** weiter. Es gibt absichtlich keinen Befehl, der einen Wert ausgibt. |
| **`webui-extension/tresor` + `sidecar`** | Seitenleisten-Ansicht „Tresor" in der WebUI: Einträge einer Sammlung ansehen, kopieren, anlegen, bearbeiten, in den Papierkorb legen. Geheimnisse kommen erst auf Klick. |

> **English in short:** A Hermes Agent plugin plus a hermes-webui sidebar extension that talk to a
> Vaultwarden (Bitwarden-compatible) server using only the Python standard library and `openssl`.
> The agent can inject a secret into a subprocess environment without it ever appearing in chat;
> the web UI lets you browse and edit one collection. Code comments and UI strings are in German.

Unabhängiges Hobbyprojekt, nicht mit Bitwarden, Vaultwarden oder Nous Research verbunden.

## Wichtig vorab

- **Die Kryptografie ist von Hand nachgebaut** (Schlüsselableitung, EncString Typ 2, RSA für Organisationsschlüssel),
  weil keine `bw`-CLI nötig sein sollte. Sie ist nicht von Dritten geprüft. Nutze ein **eigenes Dienstkonto**
  mit einer **eigenen Sammlung**, nicht dein persönliches Konto mit dem ganzen Tresor.
- **Das Hauptpasswort dieses Kontos liegt in `~/.hermes/.env`** (nur für den Hermes-Benutzer lesbar, `chmod 600`).
  Wer diese Datei lesen kann, kommt an die Sammlung.
- **Werte kommen im Klartext beim Agenten-Prozess an**, sobald ein Unterbefehl sie liest. Das Plugin verhindert nur,
  dass sie selbst im Chat landen. Was dein Befehl danach ausgibt (`echo $SECRET`), schützt es nicht.
  Eine Maskierung im Gesprächsverlauf gibt es nicht.
- Schreiben (anlegen, ändern) funktioniert gegen den Server, mit dem es entwickelt wurde (API-Kompatibilität 2026.6.0).
  Neuere Vaultwarden-Versionen verlangen beim Anlegen das Feld `encryptedFor` im Cipher-Objekt; das ist eingebaut.
  Andere Versionen sind ungetestet.
- Eine Sammlung muss dem Dienstkonto mit Schreibrecht zugewiesen sein, sonst bleibt die Ansicht schreibgeschützt.

## Einrichtung

Voraussetzungen: Hermes Agent, hermes-webui, Python 3, `openssl`, ein Vaultwarden-Server.

### 1. Zugangsdaten in `~/.hermes/.env`

```
VW_BASIS=https://vault.example.org
VW_EMAIL=hermes@example.org
VW_PASSWORT=…Hauptpasswort des Dienstkontos…
VW_SAMMLUNG=Hermes
# Nur bei eigener CA (empfohlen statt TLS-Prüfung abzuschalten):
# VW_CA_FILE=/pfad/zur/ca.pem
# Selbst erzeugte CA, Python 3.13 meldet "Basic Constraints of CA cert not marked critical":
# VW_TLS_RELAXED=1        (Kette und Hostname werden weiter geprüft)
# Notfall, schaltet die Zertifikatsprüfung ganz ab:
# VW_TLS_INSECURE=1
```

```
chmod 600 ~/.hermes/.env
```

### 2. Agenten-Plugin

```
cp -r plugin/vaultwarden-zugang ~/.hermes/plugins/
hermes plugins enable vaultwarden-zugang
```

Benutzung (Hermes ruft das über sein Terminal-Werkzeug auf):

```
python3 ~/.hermes/plugins/vaultwarden-zugang/vw_zugang.py liste
python3 ~/.hermes/plugins/vaultwarden-zugang/vw_zugang.py env mein-eintrag=MEIN_PW -- curl -u "admin:$MEIN_PW" https://…
```

`NAME` ist der Anzeigename oder ein Zusatzfeld `kennung` im Eintrag. `NAME.user`, `NAME.uri` und `NAME.<feld>`
liefern Benutzername, erste URI oder ein Zusatzfeld statt des Passworts. Bei SSH-Einträgen ist der Wert der private Schlüssel.
Es empfiehlt sich, Hermes das in `MEMORY.md` mitzuteilen, damit er den Zugang von sich aus nutzt.

### 3. WebUI-Erweiterung (optional)

```
cp -r sidecar ~/tresor
cp ~/tresor/hermes-tresor.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hermes-tresor
loginctl enable-linger "$USER"        # damit der Dienst ohne Anmeldung läuft

cp -r webui-extension/tresor ~/.hermes/webui/extensions/
```

Danach in der WebUI unter **Einstellungen → Extensions** die Sidecar-Freigabe für „Tresor" erteilen.
Dabei legt die WebUI das Token an (`~/.hermes/webui/sidecar-auth/tresor.token`), das der Sidecar bei jeder Anfrage prüft.
Der Sidecar lauscht nur auf `127.0.0.1:17831`. Nach Änderungen an den Assets die `?v=` in `manifest.json` hochzählen.

## Update-Festigkeit

Alles liegt in Ordnern, die Hermes- und WebUI-Updates nicht anfassen (`~/.hermes/plugins`, `~/.hermes/webui/extensions`,
`~/tresor`). Am WebUI-Kern wird nichts geändert.

## Konto wechseln

`VW_EMAIL` und `VW_PASSWORT` in `.env` ändern, dann `~/.hermes/plugins/vaultwarden-zugang/sitzung.json` löschen
(sonst bleibt die alte Anmeldung gespeichert) und den Sidecar neu starten.

## Lizenz

MIT, siehe [LICENSE](LICENSE). Nutzung auf eigene Gefahr, keine Gewährleistung.
