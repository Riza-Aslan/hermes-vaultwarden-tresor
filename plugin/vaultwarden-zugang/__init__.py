"""Vaultwarden-Zugang — registriert nichts bei Hermes selbst.

Das eigentliche Werkzeug ist vw_zugang.py, das der Agent ueber sein normales
Terminal-Werkzeug aufruft - absichtlich kein
Hermes-Tool mit eigenem Rueckgabewert, damit ein Geheimnis nie durch eine
Tool-Antwort in den sichtbaren Kontext laufen kann.
"""

def register(ctx):
    pass
