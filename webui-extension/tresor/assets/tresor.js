(() => {
  'use strict';

  // ── Tresor: Vaultwarden-Sammlung in der Hermes-WebUI ───────────
  // Spricht nur mit dem eigenen Sidecar über den Proxy der WebUI
  // (/api/extensions/tresor/sidecar/…). Geheimnisse kommen nie mit der Liste
  // oder dem Detail, sondern einzeln auf Klick (Anzeigen/Kopieren) und werden
  // nach 30 Sekunden wieder verdeckt.

  if (window.__hermesTresorLoaded) return;
  window.__hermesTresorLoaded = true;

  const API = '/api/extensions/tresor/sidecar/api';
  const RAIL_ID = 'htrRailBtn';
  const MOBIL_ID = 'htrMobilBtn';
  const OV_ID = 'htrOverlay';
  let VW_URL = '#';   // kommt vom Sidecar (VW_BASIS)
  const VERDECKEN_MS = 30000;
  const SVG = (pfad) => '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + pfad + '</svg>';
  const TYP = {
    login: { name: 'Login', svg: SVG('<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M17 6l3 3M14 9l2 2"/>') },
    ssh: { name: 'SSH-Schlüssel', svg: SVG('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>') },
    notiz: { name: 'Notiz', svg: SVG('<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>') },
    karte: { name: 'Karte', svg: SVG('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>') },
    identitaet: { name: 'Identität', svg: SVG('<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>') },
  };
  function typSymbol(t, klasse) {
    const s = el('span', { class: klasse, title: t.name });
    s.innerHTML = t.svg;            // feste SVG-Konstante, kein Inhalt aus Vaultwarden
    return s;
  }

  const z = { offen: false, liste: [], suche: '', aktiv: null, detail: null, info: null, ansicht: 'liste', laedt: false };

  // ── Helfer ───────────────────────────────────────────────────────────────
  function el(tag, attrs, ...kinder) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'value') n.value = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kinder.flat()) {
      if (k == null || k === false) continue;
      n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
    }
    return n;
  }
  function rein(eltern, ...kinder) { for (const k of kinder.flat()) if (k != null && k !== false) eltern.append(k); }

  async function api(pfad, body) {
    const init = { method: body === undefined ? 'GET' : 'POST', headers: {}, credentials: 'same-origin' };
    if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    let r;
    try { r = await fetch(API + pfad, init); } catch (_) { throw new Error('Tresordienst nicht erreichbar.'); }
    let d = null;
    try { d = await r.json(); } catch (_) {}
    if (!r.ok) {
      const t = (d && (d.fehler || d.error)) || ('HTTP ' + r.status);
      if (r.status === 403 && /consent/i.test(t)) throw new Error('Proxy zum Tresordienst nicht freigegeben (Einstellungen → Erweiterungen → Tresor).');
      if (r.status === 502) throw new Error('Tresordienst antwortet nicht (hermes-tresor.service läuft?).');
      throw new Error(t);
    }
    return d;
  }

  function zeit(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
  }
  function hinweis(text, art) {
    const ov = document.getElementById(OV_ID);
    if (!ov) return;
    const box = ov.querySelector('.htr-toast');
    box.textContent = text;
    box.className = 'htr-toast sichtbar ' + (art || '');
    clearTimeout(box._t);
    box._t = setTimeout(() => { box.className = 'htr-toast'; }, art === 'fehler' ? 8000 : 3500);
  }
  function icon() {
    return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/>' +
      '<path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1.2"/></svg>';
  }
  function kennungAus(name) {
    return (name || '').toLowerCase().replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  }
  function passwortErzeugen(laenge) {
    const zeichen = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.:+=!?';
    const zahlen = new Uint32Array(laenge);
    crypto.getRandomValues(zahlen);
    let s = '';
    for (const n of zahlen) s += zeichen[n % zeichen.length];
    return s;
  }

  // Zwischenablage: Wert nur für den Moment holen, kopieren, nach 30 s
  // versuchen zu leeren (klappt nur, solange die Seite den Fokus hat).
  async function kopiere(wert, was) {
    try {
      await navigator.clipboard.writeText(wert);
    } catch (_) {
      const t = el('textarea', { value: wert, style: 'position:fixed;opacity:0' });
      document.body.appendChild(t); t.select();
      try { document.execCommand('copy'); } finally { t.remove(); }
    }
    hinweis((was || 'Wert') + ' kopiert. Wird in 30 s aus der Zwischenablage entfernt.');
    clearTimeout(kopiere._t);
    kopiere._t = setTimeout(async () => {
      try { if ((await navigator.clipboard.readText()) === wert) await navigator.clipboard.writeText(''); } catch (_) {
        try { await navigator.clipboard.writeText(''); } catch (__) {}
      }
    }, VERDECKEN_MS);
  }
  async function holeGeheim(id, feld) {
    const d = await api('/geheim?id=' + encodeURIComponent(id) + '&feld=' + encodeURIComponent(feld));
    return d.wert || '';
  }

  // ── Leiste ───────────────────────────────────────────────────────────────
  function railKnopf() {
    let b = document.getElementById(RAIL_ID);
    if (b) return b;
    const rail = document.querySelector('.rail');
    if (!rail) return null;
    b = document.createElement('button');
    b.id = RAIL_ID; b.type = 'button';
    b.className = 'rail-btn nav-tab has-tooltip htr-rail';
    b.dataset.tooltip = 'Tresor (Vaultwarden)';
    b.setAttribute('aria-label', 'Tresor');
    b.innerHTML = icon();
    b.addEventListener('click', (e) => { e.preventDefault(); z.offen ? schliessen() : oeffnen(); });
    const spacer = rail.querySelector('.rail-spacer');
    spacer ? rail.insertBefore(b, spacer) : rail.appendChild(b);
    return b;
  }
  function menueKnopf() {
    let b = document.getElementById(MOBIL_ID);
    if (b) return b;
    const nav = document.querySelector('.sidebar > .sidebar-nav') || document.querySelector('.sidebar-nav');
    if (!nav) return null;
    b = document.createElement('button');
    b.id = MOBIL_ID; b.type = 'button';
    b.className = 'nav-tab has-tooltip has-tooltip--bottom htr-rail';
    b.dataset.label = 'Tresor'; b.dataset.tooltip = 'Tresor';
    b.setAttribute('aria-label', 'Tresor');
    b.innerHTML = icon().replace(/20/g, '18');
    b.addEventListener('click', (e) => {
      e.preventDefault();
      if (typeof window.closeMobileSidebar === 'function') { try { window.closeMobileSidebar(); } catch (_) {} }
      oeffnen();
    });
    const settings = nav.querySelector('[data-panel="settings"]');
    settings ? nav.insertBefore(b, settings) : nav.appendChild(b);
    return b;
  }

  // Wie bei Post: ein anderer Leisten-Klick schließt den Tresor; trifft er den
  // schon aktiven Kern-Tab, wird nur geschlossen (kein Einklappen).
  function leistenKlick(e) {
    const b = e.target.closest && e.target.closest('.rail .nav-tab, .rail .rail-btn, .sidebar-nav .nav-tab');
    if (!b || !z.offen || b.id === RAIL_ID || b.id === MOBIL_ID) return;
    schliessen();
    if (b.dataset.panel && b.classList.contains('active')) { e.preventDefault(); e.stopImmediatePropagation(); }
  }

  // ── Gerüst ───────────────────────────────────────────────────────────────
  function geruest() {
    let ov = document.getElementById(OV_ID);
    if (ov) return ov;
    const suche = el('input', { class: 'htr-input htr-suche', type: 'search', placeholder: 'Suchen: Name, Kennung, Benutzer, Adresse …',
      'aria-label': 'Suchen', oninput: () => { z.suche = suche.value; listeZeichnen(); } });
    ov = el('div', { id: OV_ID, class: 'htr-overlay' },
      el('div', { class: 'htr-bar' },
        el('button', { type: 'button', class: 'htr-btn htr-zurueck', title: 'Zurück zur Liste', onclick: () => ansicht('liste') }, '‹'),
        el('div', { class: 'htr-titel' }, el('strong', { text: 'Tresor' }), el('span', { class: 'htr-unter' })),
        suche,
        el('button', { type: 'button', class: 'htr-btn primaer', title: 'Neuer Eintrag', onclick: () => formular(null) }, '+ Neu'),
        el('button', { type: 'button', class: 'htr-btn', title: 'Neu abgleichen', onclick: () => listeHolen(true) }, '↻'),
        el('a', { class: 'htr-btn htr-vwlink', href: VW_URL, target: '_blank', rel: 'noopener', title: 'Vaultwarden im neuen Tab öffnen' }, 'Vaultwarden ↗'),
        el('button', { type: 'button', class: 'htr-btn', title: 'Schließen (Esc)', 'aria-label': 'Schließen', onclick: schliessen }, '✕')),
      el('div', { class: 'htr-main' }, el('section', { class: 'htr-liste' }), el('article', { class: 'htr-detail' })),
      el('div', { class: 'htr-toast', role: 'status' }));
    document.body.appendChild(ov);
    return ov;
  }
  function ansicht(a) { z.ansicht = a; const ov = document.getElementById(OV_ID); if (ov) ov.dataset.ansicht = a; }

  // ── Liste ────────────────────────────────────────────────────────────────
  async function listeHolen(frisch) {
    const box = geruest().querySelector('.htr-liste');
    if (!z.liste.length) { box.textContent = ''; box.appendChild(el('div', { class: 'htr-leer', text: 'lädt …' })); }
    try {
      const d = await api('/liste' + (frisch ? '?frisch=1' : ''));
      z.liste = d.eintraege || [];
      if (d.server) { VW_URL = d.server; const l = geruest().querySelector('.htr-vwlink'); if (l) l.href = d.server; }
      z.info = d;
      geruest().querySelector('.htr-unter').textContent = 'Sammlung „' + d.sammlung + '“ · ' + z.liste.length + ' Einträge' + (d.schreibbar ? '' : ' · nur lesbar');
      listeZeichnen();
      if (frisch) hinweis('Neu abgeglichen.');
    } catch (e) {
      box.textContent = '';
      box.appendChild(el('div', { class: 'htr-leer fehler', text: e.message }));
    }
  }

  function passt(e, q) {
    if (!q) return true;
    const t = (e.name + ' ' + e.kennung + ' ' + e.user + ' ' + e.uri).toLowerCase();
    return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => t.includes(w));
  }

  function listeZeichnen() {
    const box = geruest().querySelector('.htr-liste');
    box.textContent = '';
    const treffer = z.liste.filter((e) => passt(e, z.suche));
    if (!treffer.length) { box.appendChild(el('div', { class: 'htr-leer', text: z.suche ? 'Keine Treffer.' : 'Keine Einträge.' })); return; }
    let gruppe = null;
    for (const e of treffer) {
      if (e.gruppe !== gruppe) {
        gruppe = e.gruppe;
        box.appendChild(el('div', { class: 'htr-gruppe', text: gruppe }));
      }
      const rest = e.name.includes(':') ? e.name.split(':').slice(1).join(':').trim() : e.name;
      const t = TYP[e.typ] || TYP.notiz;
      box.appendChild(el('button', { type: 'button', class: 'htr-zeile' + (z.aktiv === e.id ? ' aktiv' : ''), title: e.name,
        onclick: () => zeigen(e.id) },
        typSymbol(t, 'htr-typ'),
        el('span', { class: 'htr-zeile-text' },
          el('span', { class: 'htr-zeile-name', text: rest }),
          el('span', { class: 'htr-zeile-unter', text: [e.kennung, e.user].filter(Boolean).join(' · ') }))));
    }
  }

  // ── Detail ───────────────────────────────────────────────────────────────
  function leer() {
    const box = geruest().querySelector('.htr-detail');
    box.textContent = '';
    box.appendChild(el('div', { class: 'htr-leer' },
      el('p', { text: 'Eintrag auswählen.' }),
      el('p', { class: 'htr-klein', text: 'Namensschema: „System: Was (Detail)“. Jeder Eintrag hat eine Kennung, über die der Agent ihn findet.' })));
  }

  async function zeigen(id) {
    z.aktiv = id;
    listeZeichnen();
    ansicht('detail');
    const box = geruest().querySelector('.htr-detail');
    box.textContent = '';
    box.appendChild(el('div', { class: 'htr-leer', text: 'lädt …' }));
    const zeile = document.querySelector('.htr-zeile.aktiv');
    if (zeile) zeile.scrollIntoView({ block: 'nearest' });
    try { z.detail = await api('/eintrag?id=' + encodeURIComponent(id)); }
    catch (e) { box.textContent = ''; box.appendChild(el('div', { class: 'htr-leer fehler', text: e.message })); return; }
    detailZeichnen(z.detail);
  }

  function knopf(text, fn, art, titel) {
    return el('button', { type: 'button', class: 'htr-btn ' + (art || ''), title: titel || null, onclick: fn }, text);
  }

  // Eine Zeile mit offenem Wert und Kopierknopf
  function zeileOffen(label, wert, extra) {
    if (!wert) return null;
    return el('div', { class: 'htr-feld' },
      el('div', { class: 'htr-label', text: label }),
      el('div', { class: 'htr-wert' }, el('span', { class: 'htr-text', text: wert }),
        el('span', { class: 'htr-aktionen' }, extra || null, knopf('Kopieren', () => kopiere(wert, label)))));
  }

  // Eine Zeile mit verdecktem Wert: Anzeigen / Kopieren holen ihn erst jetzt
  function zeileGeheim(label, id, feld, opt) {
    opt = opt || {};
    const anzeige = el(opt.mehrzeilig ? 'pre' : 'span', { class: 'htr-text htr-verdeckt' + (opt.mehrzeilig ? ' htr-pre' : ''), text: '••••••••••••' });
    let offen = false, timer = null;
    const zeig = knopf('Anzeigen', async () => {
      if (offen) { verdecken(); return; }
      try {
        const w = await holeGeheim(id, feld);
        anzeige.textContent = w || '(leer)';
        anzeige.classList.remove('htr-verdeckt');
        zeig.textContent = 'Verbergen';
        offen = true;
        clearTimeout(timer);
        timer = setTimeout(verdecken, VERDECKEN_MS);
      } catch (e) { hinweis(e.message, 'fehler'); }
    });
    function verdecken() {
      anzeige.textContent = '••••••••••••';
      anzeige.classList.add('htr-verdeckt');
      zeig.textContent = 'Anzeigen';
      offen = false;
      clearTimeout(timer);
    }
    const kop = knopf('Kopieren', async () => {
      try { await kopiere(await holeGeheim(id, feld), label); } catch (e) { hinweis(e.message, 'fehler'); }
    });
    const extra = opt.datei ? knopf('Als Datei', async () => {
      try {
        const w = await holeGeheim(id, feld);
        const a = el('a', { href: URL.createObjectURL(new Blob([w], { type: 'application/octet-stream' })), download: opt.datei });
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      } catch (e) { hinweis(e.message, 'fehler'); }
    }, '', 'Privaten Schlüssel als Datei herunterladen') : null;
    return el('div', { class: 'htr-feld' + (opt.mehrzeilig ? ' breit' : '') },
      el('div', { class: 'htr-label', text: label }),
      el('div', { class: 'htr-wert' }, anzeige, el('span', { class: 'htr-aktionen' }, zeig, kop, extra)));
  }

  function detailZeichnen(d) {
    const box = geruest().querySelector('.htr-detail');
    box.textContent = '';
    const t = TYP[d.typ] || TYP.notiz;
    const kopf = el('div', { class: 'htr-kopf' },
      el('h2', { class: 'htr-h', text: d.name }),
      el('div', { class: 'htr-chips' },
        el('span', { class: 'htr-chip' }, typSymbol(t, 'htr-chip-symbol'), t.name),
        d.kennung ? el('button', { type: 'button', class: 'htr-chip htr-chip-knopf', title: 'Kennung kopieren',
          onclick: () => kopiere(d.kennung, 'Kennung') }, 'Kennung: ', el('code', { text: d.kennung })) : null));
    const aktionen = el('div', { class: 'htr-leiste' });
    if (['login', 'ssh', 'notiz'].includes(d.typ) && z.info && z.info.schreibbar) {
      aktionen.append(knopf('Bearbeiten', () => formular(d), 'primaer'),
        knopf('In den Papierkorb', () => papierkorb(d), 'gefahr', 'Landet im Papierkorb von Vaultwarden und lässt sich dort wiederherstellen.'));
    } else if (!['login', 'ssh', 'notiz'].includes(d.typ)) {
      aktionen.append(el('span', { class: 'htr-klein', text: 'Diese Art bitte direkt in Vaultwarden bearbeiten.' }));
    }
    const felder = el('div', { class: 'htr-felder' });
    if (d.typ === 'login') {
      rein(felder, zeileOffen('Benutzer', d.user));
      if (d.hat_pw) felder.append(zeileGeheim('Passwort', d.id, 'pw'));
      if (d.hat_totp) felder.append(zeileGeheim('TOTP-Schlüssel', d.id, 'totp'));
      for (const u of d.uris || []) {
        const offen = /^https?:\/\//i.test(u) ? el('a', { class: 'htr-btn', href: u, target: '_blank', rel: 'noopener noreferrer' }, 'Öffnen ↗') : null;
        felder.append(zeileOffen(d.uris.length > 1 ? 'Adresse' : 'Adresse', u, offen));
      }
    }
    if (d.typ === 'ssh') {
      rein(felder, zeileOffen('Fingerabdruck', d.ssh_fp), zeileOffen('Öffentlicher Schlüssel', d.ssh_pub));
      if (d.hat_priv) {
        const datei = (d.felder.find((f) => f.name === 'datei') || {}).wert || '';
        felder.append(zeileGeheim('Privater Schlüssel', d.id, 'priv', { mehrzeilig: true, datei: (datei.split('/').pop() || 'id_' + (d.kennung || 'schluessel')) }));
      }
    }
    for (const f of d.felder || []) {
      felder.append(f.verborgen ? zeileGeheim(f.name, d.id, 'feld:' + f.name) : zeileOffen(f.name, f.wert));
    }
    rein(box, kopf, aktionen, felder);
    if (d.notiz) rein(box, el('div', { class: 'htr-label htr-abstand', text: 'Notiz' }), el('pre', { class: 'htr-notiz', text: d.notiz }));
    rein(box, el('div', { class: 'htr-meta' },
      d.geaendert ? el('span', { text: 'Geändert ' + zeit(d.geaendert) }) : null,
      d.erstellt ? el('span', { text: 'Angelegt ' + zeit(d.erstellt) }) : null,
      d.pw_verlauf ? el('span', { text: d.pw_verlauf + ' frühere Passwörter in Vaultwarden' }) : null),
      d.kennung ? el('div', { class: 'htr-agent' },
        el('span', { class: 'htr-klein', text: 'So nutzt der Agent ihn: ' }),
        el('code', { text: 'vw_zugang.py env ' + d.kennung + '=VAR -- befehl' })) : null);
  }

  async function papierkorb(d) {
    if (!confirm('„' + d.name + '“ in den Papierkorb legen?\n\nIn Vaultwarden unter „Papierkorb“ lässt er sich wiederherstellen. ' +
      'Werkzeuge, die die Kennung „' + (d.kennung || '–') + '“ nutzen, finden ihn danach nicht mehr.')) return;
    try {
      await api('/papierkorb', { id: d.id });
      hinweis('Im Papierkorb.');
      z.aktiv = null; z.detail = null; leer(); ansicht('liste');
      await listeHolen(true);
    } catch (e) { hinweis(e.message, 'fehler'); }
  }

  // ── Formular: neu oder bearbeiten ────────────────────────────────────────
  function feld(label, eingabe, hilfe) {
    return el('label', { class: 'htr-form-feld' }, el('span', { text: label }), eingabe, hilfe ? el('small', { text: hilfe }) : null);
  }

  function formular(d) {
    const neu = !d;
    ansicht('detail');
    const box = geruest().querySelector('.htr-detail');
    box.textContent = '';
    let typ = neu ? 'login' : d.typ;
    let kennungAngefasst = !neu;

    const name = el('input', { class: 'htr-input', value: neu ? '' : d.name, placeholder: 'System: Was (Detail)', maxlength: '200' });
    const kennung = el('input', { class: 'htr-input htr-mono', value: neu ? '' : d.kennung, placeholder: 'wird aus dem Namen gebildet', maxlength: '80' });
    name.addEventListener('input', () => { if (!kennungAngefasst) kennung.value = kennungAus(name.value); });
    kennung.addEventListener('input', () => { kennungAngefasst = true; });

    // Login
    const user = el('input', { class: 'htr-input', value: neu ? '' : (d.user || ''), autocomplete: 'off' });
    const pw = el('input', { class: 'htr-input htr-mono', type: 'password', autocomplete: 'new-password',
      placeholder: neu ? '' : (d.hat_pw ? 'unverändert lassen' : 'leer') });
    let pwGeaendert = false;
    pw.addEventListener('input', () => { pwGeaendert = true; });
    const pwZeigen = knopf('👁', () => { pw.type = pw.type === 'password' ? 'text' : 'password'; }, '', 'Anzeigen');
    const pwNeu = knopf('Erzeugen', () => { pw.value = passwortErzeugen(24); pw.type = 'text'; pwGeaendert = true; }, '', '24 Zeichen, zufällig');
    const uris = el('textarea', { class: 'htr-input htr-mono', rows: '3', placeholder: 'https://… (eine pro Zeile)' });
    uris.value = neu ? '' : (d.uris || []).join('\n');

    // SSH
    const sshArt = neu ? 'erzeugen' : 'behalten';
    const sshWahl = el('select', { class: 'htr-input' },
      neu ? null : el('option', { value: 'behalten', text: 'Schlüssel behalten' }),
      el('option', { value: 'erzeugen', text: 'Neuen Schlüssel erzeugen (ed25519)' }),
      el('option', { value: 'einfuegen', text: 'Privaten Schlüssel einfügen' }));
    sshWahl.value = sshArt;
    const sshPriv = el('textarea', { class: 'htr-input htr-mono', rows: '6', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' });
    const sshKommentar = el('input', { class: 'htr-input', placeholder: 'Kommentar im öffentlichen Schlüssel (optional)' });

    // Zusatzfelder
    const zf = el('div', { class: 'htr-zf' });
    function zfZeile(f) {
      const n = el('input', { class: 'htr-input', value: f ? f.name : '', placeholder: 'Feldname' });
      const w = el('input', { class: 'htr-input htr-mono', value: f && !f.verborgen ? f.wert : '',
        placeholder: f && f.verborgen ? 'unverändert lassen' : 'Wert', type: f && f.verborgen ? 'password' : 'text' });
      const v = el('input', { type: 'checkbox' });
      v.checked = !!(f && f.verborgen);
      v.addEventListener('change', () => { w.type = v.checked ? 'password' : 'text'; });
      let wAngefasst = false;
      w.addEventListener('input', () => { wAngefasst = true; });
      const zeile = el('div', { class: 'htr-zf-zeile' }, n, w,
        el('label', { class: 'htr-check', title: 'Verborgen (wie ein Passwort)' }, v, 'verborgen'),
        knopf('✕', () => zeile.remove(), '', 'Feld entfernen'));
      zeile._lies = () => ({ name: n.value.trim(), verborgen: v.checked,
        wert: (f && f.verborgen && !wAngefasst) ? null : w.value });
      zf.append(zeile);
    }
    if (!neu) (d.felder || []).forEach(zfZeile);

    const notiz = el('textarea', { class: 'htr-input', rows: '5', placeholder: 'Erklärung – nie ein Geheimnis hier hinein' });
    notiz.value = neu ? '' : (d.notiz || '');
    const fehler = el('div', { class: 'htr-fehler', hidden: true });

    const typWahl = neu ? el('div', { class: 'htr-typwahl' },
      ['login', 'ssh', 'notiz'].map((t) => el('button', { type: 'button', class: 'htr-btn' + (t === typ ? ' aktiv' : ''), 'data-typ': t,
        onclick: (ev) => { typ = t; typWahl.querySelectorAll('button').forEach((b) => b.classList.toggle('aktiv', b.dataset.typ === t)); bereiche(); } },
        typSymbol(TYP[t], 'htr-chip-symbol'), TYP[t].name))) : null;

    const bLogin = el('div', { class: 'htr-bereich' },
      feld('Benutzer', user),
      feld('Passwort', el('div', { class: 'htr-reihe' }, pw, pwZeigen, pwNeu), neu ? null : 'Leer lassen = unverändert. Ein geändertes Passwort wandert in den Verlauf.'),
      feld('Adressen', uris));
    const sshEinfuegen = feld('Privater Schlüssel', sshPriv, 'Öffentlicher Schlüssel und Fingerabdruck werden daraus berechnet.');
    const sshErzeugen = feld('Kommentar', sshKommentar);
    const bSsh = el('div', { class: 'htr-bereich' }, feld('Schlüssel', sshWahl), sshEinfuegen, sshErzeugen);
    function bereiche() {
      bLogin.hidden = typ !== 'login';
      bSsh.hidden = typ !== 'ssh';
      sshEinfuegen.hidden = sshWahl.value !== 'einfuegen';
      sshErzeugen.hidden = sshWahl.value !== 'erzeugen';
    }
    sshWahl.addEventListener('change', bereiche);
    bereiche();

    const speichern = knopf(neu ? 'Anlegen' : 'Speichern', async () => {
      fehler.hidden = true;
      const daten = { typ, name: name.value, kennung: kennung.value, notiz: notiz.value,
        felder: [...zf.children].map((r) => r._lies()).filter((f) => f.name) };
      if (!neu) daten.id = d.id;
      if (typ === 'login') {
        daten.login = { user: user.value, uris: uris.value.split('\n').map((s) => s.trim()).filter(Boolean),
          pw: neu ? pw.value : (pwGeaendert && pw.value !== '' ? pw.value : null) };
      }
      if (typ === 'ssh') {
        if (sshWahl.value === 'erzeugen') daten.ssh = { erzeugen: true, kommentar: sshKommentar.value || kennung.value };
        else if (sshWahl.value === 'einfuegen') daten.ssh = { priv: sshPriv.value };
        else daten.ssh = {};
        if (!neu && sshWahl.value === 'erzeugen' && !confirm('Wirklich einen NEUEN Schlüssel erzeugen? Der alte ist danach weg – überall, wo er hinterlegt ist, funktioniert der Zugang nicht mehr.')) return;
      }
      speichern.disabled = true;
      try {
        const r = await api('/speichern', daten);
        hinweis(neu ? 'Angelegt.' : 'Gespeichert.');
        await listeHolen(true);
        await zeigen(r.id);
      } catch (e) { fehler.hidden = false; fehler.textContent = e.message; speichern.disabled = false; }
    }, 'primaer');

    rein(box,
      el('h2', { class: 'htr-h', text: neu ? 'Neuer Eintrag' : 'Bearbeiten' }),
      typWahl,
      el('div', { class: 'htr-form' },
        feld('Name', name, 'Schema „System: Was (Detail)“, z. B. „Server: root“ oder „Postfach: support@example.org“.'),
        feld('Kennung', kennung, 'Darüber findet der Agent den Eintrag. Ändern bricht Werkzeuge, die die alte nutzen.'),
        bLogin, bSsh,
        el('div', { class: 'htr-form-feld' }, el('span', { text: 'Zusatzfelder' }), zf,
          knopf('+ Feld', () => zfZeile(null))),
        feld('Notiz', notiz)),
      fehler,
      el('div', { class: 'htr-leiste' }, speichern,
        knopf('Abbrechen', () => { if (neu) { leer(); ansicht('liste'); } else zeigen(d.id); })));
    name.focus();
  }

  // ── Öffnen / Schließen ───────────────────────────────────────────────────
  function oeffnen() {
    const ov = geruest();
    ov.style.display = 'flex';
    z.offen = true;
    ansicht(z.detail ? z.ansicht : 'liste');
    for (const id of [RAIL_ID, MOBIL_ID]) { const b = document.getElementById(id); if (b) b.classList.add('active'); }
    document.addEventListener('keydown', esc, true);
    if (!z.detail) leer();
    listeHolen(false);
    setTimeout(() => { if (window.matchMedia('(min-width: 901px)').matches) ov.querySelector('.htr-suche').focus(); }, 50);
  }
  function schliessen() {
    const ov = document.getElementById(OV_ID);
    if (ov) ov.style.display = 'none';
    z.offen = false;
    for (const id of [RAIL_ID, MOBIL_ID]) { const b = document.getElementById(id); if (b) b.classList.remove('active'); }
    document.removeEventListener('keydown', esc, true);
    // Beim Schließen alles Aufgedeckte vergessen
    z.detail = null; z.aktiv = null;
    const box = ov && ov.querySelector('.htr-detail');
    if (box) box.textContent = '';
  }
  function esc(e) { if (e.key === 'Escape') { e.stopPropagation(); schliessen(); } }

  function start(versuch) {
    versuch = versuch || 0;
    if (!document.querySelector('.rail')) {
      if (versuch < 80) setTimeout(() => start(versuch + 1), 150);
      return;
    }
    railKnopf();
    menueKnopf();
    document.addEventListener('click', leistenKlick, true);
    window.HermesTresor = { oeffnen, schliessen };
    // Der frühere, fest eingebaute Tresor ruft vzOeffnen() – umleiten, bis
    // seine Knöpfe nach dem nächsten WebUI-Neustart verschwunden sind.
    window.vzOeffnen = oeffnen;
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => start(), { once: true });
  else start();
})();
