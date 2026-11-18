/* EHP 2027 field core: encryption, local storage, sync packages, shared lists.
   Shared by the tablet field app (field/index.html) and the War Room (app/index.html). */
(function (root) {
  'use strict';
  const enc = new TextEncoder(), dec = new TextDecoder();
  const ITER = 150000;

  function b64(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) {
    const b = atob(s), u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u;
  }
  function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function uuid() {
    const r = rand(16); r[6] = (r[6] & 0x0f) | 0x40; r[8] = (r[8] & 0x3f) | 0x80;
    const h = [...r].map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  function secureOK() { return !!(root.crypto && crypto.subtle && root.indexedDB); }

  async function deriveKey(pass, salt, iter = ITER) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(key, obj) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function open(key, box) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
    return JSON.parse(dec.decode(pt));
  }

  /* ---------- IndexedDB ---------- */
  function db(name, stores) {
    return new Promise((res, rej) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => stores.forEach(s => { if (!r.result.objectStoreNames.contains(s)) r.result.createObjectStore(s); });
      r.onerror = () => rej(r.error);
      r.onsuccess = () => {
        const d = r.result;
        const tx = (s, m) => d.transaction(s, m).objectStore(s);
        const p = q => new Promise((ok, no) => { q.onsuccess = () => ok(q.result); q.onerror = () => no(q.error); });
        res({
          get: (s, k) => p(tx(s, 'readonly').get(k)),
          put: (s, k, v) => p(tx(s, 'readwrite').put(v, k)),
          del: (s, k) => p(tx(s, 'readwrite').delete(k)),
          clear: s => p(tx(s, 'readwrite').clear()),
          all: s => new Promise((ok, no) => {
            const out = []; const c = tx(s, 'readonly').openCursor();
            c.onsuccess = () => { const cur = c.result; if (cur) { out.push([cur.key, cur.value]); cur.continue(); } else ok(out); };
            c.onerror = () => no(c.error);
          })
        });
      };
    });
  }

  /* ---------- sync packages ---------- */
  async function makePackage(syncPass, payload) {
    const salt = rand(16);
    const key = await deriveKey(syncPass, salt);
    const box = await seal(key, payload);
    return { format: 'ehp27-sync', v: 1, created: new Date().toISOString(), device: payload.device || null,
      salt: b64(salt), iter: ITER, iv: box.iv, ct: box.ct };
  }
  async function openPackage(syncPass, pkg) {
    if (!pkg || pkg.format !== 'ehp27-sync') throw new Error('Not an EHP 2027 sync file');
    const key = await deriveKey(syncPass, unb64(pkg.salt), pkg.iter || ITER);
    try { return await open(key, { iv: pkg.iv, ct: pkg.ct }); }
    catch (e) { throw new Error('Wrong sync key, or the file is damaged'); }
  }
  /* merge two arrays of records by id, newest updated_at wins; deleted flags respected */
  function merge(a, b) {
    const m = new Map();
    (a || []).forEach(r => m.set(r.id, r));
    (b || []).forEach(r => { const o = m.get(r.id); if (!o || (r.updated_at || '') > (o.updated_at || '')) m.set(r.id, r); });
    return [...m.values()];
  }
  function mergePayload(base, inc) {
    const out = { coordinators: merge(base.coordinators, inc.coordinators), village_gps: merge(base.village_gps, inc.village_gps),
      village_reports: merge(base.village_reports, inc.village_reports), photos: Object.assign({}, base.photos || {}, inc.photos || {}),
      devices: merge(base.devices, inc.device ? [{ id: inc.device.id, ...inc.device, updated_at: inc.exported_at || '' }] : []) };
    return out;
  }

  /* ---------- images ---------- */
  function resizeImage(file, max = 480, q = 0.72) {
    return new Promise((res, rej) => {
      const img = new Image(); const url = URL.createObjectURL(file);
      img.onload = () => {
        const s = Math.min(1, max / Math.max(img.width, img.height));
        const c = document.createElement('canvas'); c.width = Math.round(img.width * s); c.height = Math.round(img.height * s);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height); URL.revokeObjectURL(url);
        res(c.toDataURL('image/jpeg', q));
      };
      img.onerror = () => { URL.revokeObjectURL(url); rej(new Error('Could not read the photo')); };
      img.src = url;
    });
  }

  /* ---------- shared lists ---------- */
  const LEVELS = [
    { k: 'provincial', t: 'Provincial coordinator', area: [], resp: 'Leads the province-wide organisation and supervises the 8 district coordinators.' },
    { k: 'district', t: 'District coordinator', area: ['district'], resp: 'Recruits and supervises LLG coordinators; runs district logistics, training and the weekly report.' },
    { k: 'llg', t: 'LLG coordinator', area: ['district', 'llg'], resp: 'Recruits and supervises ward coordinators across the LLG and organises LLG meetings.' },
    { k: 'ward', t: 'Ward coordinator', area: ['district', 'llg', 'ward'], resp: 'Recruits two village coordinators per village, organises ward meetings and the polling-place team.' },
    { k: 'village', t: 'Village coordinator', area: ['district', 'llg', 'ward', 'village'], resp: 'Organises village meetings, film nights and enrolment checks, recruits Family Reps from every clan, and reports village needs and support levels.' },
    { k: 'family', t: 'Family Rep', kin: true, area: ['district', 'llg', 'ward', 'village'], resp: 'Speaks for their family within the clan and tribe: shares campaign information, helps family members check their enrolment, and brings family needs to village meetings.' }
  ];
  const COMMUNITY_ROLES = ['Ward councillor', 'Village court magistrate', 'Clan / tribal leader', 'Pastor / church elder', 'Women\'s leader',
    'Youth leader', 'Teacher', 'Health worker', 'Coffee grower / buyer', 'Business person', 'Public servant', 'Student', 'Farmer', 'Other'];
  const ISSUES = ['Roads & bridges', 'Coffee & farm prices', 'Law & order / tribal fighting', 'Health / aid post', 'School fees & education',
    'Water supply', 'Electricity & phone network', 'Youth jobs & sport', 'Women & family safety', 'Markets & small business',
    'Land & mining benefits', 'Church partnership', 'Disaster / El Niño relief', 'Other'];
  const CONDUCT = 'I agree to be registered and photographed by the Fontenu 2027 campaign, and I accept the campaign code of conduct: no money, goods or promises in exchange for votes; no intimidation or threats; respect every voter\'s free and secret ballot.';

  root.FC = { b64, unb64, uuid, secureOK, deriveKey, seal, open, db, makePackage, openPackage, merge, mergePayload, resizeImage,
    LEVELS, COMMUNITY_ROLES, ISSUES, CONDUCT, levelOf: k => LEVELS.find(l => l.k === k) };
})(window);
