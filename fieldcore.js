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
      village_reports: merge(base.village_reports, inc.village_reports), village_profiles: merge(base.village_profiles, inc.village_profiles), photos: Object.assign({}, base.photos || {}, inc.photos || {}),
      devices: merge(base.devices, inc.device ? [{ id: inc.device.id, ...inc.device, updated_at: inc.exported_at || '' }] : []) };
    return purgePhotos(out);
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

  /* Optional face-recognition consent (approved 21 Nov 2026). Separate from CONDUCT; saying no never blocks registration. */
  const FACE_CONSENT = {
    v: 'face-v1-2026-11-21',
    en: "Optional: I agree that my registration photos (front and side) may be turned into a face code, kept encrypted on the candidate's phone, so his glasses can recognise me at campaign events. Camera images are checked on the spot and deleted immediately; they are never saved or shared. I can withdraw at any time, and the face code is deleted when I withdraw or when the campaign ends. Saying no does not affect my role.",
    tpi: "Sapos mi laik tasol: Mi orait long ol foto bilong mi (pes i lukluk stret na pes i tanim long sait) i ken kamap wanpela pes kod. Dispela pes kod bai i stap hait (encrypted) long fon bilong kandidet, bai ai glas bilong em i ken luksave long mi long ol kempen miting. Ol piksa bilong kamera ol i save sekim long dispela taim tasol na rausim kwiktaim; ol i no save seivim o givim long narapela. Mi ken tok nogat long wanem taim mi laik, na bai ol i rausim pes kod taim mi tok nogat o taim kempen i pinis. Sapos mi tok nogat, dispela i no bai senisim wok bilong mi."
  };
  /* Side photos exist only for face recognition: keep them only while the person consents and is not removed. */
  const faceOK = c => !!(c && c.face_consent && !c.deleted);
  function sidePurgeIds(coords) {
    const out = new Set(), keep = new Set();
    (coords || []).forEach(c => { (c.side_photo_purged || []).forEach(i => out.add(i)); if (c.side_photo_id) (faceOK(c) ? keep : out).add(c.side_photo_id); });
    keep.forEach(i => out.delete(i)); return out;
  }
  function purgePhotos(p) { if (p && p.photos) sidePurgeIds(p.coordinators).forEach(i => { delete p.photos[i]; }); return p; }
  const sidePhotoIds = coords => new Set((coords || []).map(c => c.side_photo_id).filter(Boolean));

  root.FC = { b64, unb64, uuid, secureOK, deriveKey, seal, open, db, makePackage, openPackage, merge, mergePayload, resizeImage,
    LEVELS, COMMUNITY_ROLES, ISSUES, CONDUCT, FACE_CONSENT, faceOK, sidePurgeIds, purgePhotos, sidePhotoIds, levelOf: k => LEVELS.find(l => l.k === k) };
})(window);
