// api/resolve.js — Vercel Serverless Function (Node.js 18+)
//
// GET /api/resolve?url=<enlace de Google Maps, corto o largo>
//
// Sigue las redirecciones EN EL SERVIDOR (sin CORS ni proxies públicos) y
// devuelve el Place ID. Respuesta JSON:
//   { ok: true,  placeId, name, source: "url" | "html", approx: boolean, finalUrl }
//   { ok: false, error: "invalid_url" | "host_not_allowed" | "no_place_id" | "timeout" | "upstream", ... }
//
// SEGURIDAD (SSRF): esta función hace fetch a una URL que envía el usuario, así
// que solo permite hosts de Google/goo.gl y revalida CADA redirección.
'use strict';

const PLACE_ID_RE = /^[A-Za-z0-9_-]{20,}$/;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const MAX_HOPS = 8;
const TOTAL_MS = 8500;          // presupuesto total (Vercel corta a los 10 s en plan gratis clásico)
const MAX_BODY = 3 * 1024 * 1024;

const SHORT_HOSTS = new Set(['goo.gl', 'g.co', 'g.page', 'share.google']);
// Lista cerrada de dominios de Google (evita hosts tipo google.evil.com)
const GOOGLE_HOST_RE = /^(?:www\.|maps\.|consent\.)?google\.(?:com|com\.ar|com\.br|com\.mx|com\.co|com\.pe|com\.uy|com\.au|com\.tr|co\.uk|co\.in|co\.jp|cl|es|de|fr|it|pt|nl|ca)$/;

function isAllowed(u) {
  if (u.protocol !== 'https:' || u.port || u.username || u.password) return false;
  const h = u.hostname.toLowerCase();
  if (SHORT_HOSTS.has(h) || h.endsWith('.goo.gl')) return true;           // maps.app.goo.gl, goo.gl/maps…
  if (h === 'search.google.com') return u.pathname.startsWith('/local');  // g.page/r/…/review → writereview?placeid=
  if (!GOOGLE_HOST_RE.test(h)) return false;
  if (h.startsWith('www.google.') || h.startsWith('google.')) return u.pathname.startsWith('/maps');
  return true;                                                            // maps.google.* y consent.google.*
}

/* ---------------------------------------------------------------------
   Extracción del Place ID según la estructura de la URL
   - ?placeid= / ?place_id= / ?query_place_id= / q=place_id:…
   - …/data=…!19sChIJ…   (el Place ID va tras "!19s")
   - "!1s0x…:0x…" (ftid) y ?cid= NO son Place IDs: solo se guardan para afinar
     la búsqueda dentro del HTML si hace falta.
   --------------------------------------------------------------------- */
function analyze(urlStr) {
  const out = { placeId: null, ftid: null, cid: null, name: null };
  let u;
  try { u = new URL(urlStr); } catch (e) { return out; }

  let full = u.href;
  try { full = decodeURIComponent(full); } catch (e) { /* se usa href sin decodificar */ }

  for (const k of ['placeid', 'place_id', 'query_place_id', 'destination_place_id']) {
    const v = u.searchParams.get(k);
    if (v && PLACE_ID_RE.test(v)) { out.placeId = v; break; }
  }
  if (!out.placeId) { const m = full.match(/place_id:([A-Za-z0-9_-]{20,})/); if (m) out.placeId = m[1]; }
  if (!out.placeId) { const m = full.match(/ChIJ[A-Za-z0-9_-]{16,}/); if (m) out.placeId = m[0]; }

  out.ftid = u.searchParams.get('ftid') || ((full.match(/!1s(0x[0-9a-f]+:0x[0-9a-f]+)/i) || [])[1] || null);
  out.cid = u.searchParams.get('cid');

  const pm = u.pathname.match(/\/maps\/(?:place|search)\/([^/@]+)/);
  if (pm) {
    try { out.name = decodeURIComponent(pm[1].replace(/\+/g, ' ')); } catch (e) { out.name = pm[1]; }
    if (/^-?\d+(\.\d+)?,\s*-?\d+(\.\d+)?$/.test(out.name)) out.name = null;
  }
  return out;
}

// Último recurso: buscar "ChIJ…" en el HTML (el más cercano al ftid, o el más repetido)
function scanBody(body, ftid) {
  const re = /ChIJ[A-Za-z0-9_-]{16,}/g;
  const hits = [];
  let m;
  while ((m = re.exec(body))) hits.push({ id: m[0], pos: m.index });
  if (!hits.length) return null;

  if (ftid) {
    const fpos = [];
    let i = -1;
    while ((i = body.indexOf(ftid, i + 1)) !== -1) fpos.push(i);
    let best = null, dist = Infinity;
    for (const h of hits) for (const p of fpos) {
      const d = Math.abs(h.pos - p);
      if (d < dist) { dist = d; best = h.id; }
    }
    if (best && dist <= 2000) return best;
  }
  const count = {};
  hits.forEach((h) => { count[h.id] = (count[h.id] || 0) + 1; });
  return Object.keys(count).sort((a, b) => count[b] - count[a])[0];
}

function send(res, status, body, cacheable) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', cacheable ? 'public, s-maxage=86400, stale-while-revalidate=604800' : 'no-store');
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
  if (req.method !== 'GET') return send(res, 405, { ok: false, error: 'method_not_allowed' });

  let input = Array.isArray(req.query.url) ? req.query.url[0] : req.query.url;
  input = String(input || '').trim();
  if (!input || input.length > 2048 || /\s/.test(input)) return send(res, 400, { ok: false, error: 'invalid_url' });

  let current;
  try { current = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input); }
  catch (e) { return send(res, 400, { ok: false, error: 'invalid_url' }); }
  if (current.protocol === 'http:') current.protocol = 'https:';
  if (!isAllowed(current)) return send(res, 400, { ok: false, error: 'host_not_allowed' });

  const deadline = Date.now() + TOTAL_MS;
  const known = { ftid: null, cid: null, name: null };

  try {
    for (let hop = 0; hop <= MAX_HOPS; hop++) {
      // 1) ¿Esta URL ya trae el Place ID?
      const a = analyze(current.href);
      known.ftid = known.ftid || a.ftid;
      known.cid = known.cid || a.cid;
      known.name = known.name || a.name;
      if (a.placeId) {
        return send(res, 200, { ok: true, placeId: a.placeId, name: known.name, source: 'url', approx: false, finalUrl: current.href }, true);
      }

      // 2) Pantalla de consentimiento: la URL real viene en ?continue=
      if (current.hostname.startsWith('consent.')) {
        const cont = current.searchParams.get('continue');
        if (!cont) break;
        let next;
        try { next = new URL(cont); } catch (e) { break; }
        if (!isAllowed(next)) break;
        current = next;
        continue;
      }

      if (!isAllowed(current)) return send(res, 422, { ok: false, error: 'host_not_allowed', finalUrl: current.href });

      // 3) Pedir la URL SIN seguir redirecciones automáticamente (validamos cada salto)
      const remaining = deadline - Date.now();
      if (remaining < 500) return send(res, 504, { ok: false, error: 'timeout' });
      const r = await fetch(current.href, {
        redirect: 'manual',
        headers: { 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'es-AR,es;q=0.9,en;q=0.8' },
        signal: AbortSignal.timeout(remaining)
      });

      if (r.status >= 300 && r.status < 400 && r.headers.get('location')) {
        current = new URL(r.headers.get('location'), current);
        continue;
      }
      if (!r.ok) return send(res, 502, { ok: false, error: 'upstream', status: r.status, finalUrl: current.href });

      // 4) Página final sin ID en la URL → escanear el HTML
      const body = (await r.text()).slice(0, MAX_BODY);
      const id = scanBody(body, known.ftid);
      if (id) {
        return send(res, 200, { ok: true, placeId: id, name: known.name, source: 'html', approx: true, finalUrl: current.href }, false);
      }
      break;
    }
    return send(res, 422, { ok: false, error: 'no_place_id', ftid: known.ftid, cid: known.cid, name: known.name, finalUrl: current.href });
  } catch (err) {
    const timeout = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return send(res, timeout ? 504 : 502, { ok: false, error: timeout ? 'timeout' : 'upstream' });
  }
};
