function normalizeHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) {
    out[String(k).toLowerCase()] = v;
  }
  return out;
}

export function securityHeadersProfile(resp) {
  try {
    const h = normalizeHeaders(Object.fromEntries(resp.headers));
    const keys = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
      'content-security-policy',
      'cross-origin-opener-policy',
      'cross-origin-resource-policy'
    ];
    const profile = {};
    for (const k of keys) profile[k] = h[k] || null;
    return profile;
  } catch {
    return null;
  }
}

export function parseSetCookie(setCookie) {
  if (!setCookie) return [];
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  const out = [];
  for (const raw of arr.slice(0, 20)) {
    const parts = String(raw).split(';').map(s => s.trim());
    const pair = parts.shift() || '';
    const idx = pair.indexOf('=');
    const name = idx >= 0 ? pair.slice(0, idx) : pair;
    const value = idx >= 0 ? pair.slice(idx + 1) : '';
    const attrs = {};
    for (const a of parts) {
      const eq = a.indexOf('=');
      if (eq === -1) attrs[a.toLowerCase()] = true;
      else attrs[a.slice(0, eq).toLowerCase()] = a.slice(eq + 1);
    }
    out.push({ name, value: value ? value.slice(0, 120) : '', ...attrs });
  }
  return out;
}
