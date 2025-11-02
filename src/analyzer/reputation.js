import dns from 'node:dns/promises'

const REP_TTL_MS = Number(process.env.REP_TTL_MS || 10 * 60 * 1000)
const REQ_TIMEOUT_MS = Number(process.env.REP_TIMEOUT_MS || 10000)
const URLSCAN_POLL_MS = Number(process.env.URLSCAN_POLL_MS || 8000)
const URLSCAN_POLL_INTERVAL_MS = Number(process.env.URLSCAN_POLL_INTERVAL_MS || 1000)

const cacheGSB = new Map()
const cachePT = new Map()
const cacheUSub = new Map()
const cacheURes = new Map()
const cacheUH = new Map()
const cacheTF = new Map()
const cacheOP = new Map()
const cacheDBL = new Map()
const cacheOPList = new Map()

function norm(u) {
  try {
    const x = new URL(u)
    if (x.protocol !== 'http:' && x.protocol !== 'https:') return null
    x.hash = ''
    return x.toString()
  } catch {
    return null
  }
}

function domainFromUrl(u) {
  try {
    return new URL(u).hostname.toLowerCase()
  } catch {
    return null
  }
}

function now() {
  return Date.now()
}

function fromCache(map, key) {
  const v = map.get(key)
  if (!v) return null
  if (now() - v.at > REP_TTL_MS) {
    map.delete(key)
    return null
  }
  return v.data
}

function toCache(map, key, data) {
  map.set(key, { at: now(), data })
  return data
}

async function fetchJson(url, init = {}) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT_MS).unref?.()
  try {
    const r = await fetch(url, { ...init, signal: ctrl.signal, cache: 'no-store' })
    const ct = r.headers.get('content-type') || ''
    if (!ct.includes('json')) {
      const txt = await r.text().catch(() => '')
      return { ok: r.ok, status: r.status, data: txt }
    }
    const j = await r.json().catch(() => null)
    return { ok: r.ok, status: r.status, data: j }
  } catch {
    return { ok: false, status: 0, data: null }
  } finally {
    clearTimeout(t)
  }
}

export async function safeBrowsingCheck(url) {
  const key = process.env.GSB_API_KEY
  if (!key) return { enabled: false }
  const u = norm(url)
  if (!u) return { enabled: true, verdict: 'unknown', error: true }
  const hit = fromCache(cacheGSB, u)
  if (hit) return hit
  const body = {
    client: { clientId: 'safelink', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: u }]
    }
  }
  const r = await fetchJson(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  })
  if (!r.ok || r.status >= 400) return toCache(cacheGSB, u, { enabled: true, verdict: 'unknown', error: true })
  const matches = Array.isArray(r.data?.matches) ? r.data.matches : []
  const out = { enabled: true, matches, verdict: matches.length ? 'unsafe' : 'clean', ts: new Date().toISOString() }
  return toCache(cacheGSB, u, out)
}

export async function phishTankCheck(url) {
  const key = process.env.PHISHTANK_KEY
  if (!key) return { enabled: false }
  const u = norm(url)
  if (!u) return { enabled: true, verdict: 'unknown', error: true }
  const hit = fromCache(cachePT, u)
  if (hit) return hit
  const form = new URLSearchParams({ url: u, format: 'json', app_key: key })
  const r = await fetchJson('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form
  })
  if (!r.ok || r.status >= 400) return toCache(cachePT, u, { enabled: true, verdict: 'unknown', error: true })
  const j = typeof r.data === 'string' ? (() => { try { return JSON.parse(r.data) } catch { return null } })() : r.data
  if (!j) return toCache(cachePT, u, { enabled: true, verdict: 'unknown', error: true })
  const inDb = !!j?.results?.in_database
  const verified = !!j?.results?.verified
  const valid = !!j?.results?.valid
  const verdict = inDb && verified && valid ? 'phish' : 'clean'
  const out = { enabled: true, verdict, raw: j, ts: new Date().toISOString() }
  return toCache(cachePT, u, out)
}

async function urlscanSubmit(url, key) {
  const u = norm(url)
  if (!u) return { ok: false }
  const r = await fetchJson('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'API-Key': key },
    body: JSON.stringify({ url: u, public: 'off' })
  })
  if (!r.ok) return { ok: false, status: r.status, data: r.data }
  const uuid = r.data?.uuid || (typeof r.data?.result === 'string' ? r.data.result.slice(-36) : null)
  const api = r.data?.api || null
  const result = r.data?.result || null
  return { ok: true, uuid, api, result, data: r.data }
}

async function urlscanGetResult(uuid, key) {
  const r = await fetchJson(`https://urlscan.io/api/v1/result/${uuid}/`, {
    headers: key ? { 'API-Key': key } : undefined
  })
  return r
}

function urlscanVerdictOf(j) {
  const overall = j?.verdicts?.overall || {}
  const malicious = overall.malicious === true
  const score = typeof overall.score === 'number' ? overall.score : null
  if (malicious) return { verdict: 'unsafe', reason: 'malicious' }
  if (score !== null && score >= 50) return { verdict: 'suspicious', reason: 'score' }
  const stats = j?.stats || j?.page?.stats || {}
  if (typeof stats?.malicious === 'number' && stats.malicious > 0) return { verdict: 'unsafe', reason: 'malicious-stats' }
  return { verdict: 'clean', reason: 'none' }
}

export async function urlscanCheck(url, opts = {}) {
  const key = process.env.URLSCAN_KEY
  if (!key) return { enabled: false }
  const u = norm(url)
  if (!u) return { enabled: true, error: true }
  const cached = fromCache(cacheURes, u)
  if (cached) return cached
  const subHit = fromCache(cacheUSub, u)
  let uuid = subHit?.uuid || null
  let submitted = !!subHit
  if (!uuid) {
    const sub = await urlscanSubmit(u, key)
    if (!sub.ok) return { enabled: true, submitted: false, error: true }
    uuid = sub.uuid
    submitted = true
    toCache(cacheUSub, u, { uuid, at: now() })
    if (!opts.poll) return { enabled: true, submitted: true, resultUrl: sub.result || null, uuid }
  }
  const start = now()
  let last = null
  while (now() - start < (opts.pollMs ?? URLSCAN_POLL_MS)) {
    const r = await urlscanGetResult(uuid, key)
    if (r.ok && r.data) {
      last = r.data
      break
    }
    await new Promise(s => setTimeout(s, opts.intervalMs ?? URLSCAN_POLL_INTERVAL_MS))
  }
  if (!last) return { enabled: true, submitted, pending: true, uuid }
  const v = urlscanVerdictOf(last)
  const out = { enabled: true, submitted, uuid, verdict: v.verdict, urlscanVerdict: v, raw: last, ts: new Date().toISOString() }
  return toCache(cacheURes, u, out)
}

export async function urlhausCheck(url) {
  const u = norm(url)
  if (!u) return { enabled: true, verdict: 'unknown', error: true }
  const hit = fromCache(cacheUH, u)
  if (hit) return hit
  const form = new URLSearchParams({ url: u })
  const r = await fetchJson('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form
  })
  if (!r.ok) return toCache(cacheUH, u, { enabled: true, verdict: 'unknown', error: true })
  const j = typeof r.data === 'string' ? (() => { try { return JSON.parse(r.data) } catch { return null } })() : r.data
  const listed = j?.query_status === 'ok'
  const verdict = listed ? 'malware' : 'clean'
  return toCache(cacheUH, u, { enabled: true, verdict, raw: j, ts: new Date().toISOString() })
}

export async function threatFoxCheck(target) {
  const key = (target || '').toLowerCase()
  const hit = fromCache(cacheTF, key)
  if (hit) return hit
  const body = { query: 'search_ioc', search_term: key }
  const r = await fetchJson('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  })
  if (!r.ok) return toCache(cacheTF, key, { enabled: true, verdict: 'unknown', error: true })
  const data = Array.isArray(r.data?.data) ? r.data.data : []
  const verdict = data.length ? 'malicious' : 'clean'
  return toCache(cacheTF, key, { enabled: true, verdict, count: data.length, ts: new Date().toISOString() })
}

export async function openPhishCheck(url) {
  if (!process.env.OPENPHISH_ENABLE) return { enabled: false }
  const u = norm(url)
  if (!u) return { enabled: true, verdict: 'unknown', error: true }
  const hit = fromCache(cacheOP, u)
  if (hit) return hit
  const listKey = 'openphish:list'
  let list = fromCache(cacheOPList, listKey)
  if (!list) {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT_MS).unref?.()
    let txt = null
    try {
      const r = await fetch('https://openphish.com/feed.txt', { cache: 'no-store', signal: ctrl.signal })
      if (r.ok) txt = await r.text()
    } catch {}
    clearTimeout(t)
    if (!txt) return toCache(cacheOP, u, { enabled: true, verdict: 'unknown', error: true })
    list = new Set(txt.split(/\r?\n/).filter(Boolean))
    toCache(cacheOPList, listKey, list)
  }
  const found = list.has(u)
  return toCache(cacheOP, u, { enabled: true, verdict: found ? 'phish' : 'clean', ts: new Date().toISOString() })
}

export async function spamhausDblCheck(url) {
  if (!process.env.SPAMHAUS_ENABLE) return { enabled: false }
  const d = domainFromUrl(url)
  if (!d) return { enabled: true, verdict: 'unknown', error: true }
  const hit = fromCache(cacheDBL, d)
  if (hit) return hit
  try {
    const res = await dns.resolve4(`${d}.dbl.spamhaus.org`).catch(() => null)
    const listed = Array.isArray(res) && res.some(a => /^127\./.test(a))
    return toCache(cacheDBL, d, { enabled: true, verdict: listed ? 'listed' : 'clean', ts: new Date().toISOString() })
  } catch {
    return toCache(cacheDBL, d, { enabled: true, verdict: 'unknown', error: true })
  }
}

export function summarizeReputation(reps) {
  const reasons = []
  let score = 0
  let verdict = 'unknown'
  if (reps?.gsb?.enabled) {
    if (reps.gsb.verdict === 'unsafe') { score += 80; reasons.push('GSB') }
  }
  if (reps?.phishTank?.enabled) {
    if (reps.phishTank.verdict === 'phish') { score += 90; reasons.push('PhishTank') }
  }
  if (reps?.urlscan?.enabled) {
    if (reps.urlscan.verdict === 'unsafe') { score += 70; reasons.push('urlscan') }
    else if (reps.urlscan.verdict === 'suspicious') { score += 30; reasons.push('urlscan-suspicious') }
  }
  if (reps?.urlhaus?.enabled) {
    if (reps.urlhaus.verdict === 'malware') { score += 80; reasons.push('URLhaus') }
  }
  if (reps?.threatFox?.enabled) {
    if (reps.threatFox.verdict === 'malicious') { score += 75; reasons.push('ThreatFox') }
  }
  if (reps?.openPhish?.enabled) {
    if (reps.openPhish.verdict === 'phish') { score += 90; reasons.push('OpenPhish') }
  }
  if (reps?.spamhaus?.enabled) {
    if (reps.spamhaus.verdict === 'listed') { score += 60; reasons.push('Spamhaus DBL') }
  }
  if (score >= 90) verdict = 'unsafe'
  else if (score >= 50) verdict = 'suspicious'
  else if (reasons.length > 0) verdict = 'clean'
  else if (reps && Object.values(reps).some(x => x?.enabled)) verdict = 'clean'
  return { verdict, score, reasons }
}
