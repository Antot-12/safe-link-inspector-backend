import net from 'node:net'
import { parse as parseTld } from 'tldts'

const TTL_MS = Number(process.env.WHOIS_TTL_MS || 24 * 60 * 60 * 1000)
const CACHE_MAX = Number(process.env.WHOIS_CACHE_MAX || 200)
const WHOIS_MAX_BYTES = Number(process.env.WHOIS_MAX_BYTES || 1_000_000)
const RDAP_TIMEOUT_MS = Number(process.env.RDAP_TIMEOUT_MS || 10000)
const WHOIS_TIMEOUT_MS = Number(process.env.WHOIS_TIMEOUT_MS || 10000)

const cache = new Map()
const serverCache = new Map()

function setCache(map, key, value) {
  if (map.size >= CACHE_MAX) {
    const firstKey = map.keys().next().value
    if (firstKey !== undefined) map.delete(firstKey)
  }
  map.set(key, value)
}

function extractDomainFromUrl(u) {
  try {
    const h = new URL(u).hostname
    const info = parseTld(h)
    if (info && info.domain) return info.domain
    return h.replace(/^www\./i, '')
  } catch {
    return ''
  }
}

async function rdapLookupFull(domain) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), RDAP_TIMEOUT_MS).unref?.()
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json' },
      cache: 'no-store',
      signal: ctrl.signal
    })
    if (!r.ok) return null
    const j = await r.json()
    let registrar = ''
    let registrarIanaId = null
    let abuseContact = null
    if (j.registrar) registrar = j.registrar.name || j.registrar || ''
    const ents = Array.isArray(j.entities) ? j.entities : []
    for (const e of ents) {
      const roles = e.roles || []
      if (roles.includes('registrar') || roles.includes('sponsor')) {
        const v = Array.isArray(e.vcardArray) ? e.vcardArray[1] : null
        if (Array.isArray(v)) {
          const fn = v.find(x => Array.isArray(x) && x[0] === 'fn')
          if (fn && fn[3]) registrar = String(fn[3])
          const iana = v.find(x => Array.isArray(x) && /iana/i.test(String(x[3] ?? '')))
          if (iana && iana[3]) registrarIanaId = String(iana[3]).replace(/\D+/g, '') || null
          const tel = v.find(x => Array.isArray(x) && x[0] === 'tel')
          const email = v.find(x => Array.isArray(x) && x[0] === 'email')
          if (email && email[3]) abuseContact = String(email[3])
          else if (tel && tel[3]) abuseContact = String(tel[3])
        }
        if (e.handle && !registrarIanaId && /^\d+$/.test(String(e.handle))) registrarIanaId = String(e.handle)
      }
    }
    let createdAt = null
    let updatedAt = null
    let expiresAt = null
    const ev = Array.isArray(j.events) ? j.events : []
    for (const e of ev) {
      if (/registration|create/i.test(e.eventAction || '')) {
        const dt = parseDateFlexible(e.eventDate)
        if (dt) createdAt = dt.toISOString()
      }
      if (/last\s*update|last\s*changed|update/i.test(e.eventAction || '')) {
        const dt = parseDateFlexible(e.eventDate)
        if (dt) updatedAt = dt.toISOString()
      }
      if (/expiration|expire/i.test(e.eventAction || '')) {
        const dt = parseDateFlexible(e.eventDate)
        if (dt) expiresAt = dt.toISOString()
      }
    }
    const status = Array.isArray(j.status) ? j.status.map(s => String(s)).slice(0, 20) : []
    const nameservers = Array.isArray(j.nameservers)
      ? j.nameservers.map(ns => (typeof ns === 'string' ? ns : ns.ldhName || ns.unicodeName || '')).filter(Boolean).slice(0, 20)
      : []
    const registryDomainId = j.handle || j.objectClassName === 'domain' ? j.handle || null : null
    let ageDays = null
    if (createdAt) {
      const dt = new Date(createdAt)
      if (!Number.isNaN(dt.getTime())) ageDays = Math.floor((Date.now() - dt.getTime()) / 86400000)
    }
    let expiresInDays = null
    if (expiresAt) {
      const dt = new Date(expiresAt)
      if (!Number.isNaN(dt.getTime())) expiresInDays = Math.ceil((dt.getTime() - Date.now()) / 86400000)
    }
    return {
      source: 'rdap',
      domain,
      registrar: registrar || null,
      registrarIanaId: registrarIanaId || null,
      registryDomainId: registryDomainId || null,
      createdAt: createdAt || null,
      updatedAt: updatedAt || null,
      expiresAt: expiresAt || null,
      ageDays,
      expiresInDays,
      status,
      nameservers,
      abuseContact
    }
  } catch {
    return null
  } finally {
    clearTimeout(t)
  }
}

function whoisQuery(server, query, timeoutMs = WHOIS_TIMEOUT_MS) {
  return new Promise(resolve => {
    const sock = new net.Socket()
    let buf = ''
    let done = false
    const finish = out => {
      if (!done) {
        done = true
        try { sock.destroy() } catch {}
        resolve(out)
      }
    }
    sock.setTimeout(timeoutMs, () => finish(null))
    sock.on('error', () => finish(null))
    sock.connect(43, server, () => {
      try { sock.write(query.trim() + '\r\n') } catch { finish(null) }
    })
    sock.on('data', chunk => {
      if (done) return
      buf += chunk.toString('utf8')
      if (buf.length >= WHOIS_MAX_BYTES) finish(buf.slice(0, WHOIS_MAX_BYTES))
    })
    sock.on('close', () => finish(buf || null))
  })
}

function tldOf(domain) {
  const info = parseTld(domain)
  if (info && info.publicSuffix) return info.publicSuffix.split('.').slice(-1)[0]
  const parts = String(domain).toLowerCase().split('.').filter(Boolean)
  return parts.length ? parts[parts.length - 1] : ''
}

const FALLBACK_WHOIS = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  io: 'whois.nic.io',
  co: 'whois.nic.co',
  me: 'whois.nic.me',
  uk: 'whois.nic.uk',
  ua: 'whois.ua',
  dev: 'whois.nic.google',
  app: 'whois.nic.google',
  xyz: 'whois.nic.xyz',
  info: 'whois.afilias.net',
  biz: 'whois.nic.biz',
  ru: 'whois.tcinet.ru',
  by: 'whois.cctld.by',
  pl: 'whois.dns.pl',
  cz: 'whois.nic.cz',
  sk: 'whois.sk-nic.sk'
}

async function resolveWhoisServerForTld(tld) {
  const c = serverCache.get(tld)
  if (c && Date.now() - c.at < TTL_MS) return c.server
  const resp = await whoisQuery('whois.iana.org', tld)
  if (resp) {
    const m = resp.match(/^\s*whois:\s*(.+)\s*$/mi)
    if (m) {
      const server = m[1].trim()
      setCache(serverCache, tld, { at: Date.now(), server })
      return server
    }
  }
  const fb = FALLBACK_WHOIS[tld] || null
  setCache(serverCache, tld, { at: Date.now(), server: fb })
  return fb
}

function parseDateFlexible(s) {
  if (!s) return null
  const t = Date.parse(s)
  if (!Number.isNaN(t)) return new Date(t)
  const m1 = s.match(/^(\d{4})[-.\/](\d{2})[-.\/](\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)(?:\s*Z)?/)
  if (m1) {
    const [ , y, mo, d, hh='0', mm='0', ss='0' ] = m1
    const dt = new Date(Date.UTC(+y, +mo - 1, +d, +hh, +mm, +ss))
    if (!Number.isNaN(dt.getTime())) return dt
  }
  const m2 = s.match(/^(\d{2})[.\/-](\d{2})[.\/-](\d{4})/)
  if (m2) {
    const [ , d, mo, y ] = m2
    const dt = new Date(Date.UTC(+y, +mo - 1, +d, 0, 0, 0))
    if (!Number.isNaN(dt.getTime())) return dt
  }
  const m3 = s.match(/^(\d{2})-([A-Za-z]{3})-(\d{4})/)
  if (m3) {
    const months = { jan:0,feb:1,mar:2,apr:3,may:4,jun:5,jul:6,aug:7,sep:8,oct:9,nov:10,dec:11 }
    const d = +m3[1]
    const mo = months[m3[2].toLowerCase()] ?? -1
    const y = +m3[3]
    if (mo >= 0) {
      const dt = new Date(Date.UTC(y, mo, d, 0, 0, 0))
      if (!Number.isNaN(dt.getTime())) return dt
    }
  }
  return null
}

function parseField(text, patterns) {
  const lines = String(text).split(/\r?\n/)
  for (const ln of lines) {
    for (const rx of patterns) {
      const m = ln.match(rx)
      if (m) return String(m[1]).trim()
    }
  }
  return null
}

function parseList(text, patterns) {
  const out = []
  const lines = String(text).split(/\r?\n/)
  for (const ln of lines) {
    for (const rx of patterns) {
      const m = ln.match(rx)
      if (m) out.push(String(m[1]).trim())
    }
  }
  return Array.from(new Set(out)).slice(0, 50)
}

function parseWhoisCreated(text) {
  const v = parseField(text, [
    /Creation Date\s*:\s*(.+)/i,
    /Created On\s*:\s*(.+)/i,
    /created\s*:\s*(.+)/i,
    /Registered On\s*:\s*(.+)/i,
    /Domain Registration Date\s*:\s*(.+)/i,
    /Domain Create Date\s*:\s*(.+)/i,
    /Registration Time\s*:\s*(.+)/i,
    /Registered\s*:\s*(.+)/i
  ])
  return v ? parseDateFlexible(v) : null
}

function parseWhoisUpdated(text) {
  const v = parseField(text, [
    /Updated Date\s*:\s*(.+)/i,
    /Last Updated On\s*:\s*(.+)/i,
    /Last Update\s*:\s*(.+)/i,
    /changed\s*:\s*(.+)/i
  ])
  return v ? parseDateFlexible(v) : null
}

function parseWhoisExpires(text) {
  const v = parseField(text, [
    /Registry Expiry Date\s*:\s*(.+)/i,
    /Expiration Date\s*:\s*(.+)/i,
    /Expiry Date\s*:\s*(.+)/i,
    /paid-till\s*:\s*(.+)/i
  ])
  return v ? parseDateFlexible(v) : null
}

function parseWhoisRegistrar(text) {
  const v = parseField(text, [
    /Registrar Name\s*:\s*(.+)/i,
    /Sponsoring Registrar\s*:\s*(.+)/i,
    /Registrar\s*:\s*(.+)/i,
    /registrar:\s*(.+)/i
  ])
  return v
}

function parseWhoisRegistrarIana(text) {
  const v = parseField(text, [
    /Registrar IANA ID\s*:\s*(.+)/i,
    /IANA ID\s*:\s*(.+)/i
  ])
  return v ? v.replace(/\D+/g, '') || null : null
}

function parseWhoisRegistryDomainId(text) {
  const v = parseField(text, [
    /Registry Domain ID\s*:\s*(.+)/i,
    /domain:\s*(.+)/i
  ])
  return v || null
}

function parseWhoisNameservers(text) {
  return parseList(text, [
    /Name Server\s*:\s*([A-Z0-9\.\-]+)/ig,
    /nserver:\s*([A-Z0-9\.\-]+)/ig
  ]).map(x => x.toLowerCase())
}

function parseWhoisStatus(text) {
  const items = parseList(text, [
    /Domain Status\s*:\s*([A-Za-z0-9\-_\.]+)/ig,
    /status:\s*([A-Za-z0-9\-_\.]+)/ig
  ])
  return items
}

function parseWhoisAbuse(text) {
  const email = parseField(text, [/Registrar Abuse Contact Email\s*:\s*([^ \r\n]+)/i, /abuse-mailbox:\s*([^ \r\n]+)/i])
  const phone = parseField(text, [/Registrar Abuse Contact Phone\s*:\s*([^ \r\n]+)/i])
  return email || phone || null
}

async function rawWhoisFull(domain) {
  try {
    const tld = tldOf(domain)
    const server = await resolveWhoisServerForTld(tld)
    if (!server) return null
    const resp = await whoisQuery(server, domain)
    if (!resp) return null
    if (/no match|not found|no entries/i.test(resp)) return null
    const created = parseWhoisCreated(resp)
    const updated = parseWhoisUpdated(resp)
    const expires = parseWhoisExpires(resp)
    const registrar = parseWhoisRegistrar(resp)
    const registrarIanaId = parseWhoisRegistrarIana(resp)
    const registryDomainId = parseWhoisRegistryDomainId(resp)
    const nameservers = parseWhoisNameservers(resp)
    const status = parseWhoisStatus(resp)
    const abuseContact = parseWhoisAbuse(resp)
    let createdAt = null
    let updatedAt = null
    let expiresAt = null
    let ageDays = null
    let expiresInDays = null
    if (created && !Number.isNaN(created.getTime())) {
      createdAt = created.toISOString()
      ageDays = Math.floor((Date.now() - created.getTime()) / 86400000)
    }
    if (updated && !Number.isNaN(updated.getTime())) {
      updatedAt = updated.toISOString()
    }
    if (expires && !Number.isNaN(expires.getTime())) {
      expiresAt = expires.toISOString()
      expiresInDays = Math.ceil((expires.getTime() - Date.now()) / 86400000)
    }
    return {
      source: 'whois',
      domain,
      registrar: registrar || null,
      registrarIanaId: registrarIanaId || null,
      registryDomainId: registryDomainId || null,
      createdAt,
      updatedAt,
      expiresAt,
      ageDays,
      expiresInDays,
      status,
      nameservers,
      abuseContact
    }
  } catch {
    return null
  }
}

export async function getWhoisFull(url) {
  try {
    const domain = extractDomainFromUrl(url)
    if (!domain) return null
    const now = Date.now()
    const hit = cache.get(domain)
    if (hit && now - hit.at < TTL_MS && hit.data && hit.data.createdAt !== undefined) return hit.data
    let out = await rdapLookupFull(domain)
    if (!out) out = await rawWhoisFull(domain)
    const result = out || {
      source: null,
      domain,
      registrar: null,
      registrarIanaId: null,
      registryDomainId: null,
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
      ageDays: null,
      expiresInDays: null,
      status: [],
      nameservers: [],
      abuseContact: null
    }
    setCache(cache, domain, { at: now, data: result })
    return result
  } catch {
    return null
  }
}

export async function getWhoisAge(url) {
  try {
    const full = await getWhoisFull(url)
    if (!full) return null
    return { registrar: full.registrar, createdAt: full.createdAt, ageDays: full.ageDays }
  } catch {
    return null
  }
}

export function isRecentlyRegistered(whois, days = 90) {
  if (!whois || typeof whois.ageDays !== 'number') return false
  return whois.ageDays >= 0 && whois.ageDays <= days
}

export function isExpiringSoon(whois, days = 30) {
  if (!whois || typeof whois.expiresInDays !== 'number') return false
  return whois.expiresInDays >= 0 && whois.expiresInDays <= days
}
