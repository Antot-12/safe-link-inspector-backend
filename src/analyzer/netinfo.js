import dns from 'node:dns/promises'
import net from 'node:net'

const TTL_MS = Number(process.env.NETINFO_TTL_MS || 6 * 60 * 1000)
const REQ_TIMEOUT_MS = Number(process.env.NETINFO_TIMEOUT_MS || 8000)

const cacheHost = new Map()
const cacheAbuse = new Map()

function now(){ return Date.now() }
function fromCache(map, key){
  const v = map.get(key)
  if (!v) return null
  if (now() - v.at > TTL_MS){ map.delete(key); return null }
  return v.data
}
function toCache(map, key, data){ map.set(key, { at: now(), data }); return data }

function hostFromUrl(u){
  try{ return new URL(u).hostname }catch{ return '' }
}

async function fetchJson(url, headers){
  const ctrl = new AbortController()
  const t = setTimeout(()=>ctrl.abort(), REQ_TIMEOUT_MS).unref?.()
  try{
    const r = await fetch(url, { headers: headers || {}, cache:'no-store', signal: ctrl.signal })
    if (!r.ok) return null
    const ct = r.headers.get('content-type') || ''
    if (!/json/i.test(ct)) return null
    return await r.json().catch(()=>null)
  }catch{ return null } finally{ clearTimeout(t) }
}

function uniqueBy(arr, key){
  const m = new Set(); const out=[]
  for (const x of arr){ const k = key(x); if (m.has(k)) continue; m.add(k); out.push(x) }
  return out
}

async function lookupAll(host){
  try{
    const viaLookup = await dns.lookup(host, { all:true, verbatim:false }).catch(()=>[])
    const viaA = await dns.resolve4(host).then(a=>a.map(ip=>({address:ip,family:4}))).catch(()=>[])
    const viaAAAA = await dns.resolve6(host).then(a=>a.map(ip=>({address:ip,family:6}))).catch(()=>[])
    const arr = uniqueBy([...(viaLookup||[]), ...viaA, ...viaAAAA], x=>`${x.family}|${x.address}`)
    return Array.isArray(arr) ? arr : []
  }catch{ return [] }
}

function isPrivateIPv4(ip){
  const p = ip.split('.').map(n=>+n)
  if (p.length!==4 || p.some(n=>Number.isNaN(n))) return false
  if (p[0]===10) return true
  if (p[0]===172 && p[1]>=16 && p[1]<=31) return true
  if (p[0]===192 && p[1]===168) return true
  if (p[0]===127) return true
  return false
}
function isPrivateIPv6(ip){
  const x = ip.toLowerCase()
  if (x==='::1') return true
  if (x.startsWith('fc') || x.startsWith('fd')) return true
  if (x.startsWith('fe80:')) return true
  return false
}
function isPrivateIP(ip){
  if (net.isIP(ip)===4) return isPrivateIPv4(ip)
  if (net.isIP(ip)===6) return isPrivateIPv6(ip)
  return false
}

function pickPreferred(addresses){
  if (!addresses || !addresses.length) return null
  const pub4 = addresses.find(x=>x.family===4 && !isPrivateIPv4(x.address))
  if (pub4) return pub4.address
  const any4 = addresses.find(x=>x.family===4)
  if (any4) return any4.address
  const any = addresses[0]
  return any ? any.address : null
}

async function reverseDns(ip){
  try{
    const arr = await dns.reverse(ip).catch(()=>[])
    return Array.isArray(arr) && arr.length ? arr[0] : null
  }catch{ return null }
}

async function asnCymru(ip){
  try{
    if (net.isIP(ip)===4){
      const parts = ip.split('.').reverse().join('.')
      const txt = await dns.resolveTxt(`${parts}.origin.asn.cymru.com`).catch(()=>[])
      const line = Array.isArray(txt) && txt.length && Array.isArray(txt[0]) && txt[0].length ? String(txt[0][0]) : ''
      const cols = line.split('|').map(s=>s.trim())
      if (cols.length>=5){
        const asn = cols[0] ? `AS${cols[0]}` : null
        const prefix = cols[1] || null
        const cc = cols[2] || null
        const registry = cols[3] || null
        const allocated = cols[4] || null
        let org = null
        if (asn){
          const orgTxt = await dns.resolveTxt(`${cols[0]}.asn.cymru.com`).catch(()=>[])
          const orgLine = Array.isArray(orgTxt) && orgTxt.length && Array.isArray(orgTxt[0]) && orgTxt[0].length ? String(orgTxt[0][0]) : ''
          const orgCols = orgLine.split('|').map(s=>s.trim())
          org = orgCols[4] || null
        }
        return { asn, org, prefix, cc, registry, allocated }
      }
    }
    return null
  }catch{ return null }
}

async function geoPrimary(ip){
  const j = await fetchJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { accept:'application/json' })
  if (!j) return null
  const asnField = j.asn || ''
  const asn = asnField ? (asnField.startsWith('AS') ? asnField : `AS${asnField}`) : null
  const org = j.org || j.org_name || null
  const country = j.country_name || j.country || null
  const city = j.city || null
  return { asn, org, country, city, source:'ipapi' }
}

async function geoFallback(ip){
  const j = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`, { accept:'application/json' })
  if (!j || j.success===false) return null
  const asn = j.connection && j.connection.asn ? `AS${j.connection.asn}` : null
  const org = j.connection && j.connection.org ? j.connection.org : null
  const country = j.country || j.country_code || null
  const city = j.city || null
  return { asn, org, country, city, source:'ipwho.is' }
}

async function fetchGeo(ip){
  const a = await geoPrimary(ip)
  if (a) return a
  const b = await geoFallback(ip)
  return b || { asn:null, org:null, country:null, city:null, source:null }
}

async function fetchAbuse(ip){
  const key = process.env.ABUSEIPDB_KEY
  if (!key) return { enabled:false }
  const hit = fromCache(cacheAbuse, ip)
  if (hit) return hit
  try{
    const ctrl = new AbortController()
    const t = setTimeout(()=>ctrl.abort(), REQ_TIMEOUT_MS).unref?.()
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key:key, Accept:'application/json' }, cache:'no-store', signal: ctrl.signal
    })
    clearTimeout(t)
    if (!r.ok) return toCache(cacheAbuse, ip, { enabled:true, score:null, totalReports:null })
    const j = await r.json().catch(()=>null)
    const score = j && j.data && typeof j.data.abuseConfidenceScore==='number' ? j.data.abuseConfidenceScore : null
    const total = j && j.data && typeof j.data.totalReports==='number' ? j.data.totalReports : null
    return toCache(cacheAbuse, ip, { enabled:true, score, totalReports: total })
  }catch{ return toCache(cacheAbuse, ip, { enabled:true, error:true }) }
}

export async function getIpInfo(targetUrl){
  try{
    const host = hostFromUrl(targetUrl)
    if (!host) return null
    const cached = fromCache(cacheHost, host)
    if (cached) return cached
    const addresses = await lookupAll(host)
    if (!addresses.length) return toCache(cacheHost, host, null)
    const ip = pickPreferred(addresses)
    if (!ip) return toCache(cacheHost, host, { host, ips: addresses, ip:null })

    const rdns = await reverseDns(ip).catch(()=>null)
    let asnBlock = await asnCymru(ip)
    let geo = await fetchGeo(ip)
    if (!asnBlock && geo && geo.asn) asnBlock = { asn: geo.asn, org: geo.org || null, prefix:null, cc: geo.country || null, registry:null, allocated:null }

    let abuse = { enabled:false }
    if (!isPrivateIP(ip)) abuse = await fetchAbuse(ip)

    const out = {
      host,
      ips: addresses,
      ip,
      rdns: rdns || null,
      asn: asnBlock ? asnBlock.asn : null,
      org: asnBlock ? (asnBlock.org || geo.org || null) : (geo.org || null),
      country: geo.country || null,
      city: geo.city || null,
      asnBlock,
      abuse
    }
    return toCache(cacheHost, host, out)
  }catch{
    return null
  }
}
