import got from 'got'
import { parse as parseDomain } from 'tldts'

export const SHORTENERS = new Set([
  'bit.ly','t.co','goo.gl','tinyurl.com','ow.ly','is.gd','buff.ly','adf.ly','cutt.ly','rebrand.ly','s.id','lnkd.in','v.gd','smarturl.it','trib.al','rb.gy','shorte.st','tiny.cc','bl.ink'
])

const TTL_MS = Number(process.env.UNSHORT_TTL_MS || 10 * 60 * 1000)
const REQ_TIMEOUT_MS = Number(process.env.UNSHORT_TIMEOUT_MS || 12000)
const MAX_STEPS = Number(process.env.UNSHORT_MAX_STEPS || 10)

const cache = new Map()

function now(){ return Date.now() }
function getCache(key){
  const v = cache.get(key)
  if (!v) return null
  if (now() - v.at > TTL_MS) { cache.delete(key); return null }
  return v.data
}
function setCache(key, data){ cache.set(key, { at: now(), data }); return data }

function ua(){
  return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 SafeLinkInspector/2.0'
}

function sameETLD(a, b){
  try{
    const pa = parseDomain(new URL(a).hostname)
    const pb = parseDomain(new URL(b).hostname)
    if (!pa || !pb) return false
    return pa.domain === pb.domain && !!pa.domain
  }catch{ return false }
}

function normalizeHost(h){
  const host = String(h || '').replace(/\.+$/,'').toLowerCase()
  return host.startsWith('www.') ? host.slice(4) : host
}

export function normalizeUrl(input){
  try{
    if (!input) return ''
    let s = String(input).trim()
    s = s.replace(/\\+/g,'/')
    const hasProto = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(s)
    if (!hasProto) s = `https://${s}`
    const u = new URL(s)
    if (!/^https?:$/.test(u.protocol)) return s
    u.hash = ''
    if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = ''
    u.hostname = normalizeHost(u.hostname)
    return u.toString()
  }catch{ return input }
}

function isShortener(u){
  try{ return SHORTENERS.has(normalizeHost(new URL(u).hostname)) }catch{ return false }
}

function parseMetaRefresh(html, base){
  const m = String(html).match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)["']?/i)
  if (!m) return null
  const rel = m[1].trim()
  try{ return new URL(rel, base).toString() }catch{ return rel }
}

async function fetchHeadOrGet(url){
  try{
    const r = await got(url, {
      method:'HEAD',
      followRedirect: false,
      throwHttpErrors: false,
      timeout: { request: REQ_TIMEOUT_MS },
      headers: { 'user-agent': ua(), 'accept': '*/*' }
    })
    return r
  }catch{
    try{
      const r = await got(url, {
        method:'GET',
        followRedirect: false,
        throwHttpErrors: false,
        timeout: { request: REQ_TIMEOUT_MS },
        headers: {
          'user-agent': ua(),
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      })
      return r
    }catch{
      return null
    }
  }
}

export async function unshortenUrl(inputUrl, opts = {}){
  const url = normalizeUrl(inputUrl)
  if (!/^https?:\/\//i.test(url)) return { inputUrl: url, finalUrl: url, chain: [], isShortened: false }
  const cacheHit = opts.nocache ? null : getCache(url)
  if (cacheHit) return cacheHit

  let current = url
  const chain = []
  let finalUrl = url

  for (let i = 0; i < MAX_STEPS; i++){
    const res = await fetchHeadOrGet(current)
    if (!res){ break }
    const status = res.statusCode || 0
    const loc = res.headers?.location
    if (status >= 300 && status < 400 && loc){
      let next
      try{ next = new URL(loc, current).toString() }catch{ next = loc }
      if (!next) break
      chain.push(next)
      if (chain.includes(current) || chain.filter(x => x === next).length > 1) { finalUrl = next; break }
      current = next
      finalUrl = next
      continue
    }
    const ct = String(res.headers['content-type'] || '')
    if (/text\/html/i.test(ct) && (status >= 200 && status < 400)){
      let body = ''
      try{ body = res.body?.toString?.() || '' }catch{ body = '' }
      if (!body && res.request?.options?.method === 'HEAD'){
        try{
          const r2 = await got(current, {
            method:'GET',
            followRedirect:false,
            throwHttpErrors:false,
            timeout:{ request: REQ_TIMEOUT_MS },
            headers:{ 'user-agent': ua(), 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' }
          })
          body = r2.body?.toString?.() || ''
        }catch{}
      }
      const metaNext = body ? parseMetaRefresh(body, current) : null
      if (metaNext){
        chain.push(metaNext)
        if (chain.includes(current) || chain.filter(x => x === metaNext).length > 1) { finalUrl = metaNext; break }
        current = metaNext
        finalUrl = metaNext
        continue
      }
    }
    finalUrl = current
    break
  }

  const shortened = isShortener(url) || chain.length > 0 || !sameETLD(url, finalUrl)
  const out = { inputUrl: url, finalUrl, chain, isShortened: shortened }
  return opts.nocache ? out : setCache(url, out)
}
