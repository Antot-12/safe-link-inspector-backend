const VT_BASE = 'https://www.virustotal.com/api/v3'
const TTL_MS = Number(process.env.VT_TTL_MS || 10 * 60 * 1000)
const TIMEOUT_MS = Number(process.env.VT_TIMEOUT_MS || 10000)
const POLL_TOTAL_MS = Number(process.env.VT_POLL_TOTAL_MS || 8000)
const POLL_INTERVAL_MS = Number(process.env.VT_POLL_INTERVAL_MS || 1200)

const cache = new Map()

function now(){ return Date.now() }
function getCache(k){ const v = cache.get(k); if(!v) return null; if(now()-v.at>TTL_MS){ cache.delete(k); return null } return v.data }
function setCache(k,d){ cache.set(k,{at:now(),data:d}); return d }

function normUrl(u){
  try{
    const x = new URL(u)
    if (x.protocol!=='http:' && x.protocol!=='https:') return null
    x.hash='' 
    return x.toString()
  }catch{ return null }
}

function b64url(s){
  try{ return Buffer.from(String(s),'utf8').toString('base64url') }catch{
    return Buffer.from(String(s),'utf8').toString('base64').replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_')
  }
}

function uiLink(id){ return `https://www.virustotal.com/gui/url/${id}` }

async function fetchJson(url, init){
  const ctrl = new AbortController()
  const t = setTimeout(()=>ctrl.abort(), TIMEOUT_MS).unref?.()
  try{
    const r = await fetch(url,{...init,signal:ctrl.signal})
    const ct = r.headers.get('content-type')||''
    const body = /json/i.test(ct) ? await r.json().catch(()=>null) : await r.text().catch(()=>null)
    return { ok:r.ok, status:r.status, data:body }
  }catch{ return { ok:false, status:0, data:null } } finally{ clearTimeout(t) }
}

async function vtGet(id,key){
  return fetchJson(`${VT_BASE}/urls/${id}`,{ headers:{ 'x-apikey':key } })
}

async function vtSubmit(url,key){
  const body = new URLSearchParams({ url })
  return fetchJson(`${VT_BASE}/urls`,{ method:'POST', headers:{ 'x-apikey':key }, body })
}

function parseStats(resp){
  const a = resp?.data?.attributes || {}
  const s = a.last_analysis_stats || {}
  const harmless = Number(s.harmless||0)
  const malicious = Number(s.malicious||0)
  const suspicious = Number(s.suspicious||0)
  const undetected = Number(s.undetected||0)
  const timeout = Number(s.timeout||0)
  const reputation = typeof a.reputation==='number' ? a.reputation : null
  const categories = a.categories || null
  const lastAnalysisAt = a.last_analysis_date ? new Date(a.last_analysis_date*1000).toISOString() : null
  let verdict = 'clean'
  if (malicious>0) verdict='malicious'
  else if (suspicious>0) verdict='suspicious'
  else if (reputation!==null && reputation<0) verdict='suspicious'
  const id = resp?.data?.id || null
  return { id, verdict, stats:{ harmless, malicious, suspicious, undetected, timeout }, reputation, categories, lastAnalysisAt, ui: id ? uiLink(id) : null }
}

export async function vtCheck(inputUrl, opts={}){
  const key = process.env.VT_API_KEY
  if (!key) return { enabled:false }
  const url = normUrl(inputUrl)
  if (!url) return { enabled:true, status:'error' }
  if (!opts.nocache){ const hit = getCache(url); if (hit) return hit }

  const id = b64url(url)
  let r = await vtGet(id,key)
  if (r.status===429) return setCache(url,{ enabled:true, status:'rate_limited' })
  if (r.status===404 || !r.ok){
    const s = await vtSubmit(url,key)
    if (!opts.poll) return setCache(url,{ enabled:true, status:'queued', id, ui: uiLink(id) })
    const start = now()
    let last = null
    while (now()-start < POLL_TOTAL_MS){
      await new Promise(res=>setTimeout(res, POLL_INTERVAL_MS))
      const rr = await vtGet(id,key)
      if (rr.ok && rr.data?.data){ last = rr; break }
      if (rr.status===429) return { enabled:true, status:'rate_limited' }
    }
    if (!last) return { enabled:true, status:'queued', id, ui: uiLink(id) }
    const parsed = parseStats(last.data)
    return setCache(url,{ enabled:true, status:'ok', ...parsed })
  }

  const parsed = parseStats(r.data)
  return setCache(url,{ enabled:true, status:'ok', ...parsed })
}
