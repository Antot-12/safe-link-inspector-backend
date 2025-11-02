import { parse as parseDomain } from 'tldts'
import { toUnicode } from 'node:punycode'

const TOKENS = [
  'login','signin','verify','update','secure','account','wallet','web3','bank','amazon','steam','apple',
  'support','help','reset','recover','unlock','payment','billing','invoice','gift','promo','bonus',
  'crypto','exchange','airdrop','metamask','trustwallet','binance','telegram','discord','paypal','microsoft',
  'facebook','instagram','youtube','google','coinbase','kraken','okx','bybit','tiktok','snapchat','nordvpn','ton','usdt'
]

const BRAND_TOKENS = [
  'apple','steam','amazon','binance','metamask','trustwallet','telegram','discord','paypal','microsoft',
  'facebook','instagram','youtube','google','coinbase','kraken','okx','bybit','tiktok','snapchat','nordvpn'
]

const SUSPICIOUS_TLDS = Array.from(new Set([
  'zip','mov','top','gq','work','click','country','mom','party','review','xyz','buzz','rest','cam','link',
  'monster','quest','cn','ru','su','kim','tokyo','win','loan','men','ml','ga','cf','tk','icu','fit','club','bar'
]))

const SHORTENERS = new Set([
  't.ly','bit.ly','t.co','tinyurl.com','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly','s.id','v.gd','trib.al','rb.gy','short.cm','lnkd.in'
])

const SUS_SUB_RE = /(^|[.-])(login|signin|secure|verify|update|auth|sso|id|account|billing|wallet|client|portal|support|help|pay|payment|checkout)([.-]|$)/i

const CONFUSABLES = [
  { re: /rn/g, hint: 'rn->m' },
  { re: /vv/g, hint: 'vv->w' },
  { re: /cl/g, hint: 'cl->d' },
  { re: /0o/g, hint: '0o->oo' },
  { re: /o0/g, hint: 'o0->oo' },
  { re: /l1/g, hint: 'l1->ll' },
  { re: /1l/g, hint: '1l->ll' }
]

function hasIdn(host){
  if (!host) return false
  if (/xn--/i.test(host)) return true
  if (/[\u0400-\u04FF]/.test(host)) return true
  if (/[\u0370-\u03FF]/.test(host)) return true
  if (/[\u2E80-\u9FFF\u3040-\u30FF]/.test(host)) return true
  return false
}

function isMixedScript(s){
  if (!s) return false
  const latin = /[A-Za-z]/.test(s)
  const cyr = /[\u0400-\u04FF]/.test(s)
  const gr = /[\u0370-\u03FF]/.test(s)
  const hanKana = /[\u2E80-\u9FFF\u3040-\u30FF]/.test(s)
  let cnt = 0
  if (latin) cnt++
  if (cyr) cnt++
  if (gr) cnt++
  if (hanKana) cnt++
  return cnt >= 2
}

function subDepth(host){
  try{
    const p = parseDomain(host)
    if (!p || !p.hostname) return 0
    const sub = p.subdomain || ''
    if (!sub) return 0
    return sub.split('.').filter(Boolean).length
  }catch{ return 0 }
}

function etld1(host){
  const p = parseDomain(host)
  if (p && p.domain && p.publicSuffix) return `${p.domain}.${p.publicSuffix}`
  return host
}

function leftOfEtld(host){
  const p = parseDomain(host)
  if (p && p.hostname && p.domain && p.publicSuffix){
    const tail = `${p.domain}.${p.publicSuffix}`
    return p.hostname.endsWith(`.${tail}`) ? p.hostname.slice(0, -1 - tail.length) : ''
  }
  return ''
}

function isIpLiteral(host){
  if (!host) return false
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true
  if (/^\[?[A-F0-9:]+\]?$/i.test(host) && host.includes(':')) return true
  return false
}

function findTokens(host, path){
  const s = `${host}/${path || ''}`.toLowerCase()
  const out = []
  for (const t of TOKENS){
    if (s.includes(t)) out.push(t)
  }
  return out
}

function brandMismatch(host, path){
  const base = (etld1(host).toLowerCase().split('.')[0] || '')
  const s = `${host}/${path || ''}`.toLowerCase()
  const hits = []
  for (const t of BRAND_TOKENS){
    if (s.includes(t) && !base.includes(t) && !host.toLowerCase().includes(t)) hits.push(t)
  }
  return hits
}

function brandInPathOnly(host, path){
  const base = (etld1(host).toLowerCase().split('.')[0] || '')
  const s = String(path || '').toLowerCase()
  const hits = []
  for (const t of BRAND_TOKENS){
    if (s.includes(t) && !base.includes(t)) hits.push(t)
  }
  return hits
}

function hasSecretInQuery(path){
  if (!path) return false
  return /[?&](pass(word)?|otp|pin|code|seed|mnemonic|cvv|cvc|card|privatekey|secret|2fa|one.?time)/i.test(path)
}

function hasRedirectParam(path){
  if (!path) return false
  if (/[?&](url|u|redirect|target|next|continue|dest|destination)=/i.test(path)) return true
  if (/https?:\/\//i.test(path)) return true
  return false
}

function longOrNoisySegments(pathname){
  if (!pathname) return { long:false, hyphens:false, digits:false }
  const parts = pathname.split('/').filter(Boolean)
  let long = false, hyph = false, digits = false
  for (const seg of parts){
    if (seg.length >= 40) long = true
    if ((seg.match(/-/g) || []).length >= 3) hyph = true
    if (/[0-9]{6,}/.test(seg)) digits = true
  }
  return { long, hyphens:hyph, digits }
}

function excessiveParams(search){
  if (!search) return false
  const cnt = (search.match(/&/g) || []).length + (search ? 1 : 0)
  return cnt >= 12
}

function hasAtInUrl(u){
  try{
    const x = new URL(u)
    if (x.username || x.password) return true
    return /@/.test(x.href.split('#')[0].split('?')[0])
  }catch{ return false }
}

function nonStandardPort(u){
  try{
    const x = new URL(u)
    if (!x.port) return false
    const p = Number(x.port)
    if (x.protocol === 'http:' && p !== 80) return true
    if (x.protocol === 'https:' && p !== 443) return true
    return false
  }catch{ return false }
}

function unicodeView(host){
  try{
    if (/xn--/i.test(host)) return toUnicode(host)
    return host
  }catch{ return host }
}

function confusableHints(label){
  const s = String(label || '').toLowerCase()
  const hits = []
  for (const c of CONFUSABLES){
    if (c.re.test(s)) hits.push(c.hint)
  }
  return hits
}

function levenshtein(a, b){
  a = String(a||'').toLowerCase()
  b = String(b||'').toLowerCase()
  const m = a.length, n = b.length
  if (!m) return n
  if (!n) return m
  const dp = new Array(n + 1)
  for (let j=0;j<=n;j++) dp[j]=j
  for (let i=1;i<=m;i++){
    let prev = dp[0]
    dp[0] = i
    for (let j=1;j<=n;j++){
      const tmp = dp[j]
      const cost = a[i-1] === b[j-1] ? 0 : 1
      dp[j] = Math.min(
        dp[j] + 1,
        dp[j-1] + 1,
        prev + cost
      )
      prev = tmp
    }
  }
  return dp[n]
}

function brandLookalikes(baseLabel){
  const out = []
  const base = String(baseLabel||'').toLowerCase()
  if (!base) return out
  for (const br of BRAND_TOKENS){
    const d = levenshtein(base, br)
    if (d > 0 && d <= 2 && Math.abs(base.length - br.length) <= 2) out.push(`${br}~${d}`)
  }
  return out
}

export function computeHeuristics(finalUrl){
  try{
    const u = new URL(finalUrl)
    const host = u.hostname
    const uniHost = unicodeView(host)
    const path = (u.pathname || '') + (u.search || '')
    const flags = []
    let scoreDelta = 0

    if (u.protocol === 'http:'){ flags.push('http-scheme'); scoreDelta += 6 }

    if (hasIdn(host)){ flags.push('idn'); scoreDelta += 8 }
    if (isMixedScript(uniHost)){ flags.push('mixed-script'); scoreDelta += 6 }

    const depth = subDepth(host)
    if (depth >= 3){ flags.push(`deep-subdomain:${depth}`); scoreDelta += depth >= 5 ? 6 : depth >= 4 ? 4 : 2 }

    const left = leftOfEtld(host)
    if (left && SUS_SUB_RE.test(left)){ flags.push('suspicious-subdomain'); scoreDelta += 5 }

    const conf = confusableHints(left)
    if (conf.length){ flags.push('confusables:'+conf.slice(0,4).join('|')); scoreDelta += Math.min(8, 4 + 2*conf.length) }

    const baseLabel = (etld1(host).split('.')[0] || '')
    const looks = brandLookalikes(baseLabel)
    if (looks.length){ flags.push('brand-lookalike:'+looks.slice(0,3).join('|')); scoreDelta += Math.min(10, 6 + looks.length) }

    if (isIpLiteral(host)){ flags.push('ip-host'); scoreDelta += 10 }

    const toks = findTokens(host, path)
    if (toks.length){ flags.push('tokens:'+toks.join('|')); scoreDelta += Math.min(12, 4 + 2*toks.length) }

    const mism = brandMismatch(host, path)
    if (mism.length){ flags.push('brand-mismatch:'+mism.slice(0,3).join('|')); scoreDelta += Math.min(10, 6 + 2*mism.length) }

    const bip = brandInPathOnly(host, path)
    if (bip.length){ flags.push('brand-in-path:'+bip.slice(0,3).join('|')); scoreDelta += Math.min(8, 4 + bip.length) }

    const L = finalUrl.length
    if (L > 300){ flags.push('long-url>300'); scoreDelta += 8 }
    else if (L > 180){ flags.push('long-url>180'); scoreDelta += 4 }
    else if (L > 120){ flags.push('long-url>120'); scoreDelta += 2 }

    if (hasSecretInQuery(path)){ flags.push('query-asks-secret'); scoreDelta += 8 }
    if (hasRedirectParam(path)){ flags.push('open-redirect'); scoreDelta += 5 }

    const segs = longOrNoisySegments(u.pathname || '')
    if (segs.long){ flags.push('long-segment'); scoreDelta += 2 }
    if (segs.hyphens){ flags.push('noisy-segment-hyphens'); scoreDelta += 2 }
    if (segs.digits){ flags.push('noisy-segment-digits'); scoreDelta += 2 }

    if (excessiveParams(u.search || '')){ flags.push('excessive-params'); scoreDelta += 3 }

    if (hasAtInUrl(finalUrl)){ flags.push('at-sign'); scoreDelta += 8 }
    if (nonStandardPort(finalUrl)){ flags.push('nonstd-port'); scoreDelta += 4 }

    const tld = (parseDomain(host)?.publicSuffix || '').toLowerCase()
    if (tld && SUSPICIOUS_TLDS.includes(tld)){ flags.push('suspicious-tld:'+tld); scoreDelta += 6 }

    const etld = etld1(host).toLowerCase()
    if (SHORTENERS.has(etld)){ flags.push('url-shortener'); scoreDelta += 5 }

    return {
      flags,
      scoreDelta,
      details: {
        idn: hasIdn(host),
        mixedScript: isMixedScript(uniHost),
        subdomainDepth: depth,
        tokenCount: toks.length,
        urlLength: L,
        secretQuery: hasSecretInQuery(path),
        hasRedirectParam: hasRedirectParam(path),
        ipHost: isIpLiteral(host),
        nonStdPort: nonStandardPort(finalUrl),
        confusables: conf,
        brandLookalike: looks
      }
    }
  }catch{
    return { flags: [], scoreDelta: 0, details: { idn:false, mixedScript:false, subdomainDepth:0, tokenCount:0, urlLength:0, secretQuery:false, hasRedirectParam:false, ipHost:false, nonStdPort:false, confusables:[], brandLookalike:[] } }
  }
}

export function riskScore(finalUrl){
  let score = 0
  try{
    const u = new URL(finalUrl)
    const host = u.hostname.toLowerCase()
    const et = etld1(host).toLowerCase()
    const tld = (parseDomain(host)?.publicSuffix || '').toLowerCase()
    if (u.protocol === 'http:') score += 6
    if (tld && SUSPICIOUS_TLDS.includes(tld)) score += 6
    if (isIpLiteral(host)) score += 10
    if (nonStandardPort(finalUrl)) score += 4
    if (/\.(zip|exe|apk|scr|msi|bat|cmd|ps1|jar)(?:$|\?)/i.test(u.pathname)) score += 8
    if (SHORTENERS.has(et)) score += 6
  }catch{}
  return Math.max(0, Math.min(100, score))
}

export function riskLabel(score){
  if (score >= 18) return 'High'
  if (score >= 10) return 'Medium'
  return 'Low'
}
