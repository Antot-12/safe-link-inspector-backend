import express from "express"
import cors from "cors"
import helmet from "helmet"
import morgan from "morgan"
import compression from "compression"
import { mkdir, writeFile, readFile } from "node:fs/promises"
import { join } from "node:path"
import { nanoid } from "nanoid"
import got from "got"
import { addRecord, getAll, getById, removeById, clearAll } from "./store/db.js"
import { unshortenUrl, normalizeUrl } from "./analyzer/unshorten.js"
import { riskScore, riskLabel, computeHeuristics } from "./analyzer/risk.js"
import { vtCheck } from "./analyzer/vt.js"
import { sanitizeHtml } from "./analyzer/sanitize.js"
import { getTlsProfile } from "./analyzer/tls.js"
import { getWhoisAge } from "./analyzer/whois.js"
import {
  safeBrowsingCheck,
  phishTankCheck,
  urlscanCheck,
  urlhausCheck,
  threatFoxCheck,
  openPhishCheck,
  spamhausDblCheck,
  summarizeReputation
} from "./analyzer/reputation.js"
import { getIpInfo } from "./analyzer/netinfo.js"
import { analyzeForms } from "./analyzer/forms.js"
import { securityHeadersProfile, parseSetCookie } from "./analyzer/headers.js"

function ua(){
  return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
}
function envList(name, fallback){
  const v = process.env[name]
  if (!v) return fallback
  return v.split(",").map(s=>s.trim()).filter(Boolean)
}
function allowedFramersHeader(){
  const list = envList("FRAME_ALLOWLIST", [
    "https://antot-12.github.io",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "https://safe-link-inspector.vercel.app"
  ])
  return list.join(" ")
}
function isHttpUrl(u){
  try{
    const x = new URL(u)
    return x.protocol === "http:" || x.protocol === "https:"
  }catch{ return false }
}
function stripMetaCsp(html){
  return html.replace(/<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>/ig, "")
}
function insertBase(html, baseHref){
  if (/<base\s/i.test(html)) return html
  return html.replace(/<head[^>]*>/i, m => `${m}\n<base href="${baseHref}">`)
}
function neutralizeFrameBusters(html){
  let out = html
  out = out.replace(/\btop\.location\b/gi, "window.location")
  out = out.replace(/\bparent\.location\b/gi, "window.location")
  out = out.replace(/\bwindow\.top\b/gi, "window")
  out = out.replace(/\bwindow\.parent\b/gi, "window")
  return out
}
function rewriteAttrs(html, baseHref){
  const re = /(href|src|action)=("|\')([^"\']+)("|\')/gi
  return html.replace(re, (_m, attr, q, url, q2) => {
    const u = String(url).trim()
    if (!u || /^data:|^blob:|^mailto:|^javascript:/i.test(u)) return `${attr}=${q}${u}${q2}`
    let abs
    try { abs = new URL(u, baseHref).href } catch { abs = u }
    if (!isHttpUrl(abs)) return `${attr}=${q}${u}${q2}`
    return `${attr}=${q}/api/asset?url=${encodeURIComponent(abs)}${q2}`
  })
}
function rewriteCssUrls(css, baseHref){
  return css.replace(/url\((['"]?)(?!data:|https?:|blob:|#)([^'")]+)\1\)/gi, (_m, _q, u) => {
    let abs
    try { abs = new URL(u, baseHref).href } catch { abs = u }
    if (!isHttpUrl(abs)) return `url(${u})`
    return `url(/api/asset?url=${encodeURIComponent(abs)})`
  })
}
function ensureStyles(html){
  const inject = `<style>html,body{min-height:100%}img,video{max-width:100%}a{word-break:break-word;overflow-wrap:anywhere}</style>`
  if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, `${inject}</head>`)
  return inject + html
}
async function fetchUpstream(url, extraHeaders = {}){
  return got(url, {
    method: "GET",
    followRedirect: true,
    throwHttpErrors: false,
    timeout: { request: 20000 },
    headers: {
      "user-agent": ua(),
      "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "accept-language": "en-US,en;q=0.9",
      "upgrade-insecure-requests": "1",
      ...extraHeaders
    },
    decompress: true,
    retry: { limit: 1 }
  })
}

export async function createApp(){
  const app = express()
  const CACHE_TTL_MIN = Number(process.env.CACHE_TTL_MIN || 15)
  app.disable("x-powered-by")
  app.use(express.json({ limit: "2mb" }))
  app.use(cors({
    origin: envList("CORS_ALLOWLIST", [
      "https://antot-12.github.io",
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "http://localhost:5174",
      "http://127.0.0.1:5174",
      "https://safe-link-inspector.vercel.app"
    ])
  }))
  app.use(helmet({
    contentSecurityPolicy: false,
    frameguard: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-site" }
  }))
  app.use(compression())
  app.use(morgan("tiny"))

  const DATA_ROOT = process.env.VERCEL ? "/tmp" : join(process.cwd(), "data")
  const SAFE_DIR = process.env.SAFE_DIR || join(DATA_ROOT, "sanitized")
  await mkdir(SAFE_DIR, { recursive: true })

  app.get("/api/health", (_req, res) => res.json({ ok: true }))

  app.get("/api/history/export", (req, res) => {
    const fmt = String(req.query.fmt || "csv").toLowerCase()
    const items = getAll()
    if (fmt === "json"){
      res.setHeader("Content-Type", "application/json; charset=utf-8")
      res.setHeader("Content-Disposition", "attachment; filename=history.json")
      return res.send(JSON.stringify(items, null, 2))
    }
    const header = ["id","startedAt","riskScore","riskLabel","inputUrl","finalUrl","title","description","contentType","sanitized","redirectChain","cacheHit"]
    const qf = (s="") => `"${String(s).replace(/"/g,'""')}"`
    const rows = [header.join(",")].concat(
      items.map(it => [
        it.id, it.startedAt, it.risk?.score || "", it.risk?.label || "", it.inputUrl || "", it.finalUrl || "",
        it.title || "", it.description || "", it.contentType || "", it.sanitized || "",
        (it.chain||[]).join(" -> "), it.cacheHit ? "1" : "0"
      ].map(qf).join(",")))
    res.setHeader("Content-Type","text/csv; charset=utf-8")
    res.setHeader("Content-Disposition","attachment; filename=history.csv")
    res.send(rows.join("\r\n"))
  })

  app.post("/api/history/import", async (req, res) => {
    const payload = req.body
    if (!Array.isArray(payload)) return res.status(400).json({ error: "array expected" })
    const existing = new Set(getAll().map(x => x.id))
    let added = 0
    for (const rec of payload){
      if (!rec || !rec.id || existing.has(rec.id)) continue
      existing.add(rec.id)
      await addRecord(rec)
      added++
    }
    res.json({ ok: true, added })
  })

  app.get("/api/history", (req, res) => {
    const q = String(req.query.q || "").toLowerCase()
    const risk = String(req.query.risk || "all").toLowerCase()
    const sort = String(req.query.sort || "newest")
    const skip = Number(req.query.skip || 0)
    const limit = Math.min(100, Number(req.query.limit || 100))
    let items = getAll()
    if (q){
      items = items.filter(it =>
        (it.title||"").toLowerCase().includes(q) ||
        (it.finalUrl||"").toLowerCase().includes(q) ||
        (it.inputUrl||"").toLowerCase().includes(q)
      )
    }
    if (["low","medium","high"].includes(risk)){
      items = items.filter(it => (it.risk?.label||"").toLowerCase() === risk)
    }
    if (sort === "risk"){
      items.sort((a,b)=>(b.risk?.score||0)-(a.risk?.score||0))
    } else {
      items.sort((a,b)=> new Date(b.startedAt) - new Date(a.startedAt))
    }
    const total = items.length
    items = items.slice(skip, skip + limit)
    res.json({ items, total })
  })

  app.get("/api/history/:id", (req, res) => {
    const item = getById(req.params.id)
    if (!item) return res.status(404).json({ error: "Not found" })
    res.json(item)
  })

  app.delete("/api/history/:id", async (req, res) => {
    const ok = await removeById(req.params.id)
    if (!ok) return res.status(404).json({ error: "Not found" })
    res.json({ ok: true })
  })

  app.delete("/api/history", async (_req, res) => {
    await clearAll()
    res.json({ ok: true })
  })

  app.get("/public/:id", (req, res) => {
    const item = getById(req.params.id)
    const token = req.query.token
    if (!item || !item.shareToken || token !== item.shareToken) return res.status(404).send("Not found")
    res.setHeader("Cache-Control","no-store")
    res.type("html").send(
      `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SafeLink Report</title><style>body{background:#0b0f14;color:#e6f0f1;font:16px system-ui;padding:24px}a{color:#2ee7d8;word-break:break-word;overflow-wrap:anywhere}</style></head><body><h2>SafeLink Report</h2><p><b>Final URL:</b> <a href="${item.finalUrl}" target="_blank" rel="noopener">${item.finalUrl}</a></p><p><b>Risk:</b> ${item.risk?.label} (${item.risk?.score||0})</p><p><b>Title:</b> ${item.title || "—"}</p><p><b>Description:</b> ${item.description || "—"}</p><p><b>Started:</b> ${item.startedAt}</p></body></html>`
    )
  })

  app.post("/api/analyze", async (req, res) => {
    const payload = req.body || {}
    const input = payload.url || ""
    const options = payload.options || {}
    if (!input) return res.status(400).json({ error: "url is required" })

    const id = nanoid(10)
    const startedAt = new Date().toISOString()
    const normalized = normalizeUrl(input)
    const unshort = await unshortenUrl(normalized)
    const finalUrl = unshort.finalUrl
    const chain = unshort.chain
    const isShortened = unshort.isShortened

    if (!options.nocache){
      const now = Date.now()
      const hit = getAll().find(it => it.finalUrl===finalUrl && now - new Date(it.startedAt).getTime() <= CACHE_TTL_MIN*60*1000)
      if (hit) return res.json({ ...hit, cacheHit: true })
    }

    const heur = computeHeuristics(finalUrl)
    const base = riskScore(finalUrl)
    const score = Math.max(0, Math.min(100, base + heur.scoreDelta))
    const label = riskLabel(score)

    const [vt, tls, whois, ipinfo, gsb, pt, urlscan, urlhaus, tfox, openphish, dbl] = await Promise.all([
      vtCheck(finalUrl),
      getTlsProfile(finalUrl),
      getWhoisAge(finalUrl),
      getIpInfo(finalUrl),
      safeBrowsingCheck(finalUrl),
      phishTankCheck(finalUrl),
      urlscanCheck(finalUrl),
      urlhausCheck(finalUrl),
      threatFoxCheck(new URL(finalUrl).hostname),
      openPhishCheck(finalUrl),
      spamhausDblCheck(new URL(finalUrl).hostname)
    ])

    let title = "", description = "", contentType = "", sanitizedPath = "", formFindings = [], headersProfile = null, cookies = []

    try{
      const r = await fetch(finalUrl, { redirect: "follow", headers: { "user-agent": "SafeLinkInspector/2.0" }, cache: "no-store" })
      contentType = r.headers.get("content-type") || ""
      headersProfile = securityHeadersProfile(r)
      cookies = parseSetCookie(r.headers.get("set-cookie"))
      if (/text\/html/i.test(contentType)){
        const html = await r.text()
        const t = html.match(/<title>([^<]{0,400})<\/title>/i); if (t) title = t[1].trim()
        const d1 = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{0,500})["']/i)
        if (d1) description = d1[1].trim()
        if (!description){
          const d2 = html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']{0,500})["']/i)
          if (d2) description = d2[1].trim()
        }
        formFindings = analyzeForms(html, finalUrl).slice(0, 20)
        const safe = sanitizeHtml(html)
        sanitizedPath = join(SAFE_DIR, `${id}.html`)
        await writeFile(sanitizedPath, safe)
      }
    }catch{}

    let hsts = false, httpToHttps = null
    try{
      const r2 = await got(finalUrl, { throwHttpErrors: false, followRedirect: true, timeout: { request: 8000 } })
      const h = r2.headers["strict-transport-security"]
      if (h) hsts = true
      const u = new URL(finalUrl)
      const httpUrl = `http://${u.hostname}${u.pathname || "/"}`
      const test = await got(httpUrl, { throwHttpErrors: false, followRedirect: false, timeout: { request: 6000 } }).catch(() => null)
      if (test){
        const loc = test.headers.location || ""
        httpToHttps = /^https:/i.test(loc) && test.statusCode && test.statusCode >= 300 && test.statusCode < 400
      }
    }catch{}

    const tlsWarnings = []
    if (tls){
      if (!tls.matchesHost) tlsWarnings.push("Certificate CN/SAN does not match host")
      if (typeof tls.expiresInDays === "number" && tls.expiresInDays <= 30) tlsWarnings.push(`Certificate expires in ${tls.expiresInDays} days`)
    }

    const shareToken = nanoid(8)
    const repSummary = summarizeReputation({
      gsb,
      phishTank: pt,
      urlscan,
      urlhaus,
      threatFox: tfox,
      openPhish: openphish,
      spamhaus: dbl
    })

    const record = {
      id,
      shareToken,
      startedAt,
      inputUrl: normalized,
      finalUrl,
      chain,
      isShortened,
      risk: { score, label },
      heuristics: heur,
      vt,
      tls,
      tlsWarnings,
      whois,
      net: ipinfo,
      security: { hsts, httpToHttps, headers: headersProfile, cookies },
      reputation: { gsb, phishTank: pt, urlscan, urlhaus, threatFox: tfox, openPhish: openphish, spamhaus: dbl, summary: repSummary },
      contentType,
      title,
      description,
      formFindings,
      sanitized: sanitizedPath ? `/api/sanitized/${id}` : ""
    }

    await addRecord(record)
    res.json(record)
  })

  app.get("/api/sanitized/:id", async (req, res) => {
    const file = join(SAFE_DIR, `${req.params.id}.html`)
    try{
      const html = await readFile(file)
      res.setHeader("Content-Type", "text/html; charset=utf-8")
      res.setHeader("Content-Security-Policy", [
        "default-src 'none'",
        "img-src https: data:",
        "style-src 'self' 'unsafe-inline'",
        "font-src https: data:",
        "base-uri 'none'",
        "form-action 'none'",
        `frame-ancestors ${allowedFramersHeader()}`
      ].join("; "))
      res.setHeader("X-Content-Type-Options","nosniff")
      res.setHeader("Cross-Origin-Resource-Policy","same-site")
      res.setHeader("Cache-Control","no-store")
      res.send(html)
    }catch{
      res.status(404).send("Not found")
    }
  })

  app.get(['/live', '/api/live'], async (req, res) => {
    const raw = req.query.url
    if (!raw) return res.status(400).send('url is required')
    try {
      const r = await fetchUpstream(raw)
      const ct = r.headers['content-type'] || 'text/html; charset=utf-8'
      res.setHeader('Content-Security-Policy', `default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; object-src 'none'; frame-ancestors ${allowedFramersHeader()}`)
      res.setHeader('Referrer-Policy','no-referrer')
      res.setHeader('Permissions-Policy','geolocation=(), microphone=(), camera=(), payment=()')
      res.setHeader('X-Content-Type-Options','nosniff')
      res.setHeader('Cache-Control','no-store')
      if (/text\/html/i.test(ct)) {
        let html = r.body.toString()
        html = stripMetaCsp(html)
        html = insertBase(html, raw)
        html = neutralizeFrameBusters(html)
        html = rewriteAttrs(html, raw)
        html = ensureStyles(html)
        res.type('html').send(html)
      } else {
        res.setHeader('Content-Type', ct)
        res.send(r.rawBody)
      }
    } catch {
      res.status(502).send('Bad gateway')
    }
  })

  app.get(['/asset', '/api/asset'], async (req, res) => {
    const raw = req.query.url
    if (!raw) return res.status(400).send('url is required')
    try {
      const origin = new URL(raw)
      const r = await fetchUpstream(raw, { Referer: `${origin.origin}/` })
      const ct = r.headers['content-type'] || ''
      res.setHeader('Cache-Control','no-store')
      if (/text\/css/i.test(ct)) {
        let css = r.body.toString()
        css = rewriteCssUrls(css, raw)
        res.type('text/css').send(css)
      } else {
        if (ct) res.setHeader('Content-Type', ct)
        res.send(r.rawBody)
      }
    } catch {
      res.status(502).send('Bad gateway')
    }
  })

  return app
}
