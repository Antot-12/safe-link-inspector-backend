import express from "express"
import got from "got"

const LIVE_PORT = Number(process.env.LIVE_PORT || 4080)
const FRAMERS = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5174",
  "https://antot-12.github.io"
]

function allowedFramers() {
  return FRAMERS.join(" ")
}

function ua() {
  return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
}

function stripMetaCsp(html) {
  return html.replace(/<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>/ig, "")
}

function insertBase(html, baseHref) {
  if (/<base\s/i.test(html)) return html
  return html.replace(/<head[^>]*>/i, m => `${m}\n<base href="${baseHref}">`)
}

function neutralizeFrameBusters(html) {
  let out = html
  out = out.replace(/\btop\.location\b/gi, "window.location")
  out = out.replace(/\bparent\.location\b/gi, "window.location")
  out = out.replace(/\bwindow\.top\b/gi, "window")
  out = out.replace(/\bwindow\.parent\b/gi, "window")
  return out
}

function dropSriAndCorsAttrs(html) {
  return html
    .replace(/\s(integrity|crossorigin)=("[^"]*"|'[^']*')/gi, "")
    .replace(/\sreferrerpolicy=("[^"]*"|'[^']*')/gi, "")
}

function rewriteAttrs(html, baseHref) {
  const re = /(href|src|action)=("|\')([^"\']+)("|\')/gi
  let out = html.replace(re, (_m, attr, q, url, q2) => {
    const u = String(url).trim()
    if (!u || /^data:|^blob:|^mailto:|^javascript:/i.test(u)) return `${attr}=${q}${u}${q2}`
    let abs
    try { abs = new URL(u, baseHref).href } catch { abs = u }
    const isGetLike = attr !== "action"
    const endpoint = isGetLike ? "/asset" : "/x"
    return `${attr}=${q}${endpoint}?url=${encodeURIComponent(abs)}${q2}`
  })
  out = out.replace(/\snonce=("[^"]*"|'[^']*')/gi, "")
  return out
}

function ensureStyles(html) {
  const inject = `<style>html,body{min-height:100%}img,video,canvas{max-width:100%}</style>`
  if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, `${inject}</head>`)
  return inject + html
}

function injectRuntimeShim(baseHref) {
  const js = `
    (function(){
      try{ Object.defineProperty(window,'top',{get:()=>window}); Object.defineProperty(window,'parent',{get:()=>window}); }catch(e){}
      try{
        const abs=(u)=>{ try{ return new URL(u, document.baseURI).href }catch(_){ return u } };
        const ofetch = window.fetch ? window.fetch.bind(window) : null;
        if (ofetch){
          window.fetch = function(input, init){
            try{
              const m = (init&&init.method||'GET').toUpperCase();
              const raw = typeof input==='string'? input : (input&&input.url)||'';
              const url = abs(raw);
              const ep = m==='GET' || m==='HEAD' ? '/asset?url=' : '/x?url=';
              const patched = ep + encodeURIComponent(url);
              return ofetch(patched, init);
            }catch(_){ return ofetch(input, init) }
          }
        }
        if (window.XMLHttpRequest){
          const o = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function(method, url){
            try{
              const m = String(method||'GET').toUpperCase();
              const ep = m==='GET' || m==='HEAD' ? '/asset?url=' : '/x?url=';
              const patched = ep + encodeURIComponent(abs(url));
              return o.apply(this, [method, patched, ...Array.prototype.slice.call(arguments,2)]);
            }catch(_){ return o.apply(this, arguments) }
          }
        }
        if (navigator && navigator.serviceWorker && navigator.serviceWorker.register){
          const noop = async ()=>({update:()=>{}, unregister:()=>true})
          navigator.serviceWorker.register = noop
        }
      }catch(_){}
    })();`
  return `<script>${js}</script>`
}

function rewriteCssUrls(css, baseHref) {
  let out = css.replace(/url\((['"]?)(?!data:|https?:|blob:|#)([^'")]+)\1\)/gi, (_m, q, u) => {
    let abs
    try { abs = new URL(u, baseHref).href } catch { abs = u }
    return `url(/asset?url=${encodeURIComponent(abs)})`
  })
  out = out.replace(/@import\s+(url\()?(['"])(?!data:|https?:|blob:)([^'"]+)\2\)?/gi, (_m, _u1, q, u) => {
    let abs
    try { abs = new URL(u, baseHref).href } catch { abs = u }
    return `@import url(/asset?url=${encodeURIComponent(abs)})`
  })
  return out
}

async function fetchUpstream(url, extraHeaders = {}, method = "GET", body) {
  return got(url, {
    method,
    body,
    followRedirect: true,
    throwHttpErrors: false,
    timeout: { request: 25000 },
    headers: {
      "user-agent": ua(),
      "accept": method === "GET"
        ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        : "*/*",
      "accept-language": "en-US,en;q=0.9",
      "upgrade-insecure-requests": method === "GET" ? "1" : undefined,
      ...extraHeaders
    },
    decompress: true,
    retry: { limit: 1 }
  })
}

export function startLiveServer() {
  const app = express()

  app.get("/", (_req, res) => res.type("text/plain").send("live ok"))

  app.get("/live", async (req, res) => {
    const raw = req.query.url
    if (!raw) return res.status(400).send("url is required")
    try {
      const r = await fetchUpstream(raw, { "Sec-Fetch-Dest":"document","Sec-Fetch-Mode":"navigate","Sec-Fetch-Site":"none" })
      const ct = r.headers["content-type"] || "text/html; charset=utf-8"

      res.setHeader("Content-Security-Policy",
        [
          "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'",
          "script-src * 'unsafe-inline' 'unsafe-eval' blob: data:",
          "style-src * 'unsafe-inline'",
          "img-src * data: blob:",
          "font-src * data:",
          "connect-src * data: blob:",
          "media-src * data: blob:",
          "frame-src *",
          `frame-ancestors ${allowedFramers()}`
        ].join("; ")
      )
      res.setHeader("Referrer-Policy", "no-referrer")
      res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
      res.setHeader("X-Content-Type-Options", "nosniff")
      res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
      res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none")
      res.setHeader("Cache-Control", "no-store")

      if (/text\/html/i.test(ct)) {
        let html = r.body.toString()
        html = stripMetaCsp(html)
        html = insertBase(html, raw)
        html = neutralizeFrameBusters(html)
        html = dropSriAndCorsAttrs(html)
        html = rewriteAttrs(html, raw)
        html = ensureStyles(html)
        html = html.replace(/<head[^>]*>/i, m => `${m}${injectRuntimeShim(raw)}`)
        res.type("html").send(html)
      } else {
        res.setHeader("Content-Type", ct)
        res.send(r.rawBody)
      }
    } catch {
      res.status(502).send("Bad gateway")
    }
  })

  app.get("/asset", async (req, res) => {
    const raw = req.query.url
    if (!raw) return res.status(400).send("url is required")
    try {
      const origin = new URL(raw)
      const r = await fetchUpstream(raw, { Referer: `${origin.origin}/`, "Sec-Fetch-Mode":"no-cors","Sec-Fetch-Site":"same-origin" })
      const ct = r.headers["content-type"] || ""
      res.setHeader("Cache-Control", "no-store")
      if (/text\/css/i.test(ct)) {
        let css = r.body.toString()
        css = rewriteCssUrls(css, raw)
        res.type("text/css").send(css)
      } else {
        if (ct) res.setHeader("Content-Type", ct)
        res.send(r.rawBody)
      }
    } catch {
      res.status(502).send("Bad gateway")
    }
  })

  app.use("/x", express.raw({ type: () => true, limit: "10mb" }))

  app.all("/x", async (req, res) => {
    const raw = req.query.url
    if (!raw) return res.status(400).send("url is required")
    try {
      const origin = new URL(raw)
      const hdrs = {}
      const hop = new Set(["host","cookie","authorization","origin","referer","content-length","connection","accept-encoding"])
      for (const [k,v] of Object.entries(req.headers)) {
        if (!hop.has(k.toLowerCase())) hdrs[k] = v
      }
      hdrs["Referer"] = `${origin.origin}/`
      hdrs["User-Agent"] = ua()
      const r = await fetchUpstream(raw, hdrs, req.method, req.body && req.body.length ? req.body : undefined)
      const ct = r.headers["content-type"] || ""
      res.setHeader("Cache-Control", "no-store")
      if (ct) res.setHeader("Content-Type", ct)
      res.send(r.rawBody)
    } catch {
      res.status(502).send("Bad gateway")
    }
  })

  app.listen(LIVE_PORT, () => {
    console.log(`Live sandbox server on http://localhost:${LIVE_PORT}`)
  }).on("error", e => {
    if (e && e.code === "EADDRINUSE") console.error(`Port ${LIVE_PORT} busy. Set LIVE_PORT and VITE_LIVE_ORIGIN.`)
    else console.error("Live server error:", e)
  })
}
