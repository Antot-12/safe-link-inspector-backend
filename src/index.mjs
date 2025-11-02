import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { nanoid } from "nanoid";
import got from "got";
import { parse as parseDomain } from "tldts";
import { addRecord, getAll, getById, removeById, clearAll } from "./store/db.js";
import { unshortenUrl, normalizeUrl } from "./analyzer/unshorten.js";
import { riskScore, riskLabel, computeHeuristics } from "./analyzer/risk.js";
import { vtCheck } from "./analyzer/vt.js";
import { sanitizeHtml } from "./analyzer/sanitize.js";
import { getTlsProfile } from "./analyzer/tls.js";
import { getWhoisAge } from "./analyzer/whois.js";
import { safeBrowsingCheck, phishTankCheck, urlscanCheck } from "./analyzer/reputation.js";
import { getIpInfo } from "./analyzer/netinfo.js";
import { analyzeForms } from "./analyzer/forms.js";
import { securityHeadersProfile, parseSetCookie } from "./analyzer/headers.js";
import { startLiveServer } from "./liveServer.mjs";

const app = express();
const PORT = process.env.PORT || 4000;
const CACHE_TTL_MIN = 15;

app.use(express.json({ limit: "2mb" }));
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "http://localhost:5174",
      "http://127.0.0.1:5174"
    ]
  })
);
app.use(helmet());
app.use(compression());
app.use(morgan("tiny"));

const DATA = join(process.cwd(), "data");
const SAFE = join(DATA, "sanitized");
await mkdir(SAFE, { recursive: true });

function sameETLD(a, b) {
  try {
    const da = parseDomain(a);
    const db = parseDomain(b);
    return da && db && da.domain && db.domain && da.domain === db.domain;
  } catch {
    return false;
  }
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/api/history/export", (req, res) => {
  const fmt = String(req.query.fmt || "csv").toLowerCase();
  const items = getAll();
  if (fmt === "json") {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=history.json");
    return res.send(JSON.stringify(items, null, 2));
  }
  const header = [
    "id",
    "startedAt",
    "riskScore",
    "riskLabel",
    "inputUrl",
    "finalUrl",
    "title",
    "description",
    "contentType",
    "sanitized",
    "redirectChain",
    "cacheHit"
  ];
  const qf = (s = "") => `"${String(s).replace(/"/g, '""')}"`;
  const rows = [header.join(",")].concat(
    items.map((it) =>
      [
        it.id,
        it.startedAt,
        (it.risk && it.risk.score) || "",
        (it.risk && it.risk.label) || "",
        it.inputUrl || "",
        it.finalUrl || "",
        it.title || "",
        it.description || "",
        it.contentType || "",
        it.sanitized || "",
        (it.chain || []).join(" -> "),
        it.cacheHit ? "1" : "0"
      ]
        .map(qf)
        .join(",")
    )
  );
  const csv = rows.join("\r\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=history.csv");
  res.send(csv);
});

app.post("/api/history/import", async (req, res) => {
  const payload = req.body;
  if (!Array.isArray(payload)) return res.status(400).json({ error: "array expected" });
  const existing = new Set(getAll().map((x) => x.id));
  let added = 0;
  for (const rec of payload) {
    if (!rec || !rec.id || existing.has(rec.id)) continue;
    existing.add(rec.id);
    await addRecord(rec);
    added++;
  }
  res.json({ ok: true, added });
});

app.get("/api/history", (req, res) => {
  const q = String(req.query.q || "").toLowerCase();
  const risk = String(req.query.risk || "all").toLowerCase();
  const sort = String(req.query.sort || "newest");
  const skip = Number(req.query.skip || 0);
  const limit = Math.min(100, Number(req.query.limit || 100));
  let items = getAll();
  if (q)
    items = items.filter(
      (it) =>
        (it.title || "").toLowerCase().includes(q) ||
        (it.finalUrl || "").toLowerCase().includes(q) ||
        (it.inputUrl || "").toLowerCase().includes(q)
    );
  if (["low", "medium", "high"].includes(risk))
    items = items.filter(((it) => ((it.risk && it.risk.label) || "").toLowerCase() === risk));
  if (sort === "risk")
    items.sort((a, b) => ((b.risk && b.risk.score) || 0) - ((a.risk && a.risk.score) || 0));
  else items.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  const total = items.length;
  items = items.slice(skip, skip + limit);
  res.json({ items, total });
});

app.get("/api/history/:id", (req, res) => {
  const item = getById(req.params.id);
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json(item);
});

app.delete("/api/history/:id", async (req, res) => {
  const ok = await removeById(req.params.id);
  if (!ok) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

app.delete("/api/history", async (_req, res) => {
  await clearAll();
  res.json({ ok: true });
});

app.get("/public/:id", (req, res) => {
  const item = getById(req.params.id);
  const token = req.query.token;
  if (!item || !item.shareToken || token !== item.shareToken) return res.status(404).send("Not found");
  res.setHeader("Cache-Control", "no-store");
  res
    .type("html")
    .send(
      `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SafeLink Report</title><style>body{background:#0b0f14;color:#e6f0f1;font:16px system-ui;padding:24px}a{color:#2ee7d8;word-break:break-word;overflow-wrap:anywhere}</style></head><body><h2>SafeLink Report</h2><p><b>Final URL:</b> <a href="${item.finalUrl}" target="_blank" rel="noopener">${item.finalUrl}</a></p><p><b>Risk:</b> ${item.risk && item.risk.label} (${(item.risk && item.risk.score) || 0})</p><p><b>Title:</b> ${item.title || "—"}</p><p><b>Description:</b> ${item.description || "—"}</p><p><b>Started:</b> ${item.startedAt}</p></body></html>`
    );
});

app.post("/api/analyze", async (req, res) => {
  const payload = req.body || {};
  const input = payload.url || "";
  const options = payload.options || {};
  if (!input) return res.status(400).json({ error: "url is required" });

  const id = nanoid(10);
  const startedAt = new Date().toISOString();
  const normalized = normalizeUrl(input);
  const unshort = await unshortenUrl(normalized);
  const finalUrl = unshort.finalUrl;
  const chain = unshort.chain;
  const isShortened = unshort.isShortened;

  if (!options.nocache) {
    const now = Date.now();
    const hit = getAll().find(
      (it) =>
        it.finalUrl === finalUrl &&
        now - new Date(it.startedAt).getTime() <= CACHE_TTL_MIN * 60 * 1000
    );
    if (hit) return res.json({ ...hit, cacheHit: true });
  }

  const heur = computeHeuristics(finalUrl);
  const base = riskScore(finalUrl);
  const score = base + heur.scoreDelta;
  const label = riskLabel(score);

  const vtP = vtCheck(finalUrl);
  const tlsP = getTlsProfile(finalUrl);
  const whoisP = getWhoisAge(finalUrl);
  const ipP = getIpInfo(finalUrl);
  const gsbP = safeBrowsingCheck(finalUrl);
  const ptP = phishTankCheck(finalUrl);
  const usP = urlscanCheck(finalUrl);

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

  let title = "";
  let description = "";
  let contentType = "";
  let sanitizedPath = "";
  let formFindings = [];
  let headersProfile = null;
  let cookies = [];

  try {
    const r = await fetch(finalUrl, { redirect: "follow", headers: { "user-agent": "SafeLinkInspector/2.0" }, cache: "no-store" });
    contentType = r.headers.get("content-type") || "";
    headersProfile = securityHeadersProfile(r);
    cookies = parseSetCookie(r.headers.get("set-cookie"));
    if (/text\/html/i.test(contentType)) {
      const html = await r.text();
      const t = html.match(/<title>([^<]{0,200})<\/title>/i);
      if (t) title = t[1].trim();
      const d1 = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{0,300})["']/i);
      if (d1) description = d1[1].trim();
      if (!description) {
        const d2 = html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']{0,300})["']/i);
        if (d2) description = d2[1].trim();
      }
      formFindings = analyzeForms(html, finalUrl).slice(0, 20);
      const safe = sanitizeHtml(html);
      sanitizedPath = join(SAFE, `${id}.html`);
      await writeFile(sanitizedPath, safe);
    }
  } catch {}

  let hsts = false;
  let httpToHttps = null;
  try {
    const r2 = await got(finalUrl, { throwHttpErrors: false, followRedirect: true, timeout: { request: 8000 } });
    const h = r2.headers["strict-transport-security"];
    if (h) hsts = true;
    const u = new URL(finalUrl);
    const httpUrl = `http://${u.hostname}${u.pathname || "/"}`;
    const test = await got(httpUrl, { throwHttpErrors: false, followRedirect: false, timeout: { request: 6000 } }).catch(() => null);
    if (test) {
      const loc = test.headers.location || "";
      httpToHttps = /^https:/i.test(loc) && test.statusCode && test.statusCode >= 300 && test.statusCode < 400;
    }
  } catch {}

  const tlsWarnings = [];
  if (tls) {
    if (!tls.matchesHost) tlsWarnings.push("Certificate CN/SAN does not match host");
    if (typeof tls.expiresInDays === "number" && tls.expiresInDays <= 30) tlsWarnings.push(`Certificate expires in ${tls.expiresInDays} days`);
  }

  const shareToken = nanoid(8);

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
    reputation: { gsb, phishTank: pt, urlscan, urlhaus, threatFox: tfox, openPhish: openphish, spamhaus: dbl },
    contentType,
    title,
    description,
    formFindings,
    sanitized: sanitizedPath ? `/api/sanitized/${id}` : ""
  };

  await addRecord(record);
  res.json(record);
});

app.get("/api/sanitized/:id", async (req, res) => {
  const file = join(SAFE, `${req.params.id}.html`);
  try {
    const html = await readFile(file);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'none'",
        "img-src https: data:",
        "style-src 'self' 'unsafe-inline'",
        "font-src https: data:",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'self'"
      ].join("; ")
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cross-Origin-Resource-Policy", "same-site");
    res.setHeader("Cache-Control", "no-store");
    res.send(html);
  } catch {
    res.status(404).send("Not found");
  }
});

app.listen(PORT, () => {
  console.log(`API server listening on http://localhost:${PORT}`);
});
startLiveServer();
