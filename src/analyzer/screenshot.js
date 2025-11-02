import { writeFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import puppeteer from 'puppeteer';
import sharp from 'sharp';
import { TaskQueue } from '../queue.js';

const queue = new TaskQueue(Number(process.env.SCREENSHOT_CONCURRENCY || 1));

function pickHeadless() {
  return process.env.HEADFUL === '1' ? false : 'new';
}

async function launch() {
  const args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--hide-scrollbars',
    '--window-size=1366,900',
    '--js-flags=--max-old-space-size=256'
  ];
  const cfg = { headless: pickHeadless(), ignoreHTTPSErrors: true, args };
  try { return await puppeteer.launch(cfg) } catch {}
  try { return await puppeteer.launch({ ...cfg, channel: 'chrome' }) } catch {}
  return puppeteer.launch(cfg);
}

async function shotOnce(url, outPath, opts) {
  const retina = !!opts.retina;
  const viewportHeight = Number(opts.viewportHeight || 900);
  const firstScreen = !!opts.firstScreen;
  const timeoutMs = Number(opts.timeoutMs || 30000);
  const delayMs = Number(opts.delayMs || 1500);

  const browser = await launch();
  let ctx = null;
  let page = null;
  const hosts = new Set();
  try {
    ctx = await browser.createIncognitoBrowserContext();
    page = await ctx.newPage();
    await page.setViewport({ width: 1366, height: viewportHeight, deviceScaleFactor: retina ? 2 : 1 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 SafeLinkInspector/2.0');
    await page.setRequestInterception(true);
    page.on('request', req => {
      const u = req.url();
      try { hosts.add(new URL(u).hostname) } catch {}
      const type = req.resourceType();
      if (type === 'media' || type === 'websocket' || type === 'eventsource') return req.abort();
      if (/\.(exe|zip|rar|7z|msi|dmg|apk|bat|cmd|scr|jar)(\?|$)/i.test(u)) return req.abort();
      req.continue();
    });
    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: timeoutMs });
    } catch {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    }
    if (delayMs > 0) await page.waitForTimeout(delayMs);
    await page.screenshot({ path: outPath, fullPage: !firstScreen, captureBeyondViewport: true, optimizeForSpeed: true });
    const thumbPath = outPath.replace(/\.png$/, '.thumb.jpg');
    await sharp(outPath).resize({ width: 360 }).jpeg({ quality: 72 }).toFile(thumbPath);
    return { outPath, thumbPath, hosts: Array.from(hosts).slice(0, 200) };
  } finally {
    try { await ctx?.close() } catch {}
    try { await browser?.close() } catch {}
  }
}

export async function makeScreenshot(finalUrl, outDir, base, opts) {
  await mkdir(outDir, { recursive: true });
  const outPath = join(outDir, `${base}.png`);
  return queue.push(async () => {
    try {
      const r1 = await shotOnce(finalUrl, outPath, opts || {});
      const s1 = await stat(outPath).catch(() => null);
      if (s1 && s1.size > 0) return r1;
    } catch {}
    try {
      const r2 = await shotOnce(finalUrl, outPath, { ...(opts || {}), firstScreen: true, viewportHeight: Math.max(1200, Number((opts || {}).viewportHeight || 900)) });
      const s2 = await stat(outPath).catch(() => null);
      if (s2 && s2.size > 0) return r2;
    } catch {}
    try { await writeFile(outPath, Buffer.from('')) } catch {}
    return { outPath, thumbPath: null, hosts: [] };
  });
}
