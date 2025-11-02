import { JSDOM } from 'jsdom'
import { parse as parseDomain } from 'tldts'

function etld1(host){
  try{
    const p = parseDomain(host)
    return p && p.domain ? p.domain : ''
  }catch{ return '' }
}

function sameEtldHost(aHost, bHost){
  const da = etld1(aHost)
  const db = etld1(bHost)
  return da && db && da === db
}

function normUrl(raw, base){
  try{ return new URL(raw, base).toString() }catch{ return '' }
}

function hostOf(u){
  try{ return new URL(u).hostname }catch{ return '' }
}

function collectField(el){
  const name = el.getAttribute('name') || ''
  const typeAttr = (el.getAttribute('type') || el.tagName.toLowerCase()).toLowerCase()
  const type = typeAttr === 'textarea' ? 'textarea' : typeAttr
  const autocomplete = el.getAttribute('autocomplete') || ''
  const placeholder = el.getAttribute('placeholder') || ''
  const id = el.getAttribute('id') || ''
  const ariaLabel = el.getAttribute('aria-label') || ''
  const inputmode = el.getAttribute('inputmode') || ''
  const pattern = el.getAttribute('pattern') || ''
  const maxLength = el.getAttribute('maxlength') || ''
  const minLength = el.getAttribute('minlength') || ''
  const required = el.hasAttribute('required')
  const hidden = type === 'hidden' || el.getAttribute('type') === 'hidden'
  const isPassword = type === 'password'
  const isEmail = type === 'email'
  const isTel = type === 'tel'
  const isNumber = type === 'number'
  const isFile = type === 'file'
  return { name, type, autocomplete, placeholder, id, ariaLabel, inputmode, pattern, maxLength, minLength, required, hidden, isPassword, isEmail, isTel, isNumber, isFile }
}

function sensitiveFields(list){
  const out = []
  for (const it of list){
    const s = `${it.name}|${it.type}|${it.autocomplete}|${it.placeholder}|${it.ariaLabel}|${it.inputmode}|${it.pattern}`
    if (/(password|pass|card|cvv|cvc|otp|pin|code|seed|mnemonic|iban|swift|ssn|secret|2fa|one.?time|auth|private.?key|wallet|web3|phrase)/i.test(s)) out.push(it)
    if (it.isPassword) out.push(it)
  }
  return out
}

function hasCaptcha(doc){
  if (doc.querySelector('.g-recaptcha, .h-captcha, [data-sitekey]')) return true
  if (doc.querySelector('iframe[src*="recaptcha"]')) return true
  return false
}

function countHidden(list){
  return list.reduce((n,f)=> n + (f.hidden ? 1 : 0), 0)
}

function suspiciousHiddenNames(list){
  const out = []
  const rx = /(redirect|return|next|continue|dest|destination|target|back|from|ref|token|csrf|xsrf|session|auth|state)/i
  for (const f of list){ if (rx.test(`${f.name}`)) out.push(f) }
  return out
}

function providerOf(actionUrl){
  const h = hostOf(actionUrl)
  if (!h) return null
  const d = etld1(h)
  const map = {
    'google.com': 'google-forms',
    'formspree.io': 'formspree',
    'getform.io': 'getform',
    'typeform.com': 'typeform',
    'tally.so': 'tally',
    'jotform.com': 'jotform',
    'airtable.com': 'airtable',
    'hubspot.com': 'hubspot',
    'zoho.com': 'zoho',
    'mailchimp.com': 'mailchimp'
  }
  return map[d] || null
}

function scoreFlags(flags){
  let s = 0
  if (flags.includes('cross-domain')) s += 5
  if (flags.includes('insecure-http')) s += 6
  if (flags.includes('js-action')) s += 3
  if (flags.includes('get-with-sensitive')) s += 5
  if (flags.includes('many-hidden')) s += 2
  if (flags.includes('file-upload')) s += 2
  if (flags.includes('no-captcha-with-sensitive')) s += 2
  return s
}

export function analyzeForms(html, pageUrl){
  try{
    const dom = new JSDOM(html)
    const doc = dom.window.document
    const forms = Array.from(doc.querySelectorAll('form')).slice(0,100)
    const pageHost = hostOf(pageUrl)
    const pageEtld = etld1(pageHost)
    const captchaPresent = hasCaptcha(doc)
    const out = []
    for (const f of forms){
      const actionAttr = f.getAttribute('action') || ''
      const method = (f.getAttribute('method') || 'GET').toUpperCase()
      const enctype = f.getAttribute('enctype') || ''
      const target = f.getAttribute('target') || ''
      const onsubmit = f.getAttribute('onsubmit') || ''
      const actionAbs = actionAttr ? normUrl(actionAttr, pageUrl) : ''
      const actionScheme = actionAbs ? (new URL(actionAbs)).protocol.replace(':','') : ''
      const actionHost = actionAbs ? hostOf(actionAbs) : ''
      const actionEtld = actionHost ? etld1(actionHost) : ''
      const isJsAction = /^javascript:/i.test(actionAttr)
      const isHttpInsecure = !!(actionAbs && actionScheme === 'http')
      const cross = !!(actionHost && actionEtld && pageEtld && !sameEtldHost(pageHost, actionHost))
      const inputs = Array.from(f.querySelectorAll('input,textarea,select')).map(collectField).slice(0,300)
      const sens = sensitiveFields(inputs).slice(0,100)
      const hiddenFields = inputs.filter(x=>x.hidden).slice(0,100)
      const hiddenSuspicious = suspiciousHiddenNames(hiddenFields)
      const provider = providerOf(actionAbs)
      const flags = []
      if (cross) flags.push('cross-domain')
      if (isHttpInsecure) flags.push('insecure-http')
      if (isJsAction) flags.push('js-action')
      if (method==='GET' && sens.length) flags.push('get-with-sensitive')
      if (countHidden(inputs) >= 8) flags.push('many-hidden')
      if (inputs.some(i=>i.isFile)) flags.push('file-upload')
      if (!captchaPresent && sens.length) flags.push('no-captcha-with-sensitive')
      const riskScore = scoreFlags(flags)
      out.push({
        action: actionAbs || '(empty)',
        actionScheme: actionScheme || '',
        actionHost: actionHost || '',
        crossDomain: !!cross,
        method,
        enctype,
        target,
        provider: provider || '',
        jsAction: !!isJsAction,
        insecure: !!isHttpInsecure,
        fields: inputs,
        sensitiveFields: sens,
        hiddenFields,
        hiddenSuspicious,
        flags,
        score: riskScore
      })
    }
    return out
  }catch{
    return []
  }
}
