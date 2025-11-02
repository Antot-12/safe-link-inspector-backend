import tls from 'node:tls'
import net from 'node:net'
import crypto from 'node:crypto'

const TIMEOUT_MS = Number(process.env.TLS_TIMEOUT_MS || 8000)

function lc(x){ return typeof x === 'string' ? x.toLowerCase() : '' }

function parseSans(subjectAltName){
  const out = { dns:[], ips:[] }
  if (!subjectAltName) return out
  const parts = String(subjectAltName).split(/\s*,\s*/g)
  for (const p of parts){
    const mDns = p.match(/^DNS:\s*(.+)$/i)
    if (mDns){ out.dns.push(mDns[1].trim()) ; continue }
    const mIp = p.match(/^(IP|IP\s*Address):\s*(.+)$/i)
    if (mIp){ out.ips.push(mIp[2].trim()) ; continue }
  }
  return out
}

function matchLabel(hostLabel, patLabel){
  if (patLabel === '*') return true
  return hostLabel === patLabel
}

function matchWildcardHost(host, pattern){
  const h = lc(host)
  const p = lc(pattern)
  if (!p) return false
  if (!p.includes('*')) return h === p
  const labelsH = h.split('.')
  const labelsP = p.split('.')
  if (labelsH.length !== labelsP.length) return false
  for (let i=0;i<labelsP.length;i++){
    const ph = labelsP[i]
    if (ph === '*'){
      if (i !== 0) return false
      continue
    }
    if (!matchLabel(labelsH[i], ph)) return false
  }
  return true
}

function sanMatchesHost(host, sans, cn){
  if (net.isIP(host)){
    if (Array.isArray(sans.ips) && sans.ips.some(ip => ip === host)) return true
    return false
  }
  if (Array.isArray(sans.dns) && sans.dns.some(d => matchWildcardHost(host, d))) return true
  if (cn && matchWildcardHost(host, cn)) return true
  return false
}

function parseExpiry(validTo){
  if (!validTo) return { validTo:null, expiresInDays:null, isExpired:null }
  const t = Date.parse(validTo)
  if (!Number.isFinite(t)) return { validTo, expiresInDays:null, isExpired:null }
  const days = Math.ceil((t - Date.now()) / 86400000)
  return { validTo: new Date(t).toISOString(), expiresInDays: days, isExpired: days < 0 }
}

function sha256Hex(buf){
  return crypto.createHash('sha256').update(buf).digest('hex')
}

export async function getTlsProfile(url){
  try{
    const u = new URL(url)
    const host = u.hostname
    const port = u.port ? Number(u.port) : 443
    return await new Promise(resolve=>{
      let settled = false
      const servername = net.isIP(host) ? undefined : host
      const sock = tls.connect({
        host,
        port,
        servername,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2','http/1.1'],
        minVersion: 'TLSv1.2'
      })
      const finish = (val)=>{ if (!settled){ settled = true; try{ sock.destroy() }catch{}; resolve(val) } }
      sock.setTimeout(TIMEOUT_MS, ()=> finish(null))
      sock.once('error', ()=> finish(null))
      sock.once('secureConnect', ()=>{
        try{
          const proto = sock.getProtocol() || ''
          const alpn = sock.alpnProtocol || ''
          const cipher = sock.getCipher?.() || null
          const ocsp = sock.getOCSPResponse?.() || null
          const cert = sock.getPeerCertificate(true)
          if (!cert || Object.keys(cert).length===0) return finish(null)

          const subjectCN = cert.subject?.CN || ''
          const issuerCN = cert.issuer?.CN || ''
          const issuerO  = cert.issuer?.O || ''
          const issuer = issuerCN || issuerO || ''
          const sanRaw = cert.subjectaltname || ''
          const sans = parseSans(sanRaw)
          const vf = cert.valid_from || ''
          const vtRaw = cert.valid_to || cert.validTo || ''
          const exp = parseExpiry(vtRaw)

          let fingerprint256 = cert.fingerprint256 || null
          if (!fingerprint256 && cert.raw) fingerprint256 = sha256Hex(cert.raw).toUpperCase()

          const isSelfSigned = !!(cert.issuerCertificate && cert.issuerCertificate.raw && cert.raw && cert.issuerCertificate.raw.equals?.(cert.raw))

          const okMatch = sanMatchesHost(host, sans, subjectCN)

          const warnings = []
          if (!okMatch) warnings.push('host-mismatch')
          if (exp.expiresInDays != null && exp.expiresInDays <= 30) warnings.push('expiring-soon')
          if (exp.isExpired) warnings.push('expired')
          if (isSelfSigned) warnings.push('self-signed')

          finish({
            subjectCN: subjectCN || '',
            issuer: issuer || '',
            issuerCN: issuerCN || '',
            validFrom: vf ? new Date(Date.parse(vf)).toISOString() : '',
            validTo: exp.validTo || '',
            expiresInDays: exp.expiresInDays,
            protocol: proto || '',
            alpn: alpn || '',
            cipher: cipher?.name || '',
            fingerprint256: fingerprint256 || '',
            ocspStapled: !!(ocsp && ocsp.length),
            sans: [...sans.dns, ...sans.ips],
            matchesHost: !!okMatch,
            isSelfSigned,
            warnings
          })
        }catch{
          finish(null)
        }
      })
    })
  }catch{
    return null
  }
}
