// ============================================================
//  fauzan-portfolio-api — Cloudflare Worker
//  Framework : Hono (lightweight, edge-native)
//  Storage   : Cloudflare KV (rate limiting)
//  Email     : Resend API (fetch-based, no Node.js dep)
//  Free tier : 100,000 req/day — SELAMANYA, tidak ada sleep
// ============================================================

import { Hono } from 'hono'
import { cors  } from 'hono/cors'

const app = new Hono()

// ─── CORS ─────────────────────────────────────────────────────
app.use('*', async (c, next) => {
  const origin = c.req.header('Origin') || ''
  const allowed = [
    c.env.ALLOWED_ORIGIN,
    'https://fauzandwip.pages.dev',
    'https://fauzandwip.dev',
    'https://www.fauzandwip.dev',
  ].filter(Boolean)

  if (c.req.method === 'OPTIONS') {
    if (!origin || allowed.includes(origin)) {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin':  origin || '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age':       '86400',
        },
      })
    }
    return c.json({ error: 'CORS: origin not allowed.' }, 403)
  }

  await next()

  if (origin && allowed.includes(origin)) {
    c.res.headers.set('Access-Control-Allow-Origin', origin)
    c.res.headers.set('Vary', 'Origin')
  }
})

// ─── SECURITY HEADERS ─────────────────────────────────────────
app.use('*', async (c, next) => {
  await next()
  const h = c.res.headers
  h.set('X-Frame-Options',           'DENY')
  h.set('X-Content-Type-Options',    'nosniff')
  h.set('Referrer-Policy',           'strict-origin-when-cross-origin')
  h.set('Permissions-Policy',        'camera=(), microphone=(), geolocation=()')
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
  h.delete('X-Powered-By')
  h.set('X-Request-ID', crypto.randomUUID())
})

// ════════════════════════════════════════════════════════════
//  GET /health
// ════════════════════════════════════════════════════════════
app.get('/health', (c) => {
  return c.json({
    status:    'ok',
    runtime:   'Cloudflare Workers',
    timestamp: new Date().toISOString(),
    colo:      c.req.raw.cf?.colo ?? 'unknown',
  })
})

// ════════════════════════════════════════════════════════════
//  POST /contact
//  Rate limit : 3 kirim / 15 menit per IP (via KV)
//  Protection : Honeypot + validasi + sanitasi
// ════════════════════════════════════════════════════════════
app.post('/contact', async (c) => {

  // 1. Body size guard
  const cl = parseInt(c.req.header('Content-Length') || '0')
  if (cl > 10_000) return c.json({ error: 'Request body too large.' }, 413)

  let body
  try { body = await c.req.json() }
  catch { return c.json({ error: 'Invalid JSON.' }, 400) }

  // 2. Honeypot — bot diam-diam di-drop
  if (body.website && String(body.website).length > 0) {
    return c.json({ success: true, message: 'Message received.' })
  }

  // 3. Validasi input
  const name    = sanitize(body.name    ?? '')
  const email   = sanitize(body.email   ?? '')
  const subject = sanitize(body.subject ?? 'New message from portfolio')
  const message = sanitize(body.message ?? '')

  const errors = []
  if (!name || name.length < 2 || name.length > 80)
    errors.push({ field: 'name',    msg: 'Name must be 2–80 characters.' })
  if (!email || !isValidEmail(email))
    errors.push({ field: 'email',   msg: 'Valid email required.' })
  if (!message || message.length < 10 || message.length > 2000)
    errors.push({ field: 'message', msg: 'Message must be 10–2000 characters.' })

  if (errors.length) return c.json({ error: 'Validation failed.', details: errors }, 422)

  // 4. Rate limiting via KV
  const ip     = c.req.header('CF-Connecting-IP') || 'unknown'
  const ipHash = await hashStr(ip + (c.env.IP_SALT || 'salt'))
  const kvKey  = `rl_contact:${ipHash}`
  const WINDOW = 15 * 60
  const MAX    = 3

  const now = Math.floor(Date.now() / 1000)
  let rec   = await c.env.RATE_LIMIT.get(kvKey, { type: 'json' }).catch(() => null)
       rec  = rec ?? { count: 0, resetAt: now + WINDOW }

  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + WINDOW }
  if (rec.count >= MAX) {
    const wait = Math.ceil((rec.resetAt - now) / 60)
    return c.json({ error: `Too many messages. Please wait ${wait} minute(s).` }, 429)
  }
  rec.count++
  c.env.RATE_LIMIT.put(kvKey, JSON.stringify(rec), { expirationTtl: WINDOW }).catch(() => {})

  // 5. Kirim email via Resend (fetch langsung — no Node dep)
  const domain = c.env.EMAIL_DOMAIN || 'fauzandwip.dev'
  const owner  = c.env.OWNER_EMAIL

  try {
    const [r1, r2] = await Promise.allSettled([
      sendEmail(c.env.RESEND_API_KEY, {
        from:    `Portfolio <noreply@${domain}>`,
        to:      [owner],
        replyTo: email,
        subject: `[Portfolio] ${subject}`,
        html:    tplIncoming({ name, email, subject, message }),
      }),
      sendEmail(c.env.RESEND_API_KEY, {
        from:    `M. Fauzan Dwi P <noreply@${domain}>`,
        to:      [email],
        subject: `Thanks for reaching out, ${firstName(name)}! 👋`,
        html:    tplReply(name),
      }),
    ])

    if (r1.status === 'rejected') throw r1.reason
  } catch (err) {
    console.error('Email error:', err)
    return c.json({ error: 'Failed to send message. Please email me directly.' }, 500)
  }

  return c.json({
    success: true,
    message: "Message sent! I'll get back to you within 24–48 hours.",
  })
})

// ════════════════════════════════════════════════════════════
//  GET /cv/token + GET /cv/download?token=...
//  Rate limit : 5 download / jam per IP
// ════════════════════════════════════════════════════════════
app.get('/cv/token', async (c) => {
  const ip     = c.req.header('CF-Connecting-IP') || 'unknown'
  const ipHash = await hashStr(ip + (c.env.IP_SALT || 'salt'))
  const kvKey  = `rl_cv:${ipHash}`
  const WINDOW = 3600
  const MAX    = 5

  const now = Math.floor(Date.now() / 1000)
  let rec   = await c.env.RATE_LIMIT.get(kvKey, { type: 'json' }).catch(() => null)
       rec  = rec ?? { count: 0, resetAt: now + WINDOW }

  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + WINDOW }
  if (rec.count >= MAX)
    return c.json({ error: 'Too many CV requests. Try again in an hour.' }, 429)

  rec.count++
  c.env.RATE_LIMIT.put(kvKey, JSON.stringify(rec), { expirationTtl: WINDOW }).catch(() => {})

  const token   = crypto.randomUUID()
  const expires = now + 900
  await c.env.RATE_LIMIT.put(
    `cvtok:${token}`,
    JSON.stringify({ expires, ip: ipHash, used: false }),
    { expirationTtl: 900 }
  )

  return c.json({ token, downloadUrl: `/cv/download?token=${token}` })
})

app.get('/cv/download', async (c) => {
  const token = c.req.query('token')
  if (!token) return c.json({ error: 'Missing token.' }, 400)

  const entry = await c.env.RATE_LIMIT.get(`cvtok:${token}`, { type: 'json' }).catch(() => null)
  if (!entry) return c.json({ error: 'Invalid or expired token.' }, 401)

  const now = Math.floor(Date.now() / 1000)
  if (entry.used || now > entry.expires) {
    c.env.RATE_LIMIT.delete(`cvtok:${token}`).catch(() => {})
    return c.json({ error: 'Token expired. Request a new one.' }, 401)
  }

  c.env.RATE_LIMIT.put(`cvtok:${token}`, JSON.stringify({ ...entry, used: true }), { expirationTtl: 60 }).catch(() => {})

  const cvUrl = c.env.CV_URL
  if (!cvUrl) return c.json({ error: 'CV not configured.' }, 404)

  return Response.redirect(cvUrl, 302)
})

// 404 & error
app.notFound((c) => c.json({ error: 'Not found.' }, 404))
app.onError((err, c) => { console.error(err); return c.json({ error: 'Server error.' }, 500) })

export default app

// ════════════════════════════════════════════════════════════
//  UTILITIES
// ════════════════════════════════════════════════════════════
function sanitize(str) {
  return String(str)
    .replace(/[<>"'\/]/g, c => ({'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','/':'&#x2F;'}[c]))
    .trim().slice(0, 5000)
}

function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 254
}

function firstName(name) { return (name || 'there').split(' ')[0] }

async function hashStr(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 12)
}

async function sendEmail(apiKey, payload) {
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.text()
    throw new Error(`Resend error ${res.status}: ${err}`)
  }
  return res.json()
}

// ════════════════════════════════════════════════════════════
//  EMAIL TEMPLATES
// ════════════════════════════════════════════════════════════
function tplIncoming({ name, email, subject, message }) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#04060f;padding:24px}
.wrap{max-width:580px;margin:0 auto}
.head{background:linear-gradient(135deg,#0ea5e9,#818cf8);padding:28px 32px;border-radius:12px 12px 0 0;text-align:center}
.head h1{color:#fff;font-size:20px;font-weight:600}
.body{background:#080d1c;border:1px solid rgba(56,189,248,.15);border-top:none;border-radius:0 0 12px 12px;padding:28px 32px}
.lbl{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:#64748b;margin-bottom:4px;margin-top:16px}
.lbl:first-child{margin-top:0}
.val{background:#0d1427;border-radius:6px;padding:10px 14px;font-size:13px;color:#e2e8f0;word-break:break-word;white-space:pre-wrap}
.foot{text-align:center;font-size:11px;color:#475569;margin-top:20px}
</style></head><body><div class="wrap">
<div class="head"><h1>📬 New Portfolio Message</h1></div>
<div class="body">
<p class="lbl">From</p><p class="val">${name} &lt;${email}&gt;</p>
<p class="lbl">Subject</p><p class="val">${subject}</p>
<p class="lbl">Message</p><p class="val">${message}</p>
</div>
<p class="foot">Sent via fauzan.dev · Cloudflare Workers</p>
</div></body></html>`
}

function tplReply(name) {
  const fn = firstName(name)
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#04060f;padding:24px}
.wrap{max-width:580px;margin:0 auto}
.head{background:linear-gradient(135deg,#0ea5e9,#818cf8);padding:36px 32px;border-radius:12px 12px 0 0;text-align:center}
.head h1{color:#fff;font-size:22px;font-weight:700;margin-bottom:6px}
.head p{color:rgba(255,255,255,.8);font-size:13px}
.body{background:#080d1c;border:1px solid rgba(56,189,248,.15);border-top:none;border-radius:0 0 12px 12px;padding:32px}
p{color:#94a3b8;font-size:14px;line-height:1.8;margin-bottom:12px}
strong{color:#38bdf8}
.cta{display:inline-block;margin-top:8px;background:linear-gradient(135deg,#0ea5e9,#818cf8);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}
.foot{text-align:center;font-size:11px;color:#475569;margin-top:20px}
</style></head><body><div class="wrap">
<div class="head"><h1>Hey, ${fn}! 👋</h1><p>Thanks for reaching out</p></div>
<div class="body">
<p>I received your message and I'm excited to connect! I'll get back to you within <strong>24–48 hours</strong>.</p>
<p>In the meantime, feel free to check out my projects on GitHub or connect on LinkedIn.</p>
<p>— <strong>M. Fauzan Dwi P</strong><br>AI & ML Engineer · GCP Specialist</p>
<a href="https://github.com/fauzandwip" class="cta">View My Projects →</a>
</div>
<p class="foot">fauzan.dev · Bandung, West Java, Indonesia</p>
</div></body></html>`
}
