// =============================================================
//  fauzan-portfolio-api / src/index.js
//  Runtime  : Cloudflare Workers — NO external dependencies
//  Fix      : Response body stream hanya dibaca SEKALI
// =============================================================

export default {
  async fetch(request, env) {
    const url    = new URL(request.url)
    const method = request.method
    const path   = url.pathname

    // Kumpulkan headers tambahan di sini (bukan buat Response baru berkali-kali)
    const extraHeaders = new Headers()

    // ── CORS headers ─────────────────────────────────────────
    const origin  = request.headers.get('Origin') || ''
    const allowed = getAllowedOrigins(env)

    if (!origin || allowed.includes(origin)) {
      extraHeaders.set('Access-Control-Allow-Origin',  origin || '*')
      extraHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      extraHeaders.set('Access-Control-Allow-Headers', 'Content-Type')
      extraHeaders.set('Vary', 'Origin')
    }

    // ── Security headers ──────────────────────────────────────
    extraHeaders.set('X-Frame-Options',           'DENY')
    extraHeaders.set('X-Content-Type-Options',    'nosniff')
    extraHeaders.set('Referrer-Policy',           'strict-origin-when-cross-origin')
    extraHeaders.set('Permissions-Policy',        'camera=(), microphone=(), geolocation=()')
    extraHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
    extraHeaders.set('X-Request-ID',              crypto.randomUUID())

    // ── CORS preflight ────────────────────────────────────────
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: extraHeaders })
    }

    // ── Route ke handler yang sesuai ─────────────────────────
    let result

    try {
      if      (path === '/health'       && method === 'GET')  result = await handleHealth(request, env)
      else if (path === '/contact'      && method === 'POST') result = await handleContact(request, env)
      else if (path === '/cv/token'     && method === 'GET')  result = await handleCvToken(request, env)
      else if (path === '/cv/download'  && method === 'GET')  result = await handleCvDownload(request, env, url)
      else result = { status: 404, body: { error: 'Route not found.' } }
    } catch (err) {
      console.error('Unhandled error:', err.message, err.stack)
      result = { status: 500, body: { error: 'Internal server error.' } }
    }

    // ── Bangun response SEKALI dengan semua headers ───────────
    const responseHeaders = new Headers(extraHeaders)
    responseHeaders.set('Content-Type', 'application/json')

    return new Response(JSON.stringify(result.body), {
      status:  result.status,
      headers: responseHeaders,
    })
  }
}

// =============================================================
//  HANDLERS — setiap handler return { status, body }
// =============================================================

function handleHealth(request, env) {
  return {
    status: 200,
    body: {
      status:    'ok',
      timestamp: new Date().toISOString(),
      runtime:   'Cloudflare Workers',
      colo:      request.cf?.colo ?? 'unknown',
    }
  }
}

async function handleContact(request, env) {
  // 1. Body size guard
  const cl = parseInt(request.headers.get('Content-Length') || '0')
  if (cl > 10_000) return { status: 413, body: { error: 'Request body too large.' } }

  // 2. Parse JSON
  let body
  try { body = await request.json() }
  catch { return { status: 400, body: { error: 'Invalid JSON body.' } } }

  // 3. Honeypot — bot diam-diam di-drop
  if (body.website && String(body.website).length > 0) {
    return { status: 200, body: { success: true, message: 'Message received.' } }
  }

  // 4. Sanitasi & validasi
  const name    = sanitize(String(body.name    ?? ''))
  const email   = sanitize(String(body.email   ?? ''))
  const subject = sanitize(String(body.subject ?? 'New message from portfolio'))
  const message = sanitize(String(body.message ?? ''))

  const errors = []
  if (!name    || name.length < 2    || name.length > 80)
    errors.push({ field: 'name',    msg: 'Name must be 2-80 characters.' })
  if (!email   || !isValidEmail(email))
    errors.push({ field: 'email',   msg: 'Valid email address required.' })
  if (!message || message.length < 10 || message.length > 2000)
    errors.push({ field: 'message', msg: 'Message must be 10-2000 characters.' })

  if (errors.length > 0) return { status: 422, body: { error: 'Validation failed.', details: errors } }

  // 5. Rate limiting via KV
  if (env.RATE_LIMIT) {
    const ip     = request.headers.get('CF-Connecting-IP') || 'unknown'
    const ipHash = await hashStr(ip + (env.IP_SALT || 'default_salt'))
    const rlKey  = `rl_contact:${ipHash}`
    const WINDOW = 15 * 60
    const MAX    = 3
    const now    = Math.floor(Date.now() / 1000)

    let rec = null
    try { rec = JSON.parse(await env.RATE_LIMIT.get(rlKey) || 'null') } catch {}
    rec = rec ?? { count: 0, resetAt: now + WINDOW }
    if (now > rec.resetAt) rec = { count: 0, resetAt: now + WINDOW }

    if (rec.count >= MAX) {
      const wait = Math.ceil((rec.resetAt - now) / 60)
      return { status: 429, body: { error: `Too many messages. Please wait ${wait} minute(s).` } }
    }

    rec.count++
    env.RATE_LIMIT.put(rlKey, JSON.stringify(rec), { expirationTtl: WINDOW })
  }

  // 6. Kirim email via Resend
  const domain = env.EMAIL_DOMAIN || 'example.com'
  const owner  = env.OWNER_EMAIL

  if (!env.RESEND_API_KEY) {
    console.error('RESEND_API_KEY not set!')
    return { status: 500, body: { error: 'Email service not configured. Please contact me directly.' } }
  }

  if (!owner) {
    console.error('OWNER_EMAIL not set!')
    return { status: 500, body: { error: 'Email destination not configured.' } }
  }

  try {
    await sendEmail(env.RESEND_API_KEY, {
      from:    `Portfolio <noreply@${domain}>`,
      to:      [owner],
      replyTo: email,
      subject: `[Portfolio] ${subject}`,
      html:    buildIncomingEmail({ name, email, subject, message }),
      text:    `From: ${name} <${email}>\n\n${message}`,
    })

    // Auto-reply (non-blocking — jika gagal tidak stop flow utama)
    sendEmail(env.RESEND_API_KEY, {
      from:    `M. Fauzan Dwi P <noreply@${domain}>`,
      to:      [email],
      subject: `Thanks for reaching out, ${getFirstName(name)}!`,
      html:    buildAutoReplyEmail(name),
    }).catch(err => console.error('Auto-reply failed:', err.message))

  } catch (err) {
    console.error('Email send error:', err.message)
    return { status: 500, body: { error: 'Failed to send message. Please email me directly.' } }
  }

  return {
    status: 200,
    body:   { success: true, message: "Message sent! I'll get back to you within 24-48 hours." }
  }
}

async function handleCvToken(request, env) {
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown'
  const ipHash = await hashStr(ip + (env.IP_SALT || 'default_salt'))
  const rlKey  = `rl_cv:${ipHash}`
  const now    = Math.floor(Date.now() / 1000)

  if (env.RATE_LIMIT) {
    let rec = null
    try { rec = JSON.parse(await env.RATE_LIMIT.get(rlKey) || 'null') } catch {}
    rec = rec ?? { count: 0, resetAt: now + 3600 }
    if (now > rec.resetAt) rec = { count: 0, resetAt: now + 3600 }
    if (rec.count >= 5) return { status: 429, body: { error: 'Too many CV requests. Try again in an hour.' } }
    rec.count++
    env.RATE_LIMIT.put(rlKey, JSON.stringify(rec), { expirationTtl: 3600 })
  }

  const token   = crypto.randomUUID()
  const expires = now + 900

  if (env.RATE_LIMIT) {
    await env.RATE_LIMIT.put(
      `cvtok:${token}`,
      JSON.stringify({ expires, ip: ipHash, used: false }),
      { expirationTtl: 900 }
    )
  }

  return {
    status: 200,
    body:   { token, expiresIn: '15 minutes', downloadUrl: `/cv/download?token=${token}` }
  }
}

async function handleCvDownload(request, env, url) {
  const token = url.searchParams.get('token')
  if (!token) return { status: 400, body: { error: 'Missing token.' } }

  if (env.RATE_LIMIT) {
    let entry = null
    try { entry = JSON.parse(await env.RATE_LIMIT.get(`cvtok:${token}`) || 'null') } catch {}
    if (!entry) return { status: 401, body: { error: 'Invalid or expired token.' } }

    const now = Math.floor(Date.now() / 1000)
    if (entry.used || now > entry.expires) {
      env.RATE_LIMIT.delete(`cvtok:${token}`)
      return { status: 401, body: { error: 'Token expired. Request a new one.' } }
    }
    env.RATE_LIMIT.put(`cvtok:${token}`, JSON.stringify({ ...entry, used: true }), { expirationTtl: 60 })
  }

  const cvUrl = env.CV_URL
  if (!cvUrl) return { status: 404, body: { error: 'CV not configured.' } }

  // Untuk redirect, return Response langsung (bukan { status, body })
  // Kita tangani khusus di bawah
  return { status: 302, body: null, redirectUrl: cvUrl }
}

// =============================================================
//  UTILITIES
// =============================================================

function getAllowedOrigins(env) {
  return [
    env.ALLOWED_ORIGIN,
    'https://fauzandwip.pages.dev',
    'https://fauzandwip.dev',
    'https://www.fauzandwip.dev',
    'http://localhost:5173',
    'http://localhost:3000',
  ].filter(Boolean)
}

function sanitize(str) {
  return str
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;')
    .trim().slice(0, 5000)
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) && email.length <= 254
}

function getFirstName(name) { return (name || 'there').split(' ')[0] }

async function hashStr(input) {
  const data  = new TextEncoder().encode(input)
  const hash  = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12)
}

async function sendEmail(apiKey, payload) {
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.text().catch(() => 'unknown')
    throw new Error(`Resend ${res.status}: ${err}`)
  }
  return res.json()
}

// =============================================================
//  EMAIL TEMPLATES
// =============================================================

function buildIncomingEmail({ name, email, subject, message }) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',Arial,sans-serif;background:#04060f;padding:24px}.w{max-width:560px;margin:0 auto}.h{background:linear-gradient(135deg,#0ea5e9,#818cf8);padding:28px 32px;border-radius:12px 12px 0 0;text-align:center}.h h1{color:#fff;font-size:20px;font-weight:600}.b{background:#080d1c;border:1px solid rgba(56,189,248,.15);border-top:none;border-radius:0 0 12px 12px;padding:28px 32px}.l{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:#64748b;margin:16px 0 4px;font-family:monospace}.l:first-child{margin-top:0}.v{background:#0d1427;border-radius:6px;padding:10px 14px;font-size:13px;color:#e2e8f0;word-break:break-word;white-space:pre-wrap}.f{text-align:center;font-size:11px;color:#475569;margin-top:20px}</style>
</head><body><div class="w">
<div class="h"><h1>New Portfolio Message</h1></div>
<div class="b">
<p class="l">From</p><p class="v">${name} &lt;${email}&gt;</p>
<p class="l">Subject</p><p class="v">${subject}</p>
<p class="l">Message</p><p class="v">${message}</p>
</div>
<p class="f">fauzan.dev &mdash; Cloudflare Workers</p>
</div></body></html>`
}

function buildAutoReplyEmail(name) {
  const fn = getFirstName(name)
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',Arial,sans-serif;background:#04060f;padding:24px}.w{max-width:560px;margin:0 auto}.h{background:linear-gradient(135deg,#0ea5e9,#818cf8);padding:36px 32px;border-radius:12px 12px 0 0;text-align:center}.h h1{color:#fff;font-size:22px;font-weight:700;margin-bottom:6px}.h p{color:rgba(255,255,255,.8);font-size:13px}.b{background:#080d1c;border:1px solid rgba(56,189,248,.15);border-top:none;border-radius:0 0 12px 12px;padding:32px}p{color:#94a3b8;font-size:14px;line-height:1.8;margin-bottom:12px}strong{color:#38bdf8}.cta{display:inline-block;margin-top:8px;background:linear-gradient(135deg,#0ea5e9,#818cf8);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}.f{text-align:center;font-size:11px;color:#475569;margin-top:20px}</style>
</head><body><div class="w">
<div class="h"><h1>Hey, ${fn}!</h1><p>Thanks for reaching out</p></div>
<div class="b">
<p>I received your message and I am excited to connect! I will get back to you within <strong>24&ndash;48 hours</strong>.</p>
<p>In the meantime, feel free to check out my projects on GitHub.</p>
<p>&mdash; <strong>M. Fauzan Dwi P</strong><br>AI &amp; ML Engineer &middot; GCP Specialist</p>
<a href="https://github.com/fauzandwip" class="cta">View My Projects</a>
</div>
<p class="f">fauzan.dev &middot; Cloudflare Workers</p>
</div></body></html>`
}
