# fauzan-portfolio-api

Cloudflare Worker backend untuk portfolio M. Fauzan Dwi P.
**Gratis selamanya** — 100,000 request/hari, zero cold start, global edge.

---

## Cara Deploy (5 langkah)

### 1. Install dependencies
```bash
npm install
```

### 2. Login ke Cloudflare
```bash
npx wrangler login
# Browser akan terbuka → klik Allow
```

### 3. Buat KV Namespace
```bash
npm run kv:create
# Copy id yang muncul, lalu paste ke wrangler.toml:
# id = "ID_YANG_KAMU_COPY"
```

### 4. Set Secrets (satu per satu)
```bash
npx wrangler secret put RESEND_API_KEY
# → isi: re_xxxx dari resend.com → API Keys

npx wrangler secret put OWNER_EMAIL
# → isi: email kamu (penerima pesan)

npx wrangler secret put EMAIL_DOMAIN
# → isi: fauzandwip.dev (atau nama.pages.dev kalau belum punya domain)

npx wrangler secret put IP_SALT
# → isi: random string dari https://randomkeygen.com

npx wrangler secret put CV_URL
# → isi: Google Drive share link CV kamu
```

### 5. Deploy
```bash
npm run deploy
# Output: https://fauzan-portfolio-api.USERNAME.workers.dev
# Copy URL ini → paste ke index.html (const API_URL = '...')
```

---

## API Endpoints

| Method | Path | Deskripsi |
|--------|------|-----------|
| GET | `/health` | Health check |
| POST | `/contact` | Kirim pesan contact form |
| GET | `/cv/token` | Generate CV download token |
| GET | `/cv/download?token=...` | Download CV |

---

## Security Features

- Rate limiting: 3 pesan / 15 menit per IP (via Cloudflare KV)
- Honeypot field: bot di-drop diam-diam
- Input sanitization: semua input di-escape
- CORS whitelist: hanya domain yang terdaftar
- Security headers: X-Frame-Options, HSTS, CSP, dll
- IP hashing: IP tidak disimpan plaintext (SHA-256 + salt)

---

## Troubleshooting

**Error: KV namespace not found**
→ Jalankan `npm run kv:create`, copy id ke wrangler.toml

**Email tidak terkirim**
→ Cek RESEND_API_KEY sudah di-set, domain sudah verified di resend.com

**CORS error di browser**
→ Update ALLOWED_ORIGIN di wrangler.toml dengan URL Pages kamu
