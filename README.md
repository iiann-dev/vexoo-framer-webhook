# Vexoo Framer Form → Make.com secure middleware

Proxies Framer form submissions to Make.com **after verifying Framer's webhook signature**
(`Framer-Signature`, HMAC-SHA256 — timing-safe). Safe from forged submissions; forwards
the verified payload to Make.

```
Framer (POST + Framer-Signature) → this middleware → Make.com webhook
```

## Live endpoint
After Vercel deploy: `https://<your-project>.vercel.app/api/webhook`

## Environment variables (Vercel dashboard → Settings → Environment Variables)
| Name | Value |
|---|---|
| `FRAMER_WEBHOOK_SECRET` | Your Framer webhook signing secret (Framer form settings/email) |
| `MAKE_WEBHOOK_URL` | `https://hook.make.com/...` |

## Deploy to Vercel
```
npm i -g vercel
vercel login
vercel --prod
```
Or push this repo to GitHub → import in Vercel.

## Framer side
In Framer editor → Contact form → Form Settings → "Send responses to" → **Webhook**
→ paste `https://<your-project>.vercel.app/api/webhook` → Publish.

## Local dev
```
cp .env.example .env   # fill secrets
npm start              # http://localhost:8787
npm test               # 18 tests
```

## Behavior (HTTP status codes)
| Code | Meaning |
|---|---|
| `200` | Signature valid + Make accepted |
| `401` | Invalid/missing signature (rejected, NOT forwarded) |
| `405` | Non-POST |
| `413` | Body > 1MB |
| `502` | Signature OK but Make failed/unreachable (Framer will retry) |

## Security notes
- Timing-safe signature comparison (`crypto.timingSafeEqual`)
- Signature format/length validation (`sha256=` + 64 hex)
- Raw body preserved for exact HMAC
- Make URL restricted to `https://hook.make.com/*` in production
- Secrets only from env, never logged
- 10s forward timeout, 1MB body cap
- `.env` gitignored