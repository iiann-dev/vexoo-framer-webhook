// lib/core.js — shared, framework-agnostic core logic
// Used by BOTH the local dev server (server.js) and the Vercel function (api/webhook.js)
// so verification + forwarding behave identically everywhere.

const crypto = require("crypto");

// ---- signature verification (mirrors Framer's official example) ----
function isSignatureValid(secret, submissionId, rawBody, signatureHeader) {
  try {
    if (typeof signatureHeader !== "string") return false;
    if (signatureHeader.length !== 71 || !signatureHeader.startsWith("sha256=")) return false;

    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(rawBody);
    hmac.update(submissionId);

    const expected = "sha256=" + hmac.digest("hex");
    const a = Buffer.from(signatureHeader);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ---- forward to Make (uses global fetch — Node 18+ / Vercel runtime) ----
async function forwardToMake(makeUrl, rawBody, extraHeaders = {}) {
  const allowTest = process.env.ALLOW_TEST_MAKE_URL === "1"; // test-only local http mock
  const okScheme = /^https:\/\//.test(makeUrl) || (allowTest && /^http:\/\/127\.0\.0\.1:\d+\//.test(makeUrl));
  if (!makeUrl || !okScheme) {
    return { ok: false, status: 0, error: "MAKE_WEBHOOK_URL not set or invalid" };
  }
  try {
    const res = await fetch(makeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...extraHeaders },
      body: rawBody,
      signal: AbortSignal.timeout(10000), // 10s cap — Framer will retry if we 502
    });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

// ---- raw body reader (stream -> Buffer with size cap) ----
async function readRawBody(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let received = 0;
  for await (const chunk of req) {
    received += chunk.length;
    if (received > maxBytes) {
      const err = new Error("payload too large");
      err.code = "TOO_LARGE";
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

module.exports = { isSignatureValid, forwardToMake, readRawBody };