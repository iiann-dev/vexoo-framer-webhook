// Vercel serverless function — webhook endpoint
// POST /api/webhook
// Verifies Framer signature, forwards payload to Make.
// Returns:
//   200  payload verified + Make accepted
//   401  invalid/missing signature (rejected, NOT forwarded)
//   405  not a POST
//   413  body too large
//   502  Make rejected/unreachable (Framer will retry)
//
// Env (set in Vercel dashboard):
//   FRAMER_WEBHOOK_SECRET
//   MAKE_WEBHOOK_URL

const { isSignatureValid, forwardToMake, readRawBody } = require("../lib/core");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).send("Method Not Allowed");
    return;
  }

  const secret = process.env.FRAMER_WEBHOOK_SECRET || "";
  const makeUrl = process.env.MAKE_WEBHOOK_URL || "";

  if (!secret || !makeUrl) {
    console.error("[api] missing env FRAMER_WEBHOOK_SECRET / MAKE_WEBHOOK_URL");
    res.status(500).send("Server misconfigured");
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req, 1024 * 1024);
  } catch (e) {
    res.status(e.code === "TOO_LARGE" ? 413 : 400).send("Bad request");
    return;
  }

  const signature = req.headers["framer-signature"];
  const submissionId = req.headers["framer-webhook-submission-id"];

  if (!isSignatureValid(secret, submissionId || "", rawBody, signature)) {
    console.warn("[api] invalid signature", { submissionId });
    res.status(401).send("Invalid signature");
    return;
  }

  const result = await forwardToMake(makeUrl, rawBody);

  if (result.ok) {
    console.log("[api] forwarded", { submissionId, makeStatus: result.status });
    res.status(200).send("OK");
    return;
  }

  console.error("[api] forward failed", { submissionId, makeStatus: result.status, error: result.error });
  res.status(502).send("Forward failed");
};