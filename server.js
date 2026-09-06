// vexoo-framer-webhook — local dev server
// Same core as the Vercel function. Run: npm start | npm test
// Env: PORT, FRAMER_WEBHOOK_SECRET, MAKE_WEBHOOK_URL

const http = require("http");
const { isSignatureValid, forwardToMake, readRawBody } = require("./lib/core");

const PORT = parseInt(process.env.PORT || "8787", 10);
const SECRET = process.env.FRAMER_WEBHOOK_SECRET || "";
const MAKE_URL = process.env.MAKE_WEBHOOK_URL || "";

if (!SECRET) {
  console.error("[startup] FRAMER_WEBHOOK_SECRET is not set. Refusing to start.");
  process.exit(1);
}
if (!MAKE_URL) {
  console.error("[startup] MAKE_WEBHOOK_URL is not set. Refusing to start.");
  process.exit(1);
}
const ALLOW_TEST = process.env.ALLOW_TEST_MAKE_URL === "1";
if (!ALLOW_TEST && !/^https:\/\/hook\.make\.com\//.test(MAKE_URL)) {
  console.error("[startup] MAKE_WEBHOOK_URL must be a https://hook.make.com/... URL.");
  process.exit(1);
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    return res.end("Method Not Allowed");
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req, 1024 * 1024);
  } catch (e) {
    res.writeHead(e.code === "TOO_LARGE" ? 413 : 400, { "Content-Type": "text/plain" });
    return res.end("Bad request");
  }

  const signature = req.headers["framer-signature"];
  const submissionId = req.headers["framer-webhook-submission-id"];

  if (!isSignatureValid(SECRET, submissionId || "", rawBody, signature)) {
    console.warn("[reject] invalid signature", { submissionId, ip: req.socket.remoteAddress });
    res.writeHead(401, { "Content-Type": "text/plain" });
    return res.end("Invalid signature");
  }

  const result = await forwardToMake(MAKE_URL, rawBody);

  if (result.ok) {
    console.log("[forward] ok", { submissionId, makeStatus: result.status });
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  console.error("[forward] failed", { submissionId, makeStatus: result.status, error: result.error });
  res.writeHead(502, { "Content-Type": "text/plain" });
  return res.end("Forward failed");
});

server.listen(PORT, () => {
  console.log(`[vexoo-framer-webhook] listening on :${PORT}`);
});

module.exports = { isSignatureValid, forwardToMake, server };