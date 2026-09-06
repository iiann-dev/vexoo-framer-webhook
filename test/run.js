// Test suite for vexoo-framer-webhook middleware (core + local server + Vercel handler)
// Run: npm test
// Points MAKE_WEBHOOK_URL at a local mock "Make" server → exercises the REAL HTTP path.
// Also loads api/webhook.js (Vercel handler) and tests it with mocked req/res.

const crypto = require("crypto");
const http = require("http");

const SECRET = "test-secret-123";

// ---- local mock "Make" server ----
let makeServer;
let makeReceived = [];
let makeRespond = { status: 200 };
function startMakeMock() {
  return new Promise((resolve) => {
    makeServer = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        makeReceived.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
        res.writeHead(makeRespond.status, { "Content-Type": "text/plain" });
        res.end("make-ok");
      });
    });
    makeServer.listen(0, "127.0.0.1", () => {
      resolve(`http://127.0.0.1:${makeServer.address().port}/hook/mock`);
    });
  });
}

process.env.FRAMER_WEBHOOK_SECRET = SECRET;
process.env.PORT = "8791";
process.env.ALLOW_TEST_MAKE_URL = "1";

let passed = 0;
let failed = 0;
function ok(name, cond) {
  if (cond) { passed++; console.log("  ✅ " + name); }
  else { failed++; console.log("  ❌ " + name); }
}

function sign(secret, body, submissionId) {
  const h = crypto.createHmac("sha256", secret);
  h.update(body);
  h.update(submissionId);
  return "sha256=" + h.digest("hex");
}

// ---- tiny fake req/res for the Vercel handler ----
function fakeReq({ method, headers, bodyBuffer }) {
  const { Readable } = require("stream");
  const s = Readable.from(bodyBuffer); // proper async-iterable Readable
  s.method = method;
  s.headers = headers || {};
  return s;
}
function fakeRes() {
  const state = { status: null, body: null };
  return {
    state,
    status(c) { state.status = c; return this; },
    send(b) { state.body = b; return this; },
  };
}

(async () => {
  const makeUrl = await startMakeMock();
  process.env.MAKE_WEBHOOK_URL = makeUrl; // set BEFORE requiring handler so env is available
  console.log("DEBUG env MAKE_WEBHOOK_URL =", process.env.MAKE_WEBHOOK_URL, "| FRAMER_SECRET =", process.env.FRAMER_WEBHOOK_SECRET);

  const core = require("../lib/core.js");
  const { isSignatureValid } = core;
  const handler = require("../api/webhook.js"); // Vercel module

  console.log("\n=== Unit: signature verification ===");
  const body = Buffer.from(JSON.stringify({ Name: "T", Email: "t@t.dev" }));
  const sid = "sub_123";
  const goodSig = sign(SECRET, body, sid);

  ok("valid signature => true", isSignatureValid(SECRET, sid, body, goodSig) === true);
  ok("wrong secret => false", isSignatureValid("wrong", sid, body, goodSig) === false);
  ok("wrong body => false", isSignatureValid(SECRET, sid, Buffer.from("{}"), goodSig) === false);
  ok("wrong submissionId => false", isSignatureValid(SECRET, "sub_OTHER", body, goodSig) === false);
  ok("missing header => false", isSignatureValid(SECRET, sid, body, "") === false);
  ok("bad format => false", isSignatureValid(SECRET, sid, body, "abc") === false);
  ok("bad length => false", isSignatureValid(SECRET, sid, body, "sha256=abc") === false);

  console.log("\n=== Vercel handler (api/webhook.js) ===");
  // handler mutates the res object (res.status().send()); it returns undefined.
  // So capture state from the SAME fakeRes instance we pass in.
  const callHandler = async (req) => {
    const res = fakeRes();
    await handler(req, res);
    return res.state;
  };

  // 1) valid
  makeReceived = [];
  let st = await callHandler(fakeReq({ method: "POST", headers: { "framer-signature": goodSig, "framer-webhook-submission-id": sid }, bodyBuffer: body }));
  ok("valid => 200", st.status === 200);
  ok("forwarded to Make", makeReceived.length === 1 && makeReceived[0].body === body.toString());

  // 2) invalid sig
  makeReceived = [];
  st = await callHandler(fakeReq({ method: "POST", headers: { "framer-signature": "sha256=" + "0".repeat(64), "framer-webhook-submission-id": sid }, bodyBuffer: body }));
  ok("invalid => 401", st.status === 401);
  ok("not forwarded", makeReceived.length === 0);

  // 3) GET => 405
  st = await callHandler(fakeReq({ method: "GET", headers: {}, bodyBuffer: Buffer.alloc(0) }));
  ok("GET => 405", st.status === 405);

  // 4) Make 500 => 502
  makeRespond = { status: 500 };
  st = await callHandler(fakeReq({ method: "POST", headers: { "framer-signature": goodSig, "framer-webhook-submission-id": sid }, bodyBuffer: body }));
  ok("Make 500 => 502", st.status === 502);
  makeRespond = { status: 200 };

  console.log("\n=== Local server (dev-server.js) via real HTTP ===");
  const mod = require("../dev-server.js");
  // server.listen() no longer auto-starts (guarded by require.main === module for Vercel compat)
  // so we explicitly start it here for tests:
  const localPort = parseInt(process.env.PORT || "8791", 10);
  await new Promise((resolve) => mod.server.listen(localPort, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${localPort}`;

  makeReceived = [];
  let rr = await fetch(base + "/", {
    method: "POST",
    headers: { "content-type": "application/json", "framer-signature": goodSig, "framer-webhook-submission-id": sid },
    body,
  });
  ok("valid POST => 200", rr.status === 200);
  ok("payload forwarded", makeReceived.length === 1 && makeReceived[0].body === body.toString());

  makeReceived = [];
  rr = await fetch(base + "/", {
    method: "POST",
    headers: { "content-type": "application/json", "framer-signature": "sha256=" + "0".repeat(64), "framer-webhook-submission-id": sid },
    body,
  });
  ok("invalid => 401", rr.status === 401);
  ok("not forwarded", makeReceived.length === 0);

  rr = await fetch(base + "/", { method: "GET" });
  ok("GET => 405", rr.status === 405);

  console.log(`\n${passed} passed, ${failed} failed`);
  makeServer.close();
  mod.server.close();
  process.exit(failed ? 1 : 0);
})();