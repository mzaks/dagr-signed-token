// dagr-signed-token — TypeScript example (see ../../CONTRACT.md).
// Codec is the generated gen/typescript modules; crypto is Node's built-in
// `node:crypto` (HMAC-SHA256) — no npm dependencies.
//
//   npx tsx demo.ts              → showcase
//   npx tsx demo.ts emit  PATH   → write a valid token
//   npx tsx demo.ts verify PATH  → verify+decode a token minted by any language
import { Arena, type Json } from "../../gen/typescript/Token_arena";
import { toBytesWithHeader, lazyRootWithHeader, type Jws } from "../../gen/typescript/Token_serde";
import { type ClaimsAccessor, type JsonPackedView } from "../../gen/typescript/Token";
import {
  toBytesWithHeader as toBytesWithHeaderDirect,
  type Claims as DirectClaims, type JsonValue,
} from "../../gen/typescript/Token_direct";
import { Buf, readLEB } from "../../gen/typescript/dagr_reader";
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const SECRET = Buffer.from("dagr-signed-token-demo-secret-2026");
const KID = "hmac-key-2026";
const NOW = 1_760_000_000n;
const EXP = NOW + 3600n;

function hmacSHA256(key: Buffer, msg: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(msg).digest());
}

// preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md).
function preimage(rootOffset: number, body: Uint8Array): Uint8Array {
  const m = new Uint8Array(8 + body.length);
  new DataView(m.buffer).setBigUint64(0, BigInt(rootOffset), true);
  m.set(body, 8);
  return m;
}

function mint(alg: string, exp: bigint): Uint8Array {
  const a = new Arena();
  // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
  const custom: Json = { type: "object", value: [
    a.newJsonMember("tenant", { type: "string", value: "acme" }),
    a.newJsonMember("roles", { type: "array", value: [
      { type: "string", value: "admin" }, { type: "string", value: "billing" }] }),
    a.newJsonMember("mfa", { type: "bool", value: true }),
  ]};
  const root = a.newClaims("user-42", "https://issuer.dagr.one", "dagr-api",
    NOW, exp, ["read:profile", "write:posts"], custom);
  return toBytesWithHeader(root, (rootOffset, body) => ({
    algorithm: alg, keyId: KID, signature: hmacSHA256(SECRET, preimage(rootOffset, body)),
  } satisfies Jws));
}

// Direct Graph Builder ("31 Direct Graph Builder.md"): mint the SAME token from a plain
// value tree, arena-free. Must be byte-identical to `mint` (spec §6 gate).
function mintDirect(alg: string, exp: bigint): Uint8Array {
  const custom: JsonValue = { type: "object", value: [
    { key: "tenant", value: { type: "string", value: "acme" } },
    { key: "roles", value: { type: "array", value: [
      { type: "string", value: "admin" }, { type: "string", value: "billing" }] } },
    { key: "mfa", value: { type: "bool", value: true } },
  ]};
  const root: DirectClaims = {
    subject: "user-42", issuer: "https://issuer.dagr.one", audience: "dagr-api",
    issuedAt: NOW, expiresAt: exp, scopes: ["read:profile", "write:posts"], custom,
  };
  return toBytesWithHeaderDirect(root, (rootOffset, body) => ({
    algorithm: alg, keyId: KID, signature: hmacSHA256(SECRET, preimage(rootOffset, body)),
  } satisfies Jws));
}

type Verdict =
  | { ok: true; acc: ClaimsAccessor }
  | { ok: false; reason: string; stage: string };

// Verify-before-parse, then read claims with ZERO-ALLOC LAZY ACCESSORS — no arena restore.
// `lazyRootWithHeader` runs the crypto GATE before returning a `ClaimsAccessor` that reads
// fields straight off the token buffer on demand.
function verify(token: Uint8Array, now: bigint, secret: Buffer): Verdict {
  let reason: string | null = null;
  let stage = "GATE (verify-before-parse)";
  try {
    const c = lazyRootWithHeader(token, (h, rootOffset, body) => {
      if (h.algorithm !== "HS256") { reason = "BadAlg"; throw new Error(reason); }
      const expected = Buffer.from(hmacSHA256(secret, preimage(rootOffset, body)));
      const got = Buffer.from(h.signature);
      if (got.length !== expected.length || !timingSafeEqual(got, expected)) { reason = "BadSignature"; throw new Error(reason); }
    });
    stage = "post-decode claim check";
    if (now >= c.expiresAt) return { ok: false, reason: "Expired", stage };
    if (c.audience !== "dagr-api") return { ok: false, reason: "WrongAudience", stage };
    return { ok: true, acc: c };
  } catch {
    return { ok: false, reason: reason ?? "BadSignature", stage };
  }
}

// Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
function jsonStr(j: JsonPackedView | null): string {
  if (j === null) return "-";
  switch (j.type) {
    case "string": return JSON.stringify(j.value);
    case "number": return String(j.value);
    case "bool":   return String(j.value);
    case "array":  return "[" + j.value.map(jsonStr).join(",") + "]";
    case "object": return "{" + j.value.map((m) => `${JSON.stringify(m.key)}:${jsonStr(m.value)}`).join(",") + "}";
  }
}

function report(label: string, v: Verdict): void {
  const tag = label.padEnd(22);
  if (v.ok) {
    const c = v.acc;
    console.log(`  ${tag} ACCEPT  sub="${c.subject}" custom=${jsonStr(c.custom)}`);
  } else {
    console.log(`  ${tag} REJECT  [${v.stage}] ${v.reason}`);
  }
}

const [, , cmd, path] = process.argv;
if (cmd === "direct") {
  const a = mint("HS256", EXP);
  const d = mintDirect("HS256", EXP);
  const eq = a.length === d.length && a.every((x, i) => x === d[i]);
  if (eq) { console.log(`[ts] direct == arena (${d.length} bytes) — spec 31 gate OK`); }
  else { console.log(`[ts] direct != arena (arena ${a.length} vs direct ${d.length})`); process.exit(1); }
} else if (cmd === "emit" && path) {
  writeFileSync(path, mint("HS256", EXP));
  console.log(`[ts] emitted -> ${path}`);
} else if (cmd === "verify" && path) {
  const v = verify(new Uint8Array(readFileSync(path)), NOW, SECRET);
  report(`[ts] ${path}`, v);
  process.exit(v.ok ? 0 : 1);
} else {
  console.log("== dagr-signed-token — TypeScript ==\n");
  const token = mint("HS256", EXP);
  console.log(`Minted token: ${token.length} bytes\n`);
  console.log("Verification:");
  report("valid token", verify(token, NOW, SECRET));

  const tampered = token.slice();
  const b = new Buf(token);
  const [, fLen] = readLEB(b, 0);
  const [hcs, hcsB] = readLEB(b, fLen);
  tampered[fLen + hcsB + Number(hcs)] ^= 0x01; // flip a byte in the body region
  report("tampered body", verify(tampered, NOW, SECRET));

  report("wrong key", verify(token, NOW, Buffer.from("not-the-secret")));
  report("alg:none token", verify(mint("none", EXP), NOW, SECRET));
  report("expired token", verify(mint("HS256", NOW - 1n), NOW, SECRET));
}
