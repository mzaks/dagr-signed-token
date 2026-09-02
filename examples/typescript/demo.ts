// dagr-web-token — TypeScript example (see ../../CONTRACT.md).
// Codec is the generated gen/typescript modules; crypto is Node's built-in
// `node:crypto` (HMAC-SHA256) — no npm dependencies.
//
//   npx tsx demo.ts              → showcase
//   npx tsx demo.ts emit  PATH   → write a valid token
//   npx tsx demo.ts verify PATH  → verify+decode a token minted by any language
import { Arena, type Json } from "../../gen/typescript/Token_arena";
import { toBytesWithHeader, fromBytesWithHeader, type Jws } from "../../gen/typescript/Token_serde";
import { Buf, readLEB } from "../../gen/typescript/dagr_reader";
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const SECRET = Buffer.from("dagr-web-token-demo-secret-2026");
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

type Verdict =
  | { ok: true; arena: ReturnType<typeof fromBytesWithHeader> }
  | { ok: false; reason: string; stage: string };

function verify(token: Uint8Array, now: bigint, secret: Buffer): Verdict {
  let reason: string | null = null;
  let stage = "GATE (verify-before-parse)";
  try {
    const arena = fromBytesWithHeader(token, (h, rootOffset, body) => {
      if (h.algorithm !== "HS256") { reason = "BadAlg"; throw new Error(reason); }
      const expected = Buffer.from(hmacSHA256(secret, preimage(rootOffset, body)));
      const got = Buffer.from(h.signature);
      if (got.length !== expected.length || !timingSafeEqual(got, expected)) { reason = "BadSignature"; throw new Error(reason); }
    });
    stage = "post-decode claim check";
    const c = arena.root!;
    if (now >= c.expiresAt) return { ok: false, reason: "Expired", stage };
    if (c.audience !== "dagr-api") return { ok: false, reason: "WrongAudience", stage };
    return { ok: true, arena };
  } catch {
    return { ok: false, reason: reason ?? "BadSignature", stage };
  }
}

function jsonStr(j: Json | null): string {
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
    const c = v.arena.root!;
    console.log(`  ${tag} ACCEPT  sub="${c.subject}" custom=${jsonStr(c.custom)}`);
  } else {
    console.log(`  ${tag} REJECT  [${v.stage}] ${v.reason}`);
  }
}

const [, , cmd, path] = process.argv;
if (cmd === "emit" && path) {
  writeFileSync(path, mint("HS256", EXP));
  console.log(`[ts] emitted -> ${path}`);
} else if (cmd === "verify" && path) {
  const v = verify(new Uint8Array(readFileSync(path)), NOW, SECRET);
  report(`[ts] ${path}`, v);
  process.exit(v.ok ? 0 : 1);
} else {
  console.log("== dagr-web-token — TypeScript ==\n");
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
