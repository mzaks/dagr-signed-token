// dagr-signed-token — Odin example (see ../../CONTRACT.md). Built against the generated
// package in gen/odin (the `tok` alias) and its runtime sub-package (the `dr` alias);
// the crypto is Odin's core SHA-256 HMAC (constant-time verify).
//
// CLI:  dst-odin            → showcase (mint, verify, tamper, alg:none, expiry)
//       dst-odin emit  PATH → write a valid token
//       dst-odin verify PATH → verify+decode a token minted by any language
package main

import "core:crypto/hash"
import "core:crypto/hmac"
import "core:fmt"
import "core:os"
import "core:strings"

import tok "../../gen/odin"
import dr "../../gen/odin/runtime"

SECRET :: "dagr-signed-token-demo-secret-2026"
KID :: "hmac-key-2026"
NOW :: u64(1_760_000_000)
EXP :: NOW + 3600

// preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md).
preimage :: proc(root_offset: int, body: []u8) -> []u8 {
	m := make([]u8, 8 + len(body))
	off := u64(root_offset)
	for i in 0 ..< 8 { m[i] = u8(off >> uint(8 * i)) }
	copy(m[8:], body)
	return m
}

hmac_sha256 :: proc(key: []u8, msg: []u8) -> []u8 {
	tag := make([]u8, 32)
	hmac.sum(hash.Algorithm.SHA256, tag, msg, key)
	return tag
}

Mint_Ctx :: struct { secret: string, alg: string }

header_fn :: proc(ctx: rawptr, root_offset: int, body: []u8) -> tok.Jws_Value {
	c := cast(^Mint_Ctx)ctx
	msg := preimage(root_offset, body)
	defer delete(msg)
	return tok.Jws_Value{
		algorithm = c.alg,
		key_id    = KID,
		signature = hmac_sha256(transmute([]u8)c.secret, msg),
	}
}

// Mint via the reusable direct-graph-builder Writer (spec 31 §4.3): no arena — the claims
// are a value tree handed straight to the writer, which reuses one builder across mints.
mint :: proc(w: ^tok.Claims_Writer, secret: string, alg: string, exp: u64) -> []u8 {
	// custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
	custom := tok.Json_Value{
		tag = .object,
		object = []tok.JsonMember_Value{
			{key = "tenant", value = tok.Json_Value{tag = .string, string = "acme"}},
			{key = "roles", value = tok.Json_Value{tag = .array, array = []Maybe(tok.Json_Value){
				tok.Json_Value{tag = .string, string = "admin"},
				tok.Json_Value{tag = .string, string = "billing"},
			}}},
			{key = "mfa", value = tok.Json_Value{tag = .bool, bool = true}},
		},
	}
	claims := tok.Claims_Value{
		subject    = "user-42",
		issuer     = "https://issuer.dagr.one",
		audience   = "dagr-api",
		issued_at  = NOW,
		expires_at = exp,
		scopes     = []string{"read:profile", "write:posts"},
		custom     = custom,
	}
	ctx := Mint_Ctx{secret = secret, alg = alg}
	return tok.claims_writer_to_bytes_with_header(w, claims, &ctx, header_fn)
}

Verify_Ctx :: struct { secret: string, reason: string }

// Gate (runs before the body is parsed): alg pinned + constant-time HMAC check.
gate :: proc(ctx: rawptr, h: tok.Jws_Value, root_offset: int, body: []u8) -> bool {
	c := cast(^Verify_Ctx)ctx
	if h.algorithm != "HS256" { c.reason = "BadAlg"; return false }
	msg := preimage(root_offset, body)
	defer delete(msg)
	if !hmac.verify(hash.Algorithm.SHA256, h.signature, msg, transmute([]u8)c.secret) {
		c.reason = "BadSignature"; return false
	}
	return true
}

Verdict :: struct { ok: bool, reason: string, stage: string, claims: tok.Claims_Value }

verify :: proc(token: []u8, secret: string, now: u64) -> Verdict {
	ctx := Verify_Ctx{secret = secret}
	claims, ok := tok.claims_from_bytes_with_header(token, &ctx, gate)
	if !ok { return {ok = false, reason = ctx.reason, stage = "GATE (verify-before-parse)"} }
	if now >= claims.expires_at {
		return {ok = false, reason = "Expired", stage = "post-decode claim check", claims = claims}
	}
	if aud, has := claims.audience.?; !has || aud != "dagr-api" {
		return {ok = false, reason = "WrongAudience", stage = "post-decode claim check", claims = claims}
	}
	return {ok = true, claims = claims}
}

json_str :: proc(sb: ^strings.Builder, j: tok.Json_Value) {
	switch j.tag {
	case .string: fmt.sbprintf(sb, "%q", j.string.? or_else "")
	case .number: fmt.sbprintf(sb, "%v", j.number.? or_else 0)
	case .bool:   fmt.sbprintf(sb, "%v", j.bool.? or_else false)
	case .array:
		strings.write_byte(sb, '[')
		if arr, ok := j.array.?; ok {
			for e, i in arr {
				if i > 0 { strings.write_byte(sb, ',') }
				if v, has := e.?; has { json_str(sb, v) } else { strings.write_string(sb, "null") }
			}
		}
		strings.write_byte(sb, ']')
	case .object:
		strings.write_byte(sb, '{')
		if obj, ok := j.object.?; ok {
			for mem, i in obj {
				if i > 0 { strings.write_byte(sb, ',') }
				fmt.sbprintf(sb, "%q:", mem.key)
				if v, has := mem.value.?; has { json_str(sb, v) } else { strings.write_string(sb, "null") }
			}
		}
		strings.write_byte(sb, '}')
	}
}

report :: proc(label: string, v: Verdict) {
	if v.ok {
		sb := strings.builder_make(); defer strings.builder_destroy(&sb)
		if c, ok := v.claims.custom.?; ok { json_str(&sb, c) } else { strings.write_byte(&sb, '-') }
		fmt.printf("  %-22s ACCEPT  sub=%v custom=%v\n",
			label, v.claims.subject.? or_else "-", strings.to_string(sb))
	} else {
		fmt.printf("  %-22s REJECT  [%s] %s\n", label, v.stage, v.reason)
	}
}

// body_start = framingLen + headerSpan (skip the framing word and the packed header).
body_start :: proc(data: []u8) -> int {
	_, rl := dr.read_leb(data, 0)
	hcs, hcsb := dr.read_leb(data, rl)
	return rl + hcsb + int(hcs)
}

main :: proc() {
	args := os.args
	// One reusable writer, arena-free (spec 31): the showcase mints several tokens through it.
	w := tok.claims_writer_make()
	defer tok.claims_writer_destroy(&w)

	if len(args) >= 3 && args[1] == "emit" {
		token := mint(&w, SECRET, "HS256", EXP)
		if err := os.write_entire_file(args[2], token); err != nil { fmt.eprintln("write failed"); os.exit(2) }
		fmt.printf("[odin] emitted -> %s\n", args[2])
		return
	}
	if len(args) >= 3 && args[1] == "verify" {
		data, rerr := os.read_entire_file_from_path(args[2], context.allocator)
		if rerr != nil { fmt.eprintln("read failed"); os.exit(2) }
		v := verify(data, SECRET, NOW)
		report(fmt.tprintf("[odin] %s", args[2]), v)
		os.exit(0 if v.ok else 1)
	}

	fmt.println("== dagr-signed-token — Odin ==\n")
	token := mint(&w, SECRET, "HS256", EXP)
	fmt.printf("Minted token: %d bytes\n\n", len(token))
	fmt.println("Verification:")
	report("valid token", verify(token, SECRET, NOW))

	tampered := make([]u8, len(token)); copy(tampered, token)
	tampered[body_start(tampered)] ~= 0x01
	report("tampered body", verify(tampered, SECRET, NOW))
	report("wrong key", verify(token, "not-the-secret", NOW))
	report("alg:none token", verify(mint(&w, SECRET, "none", EXP), SECRET, NOW))
	report("expired token", verify(mint(&w, SECRET, "HS256", NOW - 1), SECRET, NOW))
}
