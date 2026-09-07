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
import "core:time"

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
	// custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }.
	// NOTE: hoist every nested slice literal into a named var — an Odin compound-literal
	// `[]T{...}` used inline in a larger expression is a temporary whose backing array
	// does not outlive the statement, so a nested one would dangle before the writer walks
	// it. Named vars live for this proc's scope (the whole `to_bytes_with_header` call).
	roles := []Maybe(tok.Json_Value){
		tok.Json_Value{tag = .string, string = "admin"},
		tok.Json_Value{tag = .string, string = "billing"},
	}
	fp := []u8{0xDE, 0xAD, 0xBE, 0xEF}
	members := []tok.JsonMember_Value{
		{key = "tenant", value = tok.Json_Value{tag = .string, string = "acme"}},
		{key = "roles", value = tok.Json_Value{tag = .array, array = roles}},
		{key = "mfa", value = tok.Json_Value{tag = .bool, bool = true}},
		{key = "fp", value = tok.Json_Value{tag = .data, data = fp}},
	}
	custom := tok.Json_Value{tag = .object, object = members}
	scopes := []string{"read:profile", "write:posts"}
	claims := tok.Claims_Value{
		subject    = "user-42",
		issuer     = "https://issuer.dagr.one",
		audience   = "dagr-api",
		issued_at  = NOW,
		expires_at = exp,
		scopes     = scopes,
		custom     = custom,
	}
	ctx := Mint_Ctx{secret = secret, alg = alg}
	return tok.claims_writer_to_bytes_with_header(w, claims, &ctx, header_fn)
}

// Profiling helpers: serialize the same claims with a fixed signature — no preimage, no HMAC —
// to isolate the writer's build+serialize cost from the crypto.
FIXED_SIG := [32]u8{}
header_noop :: proc(ctx: rawptr, root_offset: int, body: []u8) -> tok.Jws_Value {
	return tok.Jws_Value{algorithm = "HS256", key_id = KID, signature = FIXED_SIG[:]}
}
mint_nohmac :: proc(w: ^tok.Claims_Writer, exp: u64) -> []u8 {
	roles := []Maybe(tok.Json_Value){
		tok.Json_Value{tag = .string, string = "admin"},
		tok.Json_Value{tag = .string, string = "billing"},
	}
	fp := []u8{0xDE, 0xAD, 0xBE, 0xEF}
	members := []tok.JsonMember_Value{
		{key = "tenant", value = tok.Json_Value{tag = .string, string = "acme"}},
		{key = "roles", value = tok.Json_Value{tag = .array, array = roles}},
		{key = "mfa", value = tok.Json_Value{tag = .bool, bool = true}},
		{key = "fp", value = tok.Json_Value{tag = .data, data = fp}},
	}
	custom := tok.Json_Value{tag = .object, object = members}
	scopes := []string{"read:profile", "write:posts"}
	claims := tok.Claims_Value{
		subject = "user-42", issuer = "https://issuer.dagr.one", audience = "dagr-api",
		issued_at = NOW, expires_at = exp, scopes = scopes, custom = custom,
	}
	return tok.claims_writer_to_bytes_with_header(w, claims, nil, header_noop)
}

Verify_Ctx :: struct { secret: string, reason: string }

// Gate (runs before the body is parsed): alg pinned + constant-time HMAC check.
// `h` is the lazy header accessor — read algorithm/signature straight from the buffer
// (zero-copy borrows), no eager restore and key_id never touched.
gate :: proc(ctx: rawptr, h: tok.Jws_Accessor, root_offset: int, body: []u8) -> bool {
	c := cast(^Verify_Ctx)ctx
	blk := tok.jws_block(h)                                   // parse field positions once
	if tok.jws_algorithm(h, blk) != "HS256" { c.reason = "BadAlg"; return false }
	msg := preimage(root_offset, body)
	defer delete(msg)
	if !hmac.verify(hash.Algorithm.SHA256, tok.jws_signature(h, blk), msg, transmute([]u8)c.secret) {
		c.reason = "BadSignature"; return false
	}
	return true
}

Verdict :: struct { ok: bool, reason: string, stage: string, acc: tok.Claims_Accessor }

// Header-aware lazy root: run the crypto GATE (verify-before-parse), then return a
// zero-copy `Claims_Accessor` rooted past the packed header — no eager restore. Mirrors
// the generated `claims_from_bytes_with_header` framing, but hands back the accessor.
lazy_root_with_header :: proc(data: []u8, ctx: rawptr,
	gate: proc(ctx: rawptr, h: tok.Jws_Accessor, root_offset: int, body: []u8) -> bool,
) -> (tok.Claims_Accessor, bool) {
	framing, rl := dr.read_leb(data, 0)
	if framing & 1 != 1 { return {}, false }
	if (framing >> 1) & 1 != 0 { return {}, false }
	stored_offset := int(framing >> 2)
	hcs, hcsb := dr.read_leb(data, rl)
	h := hcsb + int(hcs)
	header := tok.Jws_Accessor{buf = data, pos = rl}          // lazy view — no eager restore
	body := data[rl + h:]
	if !gate(ctx, header, stored_offset - h, body) { return {}, false }
	return tok.Claims_Accessor{buf = data, pos = rl + stored_offset}, true
}

// Verify-before-parse, then read claims with ZERO-ALLOC LAZY ACCESSORS — no arena/restore.
verify :: proc(token: []u8, secret: string, now: u64) -> Verdict {
	ctx := Verify_Ctx{secret = secret}
	acc, ok := lazy_root_with_header(token, &ctx, gate)
	if !ok { return {ok = false, reason = ctx.reason, stage = "GATE (verify-before-parse)"} }
	blk := tok.claims_block(acc)   // field positions parsed once; reused across reads
	if now >= tok.claims_expires_at(acc, blk) {
		return {ok = false, reason = "Expired", stage = "post-decode claim check", acc = acc}
	}
	if aud, has := tok.claims_audience(acc, blk).?; !has || aud != "dagr-api" {
		return {ok = false, reason = "WrongAudience", stage = "post-decode claim check", acc = acc}
	}
	return {ok = true, acc = acc}
}

// Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
json_str_lazy :: proc(sb: ^strings.Builder, j: tok.Json_PackedView) {
	switch tok.json_packed_view_tag(j) {
	case .string: fmt.sbprintf(sb, "%q", tok.json_packed_string(j))
	case .number: fmt.sbprintf(sb, "%v", tok.json_packed_number(j))
	case .bool:   fmt.sbprintf(sb, "%v", tok.json_packed_bool(j))
	case .array:
		strings.write_byte(sb, '[')
		for i in 0 ..< tok.json_packed_array_len(j) {
			if i > 0 { strings.write_byte(sb, ',') }
			if e, has := tok.json_packed_array_get(j, i).?; has { json_str_lazy(sb, e) } else { strings.write_string(sb, "null") }
		}
		strings.write_byte(sb, ']')
	case .object:
		strings.write_byte(sb, '{')
		for i in 0 ..< tok.json_packed_object_len(j) {
			if i > 0 { strings.write_byte(sb, ',') }
			m := tok.json_packed_object_get(j, i)
			fmt.sbprintf(sb, "%q:", tok.json_member_key(m))
			if v, has := tok.json_member_value(m).?; has { json_str_lazy(sb, v) } else { strings.write_string(sb, "null") }
		}
		strings.write_byte(sb, '}')
	case .data:
		strings.write_string(sb, "0x")
		for b in tok.json_packed_data(j) { fmt.sbprintf(sb, "%02x", b) }
	}
}

report :: proc(label: string, v: Verdict) {
	if v.ok {
		sb := strings.builder_make(); defer strings.builder_destroy(&sb)
		if c, ok := tok.claims_custom(v.acc).?; ok { json_str_lazy(&sb, c) } else { strings.write_byte(&sb, '-') }
		fmt.printf("  %-22s ACCEPT  sub=%v custom=%v\n",
			label, tok.claims_subject(v.acc).? or_else "-", strings.to_string(sb))
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

	if len(args) >= 2 && args[1] == "bench" {
		// Mint + verify throughput (no JWT baseline in Odin — see Rust/TS/Python for that).
		n := 50000
		// mint returns a slice into the reused writer, so COPY the token we verify.
		m0 := mint(&w, SECRET, "HS256", EXP)
		tok := make([]u8, len(m0)); copy(tok, m0)
		if !verify(tok, SECRET, NOW).ok { fmt.eprintln("verify must accept"); os.exit(2) }
		sink: u64 = 0
		for _ in 0 ..< n / 10 { m := mint(&w, SECRET, "HS256", EXP); sink += u64(m[0]) }   // warmup
		t0 := time.tick_now()
		for _ in 0 ..< n { m := mint(&w, SECRET, "HS256", EXP); sink += u64(m[0]) }
		dm := time.duration_nanoseconds(time.tick_since(t0)) / i64(n)
		for _ in 0 ..< n / 10 { if verify(tok, SECRET, NOW).ok { sink += 1 } }
		t1 := time.tick_now()
		for _ in 0 ..< n { if verify(tok, SECRET, NOW).ok { sink += 1 } }
		dv := time.duration_nanoseconds(time.tick_since(t1)) / i64(n)
		fmt.printf("BENCH odin dagr mint=%d verify=%d size=%d\n", dm, dv, len(tok))
		if sink == 12345678 { fmt.println("") }
		return
	}
	if len(args) >= 2 && args[1] == "profile" {
		n := 50000
		m0 := mint(&w, SECRET, "HS256", EXP)
		body := make([]u8, len(m0)); copy(body, m0); defer delete(body)
		key := transmute([]u8)string(SECRET)
		sink: u64 = 0
		for _ in 0 ..< n / 10 { m := mint(&w, SECRET, "HS256", EXP); sink += u64(m[0]) }
		t0 := time.tick_now()
		for _ in 0 ..< n { m := mint(&w, SECRET, "HS256", EXP); sink += u64(m[0]) }
		dm := time.duration_nanoseconds(time.tick_since(t0)) / i64(n)
		for _ in 0 ..< n / 10 { m := mint_nohmac(&w, EXP); sink += u64(m[0]) }
		ts := time.tick_now()
		for _ in 0 ..< n { m := mint_nohmac(&w, EXP); sink += u64(m[0]) }
		dser := time.duration_nanoseconds(time.tick_since(ts)) / i64(n)
		for _ in 0 ..< n / 10 { msg := preimage(0, body); tag := hmac_sha256(key, msg); sink += u64(tag[0]); delete(msg); delete(tag) }
		th := time.tick_now()
		for _ in 0 ..< n { msg := preimage(0, body); tag := hmac_sha256(key, msg); sink += u64(tag[0]); delete(msg); delete(tag) }
		dh := time.duration_nanoseconds(time.tick_since(th)) / i64(n)
		fmt.printf("PROFILE odin mint=%dns = serialize(no-hmac)=%dns + hmac(preimage+sum)=%dns\n", dm, dser, dh)
		if sink == 12345678 { fmt.println("") }
		return
	}
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
