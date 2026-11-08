// dagr-signed-token — Go example. Mints and verifies the shared token (see
// ../../CONTRACT.md). The codec is the generated `token` module (gen/go): the direct
// builder mints straight from a value tree, and the verifier's gate checks the header
// before the body is decoded. HMAC-SHA256 is Go's standard library.
//
// CLI:  dst-go             → run the showcase (mint, verify, tamper, alg:none, expiry)
//
//	dst-go emit   PATH → write a valid token to PATH
//	dst-go verify PATH → verify+decode a token minted by any language
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tk "token"
	"token/dagr"
	td "token/tokendirect"
)

var secret = []byte("dagr-signed-token-demo-secret-2026")

const (
	kid = "hmac-key-2026"
	now = uint64(1_760_000_000)
	exp = now + 3600
)

// preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md).
func preimage(rootOffset int, body []byte) []byte {
	m := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint64(m, uint64(rootOffset))
	return append(m, body...)
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func claims(expiresAt uint64) td.Claims {
	// custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
	custom := td.JSONObject([]td.JSONMember{
		{Key: "tenant", Value: dagr.Some(td.JSONString("acme"))},
		{Key: "roles", Value: dagr.Some(td.JSONArray(td.JSONList{
			dagr.Some(td.JSONString("admin")),
			dagr.Some(td.JSONString("billing")),
		}))},
		{Key: "mfa", Value: dagr.Some(td.JSONBool(true))},
		{Key: "fp", Value: dagr.Some(td.JSONData([]byte{0xDE, 0xAD, 0xBE, 0xEF}))},
	})
	return td.Claims{
		Subject:   dagr.Some("user-42"),
		Issuer:    dagr.Some("https://issuer.dagr.one"),
		Audience:  dagr.Some("dagr-api"),
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Scopes:    dagr.Some([]string{"read:profile", "write:posts"}),
		Custom:    dagr.Some(custom),
	}
}

func mint(key []byte, alg string, expiresAt uint64) []byte {
	return td.BuildTokenWithHeader(claims(expiresAt), 0, func(rootOffset int, body []byte) td.Jws {
		return td.Jws{
			Algorithm: alg,
			KeyID:     dagr.Some(kid),
			Signature: hmacSHA256(key, preimage(rootOffset, body)),
		}
	})
}

var (
	errBadAlg        = errors.New("BadAlg")
	errBadSignature  = errors.New("BadSignature")
	errExpired       = errors.New("Expired")
	errWrongAudience = errors.New("WrongAudience")
)

func stage(err error) string {
	if errors.Is(err, errBadAlg) || errors.Is(err, errBadSignature) {
		return "GATE (verify-before-parse)"
	}
	return "post-decode claim check"
}

// verify is verify-before-parse over the lazy reader: the gate reads only the header and
// checks the signature, then the validating open walks the body once (bounds, depth, UTF-8)
// and the claims are read in place — no value tree, no allocation.
func verify(token, key []byte, at uint64) error {
	h, ok, err := tk.OpenTokenHeader(token)
	if err != nil || !ok {
		return errBadSignature
	}
	if h.Algorithm() != "HS256" {
		return errBadAlg
	}
	start, span, rootOffset, err := dagr.HeaderFrame(token)
	if err != nil {
		return errBadSignature
	}
	mac := hmac.New(sha256.New, key)
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], uint64(rootOffset))
	mac.Write(le[:])
	mac.Write(token[start+span:])
	var sum [32]byte
	if !hmac.Equal(h.Signature(), mac.Sum(sum[:0])) {
		return errBadSignature
	}
	c, err := tk.OpenToken(token)
	if err != nil {
		return errBadSignature
	}
	if at >= c.ExpiresAt() {
		return errExpired
	}
	if aud, ok := c.Audience(); !ok || aud != "dagr-api" {
		return errWrongAudience
	}
	return nil
}

func jsonString(v td.JSONValue) string {
	switch v.Tag() {
	case td.JSONTagString:
		return strconv.Quote(v.String())
	case td.JSONTagNumber:
		return strconv.FormatFloat(v.Number(), 'g', -1, 64)
	case td.JSONTagBool:
		return strconv.FormatBool(v.Bool())
	case td.JSONTagArray:
		var parts []string
		for _, e := range v.Array() {
			if e.Ok {
				parts = append(parts, jsonString(e.V))
			} else {
				parts = append(parts, "null")
			}
		}
		return "[" + strings.Join(parts, ",") + "]"
	case td.JSONTagObject:
		var parts []string
		for _, m := range v.Object() {
			val := "null"
			if m.Value.Ok {
				val = jsonString(m.Value.V)
			}
			parts = append(parts, strconv.Quote(m.Key)+":"+val)
		}
		return "{" + strings.Join(parts, ",") + "}"
	case td.JSONTagData:
		return fmt.Sprintf("0x%x", v.Data())
	}
	return "?"
}

func report(label string, token []byte, err error) {
	if err != nil {
		fmt.Printf("  %-20s REJECT  [%s] %v\n", label, stage(err), err)
		return
	}
	c, rerr := td.RestoreTokenValues(token) // already verified: decoded only to print it
	if rerr != nil {
		panic(rerr)
	}
	sub := c.Subject.V
	custom := "-"
	if c.Custom.Ok {
		custom = jsonString(c.Custom.V)
	}
	fmt.Printf("  %-20s ACCEPT  sub=%q custom=%s\n", label, sub, custom)
}

func bodyStart(token []byte) int {
	start, span, _, err := dagr.HeaderFrame(token)
	if err != nil {
		panic(err)
	}
	return start + span
}

// timeNs runs f `iters` times after a warm-up and returns nanoseconds per call.
func timeNs(iters int, f func()) int64 {
	for i := 0; i < iters/10; i++ {
		f()
	}
	t := time.Now()
	for i := 0; i < iters; i++ {
		f()
	}
	return time.Since(t).Nanoseconds() / int64(iters)
}

var sink int

// bench: mint (direct builder + HMAC) and verify (header gate + validating lazy open), 50k
// reps each, correctness-gated first. Prints the `BENCH` line run_bench.sh tabulates.
func bench() {
	const n = 50_000
	tok := mint(secret, "HS256", exp)
	tampered := append([]byte(nil), tok...)
	tampered[bodyStart(tampered)] ^= 0x01
	if verify(tok, secret, now) != nil || verify(mint(secret, "HS256", now-1), secret, now) == nil ||
		verify(tampered, secret, now) == nil {
		panic("bench: correctness gate failed")
	}
	m := timeNs(n, func() { sink += len(mint(secret, "HS256", exp)) })
	v := timeNs(n, func() {
		if verify(tok, secret, now) == nil {
			sink++
		}
	})
	fmt.Printf("BENCH go dagr mint=%d verify=%d size=%d\n", m, v, len(tok))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bench" {
		bench()
		return
	}
	if len(os.Args) > 2 {
		switch os.Args[1] {
		case "emit":
			if err := os.WriteFile(os.Args[2], mint(secret, "HS256", exp), 0o644); err != nil {
				panic(err)
			}
			fmt.Printf("[go] emitted -> %s\n", os.Args[2])
			return
		case "verify":
			data, err := os.ReadFile(os.Args[2])
			if err != nil {
				panic(err)
			}
			verr := verify(data, secret, now)
			report("[go] "+os.Args[2], data, verr)
			if verr != nil {
				os.Exit(1)
			}
			return
		}
	}

	fmt.Println("== dagr-signed-token — Go ==")
	fmt.Println()
	token := mint(secret, "HS256", exp)
	fmt.Printf("Minted token: %d bytes\n\n", len(token))
	fmt.Println("Verification:")
	report("valid token", token, verify(token, secret, now))
	tampered := append([]byte(nil), token...)
	tampered[bodyStart(tampered)] ^= 0x01
	report("tampered body", tampered, verify(tampered, secret, now))
	report("wrong key", token, verify(token, []byte("not-the-secret"), now))
	none := mint(secret, "none", exp)
	report("alg:none token", none, verify(none, secret, now))
	expired := mint(secret, "HS256", now-1)
	report("expired token", expired, verify(expired, secret, now))
}
