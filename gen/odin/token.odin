package dagr_signed_token

import dr "runtime"

Json_Tag :: enum u8 { string, number, bool, array, object, data }
Json_PackedView :: struct { buf: []u8, vp: int, tag: u8, code: u8 }
json_packed_view_tag :: proc(v: Json_PackedView) -> Json_Tag { return Json_Tag(v.tag) }
json_packed_string :: proc(v: Json_PackedView) -> string {
	assert(v.tag == 0, "Json.string: tag mismatch")
	s, _ := dr.read_utf8(v.buf, v.vp)
	return s
}
json_packed_number :: proc(v: Json_PackedView) -> f64 {
	assert(v.tag == 1, "Json.number: tag mismatch")
	if v.code == 5 {
		x, _ := dr.decode_packed_f64(v.buf, v.vp)
		return x
	}
	return dr.read_f64(v.buf, v.vp)
}
json_packed_bool :: proc(v: Json_PackedView) -> bool {
	assert(v.tag == 2, "Json.bool: tag mismatch")
	return dr.read_bool(v.buf, v.vp)
}
json_packed_array_len :: proc(v: Json_PackedView) -> int {
	assert(v.tag == 3, "Json.array: tag mismatch")
	_, ablb := dr.read_leb(v.buf, v.vp)
	c := v.vp + ablb
	cnt, cntb := dr.read_leb(v.buf, c)
	count := int(cnt)
	nb := c + cntb
	hs_at := nb + (count + 7) / 8
	_, hsb := dr.read_leb(v.buf, hs_at)
	hstart := hs_at + hsb
	av := Json_PackedArrayView{buf = v.buf, headers_start = hstart, count = count, nil_base = nb}
	return json_packed_arr_len(av)
}
json_packed_array_get :: proc(v: Json_PackedView, i: int) -> Maybe(Json_PackedView) {
	assert(v.tag == 3, "Json.array: tag mismatch")
	_, ablb := dr.read_leb(v.buf, v.vp)
	c := v.vp + ablb
	cnt, cntb := dr.read_leb(v.buf, c)
	count := int(cnt)
	nb := c + cntb
	hs_at := nb + (count + 7) / 8
	_, hsb := dr.read_leb(v.buf, hs_at)
	hstart := hs_at + hsb
	av := Json_PackedArrayView{buf = v.buf, headers_start = hstart, count = count, nil_base = nb}
	return json_packed_arr_get(av, i)
}
json_packed_object_len :: proc(v: Json_PackedView) -> int {
	assert(v.tag == 4, "Json.object: tag mismatch")
	_, ablb := dr.read_leb(v.buf, v.vp)
	c := v.vp + ablb
	h, _ := dr.read_leb(v.buf, c)
	return int(h)
}
json_packed_object_get :: proc(v: Json_PackedView, i: int) -> JsonMember_Accessor {
	assert(v.tag == 4, "Json.object: tag mismatch")
	_, ablb := dr.read_leb(v.buf, v.vp)
	c := v.vp + ablb
	cnt, hb := dr.read_leb(v.buf, c)
	_ = cnt
	p := c + hb
	for j := 0; j < i; j += 1 { p = dr.skip_blob(v.buf, p) }
	return JsonMember_Accessor{buf = v.buf, pos = p}
}
json_packed_data :: proc(v: Json_PackedView) -> []u8 {
	assert(v.tag == 5, "Json.data: tag mismatch")
	d, _ := dr.read_data(v.buf, v.vp)
	return d
}

Json_PackedArrayView :: struct { buf: []u8, headers_start: int, count: int, nil_base: int }
json_packed_arr_len :: proc(v: Json_PackedArrayView) -> int { return v.count }
json_packed_arr_get :: proc(v: Json_PackedArrayView, i: int) -> Maybe(Json_PackedView) {
	ci := i
	present := v.count
	if v.nil_base >= 0 {
		if (v.buf[v.nil_base + (i >> 3)] >> u8(i & 7)) & 1 == 1 { return nil }
		ci = 0
		present = 0
		for j := 0; j < v.count; j += 1 {
			if (v.buf[v.nil_base + (j >> 3)] >> u8(j & 7)) & 1 == 0 {
				if j < i { ci += 1 }
				present += 1
			}
		}
	}
	hp := v.headers_start
	for _ in 0 ..< present { _, b := dr.read_leb(v.buf, hp); hp += b }
	pp := hp
	hj := v.headers_start
	for _ in 0 ..< ci {
		hh, b := dr.read_leb(v.buf, hj)
		hj += b
		pp += dr.packed_union_payload_bytes(v.buf, pp, int(hh) & 7)
	}
	hi, _ := dr.read_leb(v.buf, hj)
	return Json_PackedView{buf = v.buf, vp = pp, tag = u8((hi >> 3) & 0xFF), code = u8(hi & 7)}
}

Claims_Accessor :: struct { buf: []u8, pos: int }
Claims_Block :: struct { _p0: int, _p1: int, _p2: int, _p3: int, _p4: int, _p5: int, _p6: int, raw: u64, ready: bool }
claims_block :: proc(acc: Claims_Accessor) -> Claims_Block {
	b: Claims_Block
	_, r := dr.read_leb(acc.buf, acc.pos)
	cur := acc.pos + r
	pres := dr.read_bitset(acc.buf, cur, 1)
	cur += 1
	enc := dr.read_bitset(acc.buf, cur, 1)
	cur += 1
		if (pres >> 0) & 1 == 1 {
			b._p0 = cur
			cur = dr.skip_blob(acc.buf, cur)
		} else {
			b._p0 = -1
		}
		if (pres >> 1) & 1 == 1 {
			b._p1 = cur
			cur = dr.skip_blob(acc.buf, cur)
		} else {
			b._p1 = -1
		}
		if (pres >> 2) & 1 == 1 {
			b._p2 = cur
			cur = dr.skip_blob(acc.buf, cur)
		} else {
			b._p2 = -1
		}
		{
			if (enc >> 0) & 1 == 1 { b.raw |= 8 }
			b._p3 = cur
			cur = (enc >> 0) & 1 == 1 ? cur + 8 : dr.leb_end(acc.buf, cur)
		}
		{
			if (enc >> 1) & 1 == 1 { b.raw |= 16 }
			b._p4 = cur
			cur = (enc >> 1) & 1 == 1 ? cur + 8 : dr.leb_end(acc.buf, cur)
		}
		if (pres >> 3) & 1 == 1 {
			b._p5 = cur
			cur = dr.skip_blob(acc.buf, cur)
		} else {
			b._p5 = -1
		}
		if (pres >> 4) & 1 == 1 {
			b._p6 = cur
			uh, uhb := dr.read_leb(acc.buf, cur)
			cur = cur + uhb + dr.packed_union_payload_bytes(acc.buf, cur + uhb, int(uh & 7))
		} else {
			b._p6 = -1
		}
	_ = cur
	b.ready = true
	return b
}
claims_subject :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p0
	if pl < 0 { return nil }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
claims_subject_clone :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	v, ok := claims_subject(acc, blk).?
	if !ok { return nil }
	return dr.clone_string(v)
}
claims_issuer :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p1
	if pl < 0 { return nil }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
claims_issuer_clone :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	v, ok := claims_issuer(acc, blk).?
	if !ok { return nil }
	return dr.clone_string(v)
}
claims_audience :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p2
	if pl < 0 { return nil }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
claims_audience_clone :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(string) {
	v, ok := claims_audience(acc, blk).?
	if !ok { return nil }
	return dr.clone_string(v)
}
claims_issued_at :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> u64 {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p3
	raw := (b.raw >> 3) & 1 == 1
	if pl < 0 { return u64(0) }
	if raw { return dr.read_u64(acc.buf, pl) }
	v, _ := dr.read_leb(acc.buf, pl)
	return u64(v)
}
claims_expires_at :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> u64 {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p4
	raw := (b.raw >> 4) & 1 == 1
	if pl < 0 { return u64(0) }
	if raw { return dr.read_u64(acc.buf, pl) }
	v, _ := dr.read_leb(acc.buf, pl)
	return u64(v)
}
claims_scopes_len :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(int) {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p5
	if pl < 0 { return nil }
	_, blb := dr.read_leb(acc.buf, pl)
	c := pl + blb
	h, _ := dr.read_leb(acc.buf, c)
	return int(h)
}
claims_scopes_get :: proc(acc: Claims_Accessor, i: int, blk := Claims_Block{}) -> string {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p5
	_, blb := dr.read_leb(acc.buf, pl)
	c := pl + blb
	_, hb := dr.read_leb(acc.buf, c)
	p := c + hb
	for j := 0; j < i; j += 1 { p = dr.skip_blob(acc.buf, p) }
	s, _ := dr.read_utf8(acc.buf, p)
	return s
}
claims_custom :: proc(acc: Claims_Accessor, blk := Claims_Block{}) -> Maybe(Json_PackedView) {
	b := blk
	if !b.ready { b = claims_block(acc) }
	pl := b._p6
	if pl < 0 { return nil }
	vp, tag, code := dr.packed_union_header(acc.buf, pl)
	return Json_PackedView{buf = acc.buf, vp = vp, tag = tag, code = code}
}

JsonMember_Accessor :: struct { buf: []u8, pos: int }
JsonMember_Block :: struct { _p0: int, _p1: int, raw: u64, ready: bool }
json_member_block :: proc(acc: JsonMember_Accessor) -> JsonMember_Block {
	b: JsonMember_Block
	_, r := dr.read_leb(acc.buf, acc.pos)
	cur := acc.pos + r
	pres := dr.read_bitset(acc.buf, cur, 1)
	cur += 1
		{
			b._p0 = cur
			cur = dr.skip_blob(acc.buf, cur)
		}
		if (pres >> 0) & 1 == 1 {
			b._p1 = cur
			uh, uhb := dr.read_leb(acc.buf, cur)
			cur = cur + uhb + dr.packed_union_payload_bytes(acc.buf, cur + uhb, int(uh & 7))
		} else {
			b._p1 = -1
		}
	_ = cur
	b.ready = true
	return b
}
json_member_key :: proc(acc: JsonMember_Accessor, blk := JsonMember_Block{}) -> string {
	b := blk
	if !b.ready { b = json_member_block(acc) }
	pl := b._p0
	if pl < 0 { return "" }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
json_member_key_clone :: proc(acc: JsonMember_Accessor, blk := JsonMember_Block{}) -> string { return dr.clone_string(json_member_key(acc, blk)) }
json_member_value :: proc(acc: JsonMember_Accessor, blk := JsonMember_Block{}) -> Maybe(Json_PackedView) {
	b := blk
	if !b.ready { b = json_member_block(acc) }
	pl := b._p1
	if pl < 0 { return nil }
	vp, tag, code := dr.packed_union_header(acc.buf, pl)
	return Json_PackedView{buf = acc.buf, vp = vp, tag = tag, code = code}
}


Claims_Value :: struct { subject: Maybe(string), issuer: Maybe(string), audience: Maybe(string), issued_at: u64, expires_at: u64, scopes: Maybe([]string), custom: Maybe(Json_Value), _src: int }
JsonMember_Value :: struct { key: string, value: Maybe(Json_Value), _src: int }
Json_Value :: struct { tag: Json_Tag, string: Maybe(string), number: Maybe(f64), bool: Maybe(bool), array: Maybe([]Maybe(Json_Value)), object: Maybe([]JsonMember_Value), data: Maybe([]u8) }
apply_union_packed_json :: proc(b: ^dr.Builder, uv: Json_Value) -> u64 {
	switch uv.tag {
	case .string:
		_ = dr.store_utf8(b, uv.string.?, false)
		return u64((0 << 3) | 6)
	case .number:
		_rf := dr.store_packed_float64(b, uv.number.?, false)
		return u64((1 << 3) | (_rf ? 4 : 5))
	case .bool:
		_ = dr.store_u8(b, uv.bool.? ? 1 : 0)
		return u64((2 << 3) | 1)
	case .array:
		_pa3 := uv.array.?
		_pcb3 := b.cursor
		_ph3 := make([dynamic]u64); defer delete(_ph3)
		_pp3 := make([dynamic]bool); defer delete(_pp3)
		for _k3 := len(_pa3) - 1; _k3 >= 0; _k3 -= 1 {
			if _e3, _ok3 := _pa3[_k3].?; _ok3 { append(&_ph3, apply_union_packed_json(b, _e3)); append(&_pp3, true) }
			else { append(&_ph3, 0); append(&_pp3, false) }
		}
		_ = dr.store_packed_union_array_frame(b, _ph3[:], _pp3[:], len(_pa3), true, _pcb3)
		return u64((3 << 3) | 6)
	case .object:
		_pa4 := uv.object.?
		_pcb4 := b.cursor
		for _k4 := len(_pa4) - 1; _k4 >= 0; _k4 -= 1 {
			_ = store_json_member(b, _pa4[_k4])
		}
		_ = dr.store_leb(b, u64(len(_pa4)))
		_ = dr.store_leb(b, u64(b.cursor - _pcb4))
		return u64((4 << 3) | 6)
	case .data:
		_ = dr.store_data(b, uv.data.?)
		return u64((5 << 3) | 6)
	}
	return 0
}
store_union_packed_json :: proc(b: ^dr.Builder, uv: Json_Value) -> int {
	return dr.store_leb(b, apply_union_packed_json(b, uv))
}
restore_union_json_pk :: proc(v: Json_PackedView) -> Json_Value {
	uv: Json_Value
	uv.tag = json_packed_view_tag(v)
	switch uv.tag {
	case .string:
		uv.string = json_packed_string(v)
	case .number:
		uv.number = json_packed_number(v)
	case .bool:
		uv.bool = json_packed_bool(v)
	case .array:
		{ _an3 := json_packed_array_len(v)
		_aa3 := make([]Maybe(Json_Value), _an3)
		for _ai3 in 0 ..< _an3 { if _o3, _ok3 := json_packed_array_get(v, _ai3).?; _ok3 { _aa3[_ai3] = restore_union_json_pk(_o3) } }
		uv.array = _aa3 }
	case .object:
		{ _an4 := json_packed_object_len(v)
		_aa4 := make([]JsonMember_Value, _an4)
		for _ai4 in 0 ..< _an4 { _aa4[_ai4] = restore_json_member(json_packed_object_get(v, _ai4)) }
		uv.object = _aa4 }
	case .data:
		uv.data = json_packed_data(v)
	}
	return uv
}

restore_claims :: proc(acc: Claims_Accessor) -> Claims_Value {
	v: Claims_Value
	v._src = acc.pos
	v.subject = claims_subject(acc)
	v.issuer = claims_issuer(acc)
	v.audience = claims_audience(acc)
	v.issued_at = claims_issued_at(acc)
	v.expires_at = claims_expires_at(acc)
	if _n5, _okn5 := claims_scopes_len(acc).?; _okn5 {
		_a5 := make([]string, _n5)
		for _i5 in 0 ..< _n5 {
		_a5[_i5] = claims_scopes_get(acc, _i5)
		}
		v.scopes = _a5
	}
	if uvw6, ok6 := claims_custom(acc).?; ok6 { v.custom = restore_union_json_pk(uvw6) }
	return v
}
store_claims :: proc(b: ^dr.Builder, v: Claims_Value) -> int {
	if v._src > 0 { if _o, _ok := b.node_lookup[v._src]; _ok { return _o } }
	_before := b.cursor
	_rawbits: u64 = 0
	_pr0 := false
	if _, _okp0 := v.subject.?; _okp0 { _pr0 = true }
	_pr1 := false
	if _, _okp1 := v.issuer.?; _okp1 { _pr1 = true }
	_pr2 := false
	if _, _okp2 := v.audience.?; _okp2 { _pr2 = true }
	_pr5 := false
	if _, _okp5 := v.scopes.?; _okp5 { _pr5 = true }
	_pr6 := false
	if _, _okp6 := v.custom.?; _okp6 { _pr6 = true }
	if val6, ok6 := v.custom.?; ok6 {
		_ = store_union_packed_json(b, val6)
	}
	if val5, ok5 := v.scopes.?; ok5 {
		_pa5 := val5
		_pcb5 := b.cursor
		for _k5 := len(_pa5) - 1; _k5 >= 0; _k5 -= 1 {
			_ = dr.store_utf8(b, _pa5[_k5], false)
		}
		_ = dr.store_leb(b, u64(len(_pa5)))
		_ = dr.store_leb(b, u64(b.cursor - _pcb5))
	}
	_lv4 := u64(v.expires_at)
	if dr.leb_length(_lv4) < 8 { _ = dr.store_leb(b, _lv4) } else { _ = dr.store_u64(b, v.expires_at); _rawbits |= u64(1) << 1 }
	_lv3 := u64(v.issued_at)
	if dr.leb_length(_lv3) < 8 { _ = dr.store_leb(b, _lv3) } else { _ = dr.store_u64(b, v.issued_at); _rawbits |= u64(1) << 0 }
	if val2, ok2 := v.audience.?; ok2 {
		_ = dr.store_utf8(b, val2, false)
	}
	if val1, ok1 := v.issuer.?; ok1 {
		_ = dr.store_utf8(b, val1, false)
	}
	if val0, ok0 := v.subject.?; ok0 {
		_ = dr.store_utf8(b, val0, false)
	}
	_eb := make([]u8, 1); defer delete(_eb)
	_eb[0] = u8((_rawbits >> 0) & 0xff)
	_ = dr.store_bytes(b, _eb)
	_pb := make([]u8, 1); defer delete(_pb)
	if _pr0 { _pb[0] |= 1 }
	if _pr1 { _pb[0] |= 2 }
	if _pr2 { _pb[0] |= 4 }
	if _pr5 { _pb[0] |= 8 }
	if _pr6 { _pb[0] |= 16 }
	_ = dr.store_bytes(b, _pb)
	_ = dr.store_leb(b, u64(b.cursor - _before))
	_o := b.cursor
	if v._src > 0 { b.node_lookup[v._src] = _o }
	return _o
}

restore_json_member :: proc(acc: JsonMember_Accessor) -> JsonMember_Value {
	v: JsonMember_Value
	v._src = acc.pos
	v.key = json_member_key(acc)
	if uvw1, ok1 := json_member_value(acc).?; ok1 { v.value = restore_union_json_pk(uvw1) }
	return v
}
store_json_member :: proc(b: ^dr.Builder, v: JsonMember_Value) -> int {
	if v._src > 0 { if _o, _ok := b.node_lookup[v._src]; _ok { return _o } }
	_before := b.cursor
	_rawbits: u64 = 0
	_pr1 := false
	if _, _okp1 := v.value.?; _okp1 { _pr1 = true }
	if val1, ok1 := v.value.?; ok1 {
		_ = store_union_packed_json(b, val1)
	}
	_ = dr.store_utf8(b, v.key, false)
	_pb := make([]u8, 1); defer delete(_pb)
	if _pr1 { _pb[0] |= 1 }
	_ = dr.store_bytes(b, _pb)
	_ = dr.store_leb(b, u64(b.cursor - _before))
	_o := b.cursor
	if v._src > 0 { b.node_lookup[v._src] = _o }
	return _o
}

// ── Spec 14 header Jws: flat packed self-sized envelope (no typeId) ──
Jws_Accessor :: struct { buf: []u8, pos: int }
Jws_Block :: struct { _p0: int, _p1: int, _p2: int, raw: u64, ready: bool }
jws_block :: proc(acc: Jws_Accessor) -> Jws_Block {
	b: Jws_Block
	b._p0 = -1
	b._p1 = -1
	b._p2 = -1
	es, ee := dr.packed_bounds(acc.buf, acc.pos)
	cursor := es
	scan: for cursor < ee {
		tagv, tb := dr.read_leb(acc.buf, cursor)
		fidx := int(tagv >> 1)
		raw := (tagv & 1) == 1
		pl := cursor + tb
		switch fidx {
		case 0:
			b._p0 = pl
			if raw { b.raw |= 1 }
			cursor = dr.skip_blob(acc.buf, pl)
		case 1:
			b._p1 = pl
			if raw { b.raw |= 2 }
			cursor = dr.skip_blob(acc.buf, pl)
		case 2:
			b._p2 = pl
			if raw { b.raw |= 4 }
			cursor = dr.skip_blob(acc.buf, pl)
		case: break scan
		}
	}
	b.ready = true
	return b
}
jws_algorithm :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> string {
	b := blk
	if !b.ready { b = jws_block(acc) }
	pl := b._p0
	if pl < 0 { return "" }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
jws_algorithm_clone :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> string { return dr.clone_string(jws_algorithm(acc, blk)) }
jws_key_id :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> Maybe(string) {
	b := blk
	if !b.ready { b = jws_block(acc) }
	pl := b._p1
	if pl < 0 { return nil }
	s, _ := dr.read_utf8(acc.buf, pl)
	return s
}
jws_key_id_clone :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> Maybe(string) {
	v, ok := jws_key_id(acc, blk).?
	if !ok { return nil }
	return dr.clone_string(v)
}
jws_signature :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> []u8 {
	b := blk
	if !b.ready { b = jws_block(acc) }
	pl := b._p2
	if pl < 0 { return []u8{} }
	d, _ := dr.read_data(acc.buf, pl)
	return d
}
jws_signature_clone :: proc(acc: Jws_Accessor, blk := Jws_Block{}) -> []u8 { return dr.clone_bytes(jws_signature(acc, blk)) }
Jws_Value :: struct { algorithm: string, key_id: Maybe(string), signature: []u8, _src: int }
store_jws_packed :: proc(b: ^dr.Builder, v: Jws_Value) -> int {
	_before := b.cursor
	_ = dr.store_data(b, v.signature)
	_ = dr.store_leb(b, u64(5))
	if val1, ok1 := v.key_id.?; ok1 {
		_ = dr.store_utf8(b, val1, false)
		_ = dr.store_leb(b, u64(3))
	}
	_ = dr.store_utf8(b, v.algorithm, false)
	_ = dr.store_leb(b, u64(1))
	_ = dr.store_leb(b, u64(b.cursor - _before))
	_o := b.cursor
	return _o
}
restore_jws :: proc(acc: Jws_Accessor) -> Jws_Value {
	v: Jws_Value
	v._src = acc.pos
	v.algorithm = jws_algorithm(acc)
	v.key_id = jws_key_id(acc)
	v.signature = jws_signature(acc)
	return v
}

claims_from_bytes :: proc(data: []u8) -> Claims_Value {
	acc := Claims_Accessor{buf = data, pos = dr.root_offset(data)}
	return restore_claims(acc)
}
claims_to_bytes :: proc(v: Claims_Value) -> []u8 {
	b := dr.builder_make()
	defer dr.builder_destroy(&b)
	off := store_claims(&b, v)
	_ = dr.store_leb(&b, u64((b.cursor - off) << 2))   // framing (no header)
	return dr.make_data(&b)
}

// ── Spec 14 customizable header: framing word (00|01) + verify-before-parse gate ──
claims_to_bytes_with_header :: proc(v: Claims_Value, ctx: rawptr, header_fn: proc(ctx: rawptr, root_offset: int, body: []u8) -> Jws_Value) -> []u8 {
	b := dr.builder_make()
	defer dr.builder_destroy(&b)
	off := store_claims(&b, v)
	original_offset := b.cursor - off
	body := dr.make_data(&b)
	hv := header_fn(ctx, original_offset, body)
	hb := dr.builder_make()
	defer dr.builder_destroy(&hb)
	_ = store_jws_packed(&hb, hv)
	header_bytes := dr.make_data(&hb)
	h := len(header_bytes)
	stored_offset := u64(((original_offset + h) << 2) | 1)
	fb := dr.builder_make()
	defer dr.builder_destroy(&fb)
	_ = dr.store_leb(&fb, stored_offset)
	framing := dr.make_data(&fb)
	out := make([]u8, len(framing) + len(header_bytes) + len(body))
	copy(out[:], framing)
	copy(out[len(framing):], header_bytes)
	copy(out[len(framing) + len(header_bytes):], body)
	return out
}
claims_from_bytes_with_header :: proc(data: []u8, ctx: rawptr, gate: proc(ctx: rawptr, h: Jws_Value, root_offset: int, body: []u8) -> bool) -> (Claims_Value, bool) {
	framing, rl := dr.read_leb(data, 0)
	if framing & 1 != 1 { return {}, false }
	if (framing >> 1) & 1 != 0 { return {}, false }
	stored_offset := int(framing >> 2)
	header_start := rl
	hcs, hcsb := dr.read_leb(data, header_start)
	h := hcsb + int(hcs)
	header := restore_jws(Jws_Accessor{buf = data, pos = header_start})
	body_start := header_start + h
	body := data[body_start:]
	if !gate(ctx, header, stored_offset - h, body) { return {}, false }
	root_at := rl + stored_offset
	acc := Claims_Accessor{buf = data, pos = root_at}
	return restore_claims(acc), true
}

// ── 31 Direct Graph Builder §4.3: reusable writer (one builder, reset per mint) ──
Claims_Writer :: struct { _b: dr.Builder }
claims_writer_make :: proc() -> Claims_Writer { return Claims_Writer{_b = dr.builder_make()} }
claims_writer_destroy :: proc(w: ^Claims_Writer) { dr.builder_destroy(&w._b) }
claims_writer_to_bytes :: proc(w: ^Claims_Writer, v: Claims_Value) -> []u8 {
	dr.builder_reset(&w._b)
	off := store_claims(&w._b, v)
	_ = dr.store_leb(&w._b, u64((w._b.cursor - off) << 2))   // framing (no header)
	return dr.make_data(&w._b)
}
claims_writer_to_bytes_with_header :: proc(w: ^Claims_Writer, v: Claims_Value, ctx: rawptr, header_fn: proc(ctx: rawptr, root_offset: int, body: []u8) -> Jws_Value) -> []u8 {
	dr.builder_reset(&w._b)
	off := store_claims(&w._b, v)
	original_offset := w._b.cursor - off
	body := dr.make_data(&w._b)
	hv := header_fn(ctx, original_offset, body)
	hb := dr.builder_make()
	defer dr.builder_destroy(&hb)
	_ = store_jws_packed(&hb, hv)
	header_bytes := dr.make_data(&hb)
	h := len(header_bytes)
	stored_offset := u64(((original_offset + h) << 2) | 1)
	fb := dr.builder_make()
	defer dr.builder_destroy(&fb)
	_ = dr.store_leb(&fb, stored_offset)
	framing := dr.make_data(&fb)
	out := make([]u8, len(framing) + len(header_bytes) + len(body))
	copy(out[:], framing)
	copy(out[len(framing):], header_bytes)
	copy(out[len(framing) + len(header_bytes):], body)
	return out
}
