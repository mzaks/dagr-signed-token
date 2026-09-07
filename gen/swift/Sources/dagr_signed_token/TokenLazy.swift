import Foundation

extension Token {

    public enum JsonAccessor {
        case string(String)
        case number(Double)
        case bool(Bool)
        case array(VtableJsonOptArrayAccessor)
        case object(VtableJsonMemberOptArrayAccessor)
        case data(Foundation.Data)
    }

    public struct VtableJsonMemberArrayAccessor: Sequence {
        internal let _data: Foundation.Data
        private let _slotStart: Int
        private let _es: Int
        private let _base: Int
        public let count: Int
        public init(_ data: Foundation.Data, at pos: Int) {
            _data = data
            if pos >= 0, let (hdr, hLen) = try? restoreLEB(from: data, at: pos) {
                count = Int(hdr >> 2); let es = [1,2,4,8][Int(hdr&3)]
                _slotStart = pos + hLen; _es = es; _base = pos + hLen + count * es
            } else { count = 0; _slotStart = -1; _es = 1; _base = 0 }
        }
        public subscript(_ idx: Int) -> JsonMemberAccessor {
            get throws {
                guard _slotStart >= 0, idx >= 0, idx < count else { throw ArenaRestoreError.outsideOfBuffer }
                let ro = try readSignedRelOffset(from: _data, at: _slotStart + idx * _es, size: _es)
                guard ro != 0 else { throw ArenaRestoreError.outsideOfBuffer }
                return try JsonMemberAccessor(data: _data, at: _base + Int(ro) - 1)
            }
        }
        public struct Iterator: IteratorProtocol {
            private let _acc: VtableJsonMemberArrayAccessor
            private var _i: Int = 0
            init(_ acc: VtableJsonMemberArrayAccessor) { self._acc = acc }
            public mutating func next() -> JsonMemberAccessor? {
                guard _i < _acc.count else { return nil }
                let elem = try? _acc[_i]
                _i += 1
                return elem
            }
        }
        public func makeIterator() -> Iterator { Iterator(self) }
        public func throwingForEach(_ body: (JsonMemberAccessor) throws -> Void) throws {
            for i in 0..<count { try body(try self[i]) }
        }
        public func throwingMap<T>(_ transform: (JsonMemberAccessor) throws -> T) throws -> [T] {
            var result = [T](); result.reserveCapacity(count)
            for i in 0..<count { try result.append(transform(try self[i])) }
            return result
        }
        public func throwingFirst() throws -> JsonMemberAccessor? {
            guard count > 0 else { return nil }
            return try self[0]
        }
    }

    public struct VtableJsonMemberOptArrayAccessor: Sequence {
        internal let _data: Foundation.Data
        private let _slotStart: Int
        private let _es: Int
        private let _base: Int
        public let count: Int
        public init(_ data: Foundation.Data, at pos: Int) {
            _data = data
            if pos >= 0, let (hdr, hLen) = try? restoreLEB(from: data, at: pos) {
                count = Int(hdr >> 2); let es = [1,2,4,8][Int(hdr&3)]
                _slotStart = pos + hLen; _es = es; _base = pos + hLen + count * es
            } else { count = 0; _slotStart = -1; _es = 1; _base = 0 }
        }
        public subscript(_ idx: Int) -> JsonMemberAccessor? {
            get throws {
                guard _slotStart >= 0, idx >= 0, idx < count else { return nil }
                let ro = try readSignedRelOffset(from: _data, at: _slotStart + idx * _es, size: _es)
                guard ro != 0 else { return nil }
                return try JsonMemberAccessor(data: _data, at: _base + Int(ro) - 1)
            }
        }
        public struct Iterator: IteratorProtocol {
            private let _acc: VtableJsonMemberOptArrayAccessor
            private var _i: Int = 0
            init(_ acc: VtableJsonMemberOptArrayAccessor) { self._acc = acc }
            public mutating func next() -> JsonMemberAccessor?? {
                guard _i < _acc.count else { return nil }
                let elem = try? _acc[_i]
                _i += 1
                return elem
            }
        }
        public func makeIterator() -> Iterator { Iterator(self) }
        public func throwingForEach(_ body: (JsonMemberAccessor?) throws -> Void) throws {
            for i in 0..<count { try body(try self[i]) }
        }
        public func throwingMap<T>(_ transform: (JsonMemberAccessor?) throws -> T) throws -> [T] {
            var result = [T](); result.reserveCapacity(count)
            for i in 0..<count { try result.append(transform(try self[i])) }
            return result
        }
        public func throwingFirst() throws -> JsonMemberAccessor?? {
            guard count > 0 else { return .some(nil) }
            return try self[0]
        }
    }

    public struct VtableJsonOptArrayAccessor: Sequence {
        private let _data: Foundation.Data
        private let _nilBsStart: Int
        private let _tidStart: Int
        private let _slotStart: Int
        private let _es: Int
        private let _base: Int
        public let count: Int
        public init(_ data: Foundation.Data, at pos: Int) {
            _data = data
            if pos >= 0, let (hdr, hLen) = try? restoreLEB(from: data, at: pos) {
                count = Int(hdr >> 2); let es = [1,2,4,8][Int(hdr&3)]
                let tidLen = (count + 1) / 2
                let bsNilSize = (count + 7) / 8
                _tidStart = pos + hLen
                _nilBsStart = pos + hLen + tidLen
                _slotStart = pos + hLen + tidLen + bsNilSize; _es = es
                _base = pos + hLen + tidLen + bsNilSize + count * es
            } else { count = 0; _tidStart = 0; _nilBsStart = 0; _slotStart = -1; _es = 1; _base = 0 }
        }
        public subscript(_ idx: Int) -> JsonAccessor? {
            get throws {
                guard _slotStart >= 0, idx >= 0, idx < count else { return nil }
                guard _nilBsStart + idx / 8 < _data.count, (_data[_nilBsStart + idx / 8] >> (idx % 8)) & 1 == 0 else { return nil }
                let _typeId = Int((_data[_tidStart + idx / 2] >> ((idx % 2) * 4)) & 15)
                let ro = try readRelOffset(from: _data, at: _slotStart + idx * _es, size: _es)
                switch _typeId {
                case 0:
                    return .string(try String.restore(from: _data, at: _base + Int(ro)))
                case 1:
                    return .number(Double(bitPattern: ro))
                case 2:
                    return .bool(ro != 0)
                case 3:
                    return .array(VtableJsonOptArrayAccessor(_data, at: _base + Int(ro)))
                case 4:
                    return .object(VtableJsonMemberOptArrayAccessor(_data, at: _base + Int(ro)))
                case 5:
                    return .data(try Foundation.Data.restore(from: _data, at: _base + Int(ro)))
                default: return nil
                }
            }
        }
        public struct Iterator: IteratorProtocol {
            private let _acc: VtableJsonOptArrayAccessor
            private var _i: Int = 0
            init(_ acc: VtableJsonOptArrayAccessor) { self._acc = acc }
            public mutating func next() -> JsonAccessor?? {
                guard _i < _acc.count else { return nil }
                let elem = try? _acc[_i]
                _i += 1
                return elem
            }
        }
        public func makeIterator() -> Iterator { Iterator(self) }
        public func throwingForEach(_ body: (JsonAccessor?) throws -> Void) throws {
            for i in 0..<count { try body(try self[i]) }
        }
        public func throwingMap<T>(_ transform: (JsonAccessor?) throws -> T) throws -> [T] {
            var result = [T](); result.reserveCapacity(count)
            for i in 0..<count { try result.append(transform(try self[i])) }
            return result
        }
        public func throwingFirst() throws -> JsonAccessor?? {
            guard count > 0 else { return .some(nil) }
            return try self[0]
        }
    }

    public enum JsonPackedAccessor {
        case string(String)
        case number(Double)
        case bool(Bool)
        case array([JsonPackedAccessor?])
        case object([JsonMemberAccessor])
        case data(Foundation.Data)
    }

    public struct PackedJsonUnionOptArrayAccessor: Sequence {
        fileprivate let _data: Foundation.Data
        fileprivate let _bsStart: Int
        fileprivate let _hStart: Int   // start of headers section
        fileprivate let _pStart: Int   // start of payloads section
        public let count: Int
        public init(_ data: Foundation.Data, at pos: Int) {
            _data = data
            if pos >= 0, let (c, cB) = try? restoreLEB(from: data, at: pos) {
                count = Int(c)
                let bsEnd = pos + cB + (Int(c) + 7) / 8
                _bsStart = pos + cB
                if let (hss, hssB) = try? restoreLEB(from: data, at: bsEnd) {
                    _hStart = bsEnd + hssB
                    _pStart = bsEnd + hssB + Int(hss)
                } else { _hStart = bsEnd; _pStart = bsEnd }
            } else { count = 0; _bsStart = -1; _hStart = -1; _pStart = -1 }
        }
        public struct Iterator: IteratorProtocol {
            private let _acc: PackedJsonUnionOptArrayAccessor
            private var _i: Int = 0
            private var _hP: Int
            private var _pP: Int
            init(_ acc: PackedJsonUnionOptArrayAccessor) { self._acc = acc; self._hP = acc._hStart; self._pP = acc._pStart }
            public mutating func next() -> JsonPackedAccessor?? {
                guard _i < _acc.count, _acc._bsStart >= 0 else { return nil }
                let present = _acc._bsStart + _i/8 < _acc._data.count && (_acc._data[_acc._bsStart + _i/8] >> (_i%8)) & 1 == 0
                _i += 1
                if present {
                    guard let (hdr, hdrB) = try? restoreLEB(from: _acc._data, at: _hP) else { return nil }
                    let tid = Int(hdr >> 3), code = Int(hdr & 7); _hP += hdrB
                    let ep = _pP
                    let elem: JsonPackedAccessor? = (try? PackedJsonUnionOptArrayAccessor._decodePackedElem(in: _acc._data, at: ep, typeId: tid, code: code)) ?? nil
                    _pP = (try? PackedJsonUnionOptArrayAccessor._skipPackedElem(in: _acc._data, at: ep, typeId: tid, code: code)) ?? _pP
                    return elem
                } else { return .some(nil) }
            }
        }
        public func makeIterator() -> Iterator { Iterator(self) }
        public func throwingForEach(_ body: (JsonPackedAccessor?) throws -> Void) throws {
            guard _bsStart >= 0 else { return }
            var hP = _hStart, pP = _pStart
            for i in 0..<count {
                let present = _bsStart + i/8 < _data.count && (_data[_bsStart + i/8] >> (i%8)) & 1 == 0
                if present {
                    let (hdr, hdrB) = try restoreLEB(from: _data, at: hP)
                    let tid = Int(hdr >> 3), code = Int(hdr & 7); hP += hdrB
                    try body(Self._decodePackedElem(in: _data, at: pP, typeId: tid, code: code))
                    pP = try Self._skipPackedElem(in: _data, at: pP, typeId: tid, code: code)
                } else { try body(nil) }
            }
        }
        public func throwingMap<T>(_ transform: (JsonPackedAccessor?) throws -> T) throws -> [T] {
            var result = [T](); result.reserveCapacity(count)
            try throwingForEach { try result.append(transform($0)) }
            return result
        }
        public func throwingFirst() throws -> JsonPackedAccessor?? {
            var first: JsonPackedAccessor?? = nil
            try throwingForEach { if case .none = first { first = $0 } }
            return first
        }
        fileprivate static func _skipPackedElem(in data: Foundation.Data, at pos: Int, typeId: Int, code: Int) throws -> Int {
            var ep = pos
            switch typeId {
            case 0:
                let (_blm0, _blBm0) = try restoreLEB(from: data, at: ep)
                ep += _blBm0 + Int(_blm0)
            case 1:
                if code == 5 {
                    let (_, _fbm1) = try _decodePackedFloat64(from: data, at: ep)
                    ep += _fbm1
                } else { ep += 8 }
            case 2:
                ep += 1
            case 3:
                let (_abszm3, _abszBm3) = try restoreLEB(from: data, at: ep)
                ep += _abszBm3 + Int(_abszm3)
            case 4:
                let (_abszm4, _abszBm4) = try restoreLEB(from: data, at: ep)
                ep += _abszBm4 + Int(_abszm4)
            case 5:
                let (_blm5, _blBm5) = try restoreLEB(from: data, at: ep)
                ep += _blBm5 + Int(_blm5)
            default: break
            }
            return ep
        }

        fileprivate static func _decodePackedElem(in data: Foundation.Data, at pos: Int, typeId: Int, code: Int) throws -> JsonPackedAccessor? {
            switch typeId {
            case 0:
                return .string(try String.restore(from: data, at: pos))
            case 1:
                if code == 5 {
                    let (_fvm1, _) = try _decodePackedFloat64(from: data, at: pos)
                    return .number(_fvm1)
                } else {
                    return .number(try Double.restore(from: data, at: pos))
                }
            case 2:
                guard pos < data.count else { return nil }
                return .bool(data[pos] != 0)
            case 3:
                let (_, _abszBm3) = try restoreLEB(from: data, at: pos)
                let _abm3 = pos + _abszBm3
                var _uavm3 = [JsonPackedAccessor?]()
                for _uem3 in PackedJsonUnionOptArrayAccessor(data, at: _abm3) { _uavm3.append(_uem3) }
                return .array(_uavm3)
            case 4:
                let (_, _abszBm4) = try restoreLEB(from: data, at: pos)
                let _abm4 = pos + _abszBm4
                let (_acntm4, _acntBm4) = try restoreLEB(from: data, at: _abm4)
                var _apm4 = _abm4 + _acntBm4
                var _avm4 = [JsonMemberAccessor]()
                for _ in 0..<Int(_acntm4) {
                    let (_eblm4, _eblBm4) = try restoreLEB(from: data, at: _apm4)
                    _avm4.append(try JsonMemberAccessor(data: data, at: _apm4))
                    _apm4 += _eblBm4 + Int(_eblm4)
                }
                return .object(_avm4)
            case 5:
                return .data(try Foundation.Data.restore(from: data, at: pos))
            default: return nil
            }
        }

    }

    public struct ClaimsAccessor {
        private let _data: Foundation.Data
        internal let _nodeStart: Int
        private var _r0: Range<Int>? = nil  // subject
        private var _r1: Range<Int>? = nil  // issuer
        private var _r2: Range<Int>? = nil  // audience
        private var _v3: UInt64? = nil  // issuedAt
        private var _v4: UInt64? = nil  // expiresAt
        private var _r5: Range<Int>? = nil  // scopes
        private var _v6: Range<Int>? = nil  // custom

        public init(data: Foundation.Data, at start: Int) throws {
            _data = data
            _nodeStart = start
            let (_, _blB) = try restoreLEB(from: data, at: start)
            var _cur = start + _blB
            let _obs0: UInt8 = _cur + 0 < data.count ? data[_cur + 0] : 0
            _cur += 1
            let _ebs0: UInt8 = _cur + 0 < data.count ? data[_cur + 0] : 0
            _cur += 1
            if _obs0 & 1 != 0 {
                let (_sv0, _svB0) = try restoreLEB(from: data, at: _cur)
                _cur += _svB0
                _r0 = _cur ..< (_cur + Int(_sv0))
                _cur += Int(_sv0)
            }
            if _obs0 & 2 != 0 {
                let (_sv1, _svB1) = try restoreLEB(from: data, at: _cur)
                _cur += _svB1
                _r1 = _cur ..< (_cur + Int(_sv1))
                _cur += Int(_sv1)
            }
            if _obs0 & 4 != 0 {
                let (_sv2, _svB2) = try restoreLEB(from: data, at: _cur)
                _cur += _svB2
                _r2 = _cur ..< (_cur + Int(_sv2))
                _cur += Int(_sv2)
            }
            if _ebs0 & 1 != 0 {
                _v3 = try UInt64.restore(from: data, at: _cur); _cur += 8
            } else {
                let (_v, _vB) = try restoreLEB(from: data, at: _cur)
                _v3 = UInt64(_v); _cur += _vB
            }
            if _ebs0 & 2 != 0 {
                _v4 = try UInt64.restore(from: data, at: _cur); _cur += 8
            } else {
                let (_v, _vB) = try restoreLEB(from: data, at: _cur)
                _v4 = UInt64(_v); _cur += _vB
            }
            let (_abl5, _ablB5) = try restoreLEB(from: data, at: _cur)
            _r5 = (_cur + _ablB5) ..< (_cur + _ablB5 + Int(_abl5))
            _cur += _ablB5 + Int(_abl5)
            if _obs0 & 16 != 0 {
                let (_ubl6, _ublB6) = try restoreLEB(from: data, at: _cur)
                _v6 = _cur ..< (_cur + _ublB6)
                _cur += _ublB6
                switch Int(_ubl6 & 7) {
                case 0: if let (_, _ibB6) = try? restoreLEB(from: data, at: _cur) { _cur += _ibB6 }
                case 1: _cur += 1
                case 2: _cur += 2
                case 3: _cur += 4
                case 4: _cur += 8
                case 5: if let (_, _fb6) = try? _decodePackedFloat64(from: data, at: _cur) { _cur += _fb6 }
                case 6: if let (_sz6, _szB6) = try? restoreLEB(from: data, at: _cur) { _cur += _szB6 + Int(_sz6) }
                default: break
                }
            }
        }

        public var subject: String? {
            guard let r = _r0 else { return nil }
            return String(decoding: _data[r], as: UTF8.self)
        }

        public var issuer: String? {
            guard let r = _r1 else { return nil }
            return String(decoding: _data[r], as: UTF8.self)
        }

        public var audience: String? {
            guard let r = _r2 else { return nil }
            return String(decoding: _data[r], as: UTF8.self)
        }

        public var issuedAt: UInt64 {
            get throws {
                guard let v = _v3 else { throw ArenaRestoreError.outsideOfBuffer }
                return v
            }
        }

        public var expiresAt: UInt64 {
            get throws {
                guard let v = _v4 else { throw ArenaRestoreError.outsideOfBuffer }
                return v
            }
        }

        public var scopes: PackedUtf8ArrayAccessor {
            if let __r = _r5 { return PackedUtf8ArrayAccessor(_data, at: __r.lowerBound) }
            return PackedUtf8ArrayAccessor(_data, at: -1)
        }

        public var custom: JsonPackedAccessor? {
            get throws {
                guard let r = _v6 else { return nil }
                return try Self._readJsonPackedAccessor(_data, at: r.lowerBound)
            }
        }

        private static func _readJsonPackedAccessor(_ data: Foundation.Data, at pos: Int) throws -> JsonPackedAccessor? {
            let (hdr, hdrB) = try restoreLEB(from: data, at: pos)
            let typeId = Int(hdr >> 3)
            let code = Int(hdr & 7)
            let ep = pos + hdrB
            switch typeId {
            case 0:
                return .string(try String.restore(from: data, at: ep))
            case 1:
                if code == 5 {
                    let (_fvn1, _) = try _decodePackedFloat64(from: data, at: ep)
                    return .number(_fvn1)
                } else {
                    return .number(try Double.restore(from: data, at: ep))
                }
            case 2:
                guard ep < data.count else { return nil }
                return .bool(data[ep] != 0)
            case 3:
                let (_, _abszBn3) = try restoreLEB(from: data, at: ep)
                let _abn3 = ep + _abszBn3
                var _uavn3 = [JsonPackedAccessor?]()
                for _uen3 in PackedJsonUnionOptArrayAccessor(data, at: _abn3) { _uavn3.append(_uen3) }
                return .array(_uavn3)
            case 4:
                let (_, _abszBn4) = try restoreLEB(from: data, at: ep)
                let _abn4 = ep + _abszBn4
                let (_acntn4, _acntBn4) = try restoreLEB(from: data, at: _abn4)
                var _apn4 = _abn4 + _acntBn4
                var _avn4 = [JsonMemberAccessor]()
                for _ in 0..<Int(_acntn4) {
                    let (_ebln4, _eblBn4) = try restoreLEB(from: data, at: _apn4)
                    _avn4.append(try JsonMemberAccessor(data: data, at: _apn4))
                    _apn4 += _eblBn4 + Int(_ebln4)
                }
                return .object(_avn4)
            case 5:
                return .data(try Foundation.Data.restore(from: data, at: ep))
            default: return nil
            }
        }

    }

    public struct JsonMemberAccessor {
        private let _data: Foundation.Data
        internal let _nodeStart: Int
        private var _r0: Range<Int>? = nil  // key
        private var _v1: Range<Int>? = nil  // value

        public init(data: Foundation.Data, at start: Int) throws {
            _data = data
            _nodeStart = start
            let (_, _blB) = try restoreLEB(from: data, at: start)
            var _cur = start + _blB
            let _obs0: UInt8 = _cur + 0 < data.count ? data[_cur + 0] : 0
            _cur += 1
            let (_sv0, _svB0) = try restoreLEB(from: data, at: _cur)
            _cur += _svB0
            _r0 = _cur ..< (_cur + Int(_sv0))
            _cur += Int(_sv0)
            if _obs0 & 1 != 0 {
                let (_ubl1, _ublB1) = try restoreLEB(from: data, at: _cur)
                _v1 = _cur ..< (_cur + _ublB1)
                _cur += _ublB1
                switch Int(_ubl1 & 7) {
                case 0: if let (_, _ibB1) = try? restoreLEB(from: data, at: _cur) { _cur += _ibB1 }
                case 1: _cur += 1
                case 2: _cur += 2
                case 3: _cur += 4
                case 4: _cur += 8
                case 5: if let (_, _fb1) = try? _decodePackedFloat64(from: data, at: _cur) { _cur += _fb1 }
                case 6: if let (_sz1, _szB1) = try? restoreLEB(from: data, at: _cur) { _cur += _szB1 + Int(_sz1) }
                default: break
                }
            }
        }

        public var key: String {
            get throws {
                guard let r = _r0 else { throw ArenaRestoreError.outsideOfBuffer }
                return String(decoding: _data[r], as: UTF8.self)
            }
        }

        public var value: JsonPackedAccessor? {
            get throws {
                guard let r = _v1 else { return nil }
                return try Self._readJsonPackedAccessor(_data, at: r.lowerBound)
            }
        }

        private static func _readJsonPackedAccessor(_ data: Foundation.Data, at pos: Int) throws -> JsonPackedAccessor? {
            let (hdr, hdrB) = try restoreLEB(from: data, at: pos)
            let typeId = Int(hdr >> 3)
            let code = Int(hdr & 7)
            let ep = pos + hdrB
            switch typeId {
            case 0:
                return .string(try String.restore(from: data, at: ep))
            case 1:
                if code == 5 {
                    let (_fvn1, _) = try _decodePackedFloat64(from: data, at: ep)
                    return .number(_fvn1)
                } else {
                    return .number(try Double.restore(from: data, at: ep))
                }
            case 2:
                guard ep < data.count else { return nil }
                return .bool(data[ep] != 0)
            case 3:
                let (_, _abszBn3) = try restoreLEB(from: data, at: ep)
                let _abn3 = ep + _abszBn3
                var _uavn3 = [JsonPackedAccessor?]()
                for _uen3 in PackedJsonUnionOptArrayAccessor(data, at: _abn3) { _uavn3.append(_uen3) }
                return .array(_uavn3)
            case 4:
                let (_, _abszBn4) = try restoreLEB(from: data, at: ep)
                let _abn4 = ep + _abszBn4
                let (_acntn4, _acntBn4) = try restoreLEB(from: data, at: _abn4)
                var _apn4 = _abn4 + _acntBn4
                var _avn4 = [JsonMemberAccessor]()
                for _ in 0..<Int(_acntn4) {
                    let (_ebln4, _eblBn4) = try restoreLEB(from: data, at: _apn4)
                    _avn4.append(try JsonMemberAccessor(data: data, at: _apn4))
                    _apn4 += _eblBn4 + Int(_ebln4)
                }
                return .object(_avn4)
            case 5:
                return .data(try Foundation.Data.restore(from: data, at: ep))
            default: return nil
            }
        }

    }

    public struct JwsAccessor {
        private let _data: Foundation.Data
        internal let _nodeStart: Int
        private var _r0: Range<Int>? = nil  // algorithm
        private var _r1: Range<Int>? = nil  // keyId
        private var _r2: Range<Int>? = nil  // signature

        public init(data: Foundation.Data, at start: Int) throws {
            _data = data
            _nodeStart = start
            let (_bl, _blB) = try restoreLEB(from: data, at: start)
            var _cursor = start + _blB
            let _end = _cursor + Int(_bl)

            if _cursor < _end {
                let (_tag0, _tag0B) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag0) >> 1 == 0 {
                    _cursor += _tag0B
                    let (_sv0, _sb0) = try restoreLEB(from: data, at: _cursor)
                    _cursor += _sb0
                    _r0 = _cursor ..< (_cursor + Int(_sv0))
                    _cursor += Int(_sv0)
                }
            }
            if _cursor < _end {
                let (_tag1, _tag1B) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag1) >> 1 == 1 {
                    _cursor += _tag1B
                    let (_sv1, _sb1) = try restoreLEB(from: data, at: _cursor)
                    _cursor += _sb1
                    _r1 = _cursor ..< (_cursor + Int(_sv1))
                    _cursor += Int(_sv1)
                }
            }
            if _cursor < _end {
                let (_tag2, _tag2B) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag2) >> 1 == 2 {
                    _cursor += _tag2B
                    let (_dv2, _db2) = try restoreLEB(from: data, at: _cursor)
                    _cursor += _db2
                    _r2 = _cursor ..< (_cursor + Int(_dv2))
                    _cursor += Int(_dv2)
                }
            }
        }

        public var algorithm: String {
            get throws {
                guard let r = _r0 else { throw ArenaRestoreError.outsideOfBuffer }
                return String(decoding: _data[r], as: UTF8.self)
            }
        }

        public var keyId: String? {
            guard let r = _r1 else { return nil }
            return String(decoding: _data[r], as: UTF8.self)
        }

        public var signature: Foundation.Data {
            get throws {
                guard let r = _r2 else { throw ArenaRestoreError.outsideOfBuffer }
                return Foundation.Data(_data[r])
            }
        }

    }

    public static func lazyRoot(from data: Foundation.Data, header headerGate: (JwsAccessor, Int, Foundation.Data) throws -> Void) throws -> ClaimsAccessor {
        let (framing, hdrBytes) = try restoreLEB(from: data, at: 0)
        guard (framing & 1) == 1 else { throw ArenaRestoreError.missingHeader }
        let storedOffset = Int(framing >> 2)
        let (hcs, hcsB) = try restoreLEB(from: data, at: hdrBytes)
        let H = hcsB + Int(hcs)
        let header = try JwsAccessor(data: data, at: hdrBytes)
        let body = data.subdata(in: hdrBytes + H ..< data.count)
        try headerGate(header, storedOffset - H, body)
        return try ClaimsAccessor(data: data, at: hdrBytes + storedOffset)
    }


}
