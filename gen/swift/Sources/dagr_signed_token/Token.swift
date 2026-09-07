import Foundation

public enum Token {
    enum _Json {
        case string(String)
        case number(Double)
        case bool(Bool)
        case array([_Json?])
        case object([UInt64])
        case data(Data)
        case unknown(UInt64)
    }

    public struct ClaimsValues {
        public var subject: String? = nil
        public var issuer: String? = nil
        public var audience: String? = nil
        public var issuedAt: UInt64
        public var expiresAt: UInt64
        public var scopes: [String] = []
        var custom: _Json? = nil
    }

    public struct JsonMemberValues {
        public var key: String
        var value: _Json? = nil
    }

    public protocol ClaimsArena: AnyObject {
        static var claimsTypeId: Int { get }
        var arenaOfClaims: [ClaimsValues] { get set }
    }

    public protocol JsonMemberArena: AnyObject {
        static var jsonMemberTypeId: Int { get }
        var arenaOfJsonMember: [JsonMemberValues] { get set }
    }

    public typealias TokenGraph = ClaimsArena & JsonMemberArena
    public typealias ClaimsGraph = ClaimsArena & JsonMemberArena
    public typealias JsonMemberGraph = JsonMemberArena
    public typealias JsonGraph = JsonMemberArena

    public enum Json<Arena: JsonGraph>: Hashable {
        case string(String)
        case number(Double)
        case bool(Bool)
        case array([Json<Arena>?])
        case object([JsonMember<Arena>])
        case data(Data)
        case unknown(UInt64)
    }

    public struct Claims<Arena: ClaimsGraph> {
        let __packed: UInt64
        unowned let __graph: Arena

        var __index: Int { Int(__packed & 0x0000_00FF_FFFF_FFFF) }
        var _generation: UInt32 { UInt32(__packed >> 40) }
        var _index: Int { __index }
        var _arenaId: ObjectIdentifier { ObjectIdentifier(__graph) }

        public var subject: String? {
            get { __graph.arenaOfClaims[__index].subject }
            nonmutating set { __graph.arenaOfClaims[__index].subject = newValue }
        }
        public var issuer: String? {
            get { __graph.arenaOfClaims[__index].issuer }
            nonmutating set { __graph.arenaOfClaims[__index].issuer = newValue }
        }
        public var audience: String? {
            get { __graph.arenaOfClaims[__index].audience }
            nonmutating set { __graph.arenaOfClaims[__index].audience = newValue }
        }
        public var issuedAt: UInt64 {
            get { __graph.arenaOfClaims[__index].issuedAt }
            nonmutating set { __graph.arenaOfClaims[__index].issuedAt = newValue }
        }
        public var expiresAt: UInt64 {
            get { __graph.arenaOfClaims[__index].expiresAt }
            nonmutating set { __graph.arenaOfClaims[__index].expiresAt = newValue }
        }
        public var scopes: [String] {
            get { __graph.arenaOfClaims[__index].scopes }
            nonmutating set { __graph.arenaOfClaims[__index].scopes = newValue }
        }
        public var custom: Json<Arena>? {
            get {
                guard let item = __graph.arenaOfClaims[__index].custom else { return nil }
                switch item {
                case .string(let v): return .string(v)
                case .number(let v): return .number(v)
                case .bool(let v): return .bool(v)
                case .array(let v): return .array(v.map { $0.map { $0._toPublic(__graph) } })
                case .object(let v): return .object(v.map { Token.JsonMember(__packed: $0, __graph: __graph) })
                case .data(let v): return .data(v)
                case .unknown(let id): return .unknown(id)
                }
            }
            nonmutating set {
                __graph.arenaOfClaims[__index].custom = newValue.map { item -> _Json in
                    switch item {
                    case .string(let v): return .string(v)
                    case .number(let v): return .number(v)
                    case .bool(let v): return .bool(v)
                    case .array(let v): return .array(v.map { $0.map { $0._toStorage() } })
                    case .object(let v): return .object(v.map { $0.__packed })
                    case .data(let v): return .data(v)
                    case .unknown(let id): return .unknown(id)
                    }
                }
            }
        }
    }

    public struct JsonMember<Arena: JsonMemberGraph> {
        let __packed: UInt64
        unowned let __graph: Arena

        var __index: Int { Int(__packed & 0x0000_00FF_FFFF_FFFF) }
        var _generation: UInt32 { UInt32(__packed >> 40) }
        var _index: Int { __index }
        var _arenaId: ObjectIdentifier { ObjectIdentifier(__graph) }

        public var key: String {
            get { __graph.arenaOfJsonMember[__index].key }
            nonmutating set { __graph.arenaOfJsonMember[__index].key = newValue }
        }
        public var value: Json<Arena>? {
            get {
                guard let item = __graph.arenaOfJsonMember[__index].value else { return nil }
                switch item {
                case .string(let v): return .string(v)
                case .number(let v): return .number(v)
                case .bool(let v): return .bool(v)
                case .array(let v): return .array(v.map { $0.map { $0._toPublic(__graph) } })
                case .object(let v): return .object(v.map { Token.JsonMember(__packed: $0, __graph: __graph) })
                case .data(let v): return .data(v)
                case .unknown(let id): return .unknown(id)
                }
            }
            nonmutating set {
                __graph.arenaOfJsonMember[__index].value = newValue.map { item -> _Json in
                    switch item {
                    case .string(let v): return .string(v)
                    case .number(let v): return .number(v)
                    case .bool(let v): return .bool(v)
                    case .array(let v): return .array(v.map { $0.map { $0._toStorage() } })
                    case .object(let v): return .object(v.map { $0.__packed })
                    case .data(let v): return .data(v)
                    case .unknown(let id): return .unknown(id)
                    }
                }
            }
        }
    }

    // ── Arena<Brand> ─────────────────────────────────────────────────────────────────
    //
    // Brand is a phantom type — declare an empty enum per arena scope:
    //
    //   enum MyBrand {}
    //   let arena = Token.Arena<MyBrand>()
    //
    public class Arena<Brand>: ClaimsArena, JsonMemberArena {
        public static var claimsTypeId: Int { 0 }
        public var arenaOfClaims: [ClaimsValues] = []
        public static var jsonMemberTypeId: Int { 1 }
        public var arenaOfJsonMember: [JsonMemberValues] = []
        public init() {}

        private var _root: UInt64? = nil
        public var root: Claims<Arena<Brand>>? {
            get { _root.map { Claims(__packed: $0, __graph: self) } }
            set { _root = newValue?.__packed }
        }
    }


}

extension Token.Arena {
    public func newClaims(subject: String? = nil, issuer: String? = nil, audience: String? = nil, issuedAt: UInt64, expiresAt: UInt64, scopes: [String] = [], custom: Token.Json<Token.Arena<Brand>>? = nil) -> Token.Claims<Token.Arena<Brand>> {
        let __custom: Token._Json? = custom.map { item -> Token._Json in
            switch item {
            case .string(let v): return .string(v)
            case .number(let v): return .number(v)
            case .bool(let v): return .bool(v)
            case .array(let v): return .array(v.map { $0.map { $0._toStorage() } })
            case .object(let v): return .object(v.map { $0.__packed })
            case .data(let v): return .data(v)
            case .unknown(let id): return .unknown(id)
            }
        }
        let _idx: Int
        _idx = arenaOfClaims.count
        arenaOfClaims.append(Token.ClaimsValues(subject: subject, issuer: issuer, audience: audience, issuedAt: issuedAt, expiresAt: expiresAt, scopes: scopes, custom: __custom))
        let _packed = UInt64(_idx)
        return Token.Claims(__packed: _packed, __graph: self)
    }
}

extension Token.Arena {
    public func newJsonMember(key: String, value: Token.Json<Token.Arena<Brand>>? = nil) -> Token.JsonMember<Token.Arena<Brand>> {
        let __value: Token._Json? = value.map { item -> Token._Json in
            switch item {
            case .string(let v): return .string(v)
            case .number(let v): return .number(v)
            case .bool(let v): return .bool(v)
            case .array(let v): return .array(v.map { $0.map { $0._toStorage() } })
            case .object(let v): return .object(v.map { $0.__packed })
            case .data(let v): return .data(v)
            case .unknown(let id): return .unknown(id)
            }
        }
        let _idx: Int
        _idx = arenaOfJsonMember.count
        arenaOfJsonMember.append(Token.JsonMemberValues(key: key, value: __value))
        let _packed = UInt64(_idx)
        return Token.JsonMember(__packed: _packed, __graph: self)
    }
}

extension Token.Arena {
    public func adopt<S: Token.ClaimsGraph>(_ src: Token.Claims<S>) throws -> Token.Claims<Token.Arena<Brand>> {
        var _seen = Set<UInt64>()
        return try _adopt(src, &_seen)
    }
    func _adopt<S: Token.ClaimsGraph>(_ src: Token.Claims<S>, _ _seen: inout Set<UInt64>) throws -> Token.Claims<Token.Arena<Brand>> {
        guard _seen.insert((UInt64(0) << 48) | UInt64(src._index)).inserted else { throw DagrError.cyclicAdopt }
        defer { _seen.remove((UInt64(0) << 48) | UInt64(src._index)) }
        return newClaims(subject: src.subject, issuer: src.issuer, audience: src.audience, issuedAt: src.issuedAt, expiresAt: src.expiresAt, scopes: src.scopes, custom: try src.custom.map { try _adopt($0, &_seen) })
    }
}

extension Token.Arena {
    public func adopt<S: Token.JsonMemberGraph>(_ src: Token.JsonMember<S>) throws -> Token.JsonMember<Token.Arena<Brand>> {
        var _seen = Set<UInt64>()
        return try _adopt(src, &_seen)
    }
    func _adopt<S: Token.JsonMemberGraph>(_ src: Token.JsonMember<S>, _ _seen: inout Set<UInt64>) throws -> Token.JsonMember<Token.Arena<Brand>> {
        guard _seen.insert((UInt64(1) << 48) | UInt64(src._index)).inserted else { throw DagrError.cyclicAdopt }
        defer { _seen.remove((UInt64(1) << 48) | UInt64(src._index)) }
        return newJsonMember(key: src.key, value: try src.value.map { try _adopt($0, &_seen) })
    }
}

extension Token.Arena {
    public func adopt<S: Token.JsonGraph>(_ v: Token.Json<S>) throws -> Token.Json<Token.Arena<Brand>> {
        var _seen = Set<UInt64>()
        return try _adopt(v, &_seen)
    }
    func _adopt<S: Token.JsonGraph>(_ v: Token.Json<S>, _ _seen: inout Set<UInt64>) throws -> Token.Json<Token.Arena<Brand>> {
        switch v {
        case .string(let x): return .string(x)
        case .number(let x): return .number(x)
        case .bool(let x): return .bool(x)
        case .array(let x): return .array(try x.map { try $0.map { try _adopt($0, &_seen) } })
        case .object(let x): return .object(try x.map { try _adopt($0, &_seen) })
        case .data(let x): return .data(x)
        case .unknown(let id): return .unknown(id)
        }
    }
}

extension Token.Claims: CustomStringConvertible {
    public var description: String {
        var visited = Set<NodeKey>()
        return buildDescription(visited: &visited)
    }

    func buildDescription(visited: inout Set<NodeKey>) -> String {
        let key = NodeKey(arena: _arenaId, typeId: Arena.claimsTypeId, index: __index)
        guard !visited.contains(key) else { return "Claims@\(__index)" }
        visited.insert(key)
        let subjectStr = subject.map { "\"\($0)\"" } ?? "nil"
        let issuerStr = issuer.map { "\"\($0)\"" } ?? "nil"
        let audienceStr = audience.map { "\"\($0)\"" } ?? "nil"
        let issuedAtStr = String(describing: issuedAt)
        let expiresAtStr = String(describing: expiresAt)
        let scopesStr = String(describing: scopes)
        let customStr: String = custom.map { item -> String in switch item {
        case .string(let v): return "string(\(v))"
        case .number(let v): return "number(\(v))"
        case .bool(let v): return "bool(\(v))"
        case .array(let v): return "array(\(v))"
        case .object(let v): return "object(\(v))"
        case .data(let v): return "data(\(v))"
        case .unknown(let id): return "unknown(\(id))"
        } } ?? "nil"
        return "Claims@\(__index) { subject: \(subjectStr), issuer: \(issuerStr), audience: \(audienceStr), issuedAt: \(issuedAtStr), expiresAt: \(expiresAtStr), scopes: \(scopesStr), custom: \(customStr) }"
    }
}

extension Token.JsonMember: CustomStringConvertible {
    public var description: String {
        var visited = Set<NodeKey>()
        return buildDescription(visited: &visited)
    }

    func buildDescription(visited: inout Set<NodeKey>) -> String {
        let key = NodeKey(arena: _arenaId, typeId: Arena.jsonMemberTypeId, index: __index)
        guard !visited.contains(key) else { return "JsonMember@\(__index)" }
        visited.insert(key)
        let keyStr = "\"\(key)\""
        let valueStr: String = value.map { item -> String in switch item {
        case .string(let v): return "string(\(v))"
        case .number(let v): return "number(\(v))"
        case .bool(let v): return "bool(\(v))"
        case .array(let v): return "array(\(v))"
        case .object(let v): return "object(\(v))"
        case .data(let v): return "data(\(v))"
        case .unknown(let id): return "unknown(\(id))"
        } } ?? "nil"
        return "JsonMember@\(__index) { key: \(keyStr), value: \(valueStr) }"
    }
}

extension Token.Claims: Hashable {
    public func hash(into hasher: inout Hasher) {
        var visited = Set<NodeKey>()
        hashInto(hasher: &hasher, visited: &visited)
    }

    func hashInto(hasher: inout Hasher, visited: inout Set<NodeKey>) {
        let key = NodeKey(arena: _arenaId, typeId: Arena.claimsTypeId, index: __index)
        guard !visited.contains(key) else { return }
        visited.insert(key)
        hasher.combine(subject)
        hasher.combine(issuer)
        hasher.combine(audience)
        hasher.combine(issuedAt)
        hasher.combine(expiresAt)
        hasher.combine(scopes)
        if let item = custom {
            switch item {
            case .string(let v): hasher.combine(0); hasher.combine(v)
            case .number(let v): hasher.combine(1); hasher.combine(v)
            case .bool(let v): hasher.combine(2); hasher.combine(v)
            case .array(let v): hasher.combine(3); hasher.combine(v)
            case .object(let v): hasher.combine(4); hasher.combine(v)
            case .data(let v): hasher.combine(5); hasher.combine(v)
            case .unknown(let id): hasher.combine(id)
            }
        }
    }
}

extension Token.JsonMember: Hashable {
    public func hash(into hasher: inout Hasher) {
        var visited = Set<NodeKey>()
        hashInto(hasher: &hasher, visited: &visited)
    }

    func hashInto(hasher: inout Hasher, visited: inout Set<NodeKey>) {
        let key = NodeKey(arena: _arenaId, typeId: Arena.jsonMemberTypeId, index: __index)
        guard !visited.contains(key) else { return }
        visited.insert(key)
        hasher.combine(key)
        if let item = value {
            switch item {
            case .string(let v): hasher.combine(0); hasher.combine(v)
            case .number(let v): hasher.combine(1); hasher.combine(v)
            case .bool(let v): hasher.combine(2); hasher.combine(v)
            case .array(let v): hasher.combine(3); hasher.combine(v)
            case .object(let v): hasher.combine(4); hasher.combine(v)
            case .data(let v): hasher.combine(5); hasher.combine(v)
            case .unknown(let id): hasher.combine(id)
            }
        }
    }
}

extension Token.Claims: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        var visited = Set<ArenaPair>()
        return lhs.cycleAwareEquals(other: rhs, visited: &visited)
    }

    func cycleAwareEquals(other: Self, visited: inout Set<ArenaPair>) -> Bool {
        let pair = ArenaPair(
            leftArena: _arenaId, leftTypeId: Arena.claimsTypeId, leftIndex: __index,
            rightArena: other._arenaId, rightTypeId: Arena.claimsTypeId, rightIndex: other.__index
        )
        guard !visited.contains(pair) else { return true }
        visited.insert(pair)
        guard self.subject == other.subject else { return false }
        guard self.issuer == other.issuer else { return false }
        guard self.audience == other.audience else { return false }
        guard self.issuedAt == other.issuedAt else { return false }
        guard self.expiresAt == other.expiresAt else { return false }
        guard self.scopes == other.scopes else { return false }
        switch (self.custom, other.custom) {
        case (.none, .none): break
        case (.some(let a), .some(let b)):
            switch (a, b) {
            case (.string(let v1), .string(let v2)):
                guard v1 == v2 else { return false }
            case (.number(let v1), .number(let v2)):
                guard v1 == v2 else { return false }
            case (.bool(let v1), .bool(let v2)):
                guard v1 == v2 else { return false }
            case (.array(let v1), .array(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    switch (v1[_i], v2[_i]) {
                    case (.none, .none): break
                    case (.some(let _x), .some(let _y)):
                        guard _x._cycleEquals(_y, visited: &visited) else { return false }
                    default: return false
                    }
                }
            case (.object(let v1), .object(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    guard v1[_i].cycleAwareEquals(other: v2[_i], visited: &visited) else { return false }
                }
            case (.data(let v1), .data(let v2)):
                guard v1 == v2 else { return false }
            case (.unknown(let id1), .unknown(let id2)): guard id1 == id2 else { return false }
            default: return false
            }
        default: return false
        }
        return true
    }
}

extension Token.Claims {
    public static func == <OtherArena: Token.ClaimsGraph>(lhs: Self, rhs: Token.Claims<OtherArena>) -> Bool {
        var visited = Set<ArenaPair>()
        return lhs.cycleAwareEqualsAny(other: rhs, visited: &visited)
    }

    public static func != <OtherArena: Token.ClaimsGraph>(lhs: Self, rhs: Token.Claims<OtherArena>) -> Bool {
        return !(lhs == rhs)
    }

    func cycleAwareEqualsAny<OtherArena: Token.ClaimsGraph>(
        other: Token.Claims<OtherArena>,
        visited: inout Set<ArenaPair>
    ) -> Bool {
        let pair = ArenaPair(
            leftArena: _arenaId, leftTypeId: Arena.claimsTypeId, leftIndex: __index,
            rightArena: other._arenaId, rightTypeId: OtherArena.claimsTypeId, rightIndex: other.__index
        )
        guard !visited.contains(pair) else { return true }
        visited.insert(pair)
        guard self.subject == other.subject else { return false }
        guard self.issuer == other.issuer else { return false }
        guard self.audience == other.audience else { return false }
        guard self.issuedAt == other.issuedAt else { return false }
        guard self.expiresAt == other.expiresAt else { return false }
        guard self.scopes == other.scopes else { return false }
        switch (self.custom, other.custom) {
        case (.none, .none): break
        case (.some(let a), .some(let b)):
            switch (a, b) {
            case (.string(let v1), .string(let v2)):
                guard v1 == v2 else { return false }
            case (.number(let v1), .number(let v2)):
                guard v1 == v2 else { return false }
            case (.bool(let v1), .bool(let v2)):
                guard v1 == v2 else { return false }
            case (.array(let v1), .array(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    switch (v1[_i], v2[_i]) {
                    case (.none, .none): break
                    case (.some(let _x), .some(let _y)):
                        guard _x._cycleEquals(_y, visited: &visited) else { return false }
                    default: return false
                    }
                }
            case (.object(let v1), .object(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    guard v1[_i].cycleAwareEqualsAny(other: v2[_i], visited: &visited) else { return false }
                }
            case (.data(let v1), .data(let v2)):
                guard v1 == v2 else { return false }
            case (.unknown(let id1), .unknown(let id2)): guard id1 == id2 else { return false }
            default: return false
            }
        default: return false
        }
        return true
    }
}

extension Token.JsonMember: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        var visited = Set<ArenaPair>()
        return lhs.cycleAwareEquals(other: rhs, visited: &visited)
    }

    func cycleAwareEquals(other: Self, visited: inout Set<ArenaPair>) -> Bool {
        let pair = ArenaPair(
            leftArena: _arenaId, leftTypeId: Arena.jsonMemberTypeId, leftIndex: __index,
            rightArena: other._arenaId, rightTypeId: Arena.jsonMemberTypeId, rightIndex: other.__index
        )
        guard !visited.contains(pair) else { return true }
        visited.insert(pair)
        guard self.key == other.key else { return false }
        switch (self.value, other.value) {
        case (.none, .none): break
        case (.some(let a), .some(let b)):
            switch (a, b) {
            case (.string(let v1), .string(let v2)):
                guard v1 == v2 else { return false }
            case (.number(let v1), .number(let v2)):
                guard v1 == v2 else { return false }
            case (.bool(let v1), .bool(let v2)):
                guard v1 == v2 else { return false }
            case (.array(let v1), .array(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    switch (v1[_i], v2[_i]) {
                    case (.none, .none): break
                    case (.some(let _x), .some(let _y)):
                        guard _x._cycleEquals(_y, visited: &visited) else { return false }
                    default: return false
                    }
                }
            case (.object(let v1), .object(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    guard v1[_i].cycleAwareEquals(other: v2[_i], visited: &visited) else { return false }
                }
            case (.data(let v1), .data(let v2)):
                guard v1 == v2 else { return false }
            case (.unknown(let id1), .unknown(let id2)): guard id1 == id2 else { return false }
            default: return false
            }
        default: return false
        }
        return true
    }
}

extension Token.JsonMember {
    public static func == <OtherArena: Token.JsonMemberGraph>(lhs: Self, rhs: Token.JsonMember<OtherArena>) -> Bool {
        var visited = Set<ArenaPair>()
        return lhs.cycleAwareEqualsAny(other: rhs, visited: &visited)
    }

    public static func != <OtherArena: Token.JsonMemberGraph>(lhs: Self, rhs: Token.JsonMember<OtherArena>) -> Bool {
        return !(lhs == rhs)
    }

    func cycleAwareEqualsAny<OtherArena: Token.JsonMemberGraph>(
        other: Token.JsonMember<OtherArena>,
        visited: inout Set<ArenaPair>
    ) -> Bool {
        let pair = ArenaPair(
            leftArena: _arenaId, leftTypeId: Arena.jsonMemberTypeId, leftIndex: __index,
            rightArena: other._arenaId, rightTypeId: OtherArena.jsonMemberTypeId, rightIndex: other.__index
        )
        guard !visited.contains(pair) else { return true }
        visited.insert(pair)
        guard self.key == other.key else { return false }
        switch (self.value, other.value) {
        case (.none, .none): break
        case (.some(let a), .some(let b)):
            switch (a, b) {
            case (.string(let v1), .string(let v2)):
                guard v1 == v2 else { return false }
            case (.number(let v1), .number(let v2)):
                guard v1 == v2 else { return false }
            case (.bool(let v1), .bool(let v2)):
                guard v1 == v2 else { return false }
            case (.array(let v1), .array(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    switch (v1[_i], v2[_i]) {
                    case (.none, .none): break
                    case (.some(let _x), .some(let _y)):
                        guard _x._cycleEquals(_y, visited: &visited) else { return false }
                    default: return false
                    }
                }
            case (.object(let v1), .object(let v2)):
                guard v1.count == v2.count else { return false }
                for _i in v1.indices {
                    guard v1[_i].cycleAwareEqualsAny(other: v2[_i], visited: &visited) else { return false }
                }
            case (.data(let v1), .data(let v2)):
                guard v1 == v2 else { return false }
            case (.unknown(let id1), .unknown(let id2)): guard id1 == id2 else { return false }
            default: return false
            }
        default: return false
        }
        return true
    }
}

extension Token._Json {
    func _toPublic<Arena: Token.JsonGraph>(_ __graph: Arena) -> Token.Json<Arena> {
        switch self {
        case .string(let v): return .string(v)
        case .number(let v): return .number(v)
        case .bool(let v): return .bool(v)
        case .array(let v): return .array(v.map { $0.map { $0._toPublic(__graph) } })
        case .object(let v): return .object(v.map { Token.JsonMember(__packed: $0, __graph: __graph) })
        case .data(let v): return .data(v)
        case .unknown(let id): return .unknown(id)
        }
    }
}

extension Token.Json {
    func _toStorage() -> Token._Json {
        switch self {
        case .string(let v): return .string(v)
        case .number(let v): return .number(v)
        case .bool(let v): return .bool(v)
        case .array(let v): return .array(v.map { $0.map { $0._toStorage() } })
        case .object(let v): return .object(v.map { $0.__packed })
        case .data(let v): return .data(v)
        case .unknown(let id): return .unknown(id)
        }
    }
}

extension Token.Json {
    func _cycleEquals<OtherArena: Token.JsonGraph>(_ other: Token.Json<OtherArena>, visited: inout Set<ArenaPair>) -> Bool {
        switch (self, other) {
        case (.string(let v1), .string(let v2)):
            guard v1 == v2 else { return false }
        case (.number(let v1), .number(let v2)):
            guard v1 == v2 else { return false }
        case (.bool(let v1), .bool(let v2)):
            guard v1 == v2 else { return false }
        case (.array(let v1), .array(let v2)):
            guard v1.count == v2.count else { return false }
            for _i in v1.indices {
                switch (v1[_i], v2[_i]) {
                case (.none, .none): break
                case (.some(let _x), .some(let _y)):
                    guard _x._cycleEquals(_y, visited: &visited) else { return false }
                default: return false
                }
            }
        case (.object(let v1), .object(let v2)):
            guard v1.count == v2.count else { return false }
            for _i in v1.indices {
                guard v1[_i].cycleAwareEqualsAny(other: v2[_i], visited: &visited) else { return false }
            }
        case (.data(let v1), .data(let v2)):
            guard v1 == v2 else { return false }
        case (.unknown(let id1), .unknown(let id2)): guard id1 == id2 else { return false }
        default: return false
        }
        return true
    }
}

extension Token.Json: ArenaUnion {
    public var typeId: UInt64 {
        switch self {
        case .string: return 0
        case .number: return 1
        case .bool: return 2
        case .array: return 3
        case .object: return 4
        case .data: return 5
        case .unknown(let id): return id
        }
    }
    public var byteWidth: ByteWidth { .half }
    public func apply(builder: any ArenaBuilder) throws -> ArenaAppliedUnionType {
        switch self {
        case .string(let v): return .pointer(value: try v.store(with: builder), id: 0)
        case .number(let v): return .value(value: v.bitPattern, id: 1, width: .eight)
        case .bool(let v): return .value(value: v ? 1 : 0, id: 2, width: .one)
        case .array(let v): return .pointer(value: try v.store(with: builder), id: 3)
        case .object(let v): return .pointer(value: try v.store(with: builder), id: 4)
        case .data(let v): return .pointer(value: try v.store(with: builder), id: 5)
        case .unknown: throw ArenaRestoreError.invalidEnumValue
        }
    }
    public func applyPacked(builder: any ArenaBuilder) throws -> PackedStoreResult {
        switch self {
            case .string(let v): return try v.storePacked(with: builder)
            case .number(let v): return try v.storePacked(with: builder)
            case .bool(let v): return try v.storePacked(with: builder)
            case .array(let v): return try v.storePacked(with: builder)
            case .object(let v): return try v.storePacked(with: builder)
            case .data(let v): return try v.storePacked(with: builder)
        case .unknown: throw ArenaRestoreError.invalidEnumValue
        }
    }
}

extension Token.Claims: ArenaNodeHandle {}
extension Token.Claims: ArenaGraphStorable {
    var cycleIdentifier: ArenaCycleIdntifier {
        .init(nodeTypeId: Arena.claimsTypeId, nodeIndex: __index)
    }

    public func store(with builder: any ArenaBuilder) throws -> BufferOffset {
        if let offset = try builder.beginStoring(nodeId: cycleIdentifier) {
            return offset
        }
        _ = try storePacked(with: builder)
        let offset = builder.cursor
        try builder.finishStoring(nodeId: cycleIdentifier, offset: offset)
        return offset
    }

    public func storePacked(with builder: any ArenaBuilder) throws -> PackedStoreResult {
        let before = try builder.beginPackedStoring(nodeId: cycleIdentifier)
        if let _uv_custom = self.custom {
            let _r_custom = try _uv_custom.applyPacked(builder: builder)
            _ = try builder.storeAsLEB(value: (_uv_custom.typeId << 3) | UInt64(_r_custom.unionCode))
        }
        _ = try self.scopes.storePacked(with: builder)
        let _expiresAtPackedResult = try self.expiresAt.storePacked(with: builder)
        let _issuedAtPackedResult = try self.issuedAt.storePacked(with: builder)
        _ = try self.audience?.storePacked(with: builder)
        _ = try self.issuer?.storePacked(with: builder)
        _ = try self.subject?.storePacked(with: builder)
        var _encByte: UInt8 = 0
        if _issuedAtPackedResult.isRaw { _encByte |= 1 }
        if _expiresAtPackedResult.isRaw { _encByte |= 2 }
        _ = try builder.store(number: _encByte)
        var _nilByte: UInt8 = 0
        if self.subject != nil { _nilByte |= 1 }
        if self.issuer != nil { _nilByte |= 2 }
        if self.audience != nil { _nilByte |= 4 }
        if !self.scopes.isEmpty { _nilByte |= 8 }
        if self.custom != nil { _nilByte |= 16 }
        _ = try builder.store(number: _nilByte)
        _ = try builder.storeAsLEB(value: builder.cursor.value - before.value)
        return builder.finishPackedStoring(nodeId: cycleIdentifier)
    }
}

extension Token.JsonMember: ArenaNodeHandle {}
extension Token.JsonMember: ArenaGraphStorable {
    var cycleIdentifier: ArenaCycleIdntifier {
        .init(nodeTypeId: Arena.jsonMemberTypeId, nodeIndex: __index)
    }

    public func store(with builder: any ArenaBuilder) throws -> BufferOffset {
        if let offset = try builder.beginStoring(nodeId: cycleIdentifier) {
            return offset
        }
        _ = try storePacked(with: builder)
        let offset = builder.cursor
        try builder.finishStoring(nodeId: cycleIdentifier, offset: offset)
        return offset
    }

    public func storePacked(with builder: any ArenaBuilder) throws -> PackedStoreResult {
        let before = try builder.beginPackedStoring(nodeId: cycleIdentifier)
        if let _uv_value = self.value {
            let _r_value = try _uv_value.applyPacked(builder: builder)
            _ = try builder.storeAsLEB(value: (_uv_value.typeId << 3) | UInt64(_r_value.unionCode))
        }
        _ = try self.key.storePacked(with: builder)
        var _nilByte: UInt8 = 0
        if self.value != nil { _nilByte |= 1 }
        _ = try builder.store(number: _nilByte)
        _ = try builder.storeAsLEB(value: builder.cursor.value - before.value)
        return builder.finishPackedStoring(nodeId: cycleIdentifier)
    }
}

extension Token {
    public struct Jws: ArenaGraphStorable {
        public var algorithm: String = ""
        public var keyId: String? = nil
        public var signature: Data = Data()

        public init(algorithm: String = "", keyId: String? = nil, signature: Data = Data()) {
            self.algorithm = algorithm
            self.keyId = keyId
            self.signature = signature
        }

        public func storePacked(with builder: any ArenaBuilder) throws -> PackedStoreResult {
            let before = builder.cursor.value
            _ = try self.signature.storePacked(with: builder).store(index: 2, with: builder)
            _ = try self.keyId?.storePacked(with: builder).store(index: 1, with: builder)
            _ = try self.algorithm.storePacked(with: builder).store(index: 0, with: builder)
            _ = try builder.storeAsLEB(value: builder.cursor.value - before)
            return .raw(0)
        }

        public func store(with builder: any ArenaBuilder) throws -> BufferOffset {
            _ = try storePacked(with: builder); return builder.cursor
        }

        public static func restore(from data: Foundation.Data, at start: Int) throws -> Jws {
            var values = Jws()
            let (_bl, _blB) = try restoreLEB(from: data, at: start)
            var _cursor = start + _blB
            let _end = _cursor + Int(_bl)
            _ = _end
            if _cursor < _end {
                let (_tag_algorithm, _tag_algorithmB) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag_algorithm) >> 1 == 0 {
                    _cursor += _tag_algorithmB
                    let (_sv_algorithm, _sb_algorithm) = try restoreLEB(from: data, at: _cursor); _cursor += _sb_algorithm
                    values.algorithm = String(decoding: data[_cursor..<(_cursor + Int(_sv_algorithm))], as: UTF8.self); _cursor += Int(_sv_algorithm)
                }
            }
            if _cursor < _end {
                let (_tag_keyId, _tag_keyIdB) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag_keyId) >> 1 == 1 {
                    _cursor += _tag_keyIdB
                    let (_sv_keyId, _sb_keyId) = try restoreLEB(from: data, at: _cursor); _cursor += _sb_keyId
                    values.keyId = String(decoding: data[_cursor..<(_cursor + Int(_sv_keyId))], as: UTF8.self); _cursor += Int(_sv_keyId)
                }
            }
            if _cursor < _end {
                let (_tag_signature, _tag_signatureB) = try restoreLEB(from: data, at: _cursor)
                if Int(_tag_signature) >> 1 == 2 {
                    _cursor += _tag_signatureB
                    let (_dv_signature, _db_signature) = try restoreLEB(from: data, at: _cursor); _cursor += _db_signature
                    values.signature = Foundation.Data(data[_cursor..<(_cursor + Int(_dv_signature))]); _cursor += Int(_dv_signature)
                }
            }
            return values
        }
    }

}

extension Token.Arena {
    public func toData(header headerFn: (Int, Foundation.Data) throws -> Token.Jws) throws -> Foundation.Data {
        guard let root = root else { return Foundation.Data() }
        let builder = DataArenaBuilder()
        let rootOffset = try root.store(with: builder)
        let originalOffset = Int(builder.cursor.value - rootOffset.value)
        let body = builder.makeData
        let headerValue = try headerFn(originalOffset, body)
        let hb = DataArenaBuilder()
        _ = try headerValue.storePacked(with: hb)
        let headerBytes = hb.makeData
        let H = headerBytes.count
        let storedOffset = UInt64((originalOffset + H) << 2 | 0b01)
        var out = encodeLEB128(storedOffset)
        out.append(headerBytes)
        out.append(body)
        return out
    }

    public static func restore(from data: Foundation.Data, header headerGate: (Token.Jws, Int, Foundation.Data) throws -> Void) throws -> Token.Arena<Brand> {
        guard !data.isEmpty else { return Token.Arena<Brand>() }
        let arena = Token.Arena<Brand>()
        let (framing, lebLen) = try restoreLEB(from: data, at: 0)
        guard (framing & 1) == 1 else { throw ArenaRestoreError.missingHeader }
        guard ((framing >> 1) & 1) == 0 else { throw ArenaRestoreError.invalidFraming }
        let storedOffset = Int(framing >> 2)
        let headerStart = lebLen
        let (hcs, hcsB) = try restoreLEB(from: data, at: headerStart)
        let H = hcsB + Int(hcs)
        let header = try Token.Jws.restore(from: data, at: headerStart)
        let bodyStart = headerStart + H
        let body = data.subdata(in: bodyStart ..< data.count)
        try headerGate(header, storedOffset - H, body)
        let rootStart = lebLen + storedOffset
        var cache = [Int: Int]()
        arena.root = try arena._restoreClaims(from: data, at: rootStart, cache: &cache)
        return arena
    }

    private func _restoreClaims(from data: Foundation.Data, at start: Int, cache: inout [Int: Int]) throws -> Token.Claims<Token.Arena<Brand>> {
        if let idx = cache[start] { return Token.Claims(__packed: UInt64(idx), __graph: self) }
        let idx = arenaOfClaims.count
        cache[start] = idx
        arenaOfClaims.append(Token.ClaimsValues(issuedAt: 0, expiresAt: 0))
        var values = Token.ClaimsValues(issuedAt: 0, expiresAt: 0)
        let (_, _blB) = try restoreLEB(from: data, at: start)
        var _cur = start + _blB
        let _obs0 = _cur + 0 < data.count ? data[_cur + 0] : UInt8(0)
        _cur += 1
        let _ebs0 = _cur + 0 < data.count ? data[_cur + 0] : UInt8(0)
        _cur += 1
        if _obs0 & 1 != 0 {
            let (_sv_subject, _sb_subject) = try restoreLEB(from: data, at: _cur); _cur += _sb_subject
            values.subject = String(decoding: data[_cur..<(_cur + Int(_sv_subject))], as: UTF8.self)
            _cur += Int(_sv_subject)
        }
        if _obs0 & 2 != 0 {
            let (_sv_issuer, _sb_issuer) = try restoreLEB(from: data, at: _cur); _cur += _sb_issuer
            values.issuer = String(decoding: data[_cur..<(_cur + Int(_sv_issuer))], as: UTF8.self)
            _cur += Int(_sv_issuer)
        }
        if _obs0 & 4 != 0 {
            let (_sv_audience, _sb_audience) = try restoreLEB(from: data, at: _cur); _cur += _sb_audience
            values.audience = String(decoding: data[_cur..<(_cur + Int(_sv_audience))], as: UTF8.self)
            _cur += Int(_sv_audience)
        }
        if _ebs0 & 1 != 0 {
            values.issuedAt = try UInt64.restore(from: data, at: _cur); _cur += 8
        } else {
            let (_lv_issuedAt, _lb_issuedAt) = try restoreLEB(from: data, at: _cur)
            values.issuedAt = UInt64(_lv_issuedAt); _cur += _lb_issuedAt
        }
        if _ebs0 & 2 != 0 {
            values.expiresAt = try UInt64.restore(from: data, at: _cur); _cur += 8
        } else {
            let (_lv_expiresAt, _lb_expiresAt) = try restoreLEB(from: data, at: _cur)
            values.expiresAt = UInt64(_lv_expiresAt); _cur += _lb_expiresAt
        }
        let (_bbl_scopes, _bblB_scopes) = try restoreLEB(from: data, at: _cur)
        let _bend_scopes = _cur + _bblB_scopes + Int(_bbl_scopes)
        _cur += _bblB_scopes
        values.scopes = try _restorePackedComplexArray(from: data, at: _cur, { String(decoding: $0, as: UTF8.self) })
        _cur = _bend_scopes
        if _obs0 & 16 != 0 {
            let (_hdr_custom, _hdrB_custom) = try restoreLEB(from: data, at: _cur)
            let _tid_custom = _hdr_custom >> 3
            let _code_custom = Int(_hdr_custom & 7)
            var _vp_custom = _cur + _hdrB_custom
            var _tmp_custom = [Token._Json?]()
            switch _tid_custom {
            case 0:
                let (_bl_0, _blB_0) = try restoreLEB(from: data, at: _vp_custom)
                _tmp_custom.append(.string(try String.restore(from: data, at: _vp_custom)))
                _vp_custom += _blB_0 + Int(_bl_0)
            case 1:
                if _code_custom == 5 {
                    let (_fv_1, _fb_1) = try _decodePackedFloat64(from: data, at: _vp_custom)
                    _tmp_custom.append(.number(_fv_1))
                    _vp_custom += _fb_1
                } else {
                    _tmp_custom.append(.number(try Double.restore(from: data, at: _vp_custom)))
                    _vp_custom += 8
                }
            case 2:
                guard _vp_custom >= 0, _vp_custom < data.count else { throw ArenaRestoreError.outsideOfBuffer }
                _tmp_custom.append(.bool(data[_vp_custom] != 0))
                _vp_custom += 1
            case 3:
                let (_absz_3, _abszB_3) = try restoreLEB(from: data, at: _vp_custom)
                let _ab_3 = _vp_custom + _abszB_3
                let (_uacnt_3, _uacntB_3) = try restoreLEB(from: data, at: _ab_3)
                var _uav_3 = [Token._Json?]()
                let _ubs_3 = _ab_3 + _uacntB_3
                var _uap_3 = _ubs_3 + (Int(_uacnt_3) + 7) / 8
                let (_uhss_3, _uhssB_3) = try restoreLEB(from: data, at: _uap_3); _uap_3 += _uhssB_3
                let _uhend_3 = _uap_3 + Int(_uhss_3)
                var _uhdrs_3 = [UInt64](); while _uap_3 < _uhend_3 { let (_h, _hb) = try restoreLEB(from: data, at: _uap_3); _uhdrs_3.append(_h); _uap_3 += _hb }
                var _upp_3 = _uap_3
                var _uhi_3 = 0
                for _uei_3 in 0..<Int(_uacnt_3) {
                    if (_ubs_3 + _uei_3 / 8 < data.count ? data[_ubs_3 + _uei_3 / 8] : 0) & UInt8(1 << (_uei_3 % 8)) != 0 { _uav_3.append(nil); continue }
                    let _uhdr_3 = _uhdrs_3[_uhi_3]; _uhi_3 += 1
                    let _utid_3 = _uhdr_3 >> 3
                    let _ucode_3 = Int(_uhdr_3 & 7)
                    var _utmp_3 = [Token._Json?]()
                    switch _utid_3 {
                    case 0:
                        let (_bl_0, _blB_0) = try restoreLEB(from: data, at: _upp_3)
                        _utmp_3.append(.string(try String.restore(from: data, at: _upp_3)))
                        _upp_3 += _blB_0 + Int(_bl_0)
                    case 1:
                        if _ucode_3 == 5 {
                            let (_fv_1, _fb_1) = try _decodePackedFloat64(from: data, at: _upp_3)
                            _utmp_3.append(.number(_fv_1))
                            _upp_3 += _fb_1
                        } else {
                            _utmp_3.append(.number(try Double.restore(from: data, at: _upp_3)))
                            _upp_3 += 8
                        }
                    case 2:
                        guard _upp_3 >= 0, _upp_3 < data.count else { throw ArenaRestoreError.outsideOfBuffer }
                        _utmp_3.append(.bool(data[_upp_3] != 0))
                        _upp_3 += 1
                    case 3:
                        let (_absz_3, _abszB_3) = try restoreLEB(from: data, at: _upp_3)
                        _upp_3 += _abszB_3 + Int(_absz_3)
                    case 4:
                        let (_absz_4, _abszB_4) = try restoreLEB(from: data, at: _upp_3)
                        let _ab_4 = _upp_3 + _abszB_4
                        let (_acnt_4, _acntB_4) = try restoreLEB(from: data, at: _ab_4)
                        var _ap_4 = _ab_4 + _acntB_4
                        var _av_4 = [UInt64]()
                        for _ in 0..<Int(_acnt_4) {
                            let (_ebl_4, _eblB_4) = try restoreLEB(from: data, at: _ap_4)
                            _av_4.append(try _restoreJsonMember(from: data, at: _ap_4, cache: &cache).__packed)
                            _ap_4 += _eblB_4 + Int(_ebl_4)
                        }
                        _utmp_3.append(.object(_av_4))
                        _upp_3 += _abszB_4 + Int(_absz_4)
                    case 5:
                        let (_bl_5, _blB_5) = try restoreLEB(from: data, at: _upp_3)
                        _utmp_3.append(.data(try Foundation.Data.restore(from: data, at: _upp_3)))
                        _upp_3 += _blB_5 + Int(_bl_5)
                    default: _utmp_3.append(.unknown(_utid_3))
                    }
                    _uav_3.append(_utmp_3.first ?? nil)
                }
                _tmp_custom.append(.array(_uav_3))
                _vp_custom += _abszB_3 + Int(_absz_3)
            case 4:
                let (_absz_4, _abszB_4) = try restoreLEB(from: data, at: _vp_custom)
                let _ab_4 = _vp_custom + _abszB_4
                let (_acnt_4, _acntB_4) = try restoreLEB(from: data, at: _ab_4)
                var _ap_4 = _ab_4 + _acntB_4
                var _av_4 = [UInt64]()
                for _ in 0..<Int(_acnt_4) {
                    let (_ebl_4, _eblB_4) = try restoreLEB(from: data, at: _ap_4)
                    _av_4.append(try _restoreJsonMember(from: data, at: _ap_4, cache: &cache).__packed)
                    _ap_4 += _eblB_4 + Int(_ebl_4)
                }
                _tmp_custom.append(.object(_av_4))
                _vp_custom += _abszB_4 + Int(_absz_4)
            case 5:
                let (_bl_5, _blB_5) = try restoreLEB(from: data, at: _vp_custom)
                _tmp_custom.append(.data(try Foundation.Data.restore(from: data, at: _vp_custom)))
                _vp_custom += _blB_5 + Int(_bl_5)
            default: _tmp_custom.append(nil)
            }
            values.custom = _tmp_custom.first ?? nil
            _cur = _vp_custom
        }
        arenaOfClaims[idx] = values
        return Token.Claims(__packed: UInt64(idx), __graph: self)
    }

    private func _restoreJsonMember(from data: Foundation.Data, at start: Int, cache: inout [Int: Int]) throws -> Token.JsonMember<Token.Arena<Brand>> {
        if let idx = cache[start] { return Token.JsonMember(__packed: UInt64(idx), __graph: self) }
        let idx = arenaOfJsonMember.count
        cache[start] = idx
        arenaOfJsonMember.append(Token.JsonMemberValues(key: ""))
        var values = Token.JsonMemberValues(key: "")
        let (_, _blB) = try restoreLEB(from: data, at: start)
        var _cur = start + _blB
        let _obs0 = _cur + 0 < data.count ? data[_cur + 0] : UInt8(0)
        _cur += 1
        let (_sv_key, _sb_key) = try restoreLEB(from: data, at: _cur); _cur += _sb_key
        values.key = String(decoding: data[_cur..<(_cur + Int(_sv_key))], as: UTF8.self)
        _cur += Int(_sv_key)
        if _obs0 & 1 != 0 {
            let (_hdr_value, _hdrB_value) = try restoreLEB(from: data, at: _cur)
            let _tid_value = _hdr_value >> 3
            let _code_value = Int(_hdr_value & 7)
            var _vp_value = _cur + _hdrB_value
            var _tmp_value = [Token._Json?]()
            switch _tid_value {
            case 0:
                let (_bl_0, _blB_0) = try restoreLEB(from: data, at: _vp_value)
                _tmp_value.append(.string(try String.restore(from: data, at: _vp_value)))
                _vp_value += _blB_0 + Int(_bl_0)
            case 1:
                if _code_value == 5 {
                    let (_fv_1, _fb_1) = try _decodePackedFloat64(from: data, at: _vp_value)
                    _tmp_value.append(.number(_fv_1))
                    _vp_value += _fb_1
                } else {
                    _tmp_value.append(.number(try Double.restore(from: data, at: _vp_value)))
                    _vp_value += 8
                }
            case 2:
                guard _vp_value >= 0, _vp_value < data.count else { throw ArenaRestoreError.outsideOfBuffer }
                _tmp_value.append(.bool(data[_vp_value] != 0))
                _vp_value += 1
            case 3:
                let (_absz_3, _abszB_3) = try restoreLEB(from: data, at: _vp_value)
                let _ab_3 = _vp_value + _abszB_3
                let (_uacnt_3, _uacntB_3) = try restoreLEB(from: data, at: _ab_3)
                var _uav_3 = [Token._Json?]()
                let _ubs_3 = _ab_3 + _uacntB_3
                var _uap_3 = _ubs_3 + (Int(_uacnt_3) + 7) / 8
                let (_uhss_3, _uhssB_3) = try restoreLEB(from: data, at: _uap_3); _uap_3 += _uhssB_3
                let _uhend_3 = _uap_3 + Int(_uhss_3)
                var _uhdrs_3 = [UInt64](); while _uap_3 < _uhend_3 { let (_h, _hb) = try restoreLEB(from: data, at: _uap_3); _uhdrs_3.append(_h); _uap_3 += _hb }
                var _upp_3 = _uap_3
                var _uhi_3 = 0
                for _uei_3 in 0..<Int(_uacnt_3) {
                    if (_ubs_3 + _uei_3 / 8 < data.count ? data[_ubs_3 + _uei_3 / 8] : 0) & UInt8(1 << (_uei_3 % 8)) != 0 { _uav_3.append(nil); continue }
                    let _uhdr_3 = _uhdrs_3[_uhi_3]; _uhi_3 += 1
                    let _utid_3 = _uhdr_3 >> 3
                    let _ucode_3 = Int(_uhdr_3 & 7)
                    var _utmp_3 = [Token._Json?]()
                    switch _utid_3 {
                    case 0:
                        let (_bl_0, _blB_0) = try restoreLEB(from: data, at: _upp_3)
                        _utmp_3.append(.string(try String.restore(from: data, at: _upp_3)))
                        _upp_3 += _blB_0 + Int(_bl_0)
                    case 1:
                        if _ucode_3 == 5 {
                            let (_fv_1, _fb_1) = try _decodePackedFloat64(from: data, at: _upp_3)
                            _utmp_3.append(.number(_fv_1))
                            _upp_3 += _fb_1
                        } else {
                            _utmp_3.append(.number(try Double.restore(from: data, at: _upp_3)))
                            _upp_3 += 8
                        }
                    case 2:
                        guard _upp_3 >= 0, _upp_3 < data.count else { throw ArenaRestoreError.outsideOfBuffer }
                        _utmp_3.append(.bool(data[_upp_3] != 0))
                        _upp_3 += 1
                    case 3:
                        let (_absz_3, _abszB_3) = try restoreLEB(from: data, at: _upp_3)
                        _upp_3 += _abszB_3 + Int(_absz_3)
                    case 4:
                        let (_absz_4, _abszB_4) = try restoreLEB(from: data, at: _upp_3)
                        let _ab_4 = _upp_3 + _abszB_4
                        let (_acnt_4, _acntB_4) = try restoreLEB(from: data, at: _ab_4)
                        var _ap_4 = _ab_4 + _acntB_4
                        var _av_4 = [UInt64]()
                        for _ in 0..<Int(_acnt_4) {
                            let (_ebl_4, _eblB_4) = try restoreLEB(from: data, at: _ap_4)
                            _av_4.append(try _restoreJsonMember(from: data, at: _ap_4, cache: &cache).__packed)
                            _ap_4 += _eblB_4 + Int(_ebl_4)
                        }
                        _utmp_3.append(.object(_av_4))
                        _upp_3 += _abszB_4 + Int(_absz_4)
                    case 5:
                        let (_bl_5, _blB_5) = try restoreLEB(from: data, at: _upp_3)
                        _utmp_3.append(.data(try Foundation.Data.restore(from: data, at: _upp_3)))
                        _upp_3 += _blB_5 + Int(_bl_5)
                    default: _utmp_3.append(.unknown(_utid_3))
                    }
                    _uav_3.append(_utmp_3.first ?? nil)
                }
                _tmp_value.append(.array(_uav_3))
                _vp_value += _abszB_3 + Int(_absz_3)
            case 4:
                let (_absz_4, _abszB_4) = try restoreLEB(from: data, at: _vp_value)
                let _ab_4 = _vp_value + _abszB_4
                let (_acnt_4, _acntB_4) = try restoreLEB(from: data, at: _ab_4)
                var _ap_4 = _ab_4 + _acntB_4
                var _av_4 = [UInt64]()
                for _ in 0..<Int(_acnt_4) {
                    let (_ebl_4, _eblB_4) = try restoreLEB(from: data, at: _ap_4)
                    _av_4.append(try _restoreJsonMember(from: data, at: _ap_4, cache: &cache).__packed)
                    _ap_4 += _eblB_4 + Int(_ebl_4)
                }
                _tmp_value.append(.object(_av_4))
                _vp_value += _abszB_4 + Int(_absz_4)
            case 5:
                let (_bl_5, _blB_5) = try restoreLEB(from: data, at: _vp_value)
                _tmp_value.append(.data(try Foundation.Data.restore(from: data, at: _vp_value)))
                _vp_value += _blB_5 + Int(_bl_5)
            default: _tmp_value.append(nil)
            }
            values.value = _tmp_value.first ?? nil
            _cur = _vp_value
        }
        arenaOfJsonMember[idx] = values
        return Token.JsonMember(__packed: UInt64(idx), __graph: self)
    }

    private func _restoreJsonMemberNodeArray(from data: Foundation.Data, at pos: Int, cache: inout [Int: Int]) throws -> [UInt64] {
        let (h, hl) = try restoreLEB(from: data, at: pos)
        let cnt = Int(h >> 2); let wc = Int(h & 3)
        let es = [1,2,4,8][wc]
        let base = pos + hl + cnt * es
        var result = [UInt64]()
        for k in 0..<cnt {
            let ep = pos + hl + k * es
            let ro = try readSignedRelOffset(from: data, at: ep, size: es)
            if ro == 0 { continue }
            result.append(try _restoreJsonMember(from: data, at: base + Int(ro) - 1, cache: &cache).__packed)
        }
        return result
    }

    private func _restoreJsonMemberNodeArrayOpt(from data: Foundation.Data, at pos: Int, cache: inout [Int: Int]) throws -> [UInt64?] {
        let (h, hl) = try restoreLEB(from: data, at: pos)
        let cnt = Int(h >> 2); let wc = Int(h & 3)
        let es = [1,2,4,8][wc]
        let base = pos + hl + cnt * es
        var result = [UInt64?]()
        for k in 0..<cnt {
            let ep = pos + hl + k * es
            let ro = try readSignedRelOffset(from: data, at: ep, size: es)
            if ro == 0 { result.append(nil); continue }
            result.append(try _restoreJsonMember(from: data, at: base + Int(ro) - 1, cache: &cache).__packed)
        }
        return result
    }

    private func _restoreJsonStorage(from data: Foundation.Data, at pos: Int, cache: inout [Int: Int]) throws -> Token._Json? {
        let (hdr, tidBytes) = try restoreLEB(from: data, at: pos)
        let typeId = hdr >> 2
        let vPos = pos + tidBytes
        switch typeId {
        case 0:
            let (fwd, fwdB) = try readV62(from: data, at: vPos)
            return .string(try String.restore(from: data, at: vPos + fwdB + Int(fwd)))
        case 1:
            return .number(try Double.restore(from: data, at: vPos))
        case 2:
            return .bool(try Bool.restore(from: data, at: vPos))
        case 3:
            let (fwd, fwdB) = try readV62(from: data, at: vPos)
            let _aPos = vPos + fwdB + Int(fwd)
            return .array(try _restoreJsonStorageArrayOpt(from: data, at: _aPos, cache: &cache))
        case 4:
            let (fwd, fwdB) = try readV62(from: data, at: vPos)
            let _aPos = vPos + fwdB + Int(fwd)
            return .object(try _restoreJsonMemberNodeArray(from: data, at: _aPos, cache: &cache))
        case 5:
            let (fwd, fwdB) = try readV62(from: data, at: vPos)
            return .data(try Foundation.Data.restore(from: data, at: vPos + fwdB + Int(fwd)))
        default: return typeId < 16 ? .unknown(typeId) : nil
        }
    }

    private func _restoreJsonStorageArray(from data: Foundation.Data, at pos: Int, cache: inout [Int: Int]) throws -> [Token._Json] {
        let (hdr, hLen) = try restoreLEB(from: data, at: pos)
        let count = Int(hdr >> 2); let wc = Int(hdr & 3)
        let es = [1,2,4,8][wc]
        let tidLen = (count + 1) / 2
        let tidStart = pos + hLen
        let base = pos + hLen + tidLen + count * es
        var result = [Token._Json]()
        for i in 0..<count {
            let ep = pos + hLen + tidLen + i * es
            let ro = try readRelOffset(from: data, at: ep, size: es)
            let typeId = UInt64((data[tidStart + i / 2] >> ((i % 2) * 4)) & 15)
            switch typeId {
            case 0:
                result.append(.string(try String.restore(from: data, at: base + Int(ro))))
            case 1:
                result.append(.number(Double(bitPattern: ro)))
            case 2:
                result.append(.bool(ro != 0))
            case 3:
                result.append(.array(try _restoreJsonStorageArrayOpt(from: data, at: base + Int(ro), cache: &cache)))
            case 4:
                result.append(.object(try _restoreJsonMemberNodeArray(from: data, at: base + Int(ro), cache: &cache)))
            case 5:
                result.append(.data(try Foundation.Data.restore(from: data, at: base + Int(ro))))
            default: result.append(.unknown(typeId))
            }
        }
        return result
    }

    private func _restoreJsonStorageArrayOpt(from data: Foundation.Data, at pos: Int, cache: inout [Int: Int]) throws -> [Token._Json?] {
        let (hdr, hLen) = try restoreLEB(from: data, at: pos)
        let count = Int(hdr >> 2); let wc = Int(hdr & 3)
        let es = [1,2,4,8][wc]
        let bsNilSize = (count + 7) / 8
        let tidLen = (count + 1) / 2
        let tidStart = pos + hLen
        let base = pos + hLen + tidLen + bsNilSize + count * es
        var result = [Token._Json?]()
        for i in 0..<count {
            if pos + hLen + tidLen + i / 8 < data.count, (data[pos + hLen + tidLen + i / 8] >> (i % 8)) & 1 != 0 { result.append(nil); continue }
            let ep = pos + hLen + tidLen + bsNilSize + i * es
            let ro = try readRelOffset(from: data, at: ep, size: es)
            let typeId = UInt64((data[tidStart + i / 2] >> ((i % 2) * 4)) & 15)
            switch typeId {
            case 0:
                result.append(.string(try String.restore(from: data, at: base + Int(ro))))
            case 1:
                result.append(.number(Double(bitPattern: ro)))
            case 2:
                result.append(.bool(ro != 0))
            case 3:
                result.append(.array(try _restoreJsonStorageArrayOpt(from: data, at: base + Int(ro), cache: &cache)))
            case 4:
                result.append(.object(try _restoreJsonMemberNodeArray(from: data, at: base + Int(ro), cache: &cache)))
            case 5:
                result.append(.data(try Foundation.Data.restore(from: data, at: base + Int(ro))))
            default: result.append(.unknown(typeId))
            }
        }
        return result
    }

}


// ── Direct Graph Builder ("31 Direct Graph Builder.md") ─────────────────────
// Arena-free construction for this packed-rooted tree: value structs in,
// byte-identical graph buffer out. `Direct.toData*(v) == Arena.toData*()`.
extension Token {
    public enum Direct {
        public enum Json: ArenaUnion {
            case string(String)
            case number(Double)
            case bool(Bool)
            case array([Json?])
            case object([JsonMember])
            case data(Foundation.Data)
            case unknown(UInt64)
            public var typeId: UInt64 {
                switch self {
                case .string: return 0
                case .number: return 1
                case .bool: return 2
                case .array: return 3
                case .object: return 4
                case .data: return 5
                case .unknown(let id): return id
                }
            }
            public var byteWidth: ByteWidth { .half }
            public func apply(builder: any ArenaBuilder) throws -> ArenaAppliedUnionType {
                switch self {
                case .string(let v): return .pointer(value: try v.store(with: builder), id: 0)
                case .number(let v): return .value(value: v.bitPattern, id: 1, width: .eight)
                case .bool(let v): return .value(value: v ? 1 : 0, id: 2, width: .one)
                case .array(let v): return .pointer(value: try v.store(with: builder), id: 3)
                case .object(let v): return .pointer(value: try v.store(with: builder), id: 4)
                case .data(let v): return .pointer(value: try v.store(with: builder), id: 5)
                case .unknown: throw ArenaRestoreError.invalidEnumValue
                }
            }
            public func applyPacked(builder: any ArenaBuilder) throws -> PackedStoreResult {
                switch self {
                case .string(let v): return try v.storePacked(with: builder)
                case .number(let v): return try v.storePacked(with: builder)
                case .bool(let v): return try v.storePacked(with: builder)
                case .array(let v): return try v.storePacked(with: builder)
                case .object(let v): return try v.storePacked(with: builder)
                case .data(let v): return try v.storePacked(with: builder)
                case .unknown: throw ArenaRestoreError.invalidEnumValue
                }
            }
        }

        public struct Claims: ArenaGraphStorable {
            public var subject: String?
            public var issuer: String?
            public var audience: String?
            public var issuedAt: UInt64
            public var expiresAt: UInt64
            public var scopes: [String]
            public var custom: Json?
            public init(subject: String? = nil, issuer: String? = nil, audience: String? = nil, issuedAt: UInt64, expiresAt: UInt64, scopes: [String] = [], custom: Json? = nil) {
                self.subject = subject
                self.issuer = issuer
                self.audience = audience
                self.issuedAt = issuedAt
                self.expiresAt = expiresAt
                self.scopes = scopes
                self.custom = custom
            }
            public func store(with builder: any ArenaBuilder) throws -> BufferOffset {
                _ = try storePacked(with: builder)
                return builder.cursor
            }
            public func storePacked(with builder: any ArenaBuilder) throws -> PackedStoreResult {
                let before = builder.cursor
        if let _uv_custom = self.custom {
            let _r_custom = try _uv_custom.applyPacked(builder: builder)
            _ = try builder.storeAsLEB(value: (_uv_custom.typeId << 3) | UInt64(_r_custom.unionCode))
        }
        _ = try self.scopes.storePacked(with: builder)
        let _expiresAtPackedResult = try self.expiresAt.storePacked(with: builder)
        let _issuedAtPackedResult = try self.issuedAt.storePacked(with: builder)
        _ = try self.audience?.storePacked(with: builder)
        _ = try self.issuer?.storePacked(with: builder)
        _ = try self.subject?.storePacked(with: builder)
        var _encByte: UInt8 = 0
        if _issuedAtPackedResult.isRaw { _encByte |= 1 }
        if _expiresAtPackedResult.isRaw { _encByte |= 2 }
        _ = try builder.store(number: _encByte)
        var _nilByte: UInt8 = 0
        if self.subject != nil { _nilByte |= 1 }
        if self.issuer != nil { _nilByte |= 2 }
        if self.audience != nil { _nilByte |= 4 }
        if !self.scopes.isEmpty { _nilByte |= 8 }
        if self.custom != nil { _nilByte |= 16 }
        _ = try builder.store(number: _nilByte)
                _ = try builder.storeAsLEB(value: builder.cursor.value - before.value)
                return .raw(0)
            }
        }

        public struct JsonMember: ArenaGraphStorable {
            public var key: String
            public var value: Json?
            public init(key: String, value: Json? = nil) {
                self.key = key
                self.value = value
            }
            public func store(with builder: any ArenaBuilder) throws -> BufferOffset {
                _ = try storePacked(with: builder)
                return builder.cursor
            }
            public func storePacked(with builder: any ArenaBuilder) throws -> PackedStoreResult {
                let before = builder.cursor
        if let _uv_value = self.value {
            let _r_value = try _uv_value.applyPacked(builder: builder)
            _ = try builder.storeAsLEB(value: (_uv_value.typeId << 3) | UInt64(_r_value.unionCode))
        }
        _ = try self.key.storePacked(with: builder)
        var _nilByte: UInt8 = 0
        if self.value != nil { _nilByte |= 1 }
        _ = try builder.store(number: _nilByte)
                _ = try builder.storeAsLEB(value: builder.cursor.value - before.value)
                return .raw(0)
            }
        }

        public static func toData(_ root: Claims, header headerFn: (Int, Foundation.Data) throws -> Token.Jws) throws -> Foundation.Data {
            let builder = DataArenaBuilder()
            let rootOffset = try root.store(with: builder)
            let originalOffset = Int(builder.cursor.value - rootOffset.value)
            let body = builder.makeData
            let headerValue = try headerFn(originalOffset, body)
            let bodyLen = Int(builder.cursor.value)
            _ = try headerValue.storePacked(with: builder)
            let H = Int(builder.cursor.value) - bodyLen
            let storedOffset = UInt64((originalOffset + H) << 2 | 0b01)
            var out = encodeLEB128(storedOffset)
            out.append(builder.makeData)
            return out
        }
    }
}
