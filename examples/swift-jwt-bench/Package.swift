// swift-tools-version:5.9
// Standalone JWT baseline for the benchmark — a REAL Swift JWT library (Vapor's JWTKit),
// the analogue of Rust's `jsonwebtoken` / TS's `jsonwebtoken` / Python's PyJWT. Kept in its
// own SwiftPM package so the main Swift example stays zero-dep (built with plain swiftc and
// shared with the cross-language gate). Emits a `BENCH swift jwt …` line for run_bench.sh.
import PackageDescription

let package = Package(
    name: "swift-jwt-bench",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "swift-jwt-bench",
            dependencies: [.product(name: "JWTKit", package: "jwt-kit")]
        ),
    ]
)
