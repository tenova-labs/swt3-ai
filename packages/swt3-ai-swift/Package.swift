// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "swt3-ai",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .watchOS(.v6),
        .tvOS(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "SWT3", targets: ["SWT3"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "SWT3",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ],
            path: "Sources/SWT3"
        ),
        .testTarget(
            name: "SWT3Tests",
            dependencies: ["SWT3"],
            path: "Tests/SWT3Tests"
        ),
    ]
)
