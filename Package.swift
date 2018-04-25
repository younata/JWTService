// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JWTService",
    products: [
        .library(
            name: "JWTService",
            targets: ["JWTService"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "3.0.0-rc"),
        .package(url: "https://github.com/vapor/jwt.git", from: "3.0.0-rc"),

        .package(url: "https://github.com/Quick/Quick.git", .upToNextMajor(from: "1.2.0")),
        .package(url: "https://github.com/Quick/Nimble.git", .upToNextMajor(from: "7.0.0")),

        .package(url: "https://github.com/younata/VaporTestHelpers.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "JWTService",
            dependencies: [
                "Vapor",
                "JWT",
            ]),
        .testTarget(
            name: "JWTServiceTests",
            dependencies: [
                "JWTService",
                "Quick",
                "Nimble",
                "VaporTestHelpers",
            ]),
    ]
)
