// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "tauri-plugin-decentsecret",
    platforms: [
        .macOS(.v10_13),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "tauri-plugin-decentsecret",
            type: .static,
            targets: ["tauri-plugin-decentsecret"]),
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "tauri-plugin-decentsecret",
            dependencies: [
                .byName(name: "Tauri"),
                .byName(name: "DecentsecretClassification")
            ],
            path: "Sources"),
        // Dependency-free so that it can be unit tested without Tauri or a device.
        .target(
            name: "DecentsecretClassification",
            path: "Classification"),
        // Depends on the classification and nothing else: the tests must not
        // need Tauri, UIKit or a device to run.
        .testTarget(
            name: "DecentsecretClassificationTests",
            dependencies: [.byName(name: "DecentsecretClassification")],
            path: "Tests/ClassificationTests")
    ]
)
