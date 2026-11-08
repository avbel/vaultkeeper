// swift-tools-version:5.9
import PackageDescription

let package = Package(
  name: "BwlPlatform",
  platforms: [.macOS(.v13)],
  products: [
    .library(name: "BwlPlatform", type: .static, targets: ["BwlPlatform"])
  ],
  targets: [
    .target(name: "BwlPlatform", path: "Sources/BwlPlatform")
  ]
)
