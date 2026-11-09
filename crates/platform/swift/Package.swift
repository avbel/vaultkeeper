// swift-tools-version:5.9
import PackageDescription

let package = Package(
  name: "VkPlatform",
  platforms: [.macOS(.v13)],
  products: [
    .library(name: "VkPlatform", type: .static, targets: ["VkPlatform"])
  ],
  targets: [
    .target(name: "VkPlatform", path: "Sources/VkPlatform")
  ]
)
