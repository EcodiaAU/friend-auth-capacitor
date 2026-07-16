// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EcodiaFriendAuth",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "EcodiaFriendAuth",
            targets: ["FriendAuthPlugin"]),
        // Capacitor-free core: pure-native (SwiftUI/UIKit) apps depend on this
        // product directly and `import EcodiaFriendAuthCore`.
        .library(
            name: "EcodiaFriendAuthCore",
            targets: ["EcodiaFriendAuthCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.0.0")
    ],
    targets: [
        // No Capacitor dependency. The importable module name equals this target
        // name, so consumers `import EcodiaFriendAuthCore`.
        .target(
            name: "EcodiaFriendAuthCore",
            path: "ios/Sources/EcodiaFriendAuthCore"),
        .target(
            name: "FriendAuthPlugin",
            dependencies: [
                "EcodiaFriendAuthCore",
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios/Sources/FriendAuthPlugin")
    ]
)
