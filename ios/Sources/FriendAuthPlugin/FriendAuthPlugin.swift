import Foundation
import Capacitor
#if canImport(EcodiaFriendAuthCore)
import EcodiaFriendAuthCore
#endif

/// Capacitor bridge for native Friend SSO. The OAuth 2.1 + PKCE flow itself lives
/// in the Capacitor-free `EcodiaFriendAuthCore` target (so pure-native apps share
/// the exact same login code); this class only translates the JS `signIn` call
/// into a `FriendAuth.signIn` invocation and resolves the promise with the tokens.
///
/// Under SPM the core is a separate module and `canImport(EcodiaFriendAuthCore)`
/// is true. Under CocoaPods the podspec globs all of `ios/Sources` into one module,
/// so `FriendAuth` is in-module and the import is unnecessary (canImport false).
/// Doctrine: supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
@objc(FriendAuthPlugin)
public class FriendAuthPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "FriendAuthPlugin"
    public let jsName = "FriendAuth"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "signIn", returnType: CAPPluginReturnPromise)
    ]

    @objc func signIn(_ call: CAPPluginCall) {
        guard let urlString = call.getString("supabaseUrl"),
              let supabaseURL = URL(string: urlString),
              let anonKey = call.getString("anonKey"),
              let redirectScheme = call.getString("redirectScheme") else {
            call.reject("Missing supabaseUrl, anonKey, or redirectScheme.")
            return
        }
        let provider = call.getString("provider") ?? "custom:friend"

        // The existing single supabaseUrl is used as BOTH the authorize and token
        // base, preserving current behavior; the core keeps them separate so a
        // pure-native app can point them at different hosts if it ever needs to.
        Task {
            do {
                let tokens = try await FriendAuth.signIn(
                    authorizeBaseURL: supabaseURL,
                    tokenBaseURL: supabaseURL,
                    anonKey: anonKey,
                    provider: provider,
                    redirectScheme: redirectScheme
                )
                call.resolve([
                    "accessToken": tokens.accessToken,
                    "refreshToken": tokens.refreshToken
                ])
            } catch {
                call.reject(error.localizedDescription)
            }
        }
    }
}
