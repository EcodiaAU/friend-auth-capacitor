import Foundation
import Capacitor
import AuthenticationServices
import CryptoKit

/// Native Friend SSO for Capacitor apps. Runs the OAuth 2.1 + PKCE flow against
/// the consuming app's own Supabase project: the SDK convenience path cannot
/// carry a `custom:` provider and never seeds the code-verifier on that path
/// (the exchange then fails on an empty verifier), so we self-manage the pair.
/// We build the authorize URL by hand, present it in an ASWebAuthenticationSession
/// (Apple's native secure OAuth surface, review-accepted), catch the app-scheme
/// redirect, and exchange the code at `token?grant_type=pkce` with the verifier we
/// hold locally. The tokens are returned to JS; the web layer owns setSession so
/// the session cookie lands in the WKWebView. Ported from the proven Glovebox iOS
/// signInWithFriend (glovebox-ios AuthService.swift). Doctrine:
/// supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
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
        let redirectTo = "\(redirectScheme)://auth/callback"

        Task { @MainActor in
            do {
                let verifier = FriendAuthPlugin.makeCodeVerifier()
                let challenge = FriendAuthPlugin.codeChallenge(for: verifier)

                guard var comps = URLComponents(
                    url: supabaseURL.appendingPathComponent("auth/v1/authorize"),
                    resolvingAgainstBaseURL: false
                ) else {
                    call.reject("Could not build the sign-in URL.")
                    return
                }
                comps.queryItems = [
                    URLQueryItem(name: "provider", value: provider),
                    URLQueryItem(name: "redirect_to", value: redirectTo),
                    URLQueryItem(name: "code_challenge", value: challenge),
                    URLQueryItem(name: "code_challenge_method", value: "s256")
                ]
                guard let authorizeURL = comps.url else {
                    call.reject("Could not build the sign-in URL.")
                    return
                }

                let callback = try await FriendAuthPlugin.presentWebAuth(
                    url: authorizeURL, callbackScheme: redirectScheme
                )
                if let message = FriendAuthPlugin.callbackError(from: callback) {
                    call.reject(message)
                    return
                }
                guard let code = FriendAuthPlugin.authCode(from: callback) else {
                    call.reject("Sign-in did not return an authorization code.")
                    return
                }

                let tokens = try await FriendAuthPlugin.exchangeCode(
                    code, verifier: verifier, supabaseURL: supabaseURL, anonKey: anonKey
                )
                call.resolve([
                    "accessToken": tokens.access,
                    "refreshToken": tokens.refresh
                ])
            } catch let error as FriendAuthError {
                call.reject(error.message)
            } catch {
                call.reject(error.localizedDescription)
            }
        }
    }

    // MARK: token exchange

    private static func exchangeCode(
        _ code: String, verifier: String, supabaseURL: URL, anonKey: String
    ) async throws -> (access: String, refresh: String) {
        guard var comps = URLComponents(
            url: supabaseURL.appendingPathComponent("auth/v1/token"),
            resolvingAgainstBaseURL: false
        ) else { throw FriendAuthError("Could not build the token URL.") }
        comps.queryItems = [URLQueryItem(name: "grant_type", value: "pkce")]
        guard let tokenURL = comps.url else { throw FriendAuthError("Could not build the token URL.") }

        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue(anonKey, forHTTPHeaderField: "apikey")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["auth_code": code, "code_verifier": verifier]
        )
        request.timeoutInterval = 30

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FriendAuthError("Unexpected response from the server.")
        }
        guard (200...299).contains(http.statusCode) else {
            let message = FriendAuthPlugin.readableError(from: data)
                ?? "Sign-in could not complete (error \(http.statusCode))."
            throw FriendAuthError(message)
        }
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = obj["access_token"] as? String, !access.isEmpty,
              let refresh = obj["refresh_token"] as? String, !refresh.isEmpty else {
            throw FriendAuthError("Sign-in did not return a session.")
        }
        return (access, refresh)
    }

    // MARK: PKCE helpers (self-managed; the exchange never depends on SDK storage)

    static func makeCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 64)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            bytes = (0..<64).map { _ in UInt8.random(in: 0...255) }
        }
        return Data(bytes).friendBase64URLEncoded()
    }

    static func codeChallenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).friendBase64URLEncoded()
    }

    /// Read the `code` from a PKCE redirect (query first, fragment as a fallback).
    static func authCode(from url: URL) -> String? {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        if let code = comps.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty {
            return code
        }
        if let fragment = comps.fragment {
            for pair in fragment.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2, kv[0] == "code", !kv[1].isEmpty {
                    return String(kv[1]).removingPercentEncoding ?? String(kv[1])
                }
            }
        }
        return nil
    }

    /// Surface a GoTrue error carried back on the redirect (`?error_description`).
    static func callbackError(from url: URL) -> String? {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let items = comps.queryItems ?? []
        if let desc = items.first(where: { $0.name == "error_description" })?.value {
            return desc.replacingOccurrences(of: "+", with: " ")
        }
        return items.first(where: { $0.name == "error" })?.value
    }

    private static func readableError(from data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return (obj["error_description"] as? String)
            ?? (obj["message"] as? String)
            ?? (obj["msg"] as? String)
            ?? (obj["error"] as? String)
    }

    /// Present the OAuth authorize URL in an ASWebAuthenticationSession and
    /// resolve with the custom-scheme callback URL.
    @MainActor
    static func presentWebAuth(url: URL, callbackScheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let contextProvider = FriendWebAuthPresentationContext()
            let webSession = ASWebAuthenticationSession(
                url: url, callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let callbackURL {
                    continuation.resume(returning: callbackURL)
                } else {
                    continuation.resume(throwing: FriendAuthError("Sign-in did not complete."))
                }
                _ = contextProvider
            }
            webSession.presentationContextProvider = contextProvider
            webSession.prefersEphemeralWebBrowserSession = false
            webSession.start()
        }
    }
}

private struct FriendAuthError: Error {
    let message: String
    init(_ message: String) { self.message = message }
}

private extension Data {
    /// Base64URL (RFC 4648 s5) without padding, as PKCE requires.
    func friendBase64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Anchors the ASWebAuthenticationSession sheet to the app's foreground window.
private final class FriendWebAuthPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive } ?? UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        return scene?.keyWindow ?? scene?.windows.first ?? ASPresentationAnchor()
    }
}
