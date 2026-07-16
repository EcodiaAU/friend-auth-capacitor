import Foundation
import AuthenticationServices
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

/// Capacitor-free native Friend SSO core. Runs the OAuth 2.1 + PKCE flow against
/// the consuming app's own Supabase project: the SDK convenience path cannot
/// carry a `custom:` provider and never seeds the code-verifier on that path
/// (the exchange then fails on an empty verifier), so we self-manage the pair.
/// We build the authorize URL by hand, present it in an ASWebAuthenticationSession
/// (Apple's native secure OAuth surface, review-accepted), catch the app-scheme
/// redirect, and exchange the code at `token?grant_type=pkce` with the verifier we
/// hold locally. The tokens are returned to the caller; the caller owns setSession.
///
/// This target has NO Capacitor dependency, so pure-native (SwiftUI/UIKit) apps
/// can `import EcodiaFriendAuthCore` and call `FriendAuth.signIn` with the exact
/// same login code the Capacitor plugin uses (the plugin delegates here). Ported
/// from the proven Glovebox iOS signInWithFriend (glovebox-ios AuthService.swift).
/// Doctrine: supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
public enum FriendAuth {

    /// Run the full Friend login and return the GoTrue session tokens.
    ///
    /// - Parameters:
    ///   - authorizeBaseURL: base URL the authorize endpoint is built from
    ///     (`<authorizeBaseURL>/auth/v1/authorize`); its host is what the user
    ///     sees in the ASWebAuthenticationSession consent sheet.
    ///   - tokenBaseURL: base URL the PKCE token exchange is POSTed to
    ///     (`<tokenBaseURL>/auth/v1/token?grant_type=pkce`).
    ///   - anonKey: the project's public anon key (sent as the `apikey` header).
    ///   - provider: GoTrue provider id, defaults to `custom:friend`.
    ///   - redirectScheme: the app's registered URL scheme; the redirect is
    ///     `<redirectScheme>://auth/callback`.
    /// - Returns: the access + refresh tokens.
    public static func signIn(
        authorizeBaseURL: URL,
        tokenBaseURL: URL,
        anonKey: String,
        provider: String = "custom:friend",
        redirectScheme: String
    ) async throws -> (accessToken: String, refreshToken: String) {
        let redirectTo = "\(redirectScheme)://auth/callback"
        let verifier = makeCodeVerifier()
        let challenge = codeChallenge(for: verifier)

        guard var comps = URLComponents(
            url: authorizeBaseURL.appendingPathComponent("auth/v1/authorize"),
            resolvingAgainstBaseURL: false
        ) else {
            throw FriendAuthError("Could not build the sign-in URL.")
        }
        comps.queryItems = [
            URLQueryItem(name: "provider", value: provider),
            URLQueryItem(name: "redirect_to", value: redirectTo),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "s256")
        ]
        guard let authorizeURL = comps.url else {
            throw FriendAuthError("Could not build the sign-in URL.")
        }

        let callback = try await presentWebAuth(url: authorizeURL, callbackScheme: redirectScheme)
        if let message = callbackError(from: callback) {
            throw FriendAuthError(message)
        }
        guard let code = authCode(from: callback) else {
            throw FriendAuthError("Sign-in did not return an authorization code.")
        }

        return try await exchangeCode(
            code, verifier: verifier, tokenBaseURL: tokenBaseURL, anonKey: anonKey
        )
    }

    // MARK: token exchange

    static func exchangeCode(
        _ code: String, verifier: String, tokenBaseURL: URL, anonKey: String
    ) async throws -> (accessToken: String, refreshToken: String) {
        guard var comps = URLComponents(
            url: tokenBaseURL.appendingPathComponent("auth/v1/token"),
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
            let message = readableError(from: data)
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

    static func readableError(from data: Data) -> String? {
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

/// Carries a human-readable message; conforms to LocalizedError so a delegating
/// caller can surface it via `error.localizedDescription` without knowing the type.
struct FriendAuthError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
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
        #if canImport(UIKit)
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive } ?? UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        return scene?.keyWindow ?? scene?.windows.first ?? ASPresentationAnchor()
        #else
        return ASPresentationAnchor()
        #endif
    }
}
