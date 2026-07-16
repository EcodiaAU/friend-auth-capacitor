package au.ecodia.friendauth;

import android.content.Context;
import android.net.Uri;
import android.util.Base64;

import androidx.browser.customtabs.CustomTabsIntent;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Capacitor-free native Friend SSO core (Android). Runs the OAuth 2.1 + PKCE flow
 * against the consuming app's own Supabase project: generate the verifier/challenge
 * locally, open the authorize endpoint (provider=custom:friend) in a Chrome Custom
 * Tab, catch the app-scheme redirect, and exchange the code at
 * token?grant_type=pkce with the verifier we hold. Tokens are handed to the caller;
 * the caller owns setSession. The SDK convenience path cannot carry a custom
 * provider and never seeds the verifier, so the exchange must be self-managed.
 *
 * This class has NO Capacitor imports, so pure-native (Kotlin/Compose) apps can use
 * the exact same login code the Capacitor plugin uses (the plugin delegates here).
 * The Android web-auth handshake spans two Activity lifecycle events (launch the
 * Custom Tab, then catch the redirect in onNewIntent), so the flow is exposed as a
 * begin ({@link #signIn}) plus a redirect handoff ({@link #handleRedirect}) rather
 * than a single blocking call, which is the faithful Android mirror of the iOS
 * async {@code FriendAuth.signIn}. Ported from locals-android AuthRepo. Doctrine:
 * supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
 *
 * The host app MUST route the redirect scheme to its Activity via an intent-filter
 * (e.g. au.ecodia.studio://auth/callback) with launchMode singleTask so onNewIntent
 * fires, then forward that intent's data Uri to {@link #handleRedirect}.
 */
public final class FriendAuthCore {

    /** Result of the login. Fired on a background thread (do UI work on the main thread). */
    public interface Callback {
        void onSuccess(String accessToken, String refreshToken);
        void onError(String message);
    }

    private String pendingVerifier;
    private String tokenBase;
    private String anonKey;
    private String scheme;
    private Callback callback;

    /**
     * Generate PKCE, build the authorize URL, and open it in a Chrome Custom Tab.
     * State + callback are held until {@link #handleRedirect} delivers the redirect.
     *
     * @param ctx              any Android Context (used to launch the Custom Tab).
     * @param authorizeBaseUrl base the authorize endpoint is built from
     *                         ({@code <authorizeBaseUrl>/auth/v1/authorize}).
     * @param tokenBaseUrl     base the token exchange is POSTed to
     *                         ({@code <tokenBaseUrl>/auth/v1/token?grant_type=pkce}).
     * @param anonKey          the project's public anon key (sent as {@code apikey}).
     * @param provider         GoTrue provider id; null defaults to {@code custom:friend}.
     * @param redirectScheme   the app's registered URL scheme; the redirect is
     *                         {@code <redirectScheme>://auth/callback}.
     * @param cb               fired with the tokens (or an error) once the redirect
     *                         is handled.
     */
    public void signIn(Context ctx, String authorizeBaseUrl, String tokenBaseUrl,
                       String anonKey, String provider, String redirectScheme, Callback cb) {
        String prov = (provider == null || provider.isEmpty()) ? "custom:friend" : provider;
        String verifier = makeCodeVerifier();
        this.pendingVerifier = verifier;
        this.tokenBase = trimTrailingSlash(tokenBaseUrl);
        this.anonKey = anonKey;
        this.scheme = redirectScheme;
        this.callback = cb;

        String challenge = codeChallenge(verifier);
        String authorize = Uri.parse(trimTrailingSlash(authorizeBaseUrl) + "/auth/v1/authorize").buildUpon()
                .appendQueryParameter("provider", prov)
                .appendQueryParameter("redirect_to", redirectScheme + "://auth/callback")
                .appendQueryParameter("code_challenge", challenge)
                .appendQueryParameter("code_challenge_method", "s256")
                .build().toString();

        CustomTabsIntent intent = new CustomTabsIntent.Builder().build();
        intent.intent.setFlags(0);
        intent.launchUrl(ctx, Uri.parse(authorize));
    }

    /**
     * Forward the app-scheme redirect Uri (from the host Activity's onNewIntent).
     * No-ops unless the scheme matches and a sign-in is pending. Runs the token
     * exchange on a background thread and fires the callback exactly once.
     */
    public void handleRedirect(Uri data) {
        if (data == null || scheme == null || !scheme.equals(data.getScheme())) {
            return;
        }
        final Callback cb = callback;
        final String verifier = pendingVerifier;
        if (cb == null || verifier == null) {
            return;
        }
        new Thread(() -> {
            try {
                String err = callbackError(data);
                if (err != null) throw new IllegalStateException(err);
                String code = data.getQueryParameter("code");
                if (code == null || code.isEmpty()) {
                    throw new IllegalStateException("Sign-in did not return an authorization code.");
                }
                String[] tokens = exchangeCode(code, verifier);
                cb.onSuccess(tokens[0], tokens[1]);
            } catch (Throwable t) {
                String msg = t.getMessage();
                cb.onError(msg != null ? msg : "Sign-in could not complete.");
            } finally {
                clearPending();
            }
        }).start();
    }

    private void clearPending() {
        pendingVerifier = null;
        callback = null;
    }

    // ---- token exchange -----------------------------------------------------

    private String[] exchangeCode(String code, String verifier) throws Exception {
        URL url = new URL(tokenBase + "/auth/v1/token?grant_type=pkce");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(30_000);
        conn.setReadTimeout(30_000);
        conn.setDoOutput(true);
        conn.setRequestProperty("apikey", anonKey);
        conn.setRequestProperty("Content-Type", "application/json");

        JSONObject payload = new JSONObject();
        payload.put("auth_code", code);
        payload.put("code_verifier", verifier);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        String body = readStream(status >= 200 && status < 300 ? conn.getInputStream() : conn.getErrorStream());
        conn.disconnect();

        if (status < 200 || status >= 300) {
            throw new IllegalStateException(readableGoTrueError(body, status));
        }
        JSONObject obj = new JSONObject(body);
        String access = obj.optString("access_token", "");
        String refresh = obj.optString("refresh_token", "");
        if (access.isEmpty() || refresh.isEmpty()) {
            throw new IllegalStateException("Sign-in did not return a session.");
        }
        return new String[]{access, refresh};
    }

    private static String readStream(java.io.InputStream in) throws Exception {
        if (in == null) return "";
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return out.toString("UTF-8");
    }

    // ---- PKCE helpers (self-managed; mirror the iOS reference exactly) -------

    private static String makeCodeVerifier() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return base64Url(bytes);
    }

    private static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return base64Url(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING);
    }

    private static String callbackError(Uri uri) {
        String desc = uri.getQueryParameter("error_description");
        if (desc != null && !desc.trim().isEmpty()) return desc.replace('+', ' ');
        return uri.getQueryParameter("error");
    }

    private static String readableGoTrueError(String body, int status) {
        String fallback = "Sign-in could not complete (error " + status + ").";
        try {
            JSONObject o = new JSONObject(body);
            String m = o.optString("error_description", null);
            if (m == null) m = o.optString("msg", null);
            if (m == null) m = o.optString("message", null);
            if (m == null) m = o.optString("error", null);
            return m != null ? m : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    private static String trimTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
