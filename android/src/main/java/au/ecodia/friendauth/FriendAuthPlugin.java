package au.ecodia.friendauth;

import android.content.Intent;
import android.net.Uri;
import android.util.Base64;

import androidx.browser.customtabs.CustomTabsIntent;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Native Friend SSO for Capacitor apps (Android). Runs the OAuth 2.1 + PKCE flow
 * against the consuming app's own Supabase project: generate the verifier/challenge
 * locally, open the authorize endpoint (provider=custom:friend) in a Chrome Custom
 * Tab, catch the app-scheme redirect in handleOnNewIntent, and exchange the code at
 * token?grant_type=pkce with the verifier we hold. Tokens are returned to JS; the
 * web layer owns setSession. Ported from locals-android AuthRepo. The SDK
 * convenience path cannot carry a custom provider and never seeds the verifier, so
 * the exchange must be self-managed. Doctrine:
 * supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
 *
 * The host app MUST route the redirect scheme to its MainActivity via an
 * intent-filter (e.g. au.ecodia.studio://auth/callback) with launchMode singleTask
 * so onNewIntent (and thus handleOnNewIntent) fires.
 */
@CapacitorPlugin(name = "FriendAuth")
public class FriendAuthPlugin extends Plugin {

    private PluginCall savedCall;
    private String pendingVerifier;
    private String supabaseBase;
    private String anonKey;
    private String scheme;

    @PluginMethod
    public void signIn(PluginCall call) {
        String url = call.getString("supabaseUrl");
        String key = call.getString("anonKey");
        String sc = call.getString("redirectScheme");
        if (url == null || key == null || sc == null) {
            call.reject("Missing supabaseUrl, anonKey, or redirectScheme.");
            return;
        }
        String provider = call.getString("provider", "custom:friend");

        String verifier = makeCodeVerifier();
        this.pendingVerifier = verifier;
        this.supabaseBase = trimTrailingSlash(url);
        this.anonKey = key;
        this.scheme = sc;
        this.savedCall = call;
        call.setKeepAlive(true);
        bridge.saveCall(call);

        String challenge = codeChallenge(verifier);
        String authorize = Uri.parse(supabaseBase + "/auth/v1/authorize").buildUpon()
                .appendQueryParameter("provider", provider)
                .appendQueryParameter("redirect_to", sc + "://auth/callback")
                .appendQueryParameter("code_challenge", challenge)
                .appendQueryParameter("code_challenge_method", "s256")
                .build().toString();

        CustomTabsIntent intent = new CustomTabsIntent.Builder().build();
        intent.intent.setFlags(0);
        intent.launchUrl(getContext(), Uri.parse(authorize));
    }

    @Override
    protected void handleOnNewIntent(Intent intent) {
        super.handleOnNewIntent(intent);
        Uri data = intent.getData();
        if (data == null || scheme == null || !scheme.equals(data.getScheme())) {
            return;
        }
        final PluginCall call = savedCall;
        final String verifier = pendingVerifier;
        if (call == null || verifier == null) {
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
                JSObject ret = new JSObject();
                ret.put("accessToken", tokens[0]);
                ret.put("refreshToken", tokens[1]);
                call.resolve(ret);
            } catch (Throwable t) {
                String msg = t.getMessage();
                call.reject(msg != null ? msg : "Sign-in could not complete.");
            } finally {
                clearPending();
            }
        }).start();
    }

    private void clearPending() {
        if (savedCall != null) {
            bridge.releaseCall(savedCall);
        }
        savedCall = null;
        pendingVerifier = null;
    }

    // ---- token exchange -----------------------------------------------------

    private String[] exchangeCode(String code, String verifier) throws Exception {
        URL url = new URL(supabaseBase + "/auth/v1/token?grant_type=pkce");
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
