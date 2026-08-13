package au.ecodia.friendauth;

import android.content.Intent;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Capacitor bridge for native Friend SSO (Android). The OAuth 2.1 + PKCE flow
 * itself lives in the Capacitor-free {@link FriendAuthCore} (so pure-native Kotlin
 * apps share the exact same login code); this class only manages the Capacitor
 * PluginCall lifecycle and forwards the Custom Tab redirect from onNewIntent to the
 * core. Doctrine: supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06.
 *
 * The host app MUST route the redirect scheme to its MainActivity via an
 * intent-filter (e.g. au.ecodia.studio://auth/callback) with launchMode singleTask
 * so onNewIntent (and thus handleOnNewIntent) fires.
 */
@CapacitorPlugin(name = "FriendAuth")
public class FriendAuthPlugin extends Plugin {

    private final FriendAuthCore core = new FriendAuthCore();
    private PluginCall savedCall;
    // Closing the Custom Tab without completing (Back / swipe away) fires NO redirect, so the
    // core never calls back and the promise would hang forever. We watch the Activity resume:
    // if we come back to the app with a sign-in still pending and no redirect was seen, the
    // person cancelled - reject with a stable code the JS side swallows silently.
    private boolean awaitingRedirect = false;
    private boolean redirectSeen = false;

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

        this.savedCall = call;
        this.awaitingRedirect = true;
        this.redirectSeen = false;
        call.setKeepAlive(true);
        bridge.saveCall(call);

        // The single supabaseUrl is used as BOTH the authorize and token base,
        // preserving current behavior; the core keeps them separate so a pure-native
        // app can point them at different hosts if it ever needs to.
        core.signIn(getContext(), url, url, key, provider, sc, new FriendAuthCore.Callback() {
            @Override
            public void onSuccess(String accessToken, String refreshToken) {
                JSObject ret = new JSObject();
                ret.put("accessToken", accessToken);
                ret.put("refreshToken", refreshToken);
                call.resolve(ret);
                release();
            }

            @Override
            public void onError(String message) {
                call.reject(message);
                release();
            }
        });
    }

    @Override
    protected void handleOnNewIntent(Intent intent) {
        super.handleOnNewIntent(intent);
        if (intent.getData() != null) redirectSeen = true;
        core.handleRedirect(intent.getData());
    }

    @Override
    protected void handleOnResume() {
        super.handleOnResume();
        if (!awaitingRedirect || savedCall == null) return;
        // A redirect (onNewIntent) can land just after onResume, so give it a beat before
        // deciding this was a cancel. If a redirect was seen, the core is already completing
        // the sign-in (token exchange may still be running) - leave it alone.
        final PluginCall call = savedCall;
        bridge.getActivity().getWindow().getDecorView().postDelayed(() -> {
            if (awaitingRedirect && !redirectSeen && savedCall == call) {
                awaitingRedirect = false;
                call.reject("Sign-in cancelled.", "SIGN_IN_CANCELLED");
                release();
            }
        }, 700);
    }

    private void release() {
        awaitingRedirect = false;
        if (savedCall != null) {
            bridge.releaseCall(savedCall);
            savedCall = null;
        }
    }
}
