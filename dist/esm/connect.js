import { Capacitor } from '@capacitor/core';
import { FriendAuth } from './index';
/**
 * The one cross-platform Friend sign-in. On native (Capacitor iOS/Android) it runs
 * the self-managed PKCE flow through the FriendAuth plugin (system SSO surface),
 * sets the returned GoTrue session on the web client so the WKWebView/WebView cookie
 * lands, then runs a fire-once friend_reconcile relink. On the web it starts the
 * ordinary signInWithOAuth redirect. Either way the caller gets a uniform
 * { error } and never has to branch on platform itself.
 */
export async function connectFriend(opts) {
    const provider = opts.provider ?? 'custom:friend';
    if (Capacitor.isNativePlatform()) {
        try {
            const reconcile = opts.reconcile !== false;
            for (let attempt = 0; attempt < 2; attempt++) {
                const { accessToken, refreshToken } = await FriendAuth.signIn({
                    supabaseUrl: opts.supabaseUrl,
                    anonKey: opts.anonKey,
                    provider,
                    redirectScheme: opts.redirectScheme,
                });
                const { error: setErr } = await opts.supabase.auth.setSession({
                    access_token: accessToken,
                    refresh_token: refreshToken,
                });
                if (setErr)
                    return { error: { message: setErr.message } };
                if (reconcile && attempt === 0) {
                    try {
                        const { data } = await opts.supabase.rpc('friend_reconcile');
                        if (data && data.linked === true) {
                            await opts.supabase.auth.signOut();
                            continue;
                        }
                    }
                    catch {
                        // RPC unavailable: keep the session rather than lock the user out.
                    }
                }
                break;
            }
            opts.onNativeComplete?.();
            return { error: null };
        }
        catch (e) {
            return { error: { message: e instanceof Error ? e.message : 'Sign-in did not complete.' } };
        }
    }
    const { error } = await opts.supabase.auth.signInWithOAuth({
        provider,
        options: { redirectTo: opts.webRedirectTo },
    });
    return { error: error ? { message: error.message } : null };
}
