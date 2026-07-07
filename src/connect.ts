import { Capacitor } from '@capacitor/core';

import { FriendAuth } from './index';

/**
 * The minimal shape of the supabase-js client that connectFriend touches. We type
 * it structurally rather than importing @supabase/supabase-js so the package stays
 * dependency-light and every app can pass its own already-configured client (any
 * supabase-js major that has these methods works).
 */
export interface FriendSupabaseClient {
  auth: {
    signInWithOAuth(args: {
      provider: string;
      options?: { redirectTo?: string; skipBrowserRedirect?: boolean };
    }): Promise<{ error: { message: string } | null }>;
    setSession(args: {
      access_token: string;
      refresh_token: string;
    }): Promise<{ error: { message: string } | null }>;
    signOut(): Promise<unknown>;
  };
  rpc(fn: string): Promise<{ data: unknown; error: unknown }>;
}

export interface ConnectFriendOptions {
  /** The consuming app's configured supabase-js client. */
  supabase: FriendSupabaseClient;
  /** The app's own Supabase project URL (native token exchange needs it). */
  supabaseUrl: string;
  /** That project's public anon key. */
  anonKey: string;
  /**
   * The app's registered native URL scheme, e.g. "au.ecodia.roam". The native
   * redirect is built as "<redirectScheme>://auth/callback"; it must be on the
   * project's auth redirect allow-list AND registered as a native URL scheme
   * (iOS CFBundleURLSchemes, Android intent-filter with launchMode singleTask).
   */
  redirectScheme: string;
  /**
   * The full https callback URL used on the web redirect path, e.g.
   * "https://glovebox.ecodia.au/auth/callback?next=/". On native this is ignored
   * (the system browser returns via redirectScheme instead).
   */
  webRedirectTo: string;
  /** GoTrue provider id. Defaults to "custom:friend". */
  provider?: string;
  /**
   * Call the deny-safe public.friend_reconcile() RPC after the native session
   * lands, to merge a fresh shell into an existing account (the account-linking
   * mechanism every federated app shares). Default true. No-op on web (the
   * server /auth/callback runs reconcile there).
   */
  reconcile?: boolean;
  /**
   * Invoked once the native session is established (and reconciled). Use it to
   * navigate, e.g. () => window.location.assign('/'). Not called on the web path
   * (the browser has already left for the IdP). Optional.
   */
  onNativeComplete?: () => void;
}

/**
 * The one cross-platform Friend sign-in. On native (Capacitor iOS/Android) it runs
 * the self-managed PKCE flow through the FriendAuth plugin (system SSO surface),
 * sets the returned GoTrue session on the web client so the WKWebView/WebView cookie
 * lands, then runs a fire-once friend_reconcile relink. On the web it starts the
 * ordinary signInWithOAuth redirect. Either way the caller gets a uniform
 * { error } and never has to branch on platform itself.
 */
export async function connectFriend(
  opts: ConnectFriendOptions,
): Promise<{ error: { message: string } | null }> {
  const provider = opts.provider ?? 'custom:friend';

  if (Capacitor.isNativePlatform()) {
    try {
      // At most one relink re-run: friend_reconcile can merge this fresh shell
      // into an older account and delete the shell, which invalidates the session
      // we just set. Consent is already granted, so re-running signIn is silent.
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
        if (setErr) return { error: { message: setErr.message } };

        if (reconcile && attempt === 0) {
          try {
            const { data } = await opts.supabase.rpc('friend_reconcile');
            if (data && (data as { linked?: boolean }).linked === true) {
              await opts.supabase.auth.signOut();
              continue; // shell merged away; re-run once with the real account
            }
          } catch {
            // RPC unavailable: keep the session rather than lock the user out.
          }
        }
        break;
      }
      opts.onNativeComplete?.();
      return { error: null };
    } catch (e) {
      return { error: { message: e instanceof Error ? e.message : 'Sign-in did not complete.' } };
    }
  }

  // Web: the ordinary OAuth redirect. The browser leaves for the Friend IdP and
  // returns to webRedirectTo, where the app's /auth/callback finishes the exchange.
  const { error } = await opts.supabase.auth.signInWithOAuth({
    provider,
    options: { redirectTo: opts.webRedirectTo },
  });
  return { error: error ? { message: error.message } : null };
}
