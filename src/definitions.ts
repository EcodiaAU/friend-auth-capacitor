export interface FriendSignInOptions {
  /** The consuming app's own Supabase project URL, e.g. https://xxxx.supabase.co */
  supabaseUrl: string;
  /** That project's public anon key (RLS-protected, safe on the client). */
  anonKey: string;
  /** The GoTrue provider id. Defaults to "custom:friend". */
  provider?: string;
  /** The app's registered URL scheme, e.g. "au.ecodia.studio". The redirect is
   *  built as "<redirectScheme>://auth/callback" and MUST be on the project's
   *  auth redirect allow-list and registered as a native URL scheme. */
  redirectScheme: string;
}

export interface FriendSession {
  accessToken: string;
  refreshToken: string;
}

export interface FriendAuthPlugin {
  /**
   * Run the OAuth 2.1 + PKCE Friend login natively: open the authorize URL in
   * the system browser (ASWebAuthenticationSession on iOS, Chrome Custom Tabs on
   * Android), catch the app-scheme redirect, and exchange the code for a session
   * at the project's token endpoint with a locally-held verifier. Returns the
   * GoTrue access + refresh tokens; the caller establishes the session
   * (setSession on the web client, so the cookie is set for the webview).
   */
  signIn(options: FriendSignInOptions): Promise<FriendSession>;
}
