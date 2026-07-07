# @ecodia/friend-auth

Cross-platform "Connect your Friend" sign-in for every Ecodia app. One
`connectFriend()` call works on the web (the `signInWithOAuth` redirect) and on
native iOS/Android (self-managed PKCE through the system SSO surface), so an app
never branches on platform itself.

Why native needs its own path: the supabase-js convenience flow cannot carry a
`custom:` provider and never seeds the PKCE verifier on that path, so the token
exchange fails on an empty verifier. This package's native plugin builds the
authorize URL by hand, presents it in `ASWebAuthenticationSession` (iOS) /
Chrome Custom Tabs (Android), catches the app-scheme redirect, and exchanges the
code with a locally-held verifier. Doctrine:
`supabase-swift-custom-provider-needs-self-managed-pkce-2026-07-06`.

## Install

```bash
npm install github:EcodiaAU/friend-auth-capacitor
npx cap sync   # native apps only
```

The repo is **public** so Vercel/CI git-dependency installs resolve with no auth
(same pattern as `@ecodia/friend-chat`). `dist/` is committed; no build on install.

## Use (web + native, one call)

```ts
import { connectFriend } from '@ecodia/friend-auth';

const { error } = await connectFriend({
  supabase,                                   // your configured supabase-js client
  supabaseUrl: SUPABASE_URL,
  anonKey: SUPABASE_ANON_KEY,
  redirectScheme: 'au.ecodia.roam',           // this app's native URL scheme
  webRedirectTo: `${origin}/auth/callback?next=/`,
  onNativeComplete: () => window.location.assign('/'),
});
if (error) showError(error.message);
```

- **Web** → starts `signInWithOAuth({ provider: 'custom:friend' })`; the browser
  leaves for the Friend IdP and returns to `webRedirectTo`, where the app's
  `/auth/callback` finishes the exchange.
- **Native** → runs the plugin PKCE flow, `setSession` on your web client (so the
  WKWebView/WebView cookie lands), then a fire-once `friend_reconcile()` relink
  (deny-safe account linking). Pass `reconcile: false` to skip.

## Native wiring (per app, once)

The redirect scheme is per-app, so the intent-filter / URL type lives on the host
app, not this package.

**iOS** - add to `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>au.ecodia.roam</string></array>
  </dict>
</array>
```

**Android** - on the host app's `MainActivity` in `AndroidManifest.xml`, set
`android:launchMode="singleTask"` and add:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="au.ecodia.roam" android:host="auth" />
</intent-filter>
```

**Supabase** - add `au.ecodia.roam://auth/callback` to the project's auth redirect
allow-list (`uri_allow_list`), and ensure the `custom:friend` provider is enabled
with the friend_id copy-forward trigger pair (`patterns/supabase-custom-oidc-app-metadata-clobber-needs-before-trigger-2026-07-06`).

## Exports

- `connectFriend(opts)` - the cross-platform helper above.
- `FriendAuth` - the raw Capacitor plugin (`signIn(options)`), if you need the
  tokens without the reconcile/session plumbing.
- Types: `ConnectFriendOptions`, `FriendSignInOptions`, `FriendSession`.
