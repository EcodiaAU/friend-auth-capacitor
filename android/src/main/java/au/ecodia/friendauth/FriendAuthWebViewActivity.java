package au.ecodia.friendauth;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;

/**
 * Runs the Friend OAuth authorize flow inside an in-app WebView and hands the
 * app-scheme redirect back to the caller.
 *
 * Why this exists: the Custom Tab flow (FriendAuthCore.signIn) cannot reliably
 * return to the app when the OAuth redirect crosses domains (federated Friend
 * SSO: studio project -> friend.ecodia.au -> studio project -> app scheme).
 * Chrome blocks the redirect-driven app-scheme intent launch and falls back to a
 * full browser tab, which cannot resolve a custom scheme (NXDOMAIN), so the
 * promise hangs and the reviewer sees a dead "Opening Friend..." button.
 *
 * A WebView's {@link WebViewClient#shouldOverrideUrlLoading} fires for EVERY
 * navigation - including a server 302 to the custom scheme - so the redirect is
 * always caught, with no Chrome / App Links / Digital Asset Links dependency.
 * The whole exchange stays a first-party flow against Ecodia's own Friend IdP,
 * which is review-acceptable (unlike a third-party IdP in a WebView).
 *
 * Contract:
 *  - EXTRA_AUTHORIZE_URL: the authorize URL (FriendAuthCore.prepare).
 *  - EXTRA_REDIRECT_SCHEME: the app's registered scheme (e.g. au.ecodia.studio);
 *    the first navigation whose scheme matches is captured and returned.
 *  - result RESULT_OK with EXTRA_CALLBACK_URL set on capture; RESULT_CANCELED if
 *    the person backs out.
 */
public final class FriendAuthWebViewActivity extends Activity {

    public static final String EXTRA_AUTHORIZE_URL = "au.ecodia.friendauth.AUTHORIZE_URL";
    public static final String EXTRA_REDIRECT_SCHEME = "au.ecodia.friendauth.REDIRECT_SCHEME";
    public static final String EXTRA_CALLBACK_URL = "au.ecodia.friendauth.CALLBACK_URL";

    private WebView webView;
    private String redirectScheme;
    private boolean finished = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String authorizeUrl = getIntent().getStringExtra(EXTRA_AUTHORIZE_URL);
        redirectScheme = getIntent().getStringExtra(EXTRA_REDIRECT_SCHEME);
        if (authorizeUrl == null || redirectScheme == null) {
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        FrameLayout root = new FrameLayout(this);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.setBackgroundColor(Color.WHITE);

        webView = new WebView(this);
        webView.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        // A real UA so the IdP login page renders its normal mobile layout.
        settings.setUserAgentString(settings.getUserAgentString() + " FriendAuthWebView");

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(webView, true);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return handleUrl(request.getUrl());
            }

            @Override
            @SuppressWarnings("deprecation")
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return handleUrl(Uri.parse(url));
            }
        });

        root.addView(webView);
        setContentView(root);
        webView.loadUrl(authorizeUrl);
    }

    /** Capture the app-scheme redirect; let every other navigation load in-WebView. */
    private boolean handleUrl(Uri uri) {
        if (uri != null && redirectScheme.equals(uri.getScheme())) {
            if (!finished) {
                finished = true;
                Intent data = new Intent();
                data.putExtra(EXTRA_CALLBACK_URL, uri.toString());
                setResult(RESULT_OK, data);
                finish();
            }
            return true; // do not try to load the custom scheme in the WebView
        }
        return false; // http(s) navigations (authorize, Friend login) load normally
    }

    @Override
    public void onBackPressed() {
        // Backing out is a cancel, not a failure (mirrors the Custom Tab / ASWebAuth cancel).
        if (!finished) {
            finished = true;
            setResult(RESULT_CANCELED);
        }
        finish();
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.stopLoading();
            webView.setWebViewClient(null);
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
