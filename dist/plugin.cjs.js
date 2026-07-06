'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var core = require('@capacitor/core');

const FriendAuth = core.registerPlugin('FriendAuth', {
    web: () => Promise.resolve().then(function () { return web; }).then((m) => new m.FriendAuthWeb()),
});

class FriendAuthWeb extends core.WebPlugin {
    async signIn() {
        throw this.unavailable('Native Friend sign-in runs only on iOS and Android. On the web, use the browser OAuth redirect (signInWithOAuth).');
    }
}

var web = /*#__PURE__*/Object.freeze({
    __proto__: null,
    FriendAuthWeb: FriendAuthWeb
});

exports.FriendAuth = FriendAuth;
exports.FriendAuthWeb = FriendAuthWeb;
