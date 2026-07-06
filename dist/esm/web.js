import { WebPlugin } from '@capacitor/core';
export class FriendAuthWeb extends WebPlugin {
    async signIn() {
        throw this.unavailable('Native Friend sign-in runs only on iOS and Android. On the web, use the browser OAuth redirect (signInWithOAuth).');
    }
}
