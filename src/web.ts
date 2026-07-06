import { WebPlugin } from '@capacitor/core';

import type { FriendAuthPlugin, FriendSession } from './definitions';

export class FriendAuthWeb extends WebPlugin implements FriendAuthPlugin {
  async signIn(): Promise<FriendSession> {
    throw this.unavailable(
      'Native Friend sign-in runs only on iOS and Android. On the web, use the browser OAuth redirect (signInWithOAuth).',
    );
  }
}
