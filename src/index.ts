import { registerPlugin } from '@capacitor/core';

import type { FriendAuthPlugin } from './definitions';

const FriendAuth = registerPlugin<FriendAuthPlugin>('FriendAuth', {
  web: () => import('./web').then((m) => new m.FriendAuthWeb()),
});

export * from './definitions';
export { FriendAuth };
