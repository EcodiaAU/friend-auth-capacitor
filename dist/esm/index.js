import { registerPlugin } from '@capacitor/core';
const FriendAuth = registerPlugin('FriendAuth', {
    web: () => import('./web').then((m) => new m.FriendAuthWeb()),
});
export * from './definitions';
export * from './connect';
export { FriendAuth };
