import { WebPlugin } from '@capacitor/core';
import type { FriendAuthPlugin, FriendSession } from './definitions';
export declare class FriendAuthWeb extends WebPlugin implements FriendAuthPlugin {
    signIn(): Promise<FriendSession>;
}
