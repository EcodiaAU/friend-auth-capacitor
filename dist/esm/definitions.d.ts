export interface FriendSignInOptions {
  supabaseUrl: string;
  anonKey: string;
  provider?: string;
  redirectScheme: string;
}
export interface FriendSession {
  accessToken: string;
  refreshToken: string;
}
export interface FriendAuthPlugin {
  signIn(options: FriendSignInOptions): Promise<FriendSession>;
}
