export interface FriendSupabaseClient {
    auth: {
        signInWithOAuth(args: {
            provider: string;
            options?: {
                redirectTo?: string;
                skipBrowserRedirect?: boolean;
            };
        }): Promise<{
            error: {
                message: string;
            } | null;
        }>;
        setSession(args: {
            access_token: string;
            refresh_token: string;
        }): Promise<{
            error: {
                message: string;
            } | null;
        }>;
        signOut(): Promise<unknown>;
    };
    rpc(fn: string): Promise<{
        data: unknown;
        error: unknown;
    }>;
}
export interface ConnectFriendOptions {
    supabase: FriendSupabaseClient;
    supabaseUrl: string;
    anonKey: string;
    redirectScheme: string;
    webRedirectTo: string;
    provider?: string;
    reconcile?: boolean;
    onNativeComplete?: () => void;
}
export declare function connectFriend(opts: ConnectFriendOptions): Promise<{
    error: {
        message: string;
    } | null;
}>;
