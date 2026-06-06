import crypto from 'crypto';
import { AuthConfig } from '../types/index.js';

export type GoogleOAuthConfig = NonNullable<NonNullable<AuthConfig['oauth']>['google']>;

interface GoogleTokenResponse {
    access_token?: string
    error_description?: string
}

export interface GoogleOAuthProfile {
    sub: string
    email: string
    email_verified?: boolean
    name?: string
}

export function createOAuthState() {
    return crypto.randomUUID();
}

export function createGoogleOAuthUrl(googleConfig: GoogleOAuthConfig, state: string) {
    const params = new URLSearchParams({
        client_id: googleConfig.clientId,
        redirect_uri: googleConfig.callbackUrl,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'offline',
        prompt: 'consent',
        state
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

export async function getGoogleOAuthProfile(googleConfig: GoogleOAuthConfig, code: string) {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            client_id: googleConfig.clientId,
            client_secret: googleConfig.clientSecret,
            redirect_uri: googleConfig.callbackUrl,
            grant_type: 'authorization_code'
        })
    });

    const tokenData = await tokenResponse.json() as GoogleTokenResponse;
    if (!tokenResponse.ok || !tokenData.access_token) {
        throw new Error(tokenData.error_description ?? 'Google OAuth token exchange failed');
    }

    const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const profile = await profileResponse.json() as Partial<GoogleOAuthProfile>;
    if (!profileResponse.ok || !profile.sub || !profile.email) {
        throw new Error('Failed to fetch Google profile');
    }

    if (profile.email_verified !== true) {
        throw new Error('Google account email is not verified');
    }
    return profile as GoogleOAuthProfile;
}
