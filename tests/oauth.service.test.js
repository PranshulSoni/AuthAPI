import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createGoogleOAuthUrl,
  createOAuthState,
  getGoogleOAuthProfile
} from '../dist/services/oauth.service.js';

const googleConfig = {
  clientId: 'client-id',
  clientSecret: 'client-secret',
  callbackUrl: 'https://api.example.com/auth/oauth/google/callback'
};

test('createOAuthState returns unique non-empty values', () => {
  const first = createOAuthState();
  const second = createOAuthState();

  assert.equal(typeof first, 'string');
  assert.notEqual(first, '');
  assert.notEqual(first, second);
});

test('createGoogleOAuthUrl includes required OAuth parameters', () => {
  const url = new URL(createGoogleOAuthUrl(googleConfig, 'state-123'));

  assert.equal(url.origin, 'https://accounts.google.com');
  assert.equal(url.searchParams.get('client_id'), 'client-id');
  assert.equal(url.searchParams.get('redirect_uri'), googleConfig.callbackUrl);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('scope'), 'openid email profile');
  assert.equal(url.searchParams.get('state'), 'state-123');
});

test('getGoogleOAuthProfile throws on token exchange failure', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error_description: 'bad code' }), { status: 400 });

  try {
    await assert.rejects(
      () => getGoogleOAuthProfile(googleConfig, 'bad-code'),
      /bad code/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('getGoogleOAuthProfile throws when Google profile is missing required fields', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'google-access-token' }), { status: 200 });
    }

    return new Response(JSON.stringify({ email: 'user@example.com', email_verified: true }), { status: 200 });
  };

  try {
    await assert.rejects(
      () => getGoogleOAuthProfile(googleConfig, 'code'),
      /Failed to fetch Google profile/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('getGoogleOAuthProfile rejects unverified emails', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'google-access-token' }), { status: 200 });
    }

    return new Response(JSON.stringify({
      sub: 'google-123',
      email: 'user@example.com',
      email_verified: false,
      name: 'User'
    }), { status: 200 });
  };

  try {
    await assert.rejects(
      () => getGoogleOAuthProfile(googleConfig, 'code'),
      /Google account email is not verified/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('getGoogleOAuthProfile returns verified profile data', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'google-access-token' }), { status: 200 });
    }

    return new Response(JSON.stringify({
      sub: 'google-123',
      email: 'user@example.com',
      email_verified: true,
      name: 'User'
    }), { status: 200 });
  };

  try {
    const profile = await getGoogleOAuthProfile(googleConfig, 'code');

    assert.equal(profile.sub, 'google-123');
    assert.equal(profile.email, 'user@example.com');
    assert.equal(profile.email_verified, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
