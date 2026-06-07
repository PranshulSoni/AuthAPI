import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAuthRouter } from '../dist/routes/auth.routes.js';
import { createJsonApp, FakePool, FakeRedis, withServer } from './test-helpers.js';

const jwtSecret = 'test-secret';
const accessTokenExpiry = '15m';

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

test('register route validates required fields', async () => {
  const app = createJsonApp(createAuthRouter(new FakePool(), jwtSecret, accessTokenExpiry));

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'user@example.com' })
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'Email, password and username are required');
  });
});

test('register route rejects whitespace-only and invalid email input', async () => {
  const app = createJsonApp(createAuthRouter(new FakePool(), jwtSecret, accessTokenExpiry));

  await withServer(app, async (baseUrl) => {
    const whitespaceResponse = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: '   ', password: 'Password123!', username: 'Pranshul' })
    });
    const whitespaceBody = await whitespaceResponse.json();

    assert.equal(whitespaceResponse.status, 400);
    assert.equal(whitespaceBody.error, 'Invalid Email');

    const invalidEmailResponse = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'h@x.com', password: 'Password123!', username: 'Pranshul' })
    });
    const invalidEmailBody = await invalidEmailResponse.json();

    assert.equal(invalidEmailResponse.status, 400);
    assert.equal(invalidEmailBody.error, 'Invalid Email');
  });
});

test('register route sends verification URL from configured apiBaseUrl, not Host header', async () => {
  const originalFetch = globalThis.fetch;
  let resendBody;
  globalThis.fetch = async (_url, options) => {
    resendBody = JSON.parse(options.body);
    return new Response('{}', { status: 200 });
  };

  try {
    const app = createJsonApp(createAuthRouter(
      new FakePool(),
      jwtSecret,
      accessTokenExpiry,
      { provider: 'resend', apiKey: 'test-key', from: 'noreply@example.com' },
      undefined,
      undefined,
      undefined,
      { apiBaseUrl: 'https://api.example.com', frontendBaseUrl: 'https://app.example.com' }
    ));

    await withServer(app, async (baseUrl) => {
      const response = await originalFetch(`${baseUrl}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: 'evil.example.com'
        },
        body: JSON.stringify({
          email: 'user@example.com',
          password: 'Password123!',
          username: 'Pranshul'
        })
      });

      assert.equal(response.status, 201);
    });

    assert.match(resendBody.html, /https:\/\/api\.example\.com\/auth\/verify-email\?token=/);
    assert.doesNotMatch(resendBody.html, /evil\.example\.com/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('forgot-password route uses frontendBaseUrl for reset links', async () => {
  const pool = new FakePool();
  await pool.query('INSERT INTO auth_users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *', [
    'Pranshul',
    'user@example.com',
    'hashed-password',
    'user'
  ]);

  const originalFetch = globalThis.fetch;
  let resendBody;
  globalThis.fetch = async (_url, options) => {
    resendBody = JSON.parse(options.body);
    return new Response('{}', { status: 200 });
  };

  try {
    const app = createJsonApp(createAuthRouter(
      pool,
      jwtSecret,
      accessTokenExpiry,
      { provider: 'resend', apiKey: 'test-key', from: 'noreply@example.com' },
      undefined,
      undefined,
      undefined,
      { apiBaseUrl: 'https://api.example.com', frontendBaseUrl: 'https://app.example.com' }
    ));

    await withServer(app, async (baseUrl) => {
      const response = await originalFetch(`${baseUrl}/auth/forgot-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: 'evil.example.com'
        },
        body: JSON.stringify({ email: 'user@example.com' })
      });

      assert.equal(response.status, 200);
    });

    assert.match(resendBody.html, /https:\/\/app\.example\.com\/reset-password\?token=/);
    assert.doesNotMatch(resendBody.html, /evil\.example\.com/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('verify-email route verifies a valid token and rejects invalid token', async () => {
  const pool = new FakePool();
  const user = await pool.query('INSERT INTO auth_users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *', [
    'Pranshul',
    'user@example.com',
    'hashed-password',
    'user'
  ]);
  const token = 'verify-token';
  await pool.query('UPDATE auth_users SET email_verification_token=$1, email_verification_expires_at=$2 WHERE id=$3 RETURNING *', [
    hashToken(token),
    new Date(Date.now() + 60_000),
    user.rows[0].id
  ]);

  const app = createJsonApp(createAuthRouter(pool, jwtSecret, accessTokenExpiry));

  await withServer(app, async (baseUrl) => {
    const invalidResponse = await fetch(`${baseUrl}/auth/verify-email?token=bad-token`);
    assert.equal(invalidResponse.status, 400);

    const validResponse = await fetch(`${baseUrl}/auth/verify-email?token=${token}`);
    const body = await validResponse.json();
    assert.equal(validResponse.status, 200);
    assert.equal(body.user.is_verified, true);
    assert.equal('password' in body.user, false);
  });
});

test('oauth google route redirects and stores state in Redis', async () => {
  const redis = new FakeRedis();
  const app = createJsonApp(createAuthRouter(
    new FakePool(),
    jwtSecret,
    accessTokenExpiry,
    undefined,
    undefined,
    {
      google: {
        clientId: 'client-id',
        clientSecret: 'client-secret',
        callbackUrl: 'https://api.example.com/auth/oauth/google/callback'
      }
    },
    redis
  ));

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/oauth/google`, { redirect: 'manual' });
    const location = response.headers.get('location');
    const redirectUrl = new URL(location);
    const state = redirectUrl.searchParams.get('state');

    assert.equal(response.status, 302);
    assert.equal(redirectUrl.origin, 'https://accounts.google.com');
    assert.equal(redirectUrl.searchParams.get('client_id'), 'client-id');
    assert.equal(await redis.get(`oauth_state:${state}`), 'true');
  });
});

test('oauth callback rejects invalid state before calling Google', async () => {
  const originalFetch = globalThis.fetch;
  let googleWasCalled = false;
  globalThis.fetch = async () => {
    googleWasCalled = true;
    return new Response('{}', { status: 500 });
  };

  try {
    const app = createJsonApp(createAuthRouter(
      new FakePool(),
      jwtSecret,
      accessTokenExpiry,
      undefined,
      undefined,
      {
        google: {
          clientId: 'client-id',
          clientSecret: 'client-secret',
          callbackUrl: 'https://api.example.com/auth/oauth/google/callback'
        }
      },
      new FakeRedis()
    ));

    await withServer(app, async (baseUrl) => {
      const response = await originalFetch(`${baseUrl}/auth/oauth/google/callback?state=bad&code=code`);
      const body = await response.json();

      assert.equal(response.status, 400);
      assert.equal(body.error, 'Invalid OAuth State');
      assert.equal(googleWasCalled, false);
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('oauth callback exchanges code, deletes state, and returns AuthAPI tokens', async () => {
  const pool = new FakePool();
  const redis = new FakeRedis();
  await redis.set('oauth_state:valid-state', 'true');

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'google-access-token' }), { status: 200 });
    }

    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      return new Response(JSON.stringify({
        sub: 'google-123',
        email: 'oauth@example.com',
        email_verified: true,
        name: 'OAuth User'
      }), { status: 200 });
    }

    throw new Error(`Unexpected fetch URL: ${url}`);
  };

  try {
    const app = createJsonApp(createAuthRouter(
      pool,
      jwtSecret,
      accessTokenExpiry,
      undefined,
      undefined,
      {
        google: {
          clientId: 'client-id',
          clientSecret: 'client-secret',
          callbackUrl: 'https://api.example.com/auth/oauth/google/callback'
        }
      },
      redis
    ));

    await withServer(app, async (baseUrl) => {
      const response = await originalFetch(`${baseUrl}/auth/oauth/google/callback?state=valid-state&code=code`);
      const body = await response.json();

      assert.equal(response.status, 200);
      assert.equal(body.user.email, 'oauth@example.com');
      assert.equal(typeof body.tokens.accessToken, 'string');
      assert.equal(typeof body.tokens.refreshToken, 'string');
      assert.equal(await redis.get('oauth_state:valid-state'), null);
      assert.equal(pool.authAccounts.length, 1);
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
