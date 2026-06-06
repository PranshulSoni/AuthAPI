import test from 'node:test';
import assert from 'node:assert/strict';
import {
  loginUser,
  oauthLoginUser,
  reAuthUser,
  registerUser
} from '../dist/services/auth.service.js';

const jwtSecret = 'test-secret';
const accessTokenExpiry = '15m';

class FakePool {
  constructor() {
    this.users = [];
    this.refreshTokens = [];
    this.authAccounts = [];
  }

  async query(sql, params = []) {
    const compactSql = sql.replace(/\s+/g, ' ').trim();

    if (compactSql.startsWith('SELECT * FROM auth_users WHERE email = $1')) {
      return { rows: this.users.filter((user) => user.email === params[0]), rowCount: 1 };
    }

    if (compactSql.startsWith('SELECT * FROM auth_users WHERE id = $1')) {
      return { rows: this.users.filter((user) => user.id === params[0]), rowCount: 1 };
    }

    if (compactSql.startsWith('INSERT INTO auth_users (username, email, password, role)')) {
      const [username, email, password, role] = params;
      const user = {
        id: `user-${this.users.length + 1}`,
        username,
        email,
        password,
        role,
        is_verified: false
      };
      this.users.push(user);
      return { rows: [user], rowCount: 1 };
    }

    if (compactSql.startsWith('INSERT INTO auth_users (username, email, password, role, is_verified)')) {
      const [username, email, role] = params;
      const user = {
        id: `user-${this.users.length + 1}`,
        username,
        email,
        password: null,
        role,
        is_verified: true
      };
      this.users.push(user);
      return { rows: [user], rowCount: 1 };
    }

    if (compactSql.startsWith('INSERT INTO auth_token')) {
      const [userId, refreshTokenHash, expiresAt] = params;
      this.refreshTokens.push({ user_id: userId, refresh_token_hash: refreshTokenHash, expires_at: expiresAt });
      return { rows: [], rowCount: 1 };
    }

    if (compactSql.startsWith('DELETE FROM auth_token WHERE refresh_token_hash=$1 AND expires_at > NOW() RETURNING user_id')) {
      const index = this.refreshTokens.findIndex(
        (token) => token.refresh_token_hash === params[0] && token.expires_at > new Date()
      );
      if (index === -1) return { rows: [], rowCount: 0 };
      const [token] = this.refreshTokens.splice(index, 1);
      return { rows: [{ user_id: token.user_id }], rowCount: 1 };
    }

    if (compactSql.startsWith('SELECT auth_users.* FROM auth_accounts JOIN auth_users')) {
      const [provider, providerAccountId] = params;
      const account = this.authAccounts.find(
        (item) => item.provider === provider && item.provider_account_id === providerAccountId
      );
      const user = account ? this.users.find((item) => item.id === account.user_id) : null;
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    }

    if (compactSql.startsWith('INSERT INTO auth_accounts')) {
      const [userId, provider, providerAccountId, email] = params;
      const account = {
        id: `account-${this.authAccounts.length + 1}`,
        user_id: userId,
        provider,
        provider_account_id: providerAccountId,
        email
      };
      this.authAccounts.push(account);
      return { rows: [account], rowCount: 1 };
    }

    throw new Error(`Unhandled query in test fake: ${compactSql}`);
  }
}

test('registerUser stores a hashed password and returns a sanitized user', async () => {
  const pool = new FakePool();

  const user = await registerUser(pool, {
    email: 'user@example.com',
    password: 'password123',
    username: 'Pranshul'
  });

  assert.equal(user.email, 'user@example.com');
  assert.equal('password' in user, false);
  assert.notEqual(pool.users[0].password, 'password123');
});

test('loginUser returns sanitized user and access/refresh tokens', async () => {
  const pool = new FakePool();
  await registerUser(pool, {
    email: 'user@example.com',
    password: 'password123',
    username: 'Pranshul'
  });

  const result = await loginUser(pool, { email: 'user@example.com', password: 'password123' }, jwtSecret, accessTokenExpiry);

  assert.equal(result.user.email, 'user@example.com');
  assert.equal('password' in result.user, false);
  assert.equal(typeof result.tokens.accessToken, 'string');
  assert.equal(typeof result.tokens.refreshToken, 'string');
  assert.equal(pool.refreshTokens.length, 1);
});

test('reAuthUser rotates refresh tokens and rejects replay of the old token', async () => {
  const pool = new FakePool();
  await registerUser(pool, {
    email: 'user@example.com',
    password: 'password123',
    username: 'Pranshul'
  });
  const login = await loginUser(pool, { email: 'user@example.com', password: 'password123' }, jwtSecret, accessTokenExpiry);

  const refreshed = await reAuthUser(pool, { refreshToken: login.tokens.refreshToken }, jwtSecret, accessTokenExpiry);

  assert.equal(typeof refreshed.accessToken, 'string');
  assert.equal(typeof refreshed.refreshToken, 'string');
  assert.notEqual(refreshed.refreshToken, login.tokens.refreshToken);
  assert.equal(pool.refreshTokens.length, 1);
  await assert.rejects(
    () => reAuthUser(pool, { refreshToken: login.tokens.refreshToken }, jwtSecret, accessTokenExpiry),
    /Refresh Token Invalid/
  );
});

test('oauthLoginUser links Google account to an existing email user', async () => {
  const pool = new FakePool();
  const existingUser = await registerUser(pool, {
    email: 'user@example.com',
    password: 'password123',
    username: 'Pranshul'
  });

  const result = await oauthLoginUser(pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'user@example.com',
    username: 'Pranshul Google'
  }, jwtSecret, accessTokenExpiry);

  assert.equal(result.user.id, existingUser.id);
  assert.equal(pool.authAccounts.length, 1);
  assert.equal(pool.authAccounts[0].user_id, existingUser.id);
  assert.equal(typeof result.tokens.accessToken, 'string');
});

test('oauthLoginUser creates an OAuth-only user when no email user exists', async () => {
  const pool = new FakePool();

  const result = await oauthLoginUser(pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'oauth@example.com',
    username: 'OAuth User'
  }, jwtSecret, accessTokenExpiry);

  assert.equal(result.user.email, 'oauth@example.com');
  assert.equal(result.user.is_verified, true);
  assert.equal('password' in result.user, false);
  assert.equal(pool.users[0].password, null);
  assert.equal(pool.authAccounts.length, 1);
});

test('oauthLoginUser reuses an already linked provider account', async () => {
  const pool = new FakePool();

  const first = await oauthLoginUser(pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'oauth@example.com',
    username: 'OAuth User'
  }, jwtSecret, accessTokenExpiry);

  const second = await oauthLoginUser(pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'changed@example.com',
    username: 'Changed Name'
  }, jwtSecret, accessTokenExpiry);

  assert.equal(second.user.id, first.user.id);
  assert.equal(pool.users.length, 1);
  assert.equal(pool.authAccounts.length, 1);
});
