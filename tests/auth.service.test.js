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

    // findAuthAccount — two-step OAuth lookup (replaces JOIN)
    if (compactSql.startsWith('SELECT * FROM auth_accounts WHERE provider = $1 AND provider_account_id = $2')) {
      const [provider, providerAccountId] = params;
      const account = this.authAccounts.find(
        (item) => item.provider === provider && item.provider_account_id === providerAccountId
      );
      return { rows: account ? [account] : [], rowCount: account ? 1 : 0 };
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

function makeRepo(pool) {
  return {
    findByEmail: (email) =>
      pool.query('SELECT * FROM auth_users WHERE email = $1', [email]).then((r) => r.rows[0] ?? null),
    findById: (id) =>
      pool.query('SELECT * FROM auth_users WHERE id = $1', [id]).then((r) => r.rows[0] ?? null),
    createUser: (email, password, username, role) =>
      password === null
        ? pool.query('INSERT INTO auth_users (username, email, password, role, is_verified) VALUES ($1, $2, NULL, $3, true) RETURNING *', [username, email, role]).then((r) => r.rows[0])
        : pool.query('INSERT INTO auth_users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *', [username, email, password, role]).then((r) => r.rows[0]),
    setEmailVerificationToken: (userId, tokenHash, expiresAt) =>
      pool.query('UPDATE auth_users SET email_verification_token=$1, email_verification_expires_at=$2 WHERE id=$3 RETURNING *', [tokenHash, expiresAt, userId]).then((r) => r.rows[0] ?? null),
    verifyByEmailToken: (tokenHash) =>
      pool.query('UPDATE auth_users SET is_verified=true, email_verification_token=NULL, email_verification_expires_at=NULL WHERE email_verification_token=$1 AND email_verification_expires_at > NOW() RETURNING *', [tokenHash]).then((r) => r.rows[0] ?? null),
    setPasswordResetToken: (userId, tokenHash, expiresAt) =>
      pool.query('UPDATE auth_users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3 RETURNING *', [tokenHash, expiresAt, userId]).then((r) => r.rows[0] ?? null),
    resetPasswordByToken: (tokenHash, passwordHash) =>
      pool.query('UPDATE auth_users SET password = $1, password_reset_token = NULL, password_reset_expires_at = NULL WHERE password_reset_token = $2 AND password_reset_expires_at > NOW() RETURNING *', [passwordHash, tokenHash]).then((r) => r.rows[0] ?? null),
  };
}

test('registerUser stores a hashed password and returns a sanitized user', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  const user = await registerUser(repo, {
    email: 'user@example.com',
    password: 'Password123!',
    username: 'Pranshul'
  });

  assert.equal(user.email, 'user@example.com');
  assert.equal('password' in user, false);
  assert.notEqual(pool.users[0].password, 'Password123!');
});

test('registerUser normalizes email before storing the user', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  const user = await registerUser(repo, {
    email: '  USER@Example.COM  ',
    password: 'Password123!',
    username: 'Pranshul'
  });

  assert.equal(user.email, 'user@example.com');
  assert.equal(pool.users[0].email, 'user@example.com');
});

test('registerUser rejects whitespace, weak emails, short passwords, and script-like usernames', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  await assert.rejects(
    () => registerUser(repo, { email: '   ', password: 'Password123!', username: 'Pranshul' }),
    /Invalid Email/
  );
  await assert.rejects(
    () => registerUser(repo, { email: 'h@x.com', password: 'Password123!', username: 'Pranshul' }),
    /Invalid Email/
  );
  await assert.rejects(
    () => registerUser(repo, { email: 'user@example.com', password: 'short', username: 'Pranshul' }),
    /Password must be at least 8 characters/
  );
  await assert.rejects(
    () => registerUser(repo, { email: 'user@example.com', password: 'Password123!', username: '<script>alert(1)</script>' }),
    /Username contains invalid characters/
  );
});

test('loginUser returns sanitized user and access/refresh tokens', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  await registerUser(repo, {
    email: 'user@example.com',
    password: 'Password123!',
    username: 'Pranshul'
  });

  const result = await loginUser(repo, pool, { email: 'user@example.com', password: 'Password123!' }, jwtSecret, accessTokenExpiry);

  assert.equal(result.user.email, 'user@example.com');
  assert.equal('password' in result.user, false);
  assert.equal(typeof result.tokens.accessToken, 'string');
  assert.equal(typeof result.tokens.refreshToken, 'string');
  assert.equal(pool.refreshTokens.length, 1);
});

test('loginUser rejects whitespace input before checking credentials', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  await assert.rejects(
    () => loginUser(repo, pool, { email: '   ', password: 'Password123!' }, jwtSecret, accessTokenExpiry),
    /Invalid Email/
  );
  await assert.rejects(
    () => loginUser(repo, pool, { email: 'user@example.com', password: '   ' }, jwtSecret, accessTokenExpiry),
    /Password is required/
  );
});

test('reAuthUser rotates refresh tokens and rejects replay of the old token', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  await registerUser(repo, {
    email: 'user@example.com',
    password: 'Password123!',
    username: 'Pranshul'
  });
  const login = await loginUser(repo, pool, { email: 'user@example.com', password: 'Password123!' }, jwtSecret, accessTokenExpiry);

  const refreshed = await reAuthUser(repo, pool, { refreshToken: login.tokens.refreshToken }, jwtSecret, accessTokenExpiry);

  assert.equal(typeof refreshed.accessToken, 'string');
  assert.equal(typeof refreshed.refreshToken, 'string');
  assert.notEqual(refreshed.refreshToken, login.tokens.refreshToken);
  assert.equal(pool.refreshTokens.length, 1);
  await assert.rejects(
    () => reAuthUser(repo, pool, { refreshToken: login.tokens.refreshToken }, jwtSecret, accessTokenExpiry),
    /Refresh Token Invalid/
  );
});

test('oauthLoginUser links Google account to an existing email user', async () => {
  const pool = new FakePool();
  const repo = makeRepo(pool);

  const existingUser = await registerUser(repo, {
    email: 'user@example.com',
    password: 'Password123!',
    username: 'Pranshul'
  });

  const result = await oauthLoginUser(repo, pool, {
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
  const repo = makeRepo(pool);

  const result = await oauthLoginUser(repo, pool, {
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
  const repo = makeRepo(pool);

  const first = await oauthLoginUser(repo, pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'oauth@example.com',
    username: 'OAuth User'
  }, jwtSecret, accessTokenExpiry);

  const second = await oauthLoginUser(repo, pool, {
    provider: 'google',
    providerAccountId: 'google-123',
    email: 'changed@example.com',
    username: 'Changed Name'
  }, jwtSecret, accessTokenExpiry);

  assert.equal(second.user.id, first.user.id);
  assert.equal(pool.users.length, 1);
  assert.equal(pool.authAccounts.length, 1);
});
