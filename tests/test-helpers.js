import express from 'express';
import { createServer } from 'node:http';

export class FakePool {
  constructor() {
    this.users = [];
    this.refreshTokens = [];
    this.authAccounts = [];
    this.emailVerificationTokens = [];
    this.passwordResetTokens = [];
  }

  async query(sql, params = []) {
    const compactSql = sql.replace(/\s+/g, ' ').trim();

    if (compactSql.startsWith('SELECT * FROM auth_users WHERE email = $1')) {
      const rows = this.users.filter((user) => user.email === params[0]);
      return { rows, rowCount: rows.length };
    }

    if (compactSql.startsWith('SELECT * FROM auth_users WHERE id = $1')) {
      const rows = this.users.filter((user) => user.id === params[0]);
      return { rows, rowCount: rows.length };
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

    if (compactSql.startsWith('UPDATE auth_users SET email_verification_token=$1')) {
      const [tokenHash, expiresAt, userId] = params;
      const user = this.users.find((item) => item.id === userId);
      if (!user) return { rows: [], rowCount: 0 };
      user.email_verification_token = tokenHash;
      user.email_verification_expires_at = expiresAt;
      this.emailVerificationTokens.push({ user_id: userId, token_hash: tokenHash, expires_at: expiresAt });
      return { rows: [user], rowCount: 1 };
    }

    if (compactSql.startsWith('UPDATE auth_users SET is_verified=true')) {
      const [tokenHash] = params;
      const user = this.users.find(
        (item) => item.email_verification_token === tokenHash && item.email_verification_expires_at > new Date()
      );
      if (!user) return { rows: [], rowCount: 0 };
      user.is_verified = true;
      user.email_verification_token = null;
      user.email_verification_expires_at = null;
      return { rows: [user], rowCount: 1 };
    }

    if (compactSql.startsWith('UPDATE auth_users SET password_reset_token = $1')) {
      const [tokenHash, expiresAt, userId] = params;
      const user = this.users.find((item) => item.id === userId);
      if (!user) return { rows: [], rowCount: 0 };
      user.password_reset_token = tokenHash;
      user.password_reset_expires_at = expiresAt;
      this.passwordResetTokens.push({ user_id: userId, token_hash: tokenHash, expires_at: expiresAt });
      return { rows: [user], rowCount: 1 };
    }

    if (compactSql.startsWith('UPDATE auth_users SET password = $1')) {
      const [passwordHash, tokenHash] = params;
      const user = this.users.find(
        (item) => item.password_reset_token === tokenHash && item.password_reset_expires_at > new Date()
      );
      if (!user) return { rows: [], rowCount: 0 };
      user.password = passwordHash;
      user.password_reset_token = null;
      user.password_reset_expires_at = null;
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

    if (compactSql.startsWith('DELETE FROM auth_token WHERE refresh_token_hash=$1')) {
      const before = this.refreshTokens.length;
      this.refreshTokens = this.refreshTokens.filter((token) => token.refresh_token_hash !== params[0]);
      return { rows: [], rowCount: before - this.refreshTokens.length };
    }

    if (compactSql.startsWith('DELETE FROM auth_token WHERE user_id=$1')) {
      const before = this.refreshTokens.length;
      this.refreshTokens = this.refreshTokens.filter((token) => token.user_id !== params[0]);
      return { rows: [], rowCount: before - this.refreshTokens.length };
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

    throw new Error(`Unhandled query in fake pool: ${compactSql}`);
  }
}

export class FakeRedis {
  constructor() {
    this.values = new Map();
    this.expirations = new Map();
    this.deleted = [];
  }

  async incr(key) {
    const next = Number(this.values.get(key) ?? 0) + 1;
    this.values.set(key, String(next));
    return next;
  }

  async expire(key, seconds) {
    this.expirations.set(key, seconds);
    return true;
  }

  async set(key, value) {
    this.values.set(key, value);
    return 'OK';
  }

  async get(key) {
    return this.values.get(key) ?? null;
  }

  async del(key) {
    const existed = this.values.delete(key);
    this.deleted.push(key);
    return existed ? 1 : 0;
  }
}

export async function withServer(app, callback) {
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();

  try {
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

export function createJsonApp(router) {
  const app = express();
  app.use(express.json());
  app.use('/auth', router);
  return app;
}
