import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { checkUser } from '../dist/middlewares/protect.js';
import { requireRole } from '../dist/middlewares/requiredRole.js';
import { requireVerifiedEmail } from '../dist/middlewares/is_verified.js';
import { authRateLimiter } from '../dist/middlewares/ratelimiting.js';
import { FakeRedis, withServer } from './test-helpers.js';

const jwtSecret = 'test-secret';

function createApp(handler) {
  const app = express();
  app.use(express.json());
  handler(app);
  return app;
}

test('checkUser rejects missing and malformed Authorization headers', async () => {
  const app = createApp((appInstance) => {
    appInstance.get('/protected', checkUser(jwtSecret), (_req, res) => res.json({ ok: true }));
  });

  await withServer(app, async (baseUrl) => {
    const missing = await fetch(`${baseUrl}/protected`);
    assert.equal(missing.status, 401);

    const malformed = await fetch(`${baseUrl}/protected`, {
      headers: { Authorization: 'Token abc' }
    });
    assert.equal(malformed.status, 401);
  });
});

test('checkUser accepts valid Bearer token and exposes payload to handlers', async () => {
  const token = jwt.sign({ userId: 'user-1', role: 'admin', isVerified: true }, jwtSecret);
  const app = createApp((appInstance) => {
    appInstance.get('/protected', checkUser(jwtSecret), (req, res) => res.json({ user: req.user }));
  });

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/protected`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.user.userId, 'user-1');
    assert.equal(body.user.role, 'admin');
  });
});

test('requireRole allows matching role and rejects non-matching role', async () => {
  const adminToken = jwt.sign({ userId: 'user-1', role: 'admin', isVerified: true }, jwtSecret);
  const userToken = jwt.sign({ userId: 'user-2', role: 'user', isVerified: true }, jwtSecret);
  const app = createApp((appInstance) => {
    appInstance.get('/admin', checkUser(jwtSecret), requireRole('admin'), (_req, res) => res.json({ ok: true }));
  });

  await withServer(app, async (baseUrl) => {
    const forbidden = await fetch(`${baseUrl}/admin`, {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    assert.equal(forbidden.status, 403);

    const allowed = await fetch(`${baseUrl}/admin`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(allowed.status, 200);
  });
});

test('requireVerifiedEmail rejects unverified users and allows verified users', async () => {
  const unverifiedToken = jwt.sign({ userId: 'user-1', role: 'user', isVerified: false }, jwtSecret);
  const verifiedToken = jwt.sign({ userId: 'user-2', role: 'user', isVerified: true }, jwtSecret);
  const app = createApp((appInstance) => {
    appInstance.get('/verified', checkUser(jwtSecret), requireVerifiedEmail(), (_req, res) => res.json({ ok: true }));
  });

  await withServer(app, async (baseUrl) => {
    const rejected = await fetch(`${baseUrl}/verified`, {
      headers: { Authorization: `Bearer ${unverifiedToken}` }
    });
    assert.equal(rejected.status, 403);

    const accepted = await fetch(`${baseUrl}/verified`, {
      headers: { Authorization: `Bearer ${verifiedToken}` }
    });
    assert.equal(accepted.status, 200);
  });
});

test('authRateLimiter blocks requests after max count in window', async () => {
  const redis = new FakeRedis();
  const app = createApp((appInstance) => {
    appInstance.get('/limited', authRateLimiter(redis, {
      prefix: 'test',
      max: 2,
      windowSeconds: 60
    }), (_req, res) => res.json({ ok: true }));
  });

  await withServer(app, async (baseUrl) => {
    assert.equal((await fetch(`${baseUrl}/limited`)).status, 200);
    assert.equal((await fetch(`${baseUrl}/limited`)).status, 200);

    const blocked = await fetch(`${baseUrl}/limited`);
    const body = await blocked.json();
    assert.equal(blocked.status, 429);
    assert.equal(body.error, 'Too many requests. Please try again later.');
    assert.equal(redis.expirations.get('rate_limit:test:127.0.0.1'), 60);
  });
});
