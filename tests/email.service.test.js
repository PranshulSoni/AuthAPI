import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sendPasswordResetEmail,
  sendVerificationEmail
} from '../dist/services/email.service.js';

const emailConfig = {
  provider: 'resend',
  apiKey: 'resend-key',
  from: 'noreply@example.com'
};

test('sendVerificationEmail sends expected Resend payload', async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options, body: JSON.parse(options.body) };
    return new Response('{}', { status: 200 });
  };

  try {
    await sendVerificationEmail(emailConfig, 'user@example.com', 'https://api.example.com/auth/verify-email?token=abc');

    assert.equal(request.url, 'https://api.resend.com/emails');
    assert.equal(request.options.method, 'POST');
    assert.equal(request.options.headers.Authorization, 'Bearer resend-key');
    assert.equal(request.body.to, 'user@example.com');
    assert.equal(request.body.subject, 'Verify your email');
    assert.match(request.body.html, /verify-email\?token=abc/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('sendPasswordResetEmail sends expected Resend payload', async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options, body: JSON.parse(options.body) };
    return new Response('{}', { status: 200 });
  };

  try {
    await sendPasswordResetEmail(emailConfig, 'user@example.com', 'https://app.example.com/reset-password?token=abc');

    assert.equal(request.url, 'https://api.resend.com/emails');
    assert.equal(request.body.to, 'user@example.com');
    assert.equal(request.body.subject, 'Reset your password');
    assert.match(request.body.html, /reset-password\?token=abc/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('email service rejects unsupported providers', async () => {
  await assert.rejects(
    () => sendVerificationEmail({ ...emailConfig, provider: 'smtp' }, 'user@example.com', 'https://example.com'),
    /Email provider currently Unsupported/
  );
});

test('email service throws when Resend request fails', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 500 });

  try {
    await assert.rejects(
      () => sendPasswordResetEmail(emailConfig, 'user@example.com', 'https://example.com'),
      /Failed to send password reset email/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
