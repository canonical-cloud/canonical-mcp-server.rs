import assert from 'node:assert/strict';
import test from 'node:test';
import { isNavigationHostAllowed, isSafeMethod, validateTarget } from './readiness-audit.mjs';

test('only idempotent browser methods are allowed', () => {
  for (const method of ['GET', 'HEAD', 'OPTIONS']) assert.equal(isSafeMethod(method), true);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'TRACE']) assert.equal(isSafeMethod(method), false);
});

test('provider navigation cannot cross account-console boundaries', () => {
  assert.equal(isNavigationHostAllowed('aws', 'console.aws.amazon.com'), true);
  assert.equal(isNavigationHostAllowed('aws', 'us-east-1.console.aws.amazon.com'), true);
  assert.equal(isNavigationHostAllowed('aws', 'portal.azure.com'), false);
  assert.throws(() => validateTarget('github', 'https://example.com/'));
  assert.throws(() => validateTarget('github', 'http://github.com/'));
});

test('all twelve providers have a valid default console target', () => {
  for (const provider of [
    'aws', 'gcp', 'azure', 'cloudflare', 'github', 'upstash', 'vercel',
    'digital-ocean', 'netlify', 'render', 'fly-io', 'heroku',
  ]) {
    const target = validateTarget(provider);
    assert.equal(target.protocol, 'https:');
  }
});
