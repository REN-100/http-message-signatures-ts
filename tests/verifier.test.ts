/**
 * Tests for Signature Verification — RFC 9421 §3.2
 *
 * Includes dedicated verification scenarios:
 * - Round-trip with Ed25519, ECDSA-P256, ECDSA-P384, RSA-PSS-SHA512
 * - Wrong-key rejection
 * - Tampered body detection
 * - Expired signature rejection
 * - Missing headers rejection
 */

import { generateKeyPairSync } from 'crypto';
import {
  createSigner,
  createVerifier,
  signRequest,
  verifySignature,
  generateContentDigest,
  verifyContentDigest,
} from '../src';

// ─── Key Helpers ─────────────────────────────────────────

function ed25519Keys() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function ecdsaP256Keys() {
  return generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function ecdsaP384Keys() {
  return generateKeyPairSync('ec', {
    namedCurve: 'P-384',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function rsaPssKeys() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ─── Content-Digest Tests ────────────────────────────────

describe('Content-Digest (RFC 9530)', () => {
  const body = '{"hello":"world"}';

  test('sha-256 format is correct', () => {
    expect(generateContentDigest(body, 'sha-256')).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
  });

  test('sha-512 format is correct', () => {
    expect(generateContentDigest(body, 'sha-512')).toMatch(/^sha-512=:[A-Za-z0-9+/=]+:$/);
  });

  test('valid digest verifies', () => {
    expect(verifyContentDigest(body, generateContentDigest(body))).toBe(true);
  });

  test('tampered body fails verification', () => {
    expect(verifyContentDigest('tampered', generateContentDigest(body))).toBe(false);
  });

  test('malformed digest throws', () => {
    expect(() => verifyContentDigest(body, 'invalid')).toThrow();
  });

  test('Buffer body produces same digest as string', () => {
    const strDigest = generateContentDigest(body);
    const bufDigest = generateContentDigest(Buffer.from(body, 'utf-8'));
    expect(strDigest).toBe(bufDigest);
  });
});

// ─── Ed25519 Verification ────────────────────────────────

describe('Ed25519 Verification', () => {
  const { publicKey, privateKey } = ed25519Keys();
  const signer = createSigner({ keyId: 'ed-key', algorithm: 'ed25519', privateKey });
  const verifier = createVerifier({ keyId: 'ed-key', algorithm: 'ed25519', publicKey });

  test('GET request round-trip', async () => {
    const signed = await signRequest({
      method: 'GET', url: 'https://example.com/api', headers: {},
      signer, coveredComponents: ['@method', '@target-uri'],
    });
    const valid = await verifySignature({
      method: 'GET', url: 'https://example.com/api',
      headers: { ...signed }, verifier,
    });
    expect(valid).toBe(true);
  });

  test('POST with body round-trip', async () => {
    const body = '{"amount":"1000"}';
    const headers = { 'Content-Type': 'application/json' };
    const signed = await signRequest({
      method: 'POST', url: 'https://example.com/pay',
      headers, body, signer,
      coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
      includeContentDigest: true,
    });
    const valid = await verifySignature({
      method: 'POST', url: 'https://example.com/pay',
      headers: { ...headers, ...signed }, body, verifier,
    });
    expect(valid).toBe(true);
  });

  test('wrong key rejects', async () => {
    const { publicKey: wrong } = ed25519Keys();
    const wrongVerifier = createVerifier({ keyId: 'x', algorithm: 'ed25519', publicKey: wrong });
    const signed = await signRequest({
      method: 'GET', url: 'https://example.com', headers: {},
      signer, coveredComponents: ['@method'],
    });
    expect(await verifySignature({
      method: 'GET', url: 'https://example.com',
      headers: { ...signed }, verifier: wrongVerifier,
    })).toBe(false);
  });

  test('tampered body rejects', async () => {
    const body = '{"ok":true}';
    const signed = await signRequest({
      method: 'POST', url: 'https://example.com',
      headers: { 'Content-Type': 'application/json' }, body, signer,
      coveredComponents: ['@method', 'content-digest'],
      includeContentDigest: true,
    });
    expect(await verifySignature({
      method: 'POST', url: 'https://example.com',
      headers: { 'Content-Type': 'application/json', ...signed },
      body: '{"ok":false}', verifier,
    })).toBe(false);
  });

  test('expired signature rejects with maxAge', async () => {
    const signed = await signRequest({
      method: 'GET', url: 'https://example.com', headers: {},
      signer, coveredComponents: ['@method'],
      created: Math.floor(Date.now() / 1000) - 600,
    });
    expect(await verifySignature({
      method: 'GET', url: 'https://example.com',
      headers: { ...signed }, verifier, maxAge: 300,
    })).toBe(false);
  });

  test('missing Signature header returns false', async () => {
    expect(await verifySignature({
      method: 'GET', url: 'https://example.com',
      headers: {}, verifier,
    })).toBe(false);
  });
});

// ─── ECDSA-P256 Verification ─────────────────────────────

describe('ECDSA-P256 Verification', () => {
  const { publicKey, privateKey } = ecdsaP256Keys();
  const signer = createSigner({ keyId: 'ec256', algorithm: 'ecdsa-p256-sha256', privateKey });
  const verifier = createVerifier({ keyId: 'ec256', algorithm: 'ecdsa-p256-sha256', publicKey });

  test('POST round-trip', async () => {
    const body = '{"tx":"abc"}';
    const signed = await signRequest({
      method: 'POST', url: 'https://example.com/tx',
      headers: { 'Content-Type': 'application/json' }, body, signer,
      coveredComponents: ['@method', '@target-uri', 'content-digest'],
      includeContentDigest: true,
    });
    expect(await verifySignature({
      method: 'POST', url: 'https://example.com/tx',
      headers: { 'Content-Type': 'application/json', ...signed }, body, verifier,
    })).toBe(true);
  });
});

// ─── ECDSA-P384 Verification ─────────────────────────────

describe('ECDSA-P384 Verification', () => {
  const { publicKey, privateKey } = ecdsaP384Keys();
  const signer = createSigner({ keyId: 'ec384', algorithm: 'ecdsa-p384-sha384', privateKey });
  const verifier = createVerifier({ keyId: 'ec384', algorithm: 'ecdsa-p384-sha384', publicKey });

  test('GET round-trip', async () => {
    const signed = await signRequest({
      method: 'GET', url: 'https://example.com/resource', headers: {},
      signer, coveredComponents: ['@method', '@target-uri'],
    });
    expect(await verifySignature({
      method: 'GET', url: 'https://example.com/resource',
      headers: { ...signed }, verifier,
    })).toBe(true);
  });
});

// ─── RSA-PSS-SHA512 Verification ─────────────────────────

describe('RSA-PSS-SHA512 Verification', () => {
  const { publicKey, privateKey } = rsaPssKeys();
  const signer = createSigner({ keyId: 'rsa-key', algorithm: 'rsa-pss-sha512', privateKey });
  const verifier = createVerifier({ keyId: 'rsa-key', algorithm: 'rsa-pss-sha512', publicKey });

  test('POST with body round-trip', async () => {
    const body = '{"legacy":true}';
    const signed = await signRequest({
      method: 'POST', url: 'https://example.com/legacy',
      headers: { 'Content-Type': 'application/json' }, body, signer,
      coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
      includeContentDigest: true,
    });
    expect(await verifySignature({
      method: 'POST', url: 'https://example.com/legacy',
      headers: { 'Content-Type': 'application/json', ...signed }, body, verifier,
    })).toBe(true);
  });
});
