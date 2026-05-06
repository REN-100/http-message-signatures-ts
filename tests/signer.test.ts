/**
 * Tests for HTTP Message Signatures — Signer, Verifier, Serialization
 * 
 * End-to-end round-trip tests using Ed25519 and ECDSA-P256.
 * Validates RFC 9421 compliance for signature base construction,
 * Content-Digest (RFC 9530), and GNAP convenience functions.
 */

import { generateKeyPairSync } from 'crypto';
import {
  createSigner,
  createVerifier,
  signRequest,
  verifySignature,
  createGnapSigner,
  signGnapRequest,
  buildSignatureBase,
  resolveComponent,
  generateContentDigest,
  verifyContentDigest,
  serializeSignatureInput,
  parseSignatureInput,
} from '../src';

// ═══════════════════ Key Generation Helpers ═══════════════════

function generateEd25519Keys() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function generateEcdsaP256Keys() {
  return generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ═══════════════════ Serialization Tests ═══════════════════

describe('Signature-Input Serialization', () => {
  test('serializeSignatureInput produces correct format', () => {
    const result = serializeSignatureInput('sig', ['@method', '@target-uri'], {
      created: 1618884473,
      keyid: 'test-key',
      alg: 'ed25519',
    });

    expect(result).toBe(
      'sig=("@method" "@target-uri");created=1618884473;alg="ed25519";keyid="test-key"'
    );
  });

  test('parseSignatureInput round-trips correctly', () => {
    const original = 'sig=("@method" "@target-uri" "content-type");created=1618884473;keyid="test-key";alg="ed25519"';
    const { label, coveredComponents, params } = parseSignatureInput(original);

    expect(label).toBe('sig');
    expect(coveredComponents).toEqual(['@method', '@target-uri', 'content-type']);
    expect(params.created).toBe(1618884473);
    expect(params.keyid).toBe('test-key');
    expect(params.alg).toBe('ed25519');
  });

  test('parseSignatureInput handles all parameters', () => {
    const input = 'sig1=("@method");created=100;expires=200;nonce="abc";alg="ed25519";keyid="k1";tag="gnap"';
    const { label, coveredComponents, params } = parseSignatureInput(input);

    expect(label).toBe('sig1');
    expect(coveredComponents).toEqual(['@method']);
    expect(params).toEqual({
      created: 100,
      expires: 200,
      nonce: 'abc',
      alg: 'ed25519',
      keyid: 'k1',
      tag: 'gnap',
    });
  });

  test('parseSignatureInput throws on invalid input', () => {
    expect(() => parseSignatureInput('invalid')).toThrow();
  });
});

// ═══════════════════ Component Resolution Tests ═══════════════════

describe('Component Identifier Resolution', () => {
  const context = {
    method: 'POST',
    url: 'https://wallet.example.com/payments?status=active',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP token123',
    },
  };

  test('@method resolves to uppercase method', () => {
    expect(resolveComponent('@method', context)).toBe('POST');
  });

  test('@target-uri resolves to full URL', () => {
    expect(resolveComponent('@target-uri', context)).toBe(
      'https://wallet.example.com/payments?status=active'
    );
  });

  test('@authority resolves to host', () => {
    expect(resolveComponent('@authority', context)).toBe('wallet.example.com');
  });

  test('@scheme resolves to protocol', () => {
    expect(resolveComponent('@scheme', context)).toBe('https');
  });

  test('@path resolves to pathname', () => {
    expect(resolveComponent('@path', context)).toBe('/payments');
  });

  test('@query resolves to search string', () => {
    expect(resolveComponent('@query', context)).toBe('?status=active');
  });

  test('header component resolves case-insensitively', () => {
    expect(resolveComponent('content-type', context)).toBe('application/json');
    expect(resolveComponent('authorization', context)).toBe('GNAP token123');
  });

  test('missing component returns undefined', () => {
    expect(resolveComponent('x-nonexistent', context)).toBeUndefined();
  });
});

// ═══════════════════ Signature Base Tests ═══════════════════

describe('Signature Base Construction', () => {
  test('builds correct base string', () => {
    const base = buildSignatureBase(
      ['@method', '@target-uri', 'content-type'],
      { created: 1618884473, keyid: 'test-key', alg: 'ed25519' },
      {
        method: 'POST',
        url: 'https://example.com/resource',
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const lines = base.split('\n');
    expect(lines[0]).toBe('"@method": POST');
    expect(lines[1]).toBe('"@target-uri": https://example.com/resource');
    expect(lines[2]).toBe('"content-type": application/json');
    expect(lines[3]).toContain('"@signature-params":');
    expect(lines[3]).toContain('created=1618884473');
    expect(lines[3]).toContain('keyid="test-key"');
  });
});

// ═══════════════════ Content-Digest Tests ═══════════════════

describe('Content-Digest (RFC 9530)', () => {
  const body = '{"hello":"world"}';

  test('generateContentDigest produces valid sha-256 format', () => {
    const digest = generateContentDigest(body, 'sha-256');
    expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
  });

  test('generateContentDigest produces valid sha-512 format', () => {
    const digest = generateContentDigest(body, 'sha-512');
    expect(digest).toMatch(/^sha-512=:[A-Za-z0-9+/=]+:$/);
  });

  test('verifyContentDigest returns true for valid digest', () => {
    const digest = generateContentDigest(body);
    expect(verifyContentDigest(body, digest)).toBe(true);
  });

  test('verifyContentDigest returns false for tampered body', () => {
    const digest = generateContentDigest(body);
    expect(verifyContentDigest('{"hello":"tampered"}', digest)).toBe(false);
  });

  test('verifyContentDigest throws on malformed header', () => {
    expect(() => verifyContentDigest(body, 'invalid')).toThrow();
  });
});

// ═══════════════════ Ed25519 Sign/Verify Round-Trip ═══════════════════

describe('Ed25519 Sign + Verify', () => {
  const { publicKey, privateKey } = generateEd25519Keys();
  const signer = createSigner({ keyId: 'ed25519-key-1', algorithm: 'ed25519', privateKey });
  const verifier = createVerifier({ keyId: 'ed25519-key-1', algorithm: 'ed25519', publicKey });

  test('signs a GET request and verifies it', async () => {
    const method = 'GET';
    const url = 'https://wallet.example.com/balances';
    const headers: Record<string, string> = {};

    const signed = await signRequest({
      method,
      url,
      headers,
      signer,
      coveredComponents: ['@method', '@target-uri'],
    });

    expect(signed.Signature).toMatch(/^sig=:/);
    expect(signed['Signature-Input']).toContain('"@method"');
    expect(signed['Content-Digest']).toBeUndefined();

    // Merge signed headers and verify
    const allHeaders = { ...headers, ...signed };
    const valid = await verifySignature({ method, url, headers: allHeaders, verifier });
    expect(valid).toBe(true);
  });

  test('signs a POST request with body and verifies it', async () => {
    const method = 'POST';
    const url = 'https://wallet.example.com/incoming-payments';
    const body = JSON.stringify({ walletAddress: 'https://wallet.example.com/alice', incomingAmount: { value: '1000', assetCode: 'USD', assetScale: 2 } });
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };

    const signed = await signRequest({
      method,
      url,
      headers,
      body,
      signer,
      coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
      includeContentDigest: true,
    });

    expect(signed['Content-Digest']).toMatch(/^sha-256=:/);

    const allHeaders = { ...headers, ...signed };
    const valid = await verifySignature({ method, url, headers: allHeaders, body, verifier });
    expect(valid).toBe(true);
  });

  test('verification fails with wrong key', async () => {
    const { publicKey: wrongPub } = generateEd25519Keys();
    const wrongVerifier = createVerifier({ keyId: 'wrong', algorithm: 'ed25519', publicKey: wrongPub });

    const signed = await signRequest({
      method: 'GET',
      url: 'https://example.com',
      headers: {},
      signer,
      coveredComponents: ['@method', '@target-uri'],
    });

    const valid = await verifySignature({
      method: 'GET',
      url: 'https://example.com',
      headers: { ...signed },
      verifier: wrongVerifier,
    });
    expect(valid).toBe(false);
  });

  test('verification fails with tampered body', async () => {
    const method = 'POST';
    const url = 'https://example.com/resource';
    const body = '{"amount":"100"}';

    const signed = await signRequest({
      method,
      url,
      headers: { 'Content-Type': 'application/json' },
      body,
      signer,
      coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
      includeContentDigest: true,
    });

    const allHeaders = { 'Content-Type': 'application/json', ...signed };
    const valid = await verifySignature({
      method,
      url,
      headers: allHeaders,
      body: '{"amount":"999"}', // tampered
      verifier,
    });
    expect(valid).toBe(false);
  });

  test('verification rejects expired signature', async () => {
    const signed = await signRequest({
      method: 'GET',
      url: 'https://example.com',
      headers: {},
      signer,
      coveredComponents: ['@method', '@target-uri'],
      created: Math.floor(Date.now() / 1000) - 600, // 10 minutes ago
    });

    const valid = await verifySignature({
      method: 'GET',
      url: 'https://example.com',
      headers: { ...signed },
      verifier,
      maxAge: 300, // 5 minutes
    });
    expect(valid).toBe(false);
  });
});

// ═══════════════════ ECDSA-P256 Sign/Verify ═══════════════════

describe('ECDSA-P256 Sign + Verify', () => {
  const { publicKey, privateKey } = generateEcdsaP256Keys();
  const signer = createSigner({ keyId: 'ecdsa-key-1', algorithm: 'ecdsa-p256-sha256', privateKey });
  const verifier = createVerifier({ keyId: 'ecdsa-key-1', algorithm: 'ecdsa-p256-sha256', publicKey });

  test('round-trip sign and verify with ECDSA-P256', async () => {
    const method = 'POST';
    const url = 'https://wallet.example.com/outgoing-payments';
    const body = '{"quoteId":"https://wallet.example.com/quotes/abc"}';
    const headers = { 'Content-Type': 'application/json' };

    const signed = await signRequest({
      method,
      url,
      headers,
      body,
      signer,
      coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
      includeContentDigest: true,
    });

    const allHeaders = { ...headers, ...signed };
    const valid = await verifySignature({ method, url, headers: allHeaders, body, verifier });
    expect(valid).toBe(true);
  });
});

// ═══════════════════ GNAP Convenience Functions ═══════════════════

describe('GNAP Profile', () => {
  const { publicKey, privateKey } = generateEd25519Keys();

  test('createGnapSigner defaults to ed25519', () => {
    const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });
    expect(signer.keyId).toBe('gnap-client');
    expect(signer.algorithm).toBe('ed25519');
  });

  test('signGnapRequest auto-selects covered components for POST', async () => {
    const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });
    const verifier = createVerifier({ keyId: 'gnap-client', algorithm: 'ed25519', publicKey });

    const body = JSON.stringify({ access_token: { access: [{ type: 'incoming-payment' }] } });
    const signed = await signGnapRequest({
      method: 'POST',
      url: 'https://auth.wallet.example.com/',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'GNAP token123',
      },
      body,
      signer,
    });

    expect(signed['Signature-Input']).toContain('"@method"');
    expect(signed['Signature-Input']).toContain('"@target-uri"');
    expect(signed['Signature-Input']).toContain('"authorization"');
    expect(signed['Signature-Input']).toContain('"content-type"');
    expect(signed['Signature-Input']).toContain('"content-digest"');
    expect(signed['Signature-Input']).toContain('tag="gnap"');
    expect(signed['Content-Digest']).toBeDefined();

    // Verify the full signed request
    const allHeaders = {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP token123',
      ...signed,
    };
    const valid = await verifySignature({
      method: 'POST',
      url: 'https://auth.wallet.example.com/',
      headers: allHeaders,
      body,
      verifier,
    });
    expect(valid).toBe(true);
  });

  test('signGnapRequest skips body components for GET', async () => {
    const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });

    const signed = await signGnapRequest({
      method: 'GET',
      url: 'https://wallet.example.com/incoming-payments',
      headers: { 'Authorization': 'GNAP token456' },
      signer,
    });

    expect(signed['Signature-Input']).toContain('"authorization"');
    expect(signed['Signature-Input']).not.toContain('"content-digest"');
    expect(signed['Content-Digest']).toBeUndefined();
  });
});
