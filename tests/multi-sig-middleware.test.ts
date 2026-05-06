/**
 * Tests for Multi-Signature Support & Middleware — RFC 9421 §4.3
 */

import {
  createSigner,
  createVerifier,
  signRequest,
  verifySignature,
  parseMultipleSignatureInputs,
  serializeSignatureInput,
  createSignatureMiddleware,
  generateKeyPair,
  resolveComponent,
} from '../src';

// ─── Test Fixtures ─────────────────────────────────────────────

const keys1 = generateKeyPair('ed25519');
const keys2 = generateKeyPair('ed25519');

const signer1 = createSigner({ keyId: 'key-1', algorithm: 'ed25519', privateKey: keys1.privateKey });
const signer2 = createSigner({ keyId: 'key-2', algorithm: 'ed25519', privateKey: keys2.privateKey });

const verifier1 = createVerifier({ keyId: 'key-1', algorithm: 'ed25519', publicKey: keys1.publicKey });
const verifier2 = createVerifier({ keyId: 'key-2', algorithm: 'ed25519', publicKey: keys2.publicKey });

// ─── Multi-Signature Tests ─────────────────────────────────────

describe('Multi-Signature Support (RFC 9421 §4.3)', () => {
  test('parseMultipleSignatureInputs parses single signature', () => {
    const input = 'sig=("@method" "@target-uri");created=1000;keyid="key-1"';
    const result = parseMultipleSignatureInputs(input);

    expect(result).toHaveLength(1);
    expect(result[0].label).toBe('sig');
    expect(result[0].coveredComponents).toEqual(['@method', '@target-uri']);
    expect(result[0].params.created).toBe(1000);
  });

  test('parseMultipleSignatureInputs parses two signatures', () => {
    const input = 'sig1=("@method");created=1000, sig2=("@method" "@target-uri");created=2000';
    const result = parseMultipleSignatureInputs(input);

    expect(result).toHaveLength(2);
    expect(result[0].label).toBe('sig1');
    expect(result[0].params.created).toBe(1000);
    expect(result[1].label).toBe('sig2');
    expect(result[1].params.created).toBe(2000);
  });

  test('parseMultipleSignatureInputs handles commas inside quotes', () => {
    const input = 'sig1=("@method");keyid="key,with,commas", sig2=("@path");created=100';
    const result = parseMultipleSignatureInputs(input);

    expect(result).toHaveLength(2);
    expect(result[0].params.keyid).toBe('key,with,commas');
    expect(result[1].label).toBe('sig2');
  });

  test('custom label in signRequest', async () => {
    const signed = await signRequest({
      method: 'GET',
      url: 'https://example.com/',
      headers: {},
      signer: signer1,
      coveredComponents: ['@method'],
      label: 'my-custom-label',
    });

    expect(signed['Signature-Input']).toContain('my-custom-label=(');
    expect(signed['Signature']).toContain('my-custom-label=:');
  });

  test('two signers produce two distinct signatures on the same message', async () => {
    // First signature
    const signed1 = await signRequest({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: { 'Content-Type': 'application/json' },
      body: '{"amount":"100"}',
      signer: signer1,
      coveredComponents: ['@method', '@target-uri', 'content-type'],
      label: 'sig1',
    });

    // Second signature
    const signed2 = await signRequest({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: { 'Content-Type': 'application/json' },
      body: '{"amount":"100"}',
      signer: signer2,
      coveredComponents: ['@method', '@target-uri'],
      label: 'sig2',
    });

    // Combine into a single message (as RFC 9421 §4.3 allows)
    const combinedHeaders = {
      'Content-Type': 'application/json',
      'Signature-Input': `${signed1['Signature-Input']}, ${signed2['Signature-Input']}`,
      'Signature': `${signed1['Signature']}, ${signed2['Signature']}`,
    };

    // Verify sig1 with verifier1
    const valid1 = await verifySignature({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: combinedHeaders,
      body: '{"amount":"100"}',
      verifier: verifier1,
      label: 'sig1',
    });
    expect(valid1).toBe(true);

    // Verify sig2 with verifier2
    const valid2 = await verifySignature({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: combinedHeaders,
      body: '{"amount":"100"}',
      verifier: verifier2,
      label: 'sig2',
    });
    expect(valid2).toBe(true);

    // Wrong verifier for sig1 should fail
    const invalid = await verifySignature({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: combinedHeaders,
      body: '{"amount":"100"}',
      verifier: verifier2, // wrong key
      label: 'sig1',
    });
    expect(invalid).toBe(false);
  });

  test('requesting non-existent label returns false', async () => {
    const signed = await signRequest({
      method: 'GET',
      url: 'https://example.com/',
      headers: {},
      signer: signer1,
      coveredComponents: ['@method'],
      label: 'sig1',
    });

    const result = await verifySignature({
      method: 'GET',
      url: 'https://example.com/',
      headers: { ...signed },
      verifier: verifier1,
      label: 'nonexistent',
    });

    expect(result).toBe(false);
  });
});

// ─── @status Component Tests ───────────────────────────────────

describe('@status Derived Component (RFC 9421 §2.2.8)', () => {
  test('resolves status code for response signing', () => {
    const ctx = {
      method: 'GET',
      url: 'https://example.com/',
      headers: {},
      statusCode: 200,
    };
    expect(resolveComponent('@status', ctx)).toBe('200');
  });

  test('resolves 404 status', () => {
    const ctx = {
      method: 'GET',
      url: 'https://example.com/',
      headers: {},
      statusCode: 404,
    };
    expect(resolveComponent('@status', ctx)).toBe('404');
  });

  test('returns undefined when no statusCode provided', () => {
    const ctx = {
      method: 'GET',
      url: 'https://example.com/',
      headers: {},
    };
    expect(resolveComponent('@status', ctx)).toBeUndefined();
  });
});

// ─── Middleware Tests ──────────────────────────────────────────

describe('createSignatureMiddleware', () => {
  test('passes valid signature', async () => {
    const signed = await signRequest({
      method: 'POST',
      url: 'https://wallet.example/pay',
      headers: { 'Content-Type': 'application/json', 'Host': 'wallet.example' },
      body: '{"amount":"100"}',
      signer: signer1,
      coveredComponents: ['@method', '@target-uri'],
    });

    const middleware = createSignatureMiddleware({ verifier: verifier1, maxAge: 300 });
    const next = jest.fn();
    const req = {
      method: 'POST',
      protocol: 'https',
      headers: {
        host: 'wallet.example',
        'content-type': 'application/json',
        signature: signed['Signature'],
        'signature-input': signed['Signature-Input'],
      },
      originalUrl: '/pay',
      body: '{"amount":"100"}',
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    await middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('rejects invalid signature with 401', async () => {
    const middleware = createSignatureMiddleware({ verifier: verifier1 });
    const next = jest.fn();
    const req = {
      method: 'GET',
      protocol: 'https',
      headers: {
        host: 'example.com',
        signature: 'sig=:invalidbase64:',
        'signature-input': 'sig=("@method");created=1000;keyid="key-1";alg="ed25519"',
      },
      originalUrl: '/',
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('rejects missing signature headers with 401', async () => {
    const middleware = createSignatureMiddleware({ verifier: verifier1 });
    const next = jest.fn();
    const req = {
      method: 'GET',
      protocol: 'https',
      headers: { host: 'example.com' },
      originalUrl: '/',
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('custom error handler is called on failure', async () => {
    const onError = jest.fn();
    const middleware = createSignatureMiddleware({ verifier: verifier1, onError });
    const next = jest.fn();
    const req = {
      method: 'GET',
      protocol: 'https',
      headers: { host: 'example.com' },
      originalUrl: '/',
    };
    const res = {};

    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalled();
    expect(onError.mock.calls[0][2]).toBeInstanceOf(Error);
  });

  test('dynamic verifier resolves by keyId', async () => {
    const signed = await signRequest({
      method: 'GET',
      url: 'https://example.com/',
      headers: { Host: 'example.com' },
      signer: signer1,
      coveredComponents: ['@method'],
    });

    const dynamicVerifier = jest.fn().mockResolvedValue(verifier1);
    const middleware = createSignatureMiddleware({ verifier: dynamicVerifier, maxAge: 300 });
    const next = jest.fn();
    const req = {
      method: 'GET',
      protocol: 'https',
      headers: {
        host: 'example.com',
        signature: signed['Signature'],
        'signature-input': signed['Signature-Input'],
      },
      originalUrl: '/',
    };
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };

    await middleware(req, res, next);
    expect(dynamicVerifier).toHaveBeenCalledWith('key-1');
    expect(next).toHaveBeenCalled();
  });
});
