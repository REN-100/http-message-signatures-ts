/**
 * Tests for Key Utilities — JWK Import/Export and Key Generation
 */

import {
  generateKeyPair,
  exportPublicJwk,
  importPublicJwk,
  importPrivateJwk,
  algorithmToJwkAlg,
  createSigner,
  createVerifier,
  signRequest,
  verifySignature,
} from '../src';

describe('generateKeyPair', () => {
  test('generates Ed25519 keys by default', () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
  });

  test('generates Ed25519 keys explicitly', () => {
    const { publicKey, privateKey } = generateKeyPair('ed25519');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
  });

  test('generates ECDSA-P256 keys', () => {
    const { publicKey, privateKey } = generateKeyPair('ecdsa-p256-sha256');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
  });

  test('generates ECDSA-P384 keys', () => {
    const { publicKey, privateKey } = generateKeyPair('ecdsa-p384-sha384');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
  });

  test('generates RSA-PSS keys', () => {
    const { publicKey, privateKey } = generateKeyPair('rsa-pss-sha512');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
    expect(privateKey).toContain('BEGIN PRIVATE KEY');
  });

  test('generated keys work with signer/verifier', async () => {
    const { publicKey, privateKey } = generateKeyPair('ed25519');
    const signer = createSigner({ keyId: 'gen-key', algorithm: 'ed25519', privateKey });
    const verifier = createVerifier({ keyId: 'gen-key', algorithm: 'ed25519', publicKey });

    const signed = await signRequest({
      method: 'GET', url: 'https://example.com/', headers: {},
      signer, coveredComponents: ['@method', '@target-uri'],
    });

    const valid = await verifySignature({
      method: 'GET', url: 'https://example.com/',
      headers: { ...signed }, verifier,
    });

    expect(valid).toBe(true);
  });
});

describe('JWK Export', () => {
  test('exports Ed25519 public key to JWK', () => {
    const { publicKey } = generateKeyPair('ed25519');
    const jwk = exportPublicJwk(publicKey);

    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBeDefined();
    expect(typeof jwk.x).toBe('string');
  });

  test('exports ECDSA-P256 public key to JWK', () => {
    const { publicKey } = generateKeyPair('ecdsa-p256-sha256');
    const jwk = exportPublicJwk(publicKey);

    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
  });

  test('includes kid and alg when provided', () => {
    const { publicKey } = generateKeyPair('ed25519');
    const jwk = exportPublicJwk(publicKey, { kid: 'test-key', alg: 'EdDSA' });

    expect(jwk.kid).toBe('test-key');
    expect(jwk.alg).toBe('EdDSA');
  });
});

describe('JWK Import', () => {
  test('Ed25519 round-trip: PEM → JWK → PEM → sign/verify', async () => {
    const { publicKey, privateKey } = generateKeyPair('ed25519');

    // Export to JWK
    const jwk = exportPublicJwk(publicKey);

    // Import back to PEM
    const reimported = importPublicJwk(jwk);

    // Verify the reimported key works
    const signer = createSigner({ keyId: 'jwk-test', algorithm: 'ed25519', privateKey });
    const verifier = createVerifier({ keyId: 'jwk-test', algorithm: 'ed25519', publicKey: reimported });

    const signed = await signRequest({
      method: 'POST', url: 'https://example.com/pay',
      headers: { 'Content-Type': 'application/json' },
      body: '{"amount":"100"}', signer,
      coveredComponents: ['@method', '@target-uri', 'content-digest'],
      includeContentDigest: true,
    });

    const valid = await verifySignature({
      method: 'POST', url: 'https://example.com/pay',
      headers: { 'Content-Type': 'application/json', ...signed },
      body: '{"amount":"100"}', verifier,
    });

    expect(valid).toBe(true);
  });

  test('ECDSA-P256 round-trip: PEM → JWK → PEM', () => {
    const { publicKey } = generateKeyPair('ecdsa-p256-sha256');
    const jwk = exportPublicJwk(publicKey);
    const reimported = importPublicJwk(jwk);

    expect(reimported).toContain('BEGIN PUBLIC KEY');
  });
});

describe('importPrivateJwk', () => {
  test('imports Ed25519 private key from JWK', () => {
    // Generate a key and export to JWK to get a valid JWK
    const { privateKey } = generateKeyPair('ed25519');
    const { createPrivateKey } = require('crypto');
    const keyObj = createPrivateKey(privateKey);
    const jwk = keyObj.export({ format: 'jwk' });

    const reimported = importPrivateJwk(jwk);
    expect(reimported).toContain('BEGIN PRIVATE KEY');
  });
});

describe('algorithmToJwkAlg', () => {
  test('ed25519 → EdDSA', () => {
    expect(algorithmToJwkAlg('ed25519')).toBe('EdDSA');
  });

  test('ecdsa-p256-sha256 → ES256', () => {
    expect(algorithmToJwkAlg('ecdsa-p256-sha256')).toBe('ES256');
  });

  test('ecdsa-p384-sha384 → ES384', () => {
    expect(algorithmToJwkAlg('ecdsa-p384-sha384')).toBe('ES384');
  });

  test('rsa-pss-sha512 → PS512', () => {
    expect(algorithmToJwkAlg('rsa-pss-sha512')).toBe('PS512');
  });
});
