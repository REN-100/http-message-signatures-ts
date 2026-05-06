/**
 * Tests for GNAP Profile — RFC 9635 §7.3.3
 *
 * Validates the GNAP-specific signing profile used by
 * Open Payments wallet address servers and clients.
 */

import { generateKeyPairSync } from 'crypto';
import {
  createGnapSigner,
  signGnapRequest,
  createVerifier,
  verifySignature,
} from '../src';

function ed25519Keys() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

describe('createGnapSigner', () => {
  const { privateKey } = ed25519Keys();

  test('defaults to ed25519', () => {
    const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });
    expect(signer.keyId).toBe('gnap-client');
    expect(signer.algorithm).toBe('ed25519');
  });

  test('respects explicit algorithm', () => {
    const { privateKey: ecKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const signer = createGnapSigner({
      clientKeyId: 'ec-client',
      privateKey: ecKey,
      algorithm: 'ecdsa-p256-sha256',
    });
    expect(signer.algorithm).toBe('ecdsa-p256-sha256');
  });
});

describe('signGnapRequest — POST (grant request)', () => {
  const { publicKey, privateKey } = ed25519Keys();
  const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });
  const verifier = createVerifier({ keyId: 'gnap-client', algorithm: 'ed25519', publicKey });

  test('auto-selects all covered components for POST', async () => {
    const body = JSON.stringify({
      access_token: { access: [{ type: 'incoming-payment', actions: ['create'] }] },
    });
    const signed = await signGnapRequest({
      method: 'POST',
      url: 'https://auth.wallet.example.com/',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'GNAP os9M2pmhkdag5yKQ',
      },
      body,
      signer,
    });

    // Verify covered components
    expect(signed['Signature-Input']).toContain('"@method"');
    expect(signed['Signature-Input']).toContain('"@target-uri"');
    expect(signed['Signature-Input']).toContain('"authorization"');
    expect(signed['Signature-Input']).toContain('"content-type"');
    expect(signed['Signature-Input']).toContain('"content-digest"');

    // Verify GNAP tag
    expect(signed['Signature-Input']).toContain('tag="gnap"');

    // Verify Content-Digest was generated
    expect(signed['Content-Digest']).toBeDefined();
    expect(signed['Content-Digest']!).toMatch(/^sha-256=:/);

    // Full round-trip verification
    const allHeaders = {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP os9M2pmhkdag5yKQ',
      ...signed,
    };
    expect(await verifySignature({
      method: 'POST', url: 'https://auth.wallet.example.com/',
      headers: allHeaders, body, verifier,
    })).toBe(true);
  });
});

describe('signGnapRequest — GET (resource access)', () => {
  const { privateKey } = ed25519Keys();
  const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });

  test('skips body components for GET', async () => {
    const signed = await signGnapRequest({
      method: 'GET',
      url: 'https://wallet.example.com/incoming-payments/123',
      headers: { Authorization: 'GNAP token456' },
      signer,
    });

    expect(signed['Signature-Input']).toContain('"@method"');
    expect(signed['Signature-Input']).toContain('"@target-uri"');
    expect(signed['Signature-Input']).toContain('"authorization"');
    expect(signed['Signature-Input']).not.toContain('"content-type"');
    expect(signed['Signature-Input']).not.toContain('"content-digest"');
    expect(signed['Content-Digest']).toBeUndefined();
  });

  test('skips authorization when not present', async () => {
    const signed = await signGnapRequest({
      method: 'GET',
      url: 'https://wallet.example.com/.well-known/open-payments',
      headers: {},
      signer,
    });

    expect(signed['Signature-Input']).not.toContain('"authorization"');
  });
});

describe('signGnapRequest — Open Payments scenarios', () => {
  const { publicKey, privateKey } = ed25519Keys();
  const signer = createGnapSigner({ clientKeyId: 'gnap-client', privateKey });
  const verifier = createVerifier({ keyId: 'gnap-client', algorithm: 'ed25519', publicKey });

  test('Create Incoming Payment', async () => {
    const body = JSON.stringify({
      walletAddress: 'https://wallet.example.com/alice',
      incomingAmount: { value: '1000', assetCode: 'USD', assetScale: 2 },
    });

    const signed = await signGnapRequest({
      method: 'POST',
      url: 'https://wallet.example.com/incoming-payments',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'GNAP access-token-123',
      },
      body,
      signer,
    });

    const all = {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP access-token-123',
      ...signed,
    };
    expect(await verifySignature({
      method: 'POST', url: 'https://wallet.example.com/incoming-payments',
      headers: all, body, verifier,
    })).toBe(true);
  });

  test('Create Outgoing Payment', async () => {
    const body = JSON.stringify({
      walletAddress: 'https://wallet.example.com/alice',
      quoteId: 'https://wallet.example.com/quotes/abc123',
    });

    const signed = await signGnapRequest({
      method: 'POST',
      url: 'https://wallet.example.com/outgoing-payments',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'GNAP outgoing-token-456',
      },
      body,
      signer,
    });

    const all = {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP outgoing-token-456',
      ...signed,
    };
    expect(await verifySignature({
      method: 'POST', url: 'https://wallet.example.com/outgoing-payments',
      headers: all, body, verifier,
    })).toBe(true);
  });

  test('List Incoming Payments', async () => {
    const signed = await signGnapRequest({
      method: 'GET',
      url: 'https://wallet.example.com/incoming-payments?wallet-address=https://wallet.example.com/alice',
      headers: { 'Authorization': 'GNAP list-token-789' },
      signer,
    });

    const all = { 'Authorization': 'GNAP list-token-789', ...signed };
    expect(await verifySignature({
      method: 'GET',
      url: 'https://wallet.example.com/incoming-payments?wallet-address=https://wallet.example.com/alice',
      headers: all, verifier,
    })).toBe(true);
  });
});
