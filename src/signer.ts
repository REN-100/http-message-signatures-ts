/**
 * HTTP Message Signature Signing — RFC 9421
 *
 * Creates signers and signs HTTP requests using Ed25519, ECDSA-P256/P384,
 * or RSA-PSS-SHA512. Zero external dependencies — uses Node.js native `crypto`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.1
 */

import { createSign, createPrivateKey, sign as ed25519Sign, KeyObject } from 'crypto';
import { buildSignatureBase } from './signature-base';
import { generateContentDigest } from './content-digest';
import type {
  Algorithm,
  Signer,
  SignerOptions,
  SignRequestOptions,
  SignedHeaders,
  SignatureParams,
} from './types';
import { serializeSignatureInput } from './serialization';

/**
 * Resolve raw key material (PEM string, Buffer, or CryptoKey) into a
 * Node.js `KeyObject` for signing.
 */
function resolvePrivateKey(key: string | Buffer): KeyObject {
  if (typeof key === 'string') {
    // PEM-encoded string
    return createPrivateKey(key);
  }
  if (Buffer.isBuffer(key)) {
    // Raw key bytes — try PKCS#8 DER first, fall back to raw Ed25519 seed
    try {
      return createPrivateKey({ key, format: 'der', type: 'pkcs8' });
    } catch {
      // Assume raw Ed25519 32-byte seed
      return createPrivateKey({
        key: Buffer.concat([
          // Ed25519 PKCS#8 prefix (RFC 8410)
          Buffer.from('302e020100300506032b657004220420', 'hex'),
          key,
        ]),
        format: 'der',
        type: 'pkcs8',
      });
    }
  }
  throw new Error(
    'Unsupported key format. Provide a PEM string or Buffer.'
  );
}

/**
 * Create a low-level signing function for the given algorithm.
 */
function createSignFn(
  algorithm: Algorithm,
  keyObj: KeyObject
): (data: Buffer) => Promise<Buffer> {
  switch (algorithm) {
    case 'ed25519':
      return async (data: Buffer) => {
        return ed25519Sign(undefined, data, keyObj);
      };

    case 'ecdsa-p256-sha256':
      return async (data: Buffer) => {
        const signer = createSign('SHA256');
        signer.update(data);
        return signer.sign({ key: keyObj, dsaEncoding: 'ieee-p1363' });
      };

    case 'ecdsa-p384-sha384':
      return async (data: Buffer) => {
        const signer = createSign('SHA384');
        signer.update(data);
        return signer.sign({ key: keyObj, dsaEncoding: 'ieee-p1363' });
      };

    case 'rsa-pss-sha512':
      return async (data: Buffer) => {
        const signer = createSign('SHA512');
        signer.update(data);
        return signer.sign({
          key: keyObj,
          padding: 6, // RSA_PKCS1_PSS_PADDING
          saltLength: 64,
        });
      };

    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

// ─────────────────────────── Public API ───────────────────────────

/**
 * Create a Signer instance for generating HTTP Message Signatures.
 *
 * @example
 * ```ts
 * const signer = createSigner({
 *   keyId: 'my-key-1',
 *   algorithm: 'ed25519',
 *   privateKey: myPemString,
 * });
 * ```
 */
export function createSigner(options: SignerOptions): Signer {
  const keyObj = resolvePrivateKey(options.privateKey);
  const signFn = createSignFn(options.algorithm, keyObj);

  return {
    keyId: options.keyId,
    algorithm: options.algorithm,
    sign: signFn,
  };
}

/**
 * Sign an HTTP request per RFC 9421.
 *
 * Returns an object containing `Signature`, `Signature-Input`, and
 * optionally `Content-Digest` headers. Merge these into the outgoing request.
 *
 * @example
 * ```ts
 * const headers = await signRequest({
 *   method: 'POST',
 *   url: 'https://wallet.example/incoming-payments',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: '{"amount":"1000"}',
 *   signer,
 *   coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
 *   includeContentDigest: true,
 * });
 * ```
 */
export async function signRequest(
  options: SignRequestOptions
): Promise<SignedHeaders> {
  const {
    method,
    url,
    headers,
    body,
    signer,
    coveredComponents,
    includeContentDigest = false,
    digestAlgorithm = 'sha-256',
    created,
    expires,
    nonce,
    tag,
  } = options;

  // Clone headers so we don't mutate the caller's object
  const workingHeaders = { ...headers };
  const result: SignedHeaders = {
    Signature: '',
    'Signature-Input': '',
  };

  // 1. Generate Content-Digest if requested (must happen before signature base)
  if (includeContentDigest && body) {
    const digest = generateContentDigest(body, digestAlgorithm);
    workingHeaders['content-digest'] = digest;
    result['Content-Digest'] = digest;
  }

  // 2. Build signature parameters
  const params: SignatureParams = {
    created: created ?? Math.floor(Date.now() / 1000),
    keyid: signer.keyId,
    alg: algorithmToAlgId(signer.algorithm),
  };
  if (expires !== undefined) params.expires = expires;
  if (nonce !== undefined) params.nonce = nonce;
  if (tag !== undefined) params.tag = tag;

  // 3. Build signature base string (RFC 9421 §2.5)
  const signatureBase = buildSignatureBase(coveredComponents, params, {
    method,
    url,
    headers: workingHeaders,
  });

  // 4. Sign the base string
  const signatureBytes = await signer.sign(Buffer.from(signatureBase, 'utf-8'));
  const signatureB64 = signatureBytes.toString('base64');

  // 5. Build the Signature-Input header
  const label = 'sig';
  const sigInput = serializeSignatureInput(label, coveredComponents, params);

  // 6. Build the Signature header
  result['Signature-Input'] = sigInput;
  result['Signature'] = `${label}=:${signatureB64}:`;

  return result;
}

/**
 * Map our Algorithm type to the RFC 9421 `alg` parameter identifier.
 */
function algorithmToAlgId(algorithm: Algorithm): string {
  switch (algorithm) {
    case 'ed25519':
      return 'ed25519';
    case 'ecdsa-p256-sha256':
      return 'ecdsa-p256-sha256';
    case 'ecdsa-p384-sha384':
      return 'ecdsa-p384-sha384';
    case 'rsa-pss-sha512':
      return 'rsa-pss-sha512';
    default:
      return algorithm;
  }
}


