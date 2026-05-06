/**
 * HTTP Message Signature Signing — RFC 9421 §3.1
 *
 * Creates signers and signs HTTP requests using Ed25519, ECDSA-P256/P384,
 * or RSA-PSS-SHA512. Zero external dependencies — uses Node.js native `crypto`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.1
 */

import { createSign, createPrivateKey, sign as ed25519Sign, KeyObject, constants as cryptoConstants } from 'crypto';
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
 * Default signature label used when none is specified.
 * Per RFC 9421 §4.1, labels are arbitrary tokens chosen by the signer.
 */
const DEFAULT_LABEL = 'sig';

/**
 * RSA-PSS salt length per RFC 9421 §3.3.1:
 * "Using RSASSA-PSS with SHA-512 and a salt length of 64 bytes"
 */
const PSS_SALT_LENGTH = 64;

/**
 * Resolve raw key material (PEM string or Buffer) into a
 * Node.js `KeyObject` for signing.
 *
 * Supports:
 * - PEM-encoded PKCS#8 strings (most common)
 * - DER-encoded PKCS#8 Buffers
 * - Raw 32-byte Ed25519 seed Buffers (auto-wrapped with RFC 8410 PKCS#8 prefix)
 */
function resolvePrivateKey(key: string | Buffer): KeyObject {
  if (typeof key === 'string') {
    return createPrivateKey(key);
  }
  if (Buffer.isBuffer(key)) {
    try {
      return createPrivateKey({ key, format: 'der', type: 'pkcs8' });
    } catch {
      // Assume raw Ed25519 32-byte seed — wrap with PKCS#8 prefix (RFC 8410)
      return createPrivateKey({
        key: Buffer.concat([
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
 *
 * Algorithm implementations per RFC 9421 §3.3:
 * - Ed25519: RFC 9421 §3.3.6 — EdDSA using curve edwards25519
 * - ECDSA-P256: RFC 9421 §3.3.4 — IEEE P1363 (r||s) encoding, NOT DER
 * - ECDSA-P384: RFC 9421 §3.3.5 — IEEE P1363 (r||s) encoding, NOT DER
 * - RSA-PSS:   RFC 9421 §3.3.1 — RSASSA-PSS with SHA-512, salt=64 bytes
 */
function createSignFn(
  algorithm: Algorithm,
  keyObj: KeyObject
): (data: Buffer) => Promise<Buffer> {
  switch (algorithm) {
    case 'ed25519':
      // RFC 9421 §3.3.6 — EdDSA using curve edwards25519
      return async (data: Buffer) => {
        return ed25519Sign(undefined, data, keyObj);
      };

    case 'ecdsa-p256-sha256':
      // RFC 9421 §3.3.4 — ECDSA P-256 with SHA-256
      // MUST use IEEE P1363 raw (r||s) encoding, NOT ASN.1 DER
      return async (data: Buffer) => {
        const signer = createSign('SHA256');
        signer.update(data);
        return signer.sign({ key: keyObj, dsaEncoding: 'ieee-p1363' });
      };

    case 'ecdsa-p384-sha384':
      // RFC 9421 §3.3.5 — ECDSA P-384 with SHA-384
      // MUST use IEEE P1363 raw (r||s) encoding, NOT ASN.1 DER
      return async (data: Buffer) => {
        const signer = createSign('SHA384');
        signer.update(data);
        return signer.sign({ key: keyObj, dsaEncoding: 'ieee-p1363' });
      };

    case 'rsa-pss-sha512':
      // RFC 9421 §3.3.1 — RSASSA-PSS using SHA-512
      // Salt length: 64 octets, mask generation function: MGF1 with SHA-512
      return async (data: Buffer) => {
        const signer = createSign('SHA512');
        signer.update(data);
        return signer.sign({
          key: keyObj,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: PSS_SALT_LENGTH,
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
 * Sign an HTTP request per RFC 9421 §3.1.
 *
 * Returns an object containing `Signature`, `Signature-Input`, and
 * optionally `Content-Digest` headers. Merge these into the outgoing request.
 *
 * @param options.label - Signature label (default: 'sig'). Use unique labels
 *   when multiple signatures are needed on the same message (RFC 9421 §4.3).
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
 *   label: 'sig1', // optional, defaults to 'sig'
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
    label = DEFAULT_LABEL,
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

  // 2. Build signature parameters (RFC 9421 §2.3)
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

  // 5. Build the Signature-Input header (RFC 9421 §4.1)
  const sigInput = serializeSignatureInput(label, coveredComponents, params);

  // 6. Build the Signature header (RFC 9421 §4.2)
  result['Signature-Input'] = sigInput;
  result['Signature'] = `${label}=:${signatureB64}:`;

  return result;
}

/**
 * Map our Algorithm type to the RFC 9421 `alg` parameter identifier.
 * Per RFC 9421 §6.2, algorithm identifiers are opaque strings.
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
