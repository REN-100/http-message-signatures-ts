/**
 * HTTP Message Signature Verification — RFC 9421
 *
 * Verifies HTTP request/response signatures using Ed25519, ECDSA-P256/P384,
 * or RSA-PSS-SHA512. Zero external dependencies — uses Node.js native `crypto`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.2
 */

import { createVerify, createPublicKey, verify as ed25519Verify, KeyObject } from 'crypto';
import { buildSignatureBase } from './signature-base';
import { verifyContentDigest } from './content-digest';
import { parseSignatureInput } from './serialization';
import type { Algorithm, Verifier, VerifierOptions, VerifyRequestOptions, SignatureParams } from './types';

/**
 * Resolve raw key material into a Node.js `KeyObject` for verification.
 */
function resolvePublicKey(key: string | Buffer): KeyObject {
  if (typeof key === 'string') {
    return createPublicKey(key);
  }
  if (Buffer.isBuffer(key)) {
    try {
      return createPublicKey({ key, format: 'der', type: 'spki' });
    } catch {
      // Assume raw Ed25519 32-byte public key
      return createPublicKey({
        key: Buffer.concat([
          // Ed25519 SPKI prefix (RFC 8410)
          Buffer.from('302a300506032b6570032100', 'hex'),
          key,
        ]),
        format: 'der',
        type: 'spki',
      });
    }
  }
  throw new Error(
    'Unsupported key format. Provide a PEM string or Buffer.'
  );
}

/**
 * Create a low-level verification function for the given algorithm.
 */
function createVerifyFn(
  algorithm: Algorithm,
  keyObj: KeyObject
): (data: Buffer, signature: Buffer) => Promise<boolean> {
  switch (algorithm) {
    case 'ed25519':
      return async (data: Buffer, signature: Buffer) => {
        return ed25519Verify(undefined, data, keyObj, signature);
      };

    case 'ecdsa-p256-sha256':
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA256');
        verifier.update(data);
        return verifier.verify(
          { key: keyObj, dsaEncoding: 'ieee-p1363' },
          signature
        );
      };

    case 'ecdsa-p384-sha384':
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA384');
        verifier.update(data);
        return verifier.verify(
          { key: keyObj, dsaEncoding: 'ieee-p1363' },
          signature
        );
      };

    case 'rsa-pss-sha512':
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA512');
        verifier.update(data);
        return verifier.verify(
          {
            key: keyObj,
            padding: 6, // RSA_PKCS1_PSS_PADDING
            saltLength: 64,
          },
          signature
        );
      };

    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

// ─────────────────────────── Public API ───────────────────────────

/**
 * Create a Verifier instance for validating HTTP Message Signatures.
 *
 * @example
 * ```ts
 * const verifier = createVerifier({
 *   keyId: 'their-key-id',
 *   algorithm: 'ed25519',
 *   publicKey: theirPublicKeyPem,
 * });
 * ```
 */
export function createVerifier(options: VerifierOptions): Verifier {
  const keyObj = resolvePublicKey(options.publicKey);
  const verifyFn = createVerifyFn(options.algorithm, keyObj);

  return {
    keyId: options.keyId,
    algorithm: options.algorithm,
    verify: verifyFn,
  };
}

/**
 * Verify an HTTP Message Signature per RFC 9421.
 *
 * Performs the following checks:
 * 1. Parses the `Signature-Input` header to extract covered components + params
 * 2. Reconstructs the signature base from the request
 * 3. Verifies the signature using the provided verifier
 * 4. Optionally checks `Content-Digest` integrity
 * 5. Optionally enforces signature age (`maxAge`)
 *
 * @returns `true` if the signature is valid, `false` otherwise
 *
 * @example
 * ```ts
 * const isValid = await verifySignature({
 *   method: 'POST',
 *   url: 'https://wallet.example/incoming-payments',
 *   headers: incomingHeaders,
 *   body: incomingBody,
 *   verifier,
 *   maxAge: 300, // reject signatures older than 5 minutes
 * });
 * ```
 */
export async function verifySignature(
  options: VerifyRequestOptions
): Promise<boolean> {
  const { method, url, headers, body, verifier, maxAge } = options;

  // 1. Extract Signature and Signature-Input headers
  const signatureHeader = findHeader(headers, 'signature');
  const signatureInputHeader = findHeader(headers, 'signature-input');

  if (!signatureHeader || !signatureInputHeader) {
    return false;
  }

  // 2. Parse the Signature-Input to get components and params
  const { label, coveredComponents, params } = parseSignatureInput(signatureInputHeader);

  // 3. Extract the signature value from the Signature header
  //    Format: label=:base64value:
  const sigRegex = new RegExp(`${label}=:([A-Za-z0-9+/=]+):`);
  const sigMatch = signatureHeader.match(sigRegex);
  if (!sigMatch) {
    return false;
  }
  const signatureBytes = Buffer.from(sigMatch[1], 'base64');

  // 4. Check signature age if maxAge is specified
  if (maxAge !== undefined && params.created !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (now - params.created > maxAge) {
      return false; // Signature is too old
    }
  }

  // 5. Check expiration
  if (params.expires !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (now > params.expires) {
      return false; // Signature has expired
    }
  }

  // 6. Verify Content-Digest if present in covered components
  if (coveredComponents.includes('content-digest') && body) {
    const digestHeader = findHeader(headers, 'content-digest');
    if (!digestHeader) {
      return false;
    }
    if (!verifyContentDigest(body, digestHeader)) {
      return false;
    }
  }

  // 7. Reconstruct the signature base
  const signatureBase = buildSignatureBase(
    coveredComponents,
    params,
    { method, url, headers }
  );

  // 8. Verify the signature
  return verifier.verify(
    Buffer.from(signatureBase, 'utf-8'),
    signatureBytes
  );
}

/**
 * Case-insensitive header lookup.
 */
function findHeader(
  headers: Record<string, string>,
  name: string
): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      return value;
    }
  }
  return undefined;
}
