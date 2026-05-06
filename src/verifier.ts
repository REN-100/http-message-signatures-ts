/**
 * HTTP Message Signature Verification — RFC 9421 §3.2
 *
 * Verifies HTTP request/response signatures using Ed25519, ECDSA-P256/P384,
 * or RSA-PSS-SHA512. Zero external dependencies — uses Node.js native `crypto`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.2
 */

import { createVerify, createPublicKey, verify as ed25519Verify, KeyObject, constants as cryptoConstants } from 'crypto';
import { buildSignatureBase } from './signature-base';
import { verifyContentDigest } from './content-digest';
import { parseSignatureInput, parseMultipleSignatureInputs } from './serialization';
import type { Algorithm, Verifier, VerifierOptions, VerifyRequestOptions, SignatureParams } from './types';

/**
 * RSA-PSS salt length per RFC 9421 §3.3.1
 */
const PSS_SALT_LENGTH = 64;

/**
 * Resolve raw key material into a Node.js `KeyObject` for verification.
 *
 * Supports:
 * - PEM-encoded SPKI strings
 * - DER-encoded SPKI Buffers
 * - Raw 32-byte Ed25519 public key Buffers (auto-wrapped with RFC 8410 SPKI prefix)
 */
function resolvePublicKey(key: string | Buffer): KeyObject {
  if (typeof key === 'string') {
    return createPublicKey(key);
  }
  if (Buffer.isBuffer(key)) {
    try {
      return createPublicKey({ key, format: 'der', type: 'spki' });
    } catch {
      // Assume raw Ed25519 32-byte public key — wrap with SPKI prefix (RFC 8410)
      return createPublicKey({
        key: Buffer.concat([
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
 *
 * @see RFC 9421 §3.3 for algorithm-specific requirements
 */
function createVerifyFn(
  algorithm: Algorithm,
  keyObj: KeyObject
): (data: Buffer, signature: Buffer) => Promise<boolean> {
  switch (algorithm) {
    case 'ed25519':
      // RFC 9421 §3.3.6 — EdDSA using curve edwards25519
      return async (data: Buffer, signature: Buffer) => {
        return ed25519Verify(undefined, data, keyObj, signature);
      };

    case 'ecdsa-p256-sha256':
      // RFC 9421 §3.3.4 — MUST use IEEE P1363 raw (r||s) encoding
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA256');
        verifier.update(data);
        return verifier.verify(
          { key: keyObj, dsaEncoding: 'ieee-p1363' },
          signature
        );
      };

    case 'ecdsa-p384-sha384':
      // RFC 9421 §3.3.5 — MUST use IEEE P1363 raw (r||s) encoding
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA384');
        verifier.update(data);
        return verifier.verify(
          { key: keyObj, dsaEncoding: 'ieee-p1363' },
          signature
        );
      };

    case 'rsa-pss-sha512':
      // RFC 9421 §3.3.1 — RSASSA-PSS with SHA-512, salt=64
      return async (data: Buffer, signature: Buffer) => {
        const verifier = createVerify('SHA512');
        verifier.update(data);
        return verifier.verify(
          {
            key: keyObj,
            padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
            saltLength: PSS_SALT_LENGTH,
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
 * Verify an HTTP Message Signature per RFC 9421 §3.2.
 *
 * Performs the following checks:
 * 1. Parses the `Signature-Input` header to extract covered components + params
 * 2. Checks signature age (maxAge) and expiration (expires)
 * 3. Verifies `Content-Digest` integrity (RFC 9530) if present
 * 4. Reconstructs the signature base from the request
 * 5. Verifies the cryptographic signature
 *
 * @returns `true` if the signature is valid, `false` otherwise
 */
export async function verifySignature(
  options: VerifyRequestOptions
): Promise<boolean> {
  const { method, url, headers, body, verifier, maxAge, label: targetLabel } = options;

  // 1. Extract Signature and Signature-Input headers
  const signatureHeader = findHeader(headers, 'signature');
  const signatureInputHeader = findHeader(headers, 'signature-input');

  if (!signatureHeader || !signatureInputHeader) {
    return false;
  }

  // 2. Parse the Signature-Input — supports multiple signatures (RFC 9421 §4.3)
  let parsed: { label: string; coveredComponents: string[]; params: SignatureParams };

  if (targetLabel) {
    // Look for a specific label in a multi-signature header
    const allSigs = parseMultipleSignatureInputs(signatureInputHeader);
    const match = allSigs.find((s) => s.label === targetLabel);
    if (!match) {
      return false; // Requested label not found
    }
    parsed = match;
  } else {
    // Default: parse the first (or only) signature
    parsed = parseSignatureInput(signatureInputHeader);
  }

  const { label, coveredComponents, params } = parsed;

  // 3. Extract the signature value from the Signature header
  //    Format: label=:base64value: (RFC 9421 §4.2)
  const sigRegex = new RegExp(`${label}=:([A-Za-z0-9+/=]+):`);
  const sigMatch = signatureHeader.match(sigRegex);
  if (!sigMatch) {
    return false;
  }
  const signatureBytes = Buffer.from(sigMatch[1], 'base64');

  // 4. Check signature age if maxAge is specified (RFC 9421 §3.2.1)
  if (maxAge !== undefined && params.created !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (now - params.created > maxAge) {
      return false;
    }
  }

  // 5. Check expiration (RFC 9421 §2.3)
  if (params.expires !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (now > params.expires) {
      return false;
    }
  }

  // 6. Verify Content-Digest if present in covered components (RFC 9530)
  if (coveredComponents.includes('content-digest') && body) {
    const digestHeader = findHeader(headers, 'content-digest');
    if (!digestHeader) {
      return false;
    }
    if (!verifyContentDigest(body, digestHeader)) {
      return false;
    }
  }

  // 7. Reconstruct the signature base (RFC 9421 §2.5)
  const signatureBase = buildSignatureBase(
    coveredComponents,
    params,
    { method, url, headers }
  );

  // 8. Verify the cryptographic signature
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
