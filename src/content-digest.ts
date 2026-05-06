/**
 * Content-Digest Generation — RFC 9530
 *
 * Generates and verifies Content-Digest header values for
 * HTTP request body integrity verification.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9530
 */

import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from 'crypto';

type DigestAlgorithm = 'sha-256' | 'sha-512';

/**
 * Generate a Content-Digest header value per RFC 9530.
 *
 * @param body - The request body
 * @param algorithm - Hash algorithm (default: 'sha-256')
 * @returns Content-Digest header value (e.g., 'sha-256=:base64hash:')
 *
 * @example
 * ```ts
 * const digest = generateContentDigest('{"hello":"world"}', 'sha-256');
 * // => 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:'
 * ```
 */
export function generateContentDigest(
  body: string | Buffer,
  algorithm: DigestAlgorithm = 'sha-256'
): string {
  const hashAlg = algorithm === 'sha-256' ? 'sha256' : 'sha512';
  const bodyBuffer = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;
  const hash = createHash(hashAlg).update(bodyBuffer).digest('base64');

  return `${algorithm}=:${hash}:`;
}

/**
 * Verify a Content-Digest header value against a request body.
 *
 * Uses constant-time comparison to prevent timing side-channel attacks.
 *
 * @param body - The request body to verify
 * @param digestHeader - The Content-Digest header value
 * @returns true if the digest matches
 *
 * @example
 * ```ts
 * const isValid = verifyContentDigest(requestBody, headers['content-digest']);
 * ```
 */
export function verifyContentDigest(
  body: string | Buffer,
  digestHeader: string
): boolean {
  // Parse the digest header: "sha-256=:base64value:"
  const match = digestHeader.match(/^(sha-256|sha-512)=:([A-Za-z0-9+/=]+):$/);
  if (!match) {
    throw new Error(`Invalid Content-Digest format: ${digestHeader}`);
  }

  const [, algorithm, expectedHash] = match;
  const hashAlg = algorithm === 'sha-256' ? 'sha256' : 'sha512';
  const bodyBuffer = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;
  const actualHash = createHash(hashAlg).update(bodyBuffer).digest('base64');

  // Constant-time comparison to prevent timing side-channel attacks
  // Uses Node.js native crypto.timingSafeEqual (available since Node 6)
  const bufExpected = Buffer.from(expectedHash, 'utf-8');
  const bufActual = Buffer.from(actualHash, 'utf-8');

  if (bufExpected.length !== bufActual.length) {
    return false;
  }

  return cryptoTimingSafeEqual(bufExpected, bufActual);
}
