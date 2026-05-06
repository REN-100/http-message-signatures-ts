/**
 * Content-Digest Generation - RFC 9530
 * 
 * Generates and verifies Content-Digest header values for
 * HTTP request body integrity verification.
 */

import { createHash } from 'crypto';

type DigestAlgorithm = 'sha-256' | 'sha-512';

/**
 * Generate a Content-Digest header value per RFC 9530.
 * 
 * @param body - The request body
 * @param algorithm - Hash algorithm (default: 'sha-256')
 * @returns Content-Digest header value (e.g., 'sha-256=:base64hash:')
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
 * @param body - The request body to verify
 * @param digestHeader - The Content-Digest header value
 * @returns true if the digest matches
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

  // Constant-time comparison to prevent timing attacks
  return timingSafeEqual(expectedHash, actualHash);
}

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  
  try {
    const { timingSafeEqual: nativeEqual } = require('crypto');
    return nativeEqual(bufA, bufB);
  } catch {
    // Fallback: still constant-time via XOR
    let result = 0;
    for (let i = 0; i < bufA.length; i++) {
      result |= bufA[i] ^ bufB[i];
    }
    return result === 0;
  }
}
