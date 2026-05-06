/**
 * GNAP Profile — RFC 9635 / Open Payments HTTP Signature Profile
 *
 * Pre-configured signing utilities for GNAP (Grant Negotiation and
 * Authorization Protocol) and Open Payments. These functions wrap
 * the generic RFC 9421 signer with GNAP-specific defaults:
 *
 * - Ed25519 as the default algorithm
 * - Automatic covered component selection per the GNAP httpsig proof method
 * - Content-Digest generation for requests with bodies
 * - `tag="gnap"` on all signatures
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-7.3.3
 * @see https://openpayments.dev
 */

import { createSigner, signRequest } from './signer';
import type { Signer, GnapSignerOptions, SignedHeaders } from './types';

/**
 * Create a signer pre-configured for GNAP / Open Payments.
 *
 * Defaults to Ed25519, which is the recommended algorithm for
 * Open Payments wallet address proof-of-possession.
 *
 * @example
 * ```ts
 * import { createGnapSigner } from '@shujaapay/http-message-signatures';
 *
 * const signer = createGnapSigner({
 *   clientKeyId: 'my-wallet-key',
 *   privateKey: myEd25519PemKey,
 * });
 * ```
 */
export function createGnapSigner(options: GnapSignerOptions): Signer {
  return createSigner({
    keyId: options.clientKeyId,
    algorithm: options.algorithm || 'ed25519',
    privateKey: options.privateKey,
  });
}

/**
 * Sign a request using the GNAP httpsig proof method.
 *
 * Automatically selects covered components per RFC 9635 §7.3.3:
 * - `@method` and `@target-uri` (always)
 * - `authorization` (if the header is present)
 * - `content-type` + `content-digest` (for POST/PUT/PATCH with body)
 *
 * Sets `tag="gnap"` on the signature to distinguish it from other
 * signatures that may be present on the same message.
 *
 * @example
 * ```ts
 * // Sign a GNAP grant request
 * const signed = await signGnapRequest({
 *   method: 'POST',
 *   url: 'https://auth.wallet.example/',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({
 *     access_token: {
 *       access: [{ type: 'incoming-payment', actions: ['create', 'read'] }],
 *     },
 *   }),
 *   signer,
 * });
 *
 * // Sign a resource request with GNAP token
 * const resourceSigned = await signGnapRequest({
 *   method: 'GET',
 *   url: 'https://wallet.example.com/incoming-payments/123',
 *   headers: { Authorization: 'GNAP os9M2pmhkdag5yKQ' },
 *   signer,
 * });
 * ```
 */
export async function signGnapRequest(options: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer;
  signer: Signer;
}): Promise<SignedHeaders> {
  const { method, url, headers, body, signer } = options;

  // Build covered components per GNAP httpsig profile
  const coveredComponents: string[] = ['@method', '@target-uri'];

  // Include authorization if present (case-insensitive check)
  const hasAuth = Object.keys(headers).some(
    (k) => k.toLowerCase() === 'authorization'
  );
  if (hasAuth) {
    coveredComponents.push('authorization');
  }

  // Include body-related components for methods with bodies
  const hasBody =
    body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase());
  if (hasBody) {
    coveredComponents.push('content-type', 'content-digest');
  }

  return signRequest({
    method,
    url,
    headers,
    body,
    signer,
    coveredComponents,
    includeContentDigest: !!hasBody,
    tag: 'gnap',
  });
}
