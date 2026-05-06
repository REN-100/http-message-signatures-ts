/**
 * Key Utilities — JWK Import/Export and Key Generation
 *
 * Provides key management helpers for Open Payments / GNAP:
 * - Generate Ed25519 key pairs (recommended for Open Payments)
 * - Import/export keys in JWK format (required for GNAP key publication)
 * - Load keys from PEM files
 *
 * @see https://www.rfc-editor.org/rfc/rfc7517 (JWK)
 * @see https://www.rfc-editor.org/rfc/rfc8410 (Ed25519 key format)
 */

import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
} from 'crypto';
import type { Algorithm } from './types';

/**
 * Result of key pair generation.
 */
export interface GeneratedKeyPair {
  /** PEM-encoded public key (SPKI format) */
  publicKey: string;
  /** PEM-encoded private key (PKCS#8 format) */
  privateKey: string;
}

/**
 * JWK representation of a public key.
 * Used for GNAP key publication in grant requests.
 */
export interface JsonWebKey {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  alg?: string;
  kid?: string;
  use?: string;
  key_ops?: string[];
  [key: string]: unknown;
}

/**
 * Generate a key pair for the specified algorithm.
 *
 * Returns PEM-encoded keys ready for use with `createSigner` / `createVerifier`.
 *
 * @param algorithm - Algorithm to generate keys for (default: 'ed25519')
 * @returns Object with `publicKey` and `privateKey` PEM strings
 *
 * @example
 * ```ts
 * import { generateKeyPair, createSigner } from '@shujaapay/http-message-signatures';
 *
 * const { publicKey, privateKey } = generateKeyPair('ed25519');
 * const signer = createSigner({ keyId: 'my-key', algorithm: 'ed25519', privateKey });
 * ```
 */
export function generateKeyPair(algorithm: Algorithm = 'ed25519'): GeneratedKeyPair {
  const pubEnc = { type: 'spki' as const, format: 'pem' as const };
  const privEnc = { type: 'pkcs8' as const, format: 'pem' as const };

  switch (algorithm) {
    case 'ed25519': {
      const pair = generateKeyPairSync('ed25519', {
        publicKeyEncoding: pubEnc,
        privateKeyEncoding: privEnc,
      });
      return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    case 'ecdsa-p256-sha256': {
      const pair = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: pubEnc,
        privateKeyEncoding: privEnc,
      });
      return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    case 'ecdsa-p384-sha384': {
      const pair = generateKeyPairSync('ec', {
        namedCurve: 'P-384',
        publicKeyEncoding: pubEnc,
        privateKeyEncoding: privEnc,
      });
      return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    case 'rsa-pss-sha512': {
      const pair = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: pubEnc,
        privateKeyEncoding: privEnc,
      });
      return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }

    default:
      throw new Error(`Unsupported algorithm for key generation: ${algorithm}`);
  }
}

/**
 * Export a PEM-encoded public key to JWK format.
 *
 * This is used for GNAP key publication — when a client registers
 * its public key with an authorization server in a grant request.
 *
 * @param publicKeyPem - PEM-encoded public key
 * @param options - Optional kid and alg to include in the JWK
 * @returns JWK object suitable for JSON serialization
 *
 * @example
 * ```ts
 * const jwk = exportPublicJwk(publicKey, { kid: 'my-key', alg: 'EdDSA' });
 * // Use in GNAP grant request:
 * // { client: { key: { proof: "httpsig", jwk } } }
 * ```
 */
export function exportPublicJwk(
  publicKeyPem: string,
  options?: { kid?: string; alg?: string }
): JsonWebKey {
  const keyObj = createPublicKey(publicKeyPem);
  const jwk = keyObj.export({ format: 'jwk' }) as JsonWebKey;

  if (options?.kid) {
    jwk.kid = options.kid;
  }
  if (options?.alg) {
    jwk.alg = options.alg;
  }

  return jwk;
}

/**
 * Import a JWK-formatted public key into a PEM string.
 *
 * Used when receiving a peer's public key from a GNAP grant response
 * or from a wallet address's JWKS endpoint.
 *
 * @param jwk - JSON Web Key object
 * @returns PEM-encoded public key string
 *
 * @example
 * ```ts
 * const pem = importPublicJwk(receivedJwk);
 * const verifier = createVerifier({ keyId: jwk.kid, algorithm: 'ed25519', publicKey: pem });
 * ```
 */
export function importPublicJwk(jwk: JsonWebKey): string {
  const keyObj = createPublicKey({ key: jwk as any, format: 'jwk' });
  return keyObj.export({ type: 'spki', format: 'pem' }) as string;
}

/**
 * Import a JWK-formatted private key into a PEM string.
 *
 * @param jwk - JSON Web Key object containing private key material
 * @returns PEM-encoded private key string
 */
export function importPrivateJwk(jwk: JsonWebKey): string {
  const keyObj = createPrivateKey({ key: jwk as any, format: 'jwk' });
  return keyObj.export({ type: 'pkcs8', format: 'pem' }) as string;
}

/**
 * Map our Algorithm type to the JWK `alg` parameter.
 *
 * @param algorithm - Library algorithm identifier
 * @returns JWK algorithm string
 */
export function algorithmToJwkAlg(algorithm: Algorithm): string {
  switch (algorithm) {
    case 'ed25519':
      return 'EdDSA';
    case 'ecdsa-p256-sha256':
      return 'ES256';
    case 'ecdsa-p384-sha384':
      return 'ES384';
    case 'rsa-pss-sha512':
      return 'PS512';
    default:
      return algorithm;
  }
}
