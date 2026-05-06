/**
 * TypeScript interfaces for HTTP Message Signatures (RFC 9421)
 */

/** Supported signing algorithms */
export type Algorithm = 'ed25519' | 'ecdsa-p256-sha256' | 'ecdsa-p384-sha384' | 'rsa-pss-sha512';

/** Covered component identifiers per RFC 9421 Section 2.1 */
export type CoveredComponent =
  | '@method'
  | '@target-uri'
  | '@authority'
  | '@scheme'
  | '@request-target'
  | '@path'
  | '@query'
  | '@query-param'
  | '@status'
  | string; // Header field names

/** Options for creating a signer */
export interface SignerOptions {
  /** Identifier for the signing key */
  keyId: string;
  /** Signing algorithm */
  algorithm: Algorithm;
  /** Private key material (PEM string, Buffer, or CryptoKey) */
  privateKey: string | Buffer;
  /** Optional: label for the signature (default: 'sig') */
  label?: string;
}

/** Options for creating a verifier */
export interface VerifierOptions {
  /** Identifier for the verification key */
  keyId: string;
  /** Signing algorithm */
  algorithm: Algorithm;
  /** Public key material */
  publicKey: string | Buffer;
}

/** Signer instance returned by createSigner */
export interface Signer {
  keyId: string;
  algorithm: Algorithm;
  sign(data: Buffer): Promise<Buffer>;
}

/** Verifier instance returned by createVerifier */
export interface Verifier {
  keyId: string;
  algorithm: Algorithm;
  verify(data: Buffer, signature: Buffer): Promise<boolean>;
}

/** Options for signing an HTTP request */
export interface SignRequestOptions {
  /** HTTP method (GET, POST, etc.) */
  method: string;
  /** Full request URL */
  url: string;
  /** Request headers */
  headers: Record<string, string>;
  /** Request body (optional) */
  body?: string | Buffer;
  /** Signer instance */
  signer: Signer;
  /** Components to include in the signature base */
  coveredComponents: CoveredComponent[];
  /** Whether to generate and include Content-Digest (RFC 9530) */
  includeContentDigest?: boolean;
  /** Hash algorithm for Content-Digest (default: 'sha-256') */
  digestAlgorithm?: 'sha-256' | 'sha-512';
  /** Created timestamp (default: current time) */
  created?: number;
  /** Expiration timestamp */
  expires?: number;
  /** Nonce for replay protection */
  nonce?: string;
  /** Signature tag (e.g., 'gnap') */
  tag?: string;
  /** Signature label (default: 'sig'). Use unique labels for multiple signatures (RFC 9421 §4.3) */
  label?: string;
}

/** Options for verifying an HTTP signature */
export interface VerifyRequestOptions {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer;
  verifier: Verifier;
  /** Maximum age of signature in seconds */
  maxAge?: number;
}

/** Signature parameters (RFC 9421 Section 2.3) */
export interface SignatureParams {
  created?: number;
  expires?: number;
  nonce?: string;
  alg?: string;
  keyid?: string;
  tag?: string;
}

/** GNAP-specific signer options (convenience wrapper) */
export interface GnapSignerOptions {
  /** Client key identifier used in GNAP grant requests */
  clientKeyId: string;
  /** Ed25519 or ECDSA private key */
  privateKey: string | Buffer;
  /** Algorithm (default: 'ed25519') */
  algorithm?: Algorithm;
}

/** Result of signing a request - contains headers to merge */
export interface SignedHeaders {
  'Signature': string;
  'Signature-Input': string;
  'Content-Digest'?: string;
}
