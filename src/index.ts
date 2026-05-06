/**
 * @shujaapay/http-message-signatures
 * RFC 9421 HTTP Message Signatures for TypeScript/Node.js
 *
 * Production-quality implementation of HTTP Message Signatures with
 * GNAP-optimized profiles for Open Payments (Interledger).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://openpayments.dev
 */

// ─── Core Signing & Verification ───────────────────────────────
export { createSigner, signRequest } from './signer';
export { createVerifier, verifySignature } from './verifier';

// ─── GNAP / Open Payments Profile ──────────────────────────────
export { createGnapSigner, signGnapRequest } from './gnap-profile';

// ─── Signature Base & Components ───────────────────────────────
export { buildSignatureBase } from './signature-base';
export { resolveComponent } from './component-ids';

// ─── Content-Digest (RFC 9530) ─────────────────────────────────
export { generateContentDigest, verifyContentDigest } from './content-digest';

// ─── Serialization ─────────────────────────────────────────────
export { serializeSignatureInput, parseSignatureInput } from './serialization';

// ─── Types ─────────────────────────────────────────────────────
export type {
  Signer,
  Verifier,
  SignerOptions,
  VerifierOptions,
  SignRequestOptions,
  VerifyRequestOptions,
  Algorithm,
  CoveredComponent,
  SignatureParams,
  GnapSignerOptions,
  SignedHeaders,
} from './types';
