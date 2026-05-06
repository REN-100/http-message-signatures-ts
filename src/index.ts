/**
 * @shujaapay/http-message-signatures
 * RFC 9421 HTTP Message Signatures for TypeScript/Node.js
 * 
 * @see https://www.rfc-editor.org/rfc/rfc9421
 */

export { createSigner, signRequest, signGnapRequest, createGnapSigner } from './signer';
export { createVerifier, verifySignature } from './verifier';
export { buildSignatureBase } from './signature-base';
export { resolveComponent } from './component-ids';
export { generateContentDigest, verifyContentDigest } from './content-digest';
export { serializeSignatureInput, parseSignatureInput } from './serialization';

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
} from './types';
