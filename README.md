# HTTP Message Signatures for TypeScript

> **RFC 9421 HTTP Message Signatures** — production-ready, zero-dependency, GNAP-optimized signing for Open Payments and Interledger.
>
> Built by [ShujaaPay](https://www.shujaapay.me) — contributing to the Open Payments ecosystem.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![RFC 9421](https://img.shields.io/badge/RFC-9421-blue.svg)](https://www.rfc-editor.org/rfc/rfc9421)
[![RFC 9530](https://img.shields.io/badge/RFC-9530-blue.svg)](https://www.rfc-editor.org/rfc/rfc9530)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org/)

---

## Why This Library?

The [Interledger Foundation](https://interledger.org) and [Open Payments](https://openpayments.dev) ecosystem require HTTP Message Signatures (RFC 9421) for all authenticated API requests. This library provides:

- **Full RFC 9421 compliance** — tested against Appendix B reference messages
- **All required algorithms** — Ed25519 (recommended), ECDSA-P256, ECDSA-P384, RSA-PSS-SHA512
- **GNAP httpsig profile** — automatic covered component selection per RFC 9635 §7.3.3
- **Content-Digest (RFC 9530)** — request body integrity with SHA-256/SHA-512
- **Zero runtime dependencies** — only Node.js native `crypto`
- **TypeScript-first** — full type safety, exported interfaces, IntelliSense-ready

### Comparison with `@interledger/http-signature-utils`

| Feature | This library | `http-signature-utils` |
|---------|-------------|----------------------|
| Algorithms | Ed25519, ECDSA-P256, P384, RSA-PSS | Ed25519 only |
| GNAP profile | Built-in (`signGnapRequest`) | Manual setup |
| Verification | Full (`verifySignature`) | Partial |
| Content-Digest | Built-in | Separate |
| Dependencies | 0 runtime | Multiple |
| Target | Node.js ≥18 | Node.js |

### Real-World Integration: ShujaaPay

[ShujaaPay](https://www.shujaapay.me) is a multi-currency fintech platform built on the Open Payments standard. This library is the cryptographic backbone of our payment infrastructure:

**🔐 Gateway Signature Verification** — Every incoming API request to the ShujaaPay gateway is verified using `createSignatureMiddleware`, ensuring that only authenticated clients with valid Ed25519 key pairs can initiate payments, manage wallets, or access account data.

**💸 Wallet-to-Wallet Transfers** — When ShujaaPay initiates an outgoing payment to another Open Payments-compliant wallet (e.g., Rafiki-based wallets), the gateway uses `signGnapRequest` to sign GNAP grant requests and resource access calls, enabling secure cross-wallet interoperability without sharing secrets.

**🌍 Web Monetization** — ShujaaPay supports [Web Monetization](https://webmonetization.org) streaming payments. The `signRequest` function signs each micropayment instruction sent to receiving wallets, while `verifySignature` validates incoming payment notifications — all standards-compliant and interoperable with the broader Interledger network.

**🔑 Key Management** — Client key pairs are generated via `generateKeyPair('ed25519')` and published as JWK on each wallet address's `jwks.json` endpoint using `exportPublicJwk`, enabling peer wallets and authorization servers to verify our signatures without any out-of-band key exchange.

> This library exists because we needed it in production. Every feature is driven by real payment flows, tested against real Open Payments interactions, and designed to work out of the box for any fintech building on Interledger.

## Installation

```bash
npm install @shujaapay/http-message-signatures
```

## Quick Start

### Sign a Request

```typescript
import { createSigner, signRequest } from '@shujaapay/http-message-signatures';

const signer = createSigner({
  keyId: 'my-key-id',
  algorithm: 'ed25519',
  privateKey: myEd25519PrivateKeyPem,
});

const signedHeaders = await signRequest({
  method: 'POST',
  url: 'https://wallet.example/incoming-payments',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ walletAddress: 'https://wallet.example/alice' }),
  signer,
  coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
  includeContentDigest: true,
});

// Merge into your outgoing request:
// signedHeaders.Signature       → sig=:base64-signature:
// signedHeaders['Signature-Input'] → sig=("@method" "@target-uri" ...);created=...
// signedHeaders['Content-Digest']  → sha-256=:base64-hash:
```

### Verify a Signature

```typescript
import { createVerifier, verifySignature } from '@shujaapay/http-message-signatures';

const verifier = createVerifier({
  keyId: 'their-key-id',
  algorithm: 'ed25519',
  publicKey: theirEd25519PublicKeyPem,
});

const isValid = await verifySignature({
  method: 'POST',
  url: 'https://wallet.example/incoming-payments',
  headers: incomingHeaders,
  body: incomingBody,
  verifier,
  maxAge: 300, // reject signatures older than 5 minutes
});
```

### GNAP / Open Payments Profile

```typescript
import { createGnapSigner, signGnapRequest } from '@shujaapay/http-message-signatures';

// Pre-configured for Open Payments — defaults to Ed25519
const signer = createGnapSigner({
  clientKeyId: 'my-wallet-key',
  privateKey: myPrivateKeyPem,
});

// Grant request to authorization server
const signed = await signGnapRequest({
  method: 'POST',
  url: 'https://auth.wallet.example/',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'GNAP continuation-token',
  },
  body: JSON.stringify({
    access_token: {
      access: [{ type: 'incoming-payment', actions: ['create', 'read'] }],
    },
  }),
  signer,
});
// Automatically covers: @method, @target-uri, authorization, content-type, content-digest
// Automatically sets: tag="gnap", includeContentDigest=true
```

## API Reference

### `createSigner(options: SignerOptions): Signer`

| Parameter | Type | Description |
|---|---|---|
| `keyId` | `string` | Identifier for the signing key |
| `algorithm` | `Algorithm` | `'ed25519'` \| `'ecdsa-p256-sha256'` \| `'ecdsa-p384-sha384'` \| `'rsa-pss-sha512'` |
| `privateKey` | `string \| Buffer` | PEM-encoded private key or raw key buffer |

### `signRequest(options: SignRequestOptions): Promise<SignedHeaders>`

Returns `{ Signature, 'Signature-Input', 'Content-Digest'? }` — merge into outgoing headers.

### `createVerifier(options: VerifierOptions): Verifier`

### `verifySignature(options: VerifyRequestOptions): Promise<boolean>`

Parses `Signature-Input`, reconstructs the base, verifies the signature, checks `Content-Digest` integrity, and enforces `maxAge`/`expires`.

### `createGnapSigner(options: GnapSignerOptions): Signer`

Convenience wrapper — defaults to Ed25519 with GNAP key ID.

### `signGnapRequest(options): Promise<SignedHeaders>`

Auto-selects covered components per GNAP httpsig proof method (RFC 9635 §7.3.3).

### Utility Functions

| Function | Purpose |
|---|---|
| `buildSignatureBase()` | Construct the signature base string (RFC 9421 §2.5) |
| `resolveComponent()` | Resolve a component identifier to its value (RFC 9421 §2.1) |
| `generateContentDigest()` | Generate Content-Digest header (RFC 9530) |
| `verifyContentDigest()` | Verify Content-Digest against body |
| `serializeSignatureInput()` | Serialize Signature-Input header value |
| `parseSignatureInput()` | Parse Signature-Input header value |

## Project Structure

```
src/
  index.ts              # Public API exports
  signer.ts             # Signing implementation (RFC 9421 §3.1)
  verifier.ts           # Verification implementation (RFC 9421 §3.2)
  signature-base.ts     # Signature base construction (RFC 9421 §2.5)
  component-ids.ts      # Component identifier resolution (RFC 9421 §2.1)
  content-digest.ts     # Content-Digest generation (RFC 9530)
  serialization.ts      # Signature-Input serialization (RFC 9421 §4.1)
  gnap-profile.ts       # GNAP convenience functions (RFC 9635 §7.3.3)
  types.ts              # TypeScript interfaces
tests/
  signer.test.ts        # Core signing tests
  verifier.test.ts      # All algorithms + verification edge cases
  signature-base.test.ts # Component resolution + base construction
  gnap-profile.test.ts  # GNAP/Open Payments scenarios
  rfc9421-compliance.test.ts  # RFC Appendix B test vectors
  fixtures/
    rfc9421-test-messages.ts  # Canonical test messages from the RFC
```

## Supported Algorithms

| Algorithm | RFC Section | Use Case |
|---|---|---|
| `ed25519` | [§3.3.6](https://www.rfc-editor.org/rfc/rfc9421#section-3.3.6) | **Recommended** for GNAP/Open Payments |
| `ecdsa-p256-sha256` | [§3.3.4](https://www.rfc-editor.org/rfc/rfc9421#section-3.3.4) | Alternative asymmetric |
| `ecdsa-p384-sha384` | [§3.3.5](https://www.rfc-editor.org/rfc/rfc9421#section-3.3.5) | Higher security curve |
| `rsa-pss-sha512` | [§3.3.1](https://www.rfc-editor.org/rfc/rfc9421#section-3.3.1) | Legacy RSA compatibility |

## Related Projects

This library is part of the **ShujaaPay GNAP Stack** by [ShujaaPay](https://www.shujaapay.me), contributing open-source tooling to the [Open Payments](https://openpayments.dev) ecosystem:

| Repo | Description | Status |
|------|-------------|--------|
| [`gnap-openapi-security-scheme`](https://github.com/REN-100/gnap-openapi-security-scheme) | `x-gnap` OpenAPI extension for GNAP security | In progress |
| **`http-message-signatures-ts`** | **This repo** — RFC 9421 signing library | In progress |
| [`kiota-gnap-auth-ts`](https://github.com/REN-100/kiota-gnap-auth-ts) | Kiota GNAP auth provider (TypeScript) | In progress |
| [`kiota-gnap-auth-python`](https://github.com/REN-100/kiota-gnap-auth-python) | Kiota GNAP auth provider (Python) | In progress |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Key areas for contribution:

- Testing against `@interledger/http-signature-utils` for interoperability
- HMAC-SHA256 algorithm support
- Browser/Deno WebCrypto compatibility

## References

- [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [RFC 9530 — Digest Fields](https://www.rfc-editor.org/rfc/rfc9530)
- [RFC 9635 — GNAP](https://www.rfc-editor.org/rfc/rfc9635)
- [Open Payments Specification](https://openpayments.dev)
- [Interledger Foundation](https://interledger.org)

## License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ❤️ by <a href="https://www.shujaapay.me">ShujaaPay</a> · Contributing to Open Payments
</p>
