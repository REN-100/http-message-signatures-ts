# HTTP Message Signatures for TypeScript (`@shujaapay/http-message-signatures`)

> A production-quality RFC 9421 HTTP Message Signatures library for TypeScript/Node.js, optimized for GNAP authentication and Open Payments integration.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![RFC 9421](https://img.shields.io/badge/RFC-9421-blue.svg)](https://www.rfc-editor.org/rfc/rfc9421)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

## Overview

This library implements [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), providing the cryptographic signing layer required by GNAP (RFC 9635) for proof-of-possession. It is designed as a standalone package that can be used independently or as the signing foundation for Kiota GNAP authentication providers.

## Features

- **Full RFC 9421 compliance** - Signature base construction, component identifiers, and serialization
- **Multiple algorithms** - Ed25519, ECDSA-P256, RSA-PSS-SHA512
- **GNAP-optimized** - Pre-configured profiles for Open Payments key proofs
- **Content-Digest** - RFC 9530 support for request body integrity
- **Zero dependencies** - Uses Node.js native `crypto` module
- **TypeScript-first** - Full type safety with exported interfaces

## Installation

```bash
npm install @shujaapay/http-message-signatures
```

## Quick Start

### Sign a Request

```typescript
import { signRequest, createSigner } from '@shujaapay/http-message-signatures';

const signer = createSigner({
  keyId: 'my-key-id',
  algorithm: 'ed25519',
  privateKey: myEd25519PrivateKey,
});

const signedHeaders = await signRequest({
  method: 'POST',
  url: 'https://wallet.example/incoming-payments',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ walletAddress: 'https://wallet.example/alice' }),
  signer,
  coveredComponents: ['@method', '@target-uri', 'content-type', 'content-digest'],
  includeContentDigest: true,
});

// signedHeaders now contains:
// - Signature: sig=:base64-encoded-signature:
// - Signature-Input: sig=("@method" "@target-uri" "content-type" "content-digest");...
// - Content-Digest: sha-256=:base64-encoded-hash:
```

### Verify a Signature

```typescript
import { verifySignature, createVerifier } from '@shujaapay/http-message-signatures';

const verifier = createVerifier({
  keyId: 'their-key-id',
  algorithm: 'ed25519',
  publicKey: theirEd25519PublicKey,
});

const isValid = await verifySignature({
  method: 'POST',
  url: 'https://wallet.example/incoming-payments',
  headers: receivedHeaders,
  body: receivedBody,
  verifier,
});
```

### GNAP Profile (Open Payments)

```typescript
import { createGnapSigner, signGnapRequest } from '@shujaapay/http-message-signatures';

// Pre-configured for Open Payments GNAP requirements
const gnapSigner = createGnapSigner({
  clientKeyId: 'client-key-1',
  privateKey: myPrivateKey,
  algorithm: 'ed25519',
});

const signed = await signGnapRequest({
  method: 'POST',
  url: 'https://auth.wallet.example/',
  headers: { 'Content-Type': 'application/json' },
  body: grantRequestBody,
  signer: gnapSigner,
});
```

## API Reference

### `createSigner(options)`

Creates a signing context for generating HTTP Message Signatures.

| Parameter | Type | Description |
|---|---|---|
| `keyId` | `string` | Identifier for the signing key |
| `algorithm` | `Algorithm` | Signing algorithm |
| `privateKey` | `CryptoKey \| Buffer` | Private key material |

### `signRequest(options)`

Signs an HTTP request and returns headers with signature.

| Parameter | Type | Description |
|---|---|---|
| `method` | `string` | HTTP method |
| `url` | `string` | Request URL |
| `headers` | `Record<string, string>` | Request headers |
| `body` | `string \| Buffer` | Request body (optional) |
| `signer` | `Signer` | Signer from `createSigner` |
| `coveredComponents` | `string[]` | Components to include in signature |
| `includeContentDigest` | `boolean` | Whether to add Content-Digest |

### Supported Algorithms

| Algorithm | OID | Use Case |
|---|---|---|
| `ed25519` | Ed25519 | Recommended for GNAP |
| `ecdsa-p256-sha256` | ECDSA P-256 | Alternative for GNAP |
| `rsa-pss-sha512` | RSA-PSS | Legacy compatibility |

## Project Structure

```
src/
  index.ts              # Public API exports
  signer.ts             # Signing implementation
  verifier.ts           # Verification implementation
  signature-base.ts     # Signature base construction (RFC 9421 Section 2.5)
  component-ids.ts      # Component identifier resolution (RFC 9421 Section 2.1)
  content-digest.ts     # Content-Digest generation (RFC 9530)
  serialization.ts      # Signature-Input serialization
  gnap-profile.ts       # GNAP-specific convenience functions
  types.ts              # TypeScript interfaces
tests/
  signer.test.ts
  verifier.test.ts
  signature-base.test.ts
  gnap-profile.test.ts
  fixtures/              # RFC 9421 test vectors
```

## Relationship to Other Projects

This library is part of the **ShujaaPay GNAP Stack**, funded by the Interledger Foundation:

- [`gnap-openapi-security-scheme`](https://github.com/REN-100/gnap-openapi-security-scheme) - GNAP OpenAPI extension (WS1)
- **This repo** - HTTP Message Signatures (Workstream 4)
- Kiota GNAP Provider (TypeScript) - Coming soon (WS2)
- Kiota GNAP Provider (Python) - Coming soon (WS3)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Key areas:
- Testing against RFC 9421 test vectors
- Additional algorithm support
- Performance benchmarks

## References

- [RFC 9421 - HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [RFC 9530 - Digest Fields](https://www.rfc-editor.org/rfc/rfc9530)
- [RFC 9635 - GNAP](https://www.rfc-editor.org/rfc/rfc9635)
- [Open Payments](https://openpayments.dev)

## License

MIT License - see [LICENSE](LICENSE) for details.
