# Contributing to `@shujaapay/http-message-signatures`

Thank you for your interest in contributing to the ShujaaPay GNAP stack! This library is a critical component of the Open Payments ecosystem, providing the cryptographic signing layer for GNAP authorization.

## Getting Started

```bash
git clone https://github.com/REN-100/http-message-signatures-ts.git
cd http-message-signatures-ts
npm install
npm test
```

## Development Workflow

1. **Branch** from `main` for your feature or fix
2. **Write tests** before or alongside your implementation
3. **Run the full suite** before submitting a PR:
   ```bash
   npm test           # Run all tests
   npm run build      # Verify clean TypeScript compilation
   npm run lint       # Check code style
   ```
4. **Submit a PR** with a clear description of what and why

## Project Structure

```
src/
  index.ts              # Public API exports
  signer.ts             # Signing implementation (RFC 9421 §3.1)
  verifier.ts           # Verification implementation (RFC 9421 §3.2)
  signature-base.ts     # Signature base construction (RFC 9421 §2.5)
  component-ids.ts      # Component identifier resolution (RFC 9421 §2.1)
  content-digest.ts     # Content-Digest generation (RFC 9530)
  serialization.ts      # Signature-Input header serialization (RFC 9421 §4.1)
  gnap-profile.ts       # GNAP-specific signing profile (RFC 9635 §7.3.3)
  types.ts              # TypeScript interfaces
tests/
  signer.test.ts        # Signing round-trip tests
  verifier.test.ts      # Verification + all algorithms
  signature-base.test.ts # Component resolution + base construction
  gnap-profile.test.ts  # GNAP/Open Payments scenarios
  fixtures/             # RFC 9421 test vectors
```

## Key Areas for Contribution

### 🔴 High Priority

- **RFC 9421 Appendix B test vectors** — Validate our signature base construction against the official test messages from the RFC appendix
- **`@interledger/http-signature-utils` interop** — Ensure our signatures can be verified by the Interledger Foundation's existing library and vice versa
- **Express/Koa middleware** — Server-side middleware for verifying incoming signed requests

### 🟡 Medium Priority

- **HMAC-SHA256 support** — RFC 9421 §3.3.3 symmetric algorithm (for service-to-service auth)
- **JWK key import** — Load keys from JWK format (important for GNAP key publication)
- **Multiple signatures** — RFC 9421 §4.3 support for multiple independent signatures on a single message
- **Response signing** — Sign HTTP responses (currently only requests)

### 🟢 Nice to Have

- **Performance benchmarks** — Compare signing/verification throughput across algorithms
- **Browser/Deno support** — WebCrypto API compatibility layer
- **Structured field parsing** — RFC 8941 strict serialization for headers (§2.1.1)

## Code Style

- **TypeScript strict mode** — All code must pass `tsc --strict`
- **Zero runtime dependencies** — Use only Node.js built-in modules (`crypto`, `buffer`)
- **JSDoc comments** — Document all public functions with RFC section references
- **Constant-time operations** — Use `crypto.timingSafeEqual` for all comparisons involving secrets

## RFC Compliance

When implementing features, always reference the specific RFC section:

| RFC | Sections We Implement |
|-----|----------------------|
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) | §2.1 (Fields), §2.2 (Derived), §2.5 (Base), §3.1 (Sign), §3.2 (Verify), §4.1 (Signature-Input) |
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) | §2 (Content-Digest) |
| [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635) | §7.3.3 (httpsig proof method) |

## Testing

- All new features must have corresponding tests
- Use `generateKeyPairSync` for test keys — never commit real keys
- Test both the happy path and error cases
- For algorithm-specific tests, verify round-trip (sign → verify → true) and cross-key rejection (sign with key A → verify with key B → false)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
