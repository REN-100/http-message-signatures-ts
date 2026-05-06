/**
 * HTTP Signature Verification Middleware
 *
 * Framework-agnostic middleware for verifying HTTP Message Signatures
 * on incoming requests. Works with Express, Koa, Fastify, or any
 * Node.js HTTP server that uses (req, res, next) convention.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.2
 */

import { verifySignature } from './verifier';
import type { Verifier, MiddlewareOptions } from './types';

/**
 * Create an Express/Connect-style middleware that verifies HTTP Message Signatures.
 *
 * The middleware:
 * 1. Extracts Signature and Signature-Input headers from the request
 * 2. Reconstructs the request context (method, url, headers, body)
 * 3. Calls `verifySignature` with the provided verifier
 * 4. Calls `next()` on success, or responds with 401 on failure
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { createSignatureMiddleware, createVerifier } from '@shujaapay/http-message-signatures';
 *
 * const verifier = createVerifier({
 *   keyId: 'client-key',
 *   algorithm: 'ed25519',
 *   publicKey: clientPublicKeyPem,
 * });
 *
 * const app = express();
 * app.use(express.json());
 * app.use(createSignatureMiddleware({ verifier }));
 *
 * app.post('/incoming-payments', (req, res) => {
 *   res.json({ status: 'ok' }); // Only reached if signature is valid
 * });
 * ```
 *
 * @example
 * ```ts
 * // Dynamic verifier — resolve key by keyId from a JWKS endpoint
 * app.use(createSignatureMiddleware({
 *   verifier: async (keyId) => {
 *     const jwk = await fetchJwkByKeyId(keyId);
 *     return createVerifier({ keyId, algorithm: 'ed25519', publicKey: importPublicJwk(jwk) });
 *   },
 *   maxAge: 300,
 * }));
 * ```
 */
export function createSignatureMiddleware(options: MiddlewareOptions) {
  const { verifier, maxAge = 300, label, onError } = options;

  return async (req: any, res: any, next: any) => {
    try {
      // Build the full URL from the request
      const protocol = req.protocol || (req.socket?.encrypted ? 'https' : 'http');
      const host = req.headers?.host || req.hostname || 'localhost';
      const url = `${protocol}://${host}${req.originalUrl || req.url}`;

      // Flatten headers to Record<string, string>
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers || {})) {
        headers[key] = Array.isArray(value) ? value.join(', ') : (value as string);
      }

      // Get body — Express stores it in req.body after bodyParser
      let body: string | Buffer | undefined;
      if (req.body !== undefined) {
        if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
          body = req.body;
        } else {
          body = JSON.stringify(req.body);
        }
      }

      // Resolve the verifier (may be static or dynamic by keyId)
      let resolvedVerifier: Verifier;
      if (typeof verifier === 'function') {
        // Extract keyId from Signature-Input header
        const sigInput = headers['signature-input'];
        if (!sigInput) {
          throw new Error('Missing Signature-Input header');
        }
        const keyIdMatch = sigInput.match(/;keyid="([^"]+)"/);
        if (!keyIdMatch) {
          throw new Error('Missing keyid in Signature-Input');
        }
        resolvedVerifier = await verifier(keyIdMatch[1]);
      } else {
        resolvedVerifier = verifier;
      }

      // Verify the signature
      const isValid = await verifySignature({
        method: req.method,
        url,
        headers,
        body,
        verifier: resolvedVerifier,
        maxAge,
        label,
      });

      if (!isValid) {
        throw new Error('Invalid HTTP Message Signature');
      }

      next();
    } catch (error: any) {
      if (onError) {
        onError(req, res, error);
      } else {
        // Default: 401 Unauthorized
        if (typeof res.status === 'function') {
          // Express
          res.status(401).json({
            error: 'Unauthorized',
            message: 'HTTP signature verification failed',
          });
        } else if (typeof res.writeHead === 'function') {
          // Raw Node.js http
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Unauthorized',
            message: 'HTTP signature verification failed',
          }));
        }
      }
    }
  };
}
