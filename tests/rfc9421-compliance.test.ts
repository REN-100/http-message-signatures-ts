/**
 * RFC 9421 Compliance Tests
 *
 * Tests against the canonical examples from RFC 9421 Appendix B
 * to verify our signature base construction matches the specification.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#appendix-B
 */

import { buildSignatureBase, resolveComponent } from '../src';
import {
  RFC9421_TEST_REQUEST,
  EXPECTED_MINIMAL_BASE,
  EXPECTED_SELECTIVE_BASE,
  EXPECTED_DERIVED_BASE,
} from './fixtures/rfc9421-test-messages';

describe('RFC 9421 Appendix B — Test Message Component Resolution', () => {
  const ctx = RFC9421_TEST_REQUEST;

  test('@method resolves to POST', () => {
    expect(resolveComponent('@method', ctx)).toBe('POST');
  });

  test('@target-uri resolves to full URL with query', () => {
    expect(resolveComponent('@target-uri', ctx)).toBe(
      'https://example.com/foo?param=Value&Pet=dog'
    );
  });

  test('@authority resolves to example.com', () => {
    expect(resolveComponent('@authority', ctx)).toBe('example.com');
  });

  test('@scheme resolves to https', () => {
    expect(resolveComponent('@scheme', ctx)).toBe('https');
  });

  test('@path resolves to /foo', () => {
    expect(resolveComponent('@path', ctx)).toBe('/foo');
  });

  test('@query resolves to ?param=Value&Pet=dog', () => {
    expect(resolveComponent('@query', ctx)).toBe('?param=Value&Pet=dog');
  });

  test('content-type header resolves', () => {
    expect(resolveComponent('content-type', ctx)).toBe('application/json');
  });

  test('content-digest header resolves', () => {
    expect(resolveComponent('content-digest', ctx)).toBe(
      'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:'
    );
  });

  test('content-length header resolves', () => {
    expect(resolveComponent('content-length', ctx)).toBe('18');
  });
});

describe('RFC 9421 Appendix B — Signature Base Construction', () => {
  const ctx = RFC9421_TEST_REQUEST;

  test('B.2.1: Minimal signature base (@method, @target-uri)', () => {
    const base = buildSignatureBase(
      ['@method', '@target-uri'],
      { created: 1618884473, keyid: 'test-key-rsa-pss', alg: 'rsa-pss-sha512' },
      ctx
    );
    expect(base).toBe(EXPECTED_MINIMAL_BASE);
  });

  test('B.2.2: Selective covered components', () => {
    const base = buildSignatureBase(
      ['@method', '@authority', '@path', 'content-digest', 'content-type', 'content-length'],
      { created: 1618884473, keyid: 'test-key-rsa-pss' },
      ctx
    );
    expect(base).toBe(EXPECTED_SELECTIVE_BASE);
  });

  test('All derived components', () => {
    const base = buildSignatureBase(
      ['@method', '@target-uri', '@authority', '@scheme', '@path', '@query'],
      { created: 1618884473, keyid: 'test-key' },
      ctx
    );
    expect(base).toBe(EXPECTED_DERIVED_BASE);
  });
});

describe('RFC 9421 — Content-Digest verification', () => {
  test('test message Content-Digest is valid sha-256', () => {
    const { verifyContentDigest } = require('../src');
    const isValid = verifyContentDigest(
      RFC9421_TEST_REQUEST.body,
      RFC9421_TEST_REQUEST.headers['content-digest']
    );
    expect(isValid).toBe(true);
  });
});
