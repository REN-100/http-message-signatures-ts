/**
 * Tests for Signature Base Construction — RFC 9421 §2.5
 */

import { buildSignatureBase, resolveComponent } from '../src';

describe('Component Identifier Resolution (RFC 9421 §2.1–§2.2)', () => {
  const context = {
    method: 'POST',
    url: 'https://wallet.example.com/payments?status=active',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'GNAP token123',
    },
  };

  test('@method resolves to uppercase method', () => {
    expect(resolveComponent('@method', context)).toBe('POST');
  });

  test('@target-uri resolves to full URL', () => {
    expect(resolveComponent('@target-uri', context)).toBe(
      'https://wallet.example.com/payments?status=active'
    );
  });

  test('@authority resolves to host', () => {
    expect(resolveComponent('@authority', context)).toBe('wallet.example.com');
  });

  test('@scheme resolves to protocol without colon', () => {
    expect(resolveComponent('@scheme', context)).toBe('https');
  });

  test('@request-target resolves to path+query', () => {
    expect(resolveComponent('@request-target', context)).toBe('/payments?status=active');
  });

  test('@path resolves to pathname', () => {
    expect(resolveComponent('@path', context)).toBe('/payments');
  });

  test('@query resolves to search string', () => {
    expect(resolveComponent('@query', context)).toBe('?status=active');
  });

  test('@query with no search params returns "?"', () => {
    const ctx = { method: 'GET', url: 'https://example.com/', headers: {} };
    expect(resolveComponent('@query', ctx)).toBe('?');
  });

  test('header field resolves case-insensitively', () => {
    expect(resolveComponent('content-type', context)).toBe('application/json');
    expect(resolveComponent('authorization', context)).toBe('GNAP token123');
  });

  test('missing header returns undefined', () => {
    expect(resolveComponent('x-nonexistent', context)).toBeUndefined();
  });
});

describe('Signature Base Construction (RFC 9421 §2.5)', () => {
  test('builds correct base string with all component types', () => {
    const base = buildSignatureBase(
      ['@method', '@target-uri', 'content-type'],
      { created: 1618884473, keyid: 'test-key', alg: 'ed25519' },
      {
        method: 'POST',
        url: 'https://example.com/resource',
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const lines = base.split('\n');
    expect(lines[0]).toBe('"@method": POST');
    expect(lines[1]).toBe('"@target-uri": https://example.com/resource');
    expect(lines[2]).toBe('"content-type": application/json');
    expect(lines[3]).toContain('"@signature-params":');
    expect(lines[3]).toContain('("@method" "@target-uri" "content-type")');
    expect(lines[3]).toContain('created=1618884473');
    expect(lines[3]).toContain('keyid="test-key"');
    expect(lines[3]).toContain('alg="ed25519"');
  });

  test('handles minimal component list', () => {
    const base = buildSignatureBase(
      ['@method'],
      { created: 1000 },
      { method: 'GET', url: 'https://example.com/', headers: {} }
    );

    const lines = base.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe('"@method": GET');
    expect(lines[1]).toContain('("@method")');
  });

  test('throws on unresolvable component', () => {
    expect(() =>
      buildSignatureBase(
        ['x-missing-header'],
        {},
        { method: 'GET', url: 'https://example.com/', headers: {} }
      )
    ).toThrow('Cannot resolve');
  });

  test('includes optional params (expires, nonce, tag)', () => {
    const base = buildSignatureBase(
      ['@method'],
      { created: 1000, expires: 2000, nonce: 'abc', tag: 'gnap' },
      { method: 'GET', url: 'https://example.com/', headers: {} }
    );

    expect(base).toContain('expires=2000');
    expect(base).toContain('nonce="abc"');
    expect(base).toContain('tag="gnap"');
  });
});
