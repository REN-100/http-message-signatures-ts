/**
 * RFC 9421 Appendix B — Test Message Fixture
 *
 * This fixture contains the example HTTP message from RFC 9421 Appendix B.1,
 * used throughout the appendix examples for signature base construction.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#appendix-B.1
 */

/**
 * The example HTTP request from RFC 9421 Appendix B.1.
 *
 * POST /foo?param=Value&Pet=dog HTTP/1.1
 * Host: example.com
 * Date: Tue, 20 Apr 2021 02:07:55 GMT
 * Content-Type: application/json
 * Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
 * Content-Length: 18
 */
export const RFC9421_TEST_REQUEST = {
  method: 'POST',
  url: 'https://example.com/foo?param=Value&Pet=dog',
  headers: {
    'host': 'example.com',
    'date': 'Tue, 20 Apr 2021 02:07:55 GMT',
    'content-type': 'application/json',
    'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
    'content-length': '18',
  },
  body: '{"hello": "world"}',
};

/**
 * Expected signature base for Appendix B.2.1 — Minimal Signature Using
 * rsa-pss-sha512 with covered components: (@method, @target-uri)
 *
 * The expected string is:
 * "@method": POST
 * "@target-uri": https://example.com/foo?param=Value&Pet=dog
 * "@signature-params": ("@method" "@target-uri");created=1618884473;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"
 */
export const EXPECTED_MINIMAL_BASE =
  '"@method": POST\n' +
  '"@target-uri": https://example.com/foo?param=Value&Pet=dog\n' +
  '"@signature-params": ("@method" "@target-uri");created=1618884473;alg="rsa-pss-sha512";keyid="test-key-rsa-pss"';

/**
 * Expected signature base for a more complete set of covered components:
 * (@method, @authority, @path, content-digest, content-type, content-length)
 */
export const EXPECTED_SELECTIVE_BASE =
  '"@method": POST\n' +
  '"@authority": example.com\n' +
  '"@path": /foo\n' +
  '"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n' +
  '"content-type": application/json\n' +
  '"content-length": 18\n' +
  '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884473;keyid="test-key-rsa-pss"';

/**
 * Expected signature base for all derived components test:
 * (@method, @target-uri, @authority, @scheme, @path, @query)
 */
export const EXPECTED_DERIVED_BASE =
  '"@method": POST\n' +
  '"@target-uri": https://example.com/foo?param=Value&Pet=dog\n' +
  '"@authority": example.com\n' +
  '"@scheme": https\n' +
  '"@path": /foo\n' +
  '"@query": ?param=Value&Pet=dog\n' +
  '"@signature-params": ("@method" "@target-uri" "@authority" "@scheme" "@path" "@query");created=1618884473;keyid="test-key"';
