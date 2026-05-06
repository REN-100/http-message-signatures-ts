/**
 * Signature-Input Serialization — RFC 9421 Section 4.1
 *
 * Handles serialization and deserialization of the `Signature-Input` HTTP header,
 * which describes the covered components and parameters of a signature.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-4.1
 */

import type { CoveredComponent, SignatureParams } from './types';

/**
 * Serialize a Signature-Input header value.
 *
 * Produces a Structured Field Dictionary member with inner-list value:
 * `label=("@method" "@target-uri" "content-type");created=1618884473;keyid="test-key"`
 *
 * @param label - Signature label (e.g., 'sig', 'sig1')
 * @param components - Covered component identifiers
 * @param params - Signature parameters
 * @returns Formatted Signature-Input header value
 *
 * @example
 * ```ts
 * const input = serializeSignatureInput('sig', ['@method', '@target-uri'], {
 *   created: 1618884473,
 *   keyid: 'test-key',
 *   alg: 'ed25519',
 * });
 * // => 'sig=("@method" "@target-uri");created=1618884473;keyid="test-key";alg="ed25519"'
 * ```
 */
export function serializeSignatureInput(
  label: string,
  components: CoveredComponent[],
  params: SignatureParams
): string {
  // Build the inner list of component identifiers
  const componentList = components
    .map((c) => `"${c.toLowerCase()}"`)
    .join(' ');

  let result = `${label}=(${componentList})`;

  // Append parameters in canonical order (RFC 9421 §2.3)
  if (params.created !== undefined) {
    result += `;created=${params.created}`;
  }
  if (params.expires !== undefined) {
    result += `;expires=${params.expires}`;
  }
  if (params.nonce !== undefined) {
    result += `;nonce="${params.nonce}"`;
  }
  if (params.alg !== undefined) {
    result += `;alg="${params.alg}"`;
  }
  if (params.keyid !== undefined) {
    result += `;keyid="${params.keyid}"`;
  }
  if (params.tag !== undefined) {
    result += `;tag="${params.tag}"`;
  }

  return result;
}

/**
 * Parse a Signature-Input header value back into its constituent parts.
 *
 * Handles the format: `label=("comp1" "comp2");param1=value1;param2="value2"`
 *
 * @param input - The raw Signature-Input header value
 * @returns Parsed label, covered components, and signature parameters
 *
 * @example
 * ```ts
 * const { label, coveredComponents, params } = parseSignatureInput(
 *   'sig=("@method" "@target-uri");created=1618884473;keyid="test-key"'
 * );
 * // label => 'sig'
 * // coveredComponents => ['@method', '@target-uri']
 * // params => { created: 1618884473, keyid: 'test-key' }
 * ```
 */
export function parseSignatureInput(input: string): {
  label: string;
  coveredComponents: string[];
  params: SignatureParams;
} {
  // Split label from value at the first '='
  const eqIndex = input.indexOf('=');
  if (eqIndex === -1) {
    throw new Error(`Invalid Signature-Input: missing '=' separator`);
  }
  const label = input.substring(0, eqIndex).trim();
  const rest = input.substring(eqIndex + 1).trim();

  // Extract the inner list: (...)
  const listStart = rest.indexOf('(');
  const listEnd = rest.indexOf(')');
  if (listStart === -1 || listEnd === -1 || listEnd <= listStart) {
    throw new Error('Invalid Signature-Input: missing component list');
  }

  const componentStr = rest.substring(listStart + 1, listEnd);
  const coveredComponents = componentStr
    .split(/\s+/)
    .filter((s) => s.length > 0)
    .map((s) => s.replace(/"/g, ''));

  // Parse parameters after the closing paren
  const paramStr = rest.substring(listEnd + 1);
  const params: SignatureParams = {};

  const createdMatch = paramStr.match(/;created=(\d+)/);
  if (createdMatch) params.created = parseInt(createdMatch[1], 10);

  const expiresMatch = paramStr.match(/;expires=(\d+)/);
  if (expiresMatch) params.expires = parseInt(expiresMatch[1], 10);

  const nonceMatch = paramStr.match(/;nonce="([^"]+)"/);
  if (nonceMatch) params.nonce = nonceMatch[1];

  const algMatch = paramStr.match(/;alg="([^"]+)"/);
  if (algMatch) params.alg = algMatch[1];

  const keyidMatch = paramStr.match(/;keyid="([^"]+)"/);
  if (keyidMatch) params.keyid = keyidMatch[1];

  const tagMatch = paramStr.match(/;tag="([^"]+)"/);
  if (tagMatch) params.tag = tagMatch[1];

  return { label, coveredComponents, params };
}
