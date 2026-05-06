/**
 * Signature-Input Serialization — RFC 9421 §4.1
 *
 * Handles serialization and deserialization of the `Signature-Input` HTTP header,
 * which describes the covered components and parameters of a signature.
 * Supports both single and multiple signatures on the same message (§4.3).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-4.1
 */

import type { CoveredComponent, SignatureParams, ParsedSignatureInput } from './types';

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
 */
export function serializeSignatureInput(
  label: string,
  components: CoveredComponent[],
  params: SignatureParams
): string {
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
 * Parse a single Signature-Input header value into its constituent parts.
 *
 * Handles: `label=("comp1" "comp2");param1=value1;param2="value2"`
 */
export function parseSignatureInput(input: string): ParsedSignatureInput {
  const eqIndex = input.indexOf('=(');
  if (eqIndex === -1) {
    // Fallback: try first '=' for simple cases
    const fallbackEq = input.indexOf('=');
    if (fallbackEq === -1) {
      throw new Error(`Invalid Signature-Input: missing '=' separator`);
    }
    return parseSingleEntry(input.substring(0, fallbackEq).trim(), input.substring(fallbackEq + 1).trim());
  }

  const label = input.substring(0, eqIndex).trim();
  const rest = input.substring(eqIndex + 1).trim();
  return parseSingleEntry(label, rest);
}

/**
 * Parse a Signature-Input header that may contain multiple labeled signatures.
 *
 * RFC 9421 §4.3: Multiple signatures can be present on the same message,
 * each with a unique label. The Signature-Input header contains comma-separated
 * dictionary members.
 *
 * @param input - The full Signature-Input header value
 * @returns Array of parsed signature entries
 *
 * @example
 * ```ts
 * const sigs = parseMultipleSignatureInputs(
 *   'sig1=("@method" "@target-uri");created=1000, sig2=("@method");created=2000'
 * );
 * // Returns 2 entries: sig1 and sig2
 * ```
 */
export function parseMultipleSignatureInputs(input: string): ParsedSignatureInput[] {
  const results: ParsedSignatureInput[] = [];

  // Split on commas that are NOT inside parentheses
  // This handles: sig1=("a" "b");p=1, sig2=("c");p=2
  const entries = splitDictionaryMembers(input);

  for (const entry of entries) {
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;
    results.push(parseSignatureInput(trimmed));
  }

  return results;
}

/**
 * Split a Structured Field Dictionary into its members.
 * Splits on commas that are outside of parentheses and quotes.
 */
function splitDictionaryMembers(input: string): string[] {
  const members: string[] = [];
  let depth = 0;
  let inQuote = false;
  let current = '';

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (ch === '"' && input[i - 1] !== '\\') {
      inQuote = !inQuote;
    } else if (!inQuote) {
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      else if (ch === ',' && depth === 0) {
        members.push(current);
        current = '';
        continue;
      }
    }

    current += ch;
  }

  if (current.trim().length > 0) {
    members.push(current);
  }

  return members;
}

/**
 * Parse a single dictionary member value: ("comp1" "comp2");param1=val
 */
function parseSingleEntry(label: string, rest: string): ParsedSignatureInput {
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
