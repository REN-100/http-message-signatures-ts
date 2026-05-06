/**
 * Signature Base Construction - RFC 9421 Section 2.5
 * 
 * The signature base is the string that gets signed. It is constructed from
 * the covered components and signature parameters.
 */

import { CoveredComponent, SignatureParams } from './types';
import { resolveComponent } from './component-ids';

/**
 * Build the signature base string per RFC 9421 Section 2.5.
 * 
 * The signature base is a concatenation of covered component lines,
 * each terminated by a newline, followed by the @signature-params line.
 * 
 * @example
 * ```
 * "@method": POST
 * "@target-uri": https://example.com/resource
 * "content-type": application/json
 * "@signature-params": ("@method" "@target-uri" "content-type");created=1618884473;keyid="test-key"
 * ```
 */
export function buildSignatureBase(
  coveredComponents: CoveredComponent[],
  params: SignatureParams,
  context: {
    method: string;
    url: string;
    headers: Record<string, string>;
  }
): string {
  const lines: string[] = [];

  // Process each covered component
  for (const component of coveredComponents) {
    const value = resolveComponent(component, context);
    if (value === undefined) {
      throw new Error(`Cannot resolve covered component: ${component}`);
    }
    
    // Component identifiers are lowercased and quoted
    const identifier = component.startsWith('@')
      ? `"${component}"`
      : `"${component.toLowerCase()}"`;
    
    lines.push(`${identifier}: ${value}`);
  }

  // Build the @signature-params value
  const componentList = coveredComponents
    .map(c => `"${c.toLowerCase()}"`)
    .join(' ');
  
  let sigParams = `(${componentList})`;
  
  if (params.created !== undefined) {
    sigParams += `;created=${params.created}`;
  }
  if (params.expires !== undefined) {
    sigParams += `;expires=${params.expires}`;
  }
  if (params.nonce !== undefined) {
    sigParams += `;nonce="${params.nonce}"`;
  }
  if (params.alg !== undefined) {
    sigParams += `;alg="${params.alg}"`;
  }
  if (params.keyid !== undefined) {
    sigParams += `;keyid="${params.keyid}"`;
  }
  if (params.tag !== undefined) {
    sigParams += `;tag="${params.tag}"`;
  }

  lines.push(`"@signature-params": ${sigParams}`);

  return lines.join('\n');
}

/**
 * Parse a Signature-Input header value into its components and parameters.
 * 
 * @param input - The Signature-Input header value (e.g., 'sig=("@method" "@target-uri");created=1618884473')
 * @returns Parsed covered components and parameters
 */
export function parseSignatureBase(input: string): {
  label: string;
  coveredComponents: string[];
  params: SignatureParams;
} {
  // Parse label
  const labelEnd = input.indexOf('=');
  if (labelEnd === -1) throw new Error('Invalid Signature-Input: missing label');
  const label = input.substring(0, labelEnd);
  
  const rest = input.substring(labelEnd + 1);
  
  // Parse component list
  const listStart = rest.indexOf('(');
  const listEnd = rest.indexOf(')');
  if (listStart === -1 || listEnd === -1) {
    throw new Error('Invalid Signature-Input: missing component list');
  }
  
  const componentStr = rest.substring(listStart + 1, listEnd);
  const coveredComponents = componentStr
    .split(/\s+/)
    .filter(s => s.length > 0)
    .map(s => s.replace(/"/g, ''));
  
  // Parse parameters
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
