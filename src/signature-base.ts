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


