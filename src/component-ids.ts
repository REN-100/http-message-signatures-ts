/**
 * Component Identifier Resolution - RFC 9421 Section 2.1
 * 
 * Resolves component identifiers (both derived and header-based)
 * to their values for inclusion in the signature base.
 */

import { CoveredComponent } from './types';

/**
 * Resolve a component identifier to its value.
 * 
 * Derived components (starting with @) are computed from the request context.
 * Other identifiers are looked up as HTTP header field names.
 * 
 * @param component - The component identifier
 * @param context - The HTTP request context
 * @returns The resolved value, or undefined if not found
 */
export function resolveComponent(
  component: CoveredComponent,
  context: {
    method: string;
    url: string;
    headers: Record<string, string>;
  }
): string | undefined {
  // Derived components (RFC 9421 Section 2.2)
  if (component.startsWith('@')) {
    return resolveDerivedComponent(component, context);
  }

  // Header field components (RFC 9421 Section 2.1)
  return resolveHeaderComponent(component, context.headers);
}

/**
 * Resolve derived component identifiers.
 * 
 * These are special identifiers that derive their values from the
 * HTTP message rather than from a specific header field.
 */
function resolveDerivedComponent(
  component: string,
  context: { method: string; url: string; headers: Record<string, string> }
): string | undefined {
  const parsed = new URL(context.url);

  switch (component) {
    case '@method':
      return context.method.toUpperCase();

    case '@target-uri':
      return context.url;

    case '@authority':
      return parsed.host;

    case '@scheme':
      return parsed.protocol.replace(':', '');

    case '@request-target':
      return `${parsed.pathname}${parsed.search}`;

    case '@path':
      return parsed.pathname;

    case '@query':
      return parsed.search || '?';

    default:
      // Check for @query-param;name="key" syntax
      if (component.startsWith('@query-param')) {
        const nameMatch = component.match(/;name="([^"]+)"/);
        if (nameMatch) {
          return parsed.searchParams.get(nameMatch[1]) || undefined;
        }
      }
      return undefined;
  }
}

/**
 * Resolve a header field component.
 * 
 * Header names are case-insensitive, so we normalize to lowercase
 * for lookup. Values are trimmed of leading/trailing whitespace.
 */
function resolveHeaderComponent(
  component: string,
  headers: Record<string, string>
): string | undefined {
  const normalized = component.toLowerCase();
  
  // Case-insensitive header lookup
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === normalized) {
      // Trim and normalize whitespace per RFC 9421 Section 2.1
      return value.trim().replace(/\s+/g, ' ');
    }
  }

  return undefined;
}
