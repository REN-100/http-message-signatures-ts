/**
 * Component Identifier Resolution — RFC 9421 §2.1–§2.2
 *
 * Resolves component identifiers (both derived and header-based)
 * to their values for inclusion in the signature base.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-2.1
 */

import { CoveredComponent } from './types';

/**
 * HTTP message context for component resolution.
 *
 * For request messages: method, url, headers
 * For response messages: add statusCode
 */
export interface ComponentContext {
  method: string;
  url: string;
  headers: Record<string, string>;
  /** HTTP status code — required for @status component (response signing) */
  statusCode?: number;
}

/**
 * Resolve a component identifier to its value.
 *
 * Derived components (starting with @) are computed from the request/response context.
 * Other identifiers are looked up as HTTP header field names.
 *
 * @param component - The component identifier (e.g., '@method', 'content-type')
 * @param context - The HTTP message context
 * @returns The resolved value, or undefined if not found
 */
export function resolveComponent(
  component: CoveredComponent,
  context: ComponentContext
): string | undefined {
  // Derived components (RFC 9421 §2.2)
  if (component.startsWith('@')) {
    return resolveDerivedComponent(component, context);
  }

  // Header field components (RFC 9421 §2.1)
  return resolveHeaderComponent(component, context.headers);
}

/**
 * Resolve derived component identifiers.
 *
 * RFC 9421 §2.2: These are special identifiers that derive their values
 * from the HTTP message rather than from a specific header field.
 */
function resolveDerivedComponent(
  component: string,
  context: ComponentContext
): string | undefined {
  const parsed = new URL(context.url);

  switch (component) {
    case '@method':
      // §2.2.1: Uppercase method
      return context.method.toUpperCase();

    case '@target-uri':
      // §2.2.2: Full target URI
      return context.url;

    case '@authority':
      // §2.2.3: Host (lowercase)
      return parsed.host;

    case '@scheme':
      // §2.2.4: URI scheme without trailing colon
      return parsed.protocol.replace(':', '');

    case '@request-target':
      // §2.2.5: Request target (path + query)
      return `${parsed.pathname}${parsed.search}`;

    case '@path':
      // §2.2.6: URI path
      return parsed.pathname;

    case '@query':
      // §2.2.7: Query string including '?'. If no query, value is '?'.
      return parsed.search || '?';

    case '@status':
      // §2.2.8: HTTP status code (for response signing)
      if (context.statusCode === undefined) {
        return undefined;
      }
      return String(context.statusCode);

    default:
      // @query-param;name="key" syntax (§2.2.8)
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
 * for lookup. Values are trimmed of leading/trailing whitespace
 * and inner whitespace is normalized to single spaces (RFC 9421 §2.1).
 */
function resolveHeaderComponent(
  component: string,
  headers: Record<string, string>
): string | undefined {
  const normalized = component.toLowerCase();

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === normalized) {
      return value.trim().replace(/\s+/g, ' ');
    }
  }

  return undefined;
}

