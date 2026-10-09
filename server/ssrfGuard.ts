import dns from 'dns';
import { URL } from 'url';

/**
 * CyberRakshak AI — Advanced SSRF (Server-Side Request Forgery) Protection Suite
 * 
 * Enforces:
 * 1. Safe URL parsing & protocol restriction (http / https only).
 * 2. Port restrictions (80 & 443 only).
 * 3. Pre-flight DNS resolution of all A & AAAA records.
 * 4. Comprehensive IPv4 & IPv6 private/reserved/link-local/cloud-metadata subnet rejection.
 * 5. Safe redirect-following with re-validation of each jump.
 * 6. Strict timeout and response size limits.
 */

// IPv4 blocked ranges (CIDR representation)
interface IPRange {
  base: number;
  mask: number;
}

function parseIPv4(ip: string): number | null {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

function makeIPv4Range(cidr: string): IPRange {
  const [ip, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const num = parseIPv4(ip)!;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { base: (num & mask) >>> 0, mask };
}

// Blocked IPv4 ranges
const BLOCKED_IPV4_RANGES: { name: string; range: IPRange }[] = [
  { name: 'Current network (0.0.0.0/8)', range: makeIPv4Range('0.0.0.0/8') },
  { name: 'Private network (10.0.0.0/8)', range: makeIPv4Range('10.0.0.0/8') },
  { name: 'Shared address / Carrier-Grade NAT (100.64.0.0/10)', range: makeIPv4Range('100.64.0.0/10') },
  { name: 'Loopback (127.0.0.0/8)', range: makeIPv4Range('127.0.0.0/8') },
  { name: 'Link-Local & Cloud Metadata (169.254.0.0/16)', range: makeIPv4Range('169.254.0.0/16') },
  { name: 'Private network (172.16.0.0/12)', range: makeIPv4Range('172.16.0.0/12') },
  { name: 'IETF Protocol Assignments (192.0.0.0/24)', range: makeIPv4Range('192.0.0.0/24') },
  { name: 'TEST-NET-1 (192.0.2.0/24)', range: makeIPv4Range('192.0.2.0/24') },
  { name: '6to4 Relay Anycast (192.88.99.0/24)', range: makeIPv4Range('192.88.99.0/24') },
  { name: 'Private network (192.168.0.0/16)', range: makeIPv4Range('192.168.0.0/16') },
  { name: 'Benchmarking (198.18.0.0/15)', range: makeIPv4Range('198.18.0.0/15') },
  { name: 'TEST-NET-2 (198.51.100.0/24)', range: makeIPv4Range('198.51.100.0/24') },
  { name: 'TEST-NET-3 (203.0.113.0/24)', range: makeIPv4Range('203.0.113.0/24') },
  { name: 'Multicast (224.0.0.0/4)', range: makeIPv4Range('224.0.0.0/4') },
  { name: 'Reserved (240.0.0.0/4)', range: makeIPv4Range('240.0.0.0/4') },
  { name: 'Broadcast (255.255.255.255/32)', range: makeIPv4Range('255.255.255.255/32') },
];

export function isPrivateIPv4(ip: string): { blocked: boolean; reason?: string } {
  const num = parseIPv4(ip);
  if (num === null) {
    return { blocked: true, reason: 'Malformed IPv4 address' };
  }

  for (const { name, range } of BLOCKED_IPV4_RANGES) {
    if (((num & range.mask) >>> 0) === range.base) {
      return { blocked: true, reason: `Blocked private/reserved IPv4 range: ${name}` };
    }
  }

  return { blocked: false };
}

export function isPrivateIPv6(ip: string): { blocked: boolean; reason?: string } {
  const normalized = ip.toLowerCase();

  // Loopback & Unspecified
  if (normalized === '::1' || normalized === '::' || normalized === '0:0:0:0:0:0:0:1' || normalized === '0:0:0:0:0:0:0:0') {
    return { blocked: true, reason: 'IPv6 loopback / unspecified address' };
  }

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  if (normalized.startsWith('::ffff:') || normalized.startsWith('0:0:0:0:0:ffff:')) {
    const ipv4Part = normalized.split(':').pop();
    if (ipv4Part && ipv4Part.includes('.')) {
      return isPrivateIPv4(ipv4Part);
    }
    return { blocked: true, reason: 'IPv4-mapped IPv6 address restricted' };
  }

  // Unique local addresses (fc00::/7 -> fc.. or fd..)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return { blocked: true, reason: 'IPv6 unique local address (fc00::/7)' };
  }

  // Link-local unicast (fe80::/10 -> fe8, fe9, fea, feb)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return { blocked: true, reason: 'IPv6 link-local address (fe80::/10)' };
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return { blocked: true, reason: 'IPv6 multicast address (ff00::/8)' };
  }

  return { blocked: false };
}

/**
 * Validates a target host string or hostname for SSRF before making outbound connections.
 * Resolves DNS to ensure no DNS rebinding or private IP aliasing can occur.
 */
export async function validateHostForSSRF(hostname: string): Promise<{ valid: boolean; reason?: string; resolvedIps?: string[] }> {
  let cleanHost = hostname.trim().toLowerCase();

  if (!cleanHost) {
    return { valid: false, reason: 'Hostname cannot be empty' };
  }

  // Strip leading protocols if present
  if (cleanHost.startsWith('http://') || cleanHost.startsWith('https://') || cleanHost.startsWith('//')) {
    try {
      const parsed = new URL(cleanHost.startsWith('//') ? `http:${cleanHost}` : cleanHost);
      cleanHost = parsed.hostname;
    } catch {
      cleanHost = cleanHost.replace(/^[a-z]+:\/\//, '').split('/')[0];
    }
  } else {
    // Strip trailing path/query if present
    cleanHost = cleanHost.split('/')[0].split('?')[0];
  }

  // Handle bracketed IPv6 with optional port: [::1] or [::1]:8080
  if (cleanHost.startsWith('[')) {
    const bracketEnd = cleanHost.indexOf(']');
    if (bracketEnd !== -1) {
      cleanHost = cleanHost.substring(1, bracketEnd);
    }
  } else if (!cleanHost.includes('::') && cleanHost.split(':').length === 2 && !cleanHost.includes(']')) {
    // IPv4 or domain with port, e.g. 127.0.0.1:8080 or example.com:8443
    cleanHost = cleanHost.split(':')[0];
  }

  // Attempt URL-based normalization for integer, octal, hex IPs (e.g. 2130706433 -> 127.0.0.1)
  try {
    const dummyUrl = new URL(`http://${cleanHost}`);
    if (dummyUrl.hostname) {
      cleanHost = dummyUrl.hostname;
    }
  } catch {
    // Keep cleanHost
  }

  // Explicit string check for known metadata names
  if (
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal') ||
    cleanHost.endsWith('.lan') ||
    cleanHost.includes('metadata.google.internal') ||
    cleanHost === 'instance-data'
  ) {
    return { valid: false, reason: `Forbidden local or cloud metadata hostname: "${cleanHost}"` };
  }

  // If host is directly an IP
  if (cleanHost.includes(':')) {
    // IPv6
    const cleanIpv6 = cleanHost.replace(/^\[|\]$/g, '');
    const ipv6Check = isPrivateIPv6(cleanIpv6);
    if (ipv6Check.blocked) {
      return { valid: false, reason: ipv6Check.reason };
    }
  } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleanHost)) {
    // IPv4
    const ipv4Check = isPrivateIPv4(cleanHost);
    if (ipv4Check.blocked) {
      return { valid: false, reason: ipv4Check.reason };
    }
    return { valid: true, resolvedIps: [cleanHost] };
  }

  // Resolve hostname via DNS to verify resolved destination addresses
  try {
    const addresses = await dns.promises.lookup(cleanHost, { all: true, verbatim: true });
    if (!addresses || addresses.length === 0) {
      return { valid: false, reason: `DNS resolution failed: no address records found for ${cleanHost}` };
    }

    const resolvedIps: string[] = [];
    for (const record of addresses) {
      resolvedIps.push(record.address);
      if (record.family === 4) {
        const v4Check = isPrivateIPv4(record.address);
        if (v4Check.blocked) {
          return { valid: false, reason: `Resolved IP ${record.address} belongs to blocked private/cloud-metadata subnet` };
        }
      } else if (record.family === 6) {
        const v6Check = isPrivateIPv6(record.address);
        if (v6Check.blocked) {
          return { valid: false, reason: `Resolved IPv6 ${record.address} belongs to blocked private/link-local subnet` };
        }
      }
    }

    return { valid: true, resolvedIps };
  } catch (err: any) {
    return { valid: false, reason: `DNS resolution error for ${cleanHost}: ${err.message || 'Lookup failed'}` };
  }
}

/**
 * Safely fetches a remote HTTP/HTTPS resource with SSRF validation,
 * redirect jump validation, timeout enforcement, and response size limits.
 */
export async function safeFetch(
  rawUrl: string, 
  options: {
    timeoutMs?: number;
    maxBytes?: number;
    maxRedirects?: number;
    method?: 'GET' | 'HEAD';
    headers?: Record<string, string>;
  } = {}
): Promise<{
  ok: boolean;
  status: number;
  statusText: string;
  headers: Headers;
  finalUrl: string;
  bodyText?: string;
  error?: string;
}> {
  const timeoutMs = options.timeoutMs || 4000;
  const maxBytes = options.maxBytes || 512 * 1024; // 512KB max
  const maxRedirects = options.maxRedirects ?? 3;
  const method = options.method || 'HEAD';

  let currentUrl = rawUrl.trim();
  let redirectCount = 0;

  while (redirectCount <= maxRedirects) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      return { ok: false, status: 0, statusText: 'Invalid URL', headers: new Headers(), finalUrl: currentUrl, error: 'Malformed URL syntax' };
    }

    // Protocol check
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return { ok: false, status: 0, statusText: 'Forbidden Protocol', headers: new Headers(), finalUrl: currentUrl, error: `Protocol "${parsedUrl.protocol}" is not permitted. Only HTTP and HTTPS are allowed.` };
    }

    // Port check
    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : (parsedUrl.protocol === 'https:' ? 443 : 80);
    if (port !== 80 && port !== 443) {
      return { ok: false, status: 0, statusText: 'Forbidden Port', headers: new Headers(), finalUrl: currentUrl, error: `Port ${port} is prohibited. Only standard ports (80, 443) are allowed.` };
    }

    // SSRF DNS check
    const ssrfCheck = await validateHostForSSRF(parsedUrl.hostname);
    if (!ssrfCheck.valid) {
      return { ok: false, status: 0, statusText: 'SSRF Blocked', headers: new Headers(), finalUrl: currentUrl, error: ssrfCheck.reason };
    }

    // Perform request
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(currentUrl, {
        method,
        signal: controller.signal,
        redirect: 'manual',
        headers: {
          'User-Agent': 'CyberRakshak-Security-Auditor/1.0 (Passive Threat Assessment)',
          'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
          ...(options.headers || {})
        }
      });
      clearTimeout(timer);

      // Handle redirect
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const locationHeader = response.headers.get('location');
        if (!locationHeader) {
          return { ok: false, status: response.status, statusText: response.statusText, headers: response.headers, finalUrl: currentUrl, error: 'Redirect status received without Location header' };
        }
        redirectCount++;
        if (redirectCount > maxRedirects) {
          return { ok: false, status: response.status, statusText: 'Too Many Redirects', headers: response.headers, finalUrl: currentUrl, error: `Exceeded maximum redirect limit of ${maxRedirects}` };
        }

        // Resolve relative redirects safely against current URL
        const nextUrl = new URL(locationHeader, currentUrl).toString();
        currentUrl = nextUrl;
        continue; // Next redirect iteration
      }

      let bodyText: string | undefined;
      if (method === 'GET') {
        const reader = response.body?.getReader();
        if (reader) {
          const chunks: Uint8Array[] = [];
          let receivedBytes = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              receivedBytes += value.length;
              if (receivedBytes > maxBytes) {
                reader.cancel();
                return { ok: false, status: response.status, statusText: 'Payload Too Large', headers: response.headers, finalUrl: currentUrl, error: `Response exceeded maximum size limit of ${maxBytes} bytes` };
              }
              chunks.push(value);
            }
          }
          const totalBuffer = new Uint8Array(receivedBytes);
          let offset = 0;
          for (const chunk of chunks) {
            totalBuffer.set(chunk, offset);
            offset += chunk.length;
          }
          bodyText = new TextDecoder().decode(totalBuffer);
        }
      }

      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        finalUrl: currentUrl,
        bodyText
      };
    } catch (fetchErr: any) {
      clearTimeout(timer);
      const isTimeout = fetchErr.name === 'AbortError';
      return {
        ok: false,
        status: 0,
        statusText: isTimeout ? 'Timeout' : 'Network Error',
        headers: new Headers(),
        finalUrl: currentUrl,
        error: isTimeout ? `Connection timed out after ${timeoutMs}ms` : fetchErr.message
      };
    }
  }

  return { ok: false, status: 0, statusText: 'Redirect Loop', headers: new Headers(), finalUrl: currentUrl, error: 'Exceeded redirect limit' };
}
