import { realpathSync } from 'node:fs';
import { isIP } from 'node:net';
import { basename, dirname, join, resolve, sep } from 'node:path';

// Returns a human-readable reason when an IPv4 address is not safe to fetch.
// Exported through isPublicIpAddress for DNS-resolution checks.
function ipv4DenyReason(host: string): string | null {
  const octets = host.split('.').map(n => parseInt(n, 10));
  const [a, b, c] = octets;
  if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
    return 'invalid IPv4 address';
  }
  if (a === 0) return 'reserved IPv4 (0/8)';
  if (a === 10) return 'private IPv4 (10/8)';
  if (a === 127) return 'loopback IPv4';
  if (a === 169 && b === 254) return 'link-local / cloud metadata';
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return 'private IPv4 (172.16/12)';
  if (a === 192 && b === 168) return 'private IPv4 (192.168/16)';
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) return 'CGNAT range';
  if (a! >= 224) return 'multicast/reserved IPv4';
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return 'reserved IPv4';
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return 'reserved IPv4';
  if (a === 203 && b === 0 && c === 113) return 'reserved IPv4';
  if (a === 192 && b === 88 && c === 99) return 'reserved IPv4';
  return null;
}

// True for globally routable IPs. Used after DNS resolution too: checking only
// the URL literal lets a public hostname resolve to 127.0.0.1 / RFC1918.
export function isPublicIpAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return ipv4DenyReason(address) === null;
  if (version !== 6) return false;
  const lower = address.toLowerCase();
  // Loopback, unspecified, IPv4-mapped/compatible, ULA, link-local, and
  // multicast ranges. IPv6 literal URLs are already rejected separately.
  if (lower === '::' || lower === '::1' || lower.startsWith('::')) return false;
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return false;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return false;
  if (/^ff[0-9a-f]{2}:/.test(lower)) return false;
  if (/^2001:db8:/.test(lower)) return false;
  // 6to4 and Teredo encode an IPv4 destination; they are not ordinary globally
  // routable unicast addresses and can reach private IPv4 space.
  if (/^2002:/.test(lower) || /^2001:0{0,4}:/.test(lower) || /^64:ff9b:/.test(lower)) return false;
  return true;
}

// Reject URLs targeting private / loopback / link-local / cloud-metadata
// endpoints so prompt-injected inputs can't turn our fetch() calls into an
// SSRF vector against the host. Only HTTPS is permitted for outbound content.
export function isSafeOutboundUrl(urlStr: string): { ok: true } | { ok: false; reason: string } {
  let u: URL;
  try { u = new URL(urlStr); } catch { return { ok: false, reason: 'invalid URL' }; }
  if (u.protocol !== 'https:') return { ok: false, reason: 'only https:// is permitted' };
  if (u.username || u.password) return { ok: false, reason: 'URLs with credentials are not allowed' };

  // A trailing dot is a valid absolute-DNS spelling of the same host
  // (`localhost.`). Normalize before the hostname checks.
  const host = u.hostname.toLowerCase().replace(/\.$/, '');

  // Reject bare IPs and internal hostnames.
  const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (ipv4) {
    const reason = ipv4DenyReason(host);
    if (reason) return { ok: false, reason };
  }
  if (
    host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal' || host === 'instance-data' ||
    host === 'internal' || host === 'metadata' ||
    host.endsWith('.internal') || host.endsWith('.local') || host.endsWith('.localdomain') ||
    host.endsWith('.lan') || host.endsWith('.home') || host.endsWith('.corp')
  ) {
    return { ok: false, reason: 'internal hostname' };
  }
  if (host.includes(':')) return { ok: false, reason: 'IPv6 literal — not allowed' };
  if (!host) return { ok: false, reason: 'missing hostname' };
  return { ok: true };
}

export function isPathInside(parent: string, child: string): boolean {
  const p = resolve(parent);
  const c = resolve(child);
  return c === p || c.startsWith(p + sep);
}

// Resolve symlinks for an existing path; for a not-yet-existing target,
// resolve the nearest existing ancestor so symlinked parents are caught even
// when several trailing directories do not exist yet.
export function canonicalPath(filePath: string): string {
  const absolute = resolve(filePath);
  let current = absolute;
  const missing: string[] = [];

  while (true) {
    try {
      return join(realpathSync(current), ...missing.reverse());
    } catch {
      const parent = dirname(current);
      if (parent === current) return absolute;
      missing.push(basename(current));
      current = parent;
    }
  }
}
