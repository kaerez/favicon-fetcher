// SPDX-License-Identifier: LicenseRef-KSEC-FaviconFetcher
// Copyright (C) 2025 KSEC - Erez Kalman. All rights reserved.
// Personal non-commercial use only. Commercial license required for all other uses.
// See LICENSE.md for full terms: https://github.com/kaerez/favicon-fetcher/blob/main/LICENSE.md

// --- Cloudflare Worker for Favicon Fetcher ---
// ⚠️ SECURITY NOTE: This Worker has LIMITED SSRF protection due to platform constraints.
// It blocks direct IP addresses but CANNOT prevent domains that resolve to private IPs.
// For production use requiring strong SSRF protection, use the Docker variant instead.

import { HTMLRewriter } from 'html-rewriter-wasm';

// --- SSRF Protection Functions ---

function isIpv4Private(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
    return false;
  }
  
  const [a, b, c, d] = octets;
  
  // Check all private and reserved IPv4 ranges
  return (
    a === 0 ||                              // 0.0.0.0/8 - Current network
    a === 10 ||                             // 10.0.0.0/8 - Private
    a === 127 ||                            // 127.0.0.0/8 - Loopback
    (a === 169 && b === 254) ||             // 169.254.0.0/16 - Link-local
    (a === 172 && b >= 16 && b <= 31) ||    // 172.16.0.0/12 - Private
    (a === 192 && b === 0 && c === 0) ||    // 192.0.0.0/24 - IETF Protocol Assignments
    (a === 192 && b === 0 && c === 2) ||    // 192.0.2.0/24 - TEST-NET-1
    (a === 192 && b === 168) ||             // 192.168.0.0/16 - Private
    (a === 198 && b === 18) ||              // 198.18.0.0/15 - Benchmark testing
    (a === 198 && b === 19) ||              // 198.18.0.0/15 - Benchmark testing
    (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24 - TEST-NET-2
    (a === 203 && b === 0 && c === 113) ||  // 203.0.113.0/24 - TEST-NET-3
    a >= 224 ||                             // 224.0.0.0/4 - Multicast, 240.0.0.0/4 - Reserved
    (a === 100 && b >= 64 && b <= 127) ||   // 100.64.0.0/10 - CGNAT
    (a === 192 && b === 88 && c === 99)     // 192.88.99.0/24 - 6to4 Relay Anycast
  );
}

function isIpv6Private(ip) {
  const lower = ip.toLowerCase();
  
  // Unspecified and loopback
  if (lower === '::1' || lower === '::') return true;
  
  // Link-local
  if (lower.startsWith('fe80:')) return true;
  
  // Unique Local Addresses (ULA)
  if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
  
  // Multicast
  if (lower.startsWith('ff0')) return true;
  
  // IPv4-mapped IPv6 addresses
  if (lower.startsWith('::ffff:')) {
    const ipv4Part = ip.substring(7);
    return isIpv4Private(ipv4Part);
  }
  
  // Documentation ranges
  if (lower.startsWith('2001:db8:')) return true;
  
  // TEREDO
  if (lower.startsWith('2001:0:')) return true;
  
  // 6to4
  if (lower.startsWith('2002:')) return true;
  
  // Discard prefix
  if (lower.startsWith('100::')) return true;
  
  return false;
}

function validateDomain(domain) {
  // Block direct IPv4 addresses
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
    if (isIpv4Private(domain)) {
      throw new Error('Access to private IP addresses is blocked');
    }
    // Even if it's a public IP, fetching directly by IP is suspicious
    console.warn(`Direct IP access attempted: ${domain}`);
  }
  
  // Block IPv6 addresses
  if (domain.includes(':') && !domain.includes('://')) {
    if (isIpv6Private(domain)) {
      throw new Error('Access to private IPv6 addresses is blocked');
    }
    console.warn(`Direct IPv6 access attempted: ${domain}`);
  }
  
  // Block localhost variants
  const blockedHosts = [
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    'ip6-localhost',
    'ip6-loopback'
  ];
  if (blockedHosts.includes(domain.toLowerCase())) {
    throw new Error('Access to localhost is blocked');
  }
  
  // Block suspicious patterns
  if (domain.includes('@')) {
    throw new Error('Invalid domain format: @ character not allowed');
  }
  if (domain.includes('..')) {
    throw new Error('Invalid domain format: .. pattern not allowed');
  }
  if (domain.includes('\\')) {
    throw new Error('Invalid domain format: backslash not allowed');
  }
}

// Helper to get a value from Request (Headers or Query) case-insensitively
function getParam(request, key) {
  const url = new URL(request.url);
  // Query params take precedence
  for (const [qKey, qValue] of url.searchParams.entries()) {
    if (qKey.toLowerCase() === key.toLowerCase()) {
      return qValue;
    }
  }
  // Fallback to headers
  for (const [hKey, hValue] of request.headers.entries()) {
    if (hKey.toLowerCase() === key.toLowerCase()) {
      return hValue;
    }
  }
  return null;
}

// Helper to get the client's IP address
function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP');
}

// --- Rate Limiting Logic (using Workers KV) ---

async function checkRateLimits(request, env) {
  const keyParam = getParam(request, 'key');
  let keyId = 'a'; // Anonymous
  let isAnonymous = true;

  // Check for authenticated key
  for (const envKey in env) {
    if (envKey.toUpperCase().startsWith('AUTHN') && env[envKey] === keyParam) {
      keyId = envKey.toUpperCase().replace('AUTHN', '');
      isAnonymous = false;
      break;
    }
  }

  const limitsToApply = [];
  if (isAnonymous) {
    if (env.LIMITA) limitsToApply.push({ rule: env.LIMITA, key: 'global_anonymous' });
    if (env.LIMITI) limitsToApply.push({ rule: env.LIMITI, key: getClientIp(request) });
  } else {
    const userLimitKey = `LIMIT${keyId}`;
    if (env[userLimitKey]) limitsToApply.push({ rule: env[userLimitKey], key: `user_${keyId}` });
  }

  for (const { rule, key } of limitsToApply) {
    const rules = parseMultiLimit(rule, env.LIMIT_SEPARATOR || ',');
    for (const r of rules) {
      if (r.max === 0) return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429 });

      const fullKey = `${key}:${Math.floor(Date.now() / r.windowMs)}`;
      const current = await env.FAVICON_FETCHER_RATE_LIMITS.get(fullKey, { type: 'text' });
      const count = parseInt(current || '0', 10) + 1;

      if (count > r.max) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429 });
      }

      await env.FAVICON_FETCHER_RATE_LIMITS.put(fullKey, count.toString(), { expirationTtl: r.windowMs / 1000 });
    }
  }
  return null; // All limits passed
}

function parseMultiLimit(limitStr, separator) {
  const trimmedLimitStr = String(limitStr || '').trim();
  if (trimmedLimitStr === '0') return [{ max: 0, windowMs: 1000 }];
  
  return trimmedLimitStr.toLowerCase().split(separator).map(part => {
    const trimmedPart = part.trim();
    let unit, countStr;
    if (trimmedPart.includes(':')) {
      [unit, countStr] = trimmedPart.split(':');
    } else {
      unit = 'rps';
      countStr = trimmedPart;
    }
    const max = parseInt(countStr, 10);
    if (isNaN(max)) return null;
    let windowMs;
    switch (unit) {
      case 'rps': windowMs = 1000; break;
      case 'rpm': windowMs = 60 * 1000; break;
      case 'rph': windowMs = 60 * 60 * 1000; break;
      case 'rpd': windowMs = 24 * 60 * 60 * 1000; break;
      default: return null;
    }
    return { max, windowMs };
  }).filter(Boolean);
}


// --- Icon Fetching Logic ---

function normalizeDomain(domain) {
    if (!domain) throw new Error('Domain parameter is required');
    let url = String(domain).trim().toLowerCase();
    if (url.startsWith('http')) url = url.split('//')[1];
    url = url.split('/')[0].split('?')[0];
    if (!url || url.includes('..') || url.includes('@')) throw new Error('Invalid domain format');
    
    // ⚠️ SSRF Protection: Validate domain
    validateDomain(url);
    
    return url;
}

async function getFaviconUrls(domain, desiredSize, magic, env) {
    const domainsToTry = [domain];
    if (magic) {
        domainsToTry.push(domain.startsWith('www.') ? domain.substring(4) : `www.${domain}`);
    }

    let allIcons = [];
    for (const d of domainsToTry) {
        let iconsFromHtml = [];
        for (const protocol of ['https', 'http']) {
            try {
                const baseUrl = `${protocol}://${d}`;
                const response = await fetch(baseUrl, { 
                  headers: { 'User-Agent': env.CUSTOM_USER_AGENT || 'Favicon-Fetcher-Worker/1.0' },
                  // Add timeout to prevent hanging on slow/malicious servers
                  signal: AbortSignal.timeout(5000)
                });
                if (!response.ok) continue;

                const icons = [];
                await new HTMLRewriter()
                    .on('link[rel*="icon"], link[rel*="apple-touch-icon"]', {
                        element(el) {
                            const href = el.getAttribute('href');
                            if (!href) return;
                            let size = 0;
                            const sizes = el.getAttribute('sizes');
                            if (sizes && sizes !== 'any') {
                                const match = sizes.match(/(\d+)x(\d+)/);
                                if (match) size = parseInt(match[1], 10);
                            }
                            try {
                                icons.push({ href: new URL(href, baseUrl).href, size });
                            } catch (e) { /* ignore invalid URLs */ }
                        },
                    })
                    .transform(response)
                    .arrayBuffer(); // We need to consume the stream
                
                iconsFromHtml = icons;
                allIcons = allIcons.concat(iconsFromHtml);
                break;
            } catch (e) { 
              console.log(`Could not fetch HTML from ${protocol}://${d}: ${e.message}`);
            }
        }
        allIcons.push({ href: `https://${d}/favicon.ico`, size: 0 });
        allIcons.push({ href: `http://${d}/favicon.ico`, size: 0 });
        if (iconsFromHtml.length > 0) break;
    }

    const sortedIcons = allIcons.sort((a, b) => {
        const aDiff = Math.abs(a.size - desiredSize);
        const bDiff = Math.abs(b.size - desiredSize);
        if (a.size >= desiredSize && b.size < desiredSize) return -1;
        if (a.size < desiredSize && b.size >= desiredSize) return 1;
        return aDiff - bDiff;
    });

    const uniqueUrls = [...new Set(sortedIcons.map(icon => icon.href))];
    if (uniqueUrls.length === 0) throw new Error('No potential icon URLs found');
    return uniqueUrls;
}

async function fetchAndProcessIcon(iconUrl, env) {
    const response = await fetch(iconUrl, { 
      headers: { 'User-Agent': env.CUSTOM_USER_AGENT || 'Favicon-Fetcher-Worker/1.0' },
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw new Error(`Failed to fetch icon with status ${response.status}`);
    
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    if (!contentType.startsWith('image/')) throw new Error('Fetched file is not an image');
    
    const buffer = await response.arrayBuffer();
    return { buffer, contentType, href: iconUrl };
}

// --- Main Worker Entry Point ---

export default {
    async fetch(request, env, ctx) {
        try {
            const rateLimitResponse = await checkRateLimits(request, env);
            if (rateLimitResponse) return rateLimitResponse;

            const domain = getParam(request, 'domain');
            const size = getParam(request, 'size') || '64';
            const magic = getParam(request, 'm') !== null || getParam(request, 'magic') !== null;
            const b64 = getParam(request, 'b64') !== null;

            const desiredSize = parseInt(size, 10);
            if (isNaN(desiredSize) || desiredSize < 1 || desiredSize > 2048) {
              return new Response(JSON.stringify({ error: 'Invalid size parameter (must be between 1 and 2048)' }), { status: 400 });
            }

            const cleanDomain = normalizeDomain(domain);
            const cacheKey = `favicon:${cleanDomain}:${desiredSize}:${magic}`;

            if (String(env.CACHE_ENABLED).toLowerCase() === 'true') {
                const cached = await env.FAVICON_FETCHER_CACHE.get(cacheKey, { type: 'json' });
                if (cached) {
                    const imageBuffer = new Uint8Array(Object.values(cached.buffer)).buffer;
                    if (b64) {
                        const base64 = btoa(String.fromCharCode.apply(null, new Uint8Array(imageBuffer)));
                        return new Response(JSON.stringify({ href: cached.href, base64: `data:${cached.contentType};base64,${base64}` }), { headers: { 'Content-Type': 'application/json' } });
                    }
                    return new Response(imageBuffer, { headers: { 'Content-Type': cached.contentType } });
                }
            }

            const iconUrls = await getFaviconUrls(cleanDomain, desiredSize, magic, env);

            for (const iconUrl of iconUrls) {
                try {
                    const { buffer, contentType, href } = await fetchAndProcessIcon(iconUrl, env);

                    if (String(env.CACHE_ENABLED).toLowerCase() === 'true') {
                        const cacheTtl = parseInt(env.CACHE_TTL_SECONDS || '86400', 10);
                        ctx.waitUntil(env.FAVICON_FETCHER_CACHE.put(cacheKey, { buffer: Array.from(new Uint8Array(buffer)), contentType, href }, { expirationTtl: cacheTtl }));
                    }

                    if (b64) {
                        const base64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
                        return new Response(JSON.stringify({ href, base64: `data:${contentType};base64,${base64}` }), { headers: { 'Content-Type': 'application/json' } });
                    }
                    return new Response(buffer, { headers: { 'Content-Type': contentType } });
                } catch (e) {
                    console.log(`Individual fetch failed: ${e.message}`);
                }
            }

            return new Response(JSON.stringify({ error: 'No valid icons could be fetched' }), { status: 404 });

        } catch (e) {
            console.error(`Final error: ${e.message}`);
            let statusCode = 500;
            if (e.message.includes('Invalid') || e.message.includes('required')) statusCode = 400;
            else if (e.message.includes('blocked')) statusCode = 403;
            else if (e.message.includes('No icons') || e.message.includes('No valid icons')) statusCode = 404;
            return new Response(JSON.stringify({ error: e.message || 'An unexpected error occurred' }), { status: statusCode });
        }
    }
};
