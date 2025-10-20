// --- Cloudflare Worker for Favicon Fetcher ---

import { HTMLRewriter } from 'html-rewriter-wasm';

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
                const response = await fetch(baseUrl, { headers: { 'User-Agent': env.CUSTOM_USER_AGENT || 'Favicon-Fetcher-Worker/1.0' } });
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
            } catch (e) { /* continue */ }
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
    const response = await fetch(iconUrl, { headers: { 'User-Agent': env.CUSTOM_USER_AGENT || 'Favicon-Fetcher-Worker/1.0' } });
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
            if (isNaN(desiredSize)) return new Response(JSON.stringify({ error: 'Invalid size' }), { status: 400 });

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
            return new Response(JSON.stringify({ error: e.message || 'An unexpected error occurred' }), { status: 500 });
        }
    }
};

