const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const { Address6 } = require('ip-address');
const { promises: dns } = require('dns');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const IORedis = require('ioredis');
const { LRUCache } = require('lru-cache');

// --- Helper function to find the Redis URL ---
function findRedisUrl() {
  if (process.env.REDIS_URL) return process.env.REDIS_URL;
  for (const key in process.env) {
    if (key.startsWith('HEROKU_REDIS_')) return process.env[key];
  }
  return null;
}

// --- Environment & Constants ---

const REDIS_URL = findRedisUrl();

const env = {};
Object.keys(process.env).forEach(k => {
  env[k.toLowerCase()] = process.env[k];
});

const {
  port = 8080,
  cache_ttl_seconds = 86400,
  cache_enabled = 'true',
  in_memory_cache_max_size = 50 * 1024 * 1024,
  req_timeout_ms = 5000,
  html_payload_limit = 250 * 1024,
  icon_payload_limit = 2 * 1024 * 1024,
  custom_user_agent,
  limit_separator = ',',
  debug = 'false',
  doh1, doh2,
} = env;

const DEFAULT_USER_AGENT = custom_user_agent || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const G_CACHE_ENABLED = String(cache_enabled).toLowerCase() === 'true';
const G_DEBUG = String(debug).toLowerCase() === 'true';
const G_DOH_ENDPOINTS = [doh1, doh2].filter(Boolean);
const G_DOH_ENABLED = G_DOH_ENDPOINTS.length > 0;

const logDebug = (...args) => {
  if (G_DEBUG) console.log(...args);
};

// --- DNS Configuration ---
if (G_DOH_ENABLED) {
  console.log(`DNS over HTTPS (DoH) is enabled. Using endpoints: ${G_DOH_ENDPOINTS.join(', ')}`);
} else {
  console.log('Using system default DNS resolver.');
}

// --- Storage Setup (Hybrid: Redis or In-Memory) ---
let redisClient;
let cacheStore;

if (REDIS_URL) {
  console.log('Found Redis URL. Connecting to Redis for caching and rate limiting.');
  const redisOptions = { maxRetriesPerRequest: null, enableReadyCheck: false };
  if (REDIS_URL.includes('rediss://')) {
    redisOptions.tls = { rejectUnauthorized: false };
  }
  redisClient = new IORedis(REDIS_URL, redisOptions);
  cacheStore = {
    get: (key) => redisClient.get(key),
    set: (key, value) => redisClient.set(key, value, 'EX', parseInt(cache_ttl_seconds, 10)),
  };
} else {
  console.warn('WARNING: No Redis URL found. Falling back to in-memory cache and rate limiting.');
  const lruCache = new LRUCache({
    maxSize: parseInt(in_memory_cache_max_size, 10),
    ttl: parseInt(cache_ttl_seconds, 10) * 1000,
    sizeCalculation: (value) => (value ? Buffer.byteLength(value, 'utf8') : 1),
  });
  cacheStore = {
    get: (key) => Promise.resolve(lruCache.get(key)),
    set: (key, value) => Promise.resolve(lruCache.set(key, value)),
  };
}

// --- Security & HTTP Clients ---

// Custom error for blocking requests
class BlockedRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BlockedRequestError';
    this.isBlocked = true;
  }
}

const app = express();
app.use(helmet());
app.disable('x-powered-by');
app.set('trust proxy', 1);

const httpClient = axios.create({
  timeout: parseInt(req_timeout_ms, 10),
  headers: { 'User-Agent': DEFAULT_USER_AGENT },
  maxRedirects: 5,
});

const dohClient = axios.create({
  timeout: parseInt(req_timeout_ms, 10),
  headers: { 'User-Agent': DEFAULT_USER_AGENT },
});


// --- Auth & Rate Limiting ---

const authKeys = new Map();
const limitConfig = {};

Object.keys(process.env).forEach(key => {
  const upperKey = key.toUpperCase();
  if (upperKey.startsWith('AUTHN')) {
    authKeys.set(process.env[key], upperKey.replace('AUTHN', ''));
  } else if (upperKey.startsWith('LIMIT')) {
    limitConfig[upperKey.replace('LIMIT', '').toLowerCase()] = process.env[key];
  }
});

function parseMultiLimit(limitStr) {
  if (!limitStr) return [];
  const trimmedLimitStr = String(limitStr).trim();
  if (trimmedLimitStr === '0') return [{ max: 0, windowMs: 1000 }];

  return trimmedLimitStr.toLowerCase().split(String(limit_separator)).map(part => {
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

const getClientIp = (req) => req.ip || req.socket.remoteAddress;

const createRateLimiter = (limits, keyGenerator) => {
  if (!limits || limits.length === 0) return (req, res, next) => next();
  const limiters = limits.map(limit => {
    const store = REDIS_URL ? new RedisStore({ sendCommand: (...args) => redisClient.call(...args) }) : undefined;
    return rateLimit({
      windowMs: limit.windowMs, max: limit.max, keyGenerator, store,
      handler: (req, res) => { if (!res.headersSent) res.status(429).json({ error: 'Too many requests' }); },
    });
  });
  return (req, res, next) => {
    const runLimiters = (index) => {
      if (index >= limiters.length) return next();
      limiters[index](req, res, (err) => {
        if (err || res.headersSent) return;
        runLimiters(index + 1);
      });
    };
    runLimiters(0);
  };
};

// Pre-create rate limiters for anonymous users
const globalAnonymousLimiter = createRateLimiter(parseMultiLimit(limitConfig.a), () => 'global_anonymous');
const ipLimiter = createRateLimiter(parseMultiLimit(limitConfig.i), getClientIp);

// Cache for authenticated user rate limiters
const userLimiterCache = new Map();

app.use((req, res, next) => {
  let token = null;
  const authHeader = req.headers.authorization;
  const queryKey = Object.keys(req.query).find(k => k.toLowerCase() === 'key');
  if (authHeader) {
    const parts = authHeader.split(' ');
    if (parts.length === 2) token = parts[1];
  } else if (queryKey) {
    token = req.query[queryKey];
  }

  let keyId = 'a'; // Anonymous
  if (token && authKeys.has(token)) keyId = authKeys.get(token);

  if (keyId === 'a') {
    globalAnonymousLimiter(req, res, (err) => { if (err || res.headersSent) return; ipLimiter(req, res, next); });
  } else {
    if (!userLimiterCache.has(keyId)) {
      userLimiterCache.set(keyId, createRateLimiter(parseMultiLimit(limitConfig[keyId]), () => `user_${keyId}`));
    }
    userLimiterCache.get(keyId)(req, res, next);
  }
});

// --- Security: SSRF Protection & Custom DNS Interceptor ---

const isIpPrivate = (ip) => {
  try {
    // Try parsing as IPv6 (handles both IPv6 and IPv4-mapped addresses)
    const addr = new Address6(ip);
    
    // Check IPv6 ranges
    if (addr.isLoopback()) return true;  // ::1/128
    if (addr.isLinkLocal()) return true; // fe80::/10
    
    // Check if it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    if (addr.v4) {
      const ipv4 = addr.to4().address;
      return isIpv4Private(ipv4);
    }
    
    // IPv6-specific private/reserved ranges
    const ipv6PrivateRanges = [
      '::/128',           // Unspecified
      '::1/128',          // Loopback (redundant but explicit)
      '::ffff:0:0/96',    // IPv4-mapped
      '::ffff:0:0:0/96',  // IPv4-translated
      '64:ff9b::/96',     // IPv4/IPv6 translation
      '64:ff9b:1::/48',   // IPv4/IPv6 translation (local-use)
      '100::/64',         // Discard prefix
      '2001::/32',        // TEREDO
      '2001:10::/28',     // Deprecated (ORCHID)
      '2001:20::/28',     // ORCHIDv2
      '2001:db8::/32',    // Documentation
      '2002::/16',        // 6to4
      'fc00::/7',         // Unique Local Addresses (ULA)
      'fe80::/10',        // Link-Local (redundant but explicit)
      'ff00::/8',         // Multicast
    ];
    
    for (const range of ipv6PrivateRanges) {
      if (addr.isInSubnet(new Address6(range))) return true;
    }
    
    return false;
  } catch (e) {
    // If IPv6 parsing fails, try as IPv4
    return isIpv4Private(ip);
  }
};

const isIpv4Private = (ip) => {
  // Remove IPv4-mapped prefix if present
  let ipv4 = ip;
  if (ip.startsWith('::ffff:')) {
    ipv4 = ip.substring(7);
  }
  
  const octets = ipv4.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
    return false; // Invalid IPv4
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
};

httpClient.interceptors.request.use(async (config) => {
  const url = new URL(config.url);
  const { hostname } = url;

  try {
    let address;
    // Check if hostname is already an IP address
    let isValidIp = false;
    try {
      isValidIp = new Address6(hostname).isValid();
    } catch (e) {
      isValidIp = false;
    }
    
    if (isValidIp) {
      address = hostname;
    } else {
      if (G_DOH_ENABLED) {
        logDebug(`Resolving ${hostname} via DoH...`);
        
        if (G_DOH_ENDPOINTS.length === 0) throw new Error('DoH enabled but no endpoints configured');
        
        // 1. Resolve the DoH server's IP first, cleanly.
        const dohUrl = new URL(G_DOH_ENDPOINTS[0]);
        const dohHostname = dohUrl.hostname;
        
        logDebug(`Using system DNS for DoH bootstrap of ${dohHostname}`);
        const lookupResult = await dns.lookup(dohHostname);
        const dohIp = lookupResult.address;
        logDebug(`DoH server ${dohHostname} resolved to ${dohIp}`);

        // 2. Make the DoH request using the resolved IP (with URL-encoded hostname).
        const encodedHostname = encodeURIComponent(hostname);
        const dohRequestUrl = `${dohUrl.protocol}//${dohIp}${dohUrl.pathname}?name=${encodedHostname}&type=A`;
        const dohResponseA = await dohClient.get(dohRequestUrl, {
          headers: { 'accept': 'application/dns-json', 'Host': dohHostname }
        });
        
        let answers = dohResponseA.data?.Answer;
        if (!answers || answers.length === 0) {
          const dohRequestUrlAAAA = `${dohUrl.protocol}//${dohIp}${dohUrl.pathname}?name=${encodedHostname}&type=AAAA`;
          const dohResponseAAAA = await dohClient.get(dohRequestUrlAAAA, {
             headers: { 'accept': 'application/dns-json', 'Host': dohHostname }
          });
          answers = dohResponseAAAA.data?.Answer;
        }
        
        if (!answers || answers.length === 0) throw new Error('No A or AAAA records found via DoH');
        if (!answers[0].data) throw new Error('DoH response missing IP address data');
        address = answers[0].data;

      } else {
        logDebug(`Resolving ${hostname} via system DNS...`);
        const lookupResult = await dns.lookup(hostname);
        address = lookupResult.address;
      }
    }

    logDebug(`${hostname} resolved to ${address}`);
    if (isIpPrivate(address)) {
      throw new BlockedRequestError(`Request to private IP blocked. ${hostname} resolves to ${address}`);
    }

    // Construct new URL with IP address while preserving path, query, and fragment
    const newUrl = new URL(config.url);
    newUrl.hostname = address;
    config.url = newUrl.href;
    config.headers['Host'] = hostname;
    
    return config;
  } catch (e) {
    if (e instanceof BlockedRequestError) throw e;
    throw new Error(`DNS lookup failed for ${hostname}: ${e.message}`);
  }
});


// --- Icon Fetching Logic ---

function normalizeDomain(domain) {
  if (!domain) throw new Error('Domain parameter is required');
  let url = String(domain).trim().toLowerCase();
  if (url.startsWith('http://') || url.startsWith('https://')) url = url.split('//')[1];
  url = url.split('/')[0].split('?')[0];
  if (url.length === 0 || url.includes('..') || url.includes('@')) throw new Error('Invalid domain format');
  return url;
}

async function fetchHtml(url) {
  const response = await httpClient.get(url, { 
    maxContentLength: parseInt(html_payload_limit, 10), 
    responseType: 'text' 
  });
  const finalUrl = response.request?.res?.responseUrl || url;
  return { data: response.data, finalUrl };
}

function findIconsInHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const icons = [];
  $('link[rel*="icon"], link[rel*="apple-touch-icon"]').each((i, el) => {
    const href = $(el).attr('href');
    if (!href) return;
    let size = 0;
    const sizes = $(el).attr('sizes');
    if (sizes && sizes !== 'any') {
      const sizeMatch = sizes.match(/(\d+)x(\d+)/);
      if (sizeMatch) size = parseInt(sizeMatch[1], 10);
    }
    try {
      icons.push({ href: new URL(href, baseUrl).href, size: size || 0 });
    } catch (e) { /* Ignore invalid URLs */ }
  });
  return icons;
}

async function getFaviconUrls(domain, desiredSize, magic) {
  const domainsToConsider = new Set([domain]);
  if (magic) {
    if (domain.startsWith('www.')) domainsToConsider.add(domain.substring(4));
    else domainsToConsider.add(`www.${domain}`);
  }

  let allIcons = [];

  for (const d of [...domainsToConsider]) {
    for (const protocol of ['https', 'http']) {
      try {
        const { data, finalUrl } = await fetchHtml(`${protocol}://${d}`);
        const iconsFromHtml = findIconsInHtml(data, finalUrl);
        allIcons = allIcons.concat(iconsFromHtml);
        
        const finalDomain = new URL(finalUrl);
        domainsToConsider.add(finalDomain.hostname);
        
        break; 
      } catch (e) {
        logDebug(`Could not fetch HTML from ${protocol}://${d}: ${e.message}`);
      }
    }
  }

  for (const d of domainsToConsider) {
    allIcons.push({ href: `https://${d}/favicon.ico`, size: 0 });
    allIcons.push({ href: `http://${d}/favicon.ico`, size: 0 });
  }
  
  const sortedIcons = allIcons.sort((a, b) => {
    const aDiff = Math.abs(a.size - desiredSize);
    const bDiff = Math.abs(b.size - desiredSize);
    if (a.size >= desiredSize && b.size < desiredSize) return -1;
    if (a.size < desiredSize && b.size >= desiredSize) return 1;
    return aDiff - bDiff;
  });

  const uniqueUrls = [...new Set(sortedIcons.map(icon => icon.href))];
  if (uniqueUrls.length === 0) throw new Error('No potential icon URLs found for this domain');
  return uniqueUrls;
}

async function fetchAndProcessIcon(iconUrl) {
  try {
    const response = await httpClient.get(iconUrl, {
      responseType: 'arraybuffer',
      maxContentLength: parseInt(icon_payload_limit, 10),
      validateStatus: (status) => status >= 200 && status < 300,
    });
    const contentType = response.headers['content-type'] || 'application/octet-stream';
    if (!contentType.startsWith('image/')) throw new Error(`Fetched file is not an image: ${contentType}`);
    return { buffer: response.data, contentType, href: iconUrl };
  } catch (error) {
    if (error instanceof BlockedRequestError) throw error;
    throw new Error(`Failed to fetch icon: ${iconUrl}`);
  }
}

// --- Main Request Handler ---

app.get('/', async (req, res, next) => {
  try {
    const params = {};
    for (const key in req.headers) { params[key.toLowerCase()] = req.headers[key]; }
    for (const key in req.query) { params[key.toLowerCase()] = req.query[key]; }

    const { domain, size = '64', m, magic, b64 } = params;
    
    const desiredSize = parseInt(size, 10);
    if (isNaN(desiredSize) || desiredSize < 1 || desiredSize > 2048) {
      throw new Error('Invalid size parameter (must be between 1 and 2048)');
    }

    const useMagic = (m !== undefined || magic !== undefined);
    const useBase64 = (b64 !== undefined);
    const cleanDomain = normalizeDomain(domain);
    
    const cacheKey = `favicon:${cleanDomain}:${desiredSize}:${useMagic}`;
    if (G_CACHE_ENABLED) {
      const cachedData = await cacheStore.get(cacheKey);
      if (cachedData) {
        try {
          const parsed = JSON.parse(cachedData);
          if (parsed && parsed.buffer && parsed.contentType && parsed.href) {
            const { buffer, contentType, href } = parsed;
            const imageBuffer = Buffer.from(buffer, 'base64');
            if (useBase64) return res.json({ href, base64: `data:${contentType};base64,${imageBuffer.toString('base64')}` });
            return res.setHeader('Content-Type', contentType).send(imageBuffer);
          }
        } catch (e) {
          logDebug(`Cache data corrupted, ignoring: ${e.message}`);
        }
      }
    }
    
    const iconUrls = await getFaviconUrls(cleanDomain, desiredSize, useMagic);
    
    for (const iconUrl of iconUrls) {
      try {
        const { buffer: imageBuffer, contentType, href } = await fetchAndProcessIcon(iconUrl);
        if (G_CACHE_ENABLED) {
          const cacheValue = JSON.stringify({ buffer: imageBuffer.toString('base64'), contentType, href });
          await cacheStore.set(cacheKey, cacheValue);
        }
        if (useBase64) return res.json({ href, base64: `data:${contentType};base64,${imageBuffer.toString('base64')}` });
        return res.setHeader('Content-Type', contentType).send(imageBuffer);
      } catch (error) {
        logDebug(`Individual fetch failed: ${error.message}`);
      }
    }
    throw new Error('No valid icons could be fetched for this domain');
  } catch (error) {
    next(error);
  }
});

// --- Health Check & Error Handling ---

app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

app.use((err, req, res, next) => {
  console.error(`Final error for request: ${err.message}`);
  let statusCode = 500;
  if (err.message.includes('Invalid') || err.message.includes('required')) statusCode = 400;
  else if (err.message.includes('No icons found') || err.message.includes('No valid icons')) statusCode = 404;
  else if (err.message.includes('timeout') || err.code === 'ECONNABORTED' || err.message.includes('DNS')) statusCode = 504;
  else if (err.message.includes('blocked')) statusCode = 403;
  res.status(statusCode).json({ error: err.message || 'An unexpected error occurred' });
});

app.listen(port, () => console.log(`Favicon Fetcher listening on port ${port}`));
