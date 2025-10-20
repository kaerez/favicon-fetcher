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
} = env;

const DEFAULT_USER_AGENT = custom_user_agent || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const G_CACHE_ENABLED = String(cache_enabled).toLowerCase() === 'true';

// --- DNS Configuration ---
const customDnsServers = [];
for (let i = 1; i <= 4; i++) {
  if (process.env[`DNS${i}`]) {
    customDnsServers.push(process.env[`DNS${i}`]);
  }
}
let dnsResolver = null;
if (customDnsServers.length > 0) {
  dnsResolver = new dns.Resolver();
  dnsResolver.setServers(customDnsServers);
  console.log(`Using custom DNS servers: ${customDnsServers.join(', ')}`);
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

// --- Security & HTTP Client ---

const app = express();
app.use(helmet());
app.disable('x-powered-by');
app.set('trust proxy', 1);

const httpClient = axios.create({
  timeout: parseInt(req_timeout_ms, 10),
  headers: { 'User-Agent': DEFAULT_USER_AGENT },
  maxRedirects: 5,
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

app.use((req, res, next) => {
  let token = null;
  const authHeader = req.headers.authorization;
  const queryKey = Object.keys(req.query).find(k => k.toLowerCase() === 'key');
  if (authHeader) token = authHeader.split(' ')[1];
  else if (queryKey) token = req.query[queryKey];

  let keyId = 'a'; // Anonymous
  if (token && authKeys.has(token)) keyId = authKeys.get(token);

  if (keyId === 'a') {
    const globalLimiter = createRateLimiter(parseMultiLimit(limitConfig.a), () => 'global_anonymous');
    const ipLimiter = createRateLimiter(parseMultiLimit(limitConfig.i), getClientIp);
    globalLimiter(req, res, (err) => { if (err || res.headersSent) return; ipLimiter(req, res, next); });
  } else {
    createRateLimiter(parseMultiLimit(limitConfig[keyId]), () => `user_${keyId}`)(req, res, next);
  }
});

// --- Security: SSRF Protection ---

const isIpPrivate = (ip) => {
  try {
    const addr = new Address6(ip);
    return addr.isLoopback() || addr.isLinkLocal() || addr.isPrivate() || addr.isInSubnet('::ffff:127.0.0.0/104');
  } catch (e) {
    if (ip.startsWith('::ffff:')) {
      const ipv4 = ip.substring(7);
      if (ipv4.startsWith('127.') || ipv4.startsWith('10.') || ipv4.startsWith('172.16.') || ipv4.startsWith('192.168.')) return true;
    }
    return false;
  }
};

httpClient.interceptors.request.use(async (config) => {
  const { hostname } = new URL(config.url);
  try {
    let address;
    if (new Address6(hostname).isValid()) {
      address = hostname; // It's already an IP
    } else {
      // Perform DNS lookup using the appropriate resolver
      if (dnsResolver) {
        const addresses = await dnsResolver.resolve(hostname);
        if (addresses.length === 0) throw new Error('No addresses found');
        address = addresses[0]; // Use the first resolved address
      } else {
        const lookupResult = await dns.lookup(hostname);
        address = lookupResult.address;
      }
    }
    if (isIpPrivate(address)) {
      throw new axios.Cancel(`Request to private IP blocked. ${hostname} resolves to ${address}`);
    }
  } catch (e) {
    if (e instanceof axios.Cancel) throw e;
    throw new Error(`DNS lookup failed for ${hostname}`);
  }
  return config;
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
  const finalUrl = response.request.res.responseUrl || url;
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

  for (const d of domainsToConsider) {
    for (const protocol of ['https', 'http']) {
      try {
        const { data, finalUrl } = await fetchHtml(`${protocol}://${d}`);
        const iconsFromHtml = findIconsInHtml(data, finalUrl);
        allIcons = allIcons.concat(iconsFromHtml);
        
        const finalDomain = new URL(finalUrl);
        domainsToConsider.add(finalDomain.hostname);
        
        break; 
      } catch (e) {
        console.log(`Could not fetch HTML from ${protocol}://${d}: ${e.message}`);
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
    if (axios.isCancel(error)) throw error;
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
    if (isNaN(desiredSize)) throw new Error('Invalid size parameter');

    const useMagic = (m !== undefined || magic !== undefined);
    const useBase64 = (b64 !== undefined);
    const cleanDomain = normalizeDomain(domain);
    
    const cacheKey = `favicon:${cleanDomain}:${desiredSize}:${useMagic}`;
    if (G_CACHE_ENABLED) {
      const cachedData = await cacheStore.get(cacheKey);
      if (cachedData) {
        const { buffer, contentType, href } = JSON.parse(cachedData);
        const imageBuffer = Buffer.from(buffer, 'base64');
        if (useBase64) return res.json({ href, base64: `data:${contentType};base64,${imageBuffer.toString('base64')}` });
        return res.setHeader('Content-Type', contentType).send(imageBuffer);
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
        console.log(`Individual fetch failed: ${error.message}`);
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

