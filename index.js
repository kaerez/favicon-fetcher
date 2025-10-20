const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const { Address6 } = require('ip-address');
const dns = require('dns').promises;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const IORedis = require('ioredis');
const { LRUCache } = require('lru-cache');

// --- Environment & Constants ---

// Read all env vars into a case-insensitive map for general config
const env = {};
Object.keys(process.env).forEach(k => {
  env[k.toLowerCase()] = process.env[k];
});

const {
  port = 8080,
  redis_url,
  cache_ttl_seconds = 86400, // 24 hours
  cache_enabled = 'true',
  in_memory_cache_max_size = 50 * 1024 * 1024, // 50MB
  req_timeout_ms = 5000,
  html_payload_limit = 250 * 1024, // 250KB
  icon_payload_limit = 2 * 1024 * 1024, // 2MB
  custom_user_agent,
  limit_separator = ',', // Default to comma, can be overridden for GCP
} = env;

const DEFAULT_USER_AGENT = custom_user_agent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const G_CACHE_ENABLED = String(cache_enabled).toLowerCase() === 'true';

// --- Storage Setup (Hybrid: Redis or In-Memory) ---

let redisClient;
let cacheStore;

if (redis_url) {
  console.log('Using Redis for caching and rate limiting.');
  redisClient = new IORedis(redis_url, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });

  cacheStore = {
    get: (key) => redisClient.get(key),
    set: (key, value) => redisClient.set(key, value, 'EX', parseInt(cache_ttl_seconds, 10)),
  };
} else {
  console.warn('WARNING: REDIS_URL not set. Falling back to in-memory cache and rate limiting.');
  console.warn('In-memory mode is not suitable for production and will lose data on restart.');
  
  const lruCache = new LRUCache({
    maxSize: parseInt(in_memory_cache_max_size, 10),
    ttl: parseInt(cache_ttl_seconds, 10) * 1000,
    sizeCalculation: (value) => JSON.parse(value)?.buffer?.length || 1,
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
});

// --- Auth & Rate Limiting ---

const authKeys = new Map();
const limitConfig = {};

// Parse AUTHN and LIMIT env vars (case-sensitive keys)
Object.keys(process.env).forEach(key => {
  const upperKey = key.toUpperCase();
  if (upperKey.startsWith('AUTHN')) {
    const keyId = upperKey.replace('AUTHN', '');
    authKeys.set(process.env[key], keyId);
  } else if (upperKey.startsWith('LIMIT')) {
    // Store config key as lowercase for easier lookup
    const keyId = upperKey.replace('LIMIT', '').toLowerCase();
    limitConfig[keyId] = process.env[key];
  }
});

function parseMultiLimit(limitStr) {
  if (!limitStr) return [];
  // Handle case-insensitive limit values and custom separator
  return String(limitStr).toLowerCase().split(limit_separator).map(part => {
    const [unit, countStr] = part.trim().split(':');
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
    // A max of 0 means block all requests for this rule
    return { max, windowMs };
  }).filter(Boolean); // Remove any nulls from invalid parts
}

const getClientIp = (req) => req.ip || req.socket.remoteAddress;

const createRateLimiter = (limits, keyGenerator) => {
  if (!limits || limits.length === 0) return (req, res, next) => next();

  const limiters = limits.map(limit => {
    const store = redis_url ? new RedisStore({ sendCommand: (...args) => redisClient.call(...args) }) : undefined;
    return rateLimit({
      windowMs: limit.windowMs,
      max: limit.max,
      keyGenerator,
      store,
      handler: (req, res) => {
        // Stop processing on the first limiter that fails
        if (!res.headersSent) {
          res.status(429).json({ error: 'Too many requests' });
        }
      },
    });
  });

  // Middleware that runs all limiters in sequence for a given request
  return (req, res, next) => {
    const runLimiters = (index) => {
      if (index >= limiters.length) {
        return next(); // All limiters passed
      }
      limiters[index](req, res, (err) => {
        if (err || res.headersSent) {
          return; // Error or response already sent, stop.
        }
        runLimiters(index + 1);
      });
    };
    runLimiters(0);
  };
};

app.use((req, res, next) => {
  let token = null;
  const authHeader = req.headers.authorization;
  // Case-insensitive search for 'key' query param
  const queryKey = Object.keys(req.query).find(k => k.toLowerCase() === 'key');

  if (authHeader) {
    token = authHeader.split(' ')[1];
  } else if (queryKey) {
    token = req.query[queryKey];
  }

  let keyId = 'a'; // Default to anonymous
  if (token && authKeys.has(token)) {
    keyId = authKeys.get(token); // Authenticated
  }

  if (keyId === 'a') {
    // Anonymous: apply both global and per-IP limits
    const globalLimits = parseMultiLimit(limitConfig.a);
    const ipLimits = parseMultiLimit(limitConfig.i);
    
    const globalLimiter = createRateLimiter(globalLimits, () => 'global_anonymous');
    const ipLimiter = createRateLimiter(ipLimits, getClientIp);

    // Chain the limiters: global first, then IP
    globalLimiter(req, res, (err) => {
      if (err || res.headersSent) return; // Stop if global limit fails
      ipLimiter(req, res, next);
    });

  } else {
    // Authenticated
    const userLimits = parseMultiLimit(limitConfig[keyId]);
    const userLimiter = createRateLimiter(userLimits, () => `user_${keyId}`);
    userLimiter(req, res, next);
  }
});


// --- Security: SSRF Protection ---

const isIpPrivate = (ip) => {
  try {
    const addr = new Address6(ip);
    return addr.isLoopback() || addr.isLinkLocal() || addr.isPrivate() || addr.isInSubnet('::ffff:127.0.0.0/104');
  } catch (e) {
    // Check for IPv4-mapped IPv6 addresses that ip-address lib might miss
    if (ip.startsWith('::ffff:')) {
      const ipv4 = ip.substring(7);
      if (ipv4.startsWith('127.') || ipv4.startsWith('10.') || ipv4.startsWith('172.16.') || ipv4.startsWith('192.168.')) {
        return true;
      }
    }
    return false; // Invalid or non-private IP
  }
};

httpClient.interceptors.request.use(async (config) => {
  const { hostname } = new URL(config.url);
  try {
     // Prevent requests to IP addresses directly, unless they are public
    if (new Address6(hostname).isValid()) {
       if (isIpPrivate(hostname)) {
          throw new axios.Cancel(`Request to private IP blocked: ${hostname}`);
       }
    } else {
      // Resolve domain to IP for SSRF check
      const { address } = await dns.lookup(hostname);
      if (isIpPrivate(address)) {
        throw new axios.Cancel(`Request to private IP blocked. ${hostname} resolves to ${address}`);
      }
    }
  } catch (e) {
     // If it's already a cancellation, re-throw it. Otherwise, wrap it.
     if (e instanceof axios.Cancel) throw e;
     throw new Error(`DNS lookup failed for ${hostname}`);
  }
  return config;
}, (error) => Promise.reject(error));

// --- Icon Fetching Logic ---

function normalizeDomain(domain) {
  if (!domain) throw new Error('Domain parameter is required');
  let url = String(domain).trim().toLowerCase();
  
  // Strip protocol if present
  if (url.startsWith('http://') || url.startsWith('https://')) {
    url = url.split('//')[1];
  }
  
  // Strip path and query params
  url = url.split('/')[0].split('?')[0];
  
  // Basic validation
  if (url.length === 0 || url.includes('..') || url.includes('@')) {
    throw new Error('Invalid domain format');
  }
  return url;
}

async function fetchHtml(url) {
  const { data } = await httpClient.get(url, {
    maxContentLength: parseInt(html_payload_limit, 10),
    responseType: 'text',
  });
  return data;
}

function findIconsInHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const icons = [];

  $('link[rel*="icon"], link[rel*="apple-touch-icon"]').each((i, el) => {
    const href = $(el).attr('href');
    if (!href) return;

    const sizes = $(el).attr('sizes');
    let size = 0;
    if (sizes && sizes !== 'any') {
      const sizeMatch = sizes.match(/(\d+)x(\d+)/);
      if (sizeMatch) {
        size = parseInt(sizeMatch[1], 10);
      }
    }
    icons.push({
      href: new URL(href, baseUrl).href,
      size: size || 0,
    });
  });
  return icons;
}

async function getFaviconUrl(domain, desiredSize, magic) {
  const domainsToTry = [domain];
  if (magic) {
    if (domain.startsWith('www.')) {
      domainsToTry.push(domain.substring(4));
    } else {
      domainsToTry.push(`www.${domain}`);
    }
  }

  let allIcons = [];
  let htmlParseSuccess = false;

  for (const d of domainsToTry) {
    for (const protocol of ['https', 'http']) {
      try {
        const baseUrl = `${protocol}://${d}`;
        const html = await fetchHtml(baseUrl);
        allIcons = allIcons.concat(findIconsInHtml(html, baseUrl));
        htmlParseSuccess = true;
        break; 
      } catch (e) { /* Continue */ }
    }
    
    // Only add default /favicon.ico if HTML parsing failed for this domain
    if (!htmlParseSuccess) {
      allIcons.push({ href: `https://${d}/favicon.ico`, size: 0 });
      allIcons.push({ href: `http://${d}/favicon.ico`, size: 0 });
    }
    
    if (htmlParseSuccess) break; // If we found icons from HTML, we have the best source
  }
  
  if (allIcons.length === 0) {
    throw new Error('No icons found');
  }

  // --- Best-fit Sizing Logic ---
  let bestFit = allIcons
    .filter(icon => icon.size >= desiredSize)
    .sort((a, b) => a.size - b.size)[0];
  
  if (!bestFit) {
    bestFit = allIcons.sort((a, b) => b.size - a.size)[0];
  }
  
  return (bestFit || allIcons[0]).href;
}

async function fetchAndProcessIcon(iconUrl) {
  try {
    const response = await httpClient.get(iconUrl, {
      responseType: 'arraybuffer',
      maxContentLength: parseInt(icon_payload_limit, 10),
    });

    const contentType = response.headers['content-type'] || 'application/octet-stream';
    if (!contentType.startsWith('image/')) {
      throw new Error('Fetched file is not an image');
    }

    return {
      buffer: response.data,
      contentType,
      href: iconUrl
    };
  } catch (error) {
    if (axios.isCancel(error)) throw error;
    throw new Error(`Failed to fetch icon: ${iconUrl}`);
  }
}

// --- Main Request Handler ---

app.get('/', async (req, res, next) => {
  try {
    // 1. Parse all query params case-insensitively
    const query = {};
    Object.keys(req.query).forEach(k => {
      query[k.toLowerCase()] = req.query[k];
    });

    const {
      domain,
      s,
      size = '64', // Keep as string for parsing
      m,
      magic,
      b64,
    } = query;
    
    const desiredSize = parseInt(s || size, 10);
    if (isNaN(desiredSize)) {
      throw new Error('Invalid size parameter');
    }

    // A flag is considered true if the key exists (e.g., &m or &m=true)
    const useMagic = (m !== undefined || magic !== undefined);
    const useBase64 = (b64 !== undefined);
    const cleanDomain = normalizeDomain(domain);
    
    // 2. Check Cache
    const cacheKey = `favicon:${cleanDomain}:${desiredSize}:${useMagic}`;
    if (G_CACHE_ENABLED) {
      const cachedData = await cacheStore.get(cacheKey);
      if (cachedData) {
        const { buffer, contentType, href } = JSON.parse(cachedData);
        // We must convert the JSON buffer (which is base64) back to a real Buffer
        const imageBuffer = Buffer.from(buffer, 'base64'); 

        if (useBase64) {
          return res.json({
            href,
            base64: `data:${contentType};base64,${imageBuffer.toString('base64')}`
          });
        }
        return res.setHeader('Content-Type', contentType).send(imageBuffer);
      }
    }
    
    // 3. Cache Miss: Fetch and Process
    const iconUrl = await getFaviconUrl(cleanDomain, desiredSize, useMagic);
    const { buffer: imageBuffer, contentType, href } = await fetchAndProcessIcon(iconUrl);

    // 4. Save to Cache
    if (G_CACHE_ENABLED) {
      // Store the buffer as base64 in the cache to make it JSON-safe
      const cacheValue = JSON.stringify({
        buffer: imageBuffer.toString('base64'),
        contentType,
        href,
      });
      await cacheStore.set(cacheKey, cacheValue);
    }

    // 5. Send Response
    if (useBase64) {
      return res.json({
        href,
        base64: `data:${contentType};base64,${imageBuffer.toString('base64')}`
      });
    }
    return res.setHeader('Content-Type', contentType).send(imageBuffer);

  } catch (error) {
    next(error); // Pass to global error handler
  }
});

// --- Health Check & Error Handling ---

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use((err, req, res, next) => {
  console.error(err.message);
  let statusCode = 500;
  if (err.message.includes('Invalid') || err.message.includes('required')) {
    statusCode = 400;
  } else if (err.message.includes('No icons found') || (err.response && err.response.status === 404)) {
    statusCode = 404;
  } else if (err.message.includes('timeout') || err.code === 'ECONNABORTED' || err.message.includes('DNS')) {
    statusCode = 504;
  } else if (err.message.includes('blocked')) {
    statusCode = 403; // Forbidden
  }
  
  res.status(statusCode).json({
    error: err.message || 'An unexpected error occurred'
  });
});

app.listen(port, () => {
  console.log(`Favicon Fetcher listening on port ${port}`);
});

