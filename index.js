const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const https = require('https');
const http2 = require('http2');
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
} = env;

const DEFAULT_USER_AGENT = custom_user_agent || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const G_CACHE_ENABLED = String(cache_enabled).toLowerCase() === 'true';
const G_DEBUG = String(debug).toLowerCase() === 'true';

const logDebug = (...args) => {
  if (G_DEBUG) console.log(...args);
};

// --- DNS Configuration (Dynamic from Env Vars with System Fallback) ---
const DOH_URLS = [process.env.DOH1, process.env.DOH2].filter(Boolean);

if (DOH_URLS.length > 0) {
    console.log(`DNS over HTTPS (DoH) is enabled with ${DOH_URLS.length} provider(s).`);
} else {
    console.log('DoH not configured. Using system default DNS resolver.');
}

// --- Storage Setup ---
let cacheStore;
if (REDIS_URL) {
  console.log('Found Redis URL. Connecting to Redis for caching and rate limiting.');
  const redisOptions = { maxRetriesPerRequest: null, enableReadyCheck: false };
  if (REDIS_URL.includes('rediss://')) {
    redisOptions.tls = { rejectUnauthorized: false };
  }
  const redisClient = new IORedis(REDIS_URL, redisOptions);
  cacheStore = {
    get: (key) => redisClient.get(key),
    set: (key, value) => redisClient.set(key, value, 'EX', parseInt(cache_ttl_seconds, 10)),
    redisClient // for rate limiter
  };
} else {
  console.warn('WARNING: No Redis URL found. Falling back to in-memory cache.');
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
        const [unit, countStr] = part.trim().includes(':') ? part.trim().split(':') : ['rps', part.trim()];
        const max = parseInt(countStr, 10);
        if (isNaN(max)) return null;
        const windowMultipliers = { rps: 1, rpm: 60, rph: 3600, rpd: 86400 };
        const windowMs = (windowMultipliers[unit] || 0) * 1000;
        return windowMs > 0 ? { max, windowMs } : null;
    }).filter(Boolean);
}

const createRateLimiter = (limits, keyGenerator) => {
    if (!limits || limits.length === 0) return (req, res, next) => next();
    const limiters = limits.map(limit => {
        const store = cacheStore.redisClient ? new RedisStore({ sendCommand: (...args) => cacheStore.redisClient.call(...args) }) : undefined;
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
    const authHeader = req.headers.authorization;
    const queryKey = Object.keys(req.query).find(k => k.toLowerCase() === 'key');
    const token = authHeader ? authHeader.split(' ')[1] : (queryKey ? req.query[queryKey] : null);
    const keyId = (token && authKeys.get(token)) || 'a';

    if (keyId === 'a') {
        const globalLimiter = createRateLimiter(parseMultiLimit(limitConfig.a), () => 'global_anonymous');
        const ipLimiter = createRateLimiter(parseMultiLimit(limitConfig.i), (req) => req.ip || req.socket.remoteAddress);
        globalLimiter(req, res, (err) => { if (err || res.headersSent) return; ipLimiter(req, res, next); });
    } else {
        createRateLimiter(parseMultiLimit(limitConfig[keyId]), () => `user_${keyId}`)(req, res, next);
    }
});

// --- Security: SSRF Protection & Custom DNS Interceptor ---
const isIpPrivate = (ip) => {
  try {
    const addr = new Address6(ip);
    return addr.isLoopback() || addr.isLinkLocal() || addr.isPrivate() || addr.isInSubnet('::ffff:127.0.0.0/104');
  } catch (e) { return false; }
};

function resolveViaHttp2(hostname, dohUrl, dohIp) {
    return new Promise((resolve, reject) => {
        const url = new URL(dohUrl);
        const authority = `${url.protocol}//${dohIp}:${url.port || 443}`;
        
        const client = http2.connect(authority, {
            servername: url.hostname
        });
        
        client.on('error', (err) => reject(err));
        client.setTimeout(req_timeout_ms, () => {
            client.destroy();
            reject(new Error('Request timed out'));
        });

        const reqPath = `${url.pathname}?name=${hostname}&type=A`;
        const req = client.request({
            [http2.constants.HTTP2_HEADER_SCHEME]: 'https',
            [http2.constants.HTTP2_HEADER_METHOD]: http2.constants.HTTP2_METHOD_GET,
            [http2.constants.HTTP2_HEADER_PATH]: reqPath,
            [http2.constants.HTTP2_HEADER_AUTHORITY]: url.hostname,
            'accept': 'application/dns-json',
            'user-agent': DEFAULT_USER_AGENT
        });

        req.setEncoding('utf8');
        let data = '';
        req.on('data', (chunk) => { data += chunk; });
        req.on('end', () => {
            client.close();
            try {
                const jsonResponse = JSON.parse(data);
                const answers = (jsonResponse.Answer || []).filter(a => a.type === 1).map(a => a.data);
                if (answers.length > 0) {
                    resolve(answers[0]);
                } else {
                    reject(new Error(`No A records found for ${hostname} via ${dohUrl}`));
                }
            } catch (parseError) {
                reject(new Error(`Failed to parse DoH JSON response: ${parseError.message}`));
            }
        });
        req.end();
    });
}

async function resolveHostname(hostname) {
    if (new Address6(hostname).isValid()) return hostname;

    if (DOH_URLS.length > 0) {
        for (const dohUrl of DOH_URLS) {
            try {
                const url = new URL(dohUrl);
                logDebug(`Resolving DoH server IP for ${url.hostname} via system DNS...`);
                const { address: dohIp } = await dns.lookup(url.hostname);
                logDebug(`DoH server ${url.hostname} resolved to ${dohIp}.`);
                
                logDebug(`Resolving ${hostname} via HTTP/2 DoH at ${dohUrl}`);
                return await resolveViaHttp2(hostname, dohUrl, dohIp);
            } catch (e) {
                logDebug(`DoH lookup via ${dohUrl} failed: ${e.message}`);
            }
        }
        logDebug('All configured DoH lookups failed. Falling back to system DNS.');
    }
    
    logDebug(`Resolving ${hostname} via system DNS...`);
    const { address } = await dns.lookup(hostname);
    return address;
}

httpClient.interceptors.request.use(async (config) => {
  const url = new URL(config.url);
  const { hostname } = url;
  try {
    const resolvedIp = await resolveHostname(hostname);
    logDebug(`${hostname} resolved to ${resolvedIp}`);
    if (isIpPrivate(resolvedIp)) {
      throw new axios.Cancel(`Request to private IP blocked: ${hostname} resolved to ${resolvedIp}`);
    }
    url.hostname = resolvedIp;
    config.url = url.toString();
    config.headers['Host'] = hostname;
    return config;
  } catch (e) {
    if (axios.isCancel(e)) throw e;
    throw new Error(`DNS lookup failed for ${hostname}: ${e.message}`);
  }
});


// --- Icon Fetching Logic ---
function normalizeDomain(domain) {
  if (!domain) throw new Error('Domain parameter is required');
  let url = String(domain).trim().toLowerCase().replace(/^https?:\/\//, '');
  url = url.split('/')[0].split('?')[0];
  if (url.length === 0 || url.includes('..') || url.includes('@')) throw new Error('Invalid domain format');
  return url;
}

async function fetchHtml(url) {
  const response = await httpClient.get(url, {
    maxContentLength: parseInt(html_payload_limit, 10),
    responseType: 'text'
  });
  return { data: response.data, finalUrl: response.request.res.responseUrl || url };
}

function findIconsInHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const icons = [];
  $('link[rel*="icon"], link[rel*="apple-touch-icon"]').each((i, el) => {
    const href = $(el).attr('href');
    if (!href) return;
    const sizes = $(el).attr('sizes');
    const sizeMatch = sizes && sizes !== 'any' ? sizes.match(/(\d+)x(\d+)/) : null;
    const size = sizeMatch ? parseInt(sizeMatch[1], 10) : 0;
    try {
      icons.push({ href: new URL(href, baseUrl).href, size });
    } catch (e) { /* Ignore invalid URLs */ }
  });
  return icons;
}

async function getFaviconUrls(domain, desiredSize, magic) {
  const domainsToConsider = new Set([domain]);
  if (magic) {
    domainsToConsider.add(domain.startsWith('www.') ? domain.substring(4) : `www.${domain}`);
  }

  let allIcons = [];
  for (const d of [...domainsToConsider]) {
    for (const protocol of ['https', 'http']) {
      try {
        const { data, finalUrl } = await fetchHtml(`${protocol}://${d}`);
        allIcons.push(...findIconsInHtml(data, finalUrl));
        domainsToConsider.add(new URL(finalUrl).hostname);
        break;
      } catch (e) {
        logDebug(`Could not fetch HTML from ${protocol}://${d}: ${e.message}`);
      }
    }
  }

  for (const d of domainsToConsider) {
    allIcons.push({ href: `https://${d}/favicon.ico`, size: 0 });
  }

  allIcons.sort((a, b) => {
    const aDiff = Math.abs(a.size - desiredSize);
    const bDiff = Math.abs(b.size - desiredSize);
    if (a.size >= desiredSize && b.size < desiredSize) return -1;
    if (a.size < desiredSize && b.size >= desiredSize) return 1;
    return aDiff - bDiff;
  });

  const uniqueUrls = [...new Set(allIcons.map(icon => icon.href))];
  if (uniqueUrls.length === 0) throw new Error('No potential icon URLs found');
  return uniqueUrls;
}

async function fetchAndProcessIcon(iconUrl) {
  const response = await httpClient.get(iconUrl, {
    responseType: 'arraybuffer',
    maxContentLength: parseInt(icon_payload_limit, 10),
    validateStatus: (status) => status >= 200 && status < 300,
  });
  const contentType = response.headers['content-type'] || 'application/octet-stream';
  if (!contentType.startsWith('image/')) throw new Error(`Not an image: ${contentType}`);
  return { buffer: response.data, contentType, href: iconUrl };
}

// --- Main Request Handler ---
app.get('/', async (req, res, next) => {
  try {
    const { domain, size = '64', m, magic, b64 } = { ...req.headers, ...req.query };
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
  else if (err.message.includes('No valid icons') || err.message.includes('No potential icon')) statusCode = 404;
  else if (err.message.includes('timeout') || err.code === 'ECONNABORTED' || err.message.includes('DNS')) statusCode = 504;
  else if (err.message.includes('blocked')) statusCode = 403;
  res.status(statusCode).json({ error: err.message || 'An unexpected error occurred' });
});

app.listen(port, () => console.log(`Favicon Fetcher listening on port ${port}`));

