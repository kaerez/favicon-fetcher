# Favicon Fetcher Service
[![License](https://img.shields.io/badge/License-Personal_NonCommercial-red.svg)](./LICENSE.md)

This repository contains two variants of a high-performance service that fetches, caches, and serves website favicons:
1.  **Docker/Node.js Variant:** A traditional server application designed to run in a Docker container on platforms like Heroku, GCP Cloud Run, or any standard server.
2.  **Cloudflare Worker Variant:** A serverless version rewritten to run on Cloudflare's global edge network for extremely low latency.

## Features

- **Robust Icon Discovery:** Exhaustively parses site HTML (including `www` subdomains and redirects) for `<link>` tags before falling back to `/favicon.ico`.
- **Best-Fit Sizing:** Intelligently finds the icon that best matches the requested size.
- **Proxy Service:** Fetches and returns the image directly, bypassing client-side CORS issues.
- **Base64 Format:** Optional flag (`b64`) to return a JSON object with a CORS-safe `data:` URI.
- **Hybrid Storage:** The Docker version uses Redis or an in-memory cache. The Cloudflare version uses Workers KV.
- **Advanced Rate Limiting:** Configure multiple, concurrent limits per API key or for anonymous users.
- **Resilient DNS (Docker only):** Optionally bypass a faulty system DNS resolver by using DNS over HTTPS (DoH) or specifying custom DNS servers.
- **Debug Logging (Docker only):** Enable detailed logging for troubleshooting.
- **Secure:** Includes SSRF protection, request timeouts, and standard security headers.

---

## API Usage

**Base URL:** `https://your-app-url.com/`

All parameters and their values are **case-insensitive**. Parameters can be provided via URL query string or request headers, with query string values taking precedence.

- **`domain` (Required):** The domain to fetch. e.g., `google.com`.
- **`s` / `size` (Optional):** The desired icon size. Default: `64`.
- **`m` / `magic` (Optional):** Include the key (e.g., `&m`) to enable `www` fallback.
- **`b64` (Optional):** Include the key (e.g., `&b64`) to receive a JSON response.
- **`key` (Optional):** An API key for authenticated requests.

### Example 1: Get Image (Default)

Request: `GET /?domain=Github.com&S=128`

- **Response:**
  - **Status:** `200 OK`
  - **Headers:** `Content-Type: image/png`
  - **Body:** `(raw image data)`

### Example 2: Get Base64 JSON

Request: `GET /?domain=github.com&s=128&b64=TRUE`

- **Response:**
  - **Status:** `200 OK`
  - **Headers:** `Content-Type: application/json`
  - **Body:**
    ```json
    {
      "href": "[https://github.githubassets.com/assets/apple-touch-icon-144x144.png](https://github.githubassets.com/assets/apple-touch-icon-144x144.png)",
      "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhE..."
    }
    ```

### Example 3: Authentication

Request: `GET /?domain=google.com&key=mysecretkey0`
*(Header-based authentication is also supported)*

---

## Deployment

### Deploy to Cloudflare (Recommended for Performance)

The Cloudflare Worker variant runs on Cloudflare's edge network for the lowest possible latency. The deploy button will automatically guide you through creating the required KV namespaces.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kaerez/favicon-fetcher)

**Required Manual Step (After Deployment):**
For security, you must add your API keys as secrets after the initial deployment.
1.  In the Cloudflare dashboard, navigate to your newly deployed Worker.
2.  Go to `Settings` -> `Variables`.
3.  Under `Environment Variables`, click `Add variable`, enter the name (e.g., `AUTHN0`), enter the secret value, and click `Encrypt`.

### Deploy to Heroku (Docker Variant)

**Option 1: Deploy with Managed Redis (Production Ready)**
[![Deploy to Heroku with Redis](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kaerez/favicon-fetcher&filename=app.json)

**Option 2: Deploy Manually or In-Memory**
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kaerez/favicon-fetcher&filename=app-no-redis.json)

### Deploy to GCP Cloud Run (Docker Variant)

[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run)

---

## Local Development (Docker Variant)

1.  **Clone the repository and `cd` into it.**
2.  **Review the example configuration** in `docker-compose.yml` to understand available environment variables.
3.  **(Optional) Customize your local config:**
    - Edit `docker-compose.yml` directly, OR
    - Create a `.env` file with your custom values (Docker Compose will use it automatically)
4.  **Run with Docker Compose:** `docker-compose up --build`

The service will be available at `http://localhost:8080`.

### Example .env File (Optional)
If you prefer using a `.env` file instead of editing `docker-compose.yml`:
```bash
PORT=8080
REDIS_URL=redis://redis:6379
CACHE_ENABLED=true
CACHE_TTL_SECONDS=86400
REQ_TIMEOUT_MS=5000
HTML_PAYLOAD_LIMIT=250000
ICON_PAYLOAD_LIMIT=2097152
DEBUG=false

# Optional: DNS over HTTPS
# DOH1=https://dns.google/dns-query
# DOH2=https://cloudflare-dns.com/dns-query

# Optional: API Keys and Rate Limits
# AUTHN0=your_secret_key_here
# LIMIT0=rps:10,rpm:500

# Anonymous Rate Limits
LIMITA=rps:1,rpm:60
LIMITI=rpm:30
```

---

## Environment Variables (Docker Variant)

Variable *keys* (e.g., `PORT`, `AUTHN0`) are **case-sensitive**.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | The port the server listens on. | `8080` |
| `REDIS_URL` | Connection string for Redis. If not set, the app falls back to in-memory mode. | `""` (none) |
| `DOH1`, `DOH2` | Optional DoH endpoints. `DOH1`: `https://cloudflare-dns.com/dns-query`, `DOH2`: `https://dns.google/dns-query`. | `""` (none) |
| `DEBUG` | Set to `true` to enable detailed console logging for troubleshooting. | `false` |
| `LIMIT_SEPARATOR` | Character for separating multiple rate limit rules. Defaults to `,`. Set to `;` for GCP. | `,` |
| `CACHE_ENABLED` | Enables/disables caching (`true`/`false`). | `true` |
| `CACHE_TTL_SECONDS` | Cache expiration time in seconds. | `86400` (24h) |
| `IN_MEMORY_CACHE_MAX_SIZE`| Max cache size (in bytes) for in-memory mode. | `52428800` (50MB) |
| `REQ_TIMEOUT_MS` | Milliseconds to wait for target sites. | `5000` (5s) |
| `HTML_PAYLOAD_LIMIT` | Max HTML size to download (in bytes). | `250000` (250KB) |
| `ICON_PAYLOAD_LIMIT` | Max icon file size to download (in bytes). | `2097152` (2MB) |
| `CUSTOM_USER_AGENT` | Override the default User-Agent string. | `Mozilla/5.0 (Macintosh...)` |
| `AUTHN[0-1000]` | API key. e.g., `AUTHN0=key_abc`. | `""` |
| `LIMIT[0-1000]` | Rate limit for the corresponding API key. e.g., `LIMIT0=rps:10,rpm:500`. | `""` |
| `LIMITA` | **Global** rate limit for all anonymous users. | `rps:1,rpm:60` |
| `LIMITI` | **Per-IP** rate limit for anonymous users. Applied *in addition to* `LIMITA`.| `""` |

### Limit Format

Limits are defined as a comma/semicolon-separated list of `unit:value` pairs or just `value` (defaults to `rps`).
- **Units:** `rps` (requests per second), `rpm` (minute), `rph` (hour), `rpd` (day).
- **Value of `0`:** Blocks all requests for that key.
- **Examples:** `rps:10,rpm:500`, `10` (same as `rps:10`).

## 📜 License

**Dual Licensed:** Personal Non-Commercial OR Commercial

⚠️ **Important:** This software is available for **personal, non-commercial use only** under the free license.

**Prohibited without commercial license:**
- Business/company use of any kind
- Websites or services accessed by others
- Any gated/monetized/ad-supported use
- Educational/academic/research use
- SaaS or service provision

**Commercial licenses available:** Contact https://www.kalman.co.il

Full terms: [LICENSE.md](./LICENSE.md)
