# Favicon Fetcher Service

This is a high-performance, stateless-first Node.js application that fetches, caches, and serves website favicons.

It can be run as a "stateless" service (for local testing, using in-memory cache) or as a stateful, production-ready service connected to Redis for high-performance caching and rate-limiting.

## Features

- **Robust Icon Discovery:** Parses site HTML for `<link>` tags (including `apple-touch-icon`, etc.) before falling back to `/favicon.ico`.
- **Best-Fit Sizing:** Intelligently finds the icon that best matches the requested size.
- **Proxy Service:** Fetches and returns the image directly, masking the origin and bypassing client-side CORS issues.
- **Base64 Format:** Optional flag (`b64`) to return a JSON object with a CORS-safe `data:` URI.
- **`www` Magic:** Optional flag (`m`) to try `www.domain.com` if `domain.com` fails (and vice-versa).
- **Hybrid Storage:** Uses Redis if `REDIS_URL` is provided, otherwise falls back to a RAM-limited in-memory cache.
- **Advanced Rate Limiting:** Configure multiple concurrent limits per API key. For anonymous users, both global limits (`limita`) and per-IP limits (`limiti`) can be applied together.
- **Secure:** Includes SSRF protection, request timeouts, and standard security headers.
- **Deployable:** One-click deploy buttons for Heroku and GCP Cloud Run.

---

## API Usage

**Base URL:** `https://your-app-url.com/`

All query parameters, their values (e.g., `true`, `TRUE`), and the domain are **case-insensitive**.

- **`domain` (Required):** The domain to fetch. e.g., `google.com`.
- **`s` / `size` (Optional):** The desired icon size (if available). Default: `64`. e.g., `s=16`.
- **`m` / `magic` (Optional):** Set to `true` (or just include the key, e.g., `&m`) to enable `www` <-> non-`www` fallback.
- **`b64` (Optional):** Set to `true` (or just include the key, e.g., `&b64`) to receive a JSON response with base64 data.
- **`key` (Optional):** An alternative way to provide an API key.

### Example 1: Get Image (Default)

Request: `GET /?domain=Github.com&S=128`

- **Response:**
- **Status:** `200 OK`
- **Headers:** `Content-Type: image/png`
- **Body:** `(raw image data)`

### Example 2: Get Base64 JSON

Request: `GET /?domain=google.com&s=128&b64=TRUE`

- **Response:**
- **Status:** `200 OK`
- **Headers:** `Content-Type: application/json`
- **Body:**
  ```json
  {
    "href": "https://www.google.com/favicon.ico",
    "base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhE..."
  }
  ```

### Example 3: Authentication (2 ways)

**Method 1: Header (Recommended)**
Request: `GET /?domain=google.com`
Header: `Authorization: Bearer mysecretkey0`

**Method 2: Query Parameter**
Request: `GET /?domain=google.com&Key=mysecretkey0`

---

## Deployment

### Deploy to Heroku

You have two options for Heroku. The Redis-backed version is **strongly** recommended for any real use.

**Option 1: Deploy with Redis (Production Ready)**
This button provisions the app AND a free `heroku-redis` instance. It reads its configuration from `app.json`.

[![Deploy to Heroku with Redis](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kaerez/favicon-fetcher%filename=app.json)

**Option 2: Deploy with In-Memory Cache (Testing Only)**
This version uses a RAM-based cache and will **lose all data** on every restart. It reads its configuration from `app-no-redis.json`.

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kaerez/favicon-fetcher&filename=app-no-redis.json)

### Deploy to GCP Cloud Run

This button deploys the container using the `cloudbuild.yaml` configuration. To run in production, you **must** manually set up a Google Memorystore (Redis) instance and provide the `REDIS_URL` as an environment variable in the Cloud Run service settings.

[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run)

---

## Local Development

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/kaerez/favicon-fetcher.git
    cd favicon-fetcher
    ```

2.  **Create a local environment file:** Copy the template to a new `.env` file.
    ```sh
    cp .env.example .env
    ```

3.  **Customize your local config:** Open `.env` and add any API keys (`AUTHN0=...`) or custom limits you wish to test.

4.  **Run with Docker Compose:** This command will build the app, start the Node.js and Redis containers, and link them together.
    ```sh
    docker-compose up --build
    ```

The service will be available at `http://localhost:8080`.

---

## Environment Variables

This application is configured entirely by environment variables, following the [Twelve-Factor App](https://12factor.net/config) methodology. The file `.env.example` serves as the master template for all required variables.

Variable *keys* (e.g., `PORT`, `AUTHN0`) are **case-sensitive**. Variable *values* are **case-insensitive**.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | The port the server listens on. | `8080` |
| `REDIS_URL` | Connection string for Redis. If not set, the app falls back to in-memory mode. | `""` (none) |
| `LIMIT_SEPARATOR` | The character used to separate multiple rate limit rules. Defaults to `,`. Set to `;` for GCP. | `,` |
| `CACHE_ENABLED` | Enables/disables caching (`true`/`false`). | `true` |
| `CACHE_TTL_SECONDS` | Cache expiration time in seconds. | `86400` (24h) |
| `IN_MEMORY_CACHE_MAX_SIZE`| Max cache size (in bytes) for in-memory mode. | `52428800` (50MB) |
| `REQ_TIMEOUT_MS` | Milliseconds to wait for target sites. | `5000` (5s) |
| `HTML_PAYLOAD_LIMIT` | Max HTML size to download (in bytes). | `250000` (250KB) |
| `ICON_PAYLOAD_LIMIT` | Max icon file size to download (in bytes). | `2097152` (2MB) |
| `CUSTOM_USER_AGENT` | Override the default User-Agent string. | `Mozilla/5.0 (Macintosh...)` |
| `AUTHN[0-1000]` | API key. The number must be unique for each key. e.g., `AUTHN0=key_abc`. | `""` |
| `LIMIT[0-1000]` | Rate limit for the corresponding API key. e.g., `LIMIT0=rps:10,rpm:500`. | `""` |
| `LIMITA` | **Global** rate limit for all anonymous users. | `rps:1,rpm:60` |
| `LIMITI` | **Per-IP** rate limit for anonymous users. Applied *in addition to* `LIMITA`.| `""` |

### Limit Format

Limits are defined as a comma-separated (or semicolon-separated for GCP) list of `unit:value` pairs. A request must pass all defined limits to succeed.
- **Units:** `rps` (requests per second), `rpm` (minute), `rph` (hour), `rpd` (day).
- **Value of `0`:** A value of 0 for any unit blocks all requests for that key/rule.
- **Example:** `rps:10,rpm:500,rph:2000`
