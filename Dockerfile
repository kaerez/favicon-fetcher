# --- Stage 1: Builder ---
# Use a Node.js 18 base image for building
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files first to leverage Docker layer caching
COPY package.json package-lock.json ./

# Install only production dependencies to keep the build lean
RUN npm ci --omit=dev

# Copy the rest of the application code
# This will respect the .dockerignore file at the root of the context
COPY . .

# --- Stage 2: Production ---
# Use a slim, secure base image for the final container
FROM node:18-alpine

WORKDIR /app

# Set Node.js to production mode
ENV NODE_ENV=production
# Set a default port, can be overridden by the hosting platform
ENV PORT=8080

# Copy dependencies from the builder stage
COPY --from=builder /app/node_modules ./node_modules

# Copy only the necessary application files from the builder stage
COPY --from=builder /app/index.js ./index.js
COPY --from=builder /app/package.json ./package.json

# Expose the port the app will run on
EXPOSE $PORT

# The command to run the application
CMD ["node", "index.js"]

