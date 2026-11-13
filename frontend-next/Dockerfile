# Install and build always run on the BUILD machine's native CPU (never under QEMU emulation, which made the arm64 image
# many times slower). The output is platform-independent JavaScript; only the small runner stage is per-architecture.
FROM --platform=$BUILDPLATFORM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
# Reproducible install from the lockfile; the BuildKit cache mount keeps downloaded packages between builds,
# and the retry flags survive a flaky registry connection.
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=5000 --fetch-timeout=120000

FROM --platform=$BUILDPLATFORM node:22-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
# The image optimizer is disabled (next.config.ts) and unused: do not ship its native library, which carries its own CVEs.
RUN rm -rf node_modules/sharp node_modules/@img node_modules/@emnapi
# Run as an unprivileged user, never root.
USER node
EXPOSE 3000
CMD ["node", "server.js"]
