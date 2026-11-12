FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
# Reproducible install from the lockfile; the BuildKit cache mount keeps downloaded packages between builds,
# and the retry flags survive a flaky registry connection.
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=5000 --fetch-timeout=120000

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
