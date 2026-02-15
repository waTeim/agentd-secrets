# --- Build stage ---
FROM node:22-bookworm-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# --- Production stage ---
FROM node:22-bookworm-slim

# Install Playwright system dependencies for Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libatspi2.0-0 \
    libwayland-client0 \
    fonts-liberation \
    fonts-noto-color-emoji \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a named non-root user for the runtime process (fixed UID/GID for K8s)
RUN groupadd --gid 1500 agentd && \
    useradd --uid 1500 --gid 1500 --create-home --shell /usr/sbin/nologin agentd

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# Install Playwright browsers (chromium only) into a fixed path
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/local/lib/pw-browsers
RUN npx playwright install chromium

COPY --from=builder /app/dist ./dist

RUN chown -R agentd:agentd /app

USER agentd

EXPOSE 8080

CMD ["node", "dist/server.js"]
