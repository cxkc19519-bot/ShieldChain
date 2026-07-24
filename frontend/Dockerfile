# syntax=docker/dockerfile:1.7
FROM node:24-alpine3.22 AS builder

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29.1-alpine3.22 AS runtime

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder --chown=101:101 /build/frontend/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
