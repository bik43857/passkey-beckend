# ---- Build stage -----------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
# VITE_API_BASE_URL is deliberately left empty here — in production, Nginx
# (see nginx.conf) serves the frontend AND proxies /api on the SAME origin,
# so the frontend never needs a cross-origin API base URL at all. This also
# means the session cookie is always same-origin, which is the simplest and
# safest configuration for SameSite cookies (Section 18).
RUN npm run build

# ---- Runtime stage -----------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://localhost:80/ >/dev/null || exit 1
