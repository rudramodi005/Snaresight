# Multi-stage production container for SnareSight Web Dashboard
FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and build production assets
COPY . .
RUN npm run build

# --- Runtime Web Server Stage ---
FROM nginx:alpine-slim AS runner

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Add custom non-root reverse proxy configuration
COPY <<'EOF' /etc/nginx/conf.d/snaresight.conf
server {
    listen 5173;
    server_name localhost;

    root /usr/share/nginx/html;
    index index.html;

    # SPA routing fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Reverse proxy API requests to backend
    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Server-Sent Events streaming buffer control
    location /api/v1/stream/ {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}
EOF

# Copy compiled assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 5173

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:5173/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

