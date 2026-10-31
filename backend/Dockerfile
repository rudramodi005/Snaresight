# Multi-stage production container for SnareSight Backend Engine
FROM python:3.11-slim AS builder

WORKDIR /build

# Install uv for fast, deterministic dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency specifications
COPY pyproject.toml .

# Install dependencies into virtualenv
RUN uv venv /opt/venv && \
    uv pip install --no-cache -r pyproject.toml

# --- Final Runtime Image ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Create non-root unprivileged security service user
RUN groupadd -g 1001 snaresight && \
    useradd -u 1001 -g snaresight -s /bin/bash -m snaresight

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy backend code and migrations
COPY --chown=snaresight:snaresight . .

# Security hardening: Run as non-root user
USER snaresight

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

