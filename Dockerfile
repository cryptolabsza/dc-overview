FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"
LABEL org.opencontainers.image.description="DC Overview - GPU Datacenter Monitoring Suite"
LABEL org.opencontainers.image.licenses="MIT"

# Build arguments for version info
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown

# Set as environment variables (available at runtime)
ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_BRANCH=${GIT_BRANCH}
ENV BUILD_TIME=${BUILD_TIME}

# Install system dependencies
# - openssh-client: SSH connections to workers for exporter deployment
# - sshpass: Password-based SSH authentication
# - curl: Health checks and API calls
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install --no-cache-dir .

# Create data directories
RUN mkdir -p /data /app/ssh_keys

# Default port (can be overridden via environment variable)
ENV DC_OVERVIEW_PORT=5001
ENV DC_OVERVIEW_DATA=/data
ENV FLASK_ENV=production

# Expose default port (actual port binding is done in docker-compose)
EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${DC_OVERVIEW_PORT}/api/health || exit 1

# Run with gunicorn
# Use 1 worker to prevent duplicate background tasks
# 4 threads handles concurrent requests for dashboard use
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${DC_OVERVIEW_PORT} --workers 1 --threads 4 dc_overview.app:app"]
