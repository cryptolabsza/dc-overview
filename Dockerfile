# =============================================================================
# DC Overview - Docker Image
# GPU Datacenter Monitoring Web Application
# =============================================================================

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"
LABEL org.opencontainers.image.description="GPU Datacenter Monitoring - Server Management & Prometheus Targets"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Create app user and directories
RUN useradd -m -s /bin/bash dcuser && \
    mkdir -p /app /data /etc/dc-overview/ssh_keys && \
    chown -R dcuser:dcuser /app /data /etc/dc-overview

WORKDIR /app

# Copy and install the package
COPY --chown=dcuser:dcuser . /app/

# Install dc-overview
RUN pip install --no-cache-dir -e .

# Environment variables
ENV DC_OVERVIEW_PORT=5001
ENV DC_OVERVIEW_DATA=/data
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5001

# Volume for persistent data
VOLUME ["/data", "/etc/dc-overview"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${DC_OVERVIEW_PORT}/api/health || exit 1

# Run as app user
USER dcuser

# Start the web server
CMD ["dc-overview", "serve", "--host", "0.0.0.0"]
