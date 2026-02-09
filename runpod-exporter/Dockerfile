FROM python:3.11-slim

LABEL org.opencontainers.image.title="RunPod Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for RunPod host metrics"
LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"
LABEL org.opencontainers.image.vendor="CryptoLabs"

# Build arguments for version info
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown

# Set as environment variables (available at runtime)
ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_BRANCH=${GIT_BRANCH}
ENV BUILD_TIME=${BUILD_TIME}

WORKDIR /app

# Copy exporter script
COPY runpod_exporter.py /app/

# No additional dependencies needed - uses stdlib only
RUN chmod +x /app/runpod_exporter.py

# Data volume for persistent config (API keys stored in /data/accounts.json)
RUN mkdir -p /data
VOLUME /data

# Default port
EXPOSE 8623

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8623/health', timeout=5)" || exit 1

ENTRYPOINT ["python3", "/app/runpod_exporter.py"]
