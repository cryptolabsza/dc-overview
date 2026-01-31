FROM python:3.11-slim

LABEL org.opencontainers.image.title="RunPod Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for RunPod host metrics"
LABEL org.opencontainers.image.source="https://github.com/cryptolabsza/dc-overview"
LABEL org.opencontainers.image.vendor="CryptoLabs"

WORKDIR /app

# Copy exporter script
COPY runpod_exporter.py /app/

# No additional dependencies needed - uses stdlib only
RUN chmod +x /app/runpod_exporter.py

# Default port
EXPOSE 8623

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8623/health', timeout=5)" || exit 1

ENTRYPOINT ["python3", "/app/runpod_exporter.py"]
