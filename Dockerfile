# Deployable starter image for decision-os-min (NOT a hardened production image —
# put auth/TLS/rate-limiting at the ingress in front of this).
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DECISION_OS_AUDIT=/data/audit.jsonl

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY decision_os_min ./decision_os_min

RUN pip install --no-cache-dir ".[service]" \
    && mkdir -p /data

# Run as non-root.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /data /app
USER appuser

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

# Mount a policy at /config/policy.json and set DECISION_OS_POLICY to use it.
CMD ["decision-os-serve"]
