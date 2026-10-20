# =============================================================================
# Bayora Client LLM — Deterministic mock model under test
# Provides per-session context isolation and simulated KV-cache
# =============================================================================
FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# --- Final stage ---
FROM python:3.12-slim

RUN groupadd -r -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -d /app -s /sbin/nologin appuser

COPY --from=builder /install /usr/local

WORKDIR /app
COPY app/ ./app/
RUN chown -R appuser:appuser /app

USER appuser
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
