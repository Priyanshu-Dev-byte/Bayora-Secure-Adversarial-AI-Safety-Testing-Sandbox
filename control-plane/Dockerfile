# =============================================================================
# Bayora Control Plane — FastAPI Backend
# Handles: auth, evaluation orchestration, audit log, report export
# =============================================================================
FROM python:3.12-slim AS builder

# Install build dependencies in a separate stage
RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# --- Final stage ---
FROM python:3.12-slim

# Security: create non-root user
RUN groupadd -r -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -d /app -s /sbin/nologin appuser

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY app/ ./app/

# Ensure proper ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

EXPOSE 8000

# Run with uvicorn; --no-access-log reduces information leakage
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
