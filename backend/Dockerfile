# syntax=docker/dockerfile:1.7
FROM python:3.14.6-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
COPY backend/pyproject.toml /build/backend/pyproject.toml
COPY backend/requirements-runtime.lock /build/backend/requirements-runtime.lock
COPY backend/src /build/backend/src
RUN /opt/venv/bin/python -m pip install -r /build/backend/requirements-runtime.lock \
    && /opt/venv/bin/python -m pip install --no-deps /build/backend

FROM python:3.14.6-slim-bookworm AS runtime

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --gid 10001 shieldchain \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin shieldchain \
    && mkdir -p /var/lib/shieldchain/knowledge /app/backend \
    && chown -R 10001:10001 /var/lib/shieldchain /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 backend/alembic.ini /app/backend/alembic.ini
COPY --chown=10001:10001 backend/migrations /app/backend/migrations
COPY --chown=10001:10001 sample_docs/security_vertical /app/sample_docs/security_vertical
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "shieldchain.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
