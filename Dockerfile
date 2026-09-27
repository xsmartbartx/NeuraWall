# syntax=docker/dockerfile:1.7
# NeuraWall — one image for both the control plane (`neurawall server`) and the node agent
# (`neurawall agent run`).

# ---------------------------------------------------------------- console build
FROM node:22-alpine AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
RUN npx tsc -b && npx vite build --outDir /out --emptyOutDir

# ---------------------------------------------------------------- python build
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --extra postgres
COPY neurawall/ ./neurawall/
COPY --from=console /out ./neurawall/services/control_plane/static
RUN uv sync --frozen --no-dev --extra postgres

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="NeuraWall" \
      org.opencontainers.image.description="AI-assisted firewall: deterministic enforcement, three-tier inference, human-approved policy" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 neurawall \
 && useradd --system --uid 10001 --gid neurawall --home-dir /data --shell /usr/sbin/nologin neurawall \
 && mkdir -p /data /var/lib/neurawall-agent && chown neurawall:neurawall /data /var/lib/neurawall-agent
COPY --from=build --chown=neurawall:neurawall /app /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    NEURAWALL_DATA_DIR=/data \
    NEURAWALL_ENVIRONMENT=production
WORKDIR /data
USER neurawall
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"
ENTRYPOINT ["tini", "--", "neurawall"]
CMD ["server"]
