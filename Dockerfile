# Base image can be overridden: deploy.ps1 imports python:3.12-slim into its own ACR (no Docker Hub limit).
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt requirements.lock* ./
RUN python -m venv /opt/venv \
 && if [ -f requirements.lock ]; then /opt/venv/bin/pip install --require-hashes -r requirements.lock; \
    else /opt/venv/bin/pip install -r requirements.txt; fi
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps .

FROM ${BASE_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_ENV=production \
    PORT=8000
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app
COPY --from=build /opt/venv /opt/venv
USER 10001
WORKDIR /home/app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)" || exit 1
CMD ["python", "-m", "defender_mcp"]
