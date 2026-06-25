# AttackMap container image.
#
# Multi-stage build:
#   - builder: installs attackmap[all] into a venv from PyPI
#   - runtime: copies the venv into a slim base, runs as a non-root user
#
# Build:
#   docker build -t attackmap .
#   docker build --build-arg ATTACKMAP_VERSION=0.1.0 -t attackmap:0.1.0 .
#
# Run:
#   docker run --rm -v "$PWD:/src" attackmap analyze /src --output /src/reports
#
# To use the LLM narrative with the API backend:
#   docker run --rm -e ANTHROPIC_API_KEY -v "$PWD:/src" attackmap \
#     analyze /src --output /src/reports --llm

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS builder

ARG ATTACKMAP_VERSION

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

RUN python -m pip install --upgrade pip \
    && if [ -n "${ATTACKMAP_VERSION}" ]; then \
         pip install "attackmap[all]==${ATTACKMAP_VERSION}"; \
       else \
         pip install "attackmap[all]"; \
       fi


FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

# Non-root user for the container runtime.
RUN groupadd --system --gid 1000 attackmap \
    && useradd --system --uid 1000 --gid attackmap --create-home --home-dir /home/attackmap attackmap

COPY --from=builder /opt/venv /opt/venv

USER attackmap
WORKDIR /src

LABEL org.opencontainers.image.title="AttackMap" \
      org.opencontainers.image.description="AI-assisted defensive security analyzer for codebases." \
      org.opencontainers.image.source="https://github.com/mlaify/AttackMap" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["attackmap"]
CMD ["--help"]
