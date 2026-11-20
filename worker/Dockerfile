# Development image for the worker and the `hc` CLI.
# The repo is bind-mounted at /repo; the virtualenv, uv cache and standalone state live in Docker volumes,
# so nothing is installed on the developer's machine.
FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client git \
    && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/venv \
    UV_CACHE_DIR=/uv-cache \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    HANDSCHECK_STATE_DIR=/state \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /repo/worker

# `docker compose run --rm worker hc --help` → `uv run hc --help` (syncs the venv from uv.lock first).
ENTRYPOINT ["uv", "run"]
CMD ["hc", "--help"]
