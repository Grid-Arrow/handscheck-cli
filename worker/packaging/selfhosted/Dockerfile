# Self-hosted bundle (Track S): our own Python (python-build-standalone, glibc 2.17+, so Ubuntu 16.04–24.04)
# with the handscheck wheel and its pinned dependencies, as one directory: handscheck/{python/,bin/hc}.
# Build with worker/packaging/selfhosted/build.sh; the build context is worker/.

ARG PBS_RELEASE=20261026
ARG PBS_PYTHON=3.12.16

# ── the wheel and the hashed requirements (on the build machine) ─────────────
FROM --platform=$BUILDPLATFORM python:3.12-slim-bookworm AS wheel
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /bin/
ENV UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
COPY rules/ rules/
RUN uv build --wheel --out-dir /out \
    && uv export --frozen --no-dev --no-emit-project --format requirements-txt -o /out/requirements.txt

# ── python-build-standalone, checked against a pinned SHA256 ─────────────────
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS python
ARG TARGETARCH PBS_RELEASE PBS_PYTHON
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64;  sha=6a79e922e50006b601f29e688407659da1c2b86ebcd4e9c7254cf234be8b89de ;; \
      arm64) triple=aarch64; sha=a945427411dc6851a1393533b74a4a1ac434321ae397f2ec69897a9b4fde032b ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    name="cpython-${PBS_PYTHON}+${PBS_RELEASE}-${triple}-unknown-linux-gnu-install_only.tar.gz"; \
    curl -fsSL -o /python.tar.gz \
      "https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/${name}"; \
    echo "${sha}  /python.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/handscheck && tar -xzf /python.tar.gz -C /opt/handscheck

# ── assemble on the target architecture ───────────────────────────────────────
FROM debian:bookworm-slim AS bundle
COPY --from=python /opt/handscheck /opt/handscheck
COPY --from=wheel /out /tmp/build
COPY packaging/selfhosted/hc /opt/handscheck/bin/hc
COPY packaging/selfhosted/install.sh packaging/selfhosted/sudoers-handscheck /opt/handscheck/
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore
# Wheels for glibc 2.17 (manylinux2014) only: the build machine's newer glibc would otherwise pull
# manylinux_2_28 wheels (cryptography) that fail on Ubuntu 16.04 (glibc 2.23).
RUN set -eu; py=/opt/handscheck/python/bin/python3; \
    site=/opt/handscheck/python/lib/python3.12/site-packages; \
    m=$(uname -m); \
    tags="--platform manylinux2014_$m --platform manylinux_2_17_$m --platform manylinux2010_$m \
          --platform manylinux1_$m --implementation cp --python-version 3.12 --abi cp312 --abi abi3 --abi none"; \
    "$py" -m pip install --no-deps --only-binary :all: $tags --target "$site" \
        --require-hashes -r /tmp/build/requirements.txt; \
    "$py" -m pip install --no-deps --only-binary :all: $tags --target "$site" /tmp/build/*.whl; \
    "$py" -m pip uninstall -y -q pip; \
    rm -rf /opt/handscheck/python/lib/python3.12/test /opt/handscheck/python/lib/python3.12/idlelib \
           /opt/handscheck/python/lib/python3.12/tkinter /opt/handscheck/python/lib/python3.12/ensurepip \
           /opt/handscheck/python/lib/itcl* /opt/handscheck/python/lib/tcl* /opt/handscheck/python/lib/tk*; \
    "$py" -m compileall -q /opt/handscheck/python/lib/python3.12 >/dev/null || true; \
    chmod 755 /opt/handscheck/bin/hc /opt/handscheck/install.sh; chmod 644 /opt/handscheck/sudoers-handscheck; \
    /opt/handscheck/bin/hc version; \
    version=$("$py" -I -c 'import handscheck; print(handscheck.__version__)'); \
    arch=$(dpkg --print-architecture); \
    mkdir /out && tar -C /opt -czf "/out/handscheck-${version}-linux-${arch}.tar.gz" handscheck

FROM scratch AS out
COPY --from=bundle /out/ /
