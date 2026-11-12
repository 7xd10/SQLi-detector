# Minimal runtime image. No compiler and no build tools in the final layer --
# the only runtime dependency is httpx, which ships manylinux wheels.
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="sqliscan" \
      org.opencontainers.image.description="SQL injection scanner with baseline differencing, dual-request confirmation and evidence capture" \
      org.opencontainers.image.authors="Youssef Alaoui Hichami <alaouihichamiyoussef@gmail.com>" \
      org.opencontainers.image.source="https://github.com/7xd10/SQLi-detector" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
 && rm -rf /app/src /app/pyproject.toml /app/README.md /app/LICENSE \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sqliscan

# The scanner writes reports, so give it somewhere to write that survives the
# read-only application directory.
WORKDIR /reports
USER sqliscan

ENTRYPOINT ["sqliscan"]
CMD ["--help"]
