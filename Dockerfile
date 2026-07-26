FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY sentinel ./sentinel
RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /wheels

FROM python:3.12-slim

LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Safe reconnaissance for authorized security assessments" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/sentinel

COPY --from=builder /wheels /wheels

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel --create-home sentinel \
    && mkdir /output \
    && chown sentinel:sentinel /output \
    && python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

WORKDIR /output
USER sentinel

ENTRYPOINT ["sentinel"]
CMD ["--help"]
