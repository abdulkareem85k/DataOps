FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap nikto \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner \
    && mkdir -p /var/lib/scanner-runner \
    && chown -R scanner:scanner /var/lib/scanner-runner

WORKDIR /app
COPY runner/pyproject.toml runner/uv.lock ./
RUN pip install --no-cache-dir uv==0.13.7 \
    && uv sync --frozen --no-dev

COPY runner/app ./app
USER 10001:10001
EXPOSE 9000

CMD ["uv", "run", "--frozen", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
