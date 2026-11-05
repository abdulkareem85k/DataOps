FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Required native libraries for the later WeasyPrint PDF-report milestone.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libcairo2 \
       libffi8 \
       libgdk-pixbuf-2.0-0 \
       libharfbuzz0b \
       libpango-1.0-0 \
       libpangoft2-1.0-0 \
       libpangocairo-1.0-0 \
       shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml backend/uv.lock ./
RUN pip install --no-cache-dir uv==0.13.7 \
    && uv sync --frozen --no-dev

COPY backend/app ./app
EXPOSE 8000

CMD ["uv", "run", "--frozen", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
