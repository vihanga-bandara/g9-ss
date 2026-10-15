# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client gosu \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 appuser \
    && groupadd --gid 1000 rmapkeys \
    && useradd --uid 10001 --gid 10001 --groups rmapkeys --no-create-home --shell /usr/sbin/nologin appuser

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

RUN chown -R appuser:appuser /app/src
RUN mkdir -p /app/storage \
    && chown appuser:appuser /app/storage

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

