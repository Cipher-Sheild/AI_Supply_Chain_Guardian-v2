FROM python:3.12-slim

WORKDIR /service

# Native Guardian analysis requires no external scanner executables.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip==26.2 setuptools==83.0.0 \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user and set permissions
RUN groupadd -g 10001 appgroup && useradd --create-home -u 10001 -g appgroup -s /bin/false appuser \
    && mkdir -p /data && chown -R appuser:appgroup /service /data

ENV HOME=/home/appuser
USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
