FROM python:3.12-slim

WORKDIR /service

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip==26.2 setuptools==83.0.0 \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

RUN useradd --uid 10001 --create-home guardian && chown -R guardian:guardian /service
ENV HOME=/home/guardian
USER 10001:10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

