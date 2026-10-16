FROM python:3.12-slim

WORKDIR /service

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir torch==2.5.1+cpu --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 . .

EXPOSE 8000

RUN useradd --uid 10001 --create-home guardian && mkdir -p /data && chown guardian:guardian /data
ENV HOME=/home/guardian OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false
USER 10001:10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
