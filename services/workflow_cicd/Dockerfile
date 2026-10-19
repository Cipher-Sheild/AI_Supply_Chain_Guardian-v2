FROM python:3.12-slim

# NOTE: matches code_security's convention — WORKDIR is /service, not /app.
# If you need to exec into this container later, remember:
#   docker exec <container> cat /service/app/<file>
WORKDIR /service

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==26.2 setuptools==83.0.0
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

RUN useradd --uid 10001 --create-home guardian && chown -R guardian:guardian /service
ENV HOME=/home/guardian
USER 10001:10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]