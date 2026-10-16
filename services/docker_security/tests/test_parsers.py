import pytest
from app.parsing import DockerfileParser, ComposeParser

DOCKERFILE_SAMPLE = """
FROM ubuntu:latest AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y gcc
COPY . .

FROM python:3.11-slim
USER appuser
EXPOSE 8000
CMD ["python", "app.py"]
"""

COMPOSE_SAMPLE = """
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  db:
    image: postgres:16
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

def test_dockerfile_parser_stages():
    parser = DockerfileParser(DOCKERFILE_SAMPLE)
    assert len(parser.stages) == 2
    assert parser.stages[0].stage_name == "builder"
    assert parser.stages[0].base_image == "ubuntu"
    assert parser.stages[0].base_image_tag == "latest"

    final_stage = parser.get_final_stage()
    assert final_stage is not None
    assert final_stage.base_image == "python"
    assert final_stage.base_image_tag == "3.11-slim"
    assert final_stage.is_final_stage is True

def test_compose_parser():
    parser = ComposeParser(COMPOSE_SAMPLE)
    assert parser.is_valid_compose is True
    assert len(parser.services) == 2
    service_names = [s.name for s in parser.services]
    assert "web" in service_names
    assert "db" in service_names

    db_service = next(s for s in parser.services if s.name == "db")
    assert db_service.privileged is True
    assert len(db_service.volumes) == 1
