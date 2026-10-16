FROM python:3.12-slim
LABEL guardian.case="case_1_4"
WORKDIR /app
USER 10001
HEALTHCHECK CMD ["/bin/true"]
CMD ["/bin/true"]
ENV DATABASE_URL=postgresql://admin:GuardianFakePassword4Only@db/app
