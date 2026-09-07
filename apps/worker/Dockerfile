# docker CLI để worker chạy container tooling sibling qua docker.sock
# (ADR-0003 — không cài daemon, chỉ client)
FROM docker:29-cli AS docker-cli

FROM python:3.12-slim

WORKDIR /app

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY tests ./tests

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
