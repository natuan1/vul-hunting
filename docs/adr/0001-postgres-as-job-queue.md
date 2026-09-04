# Postgres as the job queue

Recon runs take 10–60 minutes and verifications are many short jobs, so the worker needs a queue — but we use plain Postgres (jobs table with `FOR UPDATE SKIP LOCKED`) instead of adding Redis, RabbitMQ, or Celery/Temporal infrastructure. Local-first docker compose stays at three services (Next.js, worker, Postgres), jobs and data share transactions, and one backup covers everything.

## Considered options

- **Redis + RQ/Celery** — purpose-built, but a fourth service to run, monitor, and back up for a single-user app.
- **Temporal** — durable workflows are attractive for long recon pipelines, but operationally far too heavy for v1.

## Consequences

We own retry, visibility timeout, and dead-letter logic ourselves. If job throughput ever outgrows Postgres, the queue abstraction must be swapped (worker code touches queue only through one module to keep that door open).
