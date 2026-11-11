# ADR 0002: PostgreSQL-backed job queue instead of Celery/Dramatiq

**Status:** accepted

**Context.** The platform must track, per job, the tenant, type, configuration, state, progress, retries, errors and cancellation, show it in the UI, enforce per-tenant concurrency and never run a scan twice. With a broker-based queue this state would live in two places (broker and database) that can disagree.

**Decision.** Jobs are rows in `jobs`. Workers claim with `SELECT ... FOR UPDATE SKIP LOCKED`. Enqueueing happens in the same transaction as the business change that causes it. Idempotency is a partial unique index. Retries, dead-lettering, heartbeats, stale-job recovery and cooperative cancellation are implemented in `workers/queue.py` (about 270 lines). Redis is used only for rate limiting.

**Consequences.** No broker to operate; job state is transactional and queryable; tests run the real execution path in-process. Throughput is bounded by PostgreSQL polling, which is adequate for assessment workloads (seconds to minutes per job) but not for high-frequency tasks. If that changes, the `enqueue`/handler interface allows moving execution to a broker while keeping the table as the record.
