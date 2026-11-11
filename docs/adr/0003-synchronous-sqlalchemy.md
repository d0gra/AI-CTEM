# ADR 0003: Synchronous SQLAlchemy sessions

**Status:** accepted

**Context.** FastAPI supports async handlers, and async database access is common. The tenant context depends on a session hook that runs at the start of every transaction, and the same service code runs in API requests and in worker threads.

**Decision.** Use synchronous SQLAlchemy 2 with psycopg 3. Route handlers are plain functions executed in FastAPI's thread pool; workers call the same services directly.

**Consequences.** One code path for API and workers, simple transaction semantics, and straightforward use of blocking libraries (boto3, subprocess, smtplib). Concurrency per API process is bounded by the thread pool and connection pool; scale with processes. Long outbound I/O happens in workers, not in request handlers.
