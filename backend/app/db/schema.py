"""Whether the database schema matches this build, and the start-up commands built on that.

    python -m app.db.schema migrate [--timeout S]   wait for the database, then apply migrations
    python -m app.db.schema wait [--timeout S]      wait until the schema is at this build's version
    python -m app.db.schema status                  print the schema state and exit 0 when ready

The image's entrypoint uses `migrate` for the migrate role (and for `all`, which migrates at start-up)
and `wait` for every role that serves or works, so a container never starts against a database it
cannot use. /readyz reports the same state.
"""

from __future__ import annotations

import argparse
import sys
import time
from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError, OperationalError

BACKEND = Path(__file__).resolve().parents[2]
MIGRATIONS = BACKEND / "migrations"
# Held for the whole of a migration run, so containers that start together migrate one at a time:
# the second waits, then finds nothing left to apply.
MIGRATION_LOCK = 0x4354454D4D494752  # "CTEMMIGR"

READY_STATES = ("ok", "newer")
PERMANENT_REFUSALS = ("password authentication failed", "does not exist", "no pg_hba.conf entry",
                      "is not permitted to log in")
RUN_MIGRATE = ("run the migrate role against this database (docker run <image> migrate, or the "
               "ctem-migrate Job on Kubernetes), then start this container again")


@lru_cache
def _revisions() -> tuple[frozenset[str], frozenset[str]]:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory(str(MIGRATIONS))
    return frozenset(script.get_heads()), frozenset(r.revision for r in script.walk_revisions())


def expected() -> frozenset[str]:
    """The revisions this build's code is written for."""
    return _revisions()[0]


def state(conn: Connection) -> tuple[str, str]:
    """(state, explanation). The state is one of:

    ok       at this build's version
    newer    migrated by a later release; ready, since migrations only add before they remove
    behind   created, but older than this build
    missing  never migrated: the database is empty
    """
    if conn.execute(text("select to_regclass('public.alembic_version')")).scalar() is None:
        return "missing", "the database schema has not been created"
    try:
        current = frozenset(conn.execute(text("select version_num from alembic_version")).scalars())
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "42501":  # insufficient_privilege
            raise
        conn.rollback()
        # The application role is granted read access to the version by a migration; before it has
        # run, the version cannot be read, and the schema is older than this build.
        return "behind", "the database schema is older than this build"
    heads, known = _revisions()
    if current == heads:
        return "ok", f"schema at {', '.join(sorted(current))}"
    if current and not current & known:
        return "newer", f"schema at {', '.join(sorted(current))}, newer than this build"
    have = ", ".join(sorted(current)) or "no version"
    return "behind", f"the database schema is at {have} and this build needs {', '.join(sorted(heads))}"


def _probe(engine: Engine) -> tuple[str, str]:
    try:
        with engine.connect() as conn:
            return state(conn)
    except OperationalError as exc:
        reason = (str(exc.orig).strip().splitlines() or [type(exc.orig).__name__])[0][:200]
        # The server answered and refused, which waiting will not fix. Anything else (not listening
        # yet, "the database system is starting up", the network) is worth waiting out. libpq gives
        # these no SQLSTATE, so they are recognised by their text.
        if any(marker in reason for marker in PERMANENT_REFUSALS):
            return "refused", f"the database refused the connection: {reason}"
        return "unreachable", f"cannot connect to the database: {reason}"


def _wait(engine: Engine, timeout: float, until: tuple[str, ...]) -> tuple[str, str]:
    deadline, last = time.monotonic() + timeout, None
    while True:
        status, detail = _probe(engine)
        if status in until or status == "refused" or time.monotonic() >= deadline:
            return status, detail
        if detail != last:
            print(f"[ctem] waiting: {detail}", file=sys.stderr, flush=True)
            last = detail
        time.sleep(2)


def migrate(timeout: float) -> int:
    from alembic import command
    from alembic.config import Config

    from app.core.config import get_settings

    engine = create_engine(get_settings().migration_database_url)
    try:
        status, detail = _wait(engine, timeout, ("ok", "newer", "behind", "missing"))
    finally:
        engine.dispose()
    if status in ("unreachable", "refused"):
        print(f"ctem: {detail}. Check CTEM_MIGRATION_DATABASE_URL.", file=sys.stderr)
        return 1
    if status == "newer":
        print(f"[ctem] {detail}: nothing to apply", flush=True)
        return 0
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS))
    command.upgrade(config, "head")
    return 0


def wait(timeout: float) -> int:
    from app.db.session import dispose_engine, get_engine

    try:
        status, detail = _wait(get_engine(), timeout, READY_STATES)
    finally:
        dispose_engine()
    if status in READY_STATES:
        return 0
    if status in ("unreachable", "refused"):
        print(f"ctem: {detail}. Check CTEM_DATABASE_URL.", file=sys.stderr)
    else:
        print(f"ctem: {detail}. Gave up after {timeout:g}s: {RUN_MIGRATE}.", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.db.schema")
    parser.add_argument("command", choices=["migrate", "wait", "status"])
    parser.add_argument("--timeout", type=float, default=300, help="seconds to wait (default 300)")
    args = parser.parse_args(argv)
    if args.command == "migrate":
        return migrate(args.timeout)
    if args.command == "wait":
        return wait(args.timeout)
    from app.db.session import get_engine

    status, detail = _probe(get_engine())
    print(f"{status}: {detail}")
    return 0 if status in READY_STATES else 1


if __name__ == "__main__":
    sys.exit(main())
