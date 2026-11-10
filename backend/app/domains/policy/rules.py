"""Policy rule grammar and evaluator.

A rule is a JSON document:

    {"all": [rule, ...]} | {"any": [rule, ...]} | {"not": rule}
    {"field": "<dotted.path>", "op": "<operator>", "value": <json>}

Fields are resolved against an entity view (see app.domains.policy.views). A missing field
resolves to None; comparisons against None are false except for `exists`/`not_exists`, so a
policy can never pass because data is absent.
"""

from typing import Any

from app.core.errors import ValidationFailed

OPERATORS = {
    "eq", "ne", "in", "not_in", "exists", "not_exists", "gt", "gte", "lt", "lte", "contains", "is_true",
    "is_false",
}
MAX_DEPTH = 6


def resolve(view: dict, path: str) -> Any:
    current: Any = view
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def validate_rule(rule: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValidationFailed("Policy rule is nested too deeply")
    if not isinstance(rule, dict):
        raise ValidationFailed("Policy rule must be an object")
    if rule == {}:
        return  # empty rule matches everything (valid for scope)
    keys = set(rule)
    if keys == {"all"} or keys == {"any"}:
        items = rule.get("all", rule.get("any"))
        if not isinstance(items, list) or not items or len(items) > 25:
            raise ValidationFailed("'all'/'any' require a list of 1-25 rules")
        for item in items:
            validate_rule(item, depth=depth + 1)
    elif keys == {"not"}:
        validate_rule(rule["not"], depth=depth + 1)
    elif "field" in keys and "op" in keys and keys <= {"field", "op", "value"}:
        if not isinstance(rule["field"], str) or not rule["field"] or len(rule["field"]) > 120:
            raise ValidationFailed("Rule field must be a non-empty string")
        if rule["op"] not in OPERATORS:
            raise ValidationFailed(f"Unknown operator {rule['op']!r}")
        if rule["op"] in ("in", "not_in") and not isinstance(rule.get("value"), list):
            raise ValidationFailed(f"Operator {rule['op']} requires a list value")
    else:
        raise ValidationFailed("Rule must be all/any/not or a field comparison")


def evaluate(rule: dict, view: dict) -> bool:
    if not rule:
        return True
    if "all" in rule:
        return all(evaluate(r, view) for r in rule["all"])
    if "any" in rule:
        return any(evaluate(r, view) for r in rule["any"])
    if "not" in rule:
        return not evaluate(rule["not"], view)
    actual, op, expected = resolve(view, rule["field"]), rule["op"], rule.get("value")
    if op == "exists":
        return actual not in (None, "", [], {})
    if op == "not_exists":
        return actual in (None, "", [], {})
    if actual is None:
        return False
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "is_true":
        return actual is True
    if op == "is_false":
        return actual is False
    if op == "contains":
        return expected in actual if isinstance(actual, list | str) else False
    try:
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "lt":
            return actual < expected
        if op == "lte":
            return actual <= expected
    except TypeError:
        return False
    return False


def referenced_fields(rule: dict) -> list[str]:
    if not rule:
        return []
    if "field" in rule:
        return [rule["field"]]
    children = rule.get("all") or rule.get("any") or [rule.get("not", {})]
    out: list[str] = []
    for child in children:
        out.extend(referenced_fields(child))
    return list(dict.fromkeys(out))
