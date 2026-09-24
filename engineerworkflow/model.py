"""Strict, bounded input schemas and a deliberately small IPv4 ACL model."""
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path
import re

MAX_BYTES = 1_048_576
MAX_RULES = 256
MAX_PROBES = 512
MAX_REMOVALS = 16


class InputError(ValueError):
    """An input violates the offline workflow contract."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def digest(value):
    return sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InputError("input exceeds 1 MiB budget")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda x: (_ for _ in ()).throw(
                               InputError(f"invalid JSON constant: {x}")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from exc
    return value, sha256(raw).hexdigest()


def fields(value, names, label):
    if type(value) is not dict or set(value) != set(names):
        raise InputError(f"{label}: expected exactly {', '.join(names)}")


def text(value, label):
    if (type(value) is not str or not value.strip() or len(value) > 500
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InputError(f"{label}: expected nonempty single-line text <=500 characters")
    return value


def identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise InputError("identifier must be 1-64 ASCII letters, digits, _ or -")
    return value


def version(value):
    if type(value) is not int or value != 1:
        raise InputError("schema_version must be integer 1")


def bounded_list(value, limit, label, minimum=0):
    if type(value) is not list or not minimum <= len(value) <= limit:
        raise InputError(f"{label}: expected {minimum}..{limit} items")


def action(value):
    if type(value) is not str or value not in ("allow", "deny"):
        raise InputError("action/expected must be allow or deny")
    return value


def network(value):
    if type(value) is not str or "/" not in value:
        raise InputError("network must be an explicit strict IPv4 CIDR")
    try:
        return IPv4Network(value, strict=True)
    except ValueError as exc:
        raise InputError(f"invalid IPv4 network: {value}") from exc


def address(value):
    if type(value) is not str:
        raise InputError("address must be an IPv4 string")
    try:
        return IPv4Address(value)
    except ValueError as exc:
        raise InputError(f"invalid IPv4 address: {value}") from exc


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    src: IPv4Network
    dst: IPv4Network

    @property
    def signature(self):
        return self.action, self.src, self.dst


@dataclass(frozen=True)
class ACL:
    rules: tuple[Rule, ...]

    def evaluate(self, src, dst):
        for rule in self.rules:
            if src in rule.src and dst in rule.dst:
                return rule.action
        return "deny"  # No match always denies.


@dataclass(frozen=True)
class Probe:
    id: str
    src: IPv4Address
    dst: IPv4Address
    expected: str


def parse_acl(value):
    fields(value, ("schema_version", "rules"), "ACL")
    version(value["schema_version"])
    bounded_list(value["rules"], MAX_RULES, "rules")
    rules = []
    seen = set()
    for item in value["rules"]:
        fields(item, ("id", "action", "src", "dst"), "rule")
        rid = identifier(item["id"])
        if rid in seen:
            raise InputError("duplicate rule id")
        seen.add(rid)
        rules.append(Rule(rid, action(item["action"]), network(item["src"]),
                          network(item["dst"])))
    return ACL(tuple(rules))


def parse_probes(value):
    fields(value, ("schema_version", "probes"), "probes")
    version(value["schema_version"])
    bounded_list(value["probes"], MAX_PROBES, "probes", minimum=1)
    probes = []
    seen = set()
    for item in value["probes"]:
        fields(item, ("id", "src", "dst", "expected"), "probe")
        pid = identifier(item["id"])
        if pid in seen:
            raise InputError("duplicate probe id")
        seen.add(pid)
        probes.append(Probe(pid, address(item["src"]), address(item["dst"]),
                            action(item["expected"])))
    if {p.expected for p in probes} != {"allow", "deny"}:
        raise InputError("include both positive (allow) and negative (deny) probes")
    return tuple(probes)
