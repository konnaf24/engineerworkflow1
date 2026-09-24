"""CLI: exit 0 = offline probes pass, 1 = failed validation, 2 = input/I/O error."""
import argparse
import sys

from .model import InputError
from .workflow import run


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline ACL evidence workflow; no device writes")
    parser.add_argument("--baseline", required=True, help="baseline ACL JSON (read-only)")
    parser.add_argument("--proposal", required=True, help="bounded removal proposal JSON")
    parser.add_argument("--expected", required=True, help="read-only expected probe fixture")
    parser.add_argument("--output", required=True, help="NEW output directory; parent must exist")
    args = parser.parse_args(argv)
    try:
        result = run(args.baseline, args.proposal, args.expected, args.output)
    except (InputError, OSError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2
    if not result["passed"]:
        print("BLOCKED: validation failed; inspect validation.json. No device authority.",
              file=sys.stderr)
        return 1
    print("Offline validation passed. HUMAN REVIEW REQUIRED. No device authority.")
    print(f"Evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
