#python3 src/cli.py
from __future__ import annotations

import sys
from pathlib import Path

from report_generator import generate_report


def main() -> None:

    # Get the CSV path from the command line, or use the default sample file.
    if len(sys.argv) > 1:
        rules_path = sys.argv[1]
    else:
        rules_path = "data/rules.csv"

    # Basic file existence check before running the pipeline.
    if not Path(rules_path).exists():
        print(f"[ERROR] File not found: {rules_path}")
        return

    print("=" * 58)
    print("FIREWALL RULE OPTIMISER - CLI")
    print("=" * 58)
    print(f"Input file: {rules_path}")
    print("Running pipeline...\n")

    try:
        # This is the key line.
        # generate_report() runs: load -> AI score -> detect -> optimise -> export.
        result = generate_report(rules_path)
    except Exception as exc:
        print(f"[ERROR] Pipeline failed: {exc}")
        return

    stats = result["stats"]

    print("=" * 58)
    print("PIPELINE COMPLETE")
    print("=" * 58)
    print(f"Rules before optimisation: {stats['count_before']}")
    print(f"Rules after optimisation : {stats['count_after']}")
    print(f"Duplicates found         : {len(result['duplicates'])}")
    print(f"Conflicts found          : {len(result['conflicts'])}")
    print(f"Shadowed rules found     : {len(result['shadows'])}")
    print()
    print(f"Report written to        : {result['report_path']}")
    print(f"Cleaned CSV written to   : {result['cleaned_csv_path']}")


if __name__ == "__main__":
    main()