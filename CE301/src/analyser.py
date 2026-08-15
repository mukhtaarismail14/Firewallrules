#analyser.py
#Quick console analysis — prints duplicate/conflict counts then runs the full report.
#Run directly:  python3 src/analyser.py [path/to/rules.csv]

import sys
from loaders          import load_rules
from detectors        import find_duplicates, find_conflicts, find_shadows
from report_generator import generate_report


# Quick debugging/terminal script: prints detector results then generates the full report.
def main() -> None:
    rules_path = sys.argv[1] if len(sys.argv) > 1 else "data/rules.csv"

    # Step 1: load and validate the CSV rules.
    rules = load_rules(rules_path)
    print(f"Total rules loaded: {len(rules)}")

    # Step 2: run the three structural detectors.
    duplicates = find_duplicates(rules)
    conflicts  = find_conflicts(rules)
    shadows    = find_shadows(rules)

    print(f"\nDuplicate rules  : {len(duplicates)}")
    for a, b in duplicates:
        print(f"  Rule {a} duplicates Rule {b}")

    print(f"\nConflicting rules: {len(conflicts)}")
    for a, b in conflicts:
        print(f"  Rule {a} conflicts with Rule {b}")

    print(f"\nShadowed rules   : {len(shadows)}")
    for broad, specific in shadows:
        print(f"  Rule {broad} (broad) shadows Rule {specific}")

    # Full report + exports
    # Step 3: run the full pipeline and export report/cleaned CSV.
    generate_report(rules_path)


if __name__ == "__main__":
    main()