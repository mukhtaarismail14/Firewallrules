# Runs the whole pipeline end-to-end and writes out two files:
#   1. output/cleaned_firewall_rules.csv  
#   2. output/report.txt                  
#
import csv  # Used to export the cleaned rules CSV.
import os
import time  # Used to measure pipeline stage timings.
from pathlib import Path

from aimodel import annotate_rules_with_ai
from detectors import find_conflicts, find_duplicates, find_shadows
from loaders import load_rules
from optimiser import optimise_rules


# Work out where "output/" should live. We want it next to the project
_HERE = Path(__file__).resolve().parent.parent   # src/ -> project root
OUTPUT_DIR       = str(_HERE / "output")
REPORT_PATH      = str(_HERE / "output" / "report.txt")
CLEANED_CSV_PATH = str(_HERE / "output" / "cleaned_firewall_rules.csv")


# column order for the cleaned CSV. Priority comes before ai_score so
# network admins importing this see the firewall fields first
CSV_HEADERS = [
    "ID", "Action", "Source", "Destination", "Protocol", "Port",
    "Priority", "ai_score", "ai_level", "ai_reason",
]


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# Writes the optimised rules to output/cleaned_firewall_rules.csv.
def _export_csv(rules, path=CLEANED_CSV_PATH):
    _ensure_output_dir()
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rules)


# Writes the human-readable report to output/report.txt.
def _export_report(text, path=REPORT_PATH):
    _ensure_output_dir()
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# Counts high/medium/low risk rules for the report and UI.
def _risk_counts(rules):
    counts = {"high": 0, "medium": 0, "low": 0}
    for rule in rules:
        level = str(rule.get("ai_level", "low")).lower()
        if level in counts:
            counts[level] += 1
    return counts


# Builds the plain-text report: counts, timings, risks, detections, output paths.
def _build_report(rules_path, rules, duplicates, conflicts, shadows,
                  optimised, stats, timings):
    """
    Big ugly function that stitches together the text report. Started
    out as one long print() block so refactoring it into this took a
    while but it's much easier to test now that it returns a string.
    """
    counts = _risk_counts(rules)

    reduction = stats["count_before"] - stats["count_after"]
    if stats["count_before"]:
        reduction_pct = reduction / stats["count_before"] * 100
    else:
        reduction_pct = 0.0

    total_ms = sum(timings.values()) * 1000

    lines = []

    #  Header
    lines.append("=" * 58)
    lines.append("FIREWALL RULE OPTIMISATION REPORT")
    lines.append("=" * 58)
    lines.append(f"Source file              : {rules_path}")
    lines.append(f"Rules before optimisation: {stats['count_before']}")
    lines.append(f"Rules after optimisation : {stats['count_after']}")
    lines.append(f"Rule reduction           : {reduction} ({reduction_pct:.1f}%)")
    lines.append(f"Duplicates found         : {len(duplicates)}")
    lines.append(f"Conflicts found          : {len(conflicts)}")
    lines.append(f"Shadowed rules found     : {len(shadows)}")

    #  Performance block 
    lines.append("")
    lines.append("PERFORMANCE")
    lines.append("-" * 58)
    lines.append(f"Load rules    : {timings.get('load',     0) * 1000:8.2f} ms")
    lines.append(f"AI scoring    : {timings.get('ai',       0) * 1000:8.2f} ms")
    lines.append(f"Detection     : {timings.get('detect',   0) * 1000:8.2f} ms")
    lines.append(f"Optimisation  : {timings.get('optimise', 0) * 1000:8.2f} ms")
    lines.append(f"Total         : {total_ms:8.2f} ms")

    # Risk summary
    lines.append("")
    lines.append("AI RISK SUMMARY")
    lines.append("-" * 58)
    lines.append(f"High   : {counts['high']}")
    lines.append(f"Medium : {counts['medium']}")
    lines.append(f"Low    : {counts['low']}")

    # Top high-risk rules 
    lines.append("")
    lines.append("TOP HIGH-RISK RULES")
    lines.append("-" * 58)
    top_high = sorted(
        [r for r in rules if str(r.get("ai_level", "")).lower() == "high"],
        key=lambda r: int(r.get("ai_score", 0)),
        reverse=True,
    )[:5]
    if not top_high:
        lines.append("None")
    else:
        for rule in top_high:
            lines.append(
                f"Rule {rule['ID']}: {rule['Action'].upper()} "
                f"{rule['Source']} -> {rule['Destination']} "
                f"{rule['Protocol']}/{rule['Port']} | "
                f"score={rule['ai_score']} | {rule['ai_reason']}"
            )

    # Duplicates 
    lines.append("")
    lines.append("DUPLICATES")
    lines.append("-" * 58)
    if duplicates:
        for left, right in duplicates:
            lines.append(f"Rule {left} duplicates Rule {right}")
    else:
        lines.append("None")

    # Conflicts 
    lines.append("")
    lines.append("CONFLICTS")
    lines.append("-" * 58)
    if conflicts:
        for left, right in conflicts:
            lines.append(f"Rule {left} conflicts with Rule {right}")
    else:
        lines.append("None")

    # Shadows
    lines.append("")
    lines.append("SHADOWED RULES")
    lines.append("-" * 58)
    if shadows:
        for broad_id, specific_id in shadows[:25]:
            broad    = next((r for r in rules if r["ID"] == broad_id),    None)
            specific = next((r for r in rules if r["ID"] == specific_id), None)
            if broad and specific:
                lines.append(
                    f"Rule {broad_id} shadows Rule {specific_id}: "
                    f"{broad['Action'].upper()} {broad['Source']} -> "
                    f"{broad['Destination']} {broad['Protocol']}/{broad['Port']} "
                    f"covers {specific['Source']} -> {specific['Destination']} "
                    f"{specific['Protocol']}/{specific['Port']}"
                )
        if len(shadows) > 25:
            lines.append(f"... plus {len(shadows) - 25} more shadow relationships")
    else:
        lines.append("None")

    # Preview of the optimised output 
    lines.append("")
    lines.append("FIRST 10 OPTIMISED RULES")
    lines.append("-" * 58)
    for rule in optimised[:10]:
        priority = rule.get("Priority", "-")
        lines.append(
            f"Priority {priority:<3} | Rule {rule['ID']:<3} | "
            f"{rule['Action'].upper():<6} "
            f"{rule['Source']} -> {rule['Destination']} "
            f"{rule['Protocol']}/{rule['Port']}"
        )

    # File paths 
    lines.append("")
    lines.append("OUTPUT FILES")
    lines.append("-" * 58)
    lines.append(CLEANED_CSV_PATH)
    lines.append(REPORT_PATH)
    lines.append("=" * 58)

    return "\n".join(lines)


# Main pipeline entry point: load -> AI score -> detect -> optimise -> export.
def generate_report(rules_path="rules.csv"):
    """
    Run the whole pipeline: load -> score -> detect -> optimise -> report.
    Returns a dict with everything, including the raw report text, so
    callers (like the Streamlit app) can render it however they want.
    """
    timings = {}

    # 1. load  # EXAM: loaders.py validates and normalises the CSV
    t0 = time.perf_counter()
    rules = load_rules(rules_path)
    timings["load"] = time.perf_counter() - t0

    # 2. score  # EXAM: aimodel.py adds ai_score, ai_level and ai_reason
    t0 = time.perf_counter()
    annotate_rules_with_ai(rules)
    timings["ai"] = time.perf_counter() - t0

    # 3. detect  # EXAM: detectors.py finds duplicates/conflicts/shadows
    t0 = time.perf_counter()
    duplicates = find_duplicates(rules)
    conflicts  = find_conflicts(rules)
    shadows    = find_shadows(rules)
    timings["detect"] = time.perf_counter() - t0

    # 4. optimise  # EXAM: optimiser.py dedupes, prioritises and reorders
    t0 = time.perf_counter()
    optimised, stats = optimise_rules(rules)
    timings["optimise"] = time.perf_counter() - t0

    # build + write outputs
    report_text = _build_report(
        rules_path, rules, duplicates, conflicts, shadows,
        optimised, stats, timings,
    )
    _export_report(report_text)
    _export_csv(optimised)

    return {
        "rules":            rules,
        "duplicates":       duplicates,
        "conflicts":        conflicts,
        "shadows":          shadows,
        "optimised":        optimised,
        "stats":            stats,
        "timings":          timings,
        "report_path":      REPORT_PATH,
        "cleaned_csv_path": CLEANED_CSV_PATH,
        "report_text":      report_text,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "rules.csv"
    result = generate_report(path)
    print(result["report_text"])