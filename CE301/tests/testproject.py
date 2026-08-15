# Run:
#     python3 tests/testproject.py           (prints PASS/FAIL)
#     python -m pytest tests/ -v              (if pytest installed)

import sys
import tempfile
from pathlib import Path

# Make the src/ directory importable. This is a hack but keeps the
# tests runnable from the project root without having to install the
# package as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from loaders   import load_rules
from detectors import find_duplicates, find_conflicts, find_shadows
from aimodel   import score_rule, annotate_rules_with_ai
from optimiser import remove_duplicates, compute_priority, optimise_rules


#  test fixtures 
# A few small rules I reuse across multiple tests. Keeping them at
# module level makes the individual test functions much shorter.

PERMIT_ANY = {
    "ID":     "1",   "Action": "permit", "Source":      "any",
    "Destination": "any", "Protocol": "tcp", "Port":    "any",
}

PERMIT_ANY_DUP = {
    "ID":     "2",   "Action": "permit", "Source":      "any",
    "Destination": "any", "Protocol": "tcp", "Port":    "any",
}

DENY_ANY = {
    "ID":     "3",   "Action": "deny",   "Source":      "any",
    "Destination": "any", "Protocol": "tcp", "Port":    "any",
}

SPECIFIC_RULE = {
    "ID":     "4",   "Action": "permit",
    "Source": "192.168.1.0/24", "Destination": "10.0.0.5/32",
    "Protocol": "tcp", "Port": "22",
}

HIGH_RISK_RULE = {
    "ID":     "5",   "Action": "permit", "Source":      "any",
    "Destination": "any", "Protocol": "any", "Port":    "any",
}

LOW_RISK_RULE = {
    "ID":     "6",   "Action": "deny",
    "Source": "192.168.1.5/32", "Destination": "10.0.0.1/32",
    "Protocol": "tcp", "Port": "443",
}


# loader tests

def test_load_sample_csv():
    # skip if the sample file isn't present - shouldn't happen in the
    # submitted repo but I ran into it once when testing from a stripped
    # down checkout
    sample = Path(__file__).resolve().parent.parent / "data" / "rules.csv"
    if not sample.exists():
        print("  SKIP test_load_sample_csv - data/rules.csv not found")
        return
    rules = load_rules(str(sample))
    assert len(rules) >= 5, f"Expected at least 5 rules, got {len(rules)}"
    print(f"  PASS test_load_sample_csv ({len(rules)} rules loaded)")


def test_load_rejects_bad_headers():
    # bad headers should raise, not silently carry on
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("Wrong,Headers\n1,permit\n")
        tmp = f.name
    try:
        load_rules(tmp)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  PASS test_load_rejects_bad_headers")


def test_load_skips_bad_action():
    # one bad row shouldn't stop the good ones from loading
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(
            "ID,Action,Source,Destination,Protocol,Port\n"
            "1,permit,any,any,tcp,80\n"
            "2,BADACTION,any,any,tcp,80\n"
            "3,deny,any,any,tcp,80\n"
        )
        tmp = f.name

    rules = load_rules(tmp)
    assert len(rules) == 2, f"Expected 2 rules, got {len(rules)}"
    print("  PASS test_load_skips_bad_action")


#  detector tests

def test_duplicate_detected():
    # two identical permit rules + one different one -> exactly 1 dup pair
    dups = find_duplicates([PERMIT_ANY, PERMIT_ANY_DUP, SPECIFIC_RULE])
    assert len(dups) == 1 and dups[0] == ("1", "2")
    print("  PASS test_duplicate_detected")


def test_no_false_duplicate():
    # same everything except port -> NOT duplicates
    r1 = {**PERMIT_ANY, "ID": "1", "Port": "80"}
    r2 = {**PERMIT_ANY, "ID": "2", "Port": "443"}
    assert find_duplicates([r1, r2]) == []
    print("  PASS test_no_false_duplicate")


def test_conflict_detected():
    # permit + deny with same scope = 1 conflict
    conflicts = find_conflicts([PERMIT_ANY, DENY_ANY])
    assert len(conflicts) == 1 and conflicts[0] == ("1", "3")
    print("  PASS test_conflict_detected")


def test_no_false_conflict():
    # two permits aren't a conflict, they're a duplicate
    assert find_conflicts([PERMIT_ANY, PERMIT_ANY_DUP]) == []
    print("  PASS test_no_false_conflict")


def test_shadow_detected():
    # broad permit any->any covers specific permit 192.168.1.0/24->10.0.0.5
    broad    = {**PERMIT_ANY,    "ID": "1"}
    specific = {**SPECIFIC_RULE, "ID": "2"}
    result = find_shadows([broad, specific])
    assert len(result) >= 1, f"Expected at least one shadow, got {result}"
    print("  PASS test_shadow_detected")


#  AI risk-model tests 

def test_high_risk_scores_high():
    # permit any any any any - should max out the scorer
    result = score_rule(HIGH_RISK_RULE)
    assert result["level"] == "high" and result["score"] >= 60
    print(f"  PASS test_high_risk_scores_high (score={result['score']})")


def test_low_risk_scores_low_or_medium():
    # tight deny rule, specific IPs, standard port - should be low-ish
    result = score_rule(LOW_RISK_RULE)
    assert result["level"] in ("low", "medium"), \
        f"Got {result['level']} (score {result['score']})"
    print(f"  PASS test_low_risk_scores_low_or_medium (score={result['score']})")


def test_score_has_reasons():
    # we always want a reason - that's the whole point of this vs a
    # black-box score
    result = score_rule(HIGH_RISK_RULE)
    assert len(result["reasons"]) > 0
    print("  PASS test_score_has_reasons")


def test_score_within_bounds():
    # no rule should ever get below 0 or above 100
    for rule in [HIGH_RISK_RULE, LOW_RISK_RULE, PERMIT_ANY, DENY_ANY]:
        s = score_rule(rule)["score"]
        assert 0 <= s <= 100, f"Score {s} out of bounds"
    print("  PASS test_score_within_bounds")


def test_annotate_adds_fields():
    rules = [{**PERMIT_ANY}, {**SPECIFIC_RULE}]
    annotate_rules_with_ai(rules)
    for r in rules:
        assert "ai_score"   in r
        assert "ai_level"   in r
        assert "ai_reasons" in r
    print("  PASS test_annotate_adds_fields")


#  optimiser tests 

def test_remove_duplicates_keeps_first():
    # first occurrence wins
    unique, removed = remove_duplicates(
        [PERMIT_ANY, PERMIT_ANY_DUP, SPECIFIC_RULE]
    )
    assert len(unique) == 2 and len(removed) == 1
    assert unique[0]["ID"] == "1"
    print("  PASS test_remove_duplicates_keeps_first")


def test_deny_gets_lower_priority():
    # deny rules should go before permits at the same risk level
    # (lower number = higher up)
    permit = {**PERMIT_ANY, "ai_score": 50}
    deny   = {**DENY_ANY,   "ai_score": 50}
    assert compute_priority(deny) < compute_priority(permit)
    print("  PASS test_deny_gets_lower_priority")


def test_optimise_stats():
    rules = [{**PERMIT_ANY}, {**PERMIT_ANY_DUP}, {**SPECIFIC_RULE}]
    annotate_rules_with_ai(rules)
    _, stats = optimise_rules(rules)
    assert stats["count_before"]        == 3
    assert stats["count_after"]         == 2
    assert stats["duplicates_removed"]  == 1
    print("  PASS test_optimise_stats")


# entry point 

if __name__ == "__main__":
    all_tests = [
        # loader
        test_load_sample_csv,
        test_load_rejects_bad_headers,
        test_load_skips_bad_action,
        # detectors
        test_duplicate_detected,
        test_no_false_duplicate,
        test_conflict_detected,
        test_no_false_conflict,
        test_shadow_detected,
        # AI model
        test_high_risk_scores_high,
        test_low_risk_scores_low_or_medium,
        test_score_has_reasons,
        test_score_within_bounds,
        test_annotate_adds_fields,
        # optimiser
        test_remove_duplicates_keeps_first,
        test_deny_gets_lower_priority,
        test_optimise_stats,
    ]

    print("\n" + "=" * 50)
    print("  FIREWALL OPTIMISER - TEST SUITE")
    print("=" * 50)

    passed = 0
    failed = 0
    for fn in all_tests:
        try:
            fn()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {fn.__name__}: {exc}")
            failed += 1

    print("=" * 50)
    print(f"  {passed} passed  |  {failed} failed")
    print("=" * 50 + "\n")