from aimodel import score_rule  # Used if a rule has not already been AI-scored.


# Used to measure network specificity from CIDR notation, e.g. /24 -> 24.
def _cidr_bits(value):
    text = str(value or "").strip().lower()
    if text in {"", "any", "0.0.0.0/0", "*"} or "/" not in text:
        return 0
    try:
        return max(0, min(32, int(text.split("/")[-1])))
    except ValueError:
        return 0


# Duplicate-rule identity. Ignores ID because different IDs can have identical behaviour.
def _rule_key(rule):
    # Same as the one in detectors.py - I know, DRY, but these two
    # modules used to have slightly different keys and keeping them
    # separate made it easier to change one without breaking the other.
    return (
        str(rule.get("Action",     "")).strip().lower(),
        str(rule.get("Source",     "")).strip().lower(),
        str(rule.get("Destination","")).strip().lower(),
        str(rule.get("Protocol",   "")).strip().lower(),
        str(rule.get("Port",       "")).strip().lower(),
    )


# Removes exact duplicate rules while keeping the first occurrence.
def remove_duplicates(rules):
    seen = {}
    unique = []
    removed = []

    for rule in rules:
        key = _rule_key(rule)
        if key in seen:
            removed.append((seen[key]["ID"], rule["ID"]))
        else:
            seen[key] = rule
            unique.append(rule)

    return unique, removed


# Most important optimiser function. Lower number = earlier in the final policy.
def compute_priority(rule):
    """
    Work out where a rule should sit in the ordered policy.
    Lower number = closer to the top.

    Three things go into this:
      - the AI risk score (high risk moves up)
      - a bonus for deny rules (put explicit denies first)
      - a bonus for specificity (host rules before subnet rules)

    Weights were tuned by running this on the 50-rule sample dataset
    and checking that the ordering "felt right" to me. There is almost
    certainly a better way to do this using actual firewall best-
    practice docs but this was good enough for the scope of the project.
    """
    # Higher risk should move upward, so later the score is inverted as 100 - ai_score.
    ai_score = int(rule.get("ai_score", score_rule(rule)["score"]))

    # Deny rules are pulled upward because explicit blocks should appear early.
    deny_bonus = -15 if str(rule.get("Action", "")).lower() == "deny" else 0

    src_bits = _cidr_bits(rule.get("Source",      "any"))
    dst_bits = _cidr_bits(rule.get("Destination", "any"))
    # divide by 8 so a /24 only pulls 3 points instead of 24 - the CIDR
    # bit count on its own was dwarfing the other signals
    # EXAM: Specific rules move slightly upward; // 8 keeps this as a tiebreaker.
    specificity_bonus = -(src_bits + dst_bits) // 8

    # max(1, ...) to make sure priorities stay positive - negative
    # priorities sort weirdly in spreadsheets
    # EXAM: max(1, ...) prevents zero/negative priorities in the output CSV.
    return max(1, 100 - ai_score + deny_bonus + specificity_bonus)


# Final sorting step: priority first, then ID for deterministic output.
def reorder_rules(rules):
    """Sort rules by Priority, breaking ties on numeric ID."""
    def sort_key(rule):
        try:
            rule_id = int(str(rule.get("ID", 999999)))
        except ValueError:
            # non-numeric IDs sort last
            rule_id = 999999
        return (int(rule.get("Priority", 999999)), rule_id)

    return sorted(rules, key=sort_key)


# Main entry point for optimiser.py: dedupe -> score if needed -> prioritise -> sort.
def optimise_rules(rules):
    """
    Full optimisation pipeline. Returns (ordered_rules, stats) where
    stats has count_before / count_after / duplicates_removed.
    """
    count_before = len(rules)

    unique_rules, removed_pairs = remove_duplicates(rules)

    # Some pipelines call annotate_rules_with_ai first, others don't,
    # so make sure every rule has the AI fields before we compute
    # priority (compute_priority relies on ai_score)
    for rule in unique_rules:
        if "ai_score" not in rule:
            r = score_rule(rule)
            rule["ai_score"]   = r["score"]
            rule["ai_level"]   = r["level"]
            rule["ai_reasons"] = r["reasons"]
            rule["ai_reason"]  = "; ".join(r["reasons"])
        rule["Priority"] = compute_priority(rule)

    ordered = reorder_rules(unique_rules)

    stats = {
        "count_before":       count_before,
        "count_after":        len(ordered),
        "duplicates_removed": len(removed_pairs),
    }
    return ordered, stats