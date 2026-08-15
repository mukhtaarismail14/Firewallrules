import csv  # Built-in library for reading CSV files safely.

# These are the exact columns the whole pipeline expects.
EXPECTED_HEADERS = ["ID", "Action", "Source", "Destination", "Protocol", "Port"]

# things we accept as an "action"
VALID_ACTIONS = {"permit", "deny"}

# protocols we know about. "ip" is in here because some exports use that
# instead of "any" for everything
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any", "ip"}

# values that all mean "anything" - we squash these to the string "any"
# so the rest of the code only has to check one thing
# Different firewall exports use different wildcard values; all become "any".
WILDCARDS = {"", "any", "0.0.0.0/0", "*"}


# Important normalisation function: whitespace/case/wildcards are standardised here.
def _clean(value, default="any"):
    """Strip + lowercase a field and collapse wildcards to 'any'."""
    text = str(value or "").strip().lower()
    if text in WILDCARDS:
        return default
    return text


# Important validation function: accepts wildcards, numbers, ranges, and service names.
def _is_valid_port(value):
    # Port can be: a wildcard, a single number, or a range like "80-90".
    # I also allow things like "http" because some CSVs have those, even
    # though the rest of the pipeline doesn't really handle them yet.
    if value in WILDCARDS:
        return True

    if "-" in value:
        try:
            start, end = value.split("-", 1)
            start = int(start)
            end = int(end)
        except ValueError:
            return False
        return 0 <= start <= end <= 65535

    try:
        port = int(value)
        return 0 <= port <= 65535
    except ValueError:
        # fallback - accept symbolic port names (e.g. "http")
        return value.isidentifier()


#Important validation function: returns every problem found in one row.
def _validate_rule(rule):
    """Return a list of problem strings. Empty list = rule is fine."""
    problems = []

    if not rule["ID"]:
        problems.append("missing ID")

    if rule["Action"] not in VALID_ACTIONS:
        problems.append(f"invalid action '{rule['Action']}'")

    if rule["Protocol"] not in VALID_PROTOCOLS:
        problems.append(f"invalid protocol '{rule['Protocol']}'")

    if not _is_valid_port(rule["Port"]):
        problems.append(f"invalid port '{rule['Port']}'")

    return problems


#Main entry point for this file. CSV path in -> list of valid rule dictionaries out.
def load_rules(file_path):
    rules = []
    seen_ids = set()

    with open(file_path, newline="", encoding="utf-8") as f:
        #DictReader turns each row into a dict keyed by header names.
        reader = csv.DictReader(f)

        headers = list(reader.fieldnames or [])
        #Fail early if the CSV structure is wrong.
        if headers != EXPECTED_HEADERS:
            # headers have to match exactly - we could be more forgiving
            # but then the later code has to deal with weird column names
            raise ValueError(
                f"CSV headers must be {EXPECTED_HEADERS}, got {headers}"
            )

        # start=2 because row 1 is the header and row numbers in error
        # messages should match what the user sees in Excel
        for row_number, row in enumerate(reader, start=2):
            rule = {
                "ID":          str(row.get("ID", "")).strip(),
                "Action":      _clean(row.get("Action"), default=""),
                "Source":      _clean(row.get("Source")),
                "Destination": _clean(row.get("Destination")),
                "Protocol":    _clean(row.get("Protocol")),
                "Port":        _clean(row.get("Port")),
            }

            problems = _validate_rule(rule)

            if rule["ID"] in seen_ids:
                problems.append(f"duplicate ID '{rule['ID']}'")

            # Invalid rows are skipped with a warning; the rest of the file still loads.
            if problems:
                print(f"[WARN] Skipping row {row_number}: {'; '.join(problems)}")
                continue

            seen_ids.add(rule["ID"])
            rules.append(rule)

    return rules


# Lets you run `python loaders.py data/rules.csv` to quickly check a file
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "rules.csv"
    loaded = load_rules(path)
    print(f"Loaded {len(loaded)} valid rules from '{path}'")