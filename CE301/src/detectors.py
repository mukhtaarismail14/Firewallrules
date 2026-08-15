import ipaddress  # Built-in library for CIDR/subnet comparison.

# Wildcards mean "match anything" in rule comparisons.
WILDCARDS = {"", "any", "0.0.0.0/0", "*"}


def _norm(value):
    text = str(value or "").strip().lower()
    return "any" if text in WILDCARDS else text


# Converts CIDR strings into ip_network objects; named zones fall back to string matching.
def _parse_network(value):
    value = _norm(value)
    if value == "any":
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        # not a valid CIDR - probably a zone name like "WEB" or "DMZ"
        return value


# Converts ports into comparable ranges, e.g. 80 -> (80, 80).
def _parse_port(value):
    value = _norm(value)
    if value == "any":
        return None

    if "-" in value:
        try:
            start, end = value.split("-", 1)
            return (int(start), int(end))
        except ValueError:
            return value

    try:
        p = int(value)
        return (p, p)
    except ValueError:
        return value


# Identifies the firewall effect of a rule, ignoring its ID.
def _field_key(rule):
    """5-tuple that uniquely identifies a rule's effect (ignoring ID).
    Used by duplicate detection and also by shadow detection to tell
    'identical' apart from 'broader than'."""
    return (
        _norm(rule.get("Action")),
        _norm(rule.get("Source")),
        _norm(rule.get("Destination")),
        _norm(rule.get("Protocol")),
        _norm(rule.get("Port")),
    )

# Coverage helper used for shadow detection: does broad source/destination include specific?
def _network_covers(broad, specific):
    b = _parse_network(broad)
    s = _parse_network(specific)

    if b is None:          # broad is 'any'  covers everything
        return True
    if s is None:          # specific is 'any' but broad isn't  no
        return False

    # one or both couldn't be parsed as CIDR - fall back to string match
    if isinstance(b, str) or isinstance(s, str):
        return _norm(broad) == _norm(specific)

    return s.subnet_of(b)


# Coverage helper: "any" protocol covers a specific protocol.
def _protocol_covers(broad, specific):
    b = _norm(broad)
    s = _norm(specific)
    return b == "any" or b == s


# Coverage helper: a broad port/range must include the specific port/range.
def _port_covers(broad, specific):
    b = _parse_port(broad)
    s = _parse_port(specific)

    if b is None:
        return True
    if s is None:
        return False
    if isinstance(b, str) or isinstance(s, str):
        return _norm(broad) == _norm(specific)

    # both are (low, high) tuples
    return b[0] <= s[0] and b[1] >= s[1]


#  Core shadow check: all fields of broad must cover all fields of specific.
def _same_match_scope(broad, specific):
    return (
        _network_covers(broad["Source"],      specific["Source"])
        and _network_covers(broad["Destination"], specific["Destination"])
        and _protocol_covers(broad["Protocol"],   specific["Protocol"])
        and _port_covers(broad["Port"],           specific["Port"])
    )


def _is_strictly_broader(broad, specific):
    # if the 5-tuples are identical they're really duplicates, not shadows
    return _field_key(broad) != _field_key(specific)


#  main detectors 

# Finds identical rules except for ID.
def find_duplicates(rules):
    seen = {}
    duplicates = []

    for rule in rules:
        key = _field_key(rule)
        if key in seen:
            duplicates.append((seen[key]["ID"], rule["ID"]))
        else:
            seen[key] = rule

    return duplicates


# Finds same-scope rules with opposite actions.
def find_conflicts(rules):
    conflicts = []
    for i, left in enumerate(rules):
        for right in rules[i + 1:]:
            same_scope = (
                _norm(left["Source"])      == _norm(right["Source"])
                and _norm(left["Destination"]) == _norm(right["Destination"])
                and _norm(left["Protocol"])    == _norm(right["Protocol"])
                and _norm(left["Port"])        == _norm(right["Port"])
            )
            if same_scope and _norm(left["Action"]) != _norm(right["Action"]):
                conflicts.append((left["ID"], right["ID"]))

    return conflicts


#  Finds later rules that can never fire because an earlier same-action rule covers them.
def find_shadows(rules):
    shadows = []

    for i, broad in enumerate(rules):
        for specific in rules[i + 1:]:
            # different actions = conflict territory, skip
            if _norm(broad["Action"]) != _norm(specific["Action"]):
                continue

            if not _same_match_scope(broad, specific):
                continue

            # avoid counting identical rules as shadows of themselves
            if not _is_strictly_broader(broad, specific):
                continue

            shadows.append((broad["ID"], specific["ID"]))

    return shadows