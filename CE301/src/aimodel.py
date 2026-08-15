from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

Rule = Dict[str, Any]

# Same wildcard normalisation idea used across the project.
WILDCARDS = {"", "any", "0.0.0.0/0", "*"}

#  Domain-knowledge list used by the heuristic risk scorer.
SENSITIVE_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
}

# Converts protocol names into numbers so IsolationForest can use them.
PROTOCOL_CODES = {
    "any": 0,
    "ip": 1,
    "tcp": 2,
    "udp": 3,
    "icmp": 4,
}


def _norm(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "any" if text in WILDCARDS else text


# Feature-engineering helper: broader networks get lower prefix values.
def _cidr_bits(value: Any) -> int:
    value = _norm(value)
    if value == "any" or "/" not in value:
        return 0
    try:
        return max(0, min(32, int(value.split("/")[-1])))
    except ValueError:
        return 0


# Feature-engineering helper: converts port/range/name into one numeric value.
def _port_number(value: Any) -> int:
    """Best-effort numeric representation of a port field for ML features."""
    value = _norm(value)
    if value == "any":
        return 0
    if "-" in value:
        try:
            start, end = value.split("-", 1)
            return (int(start) + int(end)) // 2
        except ValueError:
            return 0
    try:
        return int(value)
    except ValueError:
        return 0


# Key ML function: converts one firewall rule into the numeric vector for IsolationForest.
def _rule_to_features(rule: Rule) -> List[int]:
    """Convert a firewall rule into numeric features for IsolationForest."""
    protocol = _norm(rule.get("Protocol", "any"))
    proto_code = PROTOCOL_CODES.get(protocol, 0)

    return [
        _cidr_bits(rule.get("Source", "any")),
        _cidr_bits(rule.get("Destination", "any")),
        proto_code,
        _port_number(rule.get("Port", "any")),
        1 if _norm(rule.get("Action", "deny")) == "permit" else 0,
    ]


# Key ML training function: fits IsolationForest and returns anomaly scores.
def _train_isolation_forest(
    rules: List[Rule],
    contamination: float = 0.10,
    random_state: int = 42,
) -> Tuple[Optional[IsolationForest], List[Optional[float]]]:
    # Small datasets fall back to heuristic-only because anomaly detection is unstable.
    if len(rules) < 10:
        return None, [None] * len(rules)

    X = np.array([_rule_to_features(rule) for rule in rules], dtype=float)

    # IsolationForest chosen because it works on unlabelled anomaly detection and is efficient.
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)

    # scikit-learn decision_function: lower => more abnormal
    raw_scores = model.decision_function(X)
    anomaly_scores = (-raw_scores).tolist()

    return model, anomaly_scores


# Converts raw ML anomaly scores into capped risk points for explainability.
def _anomaly_to_points(anomaly_score: float) -> Tuple[int, Optional[str]]:
    """
    Map IsolationForest anomaly score onto the project 0-100 risk scale.
    """
    if anomaly_score >= 0.15:
        return 25, "ML anomaly detector flagged this rule as a strong outlier"
    if anomaly_score >= 0.05:
        return 15, "ML anomaly detector flagged this rule as unusual"
    if anomaly_score >= 0.00:
        return 5, "ML anomaly detector flagged this rule as slightly unusual"
    return 0, None


# Heuristic scoring: broad/unrestricted networks increase security risk.
def _score_network(value: Any, label: str) -> Tuple[int, List[str]]:
    value = _norm(value)
    reasons: List[str] = []

    if value == "any":
        return (20 if label == "source" else 15, [f"{label} is unrestricted"])

    bits = _cidr_bits(value)
    if bits == 0:
        return 0, reasons
    if bits <= 8:
        return 18, [f"{label} is a very broad network (/{bits})"]
    if bits <= 16:
        return 12, [f"{label} is a broad network (/{bits})"]
    if bits <= 24:
        return 6, [f"{label} covers a medium-sized subnet (/{bits})"]
    return 0, reasons


# Heuristic scoring: unrestricted protocols, all ports, and sensitive ports increase risk.
def _score_protocol_port(protocol: Any, port: Any) -> Tuple[int, List[str]]:
    protocol = _norm(protocol)
    port = _norm(port)
    total = 0
    reasons: List[str] = []

    if protocol == "any":
        total += 15
        reasons.append("protocol is unrestricted")
    elif protocol in {"tcp", "udp"}:
        total += 2

    if port == "any":
        total += 20
        reasons.append("all ports are exposed")
        return total, reasons

    if "-" in port:
        try:
            start, end = (int(part) for part in port.split("-", 1))
        except ValueError:
            return total, reasons
        if end - start >= 100:
            total += 15
            reasons.append(f"wide port range is exposed ({start}-{end})")
        for candidate in range(start, min(end, start + 25) + 1):
            if candidate in SENSITIVE_PORTS:
                total += 12
                reasons.append(f"port range includes sensitive service {candidate}")
                break
        return total, reasons

    try:
        number = int(port)
    except ValueError:
        return total, reasons

    if number in SENSITIVE_PORTS:
        total += 18
        reasons.append(f"sensitive service port is exposed ({number}/{SENSITIVE_PORTS[number]})")
    elif number < 1024:
        total += 8
        reasons.append(f"well-known service port is exposed ({number})")

    return total, reasons


# Main rule-based security score. This gives human-readable reasons.
def _heuristic_score(rule: Rule) -> Tuple[int, List[str]]:
    """Explainable rule-based score with human-readable reasons."""
    reasons: List[str] = []
    score = 0

    source_score, source_reasons = _score_network(rule.get("Source", "any"), "source")
    destination_score, destination_reasons = _score_network(rule.get("Destination", "any"), "destination")
    service_score, service_reasons = _score_protocol_port(
        rule.get("Protocol", "any"),
        rule.get("Port", "any"),
    )

    score += source_score + destination_score + service_score
    reasons.extend(source_reasons + destination_reasons + service_reasons)

    action = _norm(rule.get("Action", "deny"))
    if action == "permit":
        score += 12
        reasons.append("rule allows traffic")
    else:
        score = max(0, score - 10)
        reasons.append("rule denies traffic, which reduces exposure")

    return score, reasons


#  Hybrid scoring happens here: heuristic score + optional ML anomaly bonus.
def score_rule(rule: Rule, anomaly_score: Optional[float] = None) -> Dict[str, Any]:
    score, reasons = _heuristic_score(rule)

    if anomaly_score is not None:
        bonus, reason = _anomaly_to_points(anomaly_score)
        if bonus:
            score += bonus
            if reason:
                reasons.append(reason)

    score = max(0, min(100, score))

    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {"score": score, "level": level, "reasons": reasons}


# Adds ai_score, ai_level, and ai_reason fields to every rule in-place.
def annotate_rules_with_ai(rules: List[Rule]) -> None:

    _, anomaly_scores = _train_isolation_forest(rules)

    for rule, anomaly_score in zip(rules, anomaly_scores):
        result = score_rule(rule, anomaly_score=anomaly_score)
        rule["ai_score"] = result["score"]
        rule["ai_level"] = result["level"]
        rule["ai_reasons"] = result["reasons"]
        rule["ai_reason"] = "; ".join(result["reasons"]) if result["reasons"] else "No dominant risk factor"


# Produces the plain-English explanation shown in CLI/UI/report.
def explain_rule_ai(rule: Rule) -> str:
    score = int(rule.get("ai_score", 0))
    level = str(rule.get("ai_level", "unknown"))
    reasons = rule.get("ai_reasons") or []
    detail = "; ".join(reasons) if reasons else "no dominant risk factor"
    return f"Rated {level} risk ({score}/100): {detail}."