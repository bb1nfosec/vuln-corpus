#!/usr/bin/env python3
"""
Exploitarium Corpus Schema Validator
=====================================
Validates corpus.yaml against the extraction schema rules.
Checks: required fields, severity values, CWE formats, entry IDs, field types.

Usage:
    python3 scripts/validate-corpus.py [--json] [corpus.yaml]
    
    --json       Also validate corpus.json matches corpus.yaml
    corpus.yaml  Path to corpus file (default: corpus.yaml)

Exit codes:
    0  All validations passed
    1  Validation errors found
"""

import sys
import re
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    print("CRITICAL: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

try:
    import json
except ImportError:
    json = None

# ─── Configuration ───────────────────────────────────────────────────────────

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_LANGUAGES = {"C", "C++", "Go", "Java", "Rust", "PHP", "Python", "TypeScript",
                   "JavaScript", "TypeScript/JS", "JS", "C#", "Ruby", "Swift", "Kotlin", "Dart", "R",
                   "Shell", "PowerShell", "Assembly", "Zig", "Nim", "Haskell"}
VALID_OS = {"Windows", "Linux", "macOS", "Android", "iOS", "FreeBSD", "OpenBSD", "NetBSD", "Solaris"}

# Known vulnerability types (expanded from our corpus)
KNOWN_TYPES = {
    "RCE", "ACE", "LPE", "UAF", "OOB-W", "OOB-R", "Priv Esc", "Auth Bypass",
    "Container Escape", "HTTP Smuggling", "Info Leak", "DoS",
    "Defender Bypass", "TOCTOU", "Hijack", "Parser Bug",
    "Integer Overflow", "Type Confusion", "Template Injection",
    "Memory Corruption", "Buffer Overflow", "Heap Overflow",
    "Stack Overflow", "Format String", "SQL Injection", "XSS",
    "CSRF", "SSRF", "Path Traversal", "Race Condition"
}

# Required fields per entry (in corpus format — flat inside entries[])
REQUIRED_ENTRY_FIELDS = [
    "id", "title", "target", "classification", "root_cause", "exploit_primitive"
]

REQUIRED_TARGET_FIELDS = ["product", "version", "language"]
REQUIRED_CLASSIFICATION_FIELDS = ["type", "severity"]


# ─── Errors ──────────────────────────────────────────────────────────────────

class ValidationError:
    def __init__(self, path: str, message: str, severity: str = "error"):
        self.path = path
        self.message = message
        self.severity = severity  # error, warning, info

    def __str__(self):
        return f"[{self.severity.upper()}] {self.path}: {self.message}"


# ─── Validators ──────────────────────────────────────────────────────────────

def validate_entry_id(entry_id: str, path: str) -> list[ValidationError]:
    errors = []
    if not re.match(r'^EX-\d{3}$', entry_id):
        errors.append(ValidationError(
            f"{path}.id",
            f"Invalid entry ID format: '{entry_id}' — expected EX-XXX (e.g., EX-001)"
        ))
    return errors


def validate_severity(severity: str, path: str) -> list[ValidationError]:
    errors = []
    if severity not in VALID_SEVERITIES:
        errors.append(ValidationError(
            f"{path}.severity",
            f"Invalid severity: '{severity}' — must be one of {sorted(VALID_SEVERITIES)}"
        ))
    return errors


def validate_cwe(cwe: str, path: str) -> list[ValidationError]:
    """Validate CWE format (CWE-XXX or CWE-XXX / CWE-YYY for multiple)."""
    errors = []
    if not cwe or cwe == "null":
        return errors
    # Handle compound CWEs like "CWE-94 / CWE-862"
    parts = [p.strip() for p in cwe.replace("/", " ").split()]
    for part in parts:
        if part.startswith("CWE-"):
            num = part[4:]
            if not num.isdigit():
                errors.append(ValidationError(
                    f"{path}.cwe",
                    f"Invalid CWE format: '{part}' — expected CWE-XXX"
                ))
    return errors


def validate_entry(entry: dict, index: int) -> list[ValidationError]:
    errors = []
    base = f"entries[{index}]"
    entry_id = entry.get("id", f"EX-???")

    # Check required fields
    for field in REQUIRED_ENTRY_FIELDS:
        if field not in entry or entry[field] is None:
            errors.append(ValidationError(
                f"{base}.{field}",
                f"Missing required field: {field}"
            ))

    # Validate entry ID format
    if "id" in entry and entry["id"]:
        errors.extend(validate_entry_id(entry["id"], base))

    # Validate target fields
    target = entry.get("target", {})
    if target:
        for field in REQUIRED_TARGET_FIELDS:
            if field not in target or not target[field]:
                errors.append(ValidationError(
                    f"{base}.target.{field}",
                    f"Missing required target field: {field}"
                ))

        # Validate language
        language = target.get("language", "")
        if language and language not in VALID_LANGUAGES:
            # Accept compound languages like "Java, C++"
            langs = [l.strip() for l in language.split(",")]
            unknown = [l for l in langs if l not in VALID_LANGUAGES]
            if unknown:
                # Non-critical — warn for unknown languages
                errors.append(ValidationError(
                    f"{base}.target.language",
                    f"Unknown language(s): {unknown} — add to VALID_LANGUAGES if valid",
                    "warning"
                ))

        # Validate OS
        os_list = target.get("os", [])
        if os_list:
            unknown_os = [o for o in os_list if o not in VALID_OS]
            if unknown_os:
                errors.append(ValidationError(
                    f"{base}.target.os",
                    f"Unknown OS(es): {unknown_os}",
                    "warning"
                ))

    # Validate classification
    classification = entry.get("classification", {})
    if classification:
        for field in REQUIRED_CLASSIFICATION_FIELDS:
            if field not in classification or not classification[field]:
                errors.append(ValidationError(
                    f"{base}.classification.{field}",
                    f"Missing required classification field: {field}"
                ))

        if "severity" in classification and classification["severity"]:
            errors.extend(validate_severity(classification["severity"], f"{base}.classification"))

        if "cwe" in classification and classification["cwe"]:
            errors.extend(validate_cwe(str(classification["cwe"]), f"{base}.classification"))

    # Validate discovery methods
    discovery = entry.get("discovery", [])
    if not discovery:
        errors.append(ValidationError(
            f"{base}.discovery",
            "Empty discovery methods array — at least one method recommended",
            "warning"
        ))

    # Validate root_cause and exploit_primitive length
    for field in ["root_cause", "exploit_primitive"]:
        if field in entry and entry[field] and len(str(entry[field])) < 10:
            errors.append(ValidationError(
                f"{base}.{field}",
                f"Very short {field} — expected at least 10 characters",
                "warning"
            ))

    return errors


def validate_corpus(data: dict, source: str = "corpus.yaml") -> list[ValidationError]:
    errors = []

    # Check top-level structure
    if "corpus" not in data:
        errors.append(ValidationError("root", "Missing root 'corpus' key"))
        return errors

    corpus = data["corpus"]

    # Check metadata
    metadata = corpus.get("metadata", {})
    if not metadata:
        errors.append(ValidationError("corpus.metadata", "Missing metadata section", "error"))
    else:
        required_meta = ["name", "version", "description", "source_repository", "entry_count"]
        for field in required_meta:
            if field not in metadata:
                errors.append(ValidationError(
                    f"corpus.metadata.{field}",
                    f"Missing metadata field: {field}",
                    "warning"
                ))

    # Check entries
    entries = corpus.get("entries", [])
    if not entries:
        errors.append(ValidationError("corpus.entries", "No entries found", "error"))
        return errors

    actual_count = len(entries)
    declared_count = metadata.get("entry_count", 0)
    if declared_count and actual_count != declared_count:
        errors.append(ValidationError(
            "corpus.metadata.entry_count",
            f"Declared count ({declared_count}) does not match actual entries ({actual_count})",
            "error"
        ))

    # Validate each entry
    seen_ids = set()
    for i, entry in enumerate(entries):
        errors.extend(validate_entry(entry, i))

        # Check for duplicate IDs
        eid = entry.get("id")
        if eid:
            if eid in seen_ids:
                errors.append(ValidationError(
                    f"entries[{i}].id",
                    f"Duplicate entry ID: {eid}",
                    "error"
                ))
            seen_ids.add(eid)

    # Validate CVE cross-reference
    cve_entries = [e for e in entries if e.get("cve")]
    if cve_entries:
        for e in cve_entries:
            cve = e["cve"]
            if not re.match(r'^CVE-\d{4}-\d{4,}$', str(cve)):
                errors.append(ValidationError(
                    f"entries[id={e['id']}].cve",
                    f"Invalid CVE format: '{cve}'",
                    "warning"
                ))

    return errors


def validate_json_correspondence(yaml_path: str, json_path: str) -> list[ValidationError]:
    """Check that YAML and JSON versions have the same entries."""
    errors = []
    try:
        with open(json_path) as f:
            json_data = json.load(f)

        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        yaml_entries = {e["id"]: e for e in yaml_data["corpus"]["entries"]}
        json_entries = {e["id"]: e for e in json_data["corpus"]["entries"]}

        yaml_ids = set(yaml_entries.keys())
        json_ids = set(json_entries.keys())

        only_in_yaml = yaml_ids - json_ids
        only_in_json = json_ids - yaml_ids

        if only_in_yaml:
            errors.append(ValidationError("cross-ref", f"Entries in YAML but not JSON: {only_in_yaml}", "error"))
        if only_in_json:
            errors.append(ValidationError("cross-ref", f"Entries in JSON but not YAML: {only_in_json}", "error"))

        # Check field correspondence
        for eid in yaml_ids & json_ids:
            y_entry = yaml_entries[eid]
            j_entry = json_entries[eid]
            if y_entry.get("title") != j_entry.get("title"):
                errors.append(ValidationError(
                    f"cross-ref[{eid}]",
                    f"Title mismatch: YAML='{y_entry.get('title')}' vs JSON='{j_entry.get('title')}'",
                    "error"
                ))

    except FileNotFoundError as e:
        errors.append(ValidationError("cross-ref", f"File not found: {e.filename}", "warning"))
    except Exception as e:
        errors.append(ValidationError("cross-ref", f"JSON cross-check failed: {e}", "warning"))

    return errors


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Validate Exploitarium Corpus Schema",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/validate-corpus.py
  python3 scripts/validate-corpus.py corpus.yaml
  python3 scripts/validate-corpus.py --json corpus.yaml
  python3 scripts/validate-corpus.py --json --strict corpus.yaml
        """
    )
    parser.add_argument("corpus_path", nargs="?", default="corpus.yaml",
                        help="Path to corpus.yaml (default: corpus.yaml)")
    parser.add_argument("--json", action="store_true",
                        help="Also validate corresponding corpus.json")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as errors")
    args = parser.parse_args()

    corpus_path = Path(args.corpus_path)
    if not corpus_path.exists():
        print(f"ERROR: File not found: {corpus_path}", file=sys.stderr)
        sys.exit(1)

    # Load YAML
    with open(corpus_path) as f:
        data = yaml.safe_load(f)

    if data is None:
        print("ERROR: Empty or invalid YAML file", file=sys.stderr)
        sys.exit(1)

    # Validate
    errors = validate_corpus(data, str(corpus_path))

    # Validate JSON correspondence
    if args.json:
        json_path = corpus_path.with_suffix(".json")
        errors.extend(validate_json_correspondence(str(corpus_path), str(json_path)))

    # Report
    error_count = 0
    warning_count = 0

    for err in errors:
        if err.severity == "error":
            error_count += 1
        elif err.severity == "warning":
            warning_count += 1
        print(str(err), file=sys.stderr)

    print(f"\n{'─' * 50}", file=sys.stderr)
    print(f"Summary: {len(errors)} issues — {error_count} errors, {warning_count} warnings", file=sys.stderr)

    if args.strict:
        sys.exit(1 if (error_count > 0 or warning_count > 0) else 0)
    else:
        sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
