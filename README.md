# Exploitarium Vulnerability Corpus

> **Structured vulnerability dataset extracted from 23 proof-of-concept exploits.**
> Methodology: Structured Research Reconstruction (Facts → Timeline → Alternatives → Heuristics → Confidence)

## Overview

This corpus is a structured, machine-readable dataset of 23 real-world vulnerabilities analyzed from the [Exploitarium](https://github.com/bikini/exploitarium) repository. Each entry includes target metadata, vulnerability classification, root cause analysis, exploit primitive, and discovery methodology.

**Size:** 23 entries across 14 vulnerability classes
**Coverage:** C/C++, PHP, Go, Java, Rust, TypeScript, JavaScript — Windows, Linux, macOS
**CVEs:** 1 assigned (CVE-2026-55200)

## Data Files

| File | Format | Description |
|------|--------|-------------|
| [`corpus.yaml`](corpus.yaml) | YAML | Full structured corpus with all fields |
| [`corpus.json`](corpus.json) | JSON | Machine-readable version for programmatic ingestion |
| [`CROSS-REFERENCE.md`](CROSS-REFERENCE.md) | Markdown | Cross-reference by type, severity, language, name, and more |
| [`extraction-schema.yaml`](extraction-schema.yaml) | YAML | Schema definition for vulnerability extraction format |

## Vulnerability Summary

| Severity | Count | Entries |
|----------|-------|---------|
| Critical | 7 | EX-004, EX-006, EX-010, EX-012, EX-015, EX-018, EX-019 |
| High | 14 | EX-001, EX-003, EX-005, EX-007, EX-008, EX-009, EX-011, EX-013, EX-014, EX-016, EX-017, EX-020, EX-021, EX-023 |
| Medium | 2 | EX-002, EX-022 |

### Vulnerability Classes

| Type | Count | Entries |
|------|-------|---------|
| RCE / ACE | 7 | 4, 5, 8, 15, 18, 20, 23 |
| UAF → Calc | 2 | 6, 19 |
| OOB-W → Calc/RCE | 2 | 10, 12 |
| LPE | 2 | 1, 16 |
| Priv Esc | 1 | 13 |
| Auth Bypass | 1 | 11 |
| Container Escape | 1 | 14 |
| HTTP Smuggling | 1 | 9 |
| Info Leak | 1 | 21 |
| Parser Bug / DoS | 2 | 2, 22 |
| Defender Bypass | 1 | 7 |
| TOCTOU / Race | 1 | 3 |
| Hijack (Search Path) | 1 | 17 |

### Languages Targeted

| Language | Count |
|----------|-------|
| C / C++ | 8 (EX-005, EX-006, EX-010, EX-012, EX-016, EX-017, EX-019, EX-022) |
| PHP | 2 (EX-004, EX-013) |
| JavaScript / TypeScript / Electron | 2 (EX-018, EX-021, EX-023) |
| Go | 2 (EX-003, EX-014) |
| Java | 2 (EX-008, EX-015) |
| Rust | 1 (EX-011) |
| C++ / C# (multi) | 2 (EX-001, EX-020, EX-017) |

## Entry Format

Each entry in the corpus contains:

```yaml
- id: "EX-XXX"
  title: "Brief vulnerability title"
  cve: "CVE-XXXX-YYYYY"          # or null
  target:
    product: "Product Name"
    version: "Affected version"
    language: "Implementation language"
    os: ["Affected OSes"]
    component: "Affected module"
  classification:
    type: "Vulnerability type"
    severity: "Critical / High / Medium"
    cwe: "CWE-XXX"
  root_cause: "Concise root cause description"
  exploit_primitive: "Exploitation primitive"
  discovery: ["Discovery methods with HIGH confidence"]
```

## Methodology

This corpus was built using the **Structured Research Reconstruction** methodology:

1. **Phase 1 — Facts:** Extract only observable, evidence-tethered facts from source code, dynamic traces, PoC output
2. **Phase 2 — Research Process:** Hypothesize how the researcher likely found the bug
3. **Phase 3 — Timeline:** Construct step-by-step discovery narrative
4. **Phase 4 — Alternative Paths:** Score multiple discovery methods by confidence
5. **Phase 5 — Heuristics:** Extract reusable hunting patterns
6. **Phase 6 — Confidence:** Label every statement as FACT / INFERENCE / SPECULATION

## Relationship to Exploitarium

```
exploitarium/ (PoC exploits)
       │
       ▼
vuln-corpus/ (structured data)
  ├── corpus.yaml       ← Machine-readable extract
  ├── corpus.json       ← Same data in JSON
  ├── CROSS-REFERENCE.md ← Human-readable lookup
  ├── extraction-schema.yaml ← Schema definition
  └── README.md         ← This file
```

The Exploitarium repository contains the actual proof-of-concept exploit code. This corpus provides a structured, searchable index of the vulnerabilities discovered within it.

## Usage

```python
# Python: load the corpus
import json
with open('corpus.json') as f:
    data = json.load(f)
    for entry in data['corpus']['entries']:
        print(f"{entry['id']}: {entry['classification']['severity']} {entry['title']}")
```

```yaml
# YAML: query by severity
entries:
  filter: classification.severity == "Critical"
  count: 7
```

## License

This corpus is provided for research and educational purposes. The underlying vulnerabilities are documented in their respective CVE records and vendor advisories where applicable.
