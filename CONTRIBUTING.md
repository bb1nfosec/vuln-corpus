# Contributing

Thanks for your interest in improving the Exploitarium Vulnerability Corpus.

This repository is a **structured, machine-readable dataset** — not exploit code. Contributions should keep it accurate, well-sourced, and schema-valid.

## What belongs here

- Corrections to existing entries (versions, CWEs, severities, root causes).
- New entries derived from public proof-of-concept research, following [`extraction-schema.yaml`](extraction-schema.yaml).
- Improvements to the tooling in [`scripts/`](scripts/) and the CI workflow.

Please **do not** add operational exploit code, payloads, or weaponized tooling. This repo describes vulnerabilities at a metadata/research level only — the underlying PoCs live in their source repositories.

## Adding or editing an entry

1. Edit [`corpus.yaml`](corpus.yaml) — it is the single source of truth.
2. Regenerate the JSON view:
   ```bash
   pip install -r requirements.txt
   python3 scripts/generate-json.py
   ```
3. Validate before committing:
   ```bash
   python3 scripts/validate-corpus.py --json corpus.yaml
   ```
   The validator must report **0 errors**.
4. Update [`CROSS-REFERENCE.md`](CROSS-REFERENCE.md) counts/tables if your change affects them.

## Entry conventions

- IDs follow `EX-XXX` (zero-padded, sequential).
- `severity` is one of `Critical | High | Medium | Low | Informational`.
- `cwe` uses the `CWE-XXX` form; compound CWEs use `CWE-XXX / CWE-YYY`.
- Every claim should be traceable to a public source (source file + line, commit, or CVE record).
- Credit independent/prior discoverers where known.

## Pull requests

- Keep PRs focused (one logical change set).
- Make sure CI (schema validation) passes.
- Reference the source PoC or advisory for any new entry.

By contributing, you agree that your contributions are licensed under [CC BY 4.0](LICENSE).
