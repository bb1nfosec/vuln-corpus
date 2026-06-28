# Security & Responsible Use

## Nature of this repository

This repository is a **research dataset**. It catalogs publicly documented vulnerabilities as structured metadata (product, version, classification, CWE, one-line root cause, and discovery methodology). It does **not** host operational exploits, payloads, or weaponized tooling.

## Intended use

The corpus is intended for:

- Defensive security research, detection engineering, and patch prioritization.
- Studying vulnerability classes and discovery methodology.
- Academic and educational analysis.

It is **not** intended to facilitate unauthorized access to systems. Only test against systems you own or are explicitly authorized to assess. You are responsible for complying with all applicable laws and agreements.

## Reporting issues with the data

This repo does not run a service, so there is no exploitable attack surface here. If you find:

- **An inaccuracy** (wrong version, CWE, severity, attribution, etc.) — open an issue or PR.
- **A genuine vulnerability in the tooling** (`scripts/` or the CI workflow) — open a private security advisory via GitHub's "Security" tab, or open an issue if it is low risk.

## Upstream vulnerabilities

Vulnerabilities described in this corpus belong to their respective upstream projects. Report or follow up on those through the affected project's own disclosure process and the relevant CVE records — not here.
