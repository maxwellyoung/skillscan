# Status

Last updated: 2026-05-21
Status: Active
Lifecycle: product-hardening

## Current State

- Skill/security scanning tool is being hardened as a public developer-security product.
- Scanner now includes harsher scoring, cross-line secret exfiltration detection, lifecycle-script analysis, hostile skill-instruction checks, persistence/system-modification detection, adversarial evals, and a local installed-skills false-positive corpus.

## Revive When

- Add richer evidence extraction, SARIF/JSON exports, package manifest heuristics, and CI/CLI workflows.

## Next Useful Move

- Expand the eval corpus with real malicious repositories and wire score regressions into CI.
