# SkillScan Case Study

## Problem

AI coding tools make it easy to install local skills and MCP servers, but those packages can request broad filesystem, shell, network, and environment access. Users need a quick way to identify suspicious patterns before running untrusted code.

## Approach

SkillScan uses deterministic static checks instead of AI judgment for the core scan. The goal is not to prove safety; it is to make risky behavior visible quickly enough that developers can decide whether to keep reviewing, sandbox, or avoid the package.

## Engineering decisions

- Use regex and structural checks for speed, repeatability, and explainability.
- Return snippets, line numbers, and remediation notes so findings can be reviewed directly.
- Focus the UI on severity and concrete evidence rather than vague security posture.
- Support GitHub URLs and pasted code to keep the workflow lightweight.

## Tradeoffs

- Static checks can miss context-dependent behavior and sophisticated obfuscation.
- Pattern-based findings can produce false positives when legitimate tools need shell, network, or filesystem access.
- The scanner should be treated as a first-pass review aid, not a complete security audit.

## Next steps

- Add package manifest heuristics for suspicious dependencies and install scripts.
- Add SARIF export for CI usage.
- Add fixture-based tests for each rule category.
- Add a CLI so the scanner can run before installing a skill or MCP server.
