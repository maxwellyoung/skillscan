# Status

SkillScan is an active static review tool with a web scanner, local CLI, and composite GitHub Action.

- The published npm release is `@maxwellyoung/skillscan@0.2.0`.
- The source scanner and release candidate report their version in scan results. The default Action runs scanner source from the selected Action revision. Its optional npm mode can select a separately published version.
- Run `pnpm build:cli && pnpm build && pnpm e2e:parity` to compare the production HTTP route and both source and packed CLI execution.
- Run `pnpm benchmark --check` to verify the fixture evaluation report. The fixtures do not establish real-world detection rates.
- A shared remote scan limit is available when a deployment supplies the dedicated Redis REST URL and token documented in README.
