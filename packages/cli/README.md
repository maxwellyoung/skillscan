# @maxwellyoung/skillscan

Static, zero-AI security scanner for Claude Code skills, MCP servers, npm packages, VS Code extensions, and GitHub Actions workflows. It checks for risky patterns before you install or run them, such as credential exfiltration, lifecycle-script abuse, hostile skill instructions, persistence, and unpinned or over-privileged workflows.

Local paths are scanned entirely offline: no AI, no account, and nothing is uploaded. The package is one bundled file with no runtime dependencies.

```bash
npx @maxwellyoung/skillscan ./my-skill          # Node.js 20+
npm install -g @maxwellyoung/skillscan          # installs the `skillscan` command
```

```bash
skillscan ./my-skill                     # Claude Code skill folder
skillscan ./my-mcp-server                # MCP server repo (includes .github/workflows)
skillscan ./my-extension --json          # VS Code extension folder, JSON result
skillscan . --sarif -o skillscan.sarif   # SARIF 2.1.0 for GitHub code scanning
skillscan pkg:npm/left-pad@1.3.0         # npm package (metadata + tarball)
skillscan https://github.com/owner/repo  # GitHub repo, tree, or blob URL
skillscan https://open-vsx.org/extension/publisher/name
```

| Option | Meaning |
| --- | --- |
| `--json` | Full scan result as JSON |
| `--sarif` | SARIF 2.1.0 log with `security-severity` for code scanning |
| `-o, --output <file>` | Write the report to a file; the human-readable report still goes to stdout |
| `--fail-on <severity>` | `critical` (default, the "block install" verdict), `high`, `medium`, `low`, `info`, or `none` |
| `--verbose` | Also list informational findings in text output |

Exit codes: `0` nothing at or above `--fail-on`, `1` at least one finding at or above `--fail-on`, `2` usage error or the scan could not run.

The rules are regex and heuristic checks, so expect some false positives, and sophisticated evasions can be missed. Treat a pass as "nothing obvious found", not as proof of safety.

A composite GitHub Action, the web scanner, and the full rule list are documented at https://github.com/maxwellyoung/skillscan.

MIT License.
