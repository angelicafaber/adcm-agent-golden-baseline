# ADCM agent golden baseline

The approved, versioned security and governance configuration for AI agent repositories.
ADCM (Agent Discovery and Capability Mapping) scans agent repositories and their deployed
agents against [`agent-baseline.json`](agent-baseline.json) and reports drift. The same check
runs in pull requests through the `adcm-guardrails` action, so drift is caught before merge.

Derived from the ISD EAG golden repository baseline (repository security controls), plus
agent-specific controls: Entra Agent ID, approved models and SDKs, content safety, tool and
MCP allow-lists, telemetry, evaluations and declared-vs-deployed drift.

## Use it in an agent repository

1. Copy [`templates/`](templates) into the repository root and fill in `adcm-agent.yaml`.
2. Apply [`templates/ruleset.json`](templates/ruleset.json) as a branch ruleset
   (`gh api repos/OWNER/REPO/rulesets --input templates/ruleset.json`).
3. Keep `.github/workflows/guardrails.yml`. It pins this action by commit SHA, which also pins the
   baseline version; Dependabot proposes upgrades as pull requests.

```yaml
- uses: angelicafaber/adcm-agent-golden-baseline/.github/actions/adcm-guardrails@<commit-sha> # v1.1.0
  with:
    fail-on: high   # high, medium or low
```

The job fails when any failed control is at or above `fail-on`, writes annotations and a step
summary, and saves a JSON report. Controls that need the GitHub API (branch rules, commit
signatures) or the ADCM inventory (deployed drift) are reported as "not evaluated" in CI and
evaluated by ADCM.

## Controls (v1.1.0)

See [`agent-baseline.json`](agent-baseline.json) for the rule definitions and [`CHANGELOG.md`](CHANGELOG.md)
for version history. The action's engine is vendored from ADCM (`src/guardrails`); do not edit it here.
