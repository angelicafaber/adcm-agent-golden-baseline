# Changelog

## 1.1.0 (2026-10-27)

- Authentication flow controls. Delegated (on-behalf-of) calls keep the signed-in user's identity
  in the target's logs; app-only (client credentials) calls show only the app or managed identity.
  - GR-AUTH-001: the manifest declares `invocation` and an `auth` flow per tool; interactive
    agents use delegated access for every tool.
  - GR-AUTH-002: user-facing code does not request client-credentials tokens and uses the
    on-behalf-of exchange for delegated tools.
  - GR-AUTH-003 (evaluated by ADCM): the deployed identity of a user-facing agent holds no
    application permissions.
- New optional manifest fields: `invocation` and tool `auth`.

## 1.0.0 (2026-10-25)

- First release: 17 security and 10 governance controls for AI agent repositories.
- Repository controls derived from the ISD EAG golden repository baseline 2026.09.10.2.
- Agent controls: Entra Agent ID, approved models and SDKs, content safety, tool and MCP host
  allow-lists with human approval for write tools, telemetry, evaluations in CI, baseline pin,
  declared-vs-deployed drift.
