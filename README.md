# opencode-guardrails

Decision-model guardrails for [OpenCode](https://opencode.ai)'s `shell`, `write`,
`edit` and `patch` tools.

Every guarded tool action is judged by a decision model *before* it runs.
Allow is silent; a block is enforced through OpenCode's permission layer
(`effect: "deny"` with a reason), so the tool call is refused and the reason is
fed back to the agent, letting it pick another approach.

## Design

1. **High bar** — block only concrete, likely-irreversible harm: data
   destruction outside the project (or of unrecoverable uncommitted work),
   sending secrets to an external host, exfiltrating private data,
   `curl … | bash` remote execution, malware. Never judges task fit, style or
   conventions.
2. **Fail-open** — when no decision model answers within the timeout, the
   action runs and the failure is logged. Configurable with `failMode`.
3. **neverBlock regexes** — user-defined safety valve;
   any matching action skips the decision model entirely. `alwaysAllow`
   regexes still block.
4. **Read-only fast-path** — simple, single, non-mutating shell commands
   (`git status`, `ls`, `rg`, `cat`, a bare `cd …`, …) are allowed without a
   model call.
5. **Audit log** — every decision (allow/block/error/cache/fast-path) is
   appended to `guardrails-log.jsonl`.

## How it works in OpenCode

- Captures full tool input on `tool.execute.before` (including write/edit content).
- Enforces the verdict in `permission.evaluate` by returning `effect: "deny"` with a reason for blocked actions.
- Reloads configuration on each prompt admission.
- Registers the `/guardrails` command (`status`, `on`, `off`, `model <provider/id>`, `test`, `log`).
- Stops the local `d3-lite` systemd user unit on plugin unload if this process started it.

## Configuration

User config (highest priority, replaces defaults):

- `~/.config/opencode/guardrails.json` or `~/.config/opencode/guardrails.jsonc`
- override directory with `OPENCODE_GUARDRAILS_DIR`

Schema (all fields optional):

```jsonc
{
  "enabled": true,
  "model": ["openai-codex/gpt-5.6-luna"],
  "scope": ["shell", "write", "edit", "patch"],
  "failMode": "open",
  "timeoutMs": 12000,
  "log": true,
  "maxChars": 8000,
  "cacheTtlMs": 300000,
  "minBlockConfidence": 0.5,
  "neverBlock": [],
  "alwaysAllow": [],
  "verboseErrors": false
}
```

## Decision paths

The plugin tries configured models in order and uses the first usable answer:

1. **`google-decisions/*`** — direct call to Google's Decisions API
   (`generativelanguage.googleapis.com/v1beta/models/<id>:classify`) with
   `x-goog-api-key` auth. Supports key rotation via `GEMINI_API_KEY_N` (and
   `GEMINI_API_KEY`) environment variables; only redacted labels are logged.
2. **`ctx.experimental.generate.decisions`** — OpenCode's native decision-model API
   (preferred for models that support it).
3. **`ctx.experimental.generate.text`** — chat fallback with a strict JSON
   verdict protocol.

For `d3-lite` (local fallback), the plugin can start the `d3-lite.service`
systemd *user* unit on demand, wait for `/health`, and stop it after an idle
window — but only if this process started it.

## Commands

- `/guardrails` — status + recent log lines.
- `/guardrails on` / `off` — toggle and persist.
- `/guardrails model <provider/id>` — set the primary model and persist.
- `/guardrails test` — run a safe and a risky sample through the live guard.
- `/guardrails log` — show recent decisions.

## Notes

- The Google Decisions path uses a direct `fetch` inside the plugin.
- The local `d3-lite` fallback uses an on-demand systemd user unit and `/health` probe.
- Log and config files live under `~/.config/opencode/` by default.

MIT — based on the guardrails concept for coding-agent safety.
