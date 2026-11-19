# opencode-guardrails

Decision-model guardrails for [OpenCode](https://opencode.ai)'s `shell`, `write`,
`edit` and `patch` tools — a native OpenCode V2 plugin, rewritten from
[pi-guardrails](https://github.com/hakergeniusz/pi-guardrails).

Every guarded tool action is judged by a decision model *before* it runs.
Allow is silent; a block is enforced through OpenCode's permission layer
(`effect: "deny"` with a reason), so the tool call is refused and the reason is
fed back to the agent as a `Tool.Error`, letting it pick another approach.

## Design (inherited from the pi original)

1. **High bar** — block only concrete, likely-irreversible harm: data
   destruction outside the project (or of unrecoverable uncommitted work),
   sending secrets to an external host, exfiltrating private data,
   `curl … | bash` remote execution, malware. Never judges task fit, style or
   conventions.
2. **Fail-open** — when no decision model answers within the timeout, the
   action runs and the failure is logged. Configurable with `failMode`.
3. **neverBlock regexes** — user-defined safety valve; matching actions always
   pass, even if a model says block.
4. **Audit log** — every decision (verdicts, fast-path allows, cache hits,
   fail-opens, errors) appends to `guardrails-log.jsonl`.
5. **Read-only fast-path** — `ls`, `cat`, `rg`, `git status`, version checks…
   skip the model entirely; compound commands are never fast-pathed.
6. **Confidence floor + verdict cache + multi-model chain** — as in the
   original.

## How it maps from pi → OpenCode V2

| pi extension | OpenCode V2 plugin |
| --- | --- |
| `pi.on("tool_call")` guard | `ctx.permission.hook("evaluate")` sets `effect: "deny"` + `message` (the official pre-action review point) |
| full tool input for the verdict | `ctx.tool.hook("execute.before")` captures `event.input` keyed by `{sessionID, messageID, id}` |
| `pi.registerCommand("guardrails")` | `ctx.command.transform(editor => editor.add({ name: "guardrails", … }))` |
| `ctx.ui.notify(...)` | `ctx.session.synthetic({ sessionID, text, resume: false })` |
| `pi.on("session_start")` config reload | `ctx.session.hook("prompt", …)` (reloads on each prompt admission) |
| `pi.on("session_shutdown")` d3-lite cleanup | the `setup` cleanup function |
| `modelRegistry.classify()` / `.complete()` | `ctx.experimental.generate.decisions()` / `ctx.experimental.generate.text()` |
| `pi.registerProvider("google-decisions", classifier impl)` | direct `fetch` to Google's Decisions API inside the plugin (no custom provider registration) |
| `~/.pi/agent/guardrails*.json*` | `~/.config/opencode/guardrails*.json*` (override with `OPENCODE_GUARDRAILS_DIR`) |
| config via env/CLI | `ctx.options` (plugin object form) merged over the on-disk JSON |

`ctx.permission.assert` is deliberately **not** used for the guard: it is the
user-approval API and would prompt on every action. Automatic model-based
blocking belongs in the `evaluate` hook. The `assert`-driven permission system
is what ultimately turns the deny into a tool error the model sees.

## Decision models

Refs are `"provider/id"`, tried in order; the first usable answer wins.

- **Google AI Studio Decisions** (`google-decisions/gemini-decision-1`) — direct
  `POST /v1beta/decisions`, map-shaped questions, `noul` bools,
  `x-goog-api-key` auth. Includes the original **multi-key ring**: a per-day
  quota 429 marks a key dead until midnight Pacific, a per-minute hit cools it
  by Google's retry hint (≤120 s), an ambiguous quota 429 marks it suspected
  for 30 min, and a 401/403 is out for the day. Keys come from the resolved
  key, `GEMINI_API_KEY_N` env vars and `multi-account.json`; only redacted
  labels are ever logged. Set `GEMINI_API_KEY_1` (or more) to use this path.
- **OpenCode decision models** (e.g. `opencode/jev-1.13`) —
  `ctx.experimental.generate.decisions()` with a `choice` question, yielding a
  calibration confidence.
- **Chat models** (e.g. an OpenRouter `:free` model) —
  `ctx.experimental.generate.text()` with a strict JSON verdict protocol.
- **Local `llama.cpp/d3-lite`** — the on-demand systemd user unit from the
  original is preserved (`d3-lite.service`, started only when the chain
  reaches it, stopped after ~10 idle minutes or at plugin unload, and only if
  this plugin started it). Its verdict is requested through the configured
  OpenCode llama.cpp provider via `generate.decisions`/`generate.text`.

Defaults are `["opencode/jev-1.13", "openrouter/nvidia/nemotron-3.5-lightning:free"]`.
**Set `model` to refs available in your own OpenCode install** — the Google
path works out of the box once a `GEMINI_API_KEY_N` is set.

## Configuration

`~/.config/opencode/guardrails.json` (all keys optional; defaults below), and
optionally via the plugin object form in `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "opencode-guardrails",
      "options": {
        "enabled": true,
        "model": ["google-decisions/gemini-decision-1", "opencode/jev-1.13"],
        "scope": ["shell", "write", "edit", "patch"],
        "failMode": "open",
        "timeoutMs": 8000,
        "log": true,
        "maxChars": 6000,
        "cacheTtlMs": 300000,
        "minBlockConfidence": 0.6,
        "alwaysAllow": ["^\\s*(ls|pwd|cat|rg|grep|fd|jq)\\b"],
        "neverBlock": []
      }
    }
  ]
}
```

| key | meaning |
| --- | --- |
| `enabled` | guard on/off (also `/guardrails on|off`) |
| `model` | one ref or an ordered list of refs |
| `scope` | tool names to guard (OpenCode names: `shell`, `write`, `edit`, `patch`, `powershell`) |
| `failMode` | `open` (run when models unavailable) or `closed` (block) |
| `timeoutMs` | per-model timeout |
| `log` | append decisions to the audit log |
| `maxChars` | truncate the payload sent to the model |
| `cacheTtlMs` | identical actions reuse their verdict for this long |
| `minBlockConfidence` | block verdicts below this confidence run anyway (allow); 0 disables |
| `alwaysAllow` | shell regexes that skip the model |
| `neverBlock` | regexes (matched against the bare action) that can never be blocked |
| `verboseErrors` | keep longer model error strings in the log |

## Commands

- `/guardrails` — status + last 6 decisions
- `/guardrails on|off` — toggle (persists)
- `/guardrails model <provider/model-id>` — set the model chain (persists)
- `/guardrails test` — run a safe and a risky canned payload through the
  pipeline (nothing is executed)
- `/guardrails log` — last 15 decisions

Command output is injected as a non-resuming synthetic message in the session.

## Install / load

Local development:

```jsonc
{
  "plugins": ["./plugins/opencode-guardrails"]
}
```

Or publish the package and use `"plugins": ["opencode-guardrails"]`.

## Known gaps / differences from the pi original

- pi's provider/classifier registration API has no V2 equivalent; the Google
  Decisions classifier is instead called directly via `fetch`. The SystemOne
  classifier is represented by OpenCode's native decision models.
- `llama.cpp/d3-lite` uses whatever llama.cpp provider you have configured in
  OpenCode; the exact pi `llama-cpp-classify` wire protocol is not reproduced.
- Config/log paths moved from `~/.pi/agent/` to `~/.config/opencode/`.
- The `execute.before` input capture may not run before the permission check
  for `write`/`edit` (their permission is tool-level). In that case the guard
  falls back to the permission `resources` (target path) instead of the full
  file content. Shell commands always arrive with full text via the `shell`
  permission's scanner-produced resources.
- No TUI part: the original had none (notifications were plain text).
- Tests for the two pure helpers (d3 lifecycle, Google key rotation) were
  ported; the original had no integration tests for the hook wiring.

## License

MIT — 2026 hakergeniusz
