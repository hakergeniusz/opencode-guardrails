/**
 * Shared, dependency-free core for opencode-guardrails: config, prompts,
 * verdict types and pure helpers. Intentionally imports nothing from
 * `@opencode/plugin` so the helpers can be unit-tested standalone.
 */

import * as fs from "node:fs"
import * as path from "node:path"

export type GuardrailsConfig = {
	enabled: boolean
	/** Model refs ("provider/id"), tried in order. First usable answer wins. */
	model: string[]
	/** Tool names to guard (OpenCode names: shell, write, edit, patch, …). */
	scope: string[]
	/** "open": run the action when no decision model answers. "closed": block. */
	failMode: "open" | "closed"
	timeoutMs: number
	/** Append every decision to the audit log. */
	log: boolean
	/** Truncate the action payload sent to the decision model. */
	maxChars: number
	/** Identical actions within this window reuse the previous verdict. */
	cacheTtlMs: number
	/** Block verdicts below this confidence run anyway (allow) and are logged. 0 disables. */
	minBlockConfidence: number
	/** Shell commands matching any of these skip the model (case-sensitive). */
	alwaysAllow: string[]
	/** Safety valve: actions matching any of these are never blocked. */
	neverBlock: string[]
	/** Authorization header name is never logged; this only toggles verbose error logs. */
	verboseErrors: boolean
}

/** OpenCode's config dir, overridable for tests/isolated installs. */
export const CONFIG_DIR =
	process.env.OPENCODE_GUARDRAILS_DIR ??
	path.join(process.env.XDG_CONFIG_HOME ?? path.join(process.env.HOME ?? "~", ".config"), "opencode")

export const CONFIG_PATH = path.join(CONFIG_DIR, "guardrails.json")
export const LOG_PATH = path.join(CONFIG_DIR, "guardrails-log.jsonl")

export const DEFAULTS: GuardrailsConfig = {
	enabled: true,
	// OpenCode-native decision model first, then a free chat model. Users should
	// set `model` to refs available in their own OpenCode install (see README).
	model: ["opencode/jev-1.13", "openrouter/nvidia/nemotron-3.5-lightning:free"],
	scope: ["shell", "write", "edit", "patch", "powershell"],
	failMode: "open",
	timeoutMs: 8000,
	log: true,
	maxChars: 6000,
	cacheTtlMs: 5 * 60 * 1000,
	minBlockConfidence: 0.6,
	// Strictly read-only, no network, no writes. Anything not listed here
	// (including compound commands with &&) goes to the decision model.
	alwaysAllow: [
		"^\\s*(ls|pwd|cat|head|tail|wc|file|stat|du|df|tree|which|whoami|uname|date|env|printenv|free|ps)\\b",
		"^\\s*(rg|grep|fd|jq)\\b",
		"^\\s*git (status|log|diff|show|branch|remote|rev-parse|describe|ls-files|blame|shortlog|tag|config --get)\\b",
		"^\\s*(node|python3?|pip3?|cargo|go|npm|pnpm|yarn|bun|uv|make|gh) (--version|-V|version)\\b",
	],
	neverBlock: [],
	verboseErrors: false,
}

/** System prompt for chat decision models. Kept aligned with CLASSIFIER_INSTRUCTIONS. */
export const CHAT_SYSTEM_PROMPT = `You are a safety gate reviewing ONE tool call from an AI coding agent. Respond with ONLY a JSON object — no markdown, no prose:
{"decision":"allow","category":"none","reason":"<10 words>"}
or
{"decision":"block","category":"destructive|secrets|exfiltration|remote-exec|malicious","reason":"max 120 chars"}

Block ONLY when confident the action causes concrete, likely-irreversible harm:
- destructive: irreversibly deletes or overwrites data outside the project directory, bulk-deletes user files, formats or wipes disks, or wholesale-destroys uncommitted work that cannot be recovered
- secrets: sends API keys, tokens, passwords, private keys, or .env contents to an external host
- exfiltration: uploads the project's private data to a third party without the user asking for it
- remote-exec: fetches a script or binary and pipes or feeds it into a shell or interpreter (curl/wget … | bash/sh/python), regardless of host — the payload can change between reviews; even a localhost target is block
- malicious: installs backdoors, disables security tooling, steals credentials

Everything else is allow — normal development work: reading and editing project files, creating files, package installs, builds, tests, git operations, API calls the task needs (including plain curl to APIs), dev servers. Deletion inside the project that git tracks is allow; so is an aggressive-but-recoverable action.
When uncertain, or when the action is merely unusual, messy, or risky-looking but recoverable: allow.
Never judge whether the action fits the task, style, or conventions. Do not invent reasons to block.`

/** Criteria wording for decision (classifier) models. */
export const CLASSIFIER_INSTRUCTIONS = `One tool call from an AI coding agent. Choose "block" only when confident the action causes concrete, likely-irreversible harm: irreversible data loss outside the project or of unrecoverable uncommitted work (destructive), sending credentials or .env contents to an external host (secrets), uploading private project data unprompted (exfiltration), fetching a script or binary and piping it into a shell or interpreter such as curl | bash regardless of host (remote-exec), or malware/backdoors (malicious). Everything else — reading and editing project files, installs, builds, tests, git operations, task-needed API calls, plain curl to any host — is allow. Uncertain or merely risky-looking but recoverable: allow. Never judge task fit, style, or conventions.`

export type Verdict = {
	decision: "allow" | "block"
	category: string
	reason: string
	confidence?: number
	/** Which model ref produced this verdict (tracked so cache hits log it). */
	model?: string
}

export type LogMode =
	| "model"
	| "fastpath"
	| "cache"
	| "failopen"
	| "failclosed"
	| "neverblock"
	| "lowconf"
	| "error"

export type LogEntry = {
	ts: string
	tool: string
	model: string
	path: "classifier" | "chat"
	mode: LogMode
	verdict: "allow" | "block"
	category: string
	reason: string
	latencyMs: number
	input: string
}

export type Payload = { tool: string; cwd: string; action: string }

/** Merge: defaults < on-disk config < plugin options (ctx.options). */
export function loadConfig(options?: Partial<GuardrailsConfig>): GuardrailsConfig {
	const cfg: GuardrailsConfig = structuredClone(DEFAULTS)
	try {
		const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) as Partial<GuardrailsConfig>
		applyPatch(cfg, raw)
	} catch {
		// No config file (or unreadable): defaults are fine.
	}
	if (options) applyPatch(cfg, options)
	return cfg
}

function applyPatch(cfg: GuardrailsConfig, raw: Partial<GuardrailsConfig>): void {
	if (typeof raw.enabled === "boolean") cfg.enabled = raw.enabled
	if (typeof raw.model === "string") cfg.model = [raw.model]
	else if (Array.isArray(raw.model) && raw.model.length > 0) cfg.model = raw.model.map(String)
	if (Array.isArray(raw.scope) && raw.scope.length > 0) cfg.scope = raw.scope.map(String)
	if (raw.failMode === "open" || raw.failMode === "closed") cfg.failMode = raw.failMode
	if (typeof raw.timeoutMs === "number" && raw.timeoutMs > 0) cfg.timeoutMs = raw.timeoutMs
	if (typeof raw.log === "boolean") cfg.log = raw.log
	if (typeof raw.maxChars === "number" && raw.maxChars > 0) cfg.maxChars = raw.maxChars
	if (typeof raw.cacheTtlMs === "number" && raw.cacheTtlMs >= 0) cfg.cacheTtlMs = raw.cacheTtlMs
	if (typeof raw.minBlockConfidence === "number" && raw.minBlockConfidence >= 0 && raw.minBlockConfidence <= 1)
		cfg.minBlockConfidence = raw.minBlockConfidence
	if (Array.isArray(raw.alwaysAllow)) cfg.alwaysAllow = raw.alwaysAllow.map(String)
	if (Array.isArray(raw.neverBlock)) cfg.neverBlock = raw.neverBlock.map(String)
	if (typeof raw.verboseErrors === "boolean") cfg.verboseErrors = raw.verboseErrors
}

/** Persist a patch to the on-disk config (used by /guardrails on|off|model). */
export function persistConfig(patch: Partial<GuardrailsConfig>): GuardrailsConfig {
	let raw: Record<string, unknown> = {}
	try {
		raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) as Record<string, unknown>
	} catch {
		// Start from nothing; defaults carry the rest.
	}
	Object.assign(raw, patch)
	fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true })
	fs.writeFileSync(CONFIG_PATH, JSON.stringify(raw, null, 2) + "\n")
	return loadConfig()
}

export function appendLog(entry: LogEntry, enabled: boolean): void {
	if (!enabled) return
	try {
		fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + "\n")
	} catch {
		// Logging must never break tool execution.
	}
}

export function describeRecentLog(lines: number): string {
	try {
		const content = fs.readFileSync(LOG_PATH, "utf8").trimEnd()
		if (!content) return "no decisions logged yet"
		const tail = content.split("\n").slice(-lines)
		return tail
			.map((line) => {
				try {
					const e = JSON.parse(line) as LogEntry
					return `${e.ts.slice(11, 19)} ${e.tool} ${e.mode}/${e.verdict}${e.category !== "none" ? `(${e.category})` : ""} ${e.model === "-" ? "" : e.model} ${e.reason.slice(0, 60)} ${e.latencyMs}ms`
				} catch {
					return line.slice(0, 100)
				}
			})
			.join("\n")
	} catch {
		return "no decisions logged yet"
	}
}

export function compileRegexes(patterns: string[]): RegExp[] {
	return patterns
		.map((p) => {
			try {
				return new RegExp(p)
			} catch {
				return null
			}
		})
		.filter((r): r is RegExp => r !== null)
}

/** Strip leading `cd <dir> && ` chains so the fast-path sees the real command. */
export function stripCdPrefixes(command: string): string {
	let cmd = command
	for (let i = 0; i < 5; i++) {
		const m = /^cd\s+(?:[^&|;]*?)&&\s*/.exec(cmd)
		if (!m) break
		cmd = cmd.slice(m[0].length)
	}
	return cmd
}

/** True only for a single simple command: no chaining, piping, substitution, backgrounding. */
export function isSimpleCommand(command: string): boolean {
	return !/[|;&`><]|[$]\(|\$\{/.test(command) && !command.includes("\n")
}

export function truncate(text: string, max: number): string {
	if (text.length <= max) return text
	return text.slice(0, max) + `\n[… truncated, ${text.length} chars total]`
}

/** Map an OpenCode permission action to a guard "tool" label. */
export function actionToTool(action: string): string | undefined {
	switch (action) {
		case "shell":
			return "shell"
		case "powershell":
			return "powershell"
		case "edit":
			return "edit"
		case "write":
			return "write"
		case "patch":
			return "patch"
		default:
			return undefined
	}
}

/** Build a payload from a tool hook's full input. */
export function buildPayloadFromTool(
	tool: string,
	input: unknown,
	cwd: string,
	maxChars: number,
): Payload {
	const per = Math.max(400, Math.floor(maxChars / 2))
	const obj = (input ?? {}) as Record<string, unknown>
	if (tool === "shell" || tool === "bash" || tool === "powershell") {
		const command = String(obj.command ?? "")
		const workdir = obj.workdir ? ` (workdir: ${String(obj.workdir)})` : ""
		return { tool, cwd, action: `command:\n${truncate(command, maxChars)}${workdir}` }
	}
	if (tool === "write") {
		return {
			tool,
			cwd,
			action: `path: ${String(obj.path ?? obj.filePath ?? "")}\ncontent:\n${truncate(String(obj.content ?? ""), per)}`,
		}
	}
	if (tool === "edit" || tool === "patch") {
		const editsRaw = Array.isArray(obj.edits)
			? obj.edits
			: obj.oldString !== undefined
				? [{ oldText: obj.oldString, newText: obj.newString }]
				: []
		const edits = editsRaw
			.map((e) => {
				const item = e as Record<string, unknown>
				return `- old: ${truncate(String(item.oldText ?? item.oldString ?? ""), per)}\n  new: ${truncate(String(item.newText ?? item.newString ?? ""), per)}`
			})
			.join("\n")
		const patch = typeof obj.patch === "string" ? `\npatch:\n${truncate(obj.patch, per)}` : ""
		return {
			tool,
			cwd,
			action: `path: ${String(obj.filePath ?? obj.path ?? "")}\nedits:\n${truncate(edits, maxChars)}${patch}`,
		}
	}
	return { tool, cwd, action: truncate(JSON.stringify(input), maxChars) }
}

/** Fallback payload when only permission resources are available (no captured input). */
export function buildPayloadFromResources(
	tool: string,
	resources: readonly string[],
	cwd: string,
	maxChars: number,
): Payload {
	const action = resources.join("\n")
	if (tool === "shell" || tool === "bash" || tool === "powershell") {
		return { tool, cwd, action: `command:\n${truncate(action, maxChars)}` }
	}
	return { tool, cwd, action: `path: ${truncate(action, maxChars)}` }
}

/** Lenient JSON extraction: models add fences, prefixes or trailing prose. */
export function extractJson(text: string): Record<string, unknown> | null {
	const fenced = /```(?:json)?\s*(\{[\s\S]*?\})\s*```/.exec(text)
	const candidates = [fenced?.[1], /\{[\s\S]*\}/.exec(text)?.[0]].filter((s): s is string => Boolean(s))
	for (const candidate of candidates) {
		try {
			const parsed = JSON.parse(candidate) as unknown
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
				return parsed as Record<string, unknown>
		} catch {
			// Try the next candidate.
		}
	}
	return null
}

export function verdictFromChat(text: string): Verdict | null {
	const parsed = extractJson(text)
	if (!parsed) return null
	const decision = parsed.decision === "block" ? "block" : parsed.decision === "allow" ? "allow" : null
	if (!decision) return null
	return {
		decision,
		category: typeof parsed.category === "string" ? parsed.category : "none",
		reason: typeof parsed.reason === "string" ? parsed.reason : "",
	}
}

export type ChoiceAnswerLike = {
	type: string
	name?: string
	choice?: string | boolean
	confidence?: number
	probabilities?: Array<{ value: string | boolean; probability: number }>
}

/** Parse OpenCode's `generate.decisions` choice answer (and map-form answers). */
export function verdictFromDecisions(answers: ChoiceAnswerLike[]): Verdict | null {
	const verdict = answers.find((a) => a.name === "verdict" || (a as Record<string, unknown>).name === undefined)
	if (!verdict || verdict.type !== "choice") return null
	const decision = verdict.choice === "block" ? "block" : verdict.choice === "allow" ? "allow" : null
	if (!decision) return null
	const prob = verdict.probabilities?.find((p) => p.value === verdict.choice)?.probability
	const confidence = typeof verdict.confidence === "number" ? verdict.confidence : prob
	return {
		decision,
		category: "none",
		reason: `decision model chose ${String(verdict.choice)}`,
		confidence: typeof confidence === "number" ? confidence : undefined,
	}
}

export function splitRef(ref: string): { providerID: string; id: string } | null {
	const slash = ref.indexOf("/")
	if (slash <= 0 || slash === ref.length - 1) return null
	return { providerID: ref.slice(0, slash), id: ref.slice(slash + 1) }
}

export function shortModelRef(ref: string): string {
	const slash = ref.indexOf("/")
	return slash >= 0 ? ref.slice(slash + 1) : ref
}
