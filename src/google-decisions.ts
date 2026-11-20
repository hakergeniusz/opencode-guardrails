/**
 * Google AI Studio Decisions API classifier.
 *
 * Same verdict protocol as OpenCode's decision models, but with Google's wire
 * shapes: questions/answers are maps, yes/no is `noul` (not `predicate`), and
 * auth is the `x-goog-api-key` header. Kept dependency-free so it can be tested
 * without OpenCode.
 *
 * Multi-key ring: gemini-decision-1 quota is per project, so a 429 or a revoked
 * key tries the next key. Marks are in-memory (session-scoped); labels are the
 * key's last 4 chars — never the key itself.
 */

import * as fs from "node:fs"
import * as path from "node:path"

const BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
const API = "google-decisions"

const DEFAULT_HOME = process.env.HOME ?? "~"
const MULTI_ACCOUNT_PATH = path.join(DEFAULT_HOME, ".config", "opencode", "multi-account.json")
const SUSPECTED_TTL_MS = 30 * 60 * 1000
const MINUTE_MAX_MS = 120 * 1000

export interface ClassifierContext {
	state: unknown
	questions: Record<string, { type: string; instructions: string; criteria: unknown }>
}

export interface ClassifierResult {
	api: string
	provider: string
	model: string
	answers: Record<string, { type: string; [k: string]: unknown }>
	stopReason: "stop" | "error" | "aborted"
	errorMessage?: string
	timestamp: number
}

interface DecisionsKey {
	value: string
	label: string
}

const marks = new Map<string, number>()
let sticky: string | undefined

function redactKey(value: string): string {
	return value.length >= 8 ? `…${value.slice(-4)}` : "…"
}

/** Resolve keys from GEMINI_API_KEY_N / GEMINI_API_KEY env vars and optional local account config. Deduped. */
function keys(preferred: string | undefined): DecisionsKey[] {
	const seen = new Set<string>()
	const out: DecisionsKey[] = []
	const push = (value: string | undefined): void => {
		if (!value || seen.has(value)) return
		seen.add(value)
		out.push({ value, label: redactKey(value) })
	}
	push(preferred)
	try {
		const config = JSON.parse(fs.readFileSync(MULTI_ACCOUNT_PATH, "utf8")) as {
			providers?: Record<string, { api?: string; accounts?: Array<{ apiKey?: string }> }>
		}
		const google = config.providers?.google
		if (google?.api === "google-generative-ai" && Array.isArray(google.accounts)) {
			for (const account of google.accounts) {
				const ref = String(account.apiKey ?? "")
				push(ref.startsWith("$") ? process.env[ref.slice(1)] : ref)
			}
		}
	} catch {
		// Unreadable config: the env scan still applies.
	}
	for (const name of Object.keys(process.env)
		.filter((n) => /^GEMINI_API_KEY_\d+$/.test(n))
		.sort((a, b) => Number(/(\d+)$/.exec(a)?.[1]) - Number(/(\d+)$/.exec(b)?.[1]))) {
		push(process.env[name])
	}
	return out
}

/** Wall-clock offset of America/Los_Angeles at the given epoch (ms). */
function pacificOffsetMs(epochMs: number): number {
	const dtf = new Intl.DateTimeFormat("en-US", {
		timeZone: "America/Los_Angeles",
		hourCycle: "h23",
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	})
	const parts: Record<string, string> = {}
	for (const p of dtf.formatToParts(new Date(epochMs))) parts[p.type] = p.value
	const asUTC = Date.UTC(
		Number(parts.year),
		Number(parts.month) - 1,
		Number(parts.day),
		Number(parts.hour),
		Number(parts.minute),
		Number(parts.second),
	)
	return asUTC - Math.floor(epochMs / 1000) * 1000
}

/** Epoch ms of the next 00:00 in America/Los_Angeles (free-tier RPD reset). */
function nextPacificMidnight(epochMs: number): number {
	const offset = pacificOffsetMs(epochMs)
	const wall = epochMs + offset
	const nextDayWall = Math.floor(wall / 86400000) * 86400000 + 86400000
	return nextDayWall - offset
}

/** Dead-until for a Decisions API failure, or undefined when not key-specific. */
export function decisionsDeadUntil(errorMessage: string, now = Date.now()): number | undefined {
	if (/401|403|API[_ ]KEY[_ ]INVALID|API key not valid|PERMISSION_DENIED/i.test(errorMessage)) {
		return nextPacificMidnight(now)
	}
	if (!/429|RESOURCE_EXHAUSTED|quota|rate.?limit|too many requests/i.test(errorMessage)) return undefined
	if (/PerDay|requests? per day|RequestsPerDay/i.test(errorMessage)) return nextPacificMidnight(now)
	if (/per minute|PerMinute/i.test(errorMessage)) return now + 75_000
	const retryIn = /retry in ([0-9.]+)\s*s/i.exec(errorMessage)
	if (retryIn) {
		return now + Math.min(MINUTE_MAX_MS, Math.max(5000, Number(retryIn[1]) * 1000 + 3000))
	}
	return now + SUSPECTED_TTL_MS
}

/** Question → Google Decisions wire question (map values, `noul` for bools). */
export function googleWireQuestion(question: {
	type: string
	instructions: string
	criteria: unknown
}): Record<string, unknown> {
	if (question.type === "choice") {
		return { type: "choice", instructions: question.instructions, criteria: question.criteria }
	}
	if (question.type === "bool") {
		const criteria = question.criteria as { true?: string; false?: string } | undefined
		return {
			type: "noul",
			instructions: question.instructions,
			criteria: { true_description: criteria?.true ?? "", false_description: criteria?.false ?? "" },
		}
	}
	return { type: "score", instructions: question.instructions, criteria: question.criteria }
}

/** Reset in-memory key marks (used by tests). */
export function resetDecisionMarks(): void {
	marks.clear()
	sticky = undefined
}

/** The classifier implementation. */
export function googleDecisionsClassifier() {
	return async (
		model: { id: string; baseUrl?: string },
		context: ClassifierContext,
		options?: { apiKey?: string; signal?: AbortSignal },
	): Promise<ClassifierResult> => {
		const output: ClassifierResult = {
			api: API,
			provider: "google-decisions",
			model: model.id,
			answers: {},
			stopReason: "stop",
			timestamp: Date.now(),
		}
		const url = `${(model.baseUrl ?? BASE_URL).replace(/\/+$/u, "")}/decisions`
		const all = keys(options?.apiKey)
		if (all.length === 0) {
			output.stopReason = "error"
			output.errorMessage = "no Google API key (set GEMINI_API_KEY or GEMINI_API_KEY_1)"
			return output
		}
		const ordered = [...all]
		if (sticky) {
			const idx = ordered.findIndex((k) => k.value === sticky)
			if (idx > 0) ordered.unshift(...ordered.splice(idx, 1))
		}
		let lastError = ""
		let tried = 0
		for (const key of ordered) {
			if (options?.signal?.aborted) {
				output.stopReason = "aborted"
				return output
			}
			const deadUntil = marks.get(key.label)
			if (deadUntil && deadUntil > Date.now()) continue
			tried += 1
			try {
				const response = await fetch(url, {
					method: "POST",
					headers: { "content-type": "application/json", "x-goog-api-key": key.value },
					body: JSON.stringify({
						model: model.id,
						input: JSON.stringify(context.state),
						questions: Object.fromEntries(
							Object.entries(context.questions).map(([id, question]) => [id, googleWireQuestion(question)]),
						),
					}),
					signal: options?.signal,
				})
				const body = (await response.json()) as {
					answers?: Record<
						string,
						{
							type?: string
							choice?: string
							probabilities?: Record<string, number>
							confidence?: number
							noul?: number
							score?: number
						}
					>
					error?: { message?: string }
				}
				if (!response.ok) {
					throw new Error(`${response.status}: ${body.error?.message ?? `Google Decisions API error ${response.status}`}`)
				}
				// This key answered: sticky from now on, any mark against it is stale.
				sticky = key.value
				marks.delete(key.label)
				const answers: ClassifierResult["answers"] = {}
				for (const [id, answer] of Object.entries(body.answers ?? {})) {
					if (answer.type === "choice" && typeof answer.choice === "string") {
						answers[id] = {
							type: "choice",
							choice: answer.choice,
							probabilities: answer.probabilities ?? {},
							confidence: answer.confidence ?? 0,
						}
					} else if (answer.type === "noul" && typeof answer.noul === "number") {
						answers[id] = { type: "bool", probability: answer.noul }
					} else if (answer.type === "score" && typeof answer.score === "number") {
						answers[id] = { type: "score", score: answer.score, confidence: answer.confidence ?? 0 }
					}
				}
				output.answers = answers
				return output
			} catch (error) {
				lastError = String((error as Error)?.message ?? error)
				if (options?.signal?.aborted) {
					output.stopReason = "aborted"
					return output
				}
				const deadUntil = decisionsDeadUntil(lastError)
				if (deadUntil) marks.set(key.label, deadUntil)
			}
		}
		output.stopReason = "error"
		output.errorMessage =
			tried === 0
				? `gemini-decision-1: all ${ordered.length} key(s) are quota-marked`
				: `gemini-decision-1 failed on ${tried}/${ordered.length} key(s); last: ${lastError.slice(0, 150)}`
		return output
	}
}
