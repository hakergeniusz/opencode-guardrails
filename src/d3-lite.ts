/**
 * Lifecycle owner for the optional local d3-lite decision model, ported from
 * pi-guardrails. The systemd *user* unit is deliberately DISABLED: no model
 * sits in RAM while cloud decision models are healthy. This helper starts it
 * on demand, waits for llama-server's /health, and puts it back down after an
 * idle window or at plugin unload — but only if THIS process started it.
 *
 * Dependency-free (only node builtins) so it can be unit-tested with injected
 * deps — no systemd, no network, no real time.
 */

import { execFile } from "node:child_process"

const D3_LITE_SERVICE = "d3-lite.service"
const D3_LITE_HEALTH_URL = "http://127.0.0.1:11199/health"
const START_TIMEOUT_MS = 90_000
const PROBE_INTERVAL_MS = 500
const PROBE_TIMEOUT_MS = 1_500
const DEAD_TTL_MS = 15 * 60 * 1000
const IDLE_STOP_MS = 10 * 60 * 1000

export type D3LiteDeps = {
	probe?: () => Promise<boolean>
	isActive?: () => Promise<boolean>
	start?: () => Promise<void>
	stop?: () => Promise<void>
	sleep?: (ms: number) => Promise<void>
	now?: () => number
}

function systemctlUser(args: string[], tolerateFailure = false): Promise<void> {
	return new Promise((resolve, reject) => {
		execFile("systemctl", ["--user", ...args], (error) => {
			if (error && !tolerateFailure) reject(error)
			else resolve()
		})
	})
}

/** All methods never throw and are safe to call any number of times. */
export function d3LiteRuntime(deps: D3LiteDeps = {}) {
	const now = deps.now ?? Date.now
	const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)))
	const isActive =
		deps.isActive ?? (() => systemctlUser(["is-active", D3_LITE_SERVICE], true).then(() => true, () => false))
	const start = deps.start ?? (() => systemctlUser(["start", D3_LITE_SERVICE]))
	const stop = deps.stop ?? (() => systemctlUser(["stop", D3_LITE_SERVICE], true))
	const probe =
		deps.probe ??
		(async () => {
			try {
				return (await fetch(D3_LITE_HEALTH_URL, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) })).ok
			} catch {
				return false
			}
		})

	let deadUntil = 0
	let startedByUs = false
	let lastUsedAt = 0
	let idleTimer: ReturnType<typeof setTimeout> | undefined

	function armIdleStop(): void {
		if (idleTimer) clearTimeout(idleTimer)
		idleTimer = setTimeout(() => {
			idleTimer = undefined
			void maybeIdleStop()
		}, IDLE_STOP_MS)
		idleTimer.unref?.()
	}

	async function shutdown(): Promise<void> {
		startedByUs = false
		if (idleTimer) {
			clearTimeout(idleTimer)
			idleTimer = undefined
		}
		await stop()
	}

	async function maybeIdleStop(): Promise<void> {
		if (!startedByUs) return
		if (now() - lastUsedAt < IDLE_STOP_MS) {
			armIdleStop()
			return
		}
		await shutdown()
	}

	/** Bring the local fallback up. False = unusable right now. */
	async function ensureUp(): Promise<boolean> {
		if (await probe()) return true
		if (now() < deadUntil) return false
		if (!(await isActive())) {
			try {
				await start()
			} catch {
				deadUntil = now() + DEAD_TTL_MS
				return false
			}
			startedByUs = true
		}
		const deadline = now() + START_TIMEOUT_MS
		while (now() < deadline) {
			if (await probe()) {
				if (startedByUs) {
					lastUsedAt = now()
					armIdleStop()
				}
				return true
			}
			await sleep(PROBE_INTERVAL_MS)
		}
		// Never turned healthy: skip for a while — and if we started it, do not
		// leave a dead unit looping behind Restart=always.
		deadUntil = now() + DEAD_TTL_MS
		if (startedByUs) await shutdown()
		return false
	}

	/** A verdict came from d3-lite: keep the idle window open. */
	function noteUsed(): void {
		if (!startedByUs) return
		lastUsedAt = now()
		armIdleStop()
	}

	/** Plugin unloaded: put the unit down if this process started it. */
	function stopIfOurs(): Promise<void> {
		return startedByUs ? shutdown() : Promise.resolve()
	}

	return { ensureUp, noteUsed, stopIfOurs, maybeIdleStop }
}
