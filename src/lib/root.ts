/**
 * Root via ionstack.
 *
 * ionstack elevates any *new* adb shell to root, so the sequence is: push the
 * binary, start it, then open a fresh shell and check `id`. The host process
 * itself does not stay root (IONSTACK_SELF_ROOT=0) and we run no payload list
 * — every privileged step afterwards is an ordinary adb shell command.
 *
 * What it does *not* do is finish. The Quest 1 build holds the primitive in
 * its own process (IONSTACK_XRW_HOLD=1); it never returns, and killing it
 * takes the kernel state it is babysitting with it, which crashes the headset.
 * So we start it detached with its output redirected to a log file, poll that
 * log for progress and a fresh `id -u` for root, and once a shell comes back
 * as uid 0 we stop watching and leave ionstack running. A reboot clears it.
 */

import type { Adb } from "@yume-chan/adb";

import type { DeviceProfile } from "../data/profiles.js";
import { WORKDIR, push, shell, shellRaw } from "./device.js";

export const IONSTACK_PATH = `${WORKDIR}/ionstack`;
export const IONSTACK_LOG = `${WORKDIR}/ionstack.log`;

/** True when a freshly opened shell comes back as uid 0. */
export async function isRoot(adb: Adb): Promise<boolean> {
    const { stdout } = await shell(adb, "id -u");
    return stdout.trim() === "0";
}

export async function pushIonstack(
    adb: Adb,
    binary: Uint8Array,
    onProgress?: (transferred: number, total: number) => void,
): Promise<void> {
    await shell(adb, `mkdir -p ${WORKDIR}`);
    await push(adb, binary, IONSTACK_PATH, 0o755, (p) =>
        onProgress?.(p.transferred, p.total),
    );
    await shell(adb, `chmod 755 ${IONSTACK_PATH}`);
}

function envPrefix(env: Readonly<Record<string, string>>): string {
    return Object.entries(env)
        .map(([key, value]) => `${key}='${value}'`)
        .join(" ");
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/** ionstack colours its output; strip the escapes. */
function clean(line: string): string {
    return line.replace(/\[[0-9;]*m/g, "").trimEnd();
}

function byteLength(text: string): number {
    return new TextEncoder().encode(text).length;
}

/**
 * Follows a growing file on the device, one chunk per call.
 *
 * Each read is bounded by the size seen at the start of the call, so a write
 * landing mid-read cannot make us skip bytes — whatever arrives late is picked
 * up on the next drain.
 */
class LogTail {
    readonly #adb: Adb;
    readonly #path: string;
    readonly #onLine: ((line: string) => void) | undefined;
    #offset = 0;
    #pending = "";
    #useDd = false;

    constructor(adb: Adb, path: string, onLine?: (line: string) => void) {
        this.#adb = adb;
        this.#path = path;
        this.#onLine = onLine;
    }

    async drain(): Promise<void> {
        const size = await this.#size();
        if (size <= this.#offset) {
            return;
        }

        const text = await this.#read(size - this.#offset);
        if (!text) {
            return;
        }
        this.#offset += byteLength(text);

        this.#pending += text;
        const lines = this.#pending.split("\n");
        this.#pending = lines.pop() ?? "";
        for (const line of lines) {
            this.#onLine?.(clean(line));
        }
    }

    /** Emits the trailing partial line once the file stops growing. */
    flush(): void {
        if (this.#pending) {
            this.#onLine?.(clean(this.#pending));
            this.#pending = "";
        }
    }

    async #size(): Promise<number> {
        const { stdout } = await shell(
            this.#adb,
            `wc -c < ${this.#path} 2>/dev/null`,
        );
        const size = Number.parseInt(stdout.trim(), 10);
        return Number.isFinite(size) ? size : this.#offset;
    }

    async #read(count: number): Promise<string> {
        if (!this.#useDd) {
            const text = await shellRaw(
                this.#adb,
                `tail -c +${this.#offset + 1} ${this.#path} 2>/dev/null | head -c ${count}`,
            );
            if (text) {
                return text;
            }
            // Not every toybox tail takes a `+N` byte offset; dd is universal.
            this.#useDd = true;
        }
        return await shellRaw(
            this.#adb,
            `dd if=${this.#path} bs=1 skip=${this.#offset} count=${count} 2>/dev/null`,
        );
    }
}

/**
 * Starts ionstack detached and returns its pid, or "" when the pid could not
 * be pinned down — in which case the attempt is bounded by the clock alone.
 */
async function startIonstack(adb: Adb, profile: DeviceProfile): Promise<string> {
    await shell(adb, `rm -f ${IONSTACK_LOG}`);

    // `exec` in the subshell makes $! ionstack's own pid rather than a shell
    // wrapping it; nohup keeps it alive once this adb shell goes away.
    const command =
        `( cd ${WORKDIR} && exec nohup env ${envPrefix(profile.ionstackEnv)} ${IONSTACK_PATH} )` +
        ` </dev/null >${IONSTACK_LOG} 2>&1 & echo $!`;
    const { stdout } = await shell(adb, command);

    const pid = stdout.trim().split(/\s+/).pop() ?? "";
    if (!/^\d+$/.test(pid)) {
        return "";
    }
    // If the shell handed back a wrapper's pid instead, that pid dying says
    // nothing about ionstack, so don't track it.
    const { stdout: cmdline } = await shell(
        adb,
        `cat /proc/${pid}/cmdline 2>/dev/null | tr '\\0' ' '`,
    );
    return cmdline.includes("ionstack") ? pid : "";
}

async function isAlive(adb: Adb, pid: string): Promise<boolean> {
    const { stdout } = await shell(adb, `[ -d /proc/${pid} ] && echo alive`);
    return stdout.trim() === "alive";
}

/** Only ever called on a failed attempt — a rooted run must be left alone. */
async function stopIonstack(adb: Adb, pid: string): Promise<void> {
    if (pid) {
        await shell(
            adb,
            `kill ${pid} 2>/dev/null; sleep 1; kill -9 ${pid} 2>/dev/null`,
        );
    } else {
        await shell(adb, `pkill -f ${IONSTACK_PATH} 2>/dev/null`);
    }
}

export interface RootOptions {
    /** Kernel-specific tuning; comes from the device profile. */
    profile: DeviceProfile;
    /** Called with each line ionstack prints. */
    onLine?: (line: string) => void;
    /** How many times to retry the whole exploit before giving up. */
    attempts?: number;
    /** How long one attempt may run before it is written off. */
    timeoutMs?: number;
    /** How often to drain the log and re-check `id -u`. */
    pollMs?: number;
}

/**
 * Runs ionstack and reports whether a new shell comes back rooted.
 *
 * The exploit is racy by nature, so a failed attempt is expected occasionally
 * and simply retried. Output is streamed line by line because a run takes a
 * while and silence is indistinguishable from a hang.
 *
 * On success ionstack is still running: that is deliberate, it is what holds
 * root open. Nothing here kills it, and neither should callers.
 */
export async function acquireRoot(
    adb: Adb,
    {
        profile,
        onLine,
        attempts = 3,
        timeoutMs = 300_000,
        pollMs = 3_000,
    }: RootOptions,
): Promise<boolean> {
    if (await isRoot(adb)) {
        onLine?.("shell is already root, skipping ionstack");
        return true;
    }

    for (let attempt = 1; attempt <= attempts; attempt++) {
        onLine?.(`--- ionstack attempt ${attempt}/${attempts} (${profile.label}) ---`);

        const pid = await startIonstack(adb, profile);
        onLine?.(
            pid
                ? `ionstack running detached as pid ${pid}; watching ${IONSTACK_LOG}`
                : `ionstack running detached; watching ${IONSTACK_LOG}`,
        );

        const tail = new LogTail(adb, IONSTACK_LOG, onLine);
        const deadline = Date.now() + timeoutMs;
        let rooted = false;
        let exited = false;
        let timedOut = false;

        // The process is expected to outlive the wait, so root — not the
        // process ending — is what we watch for.
        for (;;) {
            await tail.drain();

            if (await isRoot(adb)) {
                rooted = true;
                break;
            }
            if (pid && !(await isAlive(adb, pid))) {
                exited = true;
                break;
            }
            if (Date.now() >= deadline) {
                timedOut = true;
                break;
            }
            await sleep(pollMs);
        }

        // Whatever it printed on the way out.
        await tail.drain();
        tail.flush();

        if (exited) {
            // It died, but it may have won the race on its last breath.
            rooted = await isRoot(adb);
        }

        if (rooted) {
            onLine?.("new shell is uid 0 — root acquired");
            if (pid && (await isAlive(adb, pid))) {
                onLine?.(
                    `leaving ionstack (pid ${pid}) running — it holds the primitive and ` +
                        "killing it would crash the headset. A reboot clears it.",
                );
            }
            return true;
        }

        onLine?.(
            exited
                ? "ionstack exited without producing a root shell"
                : timedOut
                  ? `no root shell after ${Math.round(timeoutMs / 1000)}s — writing this attempt off`
                  : "new shell is still unprivileged",
        );
        await stopIonstack(adb, pid);
    }

    return false;
}
