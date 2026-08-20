/**
 * Root via ionstack.
 *
 * ionstack elevates any *new* adb shell to root, so the sequence is: push the
 * binary, run it once, then open a fresh shell and check `id`. The host
 * process itself does not stay root (IONSTACK_SELF_ROOT=0) and we run no
 * payload list — every privileged step afterwards is an ordinary adb shell
 * command.
 */

import type { Adb } from "@yume-chan/adb";
import type { ReadableStream } from "@yume-chan/stream-extra";
import { TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";

import type { DeviceProfile } from "../data/profiles.js";
import { WORKDIR, push, shell } from "./device.js";

export const IONSTACK_PATH = `${WORKDIR}/ionstack`;

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

export interface RootOptions {
    /** Kernel-specific tuning; comes from the device profile. */
    profile: DeviceProfile;
    /** Called with each line ionstack prints. */
    onLine?: (line: string) => void;
    /** How many times to retry the whole exploit before giving up. */
    attempts?: number;
}

/**
 * Runs ionstack and reports whether a new shell comes back rooted.
 *
 * The exploit is racy by nature, so a failed attempt is expected occasionally
 * and simply retried. Output is streamed line by line because a run takes
 * a while and silence is indistinguishable from a hang.
 */
export async function acquireRoot(
    adb: Adb,
    { profile, onLine, attempts = 3 }: RootOptions,
): Promise<boolean> {
    if (await isRoot(adb)) {
        onLine?.("shell is already root, skipping ionstack");
        return true;
    }

    for (let attempt = 1; attempt <= attempts; attempt++) {
        onLine?.(`--- ionstack attempt ${attempt}/${attempts} (${profile.label}) ---`);

        const command = `cd ${WORKDIR} && ${envPrefix(profile.ionstackEnv)} ${IONSTACK_PATH} 2>&1`;
        const spawner = adb.subprocess.shellProtocol ?? adb.subprocess.noneProtocol;
        const process = await spawner.spawn(command);
        const output: ReadableStream<Uint8Array> =
            "stdout" in process ? process.stdout : process.output;

        let pending = "";
        await output.pipeThrough(new TextDecoderStream()).pipeTo(
            new WritableStream<string>({
                write(chunk) {
                    pending += chunk;
                    const lines = pending.split("\n");
                    pending = lines.pop() ?? "";
                    for (const line of lines) {
                        // ionstack colours its output; strip the escapes.
                        onLine?.(line.replace(/\[[0-9;]*m/g, "").trimEnd());
                    }
                },
                close() {
                    if (pending) {
                        onLine?.(pending.replace(/\[[0-9;]*m/g, "").trimEnd());
                    }
                },
            }),
        );
        await process.exited;

        if (await isRoot(adb)) {
            onLine?.("new shell is uid 0 — root acquired");
            return true;
        }
        onLine?.("new shell is still unprivileged");
    }

    return false;
}
