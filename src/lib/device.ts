/** Shell, property and file-transfer helpers on top of an authenticated `Adb`. */

import type { Adb } from "@yume-chan/adb";
import {
    ConcatStringStream,
    ReadableStream,
    TextDecoderStream,
} from "@yume-chan/stream-extra";

import versions from "../data/versions.json";
import {
    PROFILES,
    isSupported,
    missingPieces,
    profileFor,
} from "../data/profiles.js";

export interface Build {
    readonly incremental: string;
    readonly version: string;
    readonly buildDate: string;
    readonly fingerprint: string;
    readonly archive: string;
    readonly sha256: string;
}

export const BUILDS = versions.builds as readonly Build[];
/** Quest 1 build index; the downgrade target itself lives on the profile. */

/** Working directory for everything we push. */
export const WORKDIR = "/data/local/tmp/q1u";

export interface ShellResult {
    readonly stdout: string;
    readonly stderr: string;
    readonly exitCode: number;
}

/**
 * Runs a command and returns stdout/stderr/exit code.
 *
 * Prefers the shell protocol so the exit code is real; on the none protocol
 * everything arrives on one stream and the exit code is reported as 0, so
 * callers that need to detect failure should check the output instead.
 */
export async function shell(adb: Adb, command: string): Promise<ShellResult> {
    const shellProtocol = adb.subprocess.shellProtocol;
    if (shellProtocol) {
        const result = await shellProtocol.spawnWaitText(command);
        return {
            stdout: result.stdout.trim(),
            stderr: result.stderr.trim(),
            exitCode: result.exitCode,
        };
    }

    const process = await adb.subprocess.noneProtocol.spawn(command);
    const output = await process.output
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(new ConcatStringStream());
    return { stdout: output.trim(), stderr: "", exitCode: 0 };
}

/**
 * Like {@link shell}, but hands back stdout byte-for-byte.
 *
 * {@link shell} trims, which is wrong when the output is a slice of a file and
 * the trailing newline decides where a line ends.
 */
export async function shellRaw(adb: Adb, command: string): Promise<string> {
    const shellProtocol = adb.subprocess.shellProtocol;
    if (shellProtocol) {
        const result = await shellProtocol.spawnWaitText(command);
        return result.stdout;
    }

    const process = await adb.subprocess.noneProtocol.spawn(command);
    return await process.output
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(new ConcatStringStream());
}

/** Runs a command and throws unless it exits 0. */
export async function shellOk(adb: Adb, command: string): Promise<string> {
    const { stdout, stderr, exitCode } = await shell(adb, command);
    if (exitCode !== 0) {
        throw new Error(
            `command failed (exit ${exitCode}): ${command}\n${stderr || stdout}`,
        );
    }
    return stdout;
}

export async function getProp(adb: Adb, key: string): Promise<string> {
    const { stdout } = await shell(adb, `getprop ${key}`);
    return stdout;
}

export async function getProps(
    adb: Adb,
    keys: readonly string[],
): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const key of keys) {
        out[key] = await getProp(adb, key);
    }
    return out;
}

export interface DeviceIdentity {
    readonly fingerprint: string;
    readonly incremental: string;
    readonly model: string;
    readonly device: string;
    readonly release: string;
    readonly slotSuffix: string;
    /** The archive entry matching `incremental`, when the build is known. */
    readonly build: Build | undefined;
}

export async function identify(adb: Adb): Promise<DeviceIdentity> {
    const props = await getProps(adb, [
        "ro.build.fingerprint",
        "ro.build.version.incremental",
        "ro.product.model",
        "ro.product.device",
        "ro.build.version.release",
        "ro.boot.slot_suffix",
    ]);

    const incremental = props["ro.build.version.incremental"]!;
    return {
        fingerprint: props["ro.build.fingerprint"]!,
        incremental,
        model: props["ro.product.model"]!,
        device: props["ro.product.device"]!,
        release: props["ro.build.version.release"]!,
        slotSuffix: props["ro.boot.slot_suffix"]!,
        build: BUILDS.find((b) => b.incremental === incremental),
    };
}

export type GateStatus = "ok" | "warn" | "abort";

export interface Gate {
    readonly status: GateStatus;
    readonly title: string;
    readonly detail: string;
}

/**
 * Decides whether this device may proceed.
 *
 * Aborts on hardware no profile matches, on a device whose profile is not
 * finished, and on one already at or below its downgrade target. Warns — but
 * allows an explicit override — when the build is not one the root exploit has
 * been confirmed on.
 */
export function evaluateGates(identity: DeviceIdentity): Gate[] {
    const gates: Gate[] = [];

    const profile = profileFor(identity.device);
    if (!profile) {
        gates.push({
            status: "abort",
            title: "Unsupported device",
            detail:
                `This device reports "${identity.device || "unknown"}" ` +
                `(${identity.model || "unknown model"}). Supported: ` +
                `${PROFILES.map((p) => `${p.label} (${p.codenames[0]})`).join(", ")}. ` +
                "The downgrade images and the bootloader patch are specific to each " +
                "one and would brick other hardware.",
        });
        return gates;
    }

    gates.push({
        status: "ok",
        title: `Device is a ${profile.label}`,
        detail: `${identity.model} (${identity.device}), Android ${identity.release}`,
    });

    if (!isSupported(profile)) {
        gates.push({
            status: "abort",
            title: `${profile.label} is not supported yet`,
            detail:
                `Recognised, but ${missingPieces(profile).join(" and ")} is still ` +
                "missing. Downgrading a device this tool cannot then unlock would " +
                "leave it worse off, so it stops here.",
        });
        return gates;
    }

    // The build index covers the Quest 1 only. Everything after it works off
    // the incremental alone, so the rest of the gates still apply to any
    // device — they just cannot name the build.
    if (identity.build) {
        gates.push({
            status: "ok",
            title: `Build ${identity.build.version}`,
            detail: `${identity.incremental}, built ${identity.build.buildDate}`,
        });
    } else if (profile.id === "quest1") {
        gates.push({
            status: "warn",
            title: "Build not in the firmware archive",
            detail:
                `${identity.incremental} is not one of the ${BUILDS.length} known Quest 1 ` +
                "builds, so its position in the release order cannot be checked.",
        });
    } else {
        // No build index for this device, which is not something the user can
        // act on: the checks that matter — the comparison against the
        // downgrade target below, and the bootloader's own build number at
        // unlock time — do not need one. Report the build rather than warn.
        gates.push({
            status: "ok",
            title: `Build ${identity.incremental}`,
            detail: `Android ${identity.release}, ${identity.fingerprint}`,
        });
    }

    // A build past the profile's ceiling is refused before anything else is
    // considered: the exploit does not work there, and the steps that follow
    // all assume it will.
    if (profile.maxSupportedBuild !== undefined && identity.incremental) {
        const ceiling = BigInt(profile.maxSupportedBuild);
        if (BigInt(identity.incremental) > ceiling) {
            gates.push({
                status: "abort",
                title: "Build is too new for the root exploit",
                detail:
                    `This headset is on ${identity.incremental}. The exploit works up to ` +
                    `${profile.maxSupportedBuild} and no further — it was fixed after ` +
                    "that, so there is no way in on this build. Nothing here will run.",
            });
            return gates;
        }
    }

    // Verified against the archive: numeric order of `incremental` matches
    // build-date order for every known Quest 1 build.
    const current = BigInt(identity.incremental || "0");
    const target = BigInt(profile.downgradeTarget);
    const targetBuild = BUILDS.find((b) => b.incremental === profile.downgradeTarget);

    if (current <= target) {
        gates.push({
            status: "abort",
            title: "Already downgraded",
            detail:
                `This device is on ${identity.incremental}` +
                (current === target
                    ? " — exactly the build this tool downgrades to."
                    : `, which is older than the downgrade target ${profile.downgradeTarget}.`) +
                " There is nothing to downgrade; go straight to the fastboot unlock.",
        });
        return gates;
    }

    gates.push({
        status: "ok",
        title: "Newer than the downgrade target",
        detail:
            "Will downgrade the inactive slot to " +
            (targetBuild ? `${targetBuild.version} (${profile.downgradeTarget}).` : `${profile.downgradeTarget}.`),
    });

    if (profile.rootSupported.includes(identity.incremental)) {
        gates.push({
            status: "ok",
            title: "Root exploit confirmed on this build",
            detail: `ionstack has been tested against ${identity.incremental}.`,
        });
    } else {
        gates.push({
            status: "warn",
            title: "Root exploit untested on this build",
            detail:
                (profile.rootSupported.length > 0
                    ? `ionstack is only confirmed on ${profile.rootSupported.join(", ")}. `
                    : `No ${profile.label} build has been confirmed yet. `) +
                "It may simply fail to get root on this build, which is harmless, but it " +
                "may also panic the kernel and reboot the headset.",
        });
    }

    return gates;
}

export function worstStatus(gates: readonly Gate[]): GateStatus {
    if (gates.some((g) => g.status === "abort")) return "abort";
    if (gates.some((g) => g.status === "warn")) return "warn";
    return "ok";
}

/** `_a` -> `_b`, `_b` -> `_a`. */
export function otherSlot(slotSuffix: string): string {
    if (slotSuffix === "_a") return "_b";
    if (slotSuffix === "_b") return "_a";
    throw new Error(`unexpected slot suffix ${JSON.stringify(slotSuffix)}`);
}

export interface ProgressReport {
    readonly transferred: number;
    readonly total: number;
}

export type ProgressCallback = (report: ProgressReport) => void;

/** Pushes bytes to a path on the device. */
export async function push(
    adb: Adb,
    data: Uint8Array,
    filename: string,
    permission = 0o755,
    onProgress?: ProgressCallback,
): Promise<void> {
    const sync = await adb.sync();
    try {
        const chunkSize = 256 * 1024;
        let offset = 0;
        const file = new ReadableStream<Uint8Array>({
            pull(controller) {
                if (offset >= data.length) {
                    controller.close();
                    return;
                }
                const end = Math.min(offset + chunkSize, data.length);
                controller.enqueue(data.subarray(offset, end));
                offset = end;
                onProgress?.({ transferred: offset, total: data.length });
            },
        });
        await sync.write({ filename, file, permission });
    } finally {
        await sync.dispose();
    }
}

/** Reads a file off the device into memory. */
export async function pull(
    adb: Adb,
    filename: string,
    expectedSize?: number,
    onProgress?: ProgressCallback,
): Promise<Uint8Array> {
    const sync = await adb.sync();
    try {
        const chunks: Uint8Array[] = [];
        let total = 0;
        const reader = sync.read(filename).getReader();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            total += value.length;
            onProgress?.({ transferred: total, total: expectedSize ?? total });
        }

        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
            out.set(chunk, offset);
            offset += chunk.length;
        }
        return out;
    } finally {
        await sync.dispose();
    }
}

/** Streams a device file straight into a sink, so it never sits in memory twice. */
export async function pullTo(
    adb: Adb,
    filename: string,
    sink: WritableStream<Uint8Array>,
    expectedSize?: number,
    onProgress?: ProgressCallback,
): Promise<number> {
    const sync = await adb.sync();
    const writer = sink.getWriter();
    let total = 0;
    try {
        const reader = sync.read(filename).getReader();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            await writer.write(value);
            total += value.length;
            onProgress?.({ transferred: total, total: expectedSize ?? total });
        }
        await writer.close();
        return total;
    } catch (error) {
        await writer.abort(error).catch(() => undefined);
        throw error;
    } finally {
        writer.releaseLock();
        await sync.dispose();
    }
}

/**
 * Narrows a view to one backed by a plain ArrayBuffer.
 *
 * WebUSB and the file-system API both want `ArrayBuffer`-backed views, while
 * everything upstream of here is typed as the wider `ArrayBufferLike`.
 */
export function bufferSource(data: Uint8Array): Uint8Array<ArrayBuffer> {
    return data as Uint8Array<ArrayBuffer>;
}

/**
 * Free bytes on the filesystem holding `path`, or undefined if `df` output
 * cannot be parsed — callers decide what to do with "unknown" rather than
 * having it silently treated as zero or infinite.
 */
export async function freeSpace(adb: Adb, path: string): Promise<number | undefined> {
    // toybox df -k: Filesystem  1K-blocks  Used  Available  Use%  Mounted on
    const { stdout } = await shell(adb, `df -k ${path} 2>/dev/null | tail -n 1`);
    const available = Number.parseInt(stdout.trim().split(/\s+/)[3] ?? "", 10);
    return Number.isFinite(available) && available >= 0 ? available * 1024 : undefined;
}

export async function sha256(data: Uint8Array): Promise<string> {
    const buffer = data.buffer.slice(
        data.byteOffset,
        data.byteOffset + data.byteLength,
    ) as ArrayBuffer;
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
