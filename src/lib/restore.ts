/**
 * Standalone recovery path: connect a headset, get root, write a stored backup
 * back over its slot.
 *
 * This deliberately shares nothing with the unlock flow's step machine. If the
 * downgrade went wrong you want the shortest possible path from "headset
 * plugged in" to "partitions restored" — root, then write, nothing else.
 */

import type { Adb } from "@yume-chan/adb";

import { type DeviceProfile, profileFor } from "../data/profiles.js";
import { expectedHash } from "./assets.js";
import { identify, sha256, shell } from "./device.js";
import {
    type AnyPartition,
    findByNameDir,
    restorePartition,
} from "./partitions.js";
import { acquireRoot, isRoot, pushIonstack } from "./root.js";
import { BackupSet, type BackupSetMeta } from "./storage.js";

export interface RestoreEvents {
    onLog(line: string, kind?: "info" | "warn" | "error" | "good"): void;
    onProgress(label: string, transferred: number, total: number): void;
}

/**
 * Splits `abl_b.img` into its partition name and slot suffix.
 *
 * Any partition name is accepted, not just the Quest 1 set, because imported
 * backups cover whatever the device happened to expose.
 */
export function parseEntryName(
    name: string,
): { partition: AnyPartition; slotSuffix: string } | undefined {
    const match = /^(.+?)(_a|_b)\.img$/.exec(name);
    if (!match) return undefined;
    return { partition: match[1]!, slotSuffix: match[2]! };
}

export interface RestorePlan {
    readonly set: BackupSet;
    readonly meta: BackupSetMeta;
    readonly items: { partition: AnyPartition; slotSuffix: string; size: number }[];
    /** Which ionstack build to root this device with. */
    readonly profile: DeviceProfile;
    readonly totalBytes: number;
    /** True when this headset is the one the backup came from. */
    readonly serialMatches: boolean;
    readonly connectedSerial: string;
}

/** Reads a stored set and works out what restoring it would do. */
export async function planRestore(adb: Adb, id: string): Promise<RestorePlan> {
    const set = await BackupSet.load(id);
    const meta = set.meta;

    const identity = await identify(adb);
    const profile = profileFor(identity.device);
    if (!profile) {
        throw new Error(
            `no ionstack build is known for "${identity.device}", so this device cannot ` +
                "be rooted to perform the restore.",
        );
    }
    if (Object.keys(profile.ionstackEnv).length === 0 || !expectedHash(profile.ionstack)) {
        throw new Error(
            `this build has no working ionstack for the ${profile.label}, so it cannot be ` +
                "rooted and the backup cannot be written back.",
        );
    }
    // The gates guard the unlock flow; this path reaches ionstack on its own,
    // so it has to refuse a too-new build itself.
    if (
        profile.maxSupportedBuild !== undefined &&
        identity.incremental &&
        BigInt(identity.incremental) > BigInt(profile.maxSupportedBuild)
    ) {
        throw new Error(
            `this headset is on ${identity.incremental}, past the last build the exploit ` +
                `works on (${profile.maxSupportedBuild}). It cannot be rooted, so the ` +
                "backup cannot be written back from here.",
        );
    }

    const items: RestorePlan["items"] = [];
    for (const entry of meta.entries) {
        const parsed = parseEntryName(entry.name);
        if (!parsed) {
            throw new Error(`backup contains an unrecognised image: ${entry.name}`);
        }
        items.push({ ...parsed, size: entry.size });
    }
    if (items.length === 0) {
        throw new Error("this backup holds no images");
    }

    const slots = new Set(items.map((item) => item.slotSuffix));
    if (slots.size !== 1) {
        throw new Error(
            `this backup spans more than one slot (${[...slots].join(", ")}); refusing to guess`,
        );
    }

    return {
        set,
        meta,
        profile,
        items,
        totalBytes: items.reduce((sum, item) => sum + item.size, 0),
        serialMatches: meta.serial === adb.serial,
        connectedSerial: adb.serial,
    };
}

/**
 * Writes every image in the set back over its partition.
 *
 * Each image is hashed out of storage before it is written and the partition
 * is hashed after, so a restore that silently half-worked is not possible.
 */
export async function runRestore(
    adb: Adb,
    plan: RestorePlan,
    ionstack: Uint8Array,
    events: RestoreEvents,
): Promise<void> {
    const { set, items } = plan;

    events.onLog(
        `restoring ${items.length} partitions to slot ${items[0]!.slotSuffix} on ${adb.serial}`,
        "warn",
    );
    if (!plan.serialMatches) {
        events.onLog(
            `WARNING: this backup was taken from ${plan.meta.serial}, but ${adb.serial} is connected`,
            "warn",
        );
    }

    if (!(await isRoot(adb))) {
        events.onLog(
            `pushing ionstack (${ionstack.length} bytes, sha256 ${await sha256(ionstack)})`,
        );
        await pushIonstack(adb, ionstack);
        const rooted = await acquireRoot(adb, {
            profile: plan.profile,
            onLine: (line) => events.onLog(line),
        });
        if (!rooted) {
            throw new Error(
                "ionstack did not produce a root shell, so nothing was written. " +
                    "Reboot the headset and try again.",
            );
        }
    }
    events.onLog("root shell confirmed", "good");

    // Resolve the by-name directory for *this* device rather than trusting
    // whatever a previous session left set.
    const dir = await findByNameDir(adb, plan.profile.byNameDirs);
    events.onLog(`by-name directory: ${dir}`);

    // Restore in the archive's flash order so the bootloader chain lands in a
    // consistent order, and skip nothing: a partial restore is the worst state.
    const flashOrder = plan.profile.partitions;
    const order = (name: AnyPartition) => {
        const index = flashOrder.indexOf(name);
        return index < 0 ? flashOrder.length : index;
    };
    const ordered = [...items].sort((a, b) => order(a.partition) - order(b.partition));

    let done = 0;
    for (const item of ordered) {
        const { expected, actual } = await restorePartition(
            adb,
            set,
            item.partition,
            item.slotSuffix,
            (p) =>
                events.onProgress(
                    `${p.phase} ${p.partition}${item.slotSuffix} (${done + 1}/${ordered.length})`,
                    p.transferred,
                    p.total,
                ),
        );
        if (expected !== actual) {
            throw new Error(
                `${item.partition}${item.slotSuffix} did not restore cleanly: ` +
                    `wrote ${expected}, read back ${actual}. Do not reboot; retry the restore.`,
            );
        }
        done++;
        events.onLog(`  ${item.partition}${item.slotSuffix}  restored ${actual}`, "good");
    }

    await shell(adb, "sync");
    events.onLog(
        `all ${ordered.length} partitions restored and verified on slot ${ordered[0]!.slotSuffix}`,
        "good",
    );
}
