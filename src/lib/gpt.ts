/**
 * Reads A/B slot state straight out of the GPT partition attributes.
 *
 * boot_control 1.0 has no `getActiveBootSlot`, and `getCurrentSlot` reports the
 * slot the device is running from — neither answers "which slot boots next".
 * Qualcomm's boot_control keeps that state in the GPT attribute bits of each
 * slot-suffixed partition, so reading the table gives the real answer.
 *
 * Bit layout is Qualcomm's `gpt-utils` convention:
 *
 *   48-49  priority
 *   50     active
 *   51-53  retry count remaining
 *   54     successful
 *   55     unbootable
 *
 * That layout is asserted, never assumed: `crossCheck` compares the decoded
 * successful/unbootable bits against what the HAL reports, and the active bit
 * is only trusted when they agree. A confidently wrong answer about which slot
 * boots next is worse than no answer.
 */

import type { Adb } from "@yume-chan/adb";

import { shell, shellOk } from "./device.js";

const SECTOR = 512;
const GPT_SIGNATURE = "EFI PART";

export interface GptSlotAttributes {
    readonly partition: string;
    readonly slotSuffix: string;
    readonly priority: number;
    readonly active: boolean;
    readonly retriesRemaining: number;
    readonly successful: boolean;
    readonly unbootable: boolean;
    readonly raw: bigint;
}

/** Resolves the whole-disk device that backs a by-name partition link. */
export async function findDisk(adb: Adb, byNamePath: string): Promise<string> {
    const resolved = await shellOk(adb, `readlink -f ${byNamePath}`);
    const partition = resolved.trim().split("/").pop() ?? "";
    if (partition === "") {
        throw new Error(`could not resolve ${byNamePath} to a block device`);
    }

    // /sys/class/block/<part> is a symlink into .../block/<disk>/<part>, so the
    // parent directory names the disk. More reliable than stripping digits,
    // which differs between sdX58 and mmcblk0p58.
    const sys = await shellOk(adb, `readlink -f /sys/class/block/${partition}`);
    const disk = sys.trim().split("/").slice(-2, -1)[0] ?? "";
    if (disk === "" || disk === "block") {
        throw new Error(`could not find the disk holding ${partition}`);
    }
    return `/dev/block/${disk}`;
}

async function readSectors(
    adb: Adb,
    disk: string,
    skip: number,
    count: number,
): Promise<Uint8Array> {
    const encoded = await shellOk(
        adb,
        `dd if=${disk} bs=${SECTOR} skip=${skip} count=${count} 2>/dev/null | base64`,
    );
    const binary = atob(encoded.replace(/\s+/g, ""));
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
    }
    if (out.length < count * SECTOR) {
        throw new Error(
            `short read from ${disk}: wanted ${count * SECTOR} bytes, got ${out.length}`,
        );
    }
    return out;
}

/** Decodes every slot-suffixed partition's attribute bits. */
export async function readSlotAttributes(
    adb: Adb,
    byNamePath: string,
): Promise<GptSlotAttributes[]> {
    const disk = await findDisk(adb, byNamePath);

    const header = await readSectors(adb, disk, 1, 1);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const signature = new TextDecoder("ascii").decode(header.subarray(0, 8));
    if (signature !== GPT_SIGNATURE) {
        throw new Error(`${disk} has no GPT header (found ${JSON.stringify(signature)})`);
    }

    const entriesLba = Number(view.getBigUint64(72, true));
    const entryCount = view.getUint32(80, true);
    const entrySize = view.getUint32(84, true);
    if (entrySize < 128 || entryCount === 0 || entryCount > 512) {
        throw new Error(
            `implausible GPT geometry on ${disk}: ${entryCount} entries of ${entrySize} bytes`,
        );
    }

    const bytes = entryCount * entrySize;
    const table = await readSectors(
        adb,
        disk,
        entriesLba,
        Math.ceil(bytes / SECTOR),
    );
    const tableView = new DataView(table.buffer, table.byteOffset, table.byteLength);

    const results: GptSlotAttributes[] = [];
    for (let i = 0; i < entryCount; i++) {
        const base = i * entrySize;

        // An all-zero type GUID marks an unused entry.
        let used = false;
        for (let b = 0; b < 16; b++) {
            if (table[base + b] !== 0) {
                used = true;
                break;
            }
        }
        if (!used) continue;

        const name = new TextDecoder("utf-16le")
            .decode(table.subarray(base + 56, base + 128))
            .replace(/\0.*$/, "");
        const match = /^(.*)(_a|_b)$/.exec(name);
        if (!match) continue;

        const raw = tableView.getBigUint64(base + 48, true);
        results.push({
            partition: match[1]!,
            slotSuffix: match[2]!,
            priority: Number((raw >> 48n) & 0x3n),
            active: ((raw >> 50n) & 1n) === 1n,
            retriesRemaining: Number((raw >> 51n) & 0x7n),
            successful: ((raw >> 54n) & 1n) === 1n,
            unbootable: ((raw >> 55n) & 1n) === 1n,
            raw,
        });
    }

    if (results.length === 0) {
        throw new Error(`no slot-suffixed partitions found in the GPT on ${disk}`);
    }
    return results;
}

export interface SlotVerdict {
    /** Slot index whose partitions carry the active bit, if exactly one does. */
    readonly activeSlot: number | undefined;
    /** True when the decoded bits agree with what the HAL reports. */
    readonly trusted: boolean;
    readonly reason: string;
    readonly perSlot: {
        readonly slot: number;
        readonly suffix: string;
        readonly priority: number;
        readonly active: boolean;
        readonly retriesRemaining: number;
        readonly successful: boolean;
        readonly unbootable: boolean;
    }[];
}

/**
 * Summarises the GPT view and checks it against the HAL before trusting it.
 *
 * `halFlags` comes from `bootctl_shim info`. If the decoded successful and
 * unbootable bits do not match it, the attribute layout is not the one assumed
 * here and the active bit is reported as unknown rather than guessed.
 */
export function summariseSlots(
    attributes: readonly GptSlotAttributes[],
    halFlags: readonly { index: number; bootable: boolean; successful: boolean }[],
    reference = "boot",
): SlotVerdict {
    // Prefer one well-known partition; boot_control keys off a single one and
    // the rest of a slot normally carries identical bits.
    const chosen = attributes.filter((entry) => entry.partition === reference);
    const rows = chosen.length > 0 ? chosen : attributes;

    const perSlot = ["_a", "_b"].flatMap((suffix, slot) => {
        const entry = rows.find((row) => row.slotSuffix === suffix);
        return entry
            ? [
                  {
                      slot,
                      suffix,
                      priority: entry.priority,
                      active: entry.active,
                      retriesRemaining: entry.retriesRemaining,
                      successful: entry.successful,
                      unbootable: entry.unbootable,
                  },
              ]
            : [];
    });

    const mismatches: string[] = [];
    for (const row of perSlot) {
        const hal = halFlags.find((flag) => flag.index === row.slot);
        if (!hal) continue;
        if (hal.successful !== row.successful) {
            mismatches.push(
                `slot ${row.suffix}: HAL says successful=${hal.successful}, GPT bit says ${row.successful}`,
            );
        }
        if (hal.bootable === row.unbootable) {
            mismatches.push(
                `slot ${row.suffix}: HAL says bootable=${hal.bootable}, GPT unbootable bit says ${row.unbootable}`,
            );
        }
    }

    if (mismatches.length > 0) {
        return {
            activeSlot: undefined,
            trusted: false,
            reason:
                "the GPT attribute bits do not line up with the boot_control HAL, so this " +
                `device does not use the assumed layout: ${mismatches.join("; ")}`,
            perSlot,
        };
    }

    const active = perSlot.filter((row) => row.active);
    if (active.length !== 1) {
        return {
            activeSlot: undefined,
            trusted: false,
            reason:
                active.length === 0
                    ? "no slot carries the active bit"
                    : `${active.length} slots carry the active bit at once`,
            perSlot,
        };
    }

    return {
        activeSlot: active[0]!.slot,
        trusted: true,
        reason: "GPT attributes agree with the boot_control HAL",
        perSlot,
    };
}

/** Convenience: read and summarise in one call, tolerating failure. */
export async function readSlotVerdict(
    adb: Adb,
    byNameDir: string,
    halFlags: readonly { index: number; bootable: boolean; successful: boolean }[],
): Promise<SlotVerdict | undefined> {
    try {
        const { stdout } = await shell(adb, `ls ${byNameDir}/boot_a 2>/dev/null`);
        const reference = stdout.trim() !== "" ? "boot" : "";
        const attributes = await readSlotAttributes(adb, `${byNameDir}/boot_a`);
        return summariseSlots(attributes, halFlags, reference || "boot");
    } catch {
        // Reading the GPT is a cross-check, not a requirement.
        return undefined;
    }
}
