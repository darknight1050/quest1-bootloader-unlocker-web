/**
 * Slot control through `bootctl_shim`, which dlopens the vendor boot_control
 * HAL directly. The Quest 1 has no `bootctl` binary and no HIDL service we can
 * reach from a shell, so the shim is how the active slot gets changed.
 */

import type { Adb } from "@yume-chan/adb";

import { WORKDIR, push, shell, shellOk } from "./device.js";

export const BOOTCTL_PATH = `${WORKDIR}/bootctl_shim`;

export interface SlotInfo {
    readonly numberSlots: number;
    readonly currentSlot: number;
    readonly slots: {
        readonly index: number;
        readonly suffix: string;
        readonly bootable: boolean;
        readonly successful: boolean;
    }[];
    readonly module: string;
    readonly raw: string;
}

export async function pushBootctl(adb: Adb, binary: Uint8Array): Promise<void> {
    await shell(adb, `mkdir -p ${WORKDIR}`);
    await push(adb, binary, BOOTCTL_PATH, 0o755);
    await shell(adb, `chmod 755 ${BOOTCTL_PATH}`);
}

/** Parses the shim's `info` output. */
export async function readSlotInfo(adb: Adb): Promise<SlotInfo> {
    const raw = await shellOk(adb, `${BOOTCTL_PATH} info`);

    const field = (name: string) =>
        raw.match(new RegExp(`^${name}\\s*:\\s*(.+)$`, "m"))?.[1]?.trim() ?? "";

    const slots: SlotInfo["slots"] = [];
    const slotLine = /^\s*slot (\d+) \(([^)]*)\) bootable=(-?\d+) successful=(-?\d+)/gm;
    for (let match = slotLine.exec(raw); match; match = slotLine.exec(raw)) {
        slots.push({
            index: Number(match[1]),
            suffix: match[2]!,
            bootable: match[3] === "1",
            successful: match[4] === "1",
        });
    }

    const numberSlots = Number.parseInt(field("slots"), 10);
    const currentSlot = Number.parseInt(field("current"), 10);
    if (!Number.isFinite(numberSlots) || !Number.isFinite(currentSlot)) {
        throw new Error(`could not parse bootctl_shim info output:\n${raw}`);
    }

    return { numberSlots, currentSlot, slots, module: field("module"), raw };
}

export async function getCurrentSlot(adb: Adb): Promise<number> {
    const out = await shellOk(adb, `${BOOTCTL_PATH} get-current-slot`);
    const slot = Number.parseInt(out.trim(), 10);
    if (slot !== 0 && slot !== 1) {
        throw new Error(`bootctl_shim reported an unusable current slot: ${out}`);
    }
    return slot;
}

export interface SetActiveResult {
    readonly before: SlotInfo;
    readonly after: SlotInfo;
    /** True if the slot came back marked bootable but not yet successful. */
    readonly pendingFirstBoot: boolean;
}

/**
 * Makes `slot` the one the device boots next.
 *
 * Note what this does *not* verify. `getCurrentSlot()` reports the slot the
 * device is running from, not the one it will boot next, and boot_control 1.0
 * has no `getActiveBootSlot` — so until the device reboots there is no direct
 * way to read back "which slot is active". Checking `getCurrentSlot()` here
 * would compare against the slot we are still booted on and always fail.
 *
 * What we can check are the per-slot flags, which is also where the A/B
 * contract shows itself: `setActiveBootSlot` raises the slot's priority, sets
 * its retry counter, and deliberately marks it **not successful**. The
 * bootloader spends one retry per boot attempt and falls back to the other slot
 * when they run out; `markBootSuccessful()` — normally called by
 * `update_verifier` once Android is up — is what clears that state.
 *
 * So "bootable, not yet successful" is the expected, healthy result here, and a
 * slot that came back already-successful means the call did not take.
 */
export async function setActiveSlot(
    adb: Adb,
    slot: number,
): Promise<SetActiveResult> {
    const before = await readSlotInfo(adb);

    const { stdout, stderr, exitCode } = await shell(
        adb,
        `${BOOTCTL_PATH} set-active-boot-slot ${slot}`,
    );
    if (exitCode !== 0) {
        throw new Error(
            `bootctl_shim set-active-boot-slot ${slot} failed: ${stderr || stdout}`,
        );
    }

    const after = await readSlotInfo(adb);
    const target = after.slots.find((entry) => entry.index === slot);
    if (!target) {
        throw new Error(
            `bootctl_shim reported no slot ${slot} after set-active-boot-slot`,
        );
    }

    if (!target.bootable) {
        throw new Error(
            `slot ${slot} is still marked unbootable after set-active-boot-slot. ` +
                "The device would not boot it; stopping before the reboot.",
        );
    }

    const previous = before.slots.find((entry) => entry.index === slot);
    if (target.successful && previous?.successful) {
        throw new Error(
            `slot ${slot} is still marked successful and nothing about it changed, so ` +
                "set-active-boot-slot appears not to have taken effect. Refusing to " +
                "reboot on the assumption that it did.",
        );
    }

    return { before, after, pendingFirstBoot: target.bootable && !target.successful };
}

export const slotSuffix = (slot: number): string => (slot === 0 ? "_a" : "_b");
export const slotLetter = (slot: number): "a" | "b" => (slot === 0 ? "a" : "b");
export const slotFromSuffix = (suffix: string): number => (suffix === "_a" ? 0 : 1);
