/**
 * Backing up, flashing and verifying the A/B partitions we overwrite.
 *
 * Everything here needs root and runs as ordinary adb shell commands after
 * ionstack has elevated the shell.
 */

import type { Adb } from "@yume-chan/adb";

import {
    WORKDIR,
    bufferSource,
    type ProgressCallback,
    pullTo,
    push,
    sha256,
    shell,
    shellOk,
} from "./device.js";
import type { BackupSet } from "./storage.js";

/** Partition images carried in the downgrade archive, in flash order. */
export const PARTITIONS = [
    "xbl",
    "abl",
    "rpm",
    "tz",
    "hyp",
    "devcfg",
    "pmic",
    "cmnlib",
    "cmnlib64",
    "keymaster",
    "ovrtz",
    "modem",
    "boot",
] as const;

export type PartitionName = (typeof PARTITIONS)[number];

/** Imported backups may hold partitions outside the Quest 1 set. */
export type AnyPartition = PartitionName | (string & {});

/** Usual Quest 1 layout; confirmed at runtime by `findByNameDir`. */
export const BY_NAME = "/dev/block/bootdevice/by-name";
export const BACKUP_DIR = `${WORKDIR}/backup`;
export const IMAGE_DIR = `${WORKDIR}/img`;

/** Where by-name symlinks live on the connected device. Set once per session. */
let byNameDir: string = BY_NAME;

export function setByNameDir(path: string): void {
    byNameDir = path;
}

export function getByNameDir(): string {
    return byNameDir;
}

/**
 * Finds the by-name directory, trying the profile's candidates in order.
 *
 * The Quest 1 keeps them under `bootdevice`, but not every build does.
 * Guessing wrong means every later path is wrong, so this resolves it once and
 * loudly.
 */
export async function findByNameDir(
    adb: Adb,
    candidates: readonly string[],
): Promise<string> {
    for (const candidate of candidates) {
        const { stdout } = await shell(adb, `ls ${candidate} 2>/dev/null | head -n 1`);
        if (stdout.trim() !== "") {
            setByNameDir(candidate);
            return candidate;
        }
    }
    throw new Error(
        `none of these by-name directories exist or are readable: ${candidates.join(", ")}`,
    );
}

export function blockDevice(partition: string, slotSuffix: string): string {
    return `${byNameDir}/${partition}${slotSuffix}`;
}

/** Resolves the by-name symlink and reports the partition's size in bytes. */
export async function partitionSize(
    adb: Adb,
    partition: string,
    slotSuffix: string,
): Promise<number> {
    const device = blockDevice(partition, slotSuffix);
    const { stdout, exitCode } = await shell(
        adb,
        `blockdev --getsize64 ${device} 2>/dev/null || stat -c %s ${device}`,
    );
    const size = Number.parseInt(stdout.trim(), 10);
    if (exitCode !== 0 || !Number.isFinite(size) || size <= 0) {
        throw new Error(
            `cannot determine the size of ${device} — is the slot suffix right?`,
        );
    }
    return size;
}

/** Confirms every partition we intend to touch actually exists on that slot. */
export async function checkPartitions(
    adb: Adb,
    slotSuffix: string,
): Promise<Map<PartitionName, number>> {
    const sizes = new Map<PartitionName, number>();
    const missing: string[] = [];
    for (const partition of PARTITIONS) {
        try {
            sizes.set(partition, await partitionSize(adb, partition, slotSuffix));
        } catch {
            missing.push(`${partition}${slotSuffix}`);
        }
    }
    if (missing.length > 0) {
        throw new Error(
            `these partitions are missing on the target slot: ${missing.join(", ")}`,
        );
    }
    return sizes;
}

/** sha256 of a partition's first `length` bytes, computed on the device. */
export async function devicePartitionHash(
    adb: Adb,
    partition: string,
    slotSuffix: string,
    length: number,
): Promise<string> {
    const device = blockDevice(partition, slotSuffix);
    const out = await shellOk(adb, `head -c ${length} ${device} | sha256sum`);
    const hash = out.trim().split(/\s+/)[0] ?? "";
    if (!/^[0-9a-f]{64}$/.test(hash)) {
        throw new Error(`unexpected sha256sum output for ${device}: ${out}`);
    }
    return hash;
}

export interface BackupProgress {
    readonly partition: AnyPartition;
    readonly phase: "dump" | "pull";
    readonly transferred: number;
    readonly total: number;
}

/**
 * Dumps one partition to a file, streams it into OPFS, then drops the copy on
 * the device so /data does not fill up.
 */
/**
 * Name a partition image is stored under inside a backup set.
 *
 * The one definition of it: `expected`, the recorded entries, the verify and
 * restore lookups and the zip importer all have to agree, and they only do if
 * they all come from here.
 */
export function backupEntryName(
    partition: AnyPartition,
    slotSuffix: string,
): string {
    return `${partition}${slotSuffix}.img`;
}

export async function backupPartition(
    adb: Adb,
    set: BackupSet,
    partition: AnyPartition,
    slotSuffix: string,
    size: number,
    onProgress?: (progress: BackupProgress) => void,
): Promise<string> {
    const device = blockDevice(partition, slotSuffix);
    const onDevice = `${BACKUP_DIR}/${partition}${slotSuffix}.img`;
    const name = backupEntryName(partition, slotSuffix);

    onProgress?.({ partition, phase: "dump", transferred: 0, total: size });
    await shellOk(adb, `mkdir -p ${BACKUP_DIR}`);
    await shellOk(adb, `dd if=${device} of=${onDevice} bs=1048576`);
    await shellOk(adb, `chmod 644 ${onDevice}`);

    const deviceHash = await shellOk(adb, `sha256sum ${onDevice}`).then(
        (out) => out.trim().split(/\s+/)[0] ?? "",
    );

    // Stream straight into OPFS. Nothing is buffered here on purpose: the
    // browser-side hash comes from reading the stored file back, so a 32 MiB
    // partition is never held in memory twice.
    const writable = await set.open(name);
    const sink = new WritableStream<Uint8Array>({
        async write(chunk) {
            await writable.write(bufferSource(chunk));
        },
        async close() {
            await writable.close();
        },
        async abort(reason) {
            await writable.abort(reason);
        },
    });

    const pulled = await pullTo(adb, onDevice, sink, size, (p) =>
        onProgress?.({
            partition,
            phase: "pull",
            transferred: p.transferred,
            total: size,
        }),
    );

    if (pulled !== size) {
        throw new Error(
            `${name}: pulled ${pulled} bytes but the partition is ${size} bytes`,
        );
    }

    // Read the copy back out of storage and hash it, so what gets recorded is
    // the hash of what is actually stored — not of what we believe we sent.
    const stored = await set.read(name);
    const localHash = await sha256(stored);
    if (localHash !== deviceHash) {
        throw new Error(
            `${name}: backup is corrupt — device hashed ${deviceHash}, stored copy hashes ${localHash}`,
        );
    }

    await set.record({ name, size: pulled, sha256: localHash });
    await shell(adb, `rm -f ${onDevice}`);
    return localHash;
}

export interface FlashProgress {
    readonly partition: AnyPartition;
    readonly phase: "push" | "write" | "verify";
    readonly transferred: number;
    readonly total: number;
}

/**
 * Writes one image to the target slot and verifies the readback.
 *
 * The image is pushed to /data first rather than piped through `dd`'s stdin,
 * because a stalled shell stream mid-write to `xbl` or `abl` is exactly the
 * failure that leaves an unbootable slot.
 */
export async function flashPartition(
    adb: Adb,
    partition: AnyPartition,
    slotSuffix: string,
    image: Uint8Array,
    onProgress?: (progress: FlashProgress) => void,
): Promise<{ expected: string; actual: string }> {
    const device = blockDevice(partition, slotSuffix);
    const onDevice = `${IMAGE_DIR}/${partition}.img`;

    await shellOk(adb, `mkdir -p ${IMAGE_DIR}`);

    onProgress?.({ partition, phase: "push", transferred: 0, total: image.length });
    const onPush: ProgressCallback = (p) =>
        onProgress?.({
            partition,
            phase: "push",
            transferred: p.transferred,
            total: image.length,
        });
    await push(adb, image, onDevice, 0o644, onPush);

    const expected = await sha256(image);
    const pushedHash = await shellOk(adb, `sha256sum ${onDevice}`).then(
        (out) => out.trim().split(/\s+/)[0] ?? "",
    );
    if (pushedHash !== expected) {
        await shell(adb, `rm -f ${onDevice}`);
        throw new Error(
            `${partition}.img arrived corrupt (expected ${expected}, got ${pushedHash}) — nothing was written`,
        );
    }

    onProgress?.({
        partition,
        phase: "write",
        transferred: 0,
        total: image.length,
    });
    await shellOk(adb, `dd if=${onDevice} of=${device} bs=1048576`);
    await shellOk(adb, "sync");

    onProgress?.({
        partition,
        phase: "verify",
        transferred: 0,
        total: image.length,
    });
    const actual = await devicePartitionHash(adb, partition, slotSuffix, image.length);

    await shell(adb, `rm -f ${onDevice}`);
    return { expected, actual };
}

/**
 * Re-reads a stored backup and checks it against the partition it came from.
 *
 * This is deliberately a second, independent pass: the copy is read back out
 * of browser storage and re-hashed, and the live partition is hashed again on
 * the device. A backup that only ever got checked while it was being written
 * is not a backup you should bet the device on.
 */
export async function verifyBackup(
    adb: Adb,
    set: BackupSet,
    partition: AnyPartition,
    slotSuffix: string,
    onProgress?: (phase: "read" | "device") => void,
): Promise<{ stored: string; device: string; recorded: string }> {
    const name = backupEntryName(partition, slotSuffix);
    const entry = set.meta.entries.find((e) => e.name === name);
    if (!entry) {
        throw new Error(`no backup was recorded for ${name}`);
    }

    onProgress?.("read");
    const stored = await set.read(name);
    if (stored.length !== entry.size) {
        throw new Error(
            `${name}: stored copy is ${stored.length} bytes, expected ${entry.size}`,
        );
    }
    const storedHash = await sha256(stored);

    onProgress?.("device");
    const deviceHash = await devicePartitionHash(
        adb,
        partition,
        slotSuffix,
        entry.size,
    );

    return { stored: storedHash, device: deviceHash, recorded: entry.sha256 };
}

/** Writes a stored backup image back over its partition. */
export async function restorePartition(
    adb: Adb,
    set: BackupSet,
    partition: AnyPartition,
    slotSuffix: string,
    onProgress?: (progress: FlashProgress) => void,
): Promise<{ expected: string; actual: string }> {
    const name = backupEntryName(partition, slotSuffix);
    const entry = set.meta.entries.find((e) => e.name === name);
    if (!entry) {
        throw new Error(`no backup was recorded for ${name}`);
    }

    const image = await set.read(name);
    const hash = await sha256(image);
    if (hash !== entry.sha256) {
        throw new Error(
            `${name}: stored backup is corrupt (${hash}, expected ${entry.sha256}) — ` +
                "refusing to write it back",
        );
    }

    return flashPartition(adb, partition, slotSuffix, image, onProgress);
}

/** Removes everything this tool wrote to /data/local/tmp. */
export async function cleanup(adb: Adb): Promise<void> {
    await shell(adb, `rm -rf ${WORKDIR}`);
}
