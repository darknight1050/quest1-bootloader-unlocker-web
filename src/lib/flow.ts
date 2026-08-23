/**
 * The unlock procedure, as an ordered list of steps the UI drives.
 *
 * Steps run one at a time and never skip ahead. Anything destructive or
 * irreversible is marked `confirm`, so the UI stops and makes the user say yes
 * before it happens.
 */

import { Adb } from "@yume-chan/adb";
import { unzip } from "fflate";

import {
    type AblPatch,
    applyPatch,
    buildUnlockPayload,
    extractLinuxLoaderPe,
    unlockPatch,
} from "./abl.js";
import { fetchAsset, isSecureOrigin } from "./assets.js";
import {
    getCurrentSlot,
    pushBootctl,
    readSlotInfo,
    setActiveSlot,
    slotLetter,
    slotSuffix,
} from "./bootctl.js";
import {
    DEVICE,
    DOWNGRADE_TARGET,
    WORKDIR,
    type DeviceIdentity,
    type Gate,
    evaluateGates,
    freeSpace,
    identify,
    sha256,
    shell,
    worstStatus,
} from "./device.js";
import {
    FastbootDevice,
    isLinkLost,
    performUnlock,
    readUnlockState,
    rebootToBootloader,
    waitForBootloader,
    resetRollbackIndexes,
    type UnlockState,
} from "./fastboot.js";
import {
    PARTITIONS,
    type PartitionName,
    backupEntryName,
    backupPartition,
    checkPartitions,
    cleanup,
    findByNameDir,
    flashPartition,
    getByNameDir,
    restorePartition,
    verifyBackup,
} from "./partitions.js";
import { type DeviceProfile, QUEST1 } from "../data/profiles.js";
import { readSlotVerdict } from "./gpt.js";
import { acquireRoot, isRoot, pushIonstack } from "./root.js";
import { BackupSet, estimateQuota, requestPersistence } from "./storage.js";

export const ASSETS = {
    firmware: "/binaries/16476800119700000.zip",
    bootctl: "/binaries/bootctl_shim",
} as const;

/**
 * The exact `abl.img` the bootloader patch was derived from.
 *
 * The archive as a whole is verified on fetch, but this pins the one file the
 * exploit is built out of, so a repacked archive cannot slip a different
 * bootloader past the patch-site check.
 */
export const EXPECTED_ABL_SHA256 =
    "c2cc1f173bec2956fa5e068abc98db82e1cd2c651a4f4bb7ae31c79605e43707";

/**
 * sha256 of the extracted LinuxLoader image, before patching.
 *
 * Checked against the whole image rather than a prefix: with patches able to
 * touch several sites, "everything before the first edit" stops being a
 * meaningful thing to hash.
 */
export const EXPECTED_PE_SHA256 =
    "7663280938b54f8dc061b502f581cba4bea638473080c44a8dcfec88a570f74c";

export type StepState = "pending" | "running" | "done" | "failed" | "blocked";

export interface StepProgress {
    readonly label: string;
    readonly transferred: number;
    readonly total: number;
}

/**
 * A gate the user has to type their way through.
 *
 * `phrase` is always derived from this device's actual state — the real target
 * slot, the real build number — so it cannot be guessed by someone clicking
 * past the dialog without reading it.
 */
export interface Confirmation {
    readonly heading: string;
    readonly body: string[];
    readonly phrase: string;
    /** Offer to roll the target slot back to the backup from this dialog. */
    readonly offerRevert?: boolean;
}

export interface Step {
    readonly id: string;
    readonly title: string;
    readonly detail: string;
    /** Built when the step is reached, because the phrase depends on device state. */
    confirm?: Confirmation;
    state: StepState;
    error?: string;
    progress?: StepProgress;
}

export interface FlowEvents {
    onLog(line: string, kind?: "info" | "warn" | "error" | "good"): void;
    onChange(): void;
}


/** The real procedure. */
function unlockSteps(): Step[] {
    return [
        {
            id: "identify",
            title: "Identify the device",
            detail: "Read the fingerprint and check this is a supported Quest 1.",
            state: "pending",
        },
        {
            id: "assets",
            title: "Load firmware and tools",
            detail: `Unpack ${DOWNGRADE_TARGET}.zip and build the bootloader patch.`,
            state: "pending",
        },
        {
            id: "slots",
            title: "Read the boot slots",
            detail: "Determine the active slot and the one we will downgrade.",
            state: "pending",
        },
        {
            id: "root",
            title: "Get root",
            detail: "Run ionstack, then confirm a new shell comes back as uid 0.",
            state: "pending",
        },
        {
            id: "backup",
            title: "Back up the target slot",
            detail:
                "Copy all 13 partitions into browser storage, then read every image " +
                "back out and re-hash it against the live partition.",
            state: "pending",
        },
        {
            id: "flash",
            title: "Downgrade the inactive slot",
            detail: "Write the 13 images and verify every partition by hash.",
            state: "pending",
        },
        {
            id: "activate",
            title: "Switch the active slot",
            detail: "Point bootctl at the downgraded slot so it boots next.",
            state: "pending",
        },
        {
            id: "bootloader",
            title: "Reboot into fastboot",
            detail: "Restart the headset into its bootloader.",
            state: "pending",
        },
        {
            id: "unlock",
            title: "Unlock the bootloader",
            detail: "Verify the build number, then send the overflow payload.",
            state: "pending",
        },
        {
            id: "restore-slot",
            title: "Restore the original slot",
            detail:
                "Set the original slot active again, then restart the bootloader and " +
                "read the switch back.",
            state: "pending",
        },
        {
            id: "factory-reset",
            title: "Factory reset",
            detail: "Erase userdata so the downgraded slot comes up clean.",
            state: "pending",
        },
        {
            id: "boot-os",
            title: "Boot into the OS",
            detail: "Leave fastboot and let Android mark the slot successful.",
            state: "pending",
        },
    ];
}

export class Flow {
    readonly steps: Step[];
    readonly #events: FlowEvents;

    /** Which device we are talking to; decides the ionstack build and tuning. */
    profile: DeviceProfile = QUEST1;

    adb: Adb | undefined;
    identity: DeviceIdentity | undefined;
    gates: Gate[] = [];
    images: Map<string, Uint8Array> = new Map();
    payload: Uint8Array | undefined;
    /** Pristine LinuxLoader image; the payload is built from it at unlock time. */
    pe: Uint8Array | undefined;
    backup: BackupSet | undefined;
    fastboot: FastbootDevice | undefined;
    unlockState: UnlockState | undefined;
    /** Whether `oem reset-rollback-indexes` succeeded after the unlock. */
    rollbackReset: boolean | undefined;

    /** Slot the device booted from, restored at the very end. */
    originalSlot: number | undefined;
    /** Slot we downgrade and boot the vulnerable bootloader from. */
    targetSlot: number | undefined;

    #index = 0;

    constructor(events: FlowEvents) {
        this.#events = events;
        this.steps = unlockSteps();
    }

    get current(): Step | undefined {
        return this.steps[this.#index];
    }

    get finished(): boolean {
        return this.#index >= this.steps.length;
    }

    /**
     * The gate that must be typed through before `step` runs, if any.
     *
     * Phrases embed live device state so that reading the dialog is the only
     * way to know what to type.
     */
    confirmationFor(step: Step): Confirmation | undefined {
        const target = this.targetSlot === undefined ? "" : slotSuffix(this.targetSlot);
        const original =
            this.originalSlot === undefined ? "" : slotSuffix(this.originalSlot);

        switch (step.id) {
            case "root":
                return {
                    heading: "Kernel exploit — risk of bricking",
                    body: [
                        "ionstack corrupts kernel memory on purpose to win a race. When it " +
                            "misses, the usual outcome is a kernel panic and a reboot, but a " +
                            "bad write into the wrong structure can corrupt data on the " +
                            "device. Nothing has been written to a partition yet, so a panic " +
                            "here costs you a reboot and nothing more.",
                        "There is no supported way to un-brick a Quest 1 whose bootloader " +
                            "chain is damaged. You are accepting that risk.",
                        `To continue, type: root ${DEVICE.codename}`,
                    ],
                    phrase: `root ${DEVICE.codename}`,
                };

            case "flash":
                return {
                    heading: `Overwriting slot ${target} — risk of bricking`,
                    body: [
                        `This writes ${PARTITIONS.length} partitions, including the bootloader ` +
                            `chain (xbl, abl, tz, hyp), to slot ${target}. If it is interrupted ` +
                            "part-way — cable pulled, headset sleeps, browser tab closed — that " +
                            "slot will not boot.",
                        `You stay booted on slot ${original} throughout, so the backup taken ` +
                            "and re-verified in the previous steps can put this slot back " +
                            "whatever happens here. It lives in this browser's storage for " +
                            "this origin; clearing site data destroys it, so save the zip if " +
                            "you care about it.",
                        `To continue, type: overwrite ${target}`,
                    ],
                    phrase: `overwrite ${target}`,
                };

            case "unlock":
                return {
                    heading: "Unlock the bootloader",
                    body: [
                        "This sends the CVE-2021-1931 overflow payload to the bootloader and " +
                            "then requests the unlock token.",
                        "Unlocking erases userdata, misc and metadata. That is the " +
                            "bootloader's stock behaviour and this tool does not change it.",
                        `To continue, type: unlock ${DOWNGRADE_TARGET}`,
                    ],
                    phrase: `unlock ${DOWNGRADE_TARGET}`,
                };

            default:
                return undefined;
        }
    }

    #log(line: string, kind?: "info" | "warn" | "error" | "good"): void {
        this.#events.onLog(line, kind);
    }

    #progress(step: Step, label: string, transferred: number, total: number): void {
        step.progress = { label, transferred, total };
        this.#events.onChange();
    }

    /** Runs the next pending step. */
    async runNext(): Promise<boolean> {
        const step = this.current;
        if (!step) return false;

        step.state = "running";
        step.error = undefined;
        step.progress = undefined;
        this.#events.onChange();

        try {
            await this.#execute(step);
            step.state = "done";
            step.progress = undefined;
            this.#index++;
            this.#events.onChange();
            return true;
        } catch (error) {
            step.state = "failed";
            step.error = error instanceof Error ? error.message : String(error);
            step.progress = undefined;
            this.#log(`${step.title} failed: ${step.error}`, "error");
            this.#events.onChange();
            return false;
        }
    }

    async #execute(step: Step): Promise<void> {
        switch (step.id) {
            case "identify":
                return this.#stepIdentify();
            case "assets":
                return this.#stepAssets();
            case "slots":
                return this.#stepSlots();
            case "root":
                return this.#stepRoot();
            case "backup":
                return this.#stepBackup(step);
            case "flash":
                return this.#stepFlash(step);
            case "activate":
                return this.#stepActivate();
            case "bootloader":
                return this.#stepBootloader();
            case "unlock":
                return this.#stepUnlock(step);
            case "restore-slot":
                return this.#stepRestoreSlot();
            case "factory-reset":
                return this.#stepFactoryReset();
            case "boot-os":
                return this.#stepBootOs();
            default:
                throw new Error(`unknown step ${step.id}`);
        }
    }

    #requireAdb(): Adb {
        if (!this.adb) {
            throw new Error("no device connected");
        }
        return this.adb;
    }

    async #stepIdentify(): Promise<void> {
        const adb = this.#requireAdb();

        if (!isSecureOrigin()) {
            this.#log(
                "this page is not on a secure origin — payload integrity rests entirely " +
                    "on the bundled hashes, with nothing protecting them in transit",
                "warn",
            );
        }
        const identity = await identify(adb);
        this.identity = identity;
        this.gates = evaluateGates(identity);

        this.#log(`fingerprint: ${identity.fingerprint}`);
        this.#log(`build: ${identity.build?.version ?? "unknown"} (${identity.incremental})`);
        this.#log(`slot: ${identity.slotSuffix || "(none reported)"}`);

        for (const gate of this.gates) {
            this.#log(
                `${gate.title} — ${gate.detail}`,
                gate.status === "abort" ? "error" : gate.status === "warn" ? "warn" : "good",
            );
        }

        if (worstStatus(this.gates) === "abort") {
            const blocker = this.gates.find((g) => g.status === "abort")!;
            throw new Error(`${blocker.title}. ${blocker.detail}`);
        }

        // The gates above already refused anything that is not a Quest 1.
        this.profile = QUEST1;
        await findByNameDir(adb, this.profile.byNameDirs);
        this.#log(`by-name directory: ${getByNameDir()}`);
    }

    async #stepAssets(): Promise<void> {
        const zip = await this.#fetchAsset(ASSETS.firmware, "firmware archive");
        const entries = await new Promise<Record<string, Uint8Array>>((resolve, reject) => {
            unzip(zip, (error, data) => (error ? reject(error) : resolve(data)));
        });

        this.images = new Map(Object.entries(entries));
        const names = [...this.images.keys()].sort();
        this.#log(`unpacked ${names.length} images: ${names.join(", ")}`);

        for (const partition of PARTITIONS) {
            if (!this.images.has(`${partition}.img`)) {
                throw new Error(`the archive is missing ${partition}.img`);
            }
        }

        const abl = this.images.get("abl.img")!;
        const ablHash = await sha256(abl);
        if (ablHash !== EXPECTED_ABL_SHA256) {
            throw new Error(
                `abl.img inside the archive hashes ${ablHash}, expected ${EXPECTED_ABL_SHA256}. ` +
                    "The bootloader patch was derived from a specific image; refusing to " +
                    "build a payload from a different one.",
            );
        }

        const pe = await extractLinuxLoaderPe(abl.slice());
        const peHash = await sha256(pe);
        if (peHash !== EXPECTED_PE_SHA256) {
            throw new Error(
                "the extracted LinuxLoader image is not the one this patch was written " +
                    `for (hashes ${peHash}, expected ${EXPECTED_PE_SHA256})`,
            );
        }

        this.pe = pe;

        this.#log(`abl.img sha256 ${ablHash} — matches the pinned image`, "good");
        this.#log(`LinuxLoader PE ${pe.length} bytes, sha256 verified`, "good");

        // Report the payload now so it is auditable before it is sent; the
        // one actually sent is built again when the unlock step runs.
        const { payload, patch } = this.#buildPayload();
        const sites = patch.map((e) => `0x${e.offset.toString(16)}`).join(", ");
        this.#log(
            `payload: ${patch.length} site(s) at ${sites}, ${payload.length} bytes, ` +
                `sha256 ${await sha256(payload)}`,
        );
    }

    /** Builds the unlock payload from the pristine image. */
    #buildPayload(): { payload: Uint8Array; patch: AblPatch } {
        if (!this.pe) {
            throw new Error("the firmware has not been loaded yet");
        }
        const patch = unlockPatch();
        const image = this.pe.slice();
        applyPatch(image, patch);
        return { payload: buildUnlockPayload(image, patch), patch };
    }

    /** Every payload is hash-checked against the bundled manifest. */
    async #fetchAsset(url: string, what: string): Promise<Uint8Array> {
        const data = await fetchAsset(url, { what });
        this.#log(`${url} verified (${data.length} bytes)`);
        return data;
    }

    async #stepSlots(): Promise<void> {
        const adb = this.#requireAdb();
        const identity = this.identity!;

        const suffix = identity.slotSuffix;
        if (suffix !== "_a" && suffix !== "_b") {
            throw new Error(
                `ro.boot.slot_suffix is ${JSON.stringify(suffix)}; this device does not look like an A/B device.`,
            );
        }

        this.originalSlot = suffix === "_a" ? 0 : 1;
        this.targetSlot = this.originalSlot === 0 ? 1 : 0;

        this.#log(
            `active slot ${slotSuffix(this.originalSlot)}, downgrading ${slotSuffix(this.targetSlot)}`,
            "good",
        );

        const { stdout } = await shell(adb, `ls ${"/dev/block/bootdevice/by-name"} | tr '\\n' ' '`);
        this.#log(`partitions visible: ${stdout}`);
    }

    async #stepRoot(): Promise<void> {
        const adb = this.#requireAdb();

        const ionstack = await this.#fetchAsset(this.profile.ionstack, "ionstack binary");
        this.#log(`ionstack ${ionstack.length} bytes, sha256 ${await sha256(ionstack)}`);
        await pushIonstack(adb, ionstack);

        const bootctl = await this.#fetchAsset(ASSETS.bootctl, "bootctl_shim binary");
        this.#log(`bootctl_shim ${bootctl.length} bytes, sha256 ${await sha256(bootctl)}`);
        await pushBootctl(adb, bootctl);

        const rooted = await acquireRoot(adb, {
            profile: this.profile,
            onLine: (line) => this.#log(line),
        });
        if (!rooted) {
            throw new Error(
                "ionstack did not produce a root shell. Reboot the headset and try again — " +
                    "the exploit is racy and a failed attempt is harmless.",
            );
        }
        this.#log("root shell confirmed", "good");

        const info = await readSlotInfo(adb);
        this.#log(`boot_control module: ${info.module}`);
        this.#log(info.raw);

        const bootctlSlot = await getCurrentSlot(adb);
        if (bootctlSlot !== this.originalSlot) {
            throw new Error(
                `ro.boot.slot_suffix says slot ${this.originalSlot} but bootctl says ${bootctlSlot}. ` +
                    "Refusing to guess which is right.",
            );
        }
        this.#log(`bootctl agrees the active slot is ${slotSuffix(bootctlSlot)}`, "good");
    }

    async #stepBackup(step: Step): Promise<void> {
        const adb = this.#requireAdb();
        const identity = this.identity!;
        const target = slotSuffix(this.targetSlot!);

        if (!(await isRoot(adb))) {
            throw new Error("the shell is no longer root; re-run the root step");
        }

        const persisted = await requestPersistence();
        this.#log(
            persisted
                ? "browser storage marked persistent"
                : "browser did NOT grant persistent storage — download the backups when this finishes",
            persisted ? "good" : "warn",
        );

        // Exactly the partitions the flash step overwrites — no more, no less.
        // checkPartitions throws if any of them is missing on the target slot.
        const sizes = await checkPartitions(adb, target);
        const totalBytes = [...sizes.values()].reduce((a, b) => a + b, 0);
        const largest = Math.max(...sizes.values());

        this.#log(
            `backing up all ${sizes.size} partitions this tool overwrites on ${target}, ` +
                `${(totalBytes / 1048576).toFixed(1)} MiB total (largest ${(largest / 1048576).toFixed(1)} MiB)`,
        );
        for (const [name, size] of sizes) {
            this.#log(`  ${name}${target}  ${(size / 1048576).toFixed(1)} MiB`);
        }

        // Fail before touching anything rather than part-way through. A backup
        // that stops half done is the one state where the flash step must not
        // run, so it is better to refuse now and say exactly why.
        await this.#checkBackupFits(adb, totalBytes, largest);

        this.backup = await BackupSet.create(
            {
                serial: adb.serial,
                fingerprint: identity.fingerprint,
                slotSuffix: identity.slotSuffix,
                targetSlot: target,
                mode: "unlock",
                expected: [...sizes.keys()].map((name) => backupEntryName(name, target)),
            },
            new Date().toISOString(),
        );

        let done = 0;
        for (const partition of PARTITIONS) {
            const size = sizes.get(partition)!;
            const hash = await backupPartition(
                adb,
                this.backup,
                partition,
                target,
                size,
                (p) => {
                    this.#progress(
                        step,
                        `${p.phase} ${p.partition}${target} (${done + 1}/${PARTITIONS.length})`,
                        p.transferred,
                        p.total,
                    );
                },
            );
            done++;
            this.#log(`  ${partition}${target}  ${size} bytes  ${hash}`, "good");
        }

        await this.backup.markComplete();
        this.#log(
            `backup ${this.backup.id} holds all ${done} partitions and is marked complete`,
            "good",
        );

        // Copying and checking are one step because a backup nobody has read
        // back is not yet a backup: the hashes taken while writing say the
        // bytes arrived, not that storage still holds them.
        await this.#verifyBackup(step);
    }

    /**
     * Refuses the backup unless it will actually fit.
     *
     * Two separate limits: browser storage has to hold every image at once, and
     * /data has to hold the single largest one, because each partition is
     * dumped to a file there before being pulled and then deleted.
     */
    async #checkBackupFits(
        adb: Adb,
        totalBytes: number,
        largest: number,
    ): Promise<void> {
        const { usage, quota } = await estimateQuota();
        if (quota > 0) {
            const free = quota - usage;
            this.#log(
                `browser storage: ${(free / 1048576).toFixed(0)} MiB free of ` +
                    `${(quota / 1048576).toFixed(0)} MiB`,
            );
            if (totalBytes > free) {
                throw new Error(
                    `this backup needs ${(totalBytes / 1048576).toFixed(0)} MiB but only ` +
                        `${(free / 1048576).toFixed(0)} MiB of browser storage is free. ` +
                        "Every partition being overwritten has to be backed up, so nothing " +
                        "will be written until there is room. Delete old backups or free " +
                        "disk space.",
                );
            }
        } else {
            this.#log(
                "browser storage quota is unknown; proceeding, but the backup may be " +
                    "refused part-way if it does not fit",
                "warn",
            );
        }

        const onDevice = await freeSpace(adb, WORKDIR);
        if (onDevice === undefined) {
            this.#log(
                `could not read free space on ${WORKDIR}; proceeding without that check`,
                "warn",
            );
            return;
        }
        this.#log(`${WORKDIR}: ${(onDevice / 1048576).toFixed(0)} MiB free`);
        // A little headroom over the largest single image.
        const needed = largest + 16 * 1024 * 1024;
        if (onDevice < needed) {
            throw new Error(
                `the largest partition is ${(largest / 1048576).toFixed(0)} MiB but only ` +
                    `${(onDevice / 1048576).toFixed(0)} MiB is free on ${WORKDIR}. Each ` +
                    "partition is dumped there before being pulled, so free some space on " +
                    "the headset first.",
            );
        }
    }

    /**
     * Second, independent pass over the backup.
     *
     * Every image is read back out of browser storage, re-hashed, and compared
     * both to what was recorded during the copy and to a fresh hash of the
     * live partition. All three have to agree.
     */
    async #verifyBackup(step: Step): Promise<void> {
        const adb = this.#requireAdb();
        const target = slotSuffix(this.targetSlot!);
        const set = this.backup;
        if (!set) {
            throw new Error("no backup to verify — run the backup step first");
        }

        const problems: string[] = [];
        let done = 0;

        for (const partition of PARTITIONS) {
            this.#progress(
                step,
                `verifying ${partition}${target}`,
                done,
                PARTITIONS.length,
            );

            const { stored, device, recorded } = await verifyBackup(
                adb,
                set,
                partition,
                target,
            );

            if (stored !== recorded) {
                problems.push(
                    `${partition}${target}: stored copy hashes ${stored} but was recorded as ${recorded} — browser storage corrupted it`,
                );
            } else if (stored !== device) {
                problems.push(
                    `${partition}${target}: backup is ${stored} but the partition now reads ${device} — the partition changed since the backup`,
                );
            } else {
                this.#log(`  ${partition}${target}  re-verified ${stored}`, "good");
            }

            done++;
            this.#progress(
                step,
                `verifying ${partition}${target}`,
                done,
                PARTITIONS.length,
            );
        }

        if (problems.length > 0) {
            throw new Error(
                `the backup cannot be trusted, so nothing will be overwritten:\n${problems.join("\n")}`,
            );
        }

        await set.markVerified(new Date().toISOString());
        this.#log(
            `all ${PARTITIONS.length} backups re-read from storage and matched against the device`,
            "good",
        );
    }

    /**
     * Rolls the target slot back to the backup.
     *
     * Offered from the "switch the active slot" gate, which is the last moment
     * where reverting is a purely local operation.
     */
    async revertToBackup(
        onProgress?: (label: string, transferred: number, total: number) => void,
    ): Promise<void> {
        const adb = this.#requireAdb();
        const target = slotSuffix(this.targetSlot!);
        const set = this.backup;
        if (!set) {
            throw new Error("there is no backup to revert to");
        }
        if (!(await isRoot(adb))) {
            throw new Error("the shell is no longer root; re-run the root step");
        }

        this.#log(`reverting slot ${target} to backup ${set.id}`, "warn");

        let done = 0;
        for (const partition of PARTITIONS) {
            const { expected, actual } = await restorePartition(
                adb,
                set,
                partition,
                target,
                (p) =>
                    onProgress?.(
                        `${p.phase} ${p.partition}${target} (${done + 1}/${PARTITIONS.length})`,
                        p.transferred,
                        p.total,
                    ),
            );
            if (expected !== actual) {
                throw new Error(
                    `${partition}${target} did not restore cleanly: wrote ${expected}, read back ${actual}`,
                );
            }
            done++;
            this.#log(`  ${partition}${target}  restored ${actual}`, "good");
        }

        this.#log(
            `slot ${target} restored from backup; the active slot was not changed`,
            "good",
        );
        this.reset("flash");
    }

    async #stepFlash(step: Step): Promise<void> {
        const adb = this.#requireAdb();
        const target = slotSuffix(this.targetSlot!);

        if (!(await isRoot(adb))) {
            throw new Error("the shell is no longer root; re-run the root step");
        }
        if (!this.backup || this.backup.meta.entries.length !== PARTITIONS.length) {
            throw new Error(
                `refusing to flash: the backup holds ${this.backup?.meta.entries.length ?? 0} of ` +
                    `${PARTITIONS.length} partitions`,
            );
        }

        let done = 0;
        for (const partition of PARTITIONS) {
            const image = this.images.get(`${partition}.img`)!;
            const { expected, actual } = await flashPartition(
                adb,
                partition,
                target,
                image,
                (p) => {
                    this.#progress(
                        step,
                        `${p.phase} ${p.partition}${target} (${done + 1}/${PARTITIONS.length})`,
                        p.transferred,
                        p.total,
                    );
                },
            );

            if (expected !== actual) {
                throw new Error(
                    `${partition}${target} verification FAILED: wrote ${expected}, read back ${actual}. ` +
                        "The slot is now inconsistent — restore the backup before rebooting.",
                );
            }
            done++;
            this.#log(`  ${partition}${target}  verified ${actual}`, "good");
        }

        this.#log(`all ${PARTITIONS.length} partitions written and verified on ${target}`, "good");
    }

    async #stepActivate(): Promise<void> {
        const adb = this.#requireAdb();
        const target = this.targetSlot!;

        const { before, after, pendingFirstBoot } = await setActiveSlot(adb, target);

        this.#log("slot flags before:");
        this.#log(before.raw);
        this.#log("slot flags after:");
        this.#log(after.raw);

        // getCurrentSlot() reports the slot we are running from, and this HAL has
        // no getActiveBootSlot — so read the GPT attribute bits, which is where
        // boot_control actually keeps the active flag.
        const verdict = await readSlotVerdict(adb, getByNameDir(), after.slots);
        if (verdict) {
            for (const row of verdict.perSlot) {
                this.#log(
                    `  GPT ${row.suffix}: priority=${row.priority} active=${row.active} ` +
                        `retries=${row.retriesRemaining} successful=${row.successful} ` +
                        `unbootable=${row.unbootable}`,
                );
            }
            if (verdict.trusted && verdict.activeSlot !== undefined) {
                if (verdict.activeSlot !== target) {
                    throw new Error(
                        `the GPT says slot ${slotSuffix(verdict.activeSlot)} is active, but ` +
                            `${slotSuffix(target)} was requested. The device would boot the ` +
                            "wrong slot; stopping before the reboot.",
                    );
                }
                this.#log(
                    `GPT confirms slot ${slotSuffix(target)} is the active slot ` +
                        `(${verdict.reason})`,
                    "good",
                );
            } else {
                this.#log(
                    `could not confirm the active slot from the GPT: ${verdict.reason}. ` +
                        "Falling back to the boot_control flags below.",
                    "warn",
                );
            }
        } else {
            this.#log(
                "could not read the GPT attributes, so the active slot could not be " +
                    "confirmed independently; relying on the boot_control flags below",
                "warn",
            );
        }

        this.#log(
            `slot ${slotSuffix(target)} is queued for next boot ` +
                `(running slot is still ${slotSuffix(after.currentSlot)} until reboot)`,
            "good",
        );

        if (pendingFirstBoot) {
            this.#log(
                `slot ${slotSuffix(target)} is marked bootable but not yet successful — ` +
                    "this is the normal A/B state for a freshly activated slot. The " +
                    "bootloader spends one retry per boot attempt and falls back to slot " +
                    `${slotSuffix(this.originalSlot!)} if they run out, which is the safety ` +
                    "net if the downgrade does not boot.",
            );
        } else {
            this.#log(
                `slot ${slotSuffix(target)} came back already marked successful, which is ` +
                    "not what a freshly activated slot normally looks like — the retry " +
                    "fallback may not protect you here.",
                "warn",
            );
        }
    }

    async #stepBootloader(): Promise<void> {
        const adb = this.#requireAdb();
        this.#log("rebooting into the bootloader");
        await adb.power.bootloader().catch(() => shell(adb, "reboot bootloader"));
        this.adb = undefined;
        this.#log(
            "headset is rebooting — connect to the fastboot device when the picker appears",
            "warn",
        );
    }

    async #stepUnlock(step: Step): Promise<void> {
        const device = this.fastboot;
        if (!device?.opened) {
            throw new Error("connect to the fastboot device first");
        }

        const info = await device.deviceInfo();
        for (const [key, value] of info) {
            this.#log(`  ${key}: ${value}`);
        }

        const buildNumber = info.get("Build number");
        if (!buildNumber) {
            throw new Error("the bootloader did not report a build number");
        }
        if (buildNumber !== DOWNGRADE_TARGET) {
            throw new Error(
                `the bootloader reports build ${buildNumber}, but the payload is built for ` +
                    `${DOWNGRADE_TARGET}. Sending it to a different build would not unlock ` +
                    "anything and may hang the bootloader.",
            );
        }
        this.#log(`bootloader build ${buildNumber} matches the payload`, "good");

        const before = await readUnlockState(device);
        if (before.unlocked) {
            this.#log("bootloader already reports unlocked; nothing to do", "good");
            this.unlockState = before;
            return;
        }

        // The payload and the token request must not be separated: the patch
        // lives in the running bootloader's memory, so a reboot in between
        // would throw it away before the token is asked for.
        const { payload, patch } = this.#buildPayload();
        this.payload = payload;
        this.#log("the bootloader will erase userdata, misc and metadata");
        this.#log(
            `${patch.length} patch site(s), ${payload.length} bytes, sha256 ${await sha256(payload)}`,
        );

        const tentative = await performUnlock(device, payload, {
            onLog: (line) => this.#log(line),
            onProgress: (sent, total) => this.#progress(step, "sending payload", sent, total),
        });

        this.#log("state as reported by the patched bootloader:");
        for (const [key, value] of Object.entries(tentative.evidence)) {
            this.#log(`  ${key} = ${value}`);
        }

        if (tentative.linkLost) {
            // Nothing to reboot: it already went. An unlock that takes erases
            // userdata, and the headset leaves the bus to do it, so this is
            // the expected shape of success — but it is not proof, and the
            // reading that would prove it is exactly the one we could not get.
            this.#log(
                "the bootloader left the bus after the unlock request. That is what it " +
                    "does when the unlock takes: it reboots to erase userdata.",
                "warn",
            );
            try {
                await device.close();
            } catch {
                // Already gone.
            }
            this.#log("reconnecting to fastboot");
            this.#progress(step, "reconnecting to fastboot", 0, 1);
            // Short: the page can only re-open a device it still has
            // permission for, and when it does not — routinely so on Android
            // — no amount of waiting helps. Failing hands the user the picker.
            const back = await waitForBootloader({
                onLog: (line) => this.#log(line),
                timeoutMs: 15_000,
            });
            this.#progress(step, "reconnecting to fastboot", 1, 1);
            if (!back) {
                throw new Error(
                    "the headset left fastboot after the unlock request and could not be " +
                        "picked up again automatically — the unlock itself most likely " +
                        "worked. Reconnect with the picker below (or “Connect bootloader”) " +
                        "and run this step again: it will say so straight away if it did.",
                );
            }
            this.fastboot = back;
        } else {
            // That reading came from a bootloader whose verification we just
            // disabled in memory, so it says little about what was persisted.
            // Reboot and ask a clean one: that answer is the real one, and it
            // also leaves the device ready to retry if the overflow missed.
            this.#log("rebooting the bootloader to confirm the unlock persisted");
            this.#progress(step, "rebooting the bootloader", 0, 1);
            this.fastboot = await rebootToBootloader(device, {
                onLog: (line) => this.#log(line),
            });
            this.#progress(step, "rebooting the bootloader", 1, 1);
        }

        const confirmed = await readUnlockState(this.fastboot);
        this.unlockState = confirmed;

        this.#log("state after a clean boot:");
        for (const [key, value] of Object.entries(confirmed.evidence)) {
            this.#log(`  ${key} = ${value}`);
        }

        if (confirmed.linkLost) {
            throw new Error(
                "the bootloader stopped answering while the unlock was being confirmed, so " +
                    "its state is unknown — not necessarily locked. Reconnect with " +
                    "“Connect bootloader” and run this step again to read it.",
            );
        }

        if (!confirmed.unlocked) {
            throw new Error(
                tentative.unlocked
                    ? "the bootloader claimed to be unlocked while patched, but a clean " +
                          "boot reports it locked again — the unlock did not persist. Run " +
                          "this step again; the bootloader has already been restarted."
                    : "the bootloader still reports locked. The overflow does not always " +
                          "land. It has already been restarted cleanly, so run this step " +
                          "again as-is.",
            );
        }

        this.#log("bootloader reports UNLOCKED after a clean boot", "good");

        // Only once the unlock is confirmed. Verified boot keeps a minimum
        // version per image, so the slot we rolled back can be refused on a
        // later boot until that floor is cleared.
        this.#log("clearing the anti-rollback indexes");
        const rollback = await resetRollbackIndexes(this.fastboot, (line) =>
            this.#log(line),
        );

        if (rollback.status === "OKAY") {
            this.rollbackReset = true;
            this.#log("anti-rollback indexes cleared", "good");
        } else {
            this.rollbackReset = false;
            // Not fatal: the unlock itself succeeded, and failing the step here
            // would suggest otherwise. It is still worth shouting about, since
            // the downgraded slot may stop booting later.
            this.#log(
                `could not clear the anti-rollback indexes: ${rollback.message}. The unlock ` +
                    "itself succeeded, but the downgraded slot may be refused on a later " +
                    "boot. Anything already burned into fuses cannot be cleared at all.",
                "error",
            );
        }
    }

    async #stepRestoreSlot(): Promise<void> {
        const device = this.fastboot;
        if (!device?.opened) {
            throw new Error("connect to the fastboot device first");
        }

        // Re-read rather than trusting the value from the previous step.
        const state = await readUnlockState(device);
        this.unlockState = state;
        for (const [key, value] of Object.entries(state.evidence)) {
            this.#log(`  ${key} = ${value}`);
        }
        if (state.linkLost) {
            throw new Error(
                "the bootloader stopped answering, so its lock state could not be read. " +
                    "Reconnect with “Connect bootloader” and run this step again.",
            );
        }
        if (!state.unlocked) {
            throw new Error(
                "the bootloader is not unlocked, so the original slot will not be restored. " +
                    "Re-run the unlock step; switching back now would leave you on the " +
                    "original slot with nothing gained.",
            );
        }
        this.#log("unlock state confirmed before switching slots", "good");

        const original = slotLetter(this.originalSlot!);

        // Read the slot first. A previous run may have set it and then failed
        // on the reconnect — routinely so on Android, where the bootloader has
        // to be picked from the USB dialog by hand. If it is already right,
        // this step is done: switching again would restart the bootloader and
        // wait for it a second time for nothing.
        const before = await device.getVar("current-slot");
        if (before !== undefined && before.trim().replace(/^_/, "") === original) {
            this.#log(`getvar:current-slot = ${before}`);
            this.#log(
                `slot _${original} is already active and this bootloader has restarted ` +
                    "since it was set — nothing left to do here",
                "good",
            );
            this.#logSlotReminders(original);
            return;
        }

        const response = await device.setActive(original);
        this.#log(`set_active:${original} -> ${response.status} ${response.message}`, "good");

        // That answer came from the bootloader that was already running. Ask a
        // freshly started one instead: its reading is the one that predicts
        // the next boot, and the restart re-checks the unlock for free.
        this.#log("restarting the bootloader to read the slot back from a clean start");
        this.fastboot = await rebootToBootloader(device, {
            onLog: (line) => this.#log(line),
        });

        const current = await this.fastboot.getVar("current-slot");
        if (current === undefined) {
            throw new Error(
                "the bootloader does not report current-slot, so the slot switch could " +
                    "not be confirmed. Do not go on until you know which slot is active.",
            );
        }
        this.#log(`getvar:current-slot = ${current}`);
        if (current.trim().replace(/^_/, "") !== original) {
            throw new Error(
                `the bootloader reports slot "${current}" as current, not "${original}". ` +
                    "Run this step again before going any further — the headset is still " +
                    "queued to boot the downgraded slot.",
            );
        }
        this.#log(`bootloader confirms slot _${original} after a clean start`, "good");

        const after = await readUnlockState(this.fastboot);
        this.unlockState = after;
        if (after.linkLost) {
            throw new Error(
                "the bootloader stopped answering, so the unlock could not be " +
                    "re-checked. Reconnect with “Connect bootloader” and run this step " +
                    "again.",
            );
        }
        if (!after.unlocked) {
            throw new Error(
                "the bootloader came back locked after the restart, so the unlock did " +
                    "not persist. Re-run the unlock step.",
            );
        }
        this.#log("bootloader still reports UNLOCKED", "good");

        this.#logSlotReminders(original);
    }

    /** What is true once the original slot is active again, either way. */
    #logSlotReminders(original: string): void {
        if (this.rollbackReset === false) {
            this.#log(
                "reminder: the anti-rollback indexes were NOT cleared, so the downgraded " +
                    "slot may be refused on a later boot",
                "warn",
            );
        }

        this.#log(`slot ${original} is queued and the bootloader is unlocked.`, "good");
        this.#log(
            `set_active clears the successful flag, so slot ${original} now has a retry ` +
                "counter just like a freshly installed update. The last step boots the " +
                "headset, which is what sets that flag again: Android calls " +
                "markBootSuccessful once it is up. Until then the bootloader can still " +
                "fall back to the other slot.",
            "warn",
        );
    }

    /**
     * Erases userdata so the slot boots clean.
     *
     * /data is encrypted against the verified-boot state, and that state just
     * changed. What is left behind is undecryptable, which is what the
     * “device is corrupt” screen on first boot is: the OS finding data it
     * cannot open. Erasing it here means the headset comes straight up at
     * setup instead.
     *
     * userdata is the one that has to go. misc and metadata follow when the
     * bootloader allows it — misc holds the bootloader control block,
     * metadata the encryption metadata — but a refusal there is logged
     * rather than treated as a failure.
     */
    async #stepFactoryReset(): Promise<void> {
        const device = this.fastboot;
        if (!device?.opened) {
            throw new Error("connect to the fastboot device first");
        }

        const state = await readUnlockState(device);
        if (state.linkLost) {
            throw new Error(
                "the bootloader stopped answering, so its lock state could not be read. " +
                    "Reconnect with “Connect bootloader” and run this step again.",
            );
        }
        if (!state.unlocked) {
            throw new Error(
                "the bootloader is locked, so it will refuse to erase anything. Re-run " +
                    "the unlock step first.",
            );
        }

        this.#log("erasing userdata — everything on the headset goes with it", "warn");
        const userdata = await device.erase("userdata");
        this.#log(`erase:userdata -> ${userdata.status} ${userdata.message}`.trimEnd());
        if (userdata.status === "FAIL") {
            throw new Error(
                `the bootloader refused to erase userdata: ${userdata.message}. Without ` +
                    "this the first boot may come up reporting the device as corrupt; a " +
                    "factory reset from the headset's own boot menu does the same job.",
            );
        }
        this.#log("userdata erased", "good");

        // Same order the bootloader's own wipe uses: userdata, misc, metadata.
        for (const partition of ["misc", "metadata"]) {
            // Ask before erasing: not every Quest 1 GPT carries both, and a
            // bootloader asked to erase a partition it does not have answers
            // with the same opaque "Check device console." it uses for real
            // failures.
            const type = await device.getVar(`partition-type:${partition}`);
            if (type === undefined) {
                this.#log(`${partition}: not a partition this bootloader knows — skipped`);
                continue;
            }

            const response = await device.erase(partition);
            this.#log(
                `erase:${partition} -> ${response.status} ${response.message}`.trimEnd(),
                response.status === "OKAY" ? "good" : "warn",
            );
            if (response.status === "FAIL") {
                this.#log(
                    `${partition} was not erased. That is not fatal: userdata is what ` +
                        "decides whether the OS comes up clean, and it is already gone.",
                    "warn",
                );
            }
        }
    }

    /**
     * Leaves fastboot and boots the headset.
     *
     * The last thing the procedure needs is an actual boot: `set_active`
     * cleared the successful flag, and only Android calling
     * markBootSuccessful sets it again. Until that happens the bootloader is
     * still spending retries and can fall back to the other slot.
     *
     * The link drops as the device goes, so a failed transfer here is the
     * command working rather than failing.
     */
    async #stepBootOs(): Promise<void> {
        const device = this.fastboot;
        if (!device?.opened) {
            throw new Error("connect to the fastboot device first");
        }

        this.#log("sending reboot");
        try {
            const response = await device.reboot();
            this.#log(`reboot -> ${response.status} ${response.message}`.trimEnd());
        } catch (error) {
            if (!isLinkLost(error)) throw error;
            this.#log("link dropped as the headset rebooted (normal)");
        }

        await device.close();
        this.fastboot = undefined;

        this.#log("the headset is booting", "good");
        this.#log(
            "Let it boot all the way into the system — that is what marks the slot " +
                "successful. userdata was erased, so this first boot takes longer than " +
                "usual and comes up at the setup screen.",
            "warn",
        );
        this.#log(
            "It restarts itself several times on the way there. That is what a first " +
                "boot after a wipe looks like, not a boot loop — leave it plugged in and " +
                "do not interrupt it until it reaches the setup screen.",
            "warn",
        );
        this.#log(
            "If it still comes up saying the device is corrupt and cannot be trusted, " +
                "reset it from the headset itself: hold power and volume-down until the " +
                "boot menu appears, " +
                "pick Factory Reset with the volume keys and confirm with power. That " +
                "erases /data only; the unlock and the firmware on both slots survive it.",
            "warn",
        );
        if (this.rollbackReset === false) {
            this.#log(
                "reminder: the anti-rollback indexes were NOT cleared, so this boot may " +
                    "still be refused",
                "warn",
            );
        }
    }

    /** Best-effort tidy-up of the files we pushed. */
    async cleanupDevice(): Promise<void> {
        if (!this.adb) return;
        await cleanup(this.adb);
        this.#log("removed /data/local/tmp/q1u");
    }

    /** Lets the UI retry a failed step. */
    reset(stepId: string): void {
        const index = this.steps.findIndex((s) => s.id === stepId);
        if (index < 0) return;
        this.#index = index;
        for (let i = index; i < this.steps.length; i++) {
            this.steps[i]!.state = "pending";
            this.steps[i]!.error = undefined;
        }
        this.#events.onChange();
    }
}

export type { PartitionName };
