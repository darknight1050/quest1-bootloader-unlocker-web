import { Adb, AdbDaemonTransport } from "@yume-chan/adb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import {
    AdbDaemonWebUsbDevice,
    AdbDaemonWebUsbDeviceManager,
} from "@yume-chan/adb-daemon-webusb";

import { fetchAsset } from "./lib/assets.js";
import { DEVICE, DOWNGRADE_TARGET, identify } from "./lib/device.js";
import { FastbootDevice, rebootToBootloader } from "./lib/fastboot.js";
import { Flow, type Confirmation, type FlowMode } from "./lib/flow.js";
import { planRestore, runRestore } from "./lib/restore.js";
import {
    BackupSet,
    type BackupSetMeta,
    deleteBackupSet,
    downloadSetAsZip,
    importBackupSet,
    importBackupZip,
    listBackupSets,
} from "./lib/storage.js";
import { PARTITIONS, backupEntryName } from "./lib/partitions.js";

const OCULUS_VENDOR_ID = 0x2833;

const $ = <T extends HTMLElement>(id: string): T =>
    document.getElementById(id) as T;

const connectButton = $<HTMLButtonElement>("connect");
const connectFastbootButton = $<HTMLButtonElement>("connect-fastboot");
const disconnectButton = $<HTMLButtonElement>("disconnect");
const runStepButton = $<HTMLButtonElement>("run-step");
const retryStepButton = $<HTMLButtonElement>("retry-step");
const rebootBootloaderButton = $<HTMLButtonElement>("reboot-bootloader");
const stepHint = $<HTMLSpanElement>("step-hint");
const statusText = $<HTMLParagraphElement>("status");
const devicePanel = $<HTMLElement>("device-panel");
const fingerprintOutput = $<HTMLOutputElement>("fingerprint");
const propsBody = $<HTMLTableElement>("props").tBodies[0]!;
const gatesList = $<HTMLUListElement>("gates");
const stepsList = $<HTMLOListElement>("steps");
const backupsBox = $<HTMLDivElement>("backups");
const logElement = $<HTMLPreElement>("log");
const copyLogButton = $<HTMLButtonElement>("copy-log");
const importBackupButton = $<HTMLButtonElement>("import-backup");
const importFilesInput = $<HTMLInputElement>("import-files");

const dialog = $<HTMLDialogElement>("confirm-dialog");
const dialogHeading = $<HTMLHeadingElement>("confirm-heading");
const dialogBody = $<HTMLDivElement>("confirm-body");
const dialogPhrase = $<HTMLElement>("confirm-phrase");
const dialogInput = $<HTMLInputElement>("confirm-input");
const dialogOk = $<HTMLButtonElement>("confirm-ok");
const dialogCancel = $<HTMLButtonElement>("confirm-cancel");
const dialogRevert = $<HTMLButtonElement>("confirm-revert");

const devModeToggle = $<HTMLInputElement>("dev-mode");
const devBanner = $<HTMLDivElement>("dev-banner");
const devCapInput = $<HTMLInputElement>("dev-cap");
const noticeDialog = $<HTMLDialogElement>("notice-dialog");
const noticeHeading = $<HTMLHeadingElement>("notice-heading");
const noticeBody = $<HTMLDivElement>("notice-body");
const noticeOk = $<HTMLButtonElement>("notice-ok");
const noticeAction = $<HTMLButtonElement>("notice-action");

const credentialStore = new AdbWebCredentialStore("quest1-unlocker-web");

let busy = false;

const flowEvents = { onLog: log, onChange: render };

/**
 * Dev mode exists only when Vite is serving locally.
 *
 * `import.meta.env.DEV` is substituted at build time, so in a production
 * bundle this is a literal `false`: the toggle is removed, the `?dev` param is
 * ignored, and the Quest 3 payload is not even shipped (see sync-assets).
 */
const DEV_AVAILABLE = import.meta.env.DEV;

/** Read from the URL so a dev-mode session can be bookmarked. */
const initialMode: FlowMode =
    DEV_AVAILABLE && new URLSearchParams(location.search).get("dev") !== null
        ? "dev"
        : "unlock";

let flow = new Flow(flowEvents, initialMode);

function log(message: string, kind: "info" | "warn" | "error" | "good" = "info"): void {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("span");
    line.className = `log-${kind}`;
    line.textContent = `[${time}] ${message}\n`;
    logElement.append(line);
    logElement.scrollTop = logElement.scrollHeight;
}

function setStatus(
    text: string,
    kind: "idle" | "busy" | "ok" | "warn" | "error" = "idle",
): void {
    statusText.textContent = text;
    statusText.className = `status ${kind}`;
}

function formatBytes(value: number): string {
    if (value < 1024) return `${value} B`;
    if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / 1048576).toFixed(1)} MiB`;
}

// ---------------------------------------------------------------- rendering

/**
 * Buttons in the backups panel, so their enabled state can be refreshed
 * without re-reading OPFS.
 *
 * The panel is rendered from inside `withBusy`, which means every button is
 * built while `busy` is still true. Without this the disabled state set at
 * build time would never be revised — the panel is not part of `render()`,
 * because listing OPFS on every progress tick would be absurd.
 */
const backupControls: { el: HTMLButtonElement; needsDevice: boolean }[] = [];

function syncBackupControls(): void {
    for (const { el, needsDevice } of backupControls) {
        el.disabled = busy || (needsDevice && !flow.adb);
        if (needsDevice) {
            el.title = flow.adb
                ? "Roots the headset with ionstack and writes these images back"
                : "Connect the headset over ADB first";
        }
    }
}

function render(): void {
    renderDevice();
    renderSteps();
    renderActions();
    syncBackupControls();
}

function renderDevice(): void {
    const identity = flow.identity;
    if (!identity) {
        devicePanel.hidden = true;
        return;
    }
    devicePanel.hidden = false;
    fingerprintOutput.textContent = identity.fingerprint || "(empty)";

    propsBody.replaceChildren();
    const rows: [string, string][] = [
        ["model", `${identity.model} (${identity.device})`],
        ["android", identity.release],
        ["build", identity.build?.version ?? "unknown"],
        ["incremental", identity.incremental],
        ["active slot", identity.slotSuffix || "—"],
        [
            "target slot",
            flow.targetSlot === undefined ? "—" : flow.targetSlot === 0 ? "_a" : "_b",
        ],
    ];
    for (const [key, value] of rows) {
        const row = propsBody.insertRow();
        row.insertCell().textContent = key;
        row.insertCell().textContent = value;
    }

    gatesList.replaceChildren();
    for (const gate of flow.gates) {
        const item = document.createElement("li");
        item.className = `gate gate-${gate.status}`;
        const title = document.createElement("strong");
        title.textContent = gate.title;
        const detail = document.createElement("span");
        detail.textContent = gate.detail;
        item.append(title, detail);
        gatesList.append(item);
    }
}

function renderSteps(): void {
    stepsList.replaceChildren();
    for (const step of flow.steps) {
        const item = document.createElement("li");
        item.className = `step step-${step.state}`;
        if (step === flow.current) {
            item.classList.add("step-current");
        }

        const title = document.createElement("strong");
        title.textContent = step.title;

        const detail = document.createElement("span");
        detail.className = "step-detail";
        detail.textContent = step.detail;

        item.append(title, detail);

        if (step.progress) {
            const { label, transferred, total } = step.progress;
            const bar = document.createElement("div");
            bar.className = "bar";
            const fill = document.createElement("div");
            fill.className = "bar-fill";
            fill.style.width = `${total > 0 ? Math.min(100, (transferred / total) * 100) : 0}%`;
            bar.append(fill);

            const caption = document.createElement("span");
            caption.className = "step-progress";
            caption.textContent =
                total > 1024
                    ? `${label} — ${formatBytes(transferred)} / ${formatBytes(total)}`
                    : `${label} — ${transferred} / ${total}`;

            item.append(caption, bar);
        }

        if (step.error) {
            const error = document.createElement("span");
            error.className = "step-error";
            error.textContent = step.error;
            item.append(error);
        }

        stepsList.append(item);
    }
}

function renderActions(): void {
    const step = flow.current;

    if (busy) {
        runStepButton.disabled = true;
        retryStepButton.hidden = true;
        rebootBootloaderButton.disabled = true;
        stepHint.textContent = "working…";
        return;
    }

    if (!step) {
        runStepButton.disabled = true;
        runStepButton.textContent = "All steps complete";
        retryStepButton.hidden = true;
        rebootBootloaderButton.hidden = true;
        stepHint.textContent = "";
        return;
    }

    const failed = step.state === "failed";
    retryStepButton.hidden = !failed;

    // A missed overflow leaves the bootloader in an unknown state, so retrying
    // is only meaningful after a clean boot.
    const fastbootStep = [
        "unlock",
        "restore-slot",
        "boot-os",
        "dev-fastboot",
        "dev-reboot-bootloader",
    ].includes(step.id);
    rebootBootloaderButton.hidden = !(fastbootStep && flow.fastboot?.opened);
    rebootBootloaderButton.disabled = busy;
    rebootBootloaderButton.title =
        "Sends reboot-bootloader and reconnects — use this before retrying the unlock";
    runStepButton.textContent = failed ? `Run "${step.title}" again` : `Run: ${step.title}`;

    const fastbootSteps = [
        "unlock",
        "restore-slot",
        "boot-os",
        "dev-fastboot",
        "dev-reboot-bootloader",
    ];
    const needsFastboot = fastbootSteps.includes(step.id);
    const needsAdb = !needsFastboot;

    if (needsAdb && !flow.adb) {
        runStepButton.disabled = true;
        stepHint.textContent = "connect the headset over ADB first";
        return;
    }
    if (needsFastboot && !flow.fastboot?.opened) {
        runStepButton.disabled = true;
        stepHint.textContent = "connect the bootloader over fastboot first";
        return;
    }

    runStepButton.disabled = false;
    stepHint.textContent = flow.confirmationFor(step)
        ? "this step asks for a typed confirmation"
        : "";
}

async function renderBackups(): Promise<void> {
    const sets = await listBackupSets().catch(() => []);
    backupsBox.replaceChildren();
    backupControls.length = 0;

    if (sets.length === 0) {
        const empty = document.createElement("p");
        empty.className = "backups-empty";
        empty.textContent =
            "No backups stored in this browser. The unlock flow takes one before it " +
            "writes anything; if you have images saved from another machine, import " +
            "them below.";
        backupsBox.append(empty);
        return;
    }

    for (const set of sets) {
        const total = set.entries.reduce((sum, entry) => sum + entry.size, 0);
        const complete = set.complete === true;

        const box = document.createElement("div");
        box.className = complete ? "backup" : "backup backup-incomplete";

        const title = document.createElement("strong");
        title.textContent = `${set.serial} · slot ${set.targetSlot} · ${set.entries.length} partitions · ${formatBytes(total)}`;

        const badge = document.createElement("span");
        badge.className = complete ? "badge badge-complete" : "badge badge-incomplete";
        badge.textContent = complete
            ? "complete"
            : set.mode === "dev"
              ? "dev rehearsal"
              : "incomplete";
        title.append(badge);

        const detail = document.createElement("span");
        detail.textContent = `${new Date(set.createdAt).toLocaleString()} — ${set.fingerprint}`;

        box.append(title, detail);

        if (!complete) {
            const warning = document.createElement("span");
            warning.className = "step-error";
            warning.textContent =
                set.mode === "dev"
                    ? "Dev-mode rehearsal: a deliberate subset, not a device backup. " +
                      "Restoring it would leave the other partitions untouched."
                    : `Incomplete: holds ${set.entries.length} of ${set.expected?.length ?? "?"} ` +
                      "partitions. Restoring it will not fully recover the slot.";
            box.append(warning);
        }

        const actions = document.createElement("div");
        actions.className = "row backup-actions";

        const restore = document.createElement("button");
        restore.type = "button";
        restore.className = "danger-ghost";
        restore.textContent = `Restore to slot ${set.targetSlot}`;
        restore.disabled = !set.id || !flow.adb || busy;
        restore.title = flow.adb
            ? "Roots the headset with ionstack and writes these images back"
            : "Connect the headset over ADB first";
        restore.addEventListener("click", () => {
            if (set.id) void startRestore(set.id);
        });

        const save = document.createElement("button");
        save.type = "button";
        save.className = "ghost";
        save.textContent = "Save as zip";
        save.title = "Writes every partition image into a single zip";
        save.addEventListener("click", () => {
            if (!set.id) return;
            void withBusy(async () => {
                const handle = await BackupSet.load(set.id!);
                setStatus(`Building ${set.id}.zip…`, "busy");
                const result = await downloadSetAsZip(handle, (written, bytes) => {
                    setStatus(
                        `Writing ${set.id}.zip — ${formatBytes(written)} / ${formatBytes(bytes)}`,
                        "busy",
                    );
                });
                if (result.cancelled) {
                    setStatus("Save cancelled.", "idle");
                    return;
                }
                log(
                    `wrote ${set.id}.zip — ${set.entries.length} images, ${formatBytes(result.bytes)}`,
                    "good",
                );
                setStatus(`Saved ${set.id}.zip (${formatBytes(result.bytes)}).`, "ok");
            });
        });

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "ghost btn-delete";
        remove.textContent = "Delete";
        remove.title = "Removes this backup from browser storage permanently";
        remove.addEventListener("click", () => {
            if (set.id) void confirmDelete(set, sets);
        });

        if (set.id) {
            backupControls.push(
                { el: restore, needsDevice: true },
                { el: save, needsDevice: false },
                { el: remove, needsDevice: false },
            );
        } else {
            // A set with no directory name cannot be acted on at all.
            for (const button of [restore, save, remove]) {
                button.disabled = true;
                button.title = "this backup has no storage handle";
            }
        }

        actions.append(restore, save, remove);
        box.append(actions);
        backupsBox.append(box);
    }

    syncBackupControls();
}

/**
 * Offered once the unlock has finished: drop the backup, or keep it.
 *
 * Keeping it is the only thing that can put the downgraded slot back to what it
 * held before, so the choice is presented with that consequence spelled out
 * rather than as tidy-up. Choosing to delete still goes through the normal
 * typed confirmation — this is the moment someone is most likely to click
 * through on autopilot.
 */
async function offerBackupCleanup(): Promise<void> {
    const backup = flow.backup;
    if (!backup) return;

    const target = backup.meta.targetSlot;
    let wantsDelete = false;

    await showNotice(
        "Unlock complete",
        [
            `The bootloader is unlocked and the headset is booting slot ` +
                `${flow.originalSlot === 0 ? "_a" : "_b"}. Let it get all the way into the ` +
                "system once so Android marks the slot successful.",
            `The backup of slot ${target} is still stored in this browser. It is what puts ` +
                `${target} back to the firmware it held before the downgrade — that slot ` +
                `still holds ${DOWNGRADE_TARGET} until you restore it.`,
            "Delete it only if you are content to leave the downgraded slot as it is. " +
                "Saving it as a zip first costs nothing.",
        ],
        { label: "Delete the backup", run: () => (wantsDelete = true) },
        "Keep it",
    );

    if (!wantsDelete) {
        log("backup kept", "good");
        return;
    }

    const all = await listBackupSets().catch(() => []);
    await confirmDelete({ ...backup.meta, id: backup.id }, all);
}

/**
 * Deletes a stored backup, asking first.
 *
 * How hard it asks depends on what is being thrown away. A dev rehearsal or a
 * half-finished set is routine cleanup and gets a plain confirm; a complete
 * backup may be the only way to undo a downgrade, so it takes a typed phrase —
 * and says so louder if it is the last complete backup for that headset.
 */
async function confirmDelete(
    set: BackupSetMeta,
    all: readonly BackupSetMeta[],
): Promise<void> {
    if (!set.id) return;

    const complete = set.complete === true;
    const siblings = all.filter(
        (other) =>
            other.id !== set.id && other.serial === set.serial && other.complete === true,
    );
    const taken = new Date(set.createdAt).toLocaleString();

    if (!complete) {
        let confirmed = false;
        await showNotice(
            "Delete this backup?",
            [
                set.mode === "dev"
                    ? `A dev-mode rehearsal set from ${taken}. It is a deliberate subset and ` +
                      "cannot restore a device, so removing it loses nothing."
                    : `An incomplete set from ${taken}, holding ${set.entries.length} of ` +
                      `${set.expected?.length ?? "?"} partitions. It cannot fully restore a slot.`,
                "This cannot be undone.",
            ],
            { label: "Delete permanently", run: () => (confirmed = true) },
            "Cancel",
        );
        if (!confirmed) return;
    } else {
        const body = [
            `A complete backup of slot ${set.targetSlot} from ${taken}, holding all ` +
                `${set.entries.length} partitions of ${set.serial}.`,
            siblings.length === 0
                ? "This is the ONLY complete backup stored for this headset. If you have " +
                  "not saved it as a zip, deleting it means there is no way to undo a " +
                  "downgrade of that slot."
                : `${siblings.length} other complete backup(s) for this headset remain.`,
            "This cannot be undone.",
            `To delete, type: delete ${set.serial}`,
        ];
        const accepted = await askConfirmation({
            heading: "Delete a complete backup",
            body,
            phrase: `delete ${set.serial}`,
        });
        if (!accepted) {
            log("delete cancelled", "warn");
            return;
        }
    }

    await withBusy(async () => {
        await deleteBackupSet(set.id!);
        log(`deleted backup ${set.id}`, "warn");
        setStatus("Backup deleted.", "idle");
        await renderBackups();
    });
}

/**
 * Standalone recovery: root the connected headset and write a stored backup
 * back. Gated behind the same typed confirmation as any other partition write.
 */
async function startRestore(id: string): Promise<void> {
    await withBusy(async () => {
        const adb = flow.adb;
        if (!adb) {
            throw new Error("connect the headset over ADB first");
        }

        const plan = await planRestore(adb, id);
        const slot = plan.items[0]!.slotSuffix;

        const body = [
            `This writes ${plan.items.length} partitions (${formatBytes(plan.totalBytes)}) ` +
                `back over slot ${slot}, overwriting whatever is there now.`,
            `The backup was taken from ${plan.meta.serial} on ` +
                `${new Date(plan.meta.createdAt).toLocaleString()}, running ${plan.meta.fingerprint}.`,
        ];
        if (!plan.serialMatches) {
            body.push(
                `WARNING: the connected headset is ${plan.connectedSerial}, not ` +
                    `${plan.meta.serial}. These images belong to a different device.`,
            );
        }
        if (!plan.meta.complete) {
            body.push(
                plan.meta.mode === "dev"
                    ? "WARNING: this is a dev-mode rehearsal subset, not a device backup. " +
                          "The partitions it does not contain will keep whatever is on them now."
                    : `WARNING: this backup is marked incomplete — it holds ` +
                          `${plan.items.length} of ${plan.meta.expected?.length ?? "?"} partitions. ` +
                          "Restoring it will not fully recover the slot.",
            );
        }
        body.push("The headset will be rooted with ionstack first.");
        body.push(`To continue, type: restore ${slot}`);

        const accepted = await askConfirmation({
            heading: `Restore backup to slot ${slot}`,
            body,
            phrase: `restore ${slot}`,
        });
        if (!accepted) {
            log("restore cancelled at the confirmation dialog", "warn");
            return;
        }

        setStatus(`Restoring ${plan.items.length} partitions to ${slot}…`, "busy");

        const ionstack = await fetchAsset(plan.profile.ionstack, {
            what: `ionstack build for ${plan.profile.label}`,
        });
        log(`${plan.profile.ionstack} verified (${ionstack.length} bytes)`);

        await runRestore(adb, plan, ionstack, {
            onLog: log,
            onProgress: (label, transferred, total) => {
                setStatus(
                    `${label} — ${formatBytes(transferred)} / ${formatBytes(total)}`,
                    "busy",
                );
            },
        });

        setStatus(`Restored slot ${slot} from backup.`, "ok");
    });
}

// ------------------------------------------------------------- confirmation

function askConfirmation(
    confirmation: Confirmation,
    onRevert?: () => void,
): Promise<boolean> {
    return new Promise((resolve) => {
        dialogHeading.textContent = confirmation.heading;
        dialogBody.replaceChildren();
        for (const paragraph of confirmation.body) {
            const p = document.createElement("p");
            p.textContent = paragraph;
            dialogBody.append(p);
        }
        dialogPhrase.textContent = confirmation.phrase;
        dialogInput.value = "";
        dialogOk.disabled = true;
        dialogRevert.hidden = !confirmation.offerRevert || !onRevert;

        const check = () => {
            dialogOk.disabled = dialogInput.value.trim() !== confirmation.phrase;
        };
        const finish = (result: boolean) => {
            dialogInput.removeEventListener("input", check);
            dialogOk.removeEventListener("click", accept);
            dialogCancel.removeEventListener("click", cancel);
            dialogRevert.removeEventListener("click", revert);
            dialog.close();
            resolve(result);
        };
        const accept = () => {
            if (dialogInput.value.trim() === confirmation.phrase) finish(true);
        };
        const cancel = () => finish(false);
        const revert = () => {
            finish(false);
            onRevert?.();
        };

        dialogInput.addEventListener("input", check);
        dialogOk.addEventListener("click", accept);
        dialogCancel.addEventListener("click", cancel);
        dialogRevert.addEventListener("click", revert);

        dialog.showModal();
        dialogInput.focus();
    });
}

/**
 * A dialog that only informs — no phrase to type.
 *
 * `action` adds a second button; its click is a user gesture, which matters
 * because `requestDevice` will not open a picker without one.
 */
function showNotice(
    heading: string,
    body: string[],
    action?: { label: string; run: () => void },
    dismissLabel = "OK",
): Promise<void> {
    return new Promise((resolve) => {
        noticeOk.textContent = dismissLabel;
        noticeHeading.textContent = heading;
        noticeBody.replaceChildren();
        for (const paragraph of body) {
            const p = document.createElement("p");
            p.textContent = paragraph;
            noticeBody.append(p);
        }

        noticeAction.hidden = !action;
        if (action) {
            noticeAction.textContent = action.label;
        }

        const finish = (run?: () => void) => {
            noticeOk.removeEventListener("click", close);
            noticeAction.removeEventListener("click", act);
            noticeDialog.close();
            resolve();
            run?.();
        };
        const close = () => finish();
        const act = () => finish(action?.run);

        noticeOk.addEventListener("click", close);
        noticeAction.addEventListener("click", act);
        noticeDialog.showModal();
        (action ? noticeAction : noticeOk).focus();
    });
}

// -------------------------------------------------------------- connections

async function withBusy(action: () => Promise<void>): Promise<void> {
    busy = true;
    render();
    try {
        await action();
    } catch (error) {
        console.error(error);
        const message = error instanceof Error ? error.message : String(error);
        log(message, "error");
        setStatus(message, "error");
    } finally {
        busy = false;
        render();
    }
}

async function connectAdb(device: AdbDaemonWebUsbDevice): Promise<void> {
    setStatus(`Opening ${device.name} (${device.serial})…`, "busy");
    const connection = await device.connect();

    setStatus("Authenticating — accept the prompt inside the headset…", "busy");
    const transport = await AdbDaemonTransport.authenticate({
        serial: device.serial,
        connection,
        credentialStore,
    });

    const adb = new Adb(transport);
    flow.adb = adb;
    log(`connected to ${adb.serial}`, "good");

    void transport.disconnected.then(() => {
        if (flow.adb?.transport === transport) {
            flow.adb = undefined;
            disconnectButton.disabled = true;
            setStatus("Headset disconnected.", "idle");
            render();
        }
    });

    // Show what we are looking at straight away, before any step runs.
    flow.identity = await identify(adb);
    disconnectButton.disabled = false;
    setStatus(`Connected to ${adb.serial}.`, "ok");
    render();
}

connectButton.addEventListener("click", () => {
    void withBusy(async () => {
        const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
        if (!manager) {
            throw new Error("WebUSB is unavailable. Use Chrome or Edge over localhost.");
        }
        const device = await manager.requestDevice({
            filters: [{ vendorId: OCULUS_VENDOR_ID }],
        });
        if (!device) {
            setStatus("No device selected.", "idle");
            return;
        }
        await connectAdb(device);
    });
});

function connectFastboot(): void {
    void withBusy(async () => {
        const device = (await FastbootDevice.request()) ?? (await FastbootDevice.find());
        if (!device) {
            setStatus("No fastboot device selected.", "idle");
            return;
        }
        await device.open();
        flow.fastboot = device;
        log(`fastboot: ${device.productName} (${device.serial})`, "good");

        const info = await device.deviceInfo();
        for (const [key, value] of info) {
            log(`  ${key}: ${value}`);
        }
        setStatus(`Bootloader connected (${device.serial}).`, "ok");
    });
}

connectFastbootButton.addEventListener("click", connectFastboot);

disconnectButton.addEventListener("click", () => {
    void withBusy(async () => {
        const adb = flow.adb;
        flow.adb = undefined;
        disconnectButton.disabled = true;
        await adb?.close();
        await flow.fastboot?.close();
        flow.fastboot = undefined;
        setStatus("Disconnected.", "idle");
    });
});

// -------------------------------------------------------------------- steps

function runRevert(): void {
    void withBusy(async () => {
        const step = flow.current;
        await flow.revertToBackup((label, transferred, total) => {
            if (step) {
                step.progress = { label, transferred, total };
                render();
            }
        });
        await renderBackups();
    });
}

async function runCurrentStep(): Promise<void> {
    const step = flow.current;
    if (!step) return;

    const confirmation = flow.confirmationFor(step);
    if (confirmation) {
        const accepted = await askConfirmation(
            confirmation,
            confirmation.offerRevert ? runRevert : undefined,
        );
        if (!accepted) {
            log(`${step.title}: cancelled at the confirmation dialog`, "warn");
            return;
        }
        log(`${step.title}: confirmed by typing "${confirmation.phrase}"`, "warn");
    }

    setStatus(`Running: ${step.title}…`, "busy");
    const ok = await flow.runNext();
    if (ok) {
        setStatus(`${step.title} — done.`, "ok");
        if (step.id === "backup" || step.id === "verify-backup") {
            await renderBackups();
        }
        if (step.id === "boot-os") {
            await offerBackupCleanup();
        }
        if (step.id === "bootloader" || step.id === "dev-bootloader") {
            setStatus("Headset is rebooting into fastboot.", "warn");
            await showNotice(
                "Reconnect over fastboot",
                [
                    "The headset is rebooting into its bootloader. It comes back as a " +
                        "different USB device (product id 0x81), so the ADB permission you " +
                        "granted earlier does not cover it.",
                    "Wait for the boot logo to settle, then grant access to the new device " +
                        "in the picker. On Windows that interface must also be bound to " +
                        "WinUSB, separately from the ADB one.",
                    "If no device appears, unplug and replug the cable and try again.",
                    ...(flow.mode === "dev"
                        ? [
                              "Nothing has been written and no slot was changed. To go back " +
                                  "to Android: fastboot reboot, or hold the power button.",
                          ]
                        : []),
                ],
                { label: "Choose the fastboot device", run: connectFastboot },
            );
        }
    } else {
        setStatus(`${step.title} — failed. See the log.`, "error");
    }
}

runStepButton.addEventListener("click", () => {
    void withBusy(runCurrentStep);
});

retryStepButton.addEventListener("click", () => {
    const step = flow.current;
    if (!step) return;
    flow.reset(step.id);
    void withBusy(runCurrentStep);
});

devModeToggle.addEventListener("change", () => {
    if (!DEV_AVAILABLE) {
        devModeToggle.checked = false;
        return;
    }
    const mode: FlowMode = devModeToggle.checked ? "dev" : "unlock";
    if (mode === flow.mode) return;

    // Switching mode restarts the procedure; carry the live connections over
    // so the user does not have to re-grant USB permission.
    const { adb, fastboot, devMaxPartitionBytes } = flow;
    flow = new Flow(flowEvents, mode);
    flow.adb = adb;
    flow.fastboot = fastboot;
    flow.devMaxPartitionBytes = devMaxPartitionBytes;

    devBanner.hidden = mode !== "dev";
    const url = new URL(location.href);
    if (mode === "dev") {
        url.searchParams.set("dev", "1");
    } else {
        url.searchParams.delete("dev");
    }
    history.replaceState(null, "", url);

    log(
        mode === "dev"
            ? "dev mode on — read-only rehearsal, nothing will be written"
            : "dev mode off — the real unlock procedure",
        "warn",
    );
    setStatus(
        mode === "dev" ? "Dev mode: read-only." : "Unlock mode.",
        mode === "dev" ? "warn" : "idle",
    );
    render();
});

devCapInput.addEventListener("change", () => {
    const mib = Number(devCapInput.value);
    if (!Number.isFinite(mib) || mib < 1) {
        devCapInput.value = String(flow.devMaxPartitionBytes / 1048576);
        return;
    }
    flow.devMaxPartitionBytes = Math.round(mib) * 1048576;
    log(`dev backup size cap set to ${Math.round(mib)} MiB`, "warn");
});

importBackupButton.addEventListener("click", () => importFilesInput.click());

importFilesInput.addEventListener("change", () => {
    const files = [...(importFilesInput.files ?? [])];
    importFilesInput.value = "";
    if (files.length === 0) return;

    void withBusy(async () => {
        const zips = files.filter((file) => file.name.toLowerCase().endsWith(".zip"));
        if (zips.length > 1) {
            throw new Error("select one zip at a time");
        }

        const slot = flow.identity?.slotSuffix === "_a" ? "_b" : "_a";
        const createdAt = new Date().toISOString();
        const serial = flow.adb?.serial ?? "imported";
        const fingerprint = flow.identity?.fingerprint ?? "(imported from disk)";

        setStatus("Reading the archive…", "busy");

        const result = zips.length === 1
            ? await importBackupZip(zips[0]!, { serial, fingerprint, createdAt })
            : {
                  ...(await importBackupSet(files, {
                      serial,
                      fingerprint,
                      expected: PARTITIONS.map((name) => backupEntryName(name, slot)),
                      createdAt,
                  })),
                  corrupt: [] as string[],
              };

        const { set, slotSuffix, imported, ignored, corrupt } = result;

        log(`imported ${imported.length} images for slot ${slotSuffix}`, "good");
        for (const name of imported) {
            log(`  ${name}`);
        }
        if (ignored.length > 0) {
            log(`ignored (not partition images): ${ignored.join(", ")}`, "warn");
        }
        if (corrupt.length > 0) {
            log(
                `NOT imported — bytes did not match the hash recorded in the archive: ` +
                    corrupt.join(", "),
                "error",
            );
        }
        if (!set.meta.complete) {
            log(
                `this import covers ${imported.length} partitions and is marked ` +
                    "incomplete — it will not fully recover a slot",
                "warn",
            );
        }
        setStatus(
            `Imported ${imported.length} images${corrupt.length > 0 ? `, ${corrupt.length} rejected` : ""}.`,
            corrupt.length > 0 ? "error" : "ok",
        );
        await renderBackups();
    });
});

rebootBootloaderButton.addEventListener("click", () => {
    void withBusy(async () => {
        const device = flow.fastboot;
        if (!device?.opened) {
            throw new Error("no bootloader is connected");
        }
        setStatus("Rebooting the bootloader…", "busy");
        flow.fastboot = await rebootToBootloader(device, { onLog: (line) => log(line) });

        const info = await flow.fastboot.deviceInfo();
        for (const [key, value] of info) {
            log(`  ${key}: ${value}`);
        }
        setStatus(`Bootloader back (${flow.fastboot.serial}).`, "ok");
    });
});

copyLogButton.addEventListener("click", () => {
    void navigator.clipboard
        .writeText(logElement.textContent ?? "")
        .then(() => log("log copied to clipboard"));
});

// --------------------------------------------------------------- start-up

void (async () => {
    if (!DEV_AVAILABLE) {
        // Remove the control rather than disabling it: there is nothing behind
        // it in a production build.
        devModeToggle.closest("label")?.remove();
    }
    devModeToggle.checked = initialMode === "dev";
    devBanner.hidden = initialMode !== "dev";
    devCapInput.value = String(flow.devMaxPartitionBytes / 1048576);
    render();
    await renderBackups();

    if (!AdbDaemonWebUsbDeviceManager.BROWSER) {
        connectButton.disabled = true;
        connectFastbootButton.disabled = true;
        setStatus(
            "WebUSB is unavailable in this browser. Use Chrome or Edge over https or localhost.",
            "error",
        );
        return;
    }

    setStatus(
        `Ready — plug in the ${DEVICE.model} and click “Connect headset”.`,
        "idle",
    );

    const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
    const [device] = await manager.getDevices({
        filters: [{ vendorId: OCULUS_VENDOR_ID }],
    });
    if (device) {
        log(`found an already-permitted device: ${device.name} (${device.serial})`);
        await withBusy(() => connectAdb(device));
    }
})();
