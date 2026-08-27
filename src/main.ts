import { Adb, AdbDaemonTransport } from "@yume-chan/adb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import {
    AdbDaemonWebUsbDevice,
    AdbDaemonWebUsbDeviceManager,
} from "@yume-chan/adb-daemon-webusb";

import { fetchAsset } from "./lib/assets.js";
import { identify } from "./lib/device.js";
import { FastbootDevice, rebootToBootloader } from "./lib/fastboot.js";
import { Flow, type Confirmation } from "./lib/flow.js";
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
import { backupEntryName } from "./lib/partitions.js";
import { PROFILES } from "./data/profiles.js";

const OCULUS_VENDOR_ID = 0x2833;

const $ = <T extends HTMLElement>(id: string): T =>
    document.getElementById(id) as T;

const connectButton = $<HTMLButtonElement>("connect");
const connectFastbootButton = $<HTMLButtonElement>("connect-fastboot");
const disconnectButton = $<HTMLButtonElement>("disconnect");
const runStepButton = $<HTMLButtonElement>("run-step");
const retryStepButton = $<HTMLButtonElement>("retry-step");
const skipStepButton = $<HTMLButtonElement>("skip-step");
const unlockNowButton = $<HTMLButtonElement>("unlock-now");
const directUnlockRow = $<HTMLDivElement>("direct-unlock-row");
const rebootBootloaderButton = $<HTMLButtonElement>("reboot-bootloader");
const stepHint = $<HTMLSpanElement>("step-hint");
const statusText = $<HTMLParagraphElement>("status");
const deviceEmpty = $<HTMLParagraphElement>("device-empty");
const propsTable = $<HTMLTableElement>("props");
const fingerprintOutput = $<HTMLOutputElement>("fingerprint");
const propsBody = $<HTMLTableElement>("props").tBodies[0]!;
const gatesList = $<HTMLUListElement>("gates");
const stepsList = $<HTMLOListElement>("steps");
const backupsBox = $<HTMLDivElement>("backups");
const logElement = $<HTMLPreElement>("log");
const copyLogButton = $<HTMLButtonElement>("copy-log");
const unsupportedBox = $<HTMLDivElement>("unsupported");
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

const noticeDialog = $<HTMLDialogElement>("notice-dialog");
const noticeHeading = $<HTMLHeadingElement>("notice-heading");
const noticeBody = $<HTMLDivElement>("notice-body");
const noticeOk = $<HTMLButtonElement>("notice-ok");
const noticeAction = $<HTMLButtonElement>("notice-action");

const credentialStore = new AdbWebCredentialStore("quest1-unlocker-web");

let busy = false;

const flowEvents = { onLog: log, onChange: render };

let flow = new Flow(flowEvents);

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
    renderConnection();
    renderDevice();
    renderSteps();
    renderActions();
    syncBackupControls();
}

/** Set once WebUSB has been ruled out; nothing here can be connected then. */
let webusbBlocked = false;

/**
 * Keeps the three connection buttons honest about what is connected.
 *
 * Each transport is offered only while it is not already open, and
 * Disconnect only while there is something to disconnect.
 */
function renderConnection(): void {
    const adbConnected = flow.adb !== undefined;
    const fastbootConnected = flow.fastboot?.opened === true;

    connectButton.disabled =
        webusbBlocked || busy || adbConnected || fastbootConnected;
    connectButton.title = adbConnected
        ? "The headset is already connected over ADB"
        : fastbootConnected
          ? "The headset is in its bootloader — it does not answer adb there"
          : "Talks ADB to the running system";

    // A headset in fastboot is not answering adb, so a live ADB session means
    // there is nothing to connect to on the fastboot side.
    connectFastbootButton.disabled =
        webusbBlocked || busy || fastbootConnected || adbConnected;
    connectFastbootButton.title = fastbootConnected
        ? "The bootloader is already connected over fastboot"
        : adbConnected
          ? "The headset is connected over ADB — reboot it into fastboot first"
          : "Talks fastboot to the bootloader";

    disconnectButton.disabled =
        webusbBlocked || busy || !(adbConnected || fastbootConnected);

    // The shortcut is only meaningful while the flow has not reached the
    // unlock itself: past that point there is nothing left for it to skip.
    const unlockIndex = flow.steps.findIndex((step) => step.id === "unlock");
    const currentIndex = flow.current ? flow.steps.indexOf(flow.current) : flow.steps.length;
    directUnlockRow.hidden = !(fastbootConnected && currentIndex < unlockIndex);
    unlockNowButton.disabled = busy;
}

function renderDevice(): void {
    const identity = flow.identity;

    // The panel stays put either way: a column that loses a box when the
    // headset is unplugged reads as something having gone wrong.
    if (!identity) {
        deviceEmpty.hidden = false;
        fingerprintOutput.hidden = true;
        propsTable.hidden = true;
        propsBody.replaceChildren();
        gatesList.replaceChildren();
        return;
    }

    deviceEmpty.hidden = true;
    fingerprintOutput.hidden = false;
    propsTable.hidden = false;
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
        // Done steps clamp this to one line; keep the rest reachable.
        detail.title = step.detail;

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
        skipStepButton.hidden = true;
        rebootBootloaderButton.disabled = true;
        stepHint.textContent = "working…";
        return;
    }

    if (!step) {
        runStepButton.disabled = true;
        runStepButton.textContent = "All steps complete";
        retryStepButton.hidden = true;
        skipStepButton.hidden = true;
        rebootBootloaderButton.hidden = true;
        stepHint.textContent = "";
        return;
    }

    const failed = step.state === "failed";
    retryStepButton.hidden = !failed;
    skipStepButton.hidden = !flow.canSkip(step);
    skipStepButton.disabled = busy;
    skipStepButton.textContent = `Skip: ${step.title}`;
    skipStepButton.title =
        "Leaves this step unrun. It is optional because this run did not " +
        "downgrade anything.";

    // A missed overflow leaves the bootloader in an unknown state, so retrying
    // is only meaningful after a clean boot.
    const fastbootStep = FASTBOOT_STEPS.includes(step.id);
    rebootBootloaderButton.hidden = !(fastbootStep && flow.fastboot?.opened);
    rebootBootloaderButton.disabled = busy;
    rebootBootloaderButton.title =
        "Sends reboot-bootloader and reconnects — use this before retrying the unlock";
    runStepButton.textContent = failed ? `Run "${step.title}" again` : `Run: ${step.title}`;

    const needsFastboot = FASTBOOT_STEPS.includes(step.id);
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
        badge.textContent = complete ? "complete" : "incomplete";
        title.append(badge);

        // Separate from completeness: one says how much is here, the other
        // says whether what is here has been read back and checked.
        const verified = document.createElement("span");
        verified.className = set.verifiedAt
            ? "badge badge-verified"
            : "badge badge-unverified";
        verified.textContent = set.verifiedAt ? "verified" : "unverified";
        verified.title = set.verifiedAt
            ? `Every image was re-read and matched against the device on ` +
              `${new Date(set.verifiedAt).toLocaleString()}`
            : "Never read back and compared against a device since it was written";
        title.append(verified);

        const detail = document.createElement("span");
        detail.textContent =
            `${new Date(set.createdAt).toLocaleString()} — ${set.fingerprint}` +
            (set.verifiedAt
                ? ` — verified ${new Date(set.verifiedAt).toLocaleString()}`
                : "");

        box.append(title, detail);

        if (!complete) {
            const warning = document.createElement("span");
            warning.className = "step-error";
            warning.textContent =
                `Incomplete: holds ${set.entries.length} of ${set.expected?.length ?? "?"} ` +
                "partitions. Restoring it will not fully recover the slot.";
            box.append(warning);
        }

        if (!set.verifiedAt) {
            const warning = document.createElement("span");
            warning.className = "backup-warning";
            warning.textContent =
                "Never verified: these images have not been read back out of storage " +
                "and checked against a device since they were written. A backup you " +
                "have not verified is a backup you do not know you have.";
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
            "It restarts itself several times on the way there — that is a first boot " +
                "after a wipe, not a boot loop. Leave it plugged in and do not interrupt " +
                "it until it reaches the setup screen.",
            "If it still comes up saying the device is corrupt and cannot be trusted, " +
                "reset it from the headset itself: hold power and volume-down until the " +
                "boot menu appears, then pick Factory Reset. That erases /data only; the " +
                "unlock survives it.",
            `The backup of slot ${target} is still stored in this browser. It is what puts ` +
                `${target} back to the firmware it held before the downgrade — that slot ` +
                `still holds ${flow.profile.downgradeTarget} until you restore it.`,
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
 * How hard it asks depends on what is being thrown away. A half-finished set
 * is routine cleanup and gets a plain confirm; a complete
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
                `An incomplete set from ${taken}, holding ${set.entries.length} of ` +
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
                `WARNING: this backup is marked incomplete — it holds ${plan.items.length} ` +
                    `of ${plan.meta.expected?.length ?? "?"} partitions. Restoring it will ` +
                    "not fully recover the slot.",
            );
        }
        if (!plan.meta.verifiedAt) {
            body.push(
                "WARNING: this backup has never been verified — nothing has read it " +
                    "back out of storage and compared it to a device since it was " +
                    "written. The hashes recorded at the time are all there is to go " +
                    "on, and browser storage can rot underneath them.",
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

        // Every way out of the dialog has to land here exactly once. A
        // <dialog> can also be closed by the browser — Escape, or the form's
        // implicit submission — and a close that did not resolve this promise
        // would leave the caller awaiting forever with the UI stuck busy.
        let settled = false;
        const finish = (result: boolean) => {
            if (settled) return;
            settled = true;
            dialogInput.removeEventListener("input", check);
            dialogInput.removeEventListener("keydown", onKeydown);
            dialogOk.removeEventListener("click", accept);
            dialogCancel.removeEventListener("click", cancel);
            dialogRevert.removeEventListener("click", revert);
            dialog.removeEventListener("close", onClose);
            if (dialog.open) {
                dialog.close();
            }
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
        // Enter in the field would otherwise submit the form and close the
        // dialog behind our back. Treat it as pressing Continue, and as
        // nothing at all while the phrase does not match.
        const onKeydown = (event: KeyboardEvent) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            accept();
        };
        // Escape, or anything else that closes it: the same as cancelling.
        const onClose = () => finish(false);

        dialogInput.addEventListener("input", check);
        dialogInput.addEventListener("keydown", onKeydown);
        dialogOk.addEventListener("click", accept);
        dialogCancel.addEventListener("click", cancel);
        dialogRevert.addEventListener("click", revert);
        dialog.addEventListener("close", onClose);

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

        // As in askConfirmation: Escape and implicit submission close the
        // dialog without going through these buttons, and a caller left
        // awaiting a promise that never settles locks the page.
        let settled = false;
        const finish = (run?: () => void) => {
            if (settled) return;
            settled = true;
            noticeOk.removeEventListener("click", close);
            noticeAction.removeEventListener("click", act);
            noticeDialog.removeEventListener("close", onClose);
            if (noticeDialog.open) {
                noticeDialog.close();
            }
            resolve();
            run?.();
        };
        const close = () => finish();
        const act = () => finish(action?.run);
        // Dismissed by the browser: the same as pressing the dismiss button,
        // never the action — that one only ever runs from a real click.
        const onClose = () => finish();

        noticeOk.addEventListener("click", close);
        noticeAction.addEventListener("click", act);
        noticeDialog.addEventListener("close", onClose);
        noticeDialog.showModal();
        (action ? noticeAction : noticeOk).focus();
    });
}

// -------------------------------------------------------------- connections

interface WebusbProblem {
    readonly heading: string;
    readonly body: string[];
}

/**
 * Why WebUSB cannot be used here, if it cannot.
 *
 * There are three separate reasons this fails and only one of them is "wrong
 * browser", so they are reported apart: telling someone on Firefox to switch
 * to https, or someone on plain http to install Chrome, sends them off fixing
 * the wrong thing.
 */
function webusbProblem(): WebusbProblem | undefined {
    if (navigator.usb && AdbDaemonWebUsbDeviceManager.BROWSER) {
        return undefined;
    }

    if (!window.isSecureContext) {
        return {
            heading: "This page is not in a secure context, so WebUSB is switched off.",
            body: [
                `It is being served from ${window.location.origin}. Browsers only expose ` +
                    "WebUSB over https, or over http from localhost / 127.0.0.1.",
                "Open the same page over https, or run it locally with " +
                    "`npm run dev` and use the http://localhost address it prints.",
            ],
        };
    }

    if (window.self !== window.top) {
        return {
            heading: "WebUSB is blocked inside this frame.",
            body: [
                "The page is embedded in another one, and USB access is not delegated " +
                    "to it. Open it in a tab of its own.",
            ],
        };
    }

    return {
        heading: "This browser has no WebUSB.",
        body: [
            "Firefox and Safari do not implement WebUSB and have both declined to. " +
                "There is no flag or extension that changes that.",
            "Use a Chromium-based browser — Chrome, Edge, Brave, Opera or Vivaldi. " +
                "Chrome on Android works too, as long as the phone is the USB host " +
                "(a USB-C cable or an OTG adapter to the headset).",
            "If you are already in one of those, WebUSB can also be turned off by " +
                "enterprise policy (WebUsbAllowDevicesForUrls / DefaultWebUsbGuardSetting) " +
                "— check chrome://policy, or try a personal profile.",
        ],
    };
}

function showUnsupported({ heading, body }: WebusbProblem): void {
    unsupportedBox.replaceChildren();

    const title = document.createElement("strong");
    title.textContent = heading;
    unsupportedBox.append(title);

    for (const paragraph of body) {
        const p = document.createElement("p");
        p.textContent = paragraph;
        unsupportedBox.append(p);
    }
    unsupportedBox.hidden = false;
}

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

/**
 * The USB handle behind {@link Flow.adb}, kept so it can be closed directly.
 *
 * Closing the `Adb` is not always enough: a handshake that never finished
 * leaves no `Adb` at all, but the interface stays claimed.
 */
let adbDevice: AdbDaemonWebUsbDevice | undefined;

/** How long to wait for the daemon to answer before giving up on a handshake. */
const HANDSHAKE_TIMEOUT_MS = 30_000;

/**
 * Drops the current ADB session and releases the USB interface.
 *
 * Both halves matter. Anything still reading the ADB endpoint consumes the
 * packets the *next* handshake is waiting for, so a stale reader does not
 * fail the reconnect — it hangs it, forever, at "Authenticating…".
 */
async function releaseAdb(): Promise<void> {
    const adb = flow.adb;
    flow.adb = undefined;
    if (adb) {
        try {
            await adb.close();
        } catch {
            // Already gone; nothing to release.
        }
    }

    const device = adbDevice;
    adbDevice = undefined;
    if (device?.raw.opened) {
        try {
            await device.raw.close();
        } catch {
            // Same.
        }
    }
}

async function connectAdb(device: AdbDaemonWebUsbDevice): Promise<void> {
    // A previous session still holding the interface would swallow this one's
    // handshake, so it has to be gone first.
    await releaseAdb();
    adbDevice = device;

    setStatus(`Opening ${device.name} (${device.serial})…`, "busy");
    const connection = await device.connect();

    setStatus("Authenticating — accept the prompt inside the headset…", "busy");
    const attempt = AdbDaemonTransport.authenticate({
        serial: device.serial,
        connection,
        credentialStore,
    });

    // Without a deadline a daemon that never answers leaves the page busy and
    // every button disabled, with a reload as the only way out.
    let timer: ReturnType<typeof setTimeout> | undefined;
    let transport;
    try {
        transport = await Promise.race([
            attempt,
            new Promise<never>((_, reject) => {
                timer = setTimeout(
                    () =>
                        reject(
                            new Error(
                                "the headset did not answer the ADB handshake within " +
                                    `${HANDSHAKE_TIMEOUT_MS / 1000}s. If the “Allow USB ` +
                                    "debugging” dialog is up inside the headset, accept it " +
                                    "and click Connect again. Otherwise unplug and replug " +
                                    "the cable.",
                            ),
                        ),
                    HANDSHAKE_TIMEOUT_MS,
                );
            }),
        ]);
    } catch (error) {
        // The losing promise must not surface later as an unhandled rejection.
        attempt.catch(() => {});
        await releaseAdb();
        throw error;
    } finally {
        clearTimeout(timer);
    }

    const adb = new Adb(transport);
    flow.adb = adb;
    log(`connected to ${adb.serial}`, "good");

    void transport.disconnected.then(() => {
        if (flow.adb?.transport === transport) {
            flow.adb = undefined;
            adbDevice = undefined;
            setStatus("Headset disconnected.", "idle");
            render();
        }
    });

    // Show what we are looking at straight away, before any step runs.
    flow.identity = await identify(adb);
    setStatus(`Connected to ${adb.serial}.`, "ok");
    render();
}

connectButton.addEventListener("click", () => {
    void withBusy(async () => {
        const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
        if (!manager) {
            throw new Error(webusbProblem()?.heading ?? "WebUSB is unavailable.");
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
        await releaseAdb();
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

/** Steps that talk to the bootloader rather than to a running system. */
const FASTBOOT_STEPS = ["unlock", "restore-slot", "factory-reset", "boot-os"];

/**
 * Hands the user the USB picker for the bootloader.
 *
 * Every restart re-enumerates it, and a page cannot re-open a device it has
 * not been granted — `requestDevice` needs a real click, which is what the
 * button in this dialog provides. On Android the grant often does not survive
 * the reconnect at all, so this is the way out of a wait that would otherwise
 * never finish.
 */
async function offerFastbootPicker(intro: string): Promise<void> {
    await showNotice(
        "Reconnect over fastboot",
        [
            intro,
            "The bootloader is a different USB device (product id 0x81) from the ADB " +
                "one, and it comes back as a new device every time it restarts, so the " +
                "permission you granted before may no longer cover it.",
            "Wait for the boot logo to settle, then pick the device. On Windows that " +
                "interface must also be bound to WinUSB, separately from the ADB one.",
            "If no device appears, unplug and replug the cable and try again.",
        ],
        { label: "Choose the fastboot device", run: connectFastboot },
    );
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
        if (step.id === "backup") {
            await renderBackups();
        }
        if (step.id === "boot-os") {
            await offerBackupCleanup();
        }
        if (step.id === "bootloader") {
            setStatus("Headset is rebooting into fastboot.", "warn");
            await offerFastbootPicker("The headset is rebooting into its bootloader.");
        }
    } else {
        setStatus(`${step.title} — failed. See the log.`, "error");

        // A fastboot step that ends with no bootloader attached failed because
        // the device went away and could not be picked up again on its own.
        // Offer the picker rather than leaving the user to find the button.
        if (FASTBOOT_STEPS.includes(step.id) && !flow.fastboot?.opened) {
            await offerFastbootPicker(
                "The step stopped because the bootloader is no longer connected — it " +
                    "leaves the bus whenever it restarts.",
            );
        }
    }
}

runStepButton.addEventListener("click", () => {
    void withBusy(runCurrentStep);
});

unlockNowButton.addEventListener("click", () => {
    void withBusy(async () => {
        await flow.startDirectUnlock();
        setStatus(
            `Ready to unlock this ${flow.profile.label} — the downgrade steps were skipped.`,
            "warn",
        );
    });
});

skipStepButton.addEventListener("click", () => {
    const step = flow.current;
    if (!step) return;
    flow.skipCurrent();
    log(`${step.title}: skipped`, "warn");
    setStatus(`${step.title} — skipped.`, "idle");
    render();
});

retryStepButton.addEventListener("click", () => {
    const step = flow.current;
    if (!step) return;
    flow.reset(step.id);
    void withBusy(runCurrentStep);
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
                      expected: flow.profile.partitions.map((name) =>
                          backupEntryName(name, slot),
                      ),
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
    render();
    await renderBackups();

    const problem = webusbProblem();
    if (problem) {
        webusbBlocked = true;
        render();
        showUnsupported(problem);
        setStatus(problem.heading, "error");
        log(problem.heading, "error");
        for (const line of problem.body) {
            log(`  ${line}`, "error");
        }
        return;
    }

    setStatus(
        `Ready — plug in the headset (${PROFILES.map((p) => p.label).join(" or ")}) ` +
            "and click “Connect headset”.",
        "idle",
    );

    // webusbProblem() has already returned above if this is missing; the
    // check is here to say so to the type checker.
    const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
    if (!manager) {
        return;
    }

    const [device] = await manager.getDevices({
        filters: [{ vendorId: OCULUS_VENDOR_ID }],
    });
    if (device) {
        log(`found an already-permitted device: ${device.name} (${device.serial})`);
        await withBusy(() => connectAdb(device));
    }
})();
