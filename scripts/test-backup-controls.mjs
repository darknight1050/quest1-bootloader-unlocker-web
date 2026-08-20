// Reproduces the import-then-disabled bug against the real control logic.
let busy = false;
let adb = undefined;
const backupControls = [];

// lifted verbatim from src/main.ts
function syncBackupControls() {
    for (const { el, needsDevice } of backupControls) {
        el.disabled = busy || (needsDevice && !adb);
    }
}
function render() { syncBackupControls(); }
async function withBusy(action) {
    busy = true; render();
    try { await action(); } finally { busy = false; render(); }
}

function renderBackups(hasId = true) {
    backupControls.length = 0;
    const restore = { disabled: false }, save = { disabled: false }, remove = { disabled: false };
    if (hasId) {
        backupControls.push(
            { el: restore, needsDevice: true },
            { el: save, needsDevice: false },
            { el: remove, needsDevice: false },
        );
    } else {
        for (const b of [restore, save, remove]) b.disabled = true;
    }
    syncBackupControls();
    return { restore, save, remove };
}

const checks = [];
const check = (n, ok) => checks.push([n, ok]);

// --- the reported bug: import runs inside withBusy -------------------------
let buttons;
await withBusy(async () => { buttons = renderBackups(); });
check("after import: delete enabled", buttons.remove.disabled === false);
check("after import: save enabled", buttons.save.disabled === false);
check("after import: restore disabled (no device)", buttons.restore.disabled === true);

// --- connecting a device later must enable restore, no re-render ----------
adb = { serial: "TEST" };
render();
check("after connect: restore enabled", buttons.restore.disabled === false);
check("after connect: delete still enabled", buttons.remove.disabled === false);

// --- during a later busy operation everything locks ------------------------
busy = true; render();
check("during work: all disabled",
    buttons.restore.disabled && buttons.save.disabled && buttons.remove.disabled);
busy = false; render();
check("after work: re-enabled",
    !buttons.restore.disabled && !buttons.save.disabled && !buttons.remove.disabled);

// --- a set with no storage handle stays dead ------------------------------
const orphan = renderBackups(false);
check("no id: stays disabled",
    orphan.restore.disabled && orphan.save.disabled && orphan.remove.disabled);

let failed = 0;
for (const [n, ok] of checks) { console.log(ok ? "  PASS" : "  FAIL", n); if (!ok) failed++; }
console.log(failed === 0 ? "\nbackup controls OK" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
