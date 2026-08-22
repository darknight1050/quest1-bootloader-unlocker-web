// Verifies the payload builder against the real firmware archive.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { unzipSync } from "fflate";
import {
    type AblPatch,
    OVERFLOW,
    PATCH_16476800119700000,
    applyPatch,
    buildUnlockPayload,
    buildUnlockPayloadFromAbl,
    extractLinuxLoaderPe,
    patchEnd,
    unlockPatch,
} from "../src/lib/abl.js";

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(" ");

const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const files = unzipSync(zip, { filter: (f) => f.name === "abl.img" });
const abl = files["abl.img"]!;
console.log("abl.img            ", abl.length, "bytes  sha256", sha(abl));

const pristine = await extractLinuxLoaderPe(abl.slice());
console.log("LinuxLoader PE     ", `0x${pristine.length.toString(16)}`, "bytes  sha256", sha(pristine));

const patch = PATCH_16476800119700000;
const first = patch[0]!;
console.log(`patch sites        ${patch.length}: ${patch.map((e) => "0x" + e.offset.toString(16)).join(", ")}`);
console.log("bytes at 0x%s      %s", first.offset.toString(16), hex(pristine.subarray(first.offset, first.offset + 12)));

const { payload, pe } = await buildUnlockPayloadFromAbl(abl.slice());
console.log("patched to         ", hex(pe.subarray(first.offset, first.offset + 4)));
console.log("payload            ", payload.length, `(0x${payload.length.toString(16)})`, "bytes  sha256", sha(payload));

const expectedLength = OVERFLOW + patchEnd(patch);
const checks: [string, boolean][] = [
    ["PE is 0x9a000 bytes", pristine.length === 0x9a000],
    ["PE sha256 matches independently-extracted reference",
        sha(pristine) === "7663280938b54f8dc061b502f581cba4bea638473080c44a8dcfec88a570f74c"],
    [`payload length is 0x100000 + 0x${patchEnd(patch).toString(16)}`, payload.length === expectedLength],
    ["overflow region is all 0x0c", payload.subarray(0, OVERFLOW).every((b) => b === 0x0c)],
    ["every edit is present in the payload at its own offset",
        patch.every((e) => hex(payload.subarray(OVERFLOW + e.offset, OVERFLOW + e.offset + e.replace.length))
            === hex(Uint8Array.from(e.replace)))],
    ["image body copied verbatim up to the first patch site",
        payload.subarray(OVERFLOW, OVERFLOW + first.offset).every((b, i) => b === pristine[i])],
    ["bytes between edits are left untouched", (() => {
        const sorted = [...patch].sort((a, b) => a.offset - b.offset);
        for (let i = 0; i + 1 < sorted.length; i++) {
            const from = sorted[i]!.offset + sorted[i]!.replace.length;
            const to = sorted[i + 1]!.offset;
            for (let a = from; a < to; a++) {
                if (payload[OVERFLOW + a] !== pristine[a]) return false;
            }
        }
        return true;
    })()],
    ["applyPatch rejects a wrong build", (() => {
        const wrong = pristine.slice();
        wrong[first.offset] = 0x00;
        try { applyPatch(wrong, patch); return false; } catch { return true; }
    })()],

    // --- multi-edit support ------------------------------------------------
    ["patchEnd spans the last edit, not the first", (() => {
        const multi: AblPatch = [
            { offset: 0x100, expect: [...pristine.subarray(0x100, 0x104)], replace: [1, 2, 3, 4] },
            { offset: 0x2000, expect: [...pristine.subarray(0x2000, 0x2004)], replace: [5, 6, 7, 8] },
        ];
        return patchEnd(multi) === 0x2004;
    })()],
    ["every edit in a multi-site patch is written", (() => {
        const multi: AblPatch = [
            { offset: 0x100, expect: [...pristine.subarray(0x100, 0x104)], replace: [1, 2, 3, 4] },
            { offset: 0x2000, expect: [...pristine.subarray(0x2000, 0x2004)], replace: [5, 6, 7, 8] },
            { offset: 0x30000, expect: [...pristine.subarray(0x30000, 0x30002)], replace: [9, 10] },
        ];
        const copy = pristine.slice();
        applyPatch(copy, multi);
        return hex(copy.subarray(0x100, 0x104)) === "01 02 03 04"
            && hex(copy.subarray(0x2000, 0x2004)) === "05 06 07 08"
            && hex(copy.subarray(0x30000, 0x30002)) === "09 0a";
    })()],
    ["a patch is all-or-nothing: one bad edit writes none", (() => {
        const multi: AblPatch = [
            { offset: 0x100, expect: [...pristine.subarray(0x100, 0x104)], replace: [1, 2, 3, 4] },
            { offset: 0x2000, expect: [0xde, 0xad, 0xbe, 0xef], replace: [5, 6, 7, 8] },
        ];
        const copy = pristine.slice();
        try { applyPatch(copy, multi); return false; } catch {
            // the good edit must NOT have landed
            return hex(copy.subarray(0x100, 0x104)) === hex(pristine.subarray(0x100, 0x104));
        }
    })()],
    ["an out-of-range edit is refused", (() => {
        const multi: AblPatch = [{ offset: pristine.length - 2, expect: [0, 0, 0, 0], replace: [1, 2, 3, 4] }];
        try { applyPatch(pristine.slice(), multi); return false; } catch { return true; }
    })()],
    ["an empty patch is refused", (() => {
        try { applyPatch(pristine.slice(), []); return false; } catch { return true; }
    })()],
    ["payload body grows to cover the furthest edit", (() => {
        const multi: AblPatch = [
            { offset: 0x100, expect: [...pristine.subarray(0x100, 0x104)], replace: [1, 2, 3, 4] },
            { offset: 0x40000, expect: [...pristine.subarray(0x40000, 0x40004)], replace: [5, 6, 7, 8] },
        ];
        const copy = pristine.slice();
        applyPatch(copy, multi);
        const built = buildUnlockPayload(copy, multi);
        return built.length === OVERFLOW + 0x40004
            && hex(built.subarray(OVERFLOW + 0x40000, OVERFLOW + 0x40004)) === "05 06 07 08";
    })()],
];

console.log();
// --- the payload the unlock sends -----------------------------------------
{
    const patch = unlockPatch();

    checks.push(["unlockPatch is the bypass only", patch.length === 1
        && patch[0]!.offset === 0x3777c]);
    checks.push(["unlockPatch does not mutate the base patch",
        PATCH_16476800119700000.length === 1]);

    const image = pristine.slice();
    applyPatch(image, patch);
    const built = buildUnlockPayload(image, patch);
    checks.push([`payload is 0x100000 + 0x${patchEnd(patch).toString(16)}`,
        built.length === OVERFLOW + patchEnd(patch)]);
    checks.push(["payload carries every edit",
        patch.every((e) => hex(built.subarray(OVERFLOW + e.offset, OVERFLOW + e.offset + e.replace.length))
            === hex(Uint8Array.from(e.replace)))]);

    // The bootloader's userdata/misc/metadata wipe is left exactly as shipped.
    checks.push(["the payload leaves the wipe branch untouched",
        hex(image.subarray(0x37a74, 0x37a78)) === hex(pristine.subarray(0x37a74, 0x37a78))]);
}

let failed = 0;
for (const [name, ok] of checks) {
    console.log(ok ? "  PASS" : "  FAIL", name);
    if (!ok) failed++;
}
console.log(failed === 0 ? "\nall checks passed" : `\n${failed} check(s) FAILED`);
process.exit(failed === 0 ? 0 : 1);
