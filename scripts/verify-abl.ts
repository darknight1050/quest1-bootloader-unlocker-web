// Verifies the payload builder against the real firmware archive.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { unzipSync } from "fflate";
import {
    OVERFLOW,
    PATCH_16476800119700000,
    buildUnlockPayloadFromAbl,
    extractLinuxLoaderPe,
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
console.log("bytes at 0x%s      %s", patch.offset.toString(16), hex(pristine.subarray(patch.offset, patch.offset + 12)));

const { payload, pe } = await buildUnlockPayloadFromAbl(abl.slice());
console.log("patched to         ", hex(pe.subarray(patch.offset, patch.offset + 4)));
console.log("payload            ", payload.length, `(0x${payload.length.toString(16)})`, "bytes  sha256", sha(payload));

const expectedLength = OVERFLOW + patch.offset + 4;
const checks: [string, boolean][] = [
    ["PE is 0x9a000 bytes", pristine.length === 0x9a000],
    ["PE sha256 matches independently-extracted reference",
        sha(pristine) === "7663280938b54f8dc061b502f581cba4bea638473080c44a8dcfec88a570f74c"],
    ["payload length is 0x100000 + 0x37780", payload.length === expectedLength],
    ["overflow region is all 0x0c", payload.subarray(0, OVERFLOW).every((b) => b === 0x0c)],
    ["patched branch lands at payload[0x100000 + 0x3777c]",
        hex(payload.subarray(OVERFLOW + patch.offset, OVERFLOW + patch.offset + 4)) === "b6 00 00 14"],
    ["image body copied verbatim up to the patch",
        payload.subarray(OVERFLOW, OVERFLOW + patch.offset).every((b, i) => b === pristine[i])],
    ["applyPatch rejects a wrong build",
        await (async () => {
            const wrong = pristine.slice();
            wrong[patch.offset] = 0x00;
            try {
                const { applyPatch } = await import("../src/lib/abl.js");
                applyPatch(wrong, patch);
                return false;
            } catch {
                return true;
            }
        })()],
];

console.log();
let failed = 0;
for (const [name, ok] of checks) {
    console.log(ok ? "  PASS" : "  FAIL", name);
    if (!ok) failed++;
}
console.log(failed === 0 ? "\nall checks passed" : `\n${failed} check(s) FAILED`);
process.exit(failed === 0 ? 0 : 1);
