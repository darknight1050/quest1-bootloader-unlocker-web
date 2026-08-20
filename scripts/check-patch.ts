// Checks every edit in PATCH_16476800119700000 against the real image.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { unzipSync } from "fflate";
import {
    OVERFLOW,
    PATCH_16476800119700000 as PATCH,
    applyPatch,
    buildUnlockPayload,
    extractLinuxLoaderPe,
    patchEnd,
} from "../src/lib/abl.js";

const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(" ");

/** Decodes the AArch64 instructions this patch cares about. */
function decode(word: number): string {
    const COND = ["eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"];
    // B.cond : 0101 0100 imm19 0 cond
    if ((word >>> 24) === 0x54 && ((word >>> 4) & 1) === 0) {
        let imm19 = (word >>> 5) & 0x7ffff;
        if (imm19 & 0x40000) imm19 -= 0x80000;          // sign extend
        return `b.${COND[word & 0xf]} ${imm19 >= 0 ? "+" : "-"}0x${Math.abs(imm19 * 4).toString(16)}`;
    }
    // B : 000101 imm26
    if ((word >>> 26) === 0x05) {
        let imm26 = word & 0x3ffffff;
        if (imm26 & 0x2000000) imm26 -= 0x4000000;
        return `b ${imm26 >= 0 ? "+" : "-"}0x${Math.abs(imm26 * 4).toString(16)}`;
    }
    return "(not a branch)";
}

const word = (bytes: readonly number[] | Uint8Array) =>
    (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;

console.log(`PE ${pe.length} bytes, sha256 ${createHash("sha256").update(pe).digest("hex")}`);
console.log(`patch has ${PATCH.length} edit(s)\n`);

let bad = 0;
for (const [i, edit] of PATCH.entries()) {
    const actual = pe.subarray(edit.offset, edit.offset + edit.expect.length);
    const matches = edit.expect.every((b, j) => actual[j] === b);
    if (!matches) bad++;

    console.log(`edit ${i + 1} @ 0x${edit.offset.toString(16)}`);
    console.log(`  on disk   ${hex(actual)}   ${decode(word(actual))}`);
    console.log(`  expect    ${hex(Uint8Array.from(edit.expect))}   ${decode(word(edit.expect))}`);
    console.log(`  replace   ${hex(Uint8Array.from(edit.replace))}   ${decode(word(edit.replace))}`);
    console.log(`  MATCH     ${matches ? "yes" : "NO — expect bytes are wrong"}`);
    console.log(`  context   ${hex(pe.subarray(edit.offset - 16, edit.offset))} | ${hex(pe.subarray(edit.offset, edit.offset + 16))}`);
    console.log();
}

const patched = pe.slice();
if (bad === 0) {
    applyPatch(patched, PATCH);
    const payload = buildUnlockPayload(patched, PATCH);
    console.log(`payload body  0x${patchEnd(PATCH).toString(16)} bytes (was 0x37780 with one edit)`);
    console.log(`payload total ${payload.length} (0x${payload.length.toString(16)}), overflow 0x${OVERFLOW.toString(16)}`);
    console.log(`payload sha256 ${createHash("sha256").update(payload).digest("hex")}`);
}
process.exit(bad === 0 ? 0 : 1);
