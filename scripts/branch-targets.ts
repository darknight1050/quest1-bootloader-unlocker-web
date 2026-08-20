import { readFileSync } from "node:fs";
import { unzipSync } from "fflate";
import { PATCH_16476800119700000 as PATCH, extractLinuxLoaderPe } from "../src/lib/abl.js";

const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(" ");
const word = (b: readonly number[] | Uint8Array) => (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;

const bImm = (w: number) => { let i = w & 0x3ffffff; if (i & 0x2000000) i -= 0x4000000; return i * 4; };
const bcondImm = (w: number) => { let i = (w >>> 5) & 0x7ffff; if (i & 0x40000) i -= 0x80000; return i * 4; };

for (const [i, e] of PATCH.entries()) {
    const origTarget = e.offset + bcondImm(word(e.expect));
    const newTarget = e.offset + bImm(word(e.replace));
    console.log(`edit ${i + 1} @ 0x${e.offset.toString(16)}`);
    console.log(`  original branch taken -> 0x${origTarget.toString(16)}   ${hex(pe.subarray(origTarget, origTarget + 8))}`);
    console.log(`  replacement jumps to  -> 0x${newTarget.toString(16)}   ${hex(pe.subarray(newTarget, newTarget + 8))}`);
    console.log(`  same destination?        ${origTarget === newTarget ? "yes" : "NO"}`);
    if (newTarget >= pe.length) console.log("  !! replacement target is past the end of the image");
    // what an unconditional form of the ORIGINAL branch would encode as
    const uncond = (bcondImm(word(e.expect)) / 4) & 0x3ffffff;
    const enc = (0x05 << 26) | uncond;
    console.log(`  unconditional form of the original: ${hex(new Uint8Array([enc & 0xff, (enc >> 8) & 0xff, (enc >> 16) & 0xff, (enc >>> 24) & 0xff]))}  (b +0x${bcondImm(word(e.expect)).toString(16)})`);
    console.log();
}
