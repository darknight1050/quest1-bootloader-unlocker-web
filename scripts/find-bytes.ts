import { readFileSync } from "node:fs";
import { unzipSync } from "fflate";
import { extractLinuxLoaderPe } from "../src/lib/abl.js";

const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(" ");

function find(needle: number[]) {
    const hits: number[] = [];
    outer: for (let i = 0; i + needle.length <= pe.length; i++) {
        for (let j = 0; j < needle.length; j++) if (pe[i + j] !== needle[j]) continue outer;
        hits.push(i);
    }
    return hits;
}

console.log("occurrences of 01 04 00 54  (b.ne +0x80):");
for (const off of find([0x01, 0x04, 0x00, 0x54])) {
    console.log(`  0x${off.toString(16)}   ...${hex(pe.subarray(off - 8, off))} [${hex(pe.subarray(off, off + 4))}] ${hex(pe.subarray(off + 4, off + 12))}`);
}

console.log("\noccurrences of 01 02 00 54  (b.ne +0x40):");
const near = find([0x01, 0x02, 0x00, 0x54]).filter((o) => Math.abs(o - 0x37a74) < 0x4000);
for (const off of near) console.log(`  0x${off.toString(16)}`);

console.log("\nwhere edit 1's branch lands: 0x3777c + 0x2d8 = 0x" + (0x3777c + 0x2d8).toString(16));
console.log("bytes around that target:");
for (let a = 0x37a44; a < 0x37a94; a += 4) {
    const mark = a === 0x3777c + 0x2d8 ? "  <-- edit 1 lands here" : a === 0x37a74 ? "  <-- edit 2 offset" : "";
    console.log(`  0x${a.toString(16)}  ${hex(pe.subarray(a, a + 4))}${mark}`);
}
