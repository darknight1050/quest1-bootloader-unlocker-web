// Computes the sha256 of the extracted LinuxLoader image up to the patch site
// and writes it into flow.ts, so a repacked archive cannot slip a different
// bootloader past the patch-site byte check.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { unzipSync } from "fflate";
import { PATCH_16476800119700000, extractLinuxLoaderPe } from "../src/lib/abl.js";

const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
const prefix = pe.subarray(0, PATCH_16476800119700000.offset);
const hash = createHash("sha256").update(prefix).digest("hex");

console.log(`abl.img      sha256 ${createHash("sha256").update(abl).digest("hex")}`);
console.log(`PE prefix    sha256 ${hash} (${prefix.length} bytes)`);

const path = "src/lib/flow.ts";
const before = readFileSync(path, "utf8");
const after = before.replace(/"__PE_PREFIX__"|"[0-9a-f]{64}";(\s*\n\s*\/\*\*\s*\n\s*\* `unlock`)/, (m) =>
    m.startsWith('"__PE_PREFIX__"') ? `"${hash}"` : m,
);
if (after === before && !before.includes(hash)) {
    console.error("could not find the placeholder to replace");
    process.exit(1);
}
writeFileSync(path, after);
console.log(before.includes(hash) ? "already pinned" : `pinned into ${path}`);
