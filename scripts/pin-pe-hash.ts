// Recomputes the sha256 of the extracted LinuxLoader image and writes it into
// flow.ts, so a repacked archive cannot slip a different bootloader past the
// patch-site byte checks.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { unzipSync } from "fflate";
import {
    PATCH_16476800119700000,
    extractLinuxLoaderPe,
    patchEnd,
} from "../src/lib/abl.js";

const zip = new Uint8Array(readFileSync("binaries/quest1/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
const hash = createHash("sha256").update(pe).digest("hex");

console.log(`abl.img   sha256 ${createHash("sha256").update(abl).digest("hex")}`);
console.log(`PE        sha256 ${hash} (${pe.length} bytes)`);
console.log(
    `patch     ${PATCH_16476800119700000.length} site(s) at ` +
        `${PATCH_16476800119700000.map((e) => `0x${e.offset.toString(16)}`).join(", ")}, ` +
        `payload body ${patchEnd(PATCH_16476800119700000)} bytes`,
);

const path = "src/lib/flow.ts";
const before = readFileSync(path, "utf8");
const pattern = new RegExp(
    '(export const EXPECTED_PE_SHA256 =\\s*\\n\\s*")[0-9a-f]{64}(")',
);

if (!pattern.test(before)) {
    console.error("could not find EXPECTED_PE_SHA256 in flow.ts");
    process.exit(1);
}

const after = before.replace(pattern, `$1${hash}$2`);
if (after === before) {
    console.log("already pinned");
} else {
    writeFileSync(path, after);
    console.log(`pinned into ${path}`);
}
