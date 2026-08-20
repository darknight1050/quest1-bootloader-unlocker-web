// Writes the extracted LinuxLoader image to a file for external analysis.
import { readFileSync, writeFileSync } from "node:fs";
import { unzipSync } from "fflate";
import { extractLinuxLoaderPe } from "../src/lib/abl.js";

const out = process.argv[2] ?? "pe.bin";
const zip = new Uint8Array(readFileSync("binaries/16476800119700000.zip"));
const abl = unzipSync(zip, { filter: (f) => f.name === "abl.img" })["abl.img"]!;
const pe = await extractLinuxLoaderPe(abl);
writeFileSync(out, pe);
console.log(`wrote ${out}, ${pe.length} bytes`);
