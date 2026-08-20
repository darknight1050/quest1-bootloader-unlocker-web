// Round-trips synthetic partition images through the same fflate streaming
// Zip/Unzip path the app uses, and checks hashes survive.
import { createHash, randomBytes } from "node:crypto";
import { Unzip, UnzipInflate, Zip, ZipDeflate } from "fflate";

const sha = (b) => createHash("sha256").update(b).digest("hex");

// Mostly-zero payloads, like real partition images.
const make = (size, seed) => {
    const b = Buffer.alloc(size);
    randomBytes(Math.min(size, 4096)).copy(b, 0);
    b[size - 1] = seed;
    return new Uint8Array(b);
};

const images = new Map([
    ["abl_b.img", make(274432, 1)],
    ["boot_b.img", make(30248960, 2)],
    ["modem_b.img", make(32411648, 3)],
    ["pmic_b.img", make(53248, 4)],
]);
const meta = {
    serial: "TEST123", createdAt: "2026-08-20T00:00:00.000Z",
    fingerprint: "oculus/vr_monterey/monterey:10/x/y:user/release-keys",
    slotSuffix: "_a", targetSlot: "_b", mode: "unlock",
    expected: [...images.keys()], complete: true,
    entries: [...images].map(([name, data]) => ({ name, size: data.length, sha256: sha(data) })),
};

// ---- pack (streamed, as downloadSetAsZip does) ----------------------------
const out = [];
const zip = new Zip();
zip.ondata = (err, chunk) => { if (err) throw err; out.push(Buffer.from(chunk)); };

const manifest = new ZipDeflate("backup.json", { level: 1 });
zip.add(manifest);
manifest.push(new TextEncoder().encode(JSON.stringify(meta, null, 2)), true);

for (const [name, data] of images) {
    const s = new ZipDeflate(name, { level: 1 });
    zip.add(s);
    for (let o = 0; o < data.length; o += 1 << 20) {
        s.push(data.subarray(o, Math.min(o + (1 << 20), data.length)), false);
    }
    s.push(new Uint8Array(0), true);
}
zip.end();

const archive = Buffer.concat(out);
const raw = [...images.values()].reduce((n, d) => n + d.length, 0);
console.log(`packed ${images.size} images: ${(raw/1048576).toFixed(1)} MiB -> ${(archive.length/1048576).toFixed(1)} MiB zip`);

// ---- unpack (streamed, as importBackupZip does) --------------------------
const got = new Map();
let manifestText = "";
const un = new Unzip();
un.register(UnzipInflate);
un.onfile = (f) => {
    const parts = [];
    f.ondata = (err, chunk, final) => {
        if (err) throw err;
        parts.push(Buffer.from(chunk));
        if (final) {
            const buf = Buffer.concat(parts);
            if (f.name === "backup.json") manifestText = buf.toString();
            else got.set(f.name, new Uint8Array(buf));
        }
    };
    f.start();
};
for (let o = 0; o < archive.length; o += 1 << 16) {
    un.push(archive.subarray(o, Math.min(o + (1 << 16), archive.length)), false);
}
un.push(new Uint8Array(0), true);

// ---- verify ---------------------------------------------------------------
const parsed = JSON.parse(manifestText);
let bad = 0;
for (const entry of parsed.entries) {
    const data = got.get(entry.name);
    const ok = data && data.length === entry.size && sha(data) === entry.sha256;
    console.log(`  ${ok ? "PASS" : "FAIL"} ${entry.name.padEnd(14)} ${entry.size} bytes`);
    if (!ok) bad++;
}
console.log(`manifest recovered: ${parsed.entries.length === images.size ? "PASS" : "FAIL"}`);
console.log(`complete flag preserved: ${parsed.complete === true ? "PASS" : "FAIL"}`);

// corruption must be detected
const tampered = new Uint8Array(got.get("abl_b.img"));
tampered[500] ^= 0xff;
const detected = sha(tampered) !== parsed.entries.find(e => e.name === "abl_b.img").sha256;
console.log(`tampered image rejected: ${detected ? "PASS" : "FAIL"}`);

console.log(bad === 0 && detected ? "\nround-trip OK" : "\nFAILURES");
process.exit(bad === 0 && detected ? 0 : 1);
