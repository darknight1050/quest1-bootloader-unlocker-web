// Mirrors binaries/ into public/ so Vite serves them, without committing the
// same 42 MB twice — and pins what may be served.
//
// Two levels of hash checking:
//
//   1. Every file under binaries/ is checked against binaries/EXPECTED.sha256
//      before it is copied. A payload cannot change without someone editing
//      that file on purpose.
//   2. The hashes are written to src/data/asset-hashes.json, which is *bundled
//      into the JavaScript*. The app verifies every fetch against it, so
//      swapping a file in public/ (or in transit) is caught before the bytes
//      reach the headset. The manifest is deliberately not fetched at runtime;
//      if it were, an attacker able to swap a payload could swap it too.
//
// Pass --with-dev (npm run dev) to include the dev-only payloads. Without it
// (npm run build) the dev directory is removed, so a production bundle can
// never ship the Quest 3 ionstack or reach the read-only rehearsal flow.
//
// binaries/dev/ is gitignored, so a fresh clone will not have it. Its absence
// is a warning, not an error: the core flow does not need it, and only dev
// mode on that device is unavailable. Its hash still ships in the manifest, so
// the file cannot be swapped for a different one if someone does supply it.
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const CORE = ["16476800119700000.zip", "ionstack", "bootctl_shim"];
const DEV = ["dev/ionstack-quest3"];
const EXPECTED_FILE = join("binaries", "EXPECTED.sha256");
const MANIFEST_FILE = join("src", "data", "asset-hashes.json");

const withDev = process.argv.includes("--with-dev");
const regenerate = process.argv.includes("--regenerate");

async function sha256(path) {
    return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function readExpected() {
    const text = await readFile(EXPECTED_FILE, "utf8").catch(() => undefined);
    if (text === undefined) {
        throw new Error(
            `${EXPECTED_FILE} is missing. Without it there is nothing to check the ` +
                "payloads against; run `npm run hash-assets` if you intend to create it.",
        );
    }
    const expected = new Map();
    for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "" || trimmed.startsWith("#")) continue;
        const [hash, ...rest] = trimmed.split(/\s+/);
        expected.set(rest.join(" "), hash);
    }
    return expected;
}

// Every known payload is checked and pinned, whether or not it gets published.
// Keeping the manifest identical between a dev and a production build means the
// committed file does not churn; an unpublished URL simply 404s at runtime.
const names = [...CORE, ...DEV];
const publish = new Set(withDev ? names : CORE);
const manifest = {};
let failed = false;

if (regenerate) {
    const previous = await readExpected().catch(() => new Map());
    const lines = [];
    for (const name of [...CORE, ...DEV]) {
        const from = join("binaries", name);
        const present = await stat(from).catch(() => undefined);
        if (present) {
            lines.push(`${await sha256(from)}  ${name}`);
            continue;
        }
        // Keep a known hash for a payload that is simply not in this checkout,
        // rather than dropping the pin for everyone else.
        const kept = previous.get(name);
        if (kept) {
            console.warn(`${from} is absent; keeping its existing hash`);
            lines.push(`${kept}  ${name}`);
        } else {
            console.warn(`${from} is absent and has no known hash; skipping`);
        }
    }
    await writeFile(
        EXPECTED_FILE,
        "# Known-good hashes of everything this tool pushes or flashes.\n" +
            "# scripts/sync-assets.mjs refuses to run if a file under binaries/ does not\n" +
            "# match, so a payload cannot change without someone updating this file on\n" +
            "# purpose. Regenerate deliberately with: npm run hash-assets\n" +
            lines.join("\n") +
            "\n",
        "utf8",
    );
    console.log(`rewrote ${EXPECTED_FILE} from the current binaries/`);
    process.exit(0);
}

const expected = await readExpected();

for (const name of names) {
    const from = join("binaries", name);
    const to = join("public", "binaries", name);

    const want = expected.get(name);
    if (!want) {
        console.error(`${name} has no entry in ${EXPECTED_FILE}; refusing to serve it`);
        failed = true;
        continue;
    }

    // Pin the hash whether or not the file is here, so the manifest stays
    // identical across checkouts and a supplied file is still checked.
    manifest[`/binaries/${name}`] = want;

    const source = await stat(from).catch(() => undefined);
    if (!source) {
        if (DEV.includes(name)) {
            console.warn(`${from} is absent (gitignored) — dev mode for it is unavailable`);
            continue;
        }
        console.error(`missing ${from} — the app cannot run without it`);
        failed = true;
        continue;
    }

    const actual = await sha256(from);
    if (actual !== want) {
        console.error(
            `${name} does not match ${EXPECTED_FILE}:\n` +
                `  expected ${want}\n` +
                `  actual   ${actual}\n` +
                "  If you changed this payload on purpose, run `npm run hash-assets`.",
        );
        failed = true;
        continue;
    }

    if (!publish.has(name)) {
        continue;
    }

    const target = await stat(to).catch(() => undefined);
    if (!target || target.size !== source.size || target.mtimeMs < source.mtimeMs) {
        await mkdir(dirname(to), { recursive: true });
        await copyFile(from, to);
        console.log(`synced ${name} (${(source.size / 1048576).toFixed(1)} MiB)`);
    }
}

if (failed) {
    console.error("\nasset check failed — nothing was published to public/");
    process.exit(1);
}

if (!withDev) {
    await rm(join("public", "binaries", "dev"), { recursive: true, force: true });
    console.log("dev payloads excluded from this build");
}

await writeFile(
    MANIFEST_FILE,
    JSON.stringify(
        {
            $comment:
                "Generated by scripts/sync-assets.mjs. Bundled into the app and checked " +
                "against every fetched payload. Do not edit by hand.",
            assets: manifest,
        },
        null,
        2,
    ) + "\n",
    "utf8",
);
console.log(`wrote ${MANIFEST_FILE} (${Object.keys(manifest).length} assets)`);
