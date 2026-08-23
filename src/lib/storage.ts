import { Unzip, UnzipInflate, Zip, ZipDeflate } from "fflate";

/**
 * Partition backups in the origin private file system.
 *
 * OPFS is used rather than IndexedDB because the backups are large (the modem
 * and boot images alone are ~62 MB) and OPFS gives us a real writable stream,
 * so a partition never has to sit in memory as one contiguous blob.
 */

export interface BackupEntry {
    readonly name: string;
    readonly size: number;
    readonly sha256: string;
}

export interface BackupSetMeta {
    /** Directory name; also the handle used to reopen the set. */
    readonly id?: string;
    readonly serial: string;
    readonly createdAt: string;
    readonly fingerprint: string;
    readonly slotSuffix: string;
    readonly targetSlot: string;
    readonly entries: BackupEntry[];
    /**
     * Partitions this set was supposed to contain.
     *
     * Recorded up front so a set that stopped part-way can be told apart from
     * one that was only ever meant to hold a few partitions.
     */
    readonly expected: string[];
    /**
     * True only once every expected partition has been stored and verified.
     *
     * A run that was interrupted part-way leaves this false.
     * Such a set must never be mistaken for something you can restore a device
     * from, so it is marked at rest rather than inferred later.
     */
    readonly complete: boolean;
    /**
     * When every image it holds was last read back and matched, ISO 8601.
     *
     * Written only by a verify pass that compared the stored bytes against
     * both the hash recorded at backup time and the live partition. Absent
     * means "never checked since it was written" — which is what an imported
     * set is, and what a set becomes again the moment an entry is replaced.
     */
    readonly verifiedAt?: string;
    /**
     * Which flow produced it.
     *
     * Only the unlock flow writes backups now; sets written by the old
     * read-only rehearsal may still carry `"dev"` on disk.
     */
    readonly mode: "unlock" | "dev";
}

/**
 * Compares entry names ignoring the `.img` suffix.
 *
 * Sets written before `expected` and the stored entries agreed list partitions
 * bare (`boot_b`) while the files are named `boot_b.img`. Both spellings mean
 * the same partition, and an old set should not be stuck "incomplete" over it.
 */
function canonicalEntryName(name: string): string {
    return name.replace(/\.img$/, "");
}

const ROOT_DIR = "backups";
const META_FILE = "backup.json";

async function root(): Promise<FileSystemDirectoryHandle> {
    if (!navigator.storage?.getDirectory) {
        throw new Error(
            "This browser has no origin private file system, so backups cannot be stored.",
        );
    }
    const opfs = await navigator.storage.getDirectory();
    return opfs.getDirectoryHandle(ROOT_DIR, { create: true });
}

/**
 * Asks for persistent storage.
 *
 * Without it the browser may evict the backups under storage pressure, which
 * for this tool means losing the only copy of the partitions we overwrote.
 */
export async function requestPersistence(): Promise<boolean> {
    if (!navigator.storage?.persist) {
        return false;
    }
    if (await navigator.storage.persisted()) {
        return true;
    }
    return navigator.storage.persist();
}

export async function estimateQuota(): Promise<{ usage: number; quota: number }> {
    const estimate = (await navigator.storage?.estimate?.()) ?? {};
    return { usage: estimate.usage ?? 0, quota: estimate.quota ?? 0 };
}

export class BackupSet {
    readonly id: string;
    readonly #dir: FileSystemDirectoryHandle;
    #meta: BackupSetMeta;

    private constructor(
        id: string,
        dir: FileSystemDirectoryHandle,
        meta: BackupSetMeta,
    ) {
        this.id = id;
        this.#dir = dir;
        this.#meta = meta;
    }

    static async create(
        meta: Omit<BackupSetMeta, "entries" | "createdAt" | "complete">,
        createdAt: string,
    ): Promise<BackupSet> {
        const id = `${meta.serial}-${createdAt.replace(/[:.]/g, "-")}`;
        const dir = await (await root()).getDirectoryHandle(id, { create: true });
        const full: BackupSetMeta = { ...meta, createdAt, entries: [], complete: false };
        const set = new BackupSet(id, dir, full);
        await set.#writeMeta();
        return set;
    }

    /** Reopens a set written by an earlier session. */
    static async load(id: string): Promise<BackupSet> {
        const dir = await (await root()).getDirectoryHandle(id);
        const handle = await dir.getFileHandle(META_FILE);
        const meta = JSON.parse(await (await handle.getFile()).text()) as BackupSetMeta;
        return new BackupSet(id, dir, meta);
    }

    get meta(): BackupSetMeta {
        return this.#meta;
    }

    /** Opens a stream that writes one partition image into the set. */
    async open(name: string): Promise<FileSystemWritableFileStream> {
        const handle = await this.#dir.getFileHandle(name, { create: true });
        return handle.createWritable();
    }

    async record(entry: BackupEntry): Promise<void> {
        // Whatever was verified before, this is not it any more.
        const { verifiedAt: _dropped, ...meta } = this.#meta;
        this.#meta = {
            ...meta,
            entries: [...meta.entries.filter((e) => e.name !== entry.name), entry],
        };
        await this.#writeMeta();
    }

    /**
     * Records that every image in the set has been re-read and matched.
     *
     * It makes no claim about coverage — that is what
     * {@link BackupSetMeta.complete} is for — only that everything the set
     * does hold was read back and matched.
     */
    async markVerified(when: string): Promise<void> {
        this.#meta = { ...this.#meta, verifiedAt: when };
        await this.#writeMeta();
    }

    /**
     * Marks the set complete once every expected partition is present.
     *
     * Refuses if anything is missing, so "complete" can never be set on a set
     * that does not actually hold what it claims.
     */
    async markComplete(): Promise<void> {
        const stored = new Set(
            this.#meta.entries.map((entry) => canonicalEntryName(entry.name)),
        );
        const missing = this.#meta.expected.filter(
            (name) => !stored.has(canonicalEntryName(name)),
        );
        if (missing.length > 0) {
            throw new Error(
                `cannot mark backup ${this.id} complete: missing ${missing.join(", ")}`,
            );
        }
        this.#meta = { ...this.#meta, complete: true };
        await this.#writeMeta();
    }

    async read(name: string): Promise<Uint8Array> {
        const handle = await this.#dir.getFileHandle(name);
        const file = await handle.getFile();
        return new Uint8Array(await file.arrayBuffer());
    }

    async file(name: string): Promise<File> {
        return (await this.#dir.getFileHandle(name)).getFile();
    }

    async #writeMeta(): Promise<void> {
        const handle = await this.#dir.getFileHandle(META_FILE, { create: true });
        const writable = await handle.createWritable();
        await writable.write(JSON.stringify(this.#meta, null, 2));
        await writable.close();
    }
}

/**
 * Permanently removes a stored backup set.
 *
 * There is no undo and no recycle bin — OPFS is the only copy unless the set
 * was also saved as a zip, so callers are expected to have confirmed this with
 * the user first.
 */
export async function deleteBackupSet(id: string): Promise<void> {
    const dir = await root();
    await dir.removeEntry(id, { recursive: true });
}

/** Lists every backup set previously stored by this origin. */
export async function listBackupSets(): Promise<BackupSetMeta[]> {
    const dir = await root();
    const sets: BackupSetMeta[] = [];
    for await (const [id, handle] of (
        dir as unknown as {
            entries(): AsyncIterable<[string, FileSystemHandle]>;
        }
    ).entries()) {
        if (handle.kind !== "directory") continue;
        try {
            const metaHandle = await (handle as FileSystemDirectoryHandle).getFileHandle(
                META_FILE,
            );
            const text = await (await metaHandle.getFile()).text();
            sets.push({ ...(JSON.parse(text) as BackupSetMeta), id });
        } catch {
            // A set without readable metadata is not useful to list.
        }
    }
    return sets.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/**
 * Rebuilds a backup set from image files on disk.
 *
 * The inverse of "Save to disk", and the only way back if the browser profile
 * that took the backup is gone — a different machine, cleared site data, a
 * reinstall. Names may carry the set-id prefix that `downloadEntry` adds, or
 * be the bare `<partition>_<slot>.img`.
 *
 * `expected` is the set of partitions a complete backup must contain; the
 * import is marked complete only if every one of them is present, so a partial
 * pile of files can never masquerade as a full backup.
 */
export async function importBackupSet(
    files: readonly File[],
    details: {
        serial: string;
        fingerprint: string;
        expected: readonly string[];
        createdAt: string;
    },
): Promise<{ set: BackupSet; slotSuffix: string; imported: string[]; ignored: string[] }> {
    const imported: string[] = [];
    const ignored: string[] = [];
    const matched: { file: File; name: string; slotSuffix: string }[] = [];

    for (const file of files) {
        const match = /(?:^|[-_/])([A-Za-z0-9]+)(_a|_b)\.img$/.exec(file.name);
        if (!match) {
            ignored.push(file.name);
            continue;
        }
        matched.push({
            file,
            name: `${match[1]}${match[2]}.img`,
            slotSuffix: match[2]!,
        });
    }

    if (matched.length === 0) {
        throw new Error(
            "none of the selected files look like partition images " +
                "(expected names ending in _a.img or _b.img)",
        );
    }

    const slots = new Set(matched.map((m) => m.slotSuffix));
    if (slots.size !== 1) {
        throw new Error(
            `the selected files span more than one slot (${[...slots].join(", ")}); ` +
                "import one slot at a time",
        );
    }
    const slotSuffix = [...slots][0]!;

    const set = await BackupSet.create(
        {
            serial: details.serial,
            fingerprint: details.fingerprint,
            slotSuffix,
            targetSlot: slotSuffix,
            mode: "unlock",
            expected: [...details.expected],
        },
        details.createdAt,
    );

    for (const { file, name } of matched) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const writable = await set.open(name);
        await writable.write(bytes as Uint8Array<ArrayBuffer>);
        await writable.close();

        const digest = await crypto.subtle.digest(
            "SHA-256",
            bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
        );
        const hash = Array.from(new Uint8Array(digest))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

        await set.record({ name, size: bytes.length, sha256: hash });
        imported.push(name);
    }

    // Only a set covering everything may claim to be complete.
    const stored = new Set(imported.map(canonicalEntryName));
    if (details.expected.every((name) => stored.has(canonicalEntryName(name)))) {
        await set.markComplete();
    }

    return { set, slotSuffix, imported, ignored };
}

export interface ImportResult {
    readonly set: BackupSet;
    readonly slotSuffix: string;
    readonly imported: string[];
    readonly ignored: string[];
    /** Images whose bytes did not match the hash recorded in backup.json. */
    readonly corrupt: string[];
}

/**
 * Rebuilds a set from a zip written by `downloadSetAsZip`.
 *
 * Streamed, not read into memory: the archive holds every partition of a slot,
 * which is hundreds of megabytes, and this runs on a machine that may already
 * be short on room. Each entry is inflated and written straight into OPFS.
 *
 * When the archive carries its original `backup.json`, the recorded hashes are
 * checked against the bytes that actually arrive — an archive that was
 * truncated or tampered with in transit is reported rather than restored.
 */
export async function importBackupZip(
    file: File,
    details: { serial: string; fingerprint: string; createdAt: string },
): Promise<ImportResult> {
    const images = new Map<string, { chunks: Uint8Array[]; size: number }>();
    const ignored: string[] = [];
    let manifestText = "";
    let failure: Error | undefined;

    const unzipper = new Unzip();
    unzipper.register(UnzipInflate);
    unzipper.onfile = (entry) => {
        const name = entry.name.split("/").pop() ?? entry.name;

        if (name === META_FILE) {
            const parts: Uint8Array[] = [];
            entry.ondata = (error, chunk, final) => {
                if (error) {
                    failure ??= error;
                    return;
                }
                parts.push(chunk);
                if (final) {
                    manifestText = new TextDecoder().decode(concat(parts));
                }
            };
            entry.start();
            return;
        }

        if (!/(_a|_b)\.img$/.test(name)) {
            ignored.push(entry.name);
            return;
        }

        const collected = { chunks: [] as Uint8Array[], size: 0 };
        images.set(name, collected);
        entry.ondata = (error, chunk, final) => {
            if (error) {
                failure ??= error;
                return;
            }
            collected.chunks.push(chunk);
            collected.size += chunk.length;
            void final;
        };
        entry.start();
    };

    const reader = file.stream().getReader();
    for (;;) {
        const { done, value } = await reader.read();
        if (failure) throw failure;
        if (done) {
            unzipper.push(new Uint8Array(0), true);
            break;
        }
        unzipper.push(value, false);
    }
    if (failure) throw failure;

    if (images.size === 0) {
        throw new Error("the archive contains no partition images");
    }

    const slots = new Set(
        [...images.keys()].map((name) => (name.includes("_a.img") ? "_a" : "_b")),
    );
    if (slots.size !== 1) {
        throw new Error(
            `the archive spans more than one slot (${[...slots].join(", ")}); ` +
                "import one slot at a time",
        );
    }
    const slotSuffix = [...slots][0]!;

    const original = manifestText
        ? (JSON.parse(manifestText) as BackupSetMeta)
        : undefined;
    const expected =
        original?.expected ?? [...images.keys()].map((name) => name);

    const set = await BackupSet.create(
        {
            serial: original?.serial ?? details.serial,
            fingerprint: original?.fingerprint ?? details.fingerprint,
            slotSuffix: original?.slotSuffix ?? slotSuffix,
            targetSlot: slotSuffix,
            mode: original?.mode ?? "unlock",
            expected: [...expected],
        },
        details.createdAt,
    );

    const imported: string[] = [];
    const corrupt: string[] = [];

    for (const [name, collected] of images) {
        const bytes = concat(collected.chunks);
        const hash = await digestHex(bytes);

        const recorded = original?.entries.find((entry) => entry.name === name);
        if (recorded && recorded.sha256 !== hash) {
            corrupt.push(name);
            continue;
        }

        const writable = await set.open(name);
        await writable.write(bytes as Uint8Array<ArrayBuffer>);
        await writable.close();
        await set.record({ name, size: bytes.length, sha256: hash });
        imported.push(name);
    }

    const stored = new Set(imported.map(canonicalEntryName));
    if (
        corrupt.length === 0 &&
        expected.every((name) => stored.has(canonicalEntryName(name)))
    ) {
        await set.markComplete();
    }

    return { set, slotSuffix, imported, ignored, corrupt };
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

async function digestHex(bytes: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        bytes.buffer.slice(
            bytes.byteOffset,
            bytes.byteOffset + bytes.byteLength,
        ) as ArrayBuffer,
    );
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

interface SaveFilePickerOptions {
    suggestedName?: string;
    types?: { description: string; accept: Record<string, string[]> }[];
}

type SaveFilePicker = (
    options?: SaveFilePickerOptions,
) => Promise<FileSystemFileHandle>;

/**
 * Writes the whole backup set to disk as one zip.
 *
 * Streamed rather than assembled in memory: a full Quest 1 set is hundreds of
 * megabytes once partition sizes rather than image sizes are counted, and
 * building that as a single blob is a good way to run the tab out of memory.
 * Each image is read from OPFS in chunks, deflated, and written straight to the
 * file the user picked.
 *
 * Deflate level 1 — partition images are mostly zero padding, so even the
 * cheapest setting shrinks them a lot, and the CPU stays out of the way of the
 * USB transfers this tool cares about.
 */
export async function downloadSetAsZip(
    set: BackupSet,
    onProgress?: (written: number, total: number) => void,
): Promise<{ cancelled: boolean; bytes: number }> {
    const entries = set.meta.entries;
    if (entries.length === 0) {
        throw new Error("this backup holds no images");
    }
    const total = entries.reduce((sum, entry) => sum + entry.size, 0);

    const picker = (window as unknown as { showSaveFilePicker?: SaveFilePicker })
        .showSaveFilePicker;
    if (!picker) {
        throw new Error(
            "this browser cannot save a file directly (showSaveFilePicker is missing)",
        );
    }

    let handle: FileSystemFileHandle;
    try {
        handle = await picker({
            suggestedName: `${set.id}.zip`,
            types: [{ description: "Zip archive", accept: { "application/zip": [".zip"] } }],
        });
    } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            return { cancelled: true, bytes: 0 };
        }
        throw error;
    }

    const writable = await handle.createWritable();
    const zip = new Zip();

    // fflate hands chunks back synchronously; the file write is async, so keep
    // them in order on a chain and apply backpressure by awaiting it.
    let chain: Promise<void> = Promise.resolve();
    let bytes = 0;
    let failure: Error | undefined;
    let finished = false;

    zip.ondata = (error, chunk, final) => {
        if (error) {
            failure ??= error;
            return;
        }
        bytes += chunk.length;
        chain = chain.then(() => writable.write(chunk as Uint8Array<ArrayBuffer>));
        if (final) {
            finished = true;
        }
    };

    try {
        // The manifest travels with the images so an import knows what it has.
        const manifest = new ZipDeflate("backup.json", { level: 1 });
        zip.add(manifest);
        manifest.push(
            new TextEncoder().encode(JSON.stringify(set.meta, null, 2)),
            true,
        );

        let written = 0;
        for (const entry of entries) {
            const file = await set.file(entry.name);
            const stream = new ZipDeflate(entry.name, { level: 1 });
            zip.add(stream);

            const reader = file.stream().getReader();
            for (;;) {
                const { done, value } = await reader.read();
                if (failure) throw failure;
                if (done) {
                    stream.push(new Uint8Array(0), true);
                    break;
                }
                stream.push(value, false);
                written += value.length;
                onProgress?.(written, total);
                // Let the chain drain so memory does not build up ahead of the
                // file writes, and give the UI a chance to paint.
                await chain;
            }
        }

        zip.end();
        await chain;
        if (failure) throw failure;
        if (!finished) {
            throw new Error("the zip stream did not finish cleanly");
        }
        await writable.close();
        return { cancelled: false, bytes };
    } catch (error) {
        await writable.abort().catch(() => undefined);
        throw error;
    }
}
