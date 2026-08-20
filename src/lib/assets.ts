/**
 * Integrity-checked asset loading.
 *
 * Everything this tool pushes to a headset or writes to a partition is fetched
 * over HTTP from the same origin, which on its own guarantees nothing: a file
 * swapped in `public/binaries`, a truncated download, or a MITM on a plain-HTTP
 * deployment would all be flashed without complaint.
 *
 * So every payload is hashed after fetching and compared against
 * `asset-hashes.json`, which is **bundled into the JavaScript** rather than
 * fetched. An attacker who can replace a payload therefore cannot also replace
 * the expected hash — they would have to modify the bundle itself, at which
 * point no runtime check would help anyway.
 *
 * The hashes in turn come from `binaries/EXPECTED.sha256`, which is checked in
 * and enforced at build time, so a payload cannot change silently either.
 */

import manifest from "../data/asset-hashes.json";
import { sha256 } from "./device.js";

const HASHES = manifest.assets as Record<string, string>;

export class AssetIntegrityError extends Error {
    constructor(
        readonly url: string,
        readonly expected: string,
        readonly actual: string,
    ) {
        super(
            `${url} failed its integrity check.\n` +
                `  expected sha256 ${expected}\n` +
                `  actual   sha256 ${actual}\n` +
                "Nothing was sent to the device. The served file does not match the one " +
                "this build was made with — re-run `npm run sync-assets`, and if you are " +
                "not serving over https or localhost, assume it was tampered with.",
        );
        this.name = "AssetIntegrityError";
    }
}

/** The pinned hash for an asset, or undefined if it is not pinned. */
export function expectedHash(url: string): string | undefined {
    return HASHES[url];
}

export interface FetchAssetOptions {
    /** Human-readable name, used in error messages. */
    readonly what: string;
    readonly onProgress?: (received: number, total: number) => void;
}

/**
 * Fetches a payload and verifies it against the bundled manifest.
 *
 * An unpinned URL is refused outright rather than loaded unverified — the
 * whole point is that nothing reaches the headset unchecked.
 */
export async function fetchAsset(
    url: string,
    { what, onProgress }: FetchAssetOptions,
): Promise<Uint8Array> {
    const expected = expectedHash(url);
    if (!expected) {
        throw new Error(
            `${url} is not listed in the asset manifest, so its integrity cannot be ` +
                `checked. Refusing to load the ${what}.`,
        );
    }

    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) {
        throw new Error(`could not load the ${what} from ${url} (HTTP ${response.status})`);
    }

    const data = await readBody(response, onProgress);
    const actual = await sha256(data);
    if (actual !== expected) {
        throw new AssetIntegrityError(url, expected, actual);
    }
    return data;
}

async function readBody(
    response: Response,
    onProgress?: (received: number, total: number) => void,
): Promise<Uint8Array> {
    const total = Number(response.headers.get("content-length") ?? 0);
    if (!response.body || !onProgress) {
        return new Uint8Array(await response.arrayBuffer());
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.length;
        onProgress(received, total || received);
    }

    const out = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

/**
 * Whether this page is running somewhere the payloads can be trusted in transit.
 *
 * The hash check catches a swapped file either way; this is about telling the
 * user whether they are one bad hotspot away from having to rely on it.
 */
export function isSecureOrigin(): boolean {
    return window.isSecureContext;
}
