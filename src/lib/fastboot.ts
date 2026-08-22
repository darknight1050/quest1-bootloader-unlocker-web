/**
 * A small fastboot client over WebUSB, plus the CVE-2021-1931 unlock.
 *
 * The bootloader exposes a vendor-specific interface (class 0xff, subclass
 * 0x42, protocol 0x03) with one bulk in and one bulk out endpoint. Commands
 * are ASCII, responses are 4-byte-tagged packets: INFO/TEXT carry progress,
 * OKAY and FAIL end a command, DATA opens a transfer.
 */

import { bufferSource } from "./device.js";

/** Oculus vendor id; the bootloader enumerates as 2833:0081. */
export const FASTBOOT_VENDOR_ID = 0x2833;
export const FASTBOOT_PRODUCT_ID = 0x0081;

export const FASTBOOT_INTERFACE = {
    classCode: 0xff,
    subclassCode: 0x42,
    protocolCode: 0x03,
} as const;

export const FASTBOOT_FILTERS: USBDeviceFilter[] = [
    { vendorId: FASTBOOT_VENDOR_ID, ...FASTBOOT_INTERFACE },
];

export interface FastbootResponse {
    /** OKAY or FAIL — whichever ended the command. */
    readonly status: "OKAY" | "FAIL";
    /** Payload of the terminating packet. */
    readonly message: string;
    /** Every INFO/TEXT line seen along the way. */
    readonly info: string[];
}

export class FastbootError extends Error {
    constructor(
        readonly command: string,
        readonly response: FastbootResponse,
    ) {
        super(`fastboot ${command}: FAIL ${response.message}`);
        this.name = "FastbootError";
    }
}

/**
 * True for the errors WebUSB raises once the bootloader leaves the bus.
 *
 * Unlocking is one of the moments this happens by design: the bootloader
 * erases userdata and reboots to do it, so the transfer that would have read
 * the answer fails instead. That is not the same as the tool being broken, and
 * callers need to be able to tell the two apart.
 */
export function isLinkLost(error: unknown): boolean {
    if (error instanceof FastbootError) {
        // The device answered — it just said no.
        return false;
    }
    if (!(error instanceof Error)) {
        return false;
    }
    if (
        error.name === "NetworkError" ||
        error.name === "NotFoundError" ||
        error.name === "InvalidStateError" ||
        error.name === "AbortError"
    ) {
        return true;
    }
    return /transfer(In|Out)|transfer error|disconnect|device is not open|no device/i.test(
        error.message,
    );
}

interface Endpoints {
    readonly interfaceNumber: number;
    readonly inEndpoint: number;
    readonly outEndpoint: number;
}

function findEndpoints(device: USBDevice): Endpoints {
    for (const configuration of device.configurations) {
        for (const iface of configuration.interfaces) {
            for (const alternate of iface.alternates) {
                if (
                    alternate.interfaceClass !== FASTBOOT_INTERFACE.classCode ||
                    alternate.interfaceSubclass !== FASTBOOT_INTERFACE.subclassCode ||
                    alternate.interfaceProtocol !== FASTBOOT_INTERFACE.protocolCode
                ) {
                    continue;
                }
                let inEndpoint: number | undefined;
                let outEndpoint: number | undefined;
                for (const endpoint of alternate.endpoints) {
                    if (endpoint.type !== "bulk") continue;
                    if (endpoint.direction === "in") inEndpoint ??= endpoint.endpointNumber;
                    if (endpoint.direction === "out") outEndpoint ??= endpoint.endpointNumber;
                }
                if (inEndpoint !== undefined && outEndpoint !== undefined) {
                    return {
                        interfaceNumber: iface.interfaceNumber,
                        inEndpoint,
                        outEndpoint,
                    };
                }
            }
        }
    }
    throw new Error("no fastboot interface on this USB device");
}

export class FastbootDevice {
    readonly #device: USBDevice;
    #endpoints: Endpoints | undefined;
    /** In-flight bulk read, if any; see `#nextPacket`. */
    #pending: Promise<string> | undefined;

    constructor(device: USBDevice) {
        this.#device = device;
    }

    static async request(): Promise<FastbootDevice | undefined> {
        if (!navigator.usb) {
            throw new Error("WebUSB is unavailable in this browser.");
        }
        const device = await navigator.usb
            .requestDevice({ filters: FASTBOOT_FILTERS })
            .catch((error: unknown) => {
                if (error instanceof Error && error.name === "NotFoundError") {
                    return undefined;
                }
                throw error;
            });
        return device ? new FastbootDevice(device) : undefined;
    }

    /** Returns an already-permitted bootloader, if one is plugged in. */
    static async find(): Promise<FastbootDevice | undefined> {
        if (!navigator.usb) return undefined;
        for (const device of await navigator.usb.getDevices()) {
            if (device.vendorId !== FASTBOOT_VENDOR_ID) continue;
            try {
                findEndpoints(device);
                return new FastbootDevice(device);
            } catch {
                // Not in bootloader mode.
            }
        }
        return undefined;
    }

    get serial(): string {
        return this.#device.serialNumber ?? "(no serial)";
    }

    get productName(): string {
        return this.#device.productName ?? "fastboot device";
    }

    get opened(): boolean {
        return this.#endpoints !== undefined;
    }

    async open(): Promise<void> {
        if (!this.#device.opened) {
            await this.#device.open();
        }
        if (this.#device.configuration === null) {
            await this.#device.selectConfiguration(1);
        }
        const endpoints = findEndpoints(this.#device);
        await this.#device.claimInterface(endpoints.interfaceNumber);
        this.#endpoints = endpoints;
    }

    async close(): Promise<void> {
        const endpoints = this.#endpoints;
        this.#endpoints = undefined;
        if (!endpoints) return;
        try {
            await this.#device.releaseInterface(endpoints.interfaceNumber);
        } catch {
            // The bootloader often drops the link first; nothing to release.
        }
        try {
            await this.#device.close();
        } catch {
            // Same.
        }
    }

    #require(): Endpoints {
        if (!this.#endpoints) {
            throw new Error("fastboot device is not open");
        }
        return this.#endpoints;
    }

    /** Writes raw bytes to the bulk out endpoint, chunked. */
    async writeRaw(
        data: Uint8Array,
        onProgress?: (sent: number, total: number) => void,
        chunkSize = 16 * 1024,
    ): Promise<void> {
        const { outEndpoint } = this.#require();
        for (let offset = 0; offset < data.length; offset += chunkSize) {
            const chunk = data.subarray(offset, Math.min(offset + chunkSize, data.length));
            await this.#device.transferOut(outEndpoint, bufferSource(chunk));
            onProgress?.(Math.min(offset + chunk.length, data.length), data.length);
        }
    }

    async #transferIn(): Promise<string> {
        const { inEndpoint } = this.#require();
        const result = await this.#device.transferIn(inEndpoint, 256);
        if (!result.data || result.data.byteLength === 0) {
            return "";
        }
        return new TextDecoder().decode(result.data);
    }

    /**
     * The next packet, at most one transfer in flight.
     *
     * A `transferIn` cannot be cancelled, so a caller that gives up waiting
     * must not leave a read outstanding — the next command's first packet
     * would disappear into it. Instead the in-flight read is remembered and
     * handed to whoever asks next.
     */
    #nextPacket(): Promise<string> {
        if (!this.#pending) {
            const pending = this.#transferIn().finally(() => {
                if (this.#pending === pending) {
                    this.#pending = undefined;
                }
            });
            this.#pending = pending;
        }
        return this.#pending;
    }

    /**
     * Reads one packet, giving up after `ms`.
     *
     * The read stays pending and will be consumed by the next reader, so
     * giving up here never desynchronises the stream.
     */
    async readPacketOrTimeout(ms: number): Promise<string | undefined> {
        const pending = this.#nextPacket();
        return Promise.race([
            pending,
            new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), ms)),
        ]);
    }

    /** Reads packets until OKAY or FAIL. */
    async readResponse(onInfo?: (line: string) => void): Promise<FastbootResponse> {
        const info: string[] = [];
        for (;;) {
            const packet = await this.#nextPacket();
            if (packet === "") {
                continue;
            }
            const tag = packet.slice(0, 4);
            const body = packet.slice(4);
            if (tag === "INFO" || tag === "TEXT") {
                info.push(body);
                onInfo?.(body);
                continue;
            }
            if (tag === "OKAY" || tag === "FAIL") {
                return { status: tag, message: body, info };
            }
            // Anything untagged is treated as info rather than dropped.
            info.push(packet);
            onInfo?.(packet);
        }
    }

    /** Sends a command and waits for its terminating packet. */
    async command(
        command: string,
        onInfo?: (line: string) => void,
    ): Promise<FastbootResponse> {
        const { outEndpoint } = this.#require();
        await this.#device.transferOut(
            outEndpoint,
            bufferSource(new TextEncoder().encode(command)),
        );
        return this.readResponse(onInfo);
    }

    /** Sends a command, throwing on FAIL. */
    async commandOk(
        command: string,
        onInfo?: (line: string) => void,
    ): Promise<FastbootResponse> {
        const response = await this.command(command, onInfo);
        if (response.status === "FAIL") {
            throw new FastbootError(command, response);
        }
        return response;
    }

    async getVar(name: string): Promise<string | undefined> {
        const response = await this.command(`getvar:${name}`);
        return response.status === "OKAY" ? response.message : undefined;
    }

    /** Parses `oem device-info` into its `key: value` INFO lines. */
    async deviceInfo(): Promise<Map<string, string>> {
        const response = await this.command("oem device-info");
        const info = new Map<string, string>();
        for (const line of response.info) {
            const separator = line.indexOf(":");
            if (separator < 0) continue;
            info.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
        }
        if (response.status === "OKAY" && response.message.includes(":")) {
            const separator = response.message.indexOf(":");
            info.set(
                response.message.slice(0, separator).trim(),
                response.message.slice(separator + 1).trim(),
            );
        }
        return info;
    }

    async setActive(slot: "a" | "b"): Promise<FastbootResponse> {
        return this.commandOk(`set_active:${slot}`);
    }

    async reboot(target?: "bootloader" | "fastboot"): Promise<FastbootResponse> {
        return this.command(target ? `reboot-${target}` : "reboot");
    }
}

export interface RebootOptions {
    readonly onLog?: (line: string) => void;
    /** How long to wait for the bootloader to come back. */
    readonly timeoutMs?: number;
    readonly pollMs?: number;
}

/**
 * Reboots the bootloader back into fastboot and reconnects to it.
 *
 * `reboot-bootloader` is the right command here — `reboot-fastboot` enters
 * fastbootd, which runs from userspace and never executes the vulnerable `abl`
 * path, so it is useless for retrying the overflow.
 *
 * A failed overflow leaves the bootloader's command buffer in whatever state
 * the overrun put it in, so retrying without a clean boot is not meaningful.
 * The device re-enumerates, which invalidates the old handle; permission is
 * already granted for it, so it can be picked up again without a prompt.
 */
export async function rebootToBootloader(
    device: FastbootDevice,
    { onLog, timeoutMs = 30_000, pollMs = 500 }: RebootOptions = {},
): Promise<FastbootDevice> {
    onLog?.("sending reboot-bootloader");
    try {
        await device.reboot("bootloader");
    } catch {
        // The link usually drops before a response arrives; that is expected.
        onLog?.("link dropped while rebooting (normal)");
    }
    await device.close();

    // Give the old interface time to disappear before looking for the new one,
    // otherwise the stale handle gets picked straight back up.
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const back = await waitForBootloader({ onLog, timeoutMs, pollMs });
    if (!back) {
        throw new Error(
            `the bootloader did not come back within ${Math.round(timeoutMs / 1000)}s. ` +
                "Unplug and replug the cable, then use “Connect bootloader”.",
        );
    }
    return back;
}

/**
 * Waits for a fastboot interface to appear and opens it.
 *
 * Returns undefined rather than throwing when the wait runs out: a device that
 * does not come back is not always a failure — after an unlock it is off
 * wiping userdata — so what that means is the caller's call to make.
 */
export async function waitForBootloader({
    onLog,
    timeoutMs = 30_000,
    pollMs = 500,
}: RebootOptions = {}): Promise<FastbootDevice | undefined> {
    const deadline = Date.now() + timeoutMs;
    for (let attempt = 1; Date.now() < deadline; attempt++) {
        const found = await FastbootDevice.find();
        if (found) {
            try {
                await found.open();
                onLog?.(`bootloader is back (${found.serial})`);
                return found;
            } catch {
                // Still settling; keep waiting.
            }
        }
        if (attempt % 4 === 0) {
            onLog?.("waiting for the bootloader to come back…");
        }
        await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
    return undefined;
}

/**
 * Clears the anti-rollback indexes.
 *
 * `oem reset-rollback-indexes` is in this bootloader's own command table, next
 * to `oem reset-devinfo`; a failure comes back as
 * `Failed to reset rollback indexes: %r`.
 *
 * It matters after a downgrade: verified boot records a minimum version per
 * image and refuses anything older, so a slot rolled back to an earlier build
 * can be rejected on a later boot. Clearing the indexes removes that floor.
 *
 * What it cannot undo is anything already burned into fuses — the image also
 * talks to TZ via `TZ_UPDATE_ROLLBACK_VERSION_ID`, and fused versions are
 * one-way. This resets what is resettable and no more.
 */
export async function resetRollbackIndexes(
    device: FastbootDevice,
    onLog?: (line: string) => void,
): Promise<FastbootResponse> {
    const response = await device.command("oem reset-rollback-indexes", (line) =>
        onLog?.(`  info: ${line}`),
    );
    onLog?.(
        `oem reset-rollback-indexes: ${response.status} ${response.message}`.trimEnd(),
    );
    return response;
}

export interface UnlockState {
    /** True when the bootloader reports itself unlocked. */
    readonly unlocked: boolean;
    /**
     * True when the bootloader stopped answering before it could be read.
     *
     * `unlocked` is then meaningless rather than false: nothing was read, so
     * nothing was ruled out. Callers must say "unknown", never "still locked".
     */
    readonly linkLost: boolean;
    /** Raw values the decision was made from. */
    readonly evidence: Record<string, string>;
}

/**
 * Reads the unlock state from every source the Quest bootloader offers.
 *
 * `getvar:unlocked` is the standard one; `oem device-info` also reports a
 * "Device unlocked" line, and the two are cross-checked because the whole
 * point of this step is to not act on a single ambiguous reading.
 */
export async function readUnlockState(device: FastbootDevice): Promise<UnlockState> {
    const evidence: Record<string, string> = {};
    let linkLost = false;

    let unlockedVar: string | undefined;
    try {
        unlockedVar = await device.getVar("unlocked");
    } catch (error) {
        if (!isLinkLost(error)) throw error;
        linkLost = true;
        evidence["getvar:unlocked"] = "(no answer — the bootloader left the bus)";
    }
    if (unlockedVar !== undefined) {
        evidence["getvar:unlocked"] = unlockedVar;
    }

    const info = new Map<string, string>();
    if (!linkLost) {
        try {
            for (const [key, value] of await device.deviceInfo()) {
                info.set(key, value);
            }
        } catch (error) {
            if (!isLinkLost(error)) throw error;
            linkLost = true;
            evidence["oem device-info"] = "(no answer — the bootloader left the bus)";
        }
    }
    for (const [key, value] of info) {
        evidence[`oem device-info/${key}`] = value;
    }

    const truthy = (value: string | undefined) =>
        value !== undefined && /^(yes|true|1|unlocked)$/i.test(value.trim());

    const deviceUnlocked = [...info.entries()].find(([key]) =>
        /unlocked/i.test(key),
    )?.[1];

    return {
        unlocked: truthy(unlockedVar) || truthy(deviceUnlocked),
        linkLost,
        evidence,
    };
}

export interface UnlockOptions {
    readonly onLog?: (line: string) => void;
    readonly onProgress?: (sent: number, total: number) => void;
}

/**
 * Fires the overflow payload and requests the unlock token.
 *
 * The payload is a plain bulk write, not a fastboot command — it deliberately
 * overruns the command buffer. The bootloader may answer with FAIL, or not at
 * all; neither is a reason to stop, so the response is logged rather than
 * checked.
 */
export async function performUnlock(
    device: FastbootDevice,
    payload: Uint8Array,
    { onLog, onProgress }: UnlockOptions = {},
): Promise<UnlockState> {
    onLog?.(`sending ${payload.length} byte overflow payload`);
    try {
        await device.writeRaw(payload, onProgress);
    } catch (error) {
        if (!isLinkLost(error)) throw error;
        onLog?.("the bootloader left the bus while the payload was being sent");
        return { unlocked: false, linkLost: true, evidence: {} };
    }

    // The bootloader may answer, or may say nothing at all. Read at most one
    // packet and do not block on it: silence here is the normal case.
    const packet = await device.readPacketOrTimeout(3000);
    onLog?.(
        packet
            ? `payload response: ${packet.trimEnd()}`
            : "payload produced no response (expected)",
    );

    onLog?.("requesting unlock token");
    try {
        const unlockResponse = await device.command("flash:unlock_token", (line) =>
            onLog?.(`  info: ${line}`),
        );
        onLog?.(
            `unlock_token: ${unlockResponse.status} ${unlockResponse.message}`.trimEnd(),
        );
    } catch (error) {
        if (!isLinkLost(error)) throw error;
        onLog?.(
            "the bootloader left the bus without answering the unlock request — " +
                "which is what it does when the unlock takes and it reboots to wipe",
        );
        return {
            unlocked: false,
            linkLost: true,
            evidence: { "flash:unlock_token": "(link dropped before an answer)" },
        };
    }

    const state = await readUnlockState(device);
    if (state.linkLost) {
        onLog?.(
            "the bootloader stopped answering right after the unlock request — " +
                "it usually reboots at this point to erase userdata",
        );
    }
    return state;
}
