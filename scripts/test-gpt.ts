// Builds a synthetic GPT and checks the attribute decoder, including that it
// refuses to guess when the bits disagree with the HAL.
import { summariseSlots, type GptSlotAttributes } from "../src/lib/gpt.js";

const attr = (
    partition: string,
    slotSuffix: string,
    o: { priority: number; active: boolean; retries: number; successful: boolean; unbootable: boolean },
): GptSlotAttributes => {
    const raw =
        (BigInt(o.priority) << 48n) |
        (BigInt(o.active ? 1 : 0) << 50n) |
        (BigInt(o.retries) << 51n) |
        (BigInt(o.successful ? 1 : 0) << 54n) |
        (BigInt(o.unbootable ? 1 : 0) << 55n);
    return {
        partition, slotSuffix,
        priority: o.priority, active: o.active,
        retriesRemaining: o.retries, successful: o.successful,
        unbootable: o.unbootable, raw,
    };
};

const checks: [string, boolean][] = [];
const check = (name: string, ok: boolean) => checks.push([name, ok]);

// --- freshly activated _b: active, retries left, not yet successful --------
{
    const gpt = [
        attr("boot", "_a", { priority: 1, active: false, retries: 7, successful: true, unbootable: false }),
        attr("boot", "_b", { priority: 3, active: true, retries: 7, successful: false, unbootable: false }),
    ];
    const hal = [
        { index: 0, bootable: true, successful: true },
        { index: 1, bootable: true, successful: false },
    ];
    const v = summariseSlots(gpt, hal);
    check("fresh _b -> active slot is 1", v.activeSlot === 1);
    check("fresh _b -> trusted", v.trusted);
    check("fresh _b -> _b not successful", v.perSlot[1]?.successful === false);
    check("fresh _b -> retries reported", v.perSlot[1]?.retriesRemaining === 7);
}

// --- steady state: _a active and successful --------------------------------
{
    const gpt = [
        attr("boot", "_a", { priority: 3, active: true, retries: 0, successful: true, unbootable: false }),
        attr("boot", "_b", { priority: 1, active: false, retries: 0, successful: false, unbootable: true }),
    ];
    const hal = [
        { index: 0, bootable: true, successful: true },
        { index: 1, bootable: false, successful: false },
    ];
    const v = summariseSlots(gpt, hal);
    check("steady -> active slot is 0", v.activeSlot === 0);
    check("steady -> trusted", v.trusted);
}

// --- layout mismatch must NOT produce an answer ---------------------------
{
    const gpt = [
        attr("boot", "_a", { priority: 3, active: true, retries: 0, successful: false, unbootable: false }),
        attr("boot", "_b", { priority: 1, active: false, retries: 0, successful: false, unbootable: false }),
    ];
    const hal = [
        { index: 0, bootable: true, successful: true },  // HAL disagrees with the bit
        { index: 1, bootable: true, successful: false },
    ];
    const v = summariseSlots(gpt, hal);
    check("mismatch -> not trusted", !v.trusted);
    check("mismatch -> no active slot claimed", v.activeSlot === undefined);
    check("mismatch -> explains why", v.reason.includes("do not line up"));
}

// --- both slots active is ambiguous, not a coin flip ----------------------
{
    const gpt = [
        attr("boot", "_a", { priority: 3, active: true, retries: 0, successful: true, unbootable: false }),
        attr("boot", "_b", { priority: 3, active: true, retries: 0, successful: true, unbootable: false }),
    ];
    const hal = [
        { index: 0, bootable: true, successful: true },
        { index: 1, bootable: true, successful: true },
    ];
    const v = summariseSlots(gpt, hal);
    check("both active -> no claim", v.activeSlot === undefined && !v.trusted);
}

let failed = 0;
for (const [name, ok] of checks) {
    console.log(ok ? "  PASS" : "  FAIL", name);
    if (!ok) failed++;
}
console.log(failed === 0 ? "\nGPT decoding OK" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
