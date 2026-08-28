/**
 * What differs from one headset to the next.
 *
 * Everything device-specific lives here: which codenames it answers to, the
 * ionstack build and its tuning, the firmware archive we downgrade to, the
 * partitions that carries, and the bootloader patch. The flow reads it all
 * from the profile picked at connect time, so adding a device is a matter of
 * adding an entry rather than threading a second code path through the steps.
 */

import type { AblPatch } from "../lib/abl.js";
import {
    PATCH_16476800118700000,
    PATCH_16476800119700000,
} from "../lib/abl.js";

/** What the unlock step needs. Absent while a device's patch is unknown. */
export interface UnlockRecipe {
    /** Edits applied to the extracted LinuxLoader image. */
    readonly patch: AblPatch;
    /** sha256 of `abl.img` inside the firmware archive. */
    readonly ablSha256: string;
    /** sha256 of the LinuxLoader PE extracted from it. */
    readonly peSha256: string;
}

export interface DeviceProfile {
    readonly id: "quest1" | "quest2";
    readonly label: string;
    /** Values of `ro.product.device` this profile applies to. */
    readonly codenames: readonly string[];

    /** URL of the ionstack build for this kernel. */
    readonly ionstack: string;
    readonly ionstackEnv: Readonly<Record<string, string>>;
    /** Builds ionstack is known to work on. */
    readonly rootSupported: readonly string[];
    /**
     * Newest build the exploit works on, if there is a known ceiling.
     *
     * Anything above it is refused outright rather than warned about: the
     * hole is closed there, so running ionstack would at best waste a kernel
     * panic and at worst corrupt something on the way down.
     */
    readonly maxSupportedBuild?: string;

    /** Build the inactive slot is downgraded to. */
    readonly downgradeTarget: string;
    /** URL of the archive holding that build's images. */
    readonly firmware: string;
    /** Partitions the archive carries, in flash order. */
    readonly partitions: readonly string[];

    /**
     * How to unlock this device, once it is known.
     *
     * Undefined means the bootloader patch has not been derived for it. The
     * flow refuses the device outright rather than downgrading a headset it
     * then cannot unlock.
     */
    readonly unlock: UnlockRecipe | undefined;

    /** Candidate by-name directories, tried in order. */
    readonly byNameDirs: readonly string[];
}

/** Supplied verbatim by the exploit's author. */
const QUEST1_ENV: Record<string, string> = {
    IONSTACK_STAGE: "full",
    IONSTACK_SPRAY_STALL: "memfd",
    IONSTACK_KS_CORE: "7",
    IONSTACK_KS_COLLISIONS: "4",
    IONSTACK_FOPS_SAFE_TABLE: "0",
    IONSTACK_TREE_ENTRY_WRITE: "1",
    IONSTACK_FOPS_LOCK_OWNER_MODE: "",
    IONSTACK_PAGE_SETUP_ATTEMPTS: "8",
    IONSTACK_MEMFD_GATE_MAX_FIRES: "1",
    IONSTACK_STALL_HOLD_MS: "6000",
    IONSTACK_PTRACE_ROUTE_ATTEMPTS: "1",
    IONSTACK_MIN_WINDOW: "1",
    IONSTACK_RECLAIM_PERF_COUNTERS: "1",
    IONSTACK_RECLAIM_PFN_IDENTITY: "1",
    IONSTACK_RECLAIM_PHYS_PFN_START: "0x80000",
    IONSTACK_RECLAIM_PHYS_PFN_END: "0x180000",
    IONSTACK_RECLAIM_REQUIRE_PFN_MATCH: "1",
    IONSTACK_PAYLOAD: "",
    IONSTACK_PAYLOAD_TIMEOUT: "120",
    IONSTACK_XRW_KMEM: "1",
    IONSTACK_XRW_ROOT: "1",
    IONSTACK_XRW_HOLD: "1",
    IONSTACK_ROOT_WALK_MAX: "110",
    IONSTACK_SELF_ROOT: "0",
    IONSTACK_KMEM_CFG_BUDGET: "20000",
    IONSTACK_PIPE_ORACLE_FAST: "1",
};

/**
 * Quest 2 tuning, for the Android 12 kernel.
 *
 * Supplied by the exploit's author like the Quest 1 block, and not the same
 * shape as it: no `IONSTACK_XRW_*`, no `IONSTACK_SELF_ROOT`, no keeper hold.
 * Nothing here says how long a rooted shell stays rooted, so the root step
 * reports what it observes rather than assuming this build behaves like the
 * Quest 1 one.
 *
 * The name records which OS it was tuned against: a Quest 2 still on Android
 * 10 would need its own block, and running this one there is not something to
 * do by accident.
 */
const QUEST2A12_ENV: Record<string, string> = {
    IONSTACK_STAGE: "full",
    IONSTACK_FOPS_SAFE_TABLE: "1",
    IONSTACK_TREE_ENTRY_WRITE: "1",
    IONSTACK_FOPS_LOCK_OWNER_MODE: "none",
    IONSTACK_PTRACE_ROUTE_ATTEMPTS: "1",
    IONSTACK_MIN_WINDOW: "1",
    IONSTACK_RECLAIM_PERF_COUNTERS: "1",
    IONSTACK_RECLAIM_PFN_IDENTITY: "1",
    IONSTACK_RECLAIM_PHYS_PFN_START: "0x80600",
    IONSTACK_RECLAIM_PHYS_PFN_END: "0x200000",
    IONSTACK_RECLAIM_REQUIRE_PFN_MATCH: "1",
    IONSTACK_PAYLOAD: "",
    IONSTACK_PAGE_SETUP_ATTEMPTS: "24",
    IONSTACK_MEMFD_GATE_MAX_FIRES: "1",
    IONSTACK_STALL_HOLD_MS: "6000",
    IONSTACK_KS_COLLISIONS: "4",
    IONSTACK_SPRAY_STALL: "memfd",
    IONSTACK_KS_CORE: "7",
    IONSTACK_PAYLOAD_TIMEOUT: "120",
    IONSTACK_KS_AUTONARROW: "1",
    IONSTACK_RECLAIM_PHYS_PFN_RANGES: "0x80600-0x200000",
};

export const QUEST1: DeviceProfile = {
    id: "quest1",
    label: "Quest 1",
    codenames: ["monterey", "vr_monterey"],

    ionstack: "/binaries/quest1/ionstack",
    ionstackEnv: QUEST1_ENV,
    // Supplied by the exploit's author. The build index in versions.json
    // names the versions these correspond to.
    rootSupported: [
        "15849800125100000",
        "15849800145900000",
        "16476800119700000",
        "17007100171000000",
        "17007100222700000",
        "17692500170700000",
        "17692500215900000",
        "17692500235000000",
        "18371800151300000",
        "18371800230900000",
        "19130100108400000",
        "19130100171400000",
        "19130100198300000",
        "19130100301000000",
        "20169900218100000",
        "21985310243700000",
        "21985310424700000",
        "22310100490800000",
        "28467500771700000",
        "37314400805600000",
        "47421700667500000",
        "49068160374000400",
        "49713390192800400",
        "49845030259200400",
        "49845030369000410",
        "49845030443200410",
    ],

    downgradeTarget: "16476800119700000",
    firmware: "/binaries/quest1/16476800119700000.zip",
    // Every partition of the boot chain the vulnerable abl needs, plus the
    // kernel and modem that have to match it.
    partitions: [
        "xbl",
        "abl",
        "rpm",
        "tz",
        "hyp",
        "devcfg",
        "pmic",
        "cmnlib",
        "cmnlib64",
        "keymaster",
        "ovrtz",
        "modem",
        "boot",
    ],

    unlock: {
        patch: PATCH_16476800119700000,
        ablSha256: "c2cc1f173bec2956fa5e068abc98db82e1cd2c651a4f4bb7ae31c79605e43707",
        peSha256: "7663280938b54f8dc061b502f581cba4bea638473080c44a8dcfec88a570f74c",
    },

    byNameDirs: ["/dev/block/bootdevice/by-name", "/dev/block/by-name"],
};

/**
 * Quest 2 — not usable yet.
 *
 * The firmware is the 10 May 2021 build, the same era as the Quest 1 target.
 * Its chain is an SM8250 one, so it is not the Quest 1 list with different
 * names: there is no `rpm` (the AOP replaces it), no `pmic` and no `ovrtz`,
 * and there are seven the Quest 1 has no equivalent for.
 *
 * The firmware archive, the bootloader patch and the ionstack tuning are all
 * in place. The one thing still missing is the ionstack binary itself: until
 * `binaries/quest2a12/ionstack` is in the build, the flow refuses the device
 * rather than failing at the root step with a 404.
 */
export const QUEST2: DeviceProfile = {
    id: "quest2",
    label: "Quest 2",
    codenames: ["hollywood"],

    ionstack: "/binaries/quest2a12/ionstack",
    ionstackEnv: QUEST2A12_ENV,
    rootSupported: ["50670960048600150"],
    // Patched after this build; newer headsets are turned away at the gates.
    maxSupportedBuild: "50670960048600150",

    downgradeTarget: "16476800118700000",
    firmware: "/binaries/quest2a12/16476800118700000.zip",
    partitions: [
        "xbl",
        "xbl_config",
        "aop",
        "tz",
        "hyp",
        "devcfg",
        "cmnlib",
        "cmnlib64",
        "keymaster",
        "uefisecapp",
        "imagefv",
        "featenabler",
        "qupfw",
        "abl",
        "modem",
        "dtbo",
        "boot",
    ],

    unlock: {
        patch: PATCH_16476800118700000,
        ablSha256: "7fcc464d3528b6e570540e1068521e3a2fa0486c1be3a8f89c8321bafa85d008",
        peSha256: "67d424fd540d9f598285b54aa151bba25cf181b965b3ac4d65de3f6a92c39675",
    },

    // Both exist on a hollywood and both carry every partition above; this is
    // the one the device itself uses.
    byNameDirs: ["/dev/block/by-name", "/dev/block/bootdevice/by-name"],
};

export const PROFILES: readonly DeviceProfile[] = [QUEST1, QUEST2];

/**
 * Whether the whole procedure can actually run on this device.
 *
 * A profile can exist — so the device is recognised and said by name — long
 * before every piece it needs has been supplied. Refusing here is what keeps
 * a half-supported device from being downgraded and then left locked.
 */
export function isSupported(profile: DeviceProfile): boolean {
    return missingPieces(profile).length === 0;
}

/**
 * What is still missing, for a profile that is not supported yet.
 *
 * Whether the ionstack binary is actually in this build is checked separately,
 * where the payload manifest is in scope — see the identify step.
 */
export function missingPieces(profile: DeviceProfile): string[] {
    const missing: string[] = [];
    if (Object.keys(profile.ionstackEnv).length === 0) {
        missing.push("the ionstack tuning for this kernel");
    }
    if (!profile.unlock) {
        missing.push(`the bootloader patch for ${profile.downgradeTarget}`);
    }
    return missing;
}

/** Matches `ro.product.device` against the known profiles. */
export function profileFor(codename: string): DeviceProfile | undefined {
    const needle = codename.trim().toLowerCase();
    return PROFILES.find((profile) =>
        profile.codenames.some((name) => name === needle),
    );
}
