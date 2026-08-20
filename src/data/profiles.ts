/**
 * Per-device profiles.
 *
 * The ionstack tuning is kernel-specific: the Quest 1 build sprays memfd and
 * walks a single PFN range, the Quest 3 build sprays io_uring across two. They
 * are not interchangeable, so the binary and its environment travel together.
 */

export interface DeviceProfile {
    readonly id: "quest1" | "quest3";
    readonly label: string;
    /** Values of `ro.product.device` this profile applies to. */
    readonly codenames: readonly string[];
    /** URL of the ionstack build for this kernel. */
    readonly ionstack: string;
    readonly ionstackEnv: Readonly<Record<string, string>>;
    /**
     * Whether the full unlock flow may run against this device.
     *
     * Only the Quest 1 has downgrade images and a bootloader patch here.
     * Everything else is limited to the read-only dev flow.
     */
    readonly allowWrites: boolean;
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
 * Quest 3 tuning, transcribed from a real run's `startup env` lines.
 *
 * Note `IONSTACK_KEEPER_HOLD_SEC=300`: on this build a keeper process holds the
 * primitive for five minutes, so privileged work should not be left sitting.
 */
const QUEST3_ENV: Record<string, string> = {
    IONSTACK_STAGE: "full",
    IONSTACK_SPRAY_ROUTE: "io_uring",
    IONSTACK_IOURING_SPRAY_CAP: "4000",
    IONSTACK_IOURING_SPRAY_AFTER_SUCCESS: "1000",
    IONSTACK_MIN_WINDOW: "1",
    IONSTACK_PAYLOAD: "",
    IONSTACK_PAYLOAD_TIMEOUT: "120",
    IONSTACK_KS_CORE: "4",
    IONSTACK_KS_ID_START: "0xffffff8000000000",
    IONSTACK_KS_ID_END: "0xffffff8900000000",
    IONSTACK_PTRACE_ROUTE_ATTEMPTS: "4",
    IONSTACK_KEEPER_HOLD_SEC: "300",
    IONSTACK_CFI_GATE: "1",
    IONSTACK_FOPS_SAFE_TABLE: "1",
    IONSTACK_FOPS_LOCK_OWNER_MODE: "none",
    IONSTACK_TREE_ENTRY_WRITE: "1",
    IONSTACK_SKB_DATA_DELTA: "0",
    IONSTACK_RESTORE_BEFORE_ROOT: "1",
    IONSTACK_RECLAIM_CORE: "4",
    IONSTACK_RECLAIM_PERF_COUNTERS: "1",
    IONSTACK_RECLAIM_PERF_FRAG_GFP: "0x5428c0",
    IONSTACK_RECLAIM_PFN_IDENTITY: "1",
    IONSTACK_RECLAIM_REQUIRE_PFN_MATCH: "1",
    IONSTACK_RECLAIM_PHYS_PFN_START: "0x803600",
    IONSTACK_RECLAIM_PHYS_PFN_END: "0x980000",
    IONSTACK_RECLAIM_PHYS_PFN_RANGES: "0x80000-0x100000,0x803600-0x980000",
    IONSTACK_RECLAIM_LINEAR_SEGMENT_PAGES: "0x20000",
    IONSTACK_RECLAIM_POSTTARGET_SEARCH: "1",
    IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS: "8",
    IONSTACK_RECLAIM_POSTTARGET_SENDS: "8192",
};

export const PROFILES: readonly DeviceProfile[] = [
    {
        id: "quest1",
        label: "Quest 1",
        codenames: ["monterey", "vr_monterey"],
        ionstack: "/binaries/ionstack",
        ionstackEnv: QUEST1_ENV,
        allowWrites: true,
        byNameDirs: ["/dev/block/bootdevice/by-name", "/dev/block/by-name"],
    },
    {
        id: "quest3",
        label: "Quest 3 / 3S",
        codenames: ["eureka", "panther", "vr_eureka", "vr_panther"],
        ionstack: "/binaries/dev/ionstack-quest3",
        ionstackEnv: QUEST3_ENV,
        allowWrites: false,
        byNameDirs: ["/dev/block/by-name", "/dev/block/bootdevice/by-name"],
    },
];

export const QUEST1 = PROFILES[0]!;
export const QUEST3 = PROFILES[1]!;

/** Matches `ro.product.device` against the known profiles. */
export function profileFor(codename: string): DeviceProfile | undefined {
    const needle = codename.trim().toLowerCase();
    return PROFILES.find((profile) =>
        profile.codenames.some((name) => name === needle),
    );
}
