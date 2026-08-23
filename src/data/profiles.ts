/**
 * The Quest 1 device profile.
 *
 * The ionstack tuning is kernel-specific — this build sprays memfd and walks a
 * single PFN range — so the binary and its environment travel together and
 * neither is interchangeable with another device's.
 */

export interface DeviceProfile {
    readonly id: "quest1";
    readonly label: string;
    /** Values of `ro.product.device` this profile applies to. */
    readonly codenames: readonly string[];
    /** URL of the ionstack build for this kernel. */
    readonly ionstack: string;
    readonly ionstackEnv: Readonly<Record<string, string>>;
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

export const QUEST1: DeviceProfile = {
    id: "quest1",
    label: "Quest 1",
    codenames: ["monterey", "vr_monterey"],
    ionstack: "/binaries/ionstack",
    ionstackEnv: QUEST1_ENV,
    byNameDirs: ["/dev/block/bootdevice/by-name", "/dev/block/by-name"],
};

export const PROFILES: readonly DeviceProfile[] = [QUEST1];

/** Matches `ro.product.device` against the known profiles. */
export function profileFor(codename: string): DeviceProfile | undefined {
    const needle = codename.trim().toLowerCase();
    return PROFILES.find((profile) =>
        profile.codenames.some((name) => name === needle),
    );
}
