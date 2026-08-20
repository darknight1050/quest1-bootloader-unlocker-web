// bootctl_shim - minimal boot control client.
// Loads the vendor boot_control HAL module directly via dlopen, bypassing
// HIDL. Equivalent to AOSP `bootctl`, which is itself only a passthrough.
//
// build (NDK):
//   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang \
//       -O2 -Wall -Wextra -Iinc -o bootctl_shim bootctl_shim.c
// bc_min.h carries the hw_module_t / boot_control_module_t layouts copied
// verbatim from AOSP android10-release.

#include <dlfcn.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "bc_min.h"

static const char *CANDIDATES[] = {
    "/vendor/lib64/hw/bootctrl.*.so",
    "/vendor/lib/hw/bootctrl.*.so",
    // devices with no separate vendor partition (e.g. Quest 1) keep it here
    "/system/vendor/lib64/hw/bootctrl.*.so",
    "/system/vendor/lib/hw/bootctrl.*.so",
    "/system/lib64/hw/bootctrl.*.so",
    "/system/lib/hw/bootctrl.*.so",
    "/odm/lib64/hw/bootctrl.*.so",
    NULL
};

static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s [-l lib] <command>\n"
        "  read-only:\n"
        "    info                       module id/name/author + slot summary\n"
        "    get-number-slots\n"
        "    get-current-slot\n"
        "    get-suffix <slot>\n"
        "    is-slot-bootable <slot>\n"
        "    is-slot-marked-successful <slot>\n"
        "  writes:\n"
        "    set-active-boot-slot <slot>\n"
        "    set-slot-as-unbootable <slot>\n"
        "    mark-boot-successful\n"
        "  slot is 0 (_a) or 1 (_b)\n", p);
}

// Literal names to try when glob() finds nothing -- SELinux can deny listing a
// directory while still permitting open() of a file inside it, in which case
// glob returns empty but a direct dlopen succeeds.
static const char *LITERAL_DIRS[] = {
    "/vendor/lib64/hw", "/system/vendor/lib64/hw", "/system/lib64/hw",
    "/odm/lib64/hw", NULL
};
static const char *LITERAL_NAMES[] = {
    "bootctrl.msm8998.so", "bootctrl.kona.so", "bootctrl.lahaina.so",
    "bootctrl.default.so", "bootctrl.qcom.so", NULL
};

static void *try_open(const char *p, char *found, size_t n, int verbose) {
    struct stat st;
    int have = (stat(p, &st) == 0);
    void *h = dlopen(p, RTLD_NOW);
    if (h) { snprintf(found, n, "%s", p); return h; }
    if (verbose)
        fprintf(stderr, "  %-48s stat=%s dlopen=%s\n", p,
                have ? "ok" : strerror(errno), dlerror());
    return NULL;
}

static void *find_module(const char *forced, char *found, size_t n) {
    char dummy[512];
    if (forced) {
        void *h = try_open(forced, found, n, 1);
        if (!h) fprintf(stderr, "forced path failed\n");
        return h;
    }
    // pass 0 quiet, pass 1 verbose
    for (int pass = 0; pass < 2; pass++) {
        if (pass) fprintf(stderr, "searching for boot_control module (uid=%d euid=%d):\n",
                          (int)getuid(), (int)geteuid());
        for (int i = 0; CANDIDATES[i]; i++) {
            glob_t g;
            int rc = glob(CANDIDATES[i], 0, NULL, &g);
            if (pass)
                fprintf(stderr, "  glob %-44s rc=%d matches=%zu\n",
                        CANDIDATES[i], rc, rc == 0 ? g.gl_pathc : (size_t)0);
            if (rc == 0) {
                for (size_t j = 0; j < g.gl_pathc; j++) {
                    void *h = try_open(g.gl_pathv[j], found, n, pass);
                    if (h) { globfree(&g); return h; }
                }
                globfree(&g);
            }
        }
        for (int d = 0; LITERAL_DIRS[d]; d++) {
            for (int f = 0; LITERAL_NAMES[f]; f++) {
                char p[512];
                snprintf(p, sizeof(p), "%s/%s", LITERAL_DIRS[d], LITERAL_NAMES[f]);
                void *h = try_open(p, pass ? found : dummy, pass ? n : sizeof(dummy), pass);
                if (h) { snprintf(found, n, "%s", p); return h; }
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *forced = NULL;
    int a = 1;
    if (argc > 2 && strcmp(argv[1], "-l") == 0) { forced = argv[2]; a = 3; }
    if (a >= argc) { usage(argv[0]); return 2; }

    char path[512] = {0};
    void *h = find_module(forced, path, sizeof(path));
    if (!h) { fprintf(stderr, "no boot_control module could be loaded\n"); return 1; }

    boot_control_module_t *m = (boot_control_module_t *)dlsym(h, HAL_MODULE_INFO_SYM_AS_STR);
    if (!m) { fprintf(stderr, "dlsym(%s): %s\n", HAL_MODULE_INFO_SYM_AS_STR, dlerror()); return 1; }
    if (m->common.tag != HARDWARE_MODULE_TAG) {
        fprintf(stderr, "bad module tag 0x%x (expected 0x%x)\n",
                m->common.tag, HARDWARE_MODULE_TAG);
        return 1;
    }
    if (!m->init) { fprintf(stderr, "module has no init()\n"); return 1; }
    m->init(m);

    const char *cmd = argv[a];
    unsigned slot = (a + 1 < argc) ? (unsigned)strtoul(argv[a + 1], NULL, 10) : 0;
    int need_slot = (a + 1 < argc);

    if (!strcmp(cmd, "info")) {
        printf("module    : %s\n", path);
        printf("id        : %s\n", m->common.id ? m->common.id : "(null)");
        printf("name      : %s\n", m->common.name ? m->common.name : "(null)");
        printf("author    : %s\n", m->common.author ? m->common.author : "(null)");
        unsigned n = m->getNumberSlots ? m->getNumberSlots(m) : 0;
        printf("slots     : %u\n", n);
        if (m->getCurrentSlot) printf("current   : %u\n", m->getCurrentSlot(m));
        for (unsigned s = 0; s < n; s++) {
            printf("  slot %u (%s) bootable=%d successful=%d\n", s,
                   m->getSuffix ? m->getSuffix(m, s) : "?",
                   m->isSlotBootable ? m->isSlotBootable(m, s) : -1,
                   m->isSlotMarkedSuccessful ? m->isSlotMarkedSuccessful(m, s) : -1);
        }
        return 0;
    }
    if (!strcmp(cmd, "get-number-slots")) { printf("%u\n", m->getNumberSlots(m)); return 0; }
    if (!strcmp(cmd, "get-current-slot")) { printf("%u\n", m->getCurrentSlot(m)); return 0; }
    if (!strcmp(cmd, "mark-boot-successful")) {
        int r = m->markBootSuccessful(m); printf("ret=%d\n", r); return r ? 1 : 0;
    }
    if (!need_slot) { usage(argv[0]); return 2; }

    if (!strcmp(cmd, "get-suffix")) { printf("%s\n", m->getSuffix(m, slot)); return 0; }
    if (!strcmp(cmd, "is-slot-bootable")) { printf("%d\n", m->isSlotBootable(m, slot)); return 0; }
    if (!strcmp(cmd, "is-slot-marked-successful")) { printf("%d\n", m->isSlotMarkedSuccessful(m, slot)); return 0; }
    if (!strcmp(cmd, "set-active-boot-slot")) {
        int r = m->setActiveBootSlot(m, slot); printf("ret=%d\n", r); return r ? 1 : 0;
    }
    if (!strcmp(cmd, "set-slot-as-unbootable")) {
        int r = m->setSlotAsUnbootable(m, slot); printf("ret=%d\n", r); return r ? 1 : 0;
    }
    usage(argv[0]);
    return 2;
}
