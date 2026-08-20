// Self-contained subset of AOSP hardware/hardware.h + hardware/boot_control.h.
// Layouts copied verbatim from android10-release so the ABI matches the vendor
// module exactly; avoids pulling in the graphics/cutils dependency chain.
#ifndef BC_MIN_H
#define BC_MIN_H

#include <stdint.h>

#define MAKE_TAG_CONSTANT(A,B,C,D) (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define HARDWARE_MODULE_TAG        MAKE_TAG_CONSTANT('H', 'W', 'M', 'T')
#define HAL_MODULE_INFO_SYM_AS_STR "HMI"

struct hw_module_t;
struct hw_module_methods_t;
struct hw_device_t;

typedef struct hw_module_t {
    uint32_t tag;
    uint16_t module_api_version;
    uint16_t hal_api_version;
    const char *id;
    const char *name;
    const char *author;
    struct hw_module_methods_t* methods;
    void* dso;
#ifdef __LP64__
    uint64_t reserved[32-7];
#else
    uint32_t reserved[32-7];
#endif
} hw_module_t;

typedef struct hw_module_methods_t {
    int (*open)(const struct hw_module_t* module, const char* id,
                struct hw_device_t** device);
} hw_module_methods_t;

typedef struct boot_control_module {
    struct hw_module_t common;
    void (*init)(struct boot_control_module *module);
    unsigned (*getNumberSlots)(struct boot_control_module *module);
    unsigned (*getCurrentSlot)(struct boot_control_module *module);
    int (*markBootSuccessful)(struct boot_control_module *module);
    int (*setActiveBootSlot)(struct boot_control_module *module, unsigned slot);
    int (*setSlotAsUnbootable)(struct boot_control_module *module, unsigned slot);
    int (*isSlotBootable)(struct boot_control_module *module, unsigned slot);
    const char* (*getSuffix)(struct boot_control_module *module, unsigned slot);
    int (*isSlotMarkedSuccessful)(struct boot_control_module *module, unsigned slot);
    void* reserved[31];
} boot_control_module_t;

#endif
