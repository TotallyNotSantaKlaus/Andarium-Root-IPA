// SPDX-License-Identifier: GPL-2.0-or-later
// AndariumRootPreboot.dylib (v5.1 / Pre-Boot Studio v2 + Hardened JIT Engine)
// 1. Pre-main() constructor probes P_TRACED / csops, auto-arms `andarium.jit` when
//    launched from StikDebug, preserves `ANDARIUM_JIT` when VM hardware overrides
//    are active (defeating Kernarium's `hasOtherSettings` detach), and injects
//    saved VM Hardware & Multi-VM Slot env overrides before Swift AppEntry runs.
// 2. Hooks `vm_allocate` (36-bit <64 GiB address shield for StikDebug's 9-nibble
//    `fillAddress` truncation bug), `mlock` (graceful MADV_WILLNEED fallback when
//    free-cert signers strip `increased-memory-limit`), and `fprintf`/`printf`
//    (captures exact `Kernarium: JIT memory:` runtime diagnostics).
// 3. Presents floating `# Root Setup` / `# Setup · ⚡ JIT` pill on Andarium Home
//    with live JIT Doctor, 1-tap `stikdebug://enable-jit` deep-link, and dynamic
//    `androidboot.ar.cfg=5,...` kernel command line generation.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <errno.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <os/proc.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <unistd.h>
#import "fishhook.h"

extern int csops(pid_t pid, unsigned int operation, void *buffer, size_t size);

#define AR_CS_OPS_STATUS          0U
#define AR_CS_KILL                0x00000200U
#define AR_CS_DEBUGGED            0x10000000U
#define AR_STIKDEBUG_36BIT_LIMIT  0x1000000000ULL
#define AR_JIT_TRACE_CAP          24
#define AR_JIT_TRACE_LINE_LEN     256

static NSString *const kLegacyConfigKey   = @"AndariumRootPrebootConfigV4";
static NSString *const kConfigRevisionKey = @"AndariumRootPrebootRevisionV4";
static NSString *const kHardwareKey       = @"AndariumRootVmHardwareV5";
static NSString *const kCustomPresetsKey  = @"AndariumRootCustomPresetsV5";
static NSString *const kSlotListKey       = @"AndariumRootVmSlotsV5";

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static kern_return_t (*orig_vm_allocate)(vm_map_t, vm_address_t *, vm_size_t, int) = NULL;
static int (*orig_mlock)(const void *, size_t) = NULL;

static char g_override_cmdline_path[PATH_MAX] = {0};
static NSString *g_active_slot = @"default";
static NSString *g_launch_hw_sig = @"";

// Lock-free / mutex-guarded JIT hardening state & diagnostic trace ring buffer
static volatile int32_t g_jit_36bit_shield = 1;
static volatile int32_t g_jit_soft_mlock = 1;
static volatile int32_t g_jit_traced_at_launch = 0;
static volatile int32_t g_jit_relocations = 0;
static volatile int32_t g_jit_soft_mlocks = 0;
static volatile int32_t g_jit_failed_seen = 0;

static pthread_mutex_t g_jit_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_jit_trace_buf[AR_JIT_TRACE_CAP][AR_JIT_TRACE_LINE_LEN];
static int g_jit_trace_head = 0;
static int g_jit_trace_count = 0;

static void ar_jit_record_trace(const char *raw) {
    if (!raw || raw[0] == '\0') return;
    pthread_mutex_lock(&g_jit_trace_lock);
    char *dst = g_jit_trace_buf[g_jit_trace_head];
    size_t i = 0;
    for (; i < AR_JIT_TRACE_LINE_LEN - 1 && raw[i] != '\0'; i++) {
        char c = raw[i];
        if (c == '\r' || c == '\n') break;
        dst[i] = c;
    }
    dst[i] = '\0';
    if (i > 0) {
        g_jit_trace_head = (g_jit_trace_head + 1) % AR_JIT_TRACE_CAP;
        if (g_jit_trace_count < AR_JIT_TRACE_CAP) {
            g_jit_trace_count++;
        }
    }
    pthread_mutex_unlock(&g_jit_trace_lock);
}

static NSArray<NSString *> *ar_jit_copy_traces(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    pthread_mutex_lock(&g_jit_trace_lock);
    int start = (g_jit_trace_head - g_jit_trace_count + AR_JIT_TRACE_CAP) % AR_JIT_TRACE_CAP;
    for (int i = 0; i < g_jit_trace_count; i++) {
        int idx = (start + i) % AR_JIT_TRACE_CAP;
        NSString *line = [NSString stringWithUTF8String:g_jit_trace_buf[idx]];
        if (line.length > 0) {
            [out addObject:line];
        }
    }
    pthread_mutex_unlock(&g_jit_trace_lock);
    return out;
}

static BOOL ar_is_traced_now(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc kp;
    memset(&kp, 0, sizeof(kp));
    size_t sz = sizeof(kp);
    if (sysctl(mib, 4, &kp, &sz, NULL, 0) != 0) {
        return NO;
    }
    return (kp.kp_proc.p_flag & P_TRACED) != 0;
}

static BOOL ar_read_cs_flags(uint32_t *out_flags) {
    uint32_t flags = 0;
    if (csops(getpid(), AR_CS_OPS_STATUS, &flags, sizeof(flags)) != 0) {
        return NO;
    }
    if (out_flags) *out_flags = flags;
    return YES;
}

static NSString *ar_device_machine(void) {
    struct utsname u;
    memset(&u, 0, sizeof(u));
    if (uname(&u) == 0 && u.machine[0] != '\0') {
        return [NSString stringWithUTF8String:u.machine] ?: @"unknown";
    }
    return @"unknown";
}

static BOOL ar_device_expects_txm(NSString *machine) {
    if (![machine isKindOfClass:[NSString class]]) return NO;
    int major = 0, minor = 0;
    if (sscanf(machine.UTF8String, "iPhone%d,%d", &major, &minor) == 2) {
        // A17 Pro (iPhone16,1/2 = 15 Pro/Max) and A18/A19+ (iPhone17+ = 16/17 series)
        return (major >= 17) || (major == 16 && (minor == 1 || minor == 2));
    }
    if (sscanf(machine.UTF8String, "iPad%d,%d", &major, &minor) == 2) {
        // M4 iPad Pro / A17 Pro iPad mini (iPad16,x) and newer
        return major >= 16;
    }
    return NO;
}

// MARK: - Hardened Mach / Libc Hooks (fishhook excludes AndariumRootPreboot itself)

static BOOL ar_is_cmdline_path(const char *path) {
    if (!path || g_override_cmdline_path[0] == '\0') return NO;
    size_t len = strlen(path);
    const char *suffix = "/boot/kernel-command-line.txt";
    size_t slen = strlen(suffix);
    if (len < slen) return NO;
    if (strcmp(path + (len - slen), suffix) != 0) return NO;
    if (strcmp(path, g_override_cmdline_path) == 0) return NO;
    return YES;
}

static int ar_hooked_lstat(const char *path, struct stat *buf) {
    const char *target = ar_is_cmdline_path(path) ? g_override_cmdline_path : path;
    return orig_lstat ? orig_lstat(target, buf) : lstat(target, buf);
}

static FILE *ar_hooked_fopen(const char *path, const char *mode) {
    const char *target = ar_is_cmdline_path(path) ? g_override_cmdline_path : path;
    return orig_fopen ? orig_fopen(target, mode) : fopen(target, mode);
}

// Shield against StikDebug JSDebugSupport.swift 36-bit (9-nibble) address truncation:
// Relocate 16 KiB-aligned VM_FLAGS_ANYWHERE mappings >= 64 GiB into < 64 GiB slots.
static kern_return_t ar_hooked_vm_allocate(vm_map_t target_task,
                                           vm_address_t *address,
                                           vm_size_t size,
                                           int flags) {
    kern_return_t kr = orig_vm_allocate
        ? orig_vm_allocate(target_task, address, size, flags)
        : vm_allocate(target_task, address, size, flags);

    if (kr == KERN_SUCCESS &&
        g_jit_36bit_shield &&
        target_task == mach_task_self() &&
        address != NULL &&
        (flags & VM_FLAGS_ANYWHERE) != 0 &&
        size >= (16ULL * 1024ULL) &&
        size <= (1024ULL * 1024ULL * 1024ULL) &&
        (size & 0x3FFFULL) == 0) {

        uint64_t addr64 = (uint64_t)(*address);
        uint64_t size64 = (uint64_t)size;
        BOOL exceeds36Bit = (addr64 >= AR_STIKDEBUG_36BIT_LIMIT) ||
                            (size64 > AR_STIKDEBUG_36BIT_LIMIT - addr64);
        if (exceeds36Bit && size64 < AR_STIKDEBUG_36BIT_LIMIT) {
            uint64_t maxCand = AR_STIKDEBUG_36BIT_LIMIT - size64;
            BOOL relocated = NO;

            // Primary scan: 8 GiB .. 64 GiB in 64 MiB steps
            const uint64_t kPrimaryStart = 0x0200000000ULL;
            const uint64_t kPrimaryStep  = 0x04000000ULL;
            for (uint64_t cand = kPrimaryStart; cand <= maxCand; cand += kPrimaryStep) {
                vm_address_t tryAddr = (vm_address_t)cand;
                kern_return_t r = orig_vm_allocate
                    ? orig_vm_allocate(target_task, &tryAddr, size, VM_FLAGS_FIXED)
                    : vm_allocate(target_task, &tryAddr, size, VM_FLAGS_FIXED);
                if (r == KERN_SUCCESS) {
                    (void)vm_deallocate(target_task, *address, size);
                    *address = tryAddr;
                    relocated = YES;
                    break;
                }
            }

            // Secondary scan: 5 GiB .. 8 GiB in 16 MiB steps if upper space was fragmented
            if (!relocated) {
                const uint64_t kSecondaryStart = 0x0140000000ULL;
                const uint64_t kSecondaryEnd   = 0x0200000000ULL;
                const uint64_t kSecondaryStep  = 0x01000000ULL;
                uint64_t limit = maxCand < kSecondaryEnd ? maxCand : kSecondaryEnd;
                for (uint64_t cand = kSecondaryStart; cand <= limit; cand += kSecondaryStep) {
                    vm_address_t tryAddr = (vm_address_t)cand;
                    kern_return_t r = orig_vm_allocate
                        ? orig_vm_allocate(target_task, &tryAddr, size, VM_FLAGS_FIXED)
                        : vm_allocate(target_task, &tryAddr, size, VM_FLAGS_FIXED);
                    if (r == KERN_SUCCESS) {
                        (void)vm_deallocate(target_task, *address, size);
                        *address = tryAddr;
                        relocated = YES;
                        break;
                    }
                }
            }

            if (relocated) {
                __atomic_fetch_add(&g_jit_relocations, 1, __ATOMIC_RELAXED);
                char line[192];
                snprintf(line, sizeof(line),
                         "36-bit shield relocated %llu MiB region 0x%llx -> 0x%llx (<64 GiB)",
                         (unsigned long long)((size64 + (1024ULL * 1024ULL - 1ULL)) / (1024ULL * 1024ULL)),
                         (unsigned long long)addr64,
                         (unsigned long long)(*address));
                ar_jit_record_trace(line);
            }
        }
    }
    return kr;
}

// Soft-mlock fallback: if real mlock() fails with ENOMEM/EPERM/EAGAIN (common when
// free Apple ID signers strip `increased-memory-limit`), issue MADV_WILLNEED and
// return 0 so Kernarium still verifies real ARM64 code execution via Region::check().
static int ar_hooked_mlock(const void *addr, size_t len) {
    int rc = orig_mlock ? orig_mlock(addr, len) : mlock(addr, len);
    if (rc == 0) return 0;
    int saved_errno = errno;
    if (g_jit_soft_mlock &&
        (saved_errno == ENOMEM || saved_errno == EPERM || saved_errno == EAGAIN)) {
        if (addr && len > 0) {
            (void)madvise((void *)addr, len, MADV_WILLNEED);
        }
        __atomic_fetch_add(&g_jit_soft_mlocks, 1, __ATOMIC_RELAXED);
        char line[192];
        snprintf(line, sizeof(line),
                 "Soft-mlock rescued %llu MiB region (mlock errno=%d -> MADV_WILLNEED)",
                 (unsigned long long)((len + (1024ULL * 1024ULL - 1ULL)) / (1024ULL * 1024ULL)),
                 saved_errno);
        ar_jit_record_trace(line);
        errno = 0;
        return 0;
    }
    errno = saved_errno;
    return rc;
}

static BOOL ar_is_jit_log_fmt(const char *fmt) {
    if (!fmt) return NO;
    return (strstr(fmt, "Kernarium: JIT memory:") != NULL ||
            strstr(fmt, "Kernarium: running on gadgets") != NULL ||
            strstr(fmt, "Kernarium: GPU budget") != NULL ||
            strstr(fmt, "Andarium: JIT") != NULL);
}

static int ar_hooked_fprintf(FILE *stream, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (ar_is_jit_log_fmt(fmt)) {
        va_list ap_copy;
        va_copy(ap_copy, ap);
        char line[AR_JIT_TRACE_LINE_LEN];
        vsnprintf(line, sizeof(line), fmt, ap_copy);
        va_end(ap_copy);
        ar_jit_record_trace(line);
        if (strstr(line, "JIT memory:") != NULL || strstr(line, "running on gadgets") != NULL) {
            __atomic_store_n(&g_jit_failed_seen, 1, __ATOMIC_RELAXED);
        }
    }
    int ret = vfprintf(stream, fmt, ap);
    va_end(ap);
    return ret;
}

static int ar_hooked_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (ar_is_jit_log_fmt(fmt)) {
        va_list ap_copy;
        va_copy(ap_copy, ap);
        char line[AR_JIT_TRACE_LINE_LEN];
        vsnprintf(line, sizeof(line), fmt, ap_copy);
        va_end(ap_copy);
        ar_jit_record_trace(line);
        if (strstr(line, "JIT memory:") != NULL || strstr(line, "running on gadgets") != NULL) {
            __atomic_store_n(&g_jit_failed_seen, 1, __ATOMIC_RELAXED);
        }
    }
    int ret = vprintf(fmt, ap);
    va_end(ap);
    return ret;
}

// MARK: - Config / Hardware Helpers

static NSString *ar_sanitize_token(NSString *raw, NSString *allowedPattern, NSString *fallback) {
    if (![raw isKindOfClass:[NSString class]] || raw.length == 0) return fallback;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:allowedPattern options:0 error:nil];
    NSRange r = NSMakeRange(0, raw.length);
    if ([re numberOfMatchesInString:raw options:0 range:r] == 1) {
        return raw;
    }
    return fallback;
}

static NSBundle *ar_resource_bundle(void) {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"AndariumRootPreboot" ofType:@"bundle"];
    return path ? [NSBundle bundleWithPath:path] : [NSBundle mainBundle];
}

static NSDictionary *ar_load_defaults_json(void) {
    NSString *p = [ar_resource_bundle() pathForResource:@"defaults" ofType:@"json"];
    if (!p) return @{};
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) return @{};
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
}

static NSDictionary *ar_load_json_dict_key(NSString *key) {
    NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (saved.length == 0) return @{};
    id obj = [NSJSONSerialization JSONObjectWithData:[saved dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
}

static void ar_save_json_obj(id obj, NSString *key) {
    if (!obj) return;
    NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    if (!d) return;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s) return;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:s forKey:key];
    [ud synchronize];
}

static NSString *ar_sanitize_slot(NSString *raw) {
    if (![raw isKindOfClass:[NSString class]] || raw.length == 0) return @"default";
    NSString *s = ar_sanitize_token(raw, @"^[A-Za-z0-9_-]{1,32}$", @"default");
    return [s isEqualToString:@"default"] ? @"default" : s;
}

static NSDictionary *ar_current_hardware(void) {
    NSDictionary *saved = ar_load_json_dict_key(kHardwareKey);
    NSString *slot = ar_sanitize_slot(saved[@"slot"]);
    NSInteger vcpu = [saved[@"vcpu"] integerValue];
    NSInteger memMiB = [saved[@"mem_mib"] integerValue];
    NSInteger diskGiB = [saved[@"disk_gib"] integerValue];
    NSString *scale = ar_sanitize_token(saved[@"display_scale"], @"^(auto|native|1\\.0|1\\.5|2\\.0|3\\.0)$", @"auto");
    BOOL thermalNom = [saved[@"thermal_nominal"] boolValue];
    BOOL statsHud = [saved[@"stats_hud"] boolValue];
    BOOL hapticsOff = [saved[@"haptics_off"] boolValue];
    NSString *jitMode = ar_sanitize_token(saved[@"jit_mode"], @"^(auto|force_on|off)$", @"auto");
    BOOL shield36 = saved[@"jit_36bit_shield"] != nil ? [saved[@"jit_36bit_shield"] boolValue] : YES;
    BOOL softMlock = saved[@"jit_soft_mlock"] != nil ? [saved[@"jit_soft_mlock"] boolValue] : YES;
    return @{
        @"slot": slot,
        @"vcpu": @(vcpu),
        @"mem_mib": @(memMiB),
        @"disk_gib": @(diskGiB),
        @"display_scale": scale,
        @"thermal_nominal": @(thermalNom),
        @"stats_hud": @(statsHud),
        @"haptics_off": @(hapticsOff),
        @"jit_mode": jitMode,
        @"jit_36bit_shield": @(shield36),
        @"jit_soft_mlock": @(softMlock),
    };
}

static NSString *ar_hw_signature(NSDictionary *hw) {
    return [NSString stringWithFormat:@"%@|%@|%@|%@|%@|%@|%@|%@",
            hw[@"slot"] ?: @"default", hw[@"vcpu"] ?: @0, hw[@"mem_mib"] ?: @0,
            hw[@"disk_gib"] ?: @0, hw[@"display_scale"] ?: @"auto",
            hw[@"thermal_nominal"] ?: @0, hw[@"haptics_off"] ?: @0,
            hw[@"jit_mode"] ?: @"auto"];
}

static void ar_apply_vm_hardware_env(void) {
    NSDictionary *hw = ar_current_hardware();
    g_active_slot = hw[@"slot"] ?: @"default";
    g_launch_hw_sig = ar_hw_signature(hw);

    __atomic_store_n(&g_jit_36bit_shield, [hw[@"jit_36bit_shield"] boolValue] ? 1 : 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_jit_soft_mlock, [hw[@"jit_soft_mlock"] boolValue] ? 1 : 0, __ATOMIC_RELAXED);

    BOOL tracedAtLaunch = ar_is_traced_now();
    __atomic_store_n(&g_jit_traced_at_launch, tracedAtLaunch ? 1 : 0, __ATOMIC_RELAXED);

    BOOL hasOtherLaunchSettings = NO;

    if (![g_active_slot isEqualToString:@"default"]) {
        setenv("ANDARIUM_GUEST_INSTANCE", g_active_slot.UTF8String, 1);
        hasOtherLaunchSettings = YES;
    }

    NSInteger maxCpu = (NSInteger)NSProcessInfo.processInfo.activeProcessorCount;
    if (maxCpu < 1) maxCpu = 1;
    NSInteger vcpu = [hw[@"vcpu"] integerValue];
    if (vcpu >= 1 && vcpu <= maxCpu) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)vcpu);
        setenv("KERNARIUM_VCPU_COUNT", buf, 1);
        hasOtherLaunchSettings = YES;
    }

    NSInteger memMiB = [hw[@"mem_mib"] integerValue];
    if (memMiB >= 512 && memMiB <= 16384 && (memMiB % 64) == 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)memMiB);
        setenv("KERNARIUM_GUEST_MEMORY_MIB", buf, 1);
        hasOtherLaunchSettings = YES;
    }

    NSInteger diskGiB = [hw[@"disk_gib"] integerValue];
    if (diskGiB >= 4 && diskGiB <= 64) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)diskGiB);
        setenv("KERNARIUM_ANDROID_DISK_SIZE_GIB", buf, 1);
        hasOtherLaunchSettings = YES;
    }

    NSString *scale = hw[@"display_scale"];
    if ([scale isKindOfClass:[NSString class]] && scale.length > 0 && ![scale isEqualToString:@"auto"]) {
        setenv("KERNARIUM_DISPLAY_SCALE", scale.UTF8String, 1);
        hasOtherLaunchSettings = YES;
    }

    if ([hw[@"thermal_nominal"] boolValue]) {
        setenv("ANDARIUM_THERMAL_STATE", "nominal", 1);
    }
    if ([hw[@"haptics_off"] boolValue]) {
        setenv("ANDARIUM_HAPTICS", "0", 1);
    }

    // Hardened JIT launch coordination (defeats fresh-install detach & hasOtherSettings disable):
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *jitMode = hw[@"jit_mode"] ?: @"auto";
    if ([jitMode isEqualToString:@"off"]) {
        [ud setBool:NO forKey:@"andarium.jit"];
        setenv("ANDARIUM_JIT", "0", 1);
        ar_jit_record_trace("JIT mode=off -> disabled at launch");
    } else if ([jitMode isEqualToString:@"force_on"]) {
        [ud setBool:YES forKey:@"andarium.jit"];
        setenv("ANDARIUM_JIT", "1", 1);
        ar_jit_record_trace("JIT mode=force_on -> forced ANDARIUM_JIT=1 + andarium.jit=YES");
    } else {
        // Default "auto": if launched under StikDebug (P_TRACED=1), arm andarium.jit immediately
        // so fresh installs don't send `detach` on launch before the user reaches Home.
        if (tracedAtLaunch) {
            [ud setBool:YES forKey:@"andarium.jit"];
            ar_jit_record_trace("StikDebug attached at launch (P_TRACED=1) -> auto-armed andarium.jit=YES");
        }
        // If any VM Slot/vCPU/RAM/Disk/Display override is active, Kernarium sets
        // `hasOtherSettings=true` which disables JIT unless ANDARIUM_JIT is explicit.
        if (hasOtherLaunchSettings) {
            BOOL wantJit = tracedAtLaunch || [ud boolForKey:@"andarium.jit"];
            setenv("ANDARIUM_JIT", wantJit ? "1" : "0", 1);
            if (wantJit) {
                ar_jit_record_trace("Launch overrides active -> preserved ANDARIUM_JIT=1");
            }
        }
    }

    // Sync Andarium's native FPS/CPU/RAM Stats HUD preference (real key: `andarium.statistics`)
    NSDictionary *rawSaved = ar_load_json_dict_key(kHardwareKey);
    if (rawSaved[@"stats_hud"] != nil) {
        [ud setBool:[rawSaved[@"stats_hud"] boolValue] forKey:@"andarium.statistics"];
    }
}

static NSDictionary *ar_build_jit_diagnostics(void) {
    NSDictionary *hw = ar_current_hardware();
    BOOL tracedNow = ar_is_traced_now();
    BOOL tracedAtLaunch = __atomic_load_n(&g_jit_traced_at_launch, __ATOMIC_RELAXED) != 0;
    uint32_t csFlags = 0;
    BOOL csOk = ar_read_cs_flags(&csFlags);
    BOOL csDebugged = csOk && ((csFlags & AR_CS_DEBUGGED) != 0);
    BOOL csKillCleared = csOk && ((csFlags & AR_CS_KILL) == 0);
    BOOL failedSeen = __atomic_load_n(&g_jit_failed_seen, __ATOMIC_RELAXED) != 0;
    BOOL jitPref = [[NSUserDefaults standardUserDefaults] boolForKey:@"andarium.jit"];
    NSString *jitMode = hw[@"jit_mode"] ?: @"auto";

    size_t availBytes = os_proc_available_memory();
    unsigned long long availMB = (unsigned long long)(availBytes / (1024ULL * 1024ULL));
    unsigned long long physMB = (unsigned long long)(NSProcessInfo.processInfo.physicalMemory / (1024ULL * 1024ULL));

    NSBundle *mainBundle = [NSBundle mainBundle];
    NSString *bundleId = mainBundle.bundleIdentifier ?: @"com.andarium.root";
    NSString *rootName = mainBundle.infoDictionary[@"CFBundleDisplayName"]
        ?: mainBundle.infoDictionary[@"CFBundleName"] ?: @"";
    NSString *locName = mainBundle.localizedInfoDictionary[@"CFBundleDisplayName"] ?: rootName;
    BOOL stikNameOk = [rootName isEqualToString:@"Andarium"];

    NSString *machine = ar_device_machine();
    BOOL expectsTxm = ar_device_expects_txm(machine);
    NSString *iosVer = [UIDevice currentDevice].systemVersion ?: @"unknown";

    BOOL stikInstalled = NO;
    if ([NSThread isMainThread]) {
        NSURL *probe = [NSURL URLWithString:@"stikdebug://"];
        if (probe) {
            stikInstalled = [[UIApplication sharedApplication] canOpenURL:probe];
        }
    }

    NSString *statusCode = @"needs_stikdebug";
    if ([jitMode isEqualToString:@"off"]) {
        statusCode = @"disabled";
    } else if (failedSeen) {
        statusCode = @"failed";
    } else if ((csDebugged && csKillCleared) || tracedAtLaunch || tracedNow) {
        statusCode = (jitPref || [jitMode isEqualToString:@"force_on"]) ? @"ready" : @"armed";
    }

    return @{
        @"status_code": statusCode,
        @"traced_now": @(tracedNow),
        @"traced_at_launch": @(tracedAtLaunch),
        @"cs_ok": @(csOk),
        @"cs_flags_hex": [NSString stringWithFormat:@"0x%08x", csFlags],
        @"cs_debugged": @(csDebugged),
        @"cs_kill_cleared": @(csKillCleared),
        @"andarium_jit_pref": @(jitPref),
        @"jit_mode": jitMode,
        @"shield_enabled": @(__atomic_load_n(&g_jit_36bit_shield, __ATOMIC_RELAXED) != 0),
        @"soft_mlock_enabled": @(__atomic_load_n(&g_jit_soft_mlock, __ATOMIC_RELAXED) != 0),
        @"relocations": @(__atomic_load_n(&g_jit_relocations, __ATOMIC_RELAXED)),
        @"soft_mlocks": @(__atomic_load_n(&g_jit_soft_mlocks, __ATOMIC_RELAXED)),
        @"failed_seen": @(failedSeen),
        @"avail_mem_mb": @(availMB),
        @"phys_mem_mb": @(physMB),
        @"bundle_id": bundleId,
        @"root_display_name": rootName,
        @"localized_display_name": locName,
        @"stikdebug_name_ok": @(stikNameOk),
        @"machine": machine,
        @"ios_version": iosVer,
        @"expects_txm": @(expectsTxm),
        @"pid": @((int)getpid()),
        @"stikdebug_installed": @(stikInstalled),
        @"trace_lines": ar_jit_copy_traces(),
    };
}

static NSString *ar_config_key_for_slot(NSString *slot) {
    NSString *s = ar_sanitize_slot(slot);
    if ([s isEqualToString:@"default"]) return kLegacyConfigKey;
    return [NSString stringWithFormat:@"AndariumRootPrebootConfigV5_%@", s];
}

static NSString *ar_rev_key_for_slot(NSString *slot) {
    NSString *s = ar_sanitize_slot(slot);
    if ([s isEqualToString:@"default"]) return kConfigRevisionKey;
    return [NSString stringWithFormat:@"AndariumRootPrebootRevV5_%@", s];
}

static NSDictionary *ar_current_config_for_slot(NSString *slot) {
    NSDictionary *saved = ar_load_json_dict_key(ar_config_key_for_slot(slot));
    if (saved.count > 0) return saved;
    NSDictionary *defs = ar_load_defaults_json();
    NSDictionary *initCfg = defs[@"default_config"];
    return [initCfg isKindOfClass:[NSDictionary class]] ? initCfg : @{};
}

static NSArray<NSString *> *ar_saved_slots(void) {
    NSArray *arr = [[NSUserDefaults standardUserDefaults] stringArrayForKey:kSlotListKey];
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:@"default", @"pentest", @"gamer", @"privacy", nil];
    if ([arr isKindOfClass:[NSArray class]]) {
        for (NSString *s in arr) {
            NSString *clean = ar_sanitize_slot(s);
            if (![out containsObject:clean]) [out addObject:clean];
        }
    }
    if (![out containsObject:g_active_slot]) [out addObject:g_active_slot];
    return out;
}

static void ar_register_slot(NSString *slot) {
    NSString *clean = ar_sanitize_slot(slot);
    NSMutableArray<NSString *> *cur = [ar_saved_slots() mutableCopy];
    if (![cur containsObject:clean]) {
        [cur addObject:clean];
        [[NSUserDefaults standardUserDefaults] setObject:cur forKey:kSlotListKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
}

static void ar_regenerate_cmdline_file(NSDictionary *cfg, NSString *slot) {
    NSString *stockPath = [[NSBundle mainBundle].resourcePath
                           stringByAppendingPathComponent:@"andarium-system/boot/kernel-command-line.txt"];
    NSString *stockText = [NSString stringWithContentsOfFile:stockPath encoding:NSUTF8StringEncoding error:nil];
    if (stockText.length == 0) return;

    NSMutableArray<NSString *> *words = [NSMutableArray array];
    for (NSString *w in [stockText componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]) {
        if (w.length == 0) continue;
        if ([w hasPrefix:@"androidboot.ar."]) continue;
        [words addObject:w];
    }

    NSString *preset  = ar_sanitize_token(cfg[@"preset"], @"^[a-z0-9_-]{1,16}$", @"mix");
    BOOL rootOn       = cfg[@"root_enabled"] ? [cfg[@"root_enabled"] boolValue] : YES;
    NSString *selinux = [cfg[@"selinux"] isEqualToString:@"enforcing"] ? @"1" : @"0";
    BOOL stealthOn    = [cfg[@"stealth"] boolValue];
    BOOL adbrootOn    = cfg[@"adbroot"] ? [cfg[@"adbroot"] boolValue] : YES;
    BOOL dbgOn        = cfg[@"debuggable"] ? [cfg[@"debuggable"] boolValue] : YES;

    NSDictionary *mods = [cfg[@"modules"] isKindOfClass:[NSDictionary class]] ? cfg[@"modules"] : @{};
    NSDictionary *svcs = [cfg[@"services"] isKindOfClass:[NSDictionary class]] ? cfg[@"services"] : @{};
    NSDictionary *twks = [cfg[@"tweaks"] isKindOfClass:[NSDictionary class]] ? cfg[@"tweaks"] : @{};

    NSString *modsBits = [NSString stringWithFormat:@"%d%d%d%d",
                          mods[@"rezygisk"] ? [mods[@"rezygisk"] intValue] : 1,
                          mods[@"vector"] ? [mods[@"vector"] intValue] : 1,
                          mods[@"stealth_stack"] ? [mods[@"stealth_stack"] intValue] : 1,
                          svcs[@"adblock"] ? [svcs[@"adblock"] intValue] : 1];

    NSString *svcsBits = [NSString stringWithFormat:@"%d%d%d",
                          [svcs[@"frida_autostart"] intValue],
                          [svcs[@"ssh_autostart"] intValue],
                          svcs[@"shizuku_autostart"] ? [svcs[@"shizuku_autostart"] intValue] : 1];

    NSArray<NSString *> *catalogOrder = @[
        @"magisk", @"termux", @"material_files", @"microg_gms", @"microg_vending",
        @"aurora_store", @"obtainium", @"app_manager", @"shizuku", @"neo_backup",
        @"trustmealready", @"disable_flag_secure", @"gps_setter"
    ];
    NSSet *enabledApps = [NSSet setWithArray:([cfg[@"apps"] isKindOfClass:[NSArray class]] ? cfg[@"apps"] : catalogOrder)];
    NSMutableString *appsBits = [NSMutableString stringWithCapacity:catalogOrder.count];
    for (NSString *aid in catalogOrder) {
        [appsBits appendString:([enabledApps containsObject:aid] ? @"1" : @"0")];
    }

    NSString *anim  = ar_sanitize_token([twks[@"anim_scale"] description], @"^(0|0\\.5|1)$", @"0.5");
    NSString *swap  = ar_sanitize_token([twks[@"swappiness"] description], @"^[0-9]{1,3}$", @"100");
    NSString *awake = [twks[@"stay_awake"] boolValue] ? @"1" : @"0";
    NSString *dpi   = ar_sanitize_token([twks[@"dpi"] description], @"^(0|[0-9]{3})$", @"0");
    NSString *spoof = ar_sanitize_token(cfg[@"spoof_profile"], @"^[a-z0-9_-]{1,16}$", @"stock");
    NSString *proxy = ar_sanitize_token(cfg[@"proxy"], @"^[a-zA-Z0-9.:_-]{3,64}$", @"none");

    NSInteger rev   = [[NSUserDefaults standardUserDefaults] integerForKey:ar_rev_key_for_slot(slot)];
    if (rev <= 0) rev = 1;

    NSString *cfgToken = [NSString stringWithFormat:@"5,%ld,%@,%d,%@,%d,%d,%d,%@,%@,%@,%@,%@,%@,%@,%@",
                          (long)rev, preset, rootOn ? 1 : 0, selinux, stealthOn ? 1 : 0,
                          adbrootOn ? 1 : 0, dbgOn ? 1 : 0, modsBits, svcsBits, appsBits,
                          anim, swap, awake, dpi, spoof];

    [words addObject:[NSString stringWithFormat:@"androidboot.ar.preset=%@", preset]];
    [words addObject:[NSString stringWithFormat:@"androidboot.ar.cfg=%@", cfgToken]];
    if (![proxy isEqualToString:@"none"]) {
        [words addObject:[NSString stringWithFormat:@"androidboot.ar.proxy=%@", proxy]];
    }

    NSString *finalCmdline = [[words componentsJoinedByString:@" "] stringByAppendingString:@"\n"];
    NSString *cachesDir = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!cachesDir) return;
    NSString *outName = [NSString stringWithFormat:@"andarium-root-cmdline-%@.txt", ar_sanitize_slot(slot)];
    NSString *outPath = [cachesDir stringByAppendingPathComponent:outName];
    if ([finalCmdline writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        strlcpy(g_override_cmdline_path, outPath.fileSystemRepresentation, sizeof(g_override_cmdline_path));
    }
}

// MARK: - Native Pre-Boot Setup ViewController (v2 + JIT Doctor)

@interface ARPrebootViewController : UIViewController <WKScriptMessageHandler, WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@end

@implementation ARPrebootViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.03 green:0.05 blue:0.04 alpha:1.0];

    WKUserContentController *ucc = [WKUserContentController new];
    [ucc addScriptMessageHandler:self name:@"andariumPreboot"];

    WKWebViewConfiguration *wcfg = [WKWebViewConfiguration new];
    wcfg.userContentController = ucc;

    self.webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:wcfg];
    self.webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.webView.opaque = NO;
    self.webView.backgroundColor = self.view.backgroundColor;
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *htmlPath = [ar_resource_bundle() pathForResource:@"preboot" ofType:@"html"];
    if (htmlPath) {
        NSURL *url = [NSURL fileURLWithPath:htmlPath];
        [self.webView loadFileURL:url allowingReadAccessToURL:url.URLByDeletingLastPathComponent];
    }
}

- (void)pushJitDiag {
    NSDictionary *diag = ar_build_jit_diagnostics();
    NSData *json = [NSJSONSerialization dataWithJSONObject:diag options:0 error:nil];
    if (!json) return;
    NSString *jsStr = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSString *call = [NSString stringWithFormat:@"window.__andariumJitDiag && window.__andariumJitDiag(%@);", jsStr];
    [self.webView evaluateJavaScript:call completionHandler:nil];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    NSDictionary *hw = ar_current_hardware();
    NSString *slot = hw[@"slot"] ?: @"default";
    NSArray<NSString *> *slots = ar_saved_slots();
    NSMutableDictionary *slotCfgs = [NSMutableDictionary dictionaryWithCapacity:slots.count];
    for (NSString *s in slots) {
        slotCfgs[s] = ar_current_config_for_slot(s);
    }
    NSDictionary *payload = @{
        @"defaults": ar_load_defaults_json(),
        @"config": ar_current_config_for_slot(slot),
        @"slot_configs": slotCfgs,
        @"hardware": hw,
        @"active_slot": g_active_slot ?: @"default",
        @"slots": slots,
        @"custom_presets": ar_load_json_dict_key(kCustomPresetsKey),
        @"host_cpus": @((NSInteger)NSProcessInfo.processInfo.activeProcessorCount),
        @"jit_diag": ar_build_jit_diagnostics(),
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!json) return;
    NSString *jsStr = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSString *call = [NSString stringWithFormat:@"window.__andariumInit && window.__andariumInit(%@);", jsStr];
    [webView evaluateJavaScript:call completionHandler:nil];
}

- (void)launchStikDebugWithAttach:(BOOL)attachPid {
    // Ensure andarium.jit=YES is persisted before handing off to StikDebug
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:YES forKey:@"andarium.jit"];
    [ud synchronize];

    NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"com.andarium.root";
    NSMutableCharacterSet *allowed = [NSMutableCharacterSet alphanumericCharacterSet];
    [allowed addCharactersInString:@".-_"];
    NSString *encBid = [bid stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: bid;

    NSString *urlStr = attachPid
        ? [NSString stringWithFormat:@"stikdebug://enable-jit?bundle-id=%@&pid=%d&script-name=universal.js", encBid, (int)getpid()]
        : [NSString stringWithFormat:@"stikdebug://enable-jit?bundle-id=%@&script-name=universal.js", encBid];

    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) return;

    __weak typeof(self) weakSelf = self;
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:^(BOOL success) {
        if (!success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                ARPrebootViewController *strongSelf = weakSelf;
                if (!strongSelf) return;
                UIAlertController *ac = [UIAlertController
                    alertControllerWithTitle:@"StikDebug Not Found"
                                     message:@"Install StikDebug (2.3.x+) via AltStore / SideStore / App Store, pair your device, and tap this button again — or open Andarium directly from inside StikDebug."
                              preferredStyle:UIAlertControllerStyleAlert];
                [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [strongSelf presentViewController:ac animated:YES completion:nil];
            });
        }
    }];
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.body isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *msg = (NSDictionary *)message.body;
    NSString *type = msg[@"type"];

    if ([type isEqualToString:@"save"]) {
        NSDictionary *cfg = msg[@"config"];
        NSDictionary *hwIn = msg[@"hardware"];
        NSString *targetSlot = g_active_slot ?: @"default";
        BOOL needsRelaunch = NO;

        if ([hwIn isKindOfClass:[NSDictionary class]]) {
            targetSlot = ar_sanitize_slot(hwIn[@"slot"]);
            ar_register_slot(targetSlot);
            NSMutableDictionary *cleanHw = [hwIn mutableCopy];
            cleanHw[@"slot"] = targetSlot;
            ar_save_json_obj(cleanHw, kHardwareKey);

            NSDictionary *normHw = ar_current_hardware();
            __atomic_store_n(&g_jit_36bit_shield, [normHw[@"jit_36bit_shield"] boolValue] ? 1 : 0, __ATOMIC_RELAXED);
            __atomic_store_n(&g_jit_soft_mlock, [normHw[@"jit_soft_mlock"] boolValue] ? 1 : 0, __ATOMIC_RELAXED);

            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            if (cleanHw[@"stats_hud"] != nil) {
                [ud setBool:[cleanHw[@"stats_hud"] boolValue] forKey:@"andarium.statistics"];
            }
            NSString *jm = normHw[@"jit_mode"] ?: @"auto";
            if ([jm isEqualToString:@"force_on"]) {
                [ud setBool:YES forKey:@"andarium.jit"];
            } else if ([jm isEqualToString:@"off"]) {
                [ud setBool:NO forKey:@"andarium.jit"];
            }
            [ud synchronize];

            NSString *newSig = ar_hw_signature(normHw);
            needsRelaunch = ![newSig isEqualToString:g_launch_hw_sig];
        }

        if ([cfg isKindOfClass:[NSDictionary class]]) {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSString *revKey = ar_rev_key_for_slot(targetSlot);
            NSInteger prev = [ud integerForKey:revKey];
            NSInteger rev = (prev < 1 ? 1 : prev) + 1;
            [ud setInteger:rev forKey:revKey];
            ar_save_json_obj(cfg, ar_config_key_for_slot(targetSlot));
            if ([targetSlot isEqualToString:g_active_slot]) {
                ar_regenerate_cmdline_file(cfg, targetSlot);
            }
        }

        if (needsRelaunch) {
            UIAlertController *ac = [UIAlertController
                alertControllerWithTitle:@"VM Slot / Hardware / JIT Saved"
                                 message:@"Your settings are saved. Close and reopen Andarium from StikDebug (or tap Enable JIT via StikDebug) so the new VM slot, hardware, or JIT mode applies at launch."
                          preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
                [self dismissViewControllerAnimated:YES completion:nil];
            }]];
            [self presentViewController:ac animated:YES completion:nil];
        } else {
            [self dismissViewControllerAnimated:YES completion:nil];
        }
    } else if ([type isEqualToString:@"launch_stikdebug"]) {
        BOOL attachPid = [msg[@"attach"] boolValue];
        [self launchStikDebugWithAttach:attachPid];
    } else if ([type isEqualToString:@"refresh_jit_diag"]) {
        [self pushJitDiag];
    } else if ([type isEqualToString:@"save_custom_preset"]) {
        NSString *pid = ar_sanitize_token(msg[@"id"], @"^[a-z0-9_-]{1,24}$", @"");
        NSDictionary *pdata = msg[@"preset"];
        if (pid.length > 0 && [pdata isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *all = [ar_load_json_dict_key(kCustomPresetsKey) mutableCopy];
            all[pid] = pdata;
            ar_save_json_obj(all, kCustomPresetsKey);
        }
    } else if ([type isEqualToString:@"delete_custom_preset"]) {
        NSString *pid = ar_sanitize_token(msg[@"id"], @"^[a-z0-9_-]{1,24}$", @"");
        if (pid.length > 0) {
            NSMutableDictionary *all = [ar_load_json_dict_key(kCustomPresetsKey) mutableCopy];
            [all removeObjectForKey:pid];
            ar_save_json_obj(all, kCustomPresetsKey);
        }
    } else if ([type isEqualToString:@"export"]) {
        NSString *jsonText = msg[@"text"];
        if ([jsonText isKindOfClass:[NSString class]] && jsonText.length > 0) {
            UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[jsonText] applicationActivities:nil];
            avc.popoverPresentationController.sourceView = self.view;
            [self presentViewController:avc animated:YES completion:nil];
        }
    } else if ([type isEqualToString:@"close"]) {
        [self dismissViewControllerAnimated:YES completion:nil];
    }
}

@end

// MARK: - Floating Pre-Boot Pill Overlay Manager

@interface ARPrebootOverlayManager : NSObject
@property (nonatomic, strong) UIButton *pillButton;
@property (nonatomic, strong) NSTimer *visibilityTimer;
+ (instancetype)shared;
- (void)attachIfNeeded;
@end

@implementation ARPrebootOverlayManager

+ (instancetype)shared {
    static ARPrebootOverlayManager *inst;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ inst = [ARPrebootOverlayManager new]; });
    return inst;
}

- (UIWindow *)activeKeyWindow {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive &&
            [scene isKindOfClass:[UIWindowScene class]]) {
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) return w;
            }
            return ((UIWindowScene *)scene).windows.firstObject;
        }
    }
    return nil;
}

- (BOOL)containsMetalGuestView:(UIView *)view {
    if (!view) return NO;
    NSString *cls = NSStringFromClass([view class]);
    if ([cls containsString:@"MTKView"] || [cls containsString:@"GuestMetalView"]) {
        return !view.hidden && view.alpha > 0.01;
    }
    for (UIView *sub in view.subviews) {
        if ([self containsMetalGuestView:sub]) return YES;
    }
    return NO;
}

- (void)refreshPillBadge {
    if (!self.pillButton) return;
    uint32_t csFlags = 0;
    BOOL csOk = ar_read_cs_flags(&csFlags);
    BOOL csReady = csOk && ((csFlags & AR_CS_DEBUGGED) != 0) && ((csFlags & AR_CS_KILL) == 0);
    BOOL failed = __atomic_load_n(&g_jit_failed_seen, __ATOMIC_RELAXED) != 0;

    NSString *base = [g_active_slot isEqualToString:@"default"]
        ? @"# Setup"
        : [NSString stringWithFormat:@"# %@", g_active_slot];
    NSString *title = nil;
    UIColor *accent = nil;

    if (failed) {
        title = [NSString stringWithFormat:@" %@ · JIT! ", base];
        accent = [UIColor colorWithRed:1.00 green:0.36 blue:0.47 alpha:1.0];
    } else if (csReady) {
        title = [NSString stringWithFormat:@" %@ · ⚡ JIT ", base];
        accent = [UIColor colorWithRed:0.20 green:0.96 blue:0.63 alpha:1.0];
    } else {
        title = [NSString stringWithFormat:@" %@ · JIT? ", base];
        accent = [UIColor colorWithRed:0.96 green:0.73 blue:0.26 alpha:1.0];
    }

    if (![[self.pillButton titleForState:UIControlStateNormal] isEqualToString:title]) {
        [self.pillButton setTitle:title forState:UIControlStateNormal];
        [self.pillButton setTitleColor:accent forState:UIControlStateNormal];
        self.pillButton.layer.borderColor = [accent colorWithAlphaComponent:0.78].CGColor;
    }
}

- (void)updateVisibility {
    UIWindow *win = [self activeKeyWindow];
    if (!win) return;
    if (!self.pillButton) {
        [self attachIfNeeded];
        return;
    }
    if (self.pillButton.superview != win) {
        [win addSubview:self.pillButton];
        [NSLayoutConstraint activateConstraints:@[
            [self.pillButton.topAnchor constraintEqualToAnchor:win.safeAreaLayoutGuide.topAnchor constant:8.0],
            [self.pillButton.centerXAnchor constraintEqualToAnchor:win.centerXAnchor],
            [self.pillButton.heightAnchor constraintEqualToConstant:36.0],
        ]];
    }
    BOOL vmRunning = [self containsMetalGuestView:win.rootViewController.view];
    self.pillButton.hidden = vmRunning;
    if (!vmRunning) {
        [self refreshPillBadge];
        [win bringSubviewToFront:self.pillButton];
    }
}

- (void)attachIfNeeded {
    UIWindow *win = [self activeKeyWindow];
    if (!win) return;

    if (!self.pillButton) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.titleLabel.font = [UIFont systemFontOfSize:13.5 weight:UIFontWeightBold];
        btn.backgroundColor = [UIColor colorWithRed:0.05 green:0.11 blue:0.09 alpha:0.92];
        btn.layer.cornerRadius = 18.0;
        btn.layer.borderWidth = 1.25;
        btn.layer.shadowColor = [UIColor blackColor].CGColor;
        btn.layer.shadowOpacity = 0.45;
        btn.layer.shadowRadius = 8.0;
        btn.layer.shadowOffset = CGSizeMake(0, 3);
        btn.translatesAutoresizingMaskIntoConstraints = NO;
        [btn addTarget:self action:@selector(openSetup) forControlEvents:UIControlEventTouchUpInside];

        self.pillButton = btn;
        [self refreshPillBadge];
        [win addSubview:btn];
        [NSLayoutConstraint activateConstraints:@[
            [btn.topAnchor constraintEqualToAnchor:win.safeAreaLayoutGuide.topAnchor constant:8.0],
            [btn.centerXAnchor constraintEqualToAnchor:win.centerXAnchor],
            [btn.heightAnchor constraintEqualToConstant:36.0],
        ]];
    }

    if (!self.visibilityTimer) {
        self.visibilityTimer = [NSTimer scheduledTimerWithTimeInterval:0.75
                                                                target:self
                                                              selector:@selector(updateVisibility)
                                                              userInfo:nil
                                                               repeats:YES];
    }
}

- (void)openSetup {
    UIWindow *win = [self activeKeyWindow];
    UIViewController *top = win.rootViewController;
    while (top.presentedViewController) {
        top = top.presentedViewController;
    }
    if (!top) return;
    ARPrebootViewController *vc = [ARPrebootViewController new];
    vc.modalPresentationStyle = UIModalPresentationPageSheet;
    [top presentViewController:vc animated:YES completion:nil];
}

@end

__attribute__((constructor))
static void ar_preboot_init(void) {
    @autoreleasepool {
        // 1. Apply JIT hardening + VM Slot & Hardware overrides BEFORE Swift AppEntry runs
        ar_apply_vm_hardware_env();
        ar_regenerate_cmdline_file(ar_current_config_for_slot(g_active_slot), g_active_slot);

        // 2. Install hardened Mach / Libc hooks in Andarium & KRuntime_Android_6_18_4K
        struct ar_rebinding rebindings[6] = {
            {"lstat",       (void *)ar_hooked_lstat,       (void **)&orig_lstat},
            {"fopen",       (void *)ar_hooked_fopen,       (void **)&orig_fopen},
            {"vm_allocate", (void *)ar_hooked_vm_allocate, (void **)&orig_vm_allocate},
            {"mlock",       (void *)ar_hooked_mlock,       (void **)&orig_mlock},
            {"fprintf",     (void *)ar_hooked_fprintf,     NULL},
            {"printf",      (void *)ar_hooked_printf,      NULL},
        };
        ar_rebind_symbols(rebindings, 6);

        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(__unused NSNotification *note) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [[ARPrebootOverlayManager shared] attachIfNeeded];
            });
        }];
    }
}
