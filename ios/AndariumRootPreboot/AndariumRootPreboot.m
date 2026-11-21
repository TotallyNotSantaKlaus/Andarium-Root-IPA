// SPDX-License-Identifier: GPL-2.0-or-later
// AndariumRootPreboot.dylib (v5 / Pre-Boot Studio v2) — Native iOS Pre-Boot Setup Studio.
// 1. Pre-main() constructor injects saved VM Hardware & Multi-VM Slot env overrides
//    (ANDARIUM_GUEST_INSTANCE, KERNARIUM_VCPU_COUNT, KERNARIUM_GUEST_MEMORY_MIB,
//     KERNARIUM_ANDROID_DISK_SIZE_GIB, KERNARIUM_DISPLAY_SCALE, ANDARIUM_THERMAL_STATE,
//     ANDARIUM_HAPTICS) + `andarium.stats` HUD preference before Swift AppEntry starts.
// 2. Presents floating "# Root Setup" pill on Andarium Home screen (hidden during Metal VM).
// 3. Dynamically feeds sanitized `androidboot.ar.cfg=5,...` (root, preset, spoof, modules,
//    services, apps, tweaks, proxy) via fishhook on `/boot/kernel-command-line.txt`.
// 4. Persists per-slot configs and user-created Custom Presets (create/delete/import/export).

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <sys/stat.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import "fishhook.h"

static NSString *const kLegacyConfigKey   = @"AndariumRootPrebootConfigV4";
static NSString *const kConfigRevisionKey = @"AndariumRootPrebootRevisionV4";
static NSString *const kHardwareKey       = @"AndariumRootVmHardwareV5";
static NSString *const kCustomPresetsKey  = @"AndariumRootCustomPresetsV5";
static NSString *const kSlotListKey       = @"AndariumRootVmSlotsV5";

static int   (*orig_lstat)(const char *, struct stat *) = NULL;
static FILE *(*orig_fopen)(const char *, const char *)  = NULL;

static char g_override_cmdline_path[PATH_MAX] = {0};
static NSString *g_active_slot = @"default";
static NSString *g_launch_hw_sig = @"";

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
    if (ar_is_cmdline_path(path)) {
        return orig_lstat(g_override_cmdline_path, buf);
    }
    return orig_lstat(path, buf);
}

static FILE *ar_hooked_fopen(const char *path, const char *mode) {
    if (ar_is_cmdline_path(path)) {
        return orig_fopen(g_override_cmdline_path, mode);
    }
    return orig_fopen(path, mode);
}

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
    return @{
        @"slot": slot,
        @"vcpu": @(vcpu),
        @"mem_mib": @(memMiB),
        @"disk_gib": @(diskGiB),
        @"display_scale": scale,
        @"thermal_nominal": @(thermalNom),
        @"stats_hud": @(statsHud),
        @"haptics_off": @(hapticsOff),
    };
}

static NSString *ar_hw_signature(NSDictionary *hw) {
    return [NSString stringWithFormat:@"%@|%@|%@|%@|%@|%@|%@",
            hw[@"slot"] ?: @"default", hw[@"vcpu"] ?: @0, hw[@"mem_mib"] ?: @0,
            hw[@"disk_gib"] ?: @0, hw[@"display_scale"] ?: @"auto",
            hw[@"thermal_nominal"] ?: @0, hw[@"haptics_off"] ?: @0];
}

static void ar_apply_vm_hardware_env(void) {
    NSDictionary *hw = ar_current_hardware();
    g_active_slot = hw[@"slot"] ?: @"default";
    g_launch_hw_sig = ar_hw_signature(hw);

    if (![g_active_slot isEqualToString:@"default"]) {
        setenv("ANDARIUM_GUEST_INSTANCE", g_active_slot.UTF8String, 1);
    }

    NSInteger maxCpu = (NSInteger)NSProcessInfo.processInfo.activeProcessorCount;
    if (maxCpu < 1) maxCpu = 1;
    NSInteger vcpu = [hw[@"vcpu"] integerValue];
    if (vcpu >= 1 && vcpu <= maxCpu) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)vcpu);
        setenv("KERNARIUM_VCPU_COUNT", buf, 1);
    }

    NSInteger memMiB = [hw[@"mem_mib"] integerValue];
    if (memMiB >= 512 && memMiB <= 16384 && (memMiB % 64) == 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)memMiB);
        setenv("KERNARIUM_GUEST_MEMORY_MIB", buf, 1);
    }

    NSInteger diskGiB = [hw[@"disk_gib"] integerValue];
    if (diskGiB >= 4 && diskGiB <= 64) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)diskGiB);
        setenv("KERNARIUM_ANDROID_DISK_SIZE_GIB", buf, 1);
    }

    NSString *scale = hw[@"display_scale"];
    if ([scale isKindOfClass:[NSString class]] && scale.length > 0 && ![scale isEqualToString:@"auto"]) {
        setenv("KERNARIUM_DISPLAY_SCALE", scale.UTF8String, 1);
    }

    if ([hw[@"thermal_nominal"] boolValue]) {
        setenv("ANDARIUM_THERMAL_STATE", "nominal", 1);
    }
    if ([hw[@"haptics_off"] boolValue]) {
        setenv("ANDARIUM_HAPTICS", "0", 1);
    }

    // Sync Andarium's native FPS/CPU/RAM Stats HUD preference when explicitly saved
    NSDictionary *rawSaved = ar_load_json_dict_key(kHardwareKey);
    if (rawSaved[@"stats_hud"] != nil) {
        [[NSUserDefaults standardUserDefaults] setBool:[rawSaved[@"stats_hud"] boolValue] forKey:@"andarium.stats"];
    }
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

// MARK: - Native Pre-Boot Setup ViewController (v2)

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
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!json) return;
    NSString *jsStr = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSString *call = [NSString stringWithFormat:@"window.__andariumInit && window.__andariumInit(%@);", jsStr];
    [webView evaluateJavaScript:call completionHandler:nil];
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
            if (cleanHw[@"stats_hud"] != nil) {
                [[NSUserDefaults standardUserDefaults] setBool:[cleanHw[@"stats_hud"] boolValue] forKey:@"andarium.stats"];
                [[NSUserDefaults standardUserDefaults] synchronize];
            }
            NSString *newSig = ar_hw_signature(ar_current_hardware());
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
                alertControllerWithTitle:@"VM Slot / Hardware Saved"
                                 message:@"Your root & preset flags are saved. Because you changed the VM Slot or vCPU/RAM/Display hardware, close and reopen Andarium Root before tapping Start Emulation."
                          preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
                [self dismissViewControllerAnimated:YES completion:nil];
            }]];
            [self presentViewController:ac animated:YES completion:nil];
        } else {
            [self dismissViewControllerAnimated:YES completion:nil];
        }
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
        [win bringSubviewToFront:self.pillButton];
    }
}

- (void)attachIfNeeded {
    UIWindow *win = [self activeKeyWindow];
    if (!win) return;

    if (!self.pillButton) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        NSString *title = [g_active_slot isEqualToString:@"default"]
            ? @" # Root Setup "
            : [NSString stringWithFormat:@" # Setup · %@ ", g_active_slot];
        [btn setTitle:title forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor colorWithRed:0.20 green:0.96 blue:0.63 alpha:1.0] forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont systemFontOfSize:13.5 weight:UIFontWeightBold];
        btn.backgroundColor = [UIColor colorWithRed:0.05 green:0.11 blue:0.09 alpha:0.92];
        btn.layer.cornerRadius = 18.0;
        btn.layer.borderWidth = 1.25;
        btn.layer.borderColor = [UIColor colorWithRed:0.20 green:0.96 blue:0.63 alpha:0.75].CGColor;
        btn.layer.shadowColor = [UIColor blackColor].CGColor;
        btn.layer.shadowOpacity = 0.45;
        btn.layer.shadowRadius = 8.0;
        btn.layer.shadowOffset = CGSizeMake(0, 3);
        btn.translatesAutoresizingMaskIntoConstraints = NO;
        [btn addTarget:self action:@selector(openSetup) forControlEvents:UIControlEventTouchUpInside];

        self.pillButton = btn;
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
        // Apply VM Slot & Hardware env overrides BEFORE Swift AppEntry.fromArguments() runs
        ar_apply_vm_hardware_env();
        ar_regenerate_cmdline_file(ar_current_config_for_slot(g_active_slot), g_active_slot);

        struct ar_rebinding rebindings[2] = {
            {"lstat", (void *)ar_hooked_lstat, (void **)&orig_lstat},
            {"fopen", (void *)ar_hooked_fopen, (void **)&orig_fopen},
        };
        ar_rebind_symbols(rebindings, 2);

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
