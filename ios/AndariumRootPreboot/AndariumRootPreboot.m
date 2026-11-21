// SPDX-License-Identifier: GPL-2.0-or-later
// AndariumRootPreboot.dylib — Native iOS Pre-Boot Setup Studio injected into Andarium.app.
// Presents a floating "# Root Setup" pill on Andarium's Home screen (BEFORE clicking Start)
// and dynamically supplies sanitized `androidboot.ar.*` flags to the guest kernel via
// redirecting only `/boot/kernel-command-line.txt` in KRuntime_Android_6_18_4K.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <sys/stat.h>
#import <stdio.h>
#import <string.h>
#import "fishhook.h"

static NSString *const kConfigDefaultsKey = @"AndariumRootPrebootConfigV4";
static NSString *const kConfigRevisionKey = @"AndariumRootPrebootRevisionV4";
static NSString *const kCmdlineSuffix     = @"/boot/kernel-command-line.txt";

static int   (*orig_lstat)(const char *, struct stat *) = NULL;
static FILE *(*orig_fopen)(const char *, const char *)  = NULL;

static char g_override_cmdline_path[PATH_MAX] = {0};

static BOOL ar_is_cmdline_path(const char *path) {
    if (!path || g_override_cmdline_path[0] == '\0') return NO;
    size_t len = strlen(path);
    const char *suffix = "/boot/kernel-command-line.txt";
    size_t slen = strlen(suffix);
    if (len < slen) return NO;
    if (strcmp(path + (len - slen), suffix) != 0) return NO;
    // Never redirect our own override path
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

static NSDictionary *ar_current_config(void) {
    NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:kConfigDefaultsKey];
    if (saved.length > 0) {
        id obj = [NSJSONSerialization JSONObjectWithData:[saved dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if ([obj isKindOfClass:[NSDictionary class]]) {
            return obj;
        }
    }
    NSDictionary *defs = ar_load_defaults_json();
    NSDictionary *initCfg = defs[@"default_config"];
    return [initCfg isKindOfClass:[NSDictionary class]] ? initCfg : @{};
}

static void ar_regenerate_cmdline_file(NSDictionary *cfg) {
    NSString *stockPath = [[NSBundle mainBundle].resourcePath
                           stringByAppendingPathComponent:@"andarium-system/boot/kernel-command-line.txt"];
    NSString *stockText = [NSString stringWithContentsOfFile:stockPath encoding:NSUTF8StringEncoding error:nil];
    if (stockText.length == 0) return;

    // Strip any build-time androidboot.ar.* tokens so live iOS settings override cleanly
    NSMutableArray<NSString *> *words = [NSMutableArray array];
    for (NSString *w in [stockText componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]) {
        if (w.length == 0) continue;
        if ([w hasPrefix:@"androidboot.ar."]) continue;
        [words addObject:w];
    }

    NSString *preset  = ar_sanitize_token(cfg[@"preset"], @"^[a-z0-9_-]{1,20}$", @"mix");
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
    NSString *proxy = ar_sanitize_token(cfg[@"proxy"], @"^[a-zA-Z0-9.:_-]{3,64}$", @"none");
    NSInteger rev   = [[NSUserDefaults standardUserDefaults] integerForKey:kConfigRevisionKey];
    if (rev <= 0) rev = 1;

    NSString *cfgToken = [NSString stringWithFormat:@"4,%ld,%@,%d,%@,%d,%d,%d,%@,%@,%@,%@,%@,%@,%@",
                          (long)rev, preset, rootOn ? 1 : 0, selinux, stealthOn ? 1 : 0,
                          adbrootOn ? 1 : 0, dbgOn ? 1 : 0, modsBits, svcsBits, appsBits,
                          anim, swap, awake, dpi];

    [words addObject:[NSString stringWithFormat:@"androidboot.ar.preset=%@", preset]];
    [words addObject:[NSString stringWithFormat:@"androidboot.ar.cfg=%@", cfgToken]];
    if (![proxy isEqualToString:@"none"]) {
        [words addObject:[NSString stringWithFormat:@"androidboot.ar.proxy=%@", proxy]];
    }

    NSString *finalCmdline = [[words componentsJoinedByString:@" "] stringByAppendingString:@"\n"];
    NSString *cachesDir = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!cachesDir) return;
    NSString *outPath = [cachesDir stringByAppendingPathComponent:@"andarium-root-cmdline.txt"];
    if ([finalCmdline writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        strlcpy(g_override_cmdline_path, outPath.fileSystemRepresentation, sizeof(g_override_cmdline_path));
    }
}

// MARK: - Native Pre-Boot Setup ViewController

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
    NSDictionary *payload = @{
        @"defaults": ar_load_defaults_json(),
        @"config": ar_current_config(),
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
        if ([cfg isKindOfClass:[NSDictionary class]]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:cfg options:0 error:nil];
            if (d) {
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
                NSInteger prev = [ud integerForKey:kConfigRevisionKey];
                NSInteger rev = (prev < 1 ? 1 : prev) + 1;
                [ud setInteger:rev forKey:kConfigRevisionKey];
                [ud setObject:s forKey:kConfigDefaultsKey];
                [ud synchronize];
                ar_regenerate_cmdline_file(cfg);
            }
        }
        [self dismissViewControllerAnimated:YES completion:nil];
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
    // Automatically hide pill while Android VM display (MTKView) is active
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
        [btn setTitle:@" # Root Setup " forState:UIControlStateNormal];
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
        ar_regenerate_cmdline_file(ar_current_config());

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
