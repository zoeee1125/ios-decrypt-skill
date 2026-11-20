// adgatedylib_v12.m  —  目標 App 2.0.9 (com.example.targetapp)
// v11 目標：
//   1) 明確驗證 dylib 是否真的被載入（NSLog + App 彈窗 + UDP beacon 到 Mac/Linux）
//   2) 用「通知路徑」繞過看廣告：攔 -[vwMain showRewardAd:]（ADMOD_REWARD_SHOW 的觀察者），
//      不載入 AdMob，直接 post REWARD_AD_FINISH → vwSideMenu 收到後呼叫自己的 RewardAdFinish: → 真正開始更新照相點
//   3) 記錄對目標 App API 的 HTTP 請求/回應（只記錄，不偽造！照相點下載不能被擋）
//
// 編譯（Mac，已驗證）：
// clang -arch arm64 -dynamiclib -fobjc-arc -target arm64-apple-ios14.0 \
//   -isysroot /Users/zoe/Downloads/iPhoneOS27.0.sdk \
//   -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
//   -Wl,-undefined,dynamic_lookup -L /Users/zoe/Downloads/iPhoneOS27.0.sdk/usr/lib -lSystem \
//   -o adgatedylib_v12_ios.dylib adgatedylib_v12.m

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <stdarg.h>

// ---------------------------------------------------------------- logging
#define AG_TAG "adgate12"
#define AG_MAX 60
static char g_ring[AG_MAX][256];
static int  g_ringN = 0;          // total events
static int  g_ringI = 0;          // write index
static FILE *g_logf = NULL;

static void ag_ring_put(const char *s) {
    snprintf(g_ring[g_ringI], 256, "%s", s);
    g_ringI = (g_ringI + 1) % AG_MAX;
    g_ringN++;
}

static void ag_beacon(const char *s) {
    static const char *hosts[2] = { "192.168.68.52", "192.168.68.61" };
    int f = socket(AF_INET, SOCK_DGRAM, 0);
    if (f < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(9999);
    char msg[1024];
    snprintf(msg, sizeof(msg), "[%s] %s\n", AG_TAG, s);
    for (int i = 0; i < 2; i++) {
        a.sin_addr.s_addr = inet_addr(hosts[i]);
        sendto(f, msg, strlen(msg), 0, (struct sockaddr *)&a, sizeof(a));
    }
    close(f);
}

static void AG(const char *fmt, ...) {
    char buf[800];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSLog(@"[%s] %s", AG_TAG, buf);
    ag_ring_put(buf);
    if (!g_logf) {
        const char *t = getenv("TMPDIR");
        char p[512];
        snprintf(p, sizeof(p), "%s/adgate12.log", t ? t : "/tmp");
        g_logf = fopen(p, "a");
    }
    if (g_logf) { fprintf(g_logf, "%s\n", buf); fflush(g_logf); }
    ag_beacon(buf);
}

// ---------------------------------------------------------------- helpers
static void AG(const char *fmt, ...);
static Class ag_class(const char *simple) {
    Class c = objc_getClass(simple);
    if (c) return c;
    c = NSClassFromString([NSString stringWithUTF8String:simple]);
    if (c) return c;
    char full[160];
    snprintf(full, sizeof(full), "targetapp.%s", simple);
    c = objc_getClass(full);
    if (c) return c;
    // 最後手段：掃全部已註冊類別，用後綴比對（Swift 類別的 runtime 名稱可能是 _TtC7TARGETNNvwSideMenu）
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    Class found = NULL, foundApp = NULL;
    size_t sl = strlen(simple);
    for (unsigned int i = 0; i < n && list; i++) {
        const char *nm = class_getName(list[i]);
        size_t nl = strlen(nm);
        if (nl >= sl && strcmp(nm + nl - sl, simple) == 0) {
            if (!found) found = list[i];
            if (strstr(nm, "_TtC")) foundApp = list[i];   // Swift 類別的 runtime 名稱
        }
    }
    if (list) free(list);
    return foundApp ? foundApp : found;
}

static void ag_swizzle(Class c, const char *selName, IMP newImp, IMP *oldImp) {
    if (!c) { AG("!! class missing for -%s", selName); return; }
    SEL s = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, s);
    if (!m) { AG("!! -[%s %s] missing", class_getName(c), selName); return; }
    if (oldImp) *oldImp = method_getImplementation(m);
    method_setImplementation(m, newImp);
    AG("swizzled -[%s %s]", class_getName(c), selName);
}

static void ag_post_finish(const char *why) {
    AG("post REWARD_AD_FINISH (%s)", why);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"REWARD_AD_FINISH" object:nil];
    });
}

// ---------------------------------------------------------------- hooks
static IMP orig_showRewardAd = NULL;      // vwMain  -showRewardAd:
static IMP orig_btnUpdate    = NULL;      // vwSideMenu -btnUpdateCam_OnClick:
static IMP orig_rewardFinish = NULL;      // vwSideMenu -RewardAdFinish:
static IMP orig_rewardFail   = NULL;      // vwSideMenu -RewardAdFail:
static IMP orig_rewardAbort  = NULL;      // vwSideMenu -RewardAdAbort:
static IMP orig_updateDone   = NULL;      // vwMain -UpdateCamComplete:
static IMP orig_interFinish  = NULL;      // vwSideMenu -IntertitialAdFinish:
static IMP orig_doSub        = NULL;      // vwSubsAdRemove -btnDoSubscription_OnClick:

// ADMOD_REWARD_SHOW 的觀察者。原本會去向 AdMob 要廣告 → 這台重簽過的 App 拿不到廣告（Invalid request）
// → 這裡直接走「廣告已看完」的通知路徑，完全不碰 AdMob。
static void ag_showRewardAd(id self, SEL _cmd, id note) {
    @try {        AG("== [%@ showRewardAd:] 收到 ADMOD_REWARD_SHOW（%s）", object_getClass(self), note ? "有 note" : "nil");
        ag_post_finish("showRewardAd 被叫用 → 直接完成");
        // 不呼叫原方法：不載入 AdMob，避免「無法開啟廣告 / Request Error: Invalid request」
    } @catch (NSException *e) { AG("!! exception in ag_showRewardAd: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_btnUpdate(id self, SEL _cmd, id sender) {
    @try {        AG("== [%@ btnUpdateCam_OnClick:] 使用者按下更新照相點", object_getClass(self));
        if (orig_btnUpdate) ((void (*)(id, SEL, id))orig_btnUpdate)(self, _cmd, sender);
        // 保險：若流程沒有走到 showRewardAd:，1.5 秒後自己補一發
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ ag_post_finish("btnUpdate 後備觸發"); });
    } @catch (NSException *e) { AG("!! exception in ag_btnUpdate: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_rewardFinish(id self, SEL _cmd, id sender) {
    @try {        AG("== [%@ RewardAdFinish:] 進入更新流程（sender=%@）", object_getClass(self), sender);
        if (orig_rewardFinish) ((void (*)(id, SEL, id))orig_rewardFinish)(self, _cmd, sender);
    } @catch (NSException *e) { AG("!! exception in ag_rewardFinish: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_rewardFail(id self, SEL _cmd, id sender) {
    @try {        AG("!! [%@ RewardAdFail:]（原本要顯示『無法開啟廣告』）→ 改走完成流程", object_getClass(self));
        ag_post_finish("RewardAdFail 被攔截");
    } @catch (NSException *e) { AG("!! exception in ag_rewardFail: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_rewardAbort(id self, SEL _cmd, id sender) {
    @try {        AG("!! [%@ RewardAdAbort:] → 改走完成流程", object_getClass(self));
        ag_post_finish("RewardAdAbort 被攔截");
    } @catch (NSException *e) { AG("!! exception in ag_rewardAbort: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_updateDone(id self, SEL _cmd, id sender) {
    @try {        AG("== [%@ UpdateCamComplete:] 照相點更新完成事件", object_getClass(self));
        if (orig_updateDone) ((void (*)(id, SEL, id))orig_updateDone)(self, _cmd, sender);
    } @catch (NSException *e) { AG("!! exception in ag_updateDone: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_interFinish(id self, SEL _cmd, id sender) {
    @try {        AG("== [%@ IntertitialAdFinish:]", object_getClass(self));
        if (orig_interFinish) ((void (*)(id, SEL, id))orig_interFinish)(self, _cmd, sender);
    } @catch (NSException *e) { AG("!! exception in ag_interFinish: %s", e.reason.UTF8String ?: "-"); }
}
static void ag_doSub(id self, SEL _cmd, id sender) {
    @try {        AG("== [%@ btnDoSubscription_OnClick:] 使用者按下訂閱", object_getClass(self));
        if (orig_doSub) ((void (*)(id, SEL, id))orig_doSub)(self, _cmd, sender);
    } @catch (NSException *e) { AG("!! exception in ag_doSub: %s", e.reason.UTF8String ?: "-"); }
}
// ---------------------------------------------------------------- HTTP logging
static IMP orig_dataTask = NULL;

static BOOL ag_interesting(NSURL *u) {
    NSString *s = (u.absoluteString ?: @"").lowercaseString;
    // 只排除廣告網域,其餘(含目標 App 自己的 API)全部記錄,方便追更新流程
    if ([s containsString:@"doubleclick"])        return NO;
    if ([s containsString:@"googleads"])          return NO;
    if ([s containsString:@"admob"])              return NO;
    if ([s containsString:@"googlesyndication"])  return NO;
    return YES;
}

static id ag_dataTask(id self, SEL _cmd, NSURLRequest *req, id completion) {
    @try {        BOOL log = ag_interesting(req.URL);
        if (log) {
            NSData *body = req.HTTPBody;
            NSString *bs = body.length ? [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] : @"";
            if (bs.length > 400) bs = [bs substringToIndex:400];
            AG("HTTP> %@ %@\n     body=%@", req.HTTPMethod, req.URL.absoluteString, bs);
        }
        id wrapped = completion;
        if (log && completion) {
            wrapped = [^(NSData *data, NSURLResponse *resp, NSError *err) {
                NSString *s = data.length ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
                if (s.length > 500) s = [s substringToIndex:500];
                AG("HTTP< %ld %@ err=%@ data=%@", (long)[(NSHTTPURLResponse *)resp statusCode], resp.URL.absoluteString,
                   err.localizedDescription ?: @"-", s);
                ((void (^)(NSData *, NSURLResponse *, NSError *))completion)(data, resp, err);
            } copy];
        }
        if (orig_dataTask) return ((id (*)(id, SEL, NSURLRequest *, id))orig_dataTask)(self, _cmd, req, wrapped);
        return nil;
    } @catch (NSException *e) { AG("!! exception in ag_dataTask: %s", e.reason.UTF8String ?: "-"); }
}
// ---------------------------------------------------------------- alert

// ---------------------------------------------------------------- install
static void ag_install(void) {
    static BOOL done = NO;
    if (done) { AG("install skipped (already done)"); return; }
    done = YES;
    AG("---- adgatedylib v11 install ----");

    Class side = ag_class("vwSideMenu");
    Class main = ag_class("vwMain");
    Class subs = ag_class("vwSubsAdRemove");
    AG("classes: vwSideMenu=%p vwMain=%p vwSubsAdRemove=%p", side, main, subs);

    if (main) {
        ag_swizzle(main, "showRewardAd:", (IMP)ag_showRewardAd, &orig_showRewardAd);
        ag_swizzle(main, "UpdateCamComplete:", (IMP)ag_updateDone, &orig_updateDone);
    }
    if (side) {
        ag_swizzle(side, "btnUpdateCam_OnClick:", (IMP)ag_btnUpdate, &orig_btnUpdate);
        ag_swizzle(side, "RewardAdFinish:", (IMP)ag_rewardFinish, &orig_rewardFinish);
        ag_swizzle(side, "RewardAdFail:", (IMP)ag_rewardFail, &orig_rewardFail);
        ag_swizzle(side, "RewardAdAbort:", (IMP)ag_rewardAbort, &orig_rewardAbort);
        ag_swizzle(side, "IntertitialAdFinish:", (IMP)ag_interFinish, &orig_interFinish);
    }
    if (subs) {
        ag_swizzle(subs, "btnDoSubscription_OnClick:", (IMP)ag_doSub, &orig_doSub);
    }

    // HTTP logging: swizzle the real session class
    @try {
        Class sc = object_getClass([NSURLSession sharedSession]);
        ag_swizzle(sc, "dataTaskWithRequest:completionHandler:", (IMP)ag_dataTask, &orig_dataTask);
    } @catch (NSException *e) {
        AG("http swizzle failed: %@", e.reason);
    }

    AG("install done; verify: showRewardAd IMP=%p btnUpdate IMP=%p",
       (void *)method_getImplementation(class_getInstanceMethod(main, sel_registerName("showRewardAd:"))),
       (void *)method_getImplementation(class_getInstanceMethod(side, sel_registerName("btnUpdateCam_OnClick:"))));
}

@interface AGLoader12 : NSObject @end
@implementation AGLoader12
+ (void)load { ag_install(); }
@end

__attribute__((constructor)) static void ag_ctor(void) { ag_install(); }
