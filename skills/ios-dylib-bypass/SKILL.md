---
name: ios-dylib-bypass
description: Reverse an iOS app's ad/subscription gate ("watch an ad to use X", "subscribe to unlock X") and ship an injectable arm64 dylib that bypasses it — static analysis with capstone/hand-rolled Mach-O parsers on Linux, cross-compiling the dylib on a Mac with a patched iPhoneOS SDK, injecting on a non-jailbroken device (LCSign/sideload) or jailbroken (DYLD_INSERT_LIBRARIES/Frida), and real-device verification (UDP beacon, crash reports, log collect). Debug crashes and "hook not working" with a symptom-driven flow, and ALWAYS embed a self-contained crash handler (ObjC exception + signal handlers that write a crash log and beacon it on next launch) during development — it must be removed from the final delivery build. Use for any "bypass this gate / remove the ad requirement / unlock this feature" job on a decrypted IPA. ALWAYS ask the user first which deliverables they want (dylib only / dylib + unsigned IPA / full portable pack) and where to save them, before doing any analysis. Always deliver UNSIGNED artifacts — never sign anything for the user, and never suggest a specific sideload or re-sign app (the user picks their own tool).
---

# ios-dylib-bypass

目標:找出「看廣告/訂閱才能用某功能」的真正閘門 → 寫 arm64 dylib 掛掉它 → 實機驗證。
核心觀念:**不要偽造伺服器回應,不要去改「訂閱狀態」資料欄位;找到通知/事件驅動的流程,把「等第三方 SDK 回成功」那一步整段抽掉。**

## 鐵律(違反其一就會繞遠路)

1. **從「使用者看到的那句錯誤字串」下手**,不要先猜訂閱資料欄位。用 xref 找該字串的引用點,反組譯那個函式,再沿呼叫鏈上下追。
2. **先查錯誤字串的出處**。若它屬於第三方 SDK(AdMob/GAD、Facebook、RevenueCat…),失敗通常來自「重簽後的 bundle id/憑證與後台對不上」→ 只要不讓 App 去問那個 SDK,錯誤就永遠不會出現。
3. **`cmn x8,#1 / b.ne` 幾乎一定不是「未訂閱」**,而是 Swift lazy-global 的 `swift_once` 守衛(-1 = 尚未初始化)。把所有這種位址當訂閱欄位去寫,等於整支 dylib 白做,還可能崩潰。
4. **掛鉤前先確認方法存在於 ObjC method list**。Swift 內部成員(常出現在反射字串裡的名字,如 `isRewardMissionOk`)不在其中,`method_setImplementation` 會靜默失敗 → 這是最大的死路。
5. **Swift 類別若把方法暴露給 ObjC(`@objc` / `@IBAction` / selector),就能直接 swizzle**,不需要 Swift hooking。runtime 名稱帶 `_TtC<bundle><len><Name>` 前綴。
6. **補發事件一定要去重**。任何「我幫你送完成通知」的設計都必須有 in-flight / 時間窗去重,並在「完成事件」時清旗標,否則使用者一定看到「按一次跑兩輪」。
7. **`objc_msgSend` 的函式指標轉型必須與目標簽章完全一致**(含參數個數與 variadic 與否),arm64 上不一致會 `doesNotRecognizeSelector:` → SIGABRT。零參數 selector 用 `id (*)(id, SEL)`。
8. **不要在 hook 裡碰 UIKit**(彈窗/AlertController)。診斷改走 NSLog + 檔案 + UDP beacon。
9. **不要用 `mprotect(..., PROT_READ|PROT_WRITE|PROT_EXEC)` 改 `__DATA`**(iOS W^X 一定失敗);`__BSS` 位址 fileoff = 0,讀檔會拿到別的 section 的內容。
10. **`LC_LOAD_DYLIB` 不能放相對路徑**(`@executable_path/...` → dyld: relative path not allowed in hardened program → SIGABRT)。手工注入 IPA 走「絕對路徑 + 未簽名交付」,簽名由使用者自理。
11. **不要把 `.o` 改 filetype 當 dylib 交付**。驗收看 `file` + `otool -l`(LC_BUILD_VERSION `platform 2` = iOS)+ `otool -L`(安裝名只能是 `/usr/lib/*`、`/System/Library/*`)。
12. **一次只注入一個 dylib**。同一個方法被 swizzle 兩次 → `orig` 指向自己 → 無限遞迴。
13. **交付一律「未簽名」**:只產 ① dylib,或 ② 未簽名 IPA,由使用者自行簽名 / 自行注入。**絕不代簽、不碰使用者憑證、不指定也不推薦任何重簽或側載 App(由使用者自己選)。**
14. **開發期一律內建崩潰處理(6-0),功能正常後一定拿掉**:`.ips` 不保證有,自帶 handler 才拿得到死因;最終交付版不得保留。

## 第 0 步:交付形態與儲存點(動手前**必須先問使用者**)

**先問,再開工。** 不要自己預設,也不要「兩種都做」——多產未簽名 IPA 會多花一輪打包,可能白做。
交付形態只有兩種下游:**(1) 給 dylib,使用者自己注入;(2) 給未簽名 IPA,使用者自己簽名。**我們永遠不做簽名這一步。
用選項式提問,一次問完兩題:

**Q1 要產出什麼?**

| 選項 | 內容 | 適合誰 |
|---|---|---|
| **A. 只產 dylib** | `xxx_ios.dylib`(做 `install_name_tool -id` + ad-hoc `codesign` —— 只是讓它能被載入,不等於簽 App) | **使用者自行注入**:用他自己選的重簽/側載方式,或越獄機 `DYLD_INSERT_LIBRARIES` / Frida。不要問他用哪個工具、也不要推薦 |
| **B. dylib + 未簽名 IPA** | A + 把 dylib 放進 `Payload/<App>.app/Frameworks/`、在 Mach-O 補**絕對路徑**的 `LC_LOAD_DYLIB`、重打包成 `.ipa` —— **輸出未簽名 IPA,不簽** | 使用者想自己走一鍵簽名/側載;務必遵守鐵律 10 |
| **C. A + B + 可攜包** | 再加原始碼、分析工具、`EXPERIENCE` 文件、實機 log 的 `tar.gz`(全部都還是未簽名) | 要交付他人 / 存檔 / 當教材 |

**Q2 存到哪?**(可多選,要問清楚「哪台機器 + 哪個路徑」)

| 位置 | 預設路徑 | 交付方式 |
|---|---|---|
| 分析機(Linux) | `<工作目錄>/dist/` | 直接寫檔 |
| macOS | `~/Downloads/`(或使用者指定) | `xssh.py`(pty + base64 腳本)+ HTTP 收送檔 |
| 手機端使用者自行架設的檔案服務 | `/Downloads/`(GCDWebUploader 介面:`POST /upload`,multipart 欄位 `path` + `files[]`) | 上傳後 **`GET /download?path=...` 抓回來比 sha256**;這只是檔案通道,不是代簽 |
| 既有 repo / 雲端 | 使用者指定 | 用該平台的 API / CLI 推送(憑證不足時回報,別硬猜) |

**預設值**(只有當使用者說「你決定」/跳過時才用):**A 形態 + 存到 macOS `~/Downloads/` 與分析機 `dist/`**。
**每次交付都要回報:完整路徑 + bytes + sha256**;送到裝置或遠端後一定抓回來比對。
使用者中途改主意 → **追加**產物就好,不要重做分析。

## 第 1 步:定位閘門(分析機,不需 Mac)

必備:`python3` + `capstone`。`otool/r2/ghidra` 常常沒有,自己寫 parser 反而快。

Mach-O arm64 座標(手寫 parser 常錯的欄位偏移):

```
LC_SEGMENT_64: cmd@+0(4) cmdsize@+4(4) segname@+8(16) vmaddr@+24(8) vmsize@+32(8)
               fileoff@+40(8) filesize@+48(8) maxprot@+56(4) initprot@+60(4) nsects@+64(4)
VA → file offset = VA − __TEXT.vmaddr   (PIE 下通常是 VA − 0x100000000)
```

先拿三張表:節區表(`__text`, `__cstring`, `__data`, `__objc_selrefs` 的 addr/size/fileoff)、
ObjC class list(class_data_bits 要 `& 0x00007ffffffffff8`;class_ro_t: name@+24、baseMethods@+32)、
以及 chained fixups 解碼器(`if (v>>62)&1: v & 0xFFFFFFFFFF` 之類的分支)。

**method list 在 iOS 15+ 是 relative**:`entsizeAndFlags` 高位帶 `0x80000000`,entry 是 3×int32 相對位移,**各自相對於「該欄位自身」**;
而 name 欄位指向的是 **`__objc_selrefs` 的 slot**,要再解一次 chained fixup 才是 SEL 字串。

xref 掃描(自己解 opcode,別依賴 objdump):在**同一趟迴圈**維護 `reg → page`,遇到 ADRP 設 page、遇到其他指令寫入該 reg 就清掉;
只認緊鄰的 `ADRP+ADD`(字串指標)與 `ADRP+LDR`(selref/global)。
> 坑:用「全檔最後一次 ADRP」建 map 的寫法會讓所有查詢回 0;分成兩趟也會讓註解全錯。

反組譯時自動標註:ObjC method IMP 名、dyld stub 名、selref 選擇器、`__cstring` 字串、section+offset。
> 坑:檔案**不要命名為 `dis.py`**(會遮蔽 stdlib `dis`,capstone import 失敗)。

抓幾個關鍵字串進場:`alert/message/error` + 功能名 + `fail/abort`,以及 `ADMOD_*`、`REWARD_*`、`*_FINISH` 之類的通知名。

## 第 2 步:判斷機制類型 → 選繞法

| 觀察 | 機制 | 繞法 |
|---|---|---|
| 找到 `postNotificationName:` 與 `addObserver:selector:name:` 配對(同名 notification) | **通知驅動**(最常見) | swizzle 觀察者方法的呼叫端,或直接由 dylib 補發「成功通知」;把「等 SDK 成功」那段整個抽掉 |
| 閘門在自己的 ObjC 方法裡直接 `if (subscribed)` | 直接判斷 | swizzle 那個方法或回傳狀態的 getter |
| 判斷散在 Swift 裡、方法不在 ObjC method list | Swift 內部 | 找它暴露出來的 `@objc`/`@IBAction` 入口(按鈕 `*_OnClick:`、`viewDidLoad`、通知觀察者)去掛;或用 Frida/stalker 找出真正的 Swift 函式入口 |
| 狀態存在 `__DATA`/`__BSS` 的整數欄位 | 全域旗標 | **先確認它是什麼**(x8 == -1 的比較很可能是 swift_once 守衛);確定是旗標才用 `mprotect(RW)` 改,並加持續重寫 |
| 錯誤字串來自第三方 SDK(AdMob 的 `Request Error: Invalid request.`、`No ad to show`) | SDK 失敗被當成功能失敗 | 別碰 SDK;**不呼叫它**、或把它的失敗回呼改走成功路徑 |

驗證「這真的是閘門」的標準:該函式內只有它引用了那句使用者可見的錯誤字串(全檔引用次數 = 1 最好)。

## 第 3 步:dylib 骨架

```objc
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <sys/socket.h>          // UDP beacon
#include <netinet/in.h>
#include <arpa/inet.h>

#define AG_TAG "adgate"
static void AG(NSString *fmt, ...) { /* NSLog + 環形緩衝 + 寫 TMPDIR/<AG_TAG>.log + UDP beacon */ }

static Class ag_class(const char *simple) {         // Swift 類別名有 _TtC… 前綴
    Class c = objc_getClass(simple);
    if (!c) { NSString *n = [NSString stringWithFormat:@"targetapp.%s", simple]; c = NSClassFromString(n); }
    if (!c) { /* objc_copyClassList + 後綴比對 */ }
    return c;
}

static IMP origA;
static void ag_install(void) {
    static BOOL done = NO;                  // +load 與 __init_offsets 的 ctor 都會呼叫 → 必須防重入
    if (done) return; done = YES;
    Class c = ag_class("vwMain");
    Method m = class_getInstanceMethod(c, sel_registerName("showRewardAd:"));
    if (m) { origA = method_getImplementation(m); method_setImplementation(m, (IMP)ag_hookA); }
}
__attribute__((constructor)) static void ag_ctor(void) { ag_install(); }
@interface AGLoader : NSObject @end
@implementation AGLoader + (void)load { ag_install(); } @end   // 備援觸發(新版 dyld 只有 __init_offsets 時靠這個)
```

去重樣板(修「按一次跑兩輪」):

```c
static BOOL g_inflight = NO; static CFAbsoluteTime g_inflightAt = 0;
static void ag_post_finish(const char *why) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (g_inflight && (now - g_inflightAt) < 15.0) { AG(@"skip (%.2fs, %s)", now - g_inflightAt, why); return; }
    g_inflight = YES; g_inflightAt = now;
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"REWARD_AD_FINISH" object:nil];
    });
}
// 在「完成」事件裡 g_inflight = NO;  → 下一輪按鍵立即可用;15 秒是保險
```

診斷用 UDP beacon(實機沒有 console 也能看,且不受 ATS 限制):`sendto()` 到分析機的 9999,另一端 `nc -u -l 9999` 或自寫 UDP listener。

**開發期必掛**:`ag_install()` 開頭先 `ag_crash_flush()`(把上次崩潰記錄 beacon 出去),再 `ag_crash_install()`(ObjC 例外 + signal handler)。完整程式碼與「交付前拿掉」的流程見 **6-0**。

## 第 4 步:編譯(在 macOS 上;Linux 做不出合法 iOS dylib)

```bash
clang -arch arm64 -dynamiclib -fobjc-arc -target arm64-apple-ios14.0 \
  -isysroot $SDK -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
  -Wl,-undefined,dynamic_lookup -L $SDK/usr/lib -lSystem -o OUT.dylib SRC.m
install_name_tool -id "@executable_path/Frameworks/OUT.dylib" OUT.dylib
codesign -f -s - OUT.dylib
```

* **SDK 路徑是各機不同的變數**:範例 `SDK=/Users/<user>/Downloads/iPhoneOS27.0.sdk`(社群版如 `xybp888/iOS-SDKs`)。**開工前先確認它還在**,不在就重新下載 —— 整條 `clang` 指令都靠它,沒有它無法產出 iOS dylib(只有 macOS SDK 會編出 macOS dylib,注入後不會載入)。
* **SDK 前置修復**:社群 iPhoneOS `.sdk` 的 `.tbd` 含 `arm64e.x1-ios` 這類新架構字串,舊 `ld` 會報 `unknown architecture` / `unknown file type`。對 SDK 內所有 `.tbd`:
  `sed -i '' -E 's/arm64e\.x[0-9]+-ios/arm64-ios/g; s/arm64e\.x[0-9]+-macos/arm64-macos/g; s/arm64e\.x[0-9]+-maccatalyst/arm64-maccatalyst/g'`
* **不要 `#import <UIKit/UIKit.h>`**:這組合常在 `UIAccelerometer.h` 等處因缺 `API_OBSOLETED` 巨集爆 18 個 error。全部改用 objc runtime 動態呼叫。
* 警告 `-undefined dynamic_lookup is deprecated on iOS`、`ignoring duplicate libraries: '-lSystem'` 可忽略。
* 驗收:`file` / `otool -l | grep -A3 LC_BUILD_VERSION`(platform 2)/ `otool -L`(只允許 `/usr/lib`、`/System/Library`)/ `shasum -a 256`。

## 第 5 步:注入(依第 0 步選定形態)

選了 **A** 就只到「交出 dylib + 路徑/sha256」;選了 **B/C** 才需要下面的注入與打包。

| 情境 | 做法 |
|---|---|
| 未越獄 + 使用者自行重簽側載(實務主流) | 把 dylib 交到使用者指定的位置,由他用自己的工具處理(**不由我方操作、不指定也不推薦工具**);若走手機端檔案服務,API:`GET /list?path=`、`POST /upload`(`path` + `files[]`)、`GET /download?path=`,上傳後抓回來比 sha256。**只勾一個 dylib** |
| 越獄 | `DYLD_INSERT_LIBRARIES`、`TrollStore`、或 Frida(`Module.load`) |
| 想自己做未簽名 IPA | 可以:補 `LC_LOAD_DYLIB` **絕對路徑**、把 dylib 放進 `Frameworks/`,重新 `zip` 成 `.ipa`,**不簽名**交付(相對路徑會被 dyld 拒) |

## 第 6 步:實機驗證與 debug(未越獄 iPhone)

### 6-0 內建崩潰處理(開發期**一律**掛,交付前一定拿掉)

**規則:開發/驗證階段的每個 dylib 都必須掛 crash handler;等「功能跑通、連續幾輪不閃退」之後,把 handler 拿掉再編最終版**(重新 `install_name_tool` / `codesign` / 算 sha256 交付)。

為什麼要自帶:`.ips` 只在真的閃退時才有;若 App 被系統殺、或 dylib 根本沒載入,沒有 handler 就只能瞎猜。自帶 handler 讓死因**留在 App 容器裡**,下次啟動由 beacon 送出來 —— 連 Mac 不在旁邊都拿得到死因。

```objc
// ---- 開發期診斷:ObjC 例外 + signal 崩潰 → 寫檔;下次啟動 beacon 出去 ----
#include <execinfo.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static char g_crashpath[512];
static const char *ag_crash_path(void) {
    if (!g_crashpath[0]) {
        const char *t = getenv("TMPDIR"); if (!t) t = "/tmp";   // App 容器內
        snprintf(g_crashpath, sizeof(g_crashpath), "%s/adgate_crash.log", t);
    }
    return g_crashpath;
}
static void ag_crash_append(const char *s, size_t n) {          // signal 內也安全
    int fd = open(ag_crash_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return; write(fd, s, n); close(fd);
}

static void ag_signal_handler(int sig) {
    char hdr[64];
    int n = snprintf(hdr, sizeof(hdr), "\n=== SIGNAL %d ===\n", sig);
    if (n > (int)sizeof(hdr)) n = (int)sizeof(hdr);              // snprintf 回傳的是「想要」長度,必須夾
    ag_crash_append(hdr, (size_t)n);

    int fd = open(ag_crash_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { void *bt[64]; int c = backtrace(bt, 64); backtrace_symbols_fd(bt, c, fd); close(fd); }

    signal(sig, SIG_DFL); raise(sig);                            // 保留原本的崩潰行為
}

static void ag_exception_handler(NSException *e) {               // ObjC 例外沒有 signal 限制
    NSString *rep = [NSString stringWithFormat:@"\n=== OBJC EXCEPTION %@: %@ ===\n%@\n",
                     e.name, e.reason, e.callStackSymbols];
    const char *u = rep.UTF8String; if (u) ag_crash_append(u, strlen(u));
}

static void ag_crash_install(void) {
    NSSetUncaughtExceptionHandler(&ag_exception_handler);
    int sigs[] = {SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) signal(sigs[i], ag_signal_handler);
}

static void ag_crash_flush(void) {                               // 啟動時把上次的死因送出來
    const char *p = ag_crash_path();
    int fd = open(p, O_RDONLY); if (fd < 0) return;
    char buf[1024]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        char line[1100]; int m = snprintf(line, sizeof(line), "CRASHLOG> %.*s", (int)n, buf);
        if (m > 0) ag_beacon(line);                              // 走你原本的 beacon
    }
    close(fd); unlink(p);                                        // 送過就刪,避免重複回報
}
```

| 階段 | 做什麼 |
|---|---|
| 開發 / 驗證 | `ag_install()` 開頭:`ag_crash_flush(); ag_crash_install();`;每個 hook 進入都 `AG(@"enter <method>")` |
| 確認正常 | 功能跑通、連按數輪不閃退、裝置上沒有新的 `.ips` |
| **交付前** | **移除 `ag_crash_flush()` / `ag_crash_install()` 兩個呼叫**(函式可留著不用),重編 → 重新 `install_name_tool` + `codesign` → 重新算 sha256 → 交付 |

注意:
* signal handler 裡只能用 async-signal-safe 的東西(`open`/`write`/`close`/`backtrace_symbols_fd`/`signal`/`raise`)——**不要**碰 Foundation / NSString;`snprintf` 嚴格說不在該清單,實務可用,要更保守就先填好固定 header 再 `write`。
* ObjC 例外常式沒有限制,可用 `e.callStackSymbols`。
* 這東西**不要留在最終交付版**:它會改變崩潰行為、也會在容器裡留檔。
* 回報格式:`CRASHLOG> === SIGNAL 11 ===` + `backtrace_symbols_fd` 的 `image + offset symbol` 行 → 直接看得出是落在你的 dylib 哪個函式。

### 6-1 先分流:症狀 → 幾乎確定的原因 → 動作

| 症狀 | 幾乎可以確定的原因 | 動作 |
|---|---|---|
| **完全沒有訊號**(沒 beacon / 沒 log / 沒彈窗),App 卻正常 | **dylib 根本沒被載入**:注入沒生效、dylib 沒進 `Frameworks/`、`LC_LOAD_DYLIB` 沒補或補了相對路徑、簽名流程把 dylib 丟掉 | ① 對交付檔案 `strings -a x.dylib \| grep <beacon 標記>` 確認標記真的在;② 拆開交付的 IPA:`unzip -l x.ipa \| grep -i dylib`、反組譯主二進位確認 `LC_LOAD_DYLIB` 是**絕對路徑**;③ 抓 `.ips`:`termination.reasons` 若出現 `Library not loaded`(相對路徑會寫 `relative path not allowed in hardened program`)→ 就是載入失敗;④ 換一種注入/簽名方式再測 |
| **一啟動就閃退** | hook 造成例外。最常見:`objc_msgSend` 轉型與簽章不符 → `doesNotRecognizeSelector:` → SIGABRT;swizzle 到不存在的方法;`orig` 被覆寫成自己 → 無限遞迴 | 抓 `.ips` 讀 backtrace:看 `exception.signal` 與 crash frame **是否落在你的 dylib**(落在 → 就是你的 hook;落在 UIKit/StoreKit → 你的 hook 逼出了別人的路徑) |
| **用一陣子才閃退** | 延遲觸發的副作用:`dispatch_after` 計時器、彈窗(UIKit + AutoLayout)、週期性重掃 | 第一版**不要放**彈窗/計時器/週期重掃,先只留 hook + beacon;確認穩定後再一項一項加回來,加到哪一項閃退就是它 |
| **有 beacon,但按鍵功能沒生效** | 閘門判斷錯:掛到不在 ObjC method list 的方法(靜默失敗)、事件沒被觸發、或流程在更下游被擋 | 看 beacon 的**事件序列**是否照預期走(缺哪一步就是斷點);打開 HTTP 記錄(6-3)確認請求有沒有發出去、誰回的 |
| **功能生效但跑兩輪** | 補發事件沒去重,或「後備觸發」與正常路徑同時命中 | in-flight 旗標 + 完成事件清旗標,時間窗 10–15 秒 |
| **原本的錯誤訊息還在**(例:「無法開啟廣告」) | 沒攔到真正入口,或 App 走另一條路徑 | 用 xref 回頭列出該錯誤字串的**所有**引用點,逐一 hook;或在最上游的 `postNotification` 處就把流程改道 |

### 6-2 取證管道(照可靠度排序)

0. **dylib 自帶的崩潰記錄(開發期最優先,見 6-0)** — 不需要 Mac/筆電在旁邊,死因直接 beacon 回來
1. **崩潰報告(最可靠,不需要 Xcode)**
   `xcrun devicectl device copy from --device <id> --domain-type systemCrashLogs --source . --destination <dir>`
   讀 `.ips` 的 `exception` / `termination.reasons` / `usedImages` / backtrace。自己編的 dylib 有符號,frame 會直接寫 `你的dylib + <offset> <函式名>`。
   只有 offset 時:對 dylib 用 `nm -n x.dylib | sort` 或反組譯工具換算(offset 相對 __TEXT 起點)。
2. **裝置系統日誌**
   `sudo log collect --device-udid <UDID> --last 20m --size 60m --output x.logarchive`(**必須 root**;`--predicate` 對實機被忽略)。
   新版 macOS 的 `log show` 讀不了(version 6)→ `find x.logarchive -name "*.tracev3" -exec strings -a {} + \| grep <關鍵字>`。
3. **dylib 自己的訊號(最省事、最先該做)**
   UDP beacon 打回分析機/筆電(`nc -u -l 9999`)+ 寫 `NSTemporaryDirectory()/<name>.log`。**每次 hook 進入就送一行**,這是判斷「有沒有載入 + 走到哪一步」的主力。
4. **彈窗**只能當第一版的臨時手段(鐵律 8:ABI 不一致會 SIGABRT,而且常是「用一陣子才閃退」的元凶)。

### 6-3 網路層要看什麼

swizzle `NSURLSession` / `NSURLConnection` 的 `dataTaskWithRequest:completionHandler:` **只記錄、不改內容**(偽造回應會破壞 App 自己的下載流程)。
記錄:method / URL / body 前 400 字 / 回應 status + body 前 500 字。**只過濾廣告網域**(doubleclick / googleads / admob / googlesyndication),其餘全記,才看得到真正的更新請求。

### 6-4 兩個常見誤判

* **沒有崩潰報告 ≠ 沒事**:沒閃退本來就沒有報告,要靠 beacon 判斷是否載入。
* **`devicectl` 的空結果不是證據**:`device info apps` / `info processes` 常回 0 筆、`--domain-type appDataContainer` 回 `ContainerLookupErrorDomain -1`、`device process launch` 報 not installed。**不要因此判定「App 沒安裝」**,改用 logarchive 字串(bundle container、SpringBoard scene、通知識別碼)判斷。

## 收尾檢查清單

- [ ] **開工前已問清交付形態(A/B/C)與儲存點**,沒有自作主張多做或少做
- [ ] 每個產物都回報「路徑 + bytes + sha256」;送到裝置/遠端的有抓回比對
- [ ] 錯誤字串 → 引用點 → 函式語意,確認這就是閘門(引用次數最好 = 1)
- [ ] 閘門是通知驅動?是否能把「等 SDK 成功」整段抽掉
- [ ] 掛鉤的方法真的在 ObjC method list 裡(用 class/method 傾印確認)
- [ ] `orig` 有保存、`ag_install()` 有 `static BOOL done` 防重入
- [ ] 補發事件有去重,且「完成事件」會清旗標
- [ ] 沒有任何 UIKit 依賴、`objc_msgSend` 轉型全部對得上簽章
- [ ] `otool -l` platform 2 / `otool -L` 乾淨 / sha256 記下
- [ ] 上傳後抓回來比 sha256;只注入一個 dylib
- [ ] 實機:beacon 顯示已載入、無崩潰報告、按一次只跑一輪;有症狀先過 6-1 分流表,不要亂改
- [ ] **開發期有掛 crash handler(6-0:exception + signal);交付前已拿掉並重編、sha256 已重算**

參考實例(目標 App 2.0.9):`re/appgate/EXPERIENCE.md`、`SOLUTION.md`,可重用工具 `re/appgate/{adis,xref,objcdump2,smartdis,xssh}.py`。
