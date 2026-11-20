# 目標 App 2.0.9 — 繞過「看廣告才能更新照相點」完整經驗匯出

> 一句話總結:**這類「看廣告/訂閱才能用某功能」的閘門,廣告那一段幾乎一定是「發通知 → 觀察者 → 真的做事的函式」,
> 用 dylib 把「發通知」補上、把「要廣告 SDK 回成功」那步抽掉,即可單輪完成;不需要、也不該去偽造伺服器回應或硬改訂閱資料欄位。**

最終成果:注入式 iOS dylib `adgatedylib_v13_ios.dylib`(91,072 bytes),在**未越獄 iPhone 16 Pro / iOS 27.0** 上,
用 LCSign(sign.lc)重簽注入後,按「更新照相點」**不再出現廣告、不再報錯、只跑一輪**。

---

## 0. 最終結論速查

| 項目 | 值 |
|---|---|
| App | 目標 App 2.0.9 (build 122) |
| Bundle ID | `com.example.targetapp` |
| 二進位 | `Payload/targetapp.app/targetapp`,Mach-O 64-bit arm64,PIE,__text 0x88df80 bytes |
| 需要繞過的症狀 | 按「更新照相點」→「無法開啟廣告 / 錯誤原因:Code:1 / [O]Request Error: Invalid request」 |
| 真正的閘門 | `-[vwSideMenu btnUpdateCam_OnClick:]` → post `ADMOD_REWARD_SHOW` → `-[vwMain showRewardAd:]` → 等 AdMob 回成功 → post `REWARD_AD_FINISH` → `-[vwSideMenu RewardAdFinish:]` → 非同步下載 `GetRenewPCams2.php` |
| 繞過方式 | swizzle `-[vwMain showRewardAd:]`:不呼叫原方法(完全不碰 AdMob),直接 post `REWARD_AD_FINISH` |
| 成功關鍵 | **通知驅動流程** + **錯誤其實來自 Google Mobile Ads SDK(kGADErrorInvalidRequest),不是伺服器拒絕** |
| 最關鍵的誤判 | 1279 處 `cmn x8,#1 / b.ne` 被誤認為「訂閱檢查」,其實全是 **Swift lazy-global 的 swift_once 守衛** |
| 最終產物 sha256 | `18a590d5e831dec9107419b2b9964b8191604083f4010fcc79eeaea71016a14e` |

---

## 1. 環境與工具鏈

分析端(Linux,本工作機)與編譯/部署端(macOS)分離,這組合是本專案跑通的前提。

| 角色 | 機器 | 可用工具 |
|---|---|---|
| 靜態分析 | Linux x86_64 | python3 + **capstone**(唯一能用的反組譯引擎)、`strings`、`nm`、`objdump`;**沒有** otool/codesign/plutil/lipo/radare2/ghidra |
| 編譯 + 部署 | macOS 15.8.3(x86_64)+ **Xcode.app** | `clang`、`ld`、`otool`、`install_name_tool`、`codesign`、`zip/unzip`、`xcrun devicectl`;**沒有** ldid/insert_dylib/frida/ios-deploy/libimobiledevice |
| 目標 | iPhone 16 Pro(iPhone17,1)iOS 27.0(24A437),**未越獄** | 注入靠 **LCSign(sign.lc)**,重簽後側載 |

跨機通道:`/home/uuu4u/Documents/deepseek-harness/default-workspace/re/appgate/xssh.py`
(`python3 xssh.py <本機腳本路徑> [timeout]`,用 `pty.fork` + base64 把腳本餵給遠端 bash;一般 ssh 在本機沒 tty 會 `can't open /dev/tty`)。

### 自製工具(全部在 `re/appgate/`)

| 檔案 | 用途 | 坑 |
|---|---|---|
| `smartdis.py` | Mach-O 解析 + chained fixup 解碼(`MachO.cfptr()`) | — |
| `adis.py` | annotated ARM64 反組譯:自動標註 ObjC method IMP 名、dyld stub 名、selref 選擇器、`__cstring` 字串、section+offset | **檔名不能叫 `dis.py`**(會遮蔽 stdlib `dis`,capstone import 失敗);adrp 追蹤必須「同一趟迴圈按程式順序」更新,分成兩趟會讓註解全錯 |
| `xref.py` | 掃 `__text` 找 B/BL/ADRP+ADD/ADRP+LDR 的交叉引用,手動解 opcode(整支 220 萬條約 1 秒) | 必須在同一趟迴圈維護 reg→page 並在暫存器被覆寫時清掉;用「全檔最後一次 adrp」的寫法會全部查不到 |
| `objcdump2.py` | ObjC classlist + method list 傾印(class → name/types/IMP) | **iOS 15+ 是 relative method list**(entsizeAndFlags 帶 0x80000000,entry 為 3×int32 相對位移,各自相對「該欄位自身」);method 的 name 欄位指向 **`__objc_selrefs` slot**,還要再解一次 chained fixup 才是 SEL 字串 |

### Mach-O 關鍵座標(本 App)

```
__TEXT       vmaddr 0x100000000  fileoff 0x0        filesize 0xc04000
__DATA_CONST vmaddr 0x100c04000  fileoff 0xc04000   size     0x84000
__DATA       vmaddr 0x100c88000  fileoff 0xc88000   vmsize   0x1e0000
__LINKEDIT   vmaddr 0x100e68000  fileoff 0xe48000

__text    addr 0x100004000 size 0x88df80  fileoff 0x4000
__cstring addr 0x1009a3640 size 0xce5a1   fileoff 0x9a3640
__data    addr 0x100deb358 size 0x59a85   fileoff 0xdeb358
__objc_selrefs addr 0x100d7dfe0 fileoff 0xd7dfe0

VA → file offset = VA − 0x100000000
```

LC_SEGMENT_64 欄位偏移(手寫 parser 常踩):

```
cmd@+0(4) cmdsize@+4(4) segname@+8(16) vmaddr@+24(8) vmsize@+32(8)
fileoff@+40(8) filesize@+48(8) maxprot@+56(4) initprot@+60(4) nsects@+64(4)
```

---

## 2. 機制定案(本案最核心的知識)

### 2.1 流程圖(全部由 `xref.py` 的引用點 + 反組譯拼出)

```
使用者按「更新照相點」
  └─ -[vwSideMenu btnUpdateCam_OnClick:]            IMP 0x10003867c → 真 body 0x100038014
       │  (只檢查一些 App 狀態旗標,沒有任何真正的訂閱判斷)
       ├─ post NSNotification  @"ADMOD_REWARD_SHOW"          ← 0x100038230
       ▼
     -[vwMain showRewardAd:]                        IMP 0x10015d780 → body 0x10015d78c
       │  (viewDidLoad 早就 addObserver:@selector(showRewardAd:) name:@"ADMOD_REWARD_SHOW")
       ├─ 真的去 AdMob 載獎勵廣告 → 重簽後 bundle id/憑證與 AdMob 註冊不符
       │     → GADError 1 kGADErrorInvalidRequest → 失敗
       └─ 只有在廣告成功時才會 post  @"REWARD_AD_FINISH"     ← 0x10015d9f0 (body +0x270)
       ▼
     -[vwSideMenu RewardAdFinish:]                  IMP 0x10003e3a8 → body 0x10003e3d0
       │  (viewDidLoad 也註冊了 addObserver:@selector(RewardAdFinish:) name:@"REWARD_AD_FINISH")
       └─ DispatchQueue.main.async { <Swift async 協程閉包 0x1001c9d58> }
             └─ 非同步 HTTP GET  http://www.api.example.com/WebApi/GetRenewPCams2.php   ← 引用點 0x1000e0708
                  └─ 成功 → -[vwMain UpdateCamComplete:]  (「已經更新 %d 個照相點,謝謝!」)
```

失敗分支(使用者看到的錯誤):

```
AdMob 失敗 → -[vwSideMenu RewardAdFail:] / RewardAdAbort:   IMP 0x10003e6e0 / 0x10003efb4
   └─ 顯示「無法開啟廣告」0x10003ea00 / 0x10003ed64 / 0x10003ee28
      以及「廣告啟動失敗!, 錯誤碼:」0x10003f64c
```

「還沒看廣告就按更新」的另一條提示路徑:
無名閉包 ~0x10003e5d0–0x10003e6d8 → `[delegate isEnabled]` 為 false → `[delegate setEnabled:1]`
→ `swift_once(&0x100deb380)` → `showAlert(0x1000336d0, msg=0x1009a8dd0)`
→ 顯示「完整的影片播放後,才會進入更新步驟喔. 感謝!」(全檔**只有 0x10003e66c 一處**引用這個字串)。

### 2.2 「錯誤原因:Code:1 / [O]Request Error: Invalid request」是 AdMob 的錯,不是伺服器

* `Request Error: Invalid request.` 字串屬於 **Google Mobile Ads SDK 的錯誤表**(與 `Request Error: No ad to show`、`Request Error: Server error processing the request` 同一張表,檔案偏移約 0x60a4f0)。
* 意思是 `kGADErrorInvalidRequest = 1` —— **重簽後的 App 與 AdMob 後台的 bundle id / 憑證對不上**,廣告請求本來就一定會失敗。
* 推論:只要不讓 App 去問 AdMob(改成自己補發 `REWARD_AD_FINISH`),錯誤就永遠不會出現,也不需要碰伺服器。

### 2.3 伺服器端的兩個端點(記錄用,最終並未需要繞過)

| 端點 | 用途 | `__text` 引用點 |
|---|---|---|
| `http://www.api.example.com/WebApi/GetRenewPCams2.php` | 下載/更新照相點(multipart/form-data) | 0x1000e0708 |
| `http://www.api.example.com:56888/SubsApi/GetInfo` | 伺服器端訂閱狀態查詢 | 0x1000dedac |
| `http://www.api.example.com/WebApi/GetStatus.php` | 遠端設定(`abort_ad_no_fill`、`ver_cctv_nfb=`、`ver_app_limit_min`…) | 0x100157894 |

實測:更新照相點的請求在繞過廣告後**一次就 200**,伺服器端沒有再擋。

---

## 3. 誤區與教訓(本案花了最多時間的部分,務必先讀)

1. **`cmn x8,#1 / b.ne` ≠ 訂閱檢查。**
   全檔有 1279 處這個配對,`0x100deb358/0x100deb380/0x100deb388` 這些位址被當成「訂閱狀態」在 v1–v9 寫入 0。
   實際上它們是 **Swift lazy global 的 swift_once 守衛**(x8 == −1 表示「還沒初始化」),`b.ne` 的目標才是「已初始化 → 使用該值」的正常路徑。
   教訓:先確認一個資料位址落在哪個 section(`0x100deb380` 是 `__DATA,__data`;`0x100e550240` 屬 `__BSS`,**fileoff = 0,讀檔會讀到別的 section 的內容**),
   再確認它被讀取時的用途,別看到「-1 比較」就當成未訂閱。

2. **`RemoveADValidSub` / `isRewardMissionOk` 根本不是 ObjC 方法。**
   在 24,710 行的 ObjC method 清單裡查不到 —— 它們是 Swift 內部成員(`isRewardMissionOk` 只出現在 Swift field-name 反射字串
   `…WattingRADprepare2ShowMode.rewardedAd.tmCloseAD.isRewardMissionOk.timerClock…`,屬 `_TtC7TARGET17clsGlobalVariable`,methods = 0)。
   → v1–v9 用 method swizzling 去掛這兩個名字,**永遠不會生效也不會報錯**(靜默失敗),這是最長的死路。

3. **Swift 類別的方法在 ObjC method list 裡,可以直接 swizzle。**
   `_TtC7TARGET10vwSideMenu` / `_TtC7TARGET6vwMain` 的 `btnUpdateCam_OnClick:`、`showRewardAd:`、`RewardAdFinish:` 等
   都是 Swift 實作但暴露在 ObjC method list → `method_setImplementation` 就能掛,**不需要 Swift hooking**。
   但要注意 Swift 類別的 runtime 名有 `_TtC7TARGET` 前綴:查類別要 `objc_getClass` → `NSClassFromString("targetapp.X")` → 最後用 `objc_copyClassList` 後綴比對,只試短路徑名會靜默失敗。

4. **Swift 方法進入點常是 3 指令 thunk,真 body 在後面。**
   形如 `adrp x3,<closure>; add x3,…; b <helper>`(helper 兩種:0x10003d0cc 通用、0x100014bcc 會 `bridgeAnyObjectToAny` + `blr x19`)。
   例:`btnUpdateCam_OnClick:` thunk 0x10003867c → 真邏輯在 closure 0x100038014;`showRewardAd:` thunk 0x10015d780 → body 0x10015d78c。

5. **`objc_msgSend` 的函式指標轉型必須與目標簽章完全一致。**
   v11 用 `id (*)(id, SEL, id, ...)`(可變參數)去呼叫 `+[UIAlertController alertControllerWithTitle:message:preferredStyle:]`,
   arm64 上可變參數會改走堆疊傳遞,被呼叫端從 x3 讀到垃圾 → `doesNotRecognizeSelector:` → **SIGABRT 閃退**(實機 8 份崩潰報告全指向這裡)。
   零參數 selector 也要用 `id (*)(id, SEL)` 單獨轉型。
   → **dylib 裡最保險的做法是根本不要在 hook 裡碰 UIKit**:v12 起直接移除所有彈窗,診斷改走日誌 + UDP。

6. **`NSURLProtocol` 偽造回應會把 App 弄死一半。**
   v9/v10 攔 `api.example.com` 回假 JSON `{"subscribed":true,…}` → 連「下載照相點」都被擋掉。
   要攔就只記錄、不要改回應;或只攔廣告網域。

7. **不要用 `mprotect(page, RWX)` 改 `__DATA`。** iOS 有 W^X,`PROT_EXEC` 會失敗(v8 的修補從頭到尾沒生效)。要改就 `PROT_READ|PROT_WRITE`。
   但在本案最終也沒必要改任何資料 —— 見第 1 點。

8. **靜態 patch 比對錯目標會直接弄壞 App。**
   v1 把 0x10003e65c / 0x10003e678 / 0x10003e6a8 改成 NOP,實際上破壞的是**廣告失敗提示的 Swift 函式**(移除了 `isEnabled`/`setEnabled` 與提示視窗)。任何 patch 前先用 `xref.py` + `adis.py` 確認函式語意。

9. **`LC_LOAD_DYLIB` 不能放相對路徑。** 用 `@executable_path/Frameworks/xxx.dylib` 注入會被 dyld 拒絕:
   `Library not loaded: */adgatedylib_v3.dylib … (relative path not allowed in hardened program)` → SIGABRT。「手動注入 IPA」這條路因此作廢,改用 LCSign 重簽注入。

10. **不可以把 `.o` 改 filetype 當 dylib。**
    v8 早期把 Mach-O object file(filetype 1)改成 6 交付 → dyld 載不進去,使用者只看到「完全沒有 dylib 的 console 輸出」,浪費一輪。
    驗收 dylib 一定要看 `otool -l`(LC_BUILD_VERSION platform 2 = iOS)、`otool -L`(安裝名全為 `/usr/lib`、`/System/Library`)與 `file`。

11. **`printf`/`vsnprintf` 不吃 `%@`。** 日誌裡格式字串用 `"%@"` 只會印出 `@`(純外觀問題,但會讓人誤判參數傳錯)。

---

## 4. 最終 dylib(v13)設計

原始碼:`re/appgate/adgatedylib_v13.m`(13 KB,純 Objective-C + objc runtime,**不 import UIKit / StoreKit**)。

### 4.1 掛鉤表

| 類別 | 方法 | 行為 |
|---|---|---|
| `vwMain` | `showRewardAd:` | **不呼叫原方法**(完全不碰 AdMob)→ `ag_post_finish("showRewardAd -> bypass")` 直接送完成通知 |
| `vwMain` | `UpdateCamComplete:` | log + `g_inflight = NO`(這輪結束,允許下一次按鍵)+ 原方法 |
| `vwSideMenu` | `btnUpdateCam_OnClick:` | log + 原方法(原方法會 post `ADMOD_REWARD_SHOW`,由上面的 hook 接手);另留 1.5 秒後備觸發 |
| `vwSideMenu` | `RewardAdFinish:` | log + 原方法 |
| `vwSideMenu` | `RewardAdFail:` / `RewardAdAbort:` | log → 改走 `ag_post_finish` |
| `vwSideMenu` | `IntertitialAdFinish:` | log + 原方法 |
| `vwSubsAdRemove` | `btnDoSubscription_OnClick:` | log + 原方法(觀察訂閱流程) |
| `NSURLSession` | `dataTaskWithRequest:completionHandler:` | **只記錄** exampleapi / SubsApi 的請求與回應(前 ~400 字),不改內容 |

### 4.2 三個關鍵設計點

**(a) 通知補發 + in-flight 去重 —— 修掉「按一次跑兩輪」**

```c
static BOOL g_inflight = NO;
static CFAbsoluteTime g_inflightAt = 0;

static void ag_post_finish(const char *why) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (g_inflight && (now - g_inflightAt) < 15.0) {   // 已在更新中 → 丟棄重複觸發
        AG("skip REWARD_AD_FINISH (%.2fs 前已觸發,仍在更新中; %s)", now - g_inflightAt, why);
        return;
    }
    g_inflight = YES; g_inflightAt = now;
    AG("post REWARD_AD_FINISH (%s)", why);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"REWARD_AD_FINISH" object:nil];
    });
}
```

為什麼需要:同一輪裡有三個地方會送 `REWARD_AD_FINISH`(實機 log):

```
19:40:08  btnUpdateCam_OnClick → showRewardAd → post FINISH → RewardAdFinish(第1輪) → HTTP 200 → UpdateCamComplete
19:40:09  post FINISH (btnUpdate 的 1.5 秒後備觸發) → RewardAdFinish(第2輪)   ← 使用者看到的「跑兩次」
19:40:14  RewardAdFail(AdMob 逾時約 6 秒) → post FINISH → RewardAdFinish(第3輪)  ← 再補一刀
```

`UpdateCamComplete:` 到達時清掉 `g_inflight`(更新真的完成 → 下一輪按鍵立即可用),15 秒保險避免更新失敗時永久卡住。
後備觸發保留:萬一 `showRewardAd:` 沒被叫用,`g_inflight` 還是 NO,1.5 秒的補發會生效。

**(b) 防重入:兩個進入點只能裝一次**

`+[AGLoader13 load]` 與 `__init_offsets` 的 `_ag_ctor` 都會呼叫 `ag_install()`,
沒有 `static BOOL done` 守衛時第二次 swizzle 會讓 `orig` 指向自己 → 無限遞迴。

**(c) 診斷不碰 UIKit,改用 UDP beacon**

```c
// raw socket、不受 ATS 限制,UDP 送到 Mac 與 Linux 兩端 9999
sendto(sock, line, len, 0, (struct sockaddr *)&addr, sizeof(addr));
```

`AG()` = `NSLog` + 環形緩衝 + 寫 `NSTemporaryDirectory()/adgate13.log` + UDP beacon。
實機上可以完全沒有 Xcode/console,只要另一端 `nc -u -l 9999` 就能即時看到 swizzle 與流程軌跡(本案就是靠這個一次定位成功與否)。

### 4.3 版本演進(死路紀錄)

| 版本 | 做法 | 結果 |
|---|---|---|
| v1–v5 | 掛 `RemoveADValidSub` / `isRewardMissionOk` / `SKPaymentQueue` / `GADRewardedAd` + 硬改訂閱資料欄位 | 全部無效(名字不存在;欄位是 swift_once 守衛) |
| v6–v7 | 加 mprotect 掃描、`NSURLProtocol` 假回應 | W^X 擋掉寫入;假回應反而擋住下載 |
| v8 | `mprotect(RWX)` + 4 秒 UIKit 彈窗;並用「`.o` 改 filetype」硬造 dylib | dylib 載不進去;修補無效 |
| v9 | 持續 0.5s×240 次重寫訂閱欄位 + `NSURLProtocol` | 仍無效 |
| v10 | 首次真的 swizzle 到 `btnUpdateCam_OnClick:` / `showRewardAd:` | 方向對了,但 `showRewardAd:` 仍走原方法 |
| **v11** | `showRewardAd:` 不呼叫原方法、直接 post `REWARD_AD_FINISH` | ✅ **首次成功繞過**(實機 19:40 驗證),但啟動 5 秒後 SIGABRT 閃退(UIKit 彈窗 ABI) |
| v12 | 移除所有 UIKit 彈窗 + hook 全包 `@try/@catch` | ✅ 不閃退,但按一次會跑兩輪 |
| **v13** | in-flight 去重 + `UpdateCamComplete:` 清旗標 | ✅ 最終版:不閃退、單輪完成 |

---

## 5. 編譯與交付流程

### 5.1 iOS dylib 編譯指令(在 macOS 上,**實測可用**)

```bash
clang -arch arm64 -dynamiclib -fobjc-arc -target arm64-apple-ios14.0 \
  -isysroot /Users/zoe/Downloads/iPhoneOS27.0.sdk \
  -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
  -Wl,-undefined,dynamic_lookup \
  -L /Users/zoe/Downloads/iPhoneOS27.0.sdk/usr/lib -lSystem \
  -o OUT.dylib SRC.m
```

警告 `-undefined dynamic_lookup is deprecated on iOS`、`ignoring duplicate libraries: '-lSystem'` 可忽略。

**前置修復(必要)**:`iPhoneOS27.0.sdk`(GitHub `xybp888/iOS-SDKs`)的 `.tbd` 內含 `arm64e.x1-ios` 這類新架構字串,這套 `ld` 不認識,會報 `unknown architecture` / `malformed file` / `unknown file type`。修法:對 SDK 內所有含 `arm64e.x` 的 `.tbd` 做:

```bash
sed -i '' -E 's/arm64e\.x[0-9]+-ios/arm64-ios/g; s/arm64e\.x[0-9]+-macos/arm64-macos/g; s/arm64e\.x[0-9]+-maccatalyst/arm64-maccatalyst/g' <each .tbd>
```

另外**不要在 dylib 原始碼裡 `#import <UIKit/UIKit.h>`**:這套 clang + 這份 SDK 的標頭組合會在 `UIAccelerometer.h` 等處因缺 `API_OBSOLETED` 巨集而編譯失敗(18 errors)。全部改用 objc runtime 動態呼叫。

### 5.2 後處理與驗收

```bash
install_name_tool -id "@executable_path/Frameworks/adgatedylib_v13_ios.dylib" OUT.dylib
codesign -f -s - OUT.dylib
otool -l OUT.dylib | grep -A3 LC_BUILD_VERSION   # 要看到 platform 2 (iOS)、minos 14.0
otool -L OUT.dylib                               # 只能出現 /usr/lib/* 與 /System/Library/* 的安裝名
file OUT.dylib                                   # Mach-O 64-bit dynamically linked shared library arm64
ls -l OUT.dylib; shasum -a 256 OUT.dylib
```

### 5.3 上到手機(LCSign / GCDWebUploader 的 API)

`192.168.68.62:8088` 就是手機上的 LCSign,它是一個 GCDWebUploader;前端網頁用的端點:

```bash
# 列目錄
curl "http://192.168.68.62:8088/list?path=%2FDownloads%2F"
# 上傳(multipart 欄位:path = 目標資料夾、files[] = 檔案)
curl -F "path=/Downloads/" -F "files[]=@adgatedylib_v13_ios.dylib" http://192.168.68.62:8088/upload
# 下載(驗證用:抓回來比 sha256)
curl -o /tmp/dl.dylib "http://192.168.68.62:8088/download?path=%2FDownloads%2Fadgatedylib_v13_ios.dylib"
```

手機上的資料夾:`/Downloads/`(注入用檔案都放這)、`/InputFile/`、`/Output/`、`/Projects/`。
**注入時只勾一個 dylib** —— 同時注入兩個版本會讓同一個方法被 swizzle 兩次 → `orig` 指向自己 → 無限遞迴。

---

## 6. 實機 debug 管道(未越獄 iPhone,無 Xcode 專案)

這是本案能收斂的關鍵基礎設施,值得記下來。

| 目的 | 指令 | 備註 |
|---|---|---|
| 列裝置 | `xcrun devicectl list devices` | iPhone 16 Pro,UDID `00008140-000064C60882201C` |
| **崩潰報告** | `xcrun devicectl device copy from --device <id> --domain-type systemCrashLogs --source . --destination <dir>` | **最可靠的管道**;`.ips` 內含完整 backtrace(本案就是靠它定位 UIKit ABI 閃退) |
| 裝置系統日誌 | `echo <pw> \| sudo -S -p '' log collect --device-udid <UDID> --last 20m --size 60m --output /tmp/x.logarchive` | **必須 root**;`--predicate` 對實機無效;macOS 15 的 `log show` 讀不了版本 6 → 只能 `find <archive> -name "*.tracev3" -exec strings -a {} + \| grep <kw>` |
| 即時診斷(本案主力) | dylib 內 UDP beacon → `nc -u -l 9999`(Mac)/ 自寫 UDP listener(Linux) | 不受 ATS、不需要 console、不需要 Xcode |
| App 內診斷 | 早期版本用 `UIAlertController` 彈窗 | **已淘汰**:容易踩 objc_msgSend ABI → 閃退;改用日誌 + UDP |

`devicectl` 在這組 iOS 27 上**不可靠**:`device info apps` / `info processes` 都回 0 筆、`device copy from --domain-type appDataContainer` 回 `ContainerLookupErrorDomain -1`、
`device process launch --console` 回 `not installed`(LS error -10814)。但 App 其實裝著也在跑(從 logarchive 字串可看到 bundle container、SpringBoard scene、通知字串)。
→ **不要把這些 API 的空結果當成「App 沒安裝」的證據。**

---

## 7. 驗證結果(實機)

成功的 beacon 軌跡(iPhone 192.168.68.62 → Linux 9999):

```
19:39:56  swizzled -[targetapp.vwSideMenu btnUpdateCam_OnClick:] / RewardAdFail:
19:39:56  swizzled -[targetapp.vwMain showRewardAd:] / UpdateCamComplete:
19:40:08  == btnUpdateCam_OnClick: (繞過廣告) ==
19:40:08  showRewardAd -> bypass(不呼叫原方法) → post REWARD_AD_FINISH
19:40:08  RewardAdFinish: → HTTP < 200
19:40:08  == UpdateCamComplete: 照相點更新完成事件 ==
19:40:14  RewardAdFail: 被攔截 → (v13 起被 in-flight 去重丟棄)
```

使用者回報:「成功了 成功繞過並且更新照相點了」→(v12 閃退修正後)「不會閃退了,但是按下更新照相點後會好像觸發兩次」
→(v13)「成功了」。

---

## 8. 可重用 SOP:逆向 iOS App 的「看廣告/訂閱才能用某功能」

1. **不要先猜訂閱資料欄位。** 先用 xref 把「使用者看到的那句錯誤字串」的引用點找出來,再從那個函式往上/往下追。
2. **查錯誤字串的來源**。若字串屬於第三方 SDK(本案:Google Mobile Ads SDK 的錯誤表),代表失敗根本不是伺服器拒絕 → 只要繞過 SDK 呼叫即可,別去偽造 API 回應。
3. **確認是通知驅動還是直接呼叫**。找 `postNotificationName:` / `addObserver:selector:name:` 的配對(本案 `ADMOD_REWARD_SHOW` → `showRewardAd:`、`REWARD_AD_FINISH` → `RewardAdFinish:`),
   通知驅動的流程最好繞:**把「等 SDK 成功」那一步整段抽掉,由我們直接補發成功通知**。
4. **確認哪些方法真的存在於 ObjC method list**(`objcdump2.py`)。Swift 內部成員(常出現在反射字串裡的名字)掛不到,別浪費時間。
5. **驗收要看真機**:`otool` 結構 + 實機 beacon/UDP 日誌 + 崩潰報告三件套。
6. **去重**:任何「補發事件」的設計都要有 in-flight/時間窗去重,並在「完成事件」時清旗標,否則必然出現重複觸發。

---

## 9. 檔案清單(本案產物)

| 路徑 | 說明 |
|---|---|
| `re/appgate/EXPERIENCE.md` | 本文件 |
| `re/appgate/SOLUTION.md` | 機制圖 + 掛鉤表 + 踩坑(v12/v13 章節) |
| `re/appgate/adgatedylib_v13.m` | 最終 dylib 原始碼 |
| `re/appgate/dist/adgatedylib_v13_ios.dylib` | 最終產物(sha256 `18a590d5…`,已上到手機 `/Downloads/`) |
| `re/appgate/dist/adgatedylib_v11_ios.dylib` / `_v12_ios.dylib` | 中間版本(留作對照) |
| `re/appgate/dist/beacon_ios.log` / `beacon_mac.log` | 實機成功軌跡 |
| `re/appgate/{adis,xref,objcdump2,smartdis,scan_refs}.py` | Mach-O / ARM64 / ObjC 分析工具 |
| `re/appgate/{xssh,deploy_v13,inject_dylib}.py` | SSH 執行器、遠端編譯部署、Mach-O 注入腳本 |
| `re/appgate/orig_ex/Payload/targetapp.app/targetapp` | **未補丁**原始二進位(分析基準,勿覆寫) |

---

## 附錄:Xcode 還需要留著嗎?

**結論:編譯 dylib 不需要 Xcode,只需要 Command Line Tools(2.1 GB,獨立安裝,務必保留)。**

實測(把 `DEVELOPER_DIR` 指到 CLT,完全不碰 Xcode.app):

```bash
DEVELOPER_DIR=/Library/Developer/CommandLineTools clang -arch arm64 -dynamiclib -fobjc-arc \
  -target arm64-apple-ios14.0 -isysroot /Users/zoe/Downloads/iPhoneOS27.0.sdk \
  -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
  -Wl,-undefined,dynamic_lookup -L /Users/zoe/Downloads/iPhoneOS27.0.sdk/usr/lib -lSystem \
  -o /tmp/clt_test.dylib adgatedylib_v13.m
# → Mach-O 64-bit dynamically linked shared library arm64;LC_BUILD_VERSION platform 2,minos 14.0 ✅
```

`clang` / `ld` / `otool` / `install_name_tool` / `codesign` / `zip` / `git` 全部由 CLT 提供(CLT 16.4.0)。
Xcode.app 唯一不可替代的是 **`xcrun devicectl`**(撈裝置崩潰報告/列舉裝置)。

磁碟實測(macOS 15.8.3,113 GB 卷,26 GB 可用):

| 項目 | 大小 | 刪掉會怎樣 |
|---|---|---|
| `/Applications/Xcode.app` | 4.7 GB | 失去 `xcrun devicectl`、Instruments |
| `~/Library/Developer/Xcode/iOS DeviceSupport/iPhone17,1 27.0 (24A437)` | **6.6 GB** | 失去裝置符號化;下次連裝置會自動重建(要幾分鐘) |
| `~/Library/Developer/Xcode/DerivedData` | 409 MB | 純快取,可刪 |
| `~/Library/Developer/CoreSimulator` | 192 MB | 沒在用模擬器就沒差 |
| `/Library/Developer/CommandLineTools` | 2.1 GB | **不要刪**(編譯器本體) |
| `/Users/zoe/Downloads/iPhoneOS27.0.sdk` | — | **不要刪**(已修好 `.tbd` 的 iOS SDK) |

要刪之前**務必先切換工具鏈**,否則 `/usr/bin/clang`、`xcrun` 會直接壞掉:

```bash
sudo xcode-select -s /Library/Developer/CommandLineTools
# 驗證(應印出 CLT 路徑):
xcode-select -p; DEVELOPER_DIR=/Library/Developer/CommandLineTools clang --version | head -1
# 再刪:
rm -rf /Applications/Xcode.app ~/Library/Developer/Xcode ~/Library/Developer/CoreSimulator
```

之後唯一的損失是「從 Mac 撈裝置崩潰報告」。替代方案:
1. **在手機上看**:設定 → 隱私權與安全性 → 分析與改進功能 → 分析資料 → 找 `targetapp-*.ips` → 分享出來。
2. 即時診斷本來就不靠 Mac,dylib 的 UDP beacon + `nc -u -l 9999` 就夠。
3. 真的需要 devicectl,再裝回 Xcode 即可(專案檔案都在本目錄,不依賴 Xcode)。

### 實際執行結果(2026-11-20)

```
sudo xcode-select -s /Library/Developer/CommandLineTools   # 先切,否則 clang/xcrun 直接壞
xcode-select -p => /Library/Developer/CommandLineTools
clang --version => Apple clang version 17.0.0              # CLT 提供,不受影響
rm -rf /Applications/Xcode.app ~/Library/Developer/Xcode ~/Library/Developer/CoreSimulator
可用空間 26Gi → 38Gi(+12 GB);刪除後再用 iPhoneOS SDK 編譯 v13 仍成功(Mach-O arm64 dylib)
git 2.39.5 / zip / otool / codesign / install_name_tool 全部正常
```

還可再回收:`/Library/Developer/CoreSimulator` = **25 GB**(Volumes 21 GB = iOS 模擬器 runtime `iOS_23D8133`、Caches 4.3 GB)。
Xcode 已移除 → 模擬器不可用 → 這 25 GB 是純死重,可 `sudo rm -rf /Library/Developer/CoreSimulator` 回收。

**注意**:`xcrun devicectl` 隨 Xcode 一起消失(`unable to find utility "devicectl"`)。
`log collect --device-udid` 在「手機沒接著」時會回 `Device not configured (6)` —— 此結果不具結論性,
要確認是否仍可撈裝置日誌,必須**接著手機再測一次**。崩潰報告的保底方案仍是在手機端:
設定 → 隱私權與安全性 → 分析與改進功能 → 分析資料 → `targetapp-*.ips`。

### 清乾淨:最終結果(2026-11-20)

**可用空間 26 GiB → 52 GiB(+26 GB)**

| 動作 | 回收 |
|---|---|
| 刪 `/Applications/Xcode.app` | 4.7 GB |
| 刪 `~/Library/Developer/Xcode`(含 iOS DeviceSupport 6.6 GB) | 7.0 GB |
| 卸載唯讀模擬器 runtime 卷 + 刪 `/Library/Developer/CoreSimulator` | — |
| 刪 MobileAsset 模擬器 runtime(`/System/Volumes/Data/System/Library/AssetsV2/com_apple_MobileAsset_iOSSimulatorRuntime`) | 9.7 GB |
| detach 殘留磁碟映像(被 `rm` 掉 dmg 但仍在掛載的 Sideloadly 安裝映像 + 兩個孤兒 disk image) | ~10 GB |
| 刪 `~/Downloads/test`、`crashlogs*`、`~/Library/Caches/puccinialin`、清空 `~/.Trash` | ~1 GB |

踩到的兩個點:
1. **模擬器 runtime 是唯讀掛載的 APFS 卷**(`Read-only file system` 拒絕 `rm`),必須先
   `sudo diskutil unmount force /Library/Developer/CoreSimulator/Volumes/iOS_23D8133` 再刪;
   實際佔空間的是 Cryptex 背後的 MobileAsset(`/System/Volumes/Data/System/Library/AssetsV2/…`),那才是真正要刪的目標。
2. **刪掉 dmg 檔案不等於卸載**:`/Volumes/Sideloadly! v0.72 Setup` 還掛著、`hdiutil info` 還列著孤立映像,
   它們照樣佔空間。用 `diskutil unmount force` + `hdiutil detach -f` 收掉才真的釋放。

**保留(必要)**:`/Library/Developer/CommandLineTools` 2.1 GB(clang/ld/otool/codesign/git 本體)、
`/Library/Developer/{CoreDevice,DeveloperDiskImages,PrivateFrameworks,DeviceKit}` ~173 MB(裝置連線用)、
`/Users/zoe/Downloads/iPhoneOS27.0.sdk` 381 MB(已修好的 iOS SDK,sysroot)。

**重要更正**:`xcrun devicectl` 確實隨 Xcode 消失,但 **`log collect --device-udid` 照樣能用**
(實測 `Archive successfully written`,手機接著時可撈裝置日誌)。所以移除 Xcode 後仍保有裝置日誌管道;
只有 `devicectl` 特有的列舉/容器 API 與 Instruments 沒了。崩潰報告仍可從手機端「分析資料」取得。

**仍可再省(未動,屬使用者 App 快取)**:`~/Library/Caches/Firefox` 1.0 GB、`com.spotify.client` 742 MB、
`icloudmailagent` 595 MB。
