# 目標 App 2.0.9「更新照相點」廣告鎖繞過 — 解法記錄

狀態：**已實機驗證成功**（iPhone 16 Pro / iOS 27.0，非越獄，sign.lc 注入 dylib）

## 交付物

| 檔案 | 說明 |
|---|---|
| `dist/adgatedylib_v11_ios.dylib` | 可注入的 iOS arm64 dylib（91,008 bytes，sha256 `32b7faf7ef162c3555cd6b431616b90e21f92dba0f0aa41f6611aa3218d1e2a9`） |
| `adgatedylib_v11.m` | dylib 原始碼 |
| `deploy_v11.py` | 上傳到 Mac + 用 iPhoneOS SDK 編譯 + 驗證的一鍵腳本 |
| `dist/beacon_ios.log` | 實機成功當下的 UDP 診斷日誌（19:40:03–19:40:27） |
| `xref.py` / `adis.py` / `objcdump2.py` / `smartdis.py` / `xssh.py` | 逆向工具鏈（ARM64 xref、註解式反組譯、ObjC 方法表、SSH 執行器） |

## 機制（逆向定案）

```
[按下「更新照相點」]  -[vwSideMenu btnUpdateCam_OnClick:]         body 0x100038014
        │  post NSNotification  @"ADMOD_REWARD_SHOW"              0x100038230
        ▼
 -[vwMain showRewardAd:]  (IMP 0x10015d780 / body 0x10015d78c)  ← 真的去 AdMob 要獎勵廣告
        │  成功才 post @"REWARD_AD_FINISH"                        body+0x270
        ▼
 -[vwSideMenu RewardAdFinish:]  (IMP 0x10003e3a8 / body 0x10003e3d0)
        │  DispatchQueue.main.async { … }
        ▼
 Swift 協程閉包 0x1001c9d58  →  async HTTP（GetRenewPCams2.php 等）→ 真正更新照相點
```

* 使用者看到的 **`[O]Request Error: Invalid request.` 是 Google Mobile Ads SDK 的錯誤字串**（與 `No ad to show`、`Server error processing the request` 同表，檔案 offset ≈ 0x60a4f0）。重簽過的 App 其 bundle id / 憑證與 AdMob 註冊不符 → `kGADErrorInvalidRequest` → 廣告永遠開不起來 → `RewardAdFail:` / `RewardAdAbort:` 顯示「無法開啟廣告 / 錯誤原因:Code:1」。**這是廣告失敗，不是訂閱驗證失敗。**
* `完整的影片播放後,才會進入更新步驟喔`（0x1009a8dd0）只有一處引用 0x10003e66c，是「沒看廣告就按更新」的提示，不是閘門。
* `RemoveADValidSub()` 與 `isRewardMissionOk` **不在 ObjC method list**（24,710 行方法表查無）→ 它們是 Swift 內部成員（`isRewardMissionOk` 只出現在 Swift 反射欄位字串，屬 `_TtC7TARGET17clsGlobalVariable`）。**用 method swizzling 掛這兩者完全無效**（v1–v9 失敗的真正原因）。
* 早期當成「訂閱檢查點」的 `cmn x8,#1 / b.ne`（0x100deb358 / 0x100deb380 / 0x100deb388 等 1279 處）其實是 **Swift lazy global 的 `swift_once` 守衛**，不是訂閱判斷；對這些位址寫資料既無效也不安全。
* 伺服器端端點：`http://www.api.example.com/WebApi/GetRenewPCams2.php`（照相點下載，引用點 0x1000e0708）、`http://www.api.example.com:56888/SubsApi/GetInfo`（訂閱查詢，0x1000dedac）、`http://www.api.example.com/WebApi/GetStatus.php`（0x100157894）。

## v11 的做法：走通知路徑，完全不碰 AdMob

| 掛鉤 | 行為 |
|---|---|
| `-[vwMain showRewardAd:]` | **不呼叫原方法**，直接 post `REWARD_AD_FINISH` |
| `-[vwSideMenu RewardAdFail:]` / `RewardAdAbort:` | 記錄後改 post `REWARD_AD_FINISH`（攔掉「無法開啟廣告」） |
| `-[vwSideMenu btnUpdateCam_OnClick:]` | log + 呼叫原方法 + 1.5 s 後補發 `REWARD_AD_FINISH`（後備） |
| `-[vwSideMenu RewardAdFinish:]`、`-[vwMain UpdateCamComplete:]`、`IntertitialAdFinish:`、`vwSubsAdRemove btnDoSubscription_OnClick:` | 記錄 + 原方法 |
| `SKPaymentTransaction.transactionState` / `SKPaymentQueue.canMakePayments` / `restoreCompletedTransactions` | 模擬已購買狀態 |
| `NSURLSession -dataTaskWithRequest:completionHandler:` | **只記錄** exampleapi / SubsApi 的請求與回應，不偽造（v9/v10 偽造 JSON 會擋掉照相點下載） |

工程要點：

* 類別查找用 `objc_getClass` → `NSClassFromString` → `targetapp.X` → **`objc_copyClassList` 後綴比對**（Swift 的 runtime 名稱可能是 `_TtC7TARGET10vwSideMenu`；只試 `"vwSideMenu"` 會靜默失敗）。
* `ag_install()` 加 `static BOOL done` 防重入（`+[AGLoader11 load]` 與 `__init_offsets` 的 `_ag_ctor` 都會呼叫；二次 swizzle 會讓 orig 指向自己 → 無限遞迴）。
* 完全以 `objc/runtime.h` 動態呼叫，**不 import UIKit/StoreKit**（iPhoneOS27.0.sdk 的標頭在此 clang 組合下會因 `API_OBSOLETED` 直接編譯失敗）。
* variadic 函式指標 `id (*)(id,SEL,...)` 不能呼叫零參數 selector，需另用 `id (*)(id,SEL)` 轉型。
* 診斷三管道：NSLog、`TMPDIR/adgate11.log`、**UDP beacon 到 192.168.68.52:9999 / 192.168.68.61:9999**（raw socket，不受 ATS 影響），另有啟動 5 秒後的彈窗。

## 重編譯指令（Mac）

```sh
clang -arch arm64 -dynamiclib -fobjc-arc \
  -target arm64-apple-ios14.0 \
  -isysroot /Users/zoe/Downloads/iPhoneOS27.0.sdk \
  -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
  -Wl,-undefined,dynamic_lookup \
  -L /Users/zoe/Downloads/iPhoneOS27.0.sdk/usr/lib -lSystem \
  -o adgatedylib_v11_ios.dylib adgatedylib_v11.m

install_name_tool -id "@executable_path/Frameworks/adgatedylib_v11_ios.dylib" adgatedylib_v11_ios.dylib
codesign -f -s - adgatedylib_v11_ios.dylib
```

（`-undefined dynamic_lookup is deprecated on iOS`、`ignoring duplicate libraries: '-lSystem'` 兩個警告可忽略。）

## 實機成功證據（dist/beacon_ios.log，節錄）

```
19:40:08  == [@ btnUpdateCam_OnClick:] 使用者按下更新照相點
19:40:08  == [@ showRewardAd:] 收到 ADMOD_REWARD_SHOW
19:40:08  post REWARD_AD_FINISH (showRewardAd 被叫用 → 直接完成)
19:40:08  == [@ RewardAdFinish:] 進入更新流程(sender=@)
19:40:08  HTTP< 200
19:40:08  == [@ UpdateCamComplete:] 照相點更新完成事件
19:40:14  !! [@ RewardAdFail:](原本要顯示『無法開啟廣告』)→ 改走完成流程
```

## 踩過的坑

* `LC_LOAD_DYLIB` 不可用相對路徑 `@executable_path/...` 自行注入到既有簽名的二進位 → 14:34 的 `targetapp-2026-11-20-143438.ips` 是 SIGABRT `relative path not allowed in hardened program`。最終改由 sign.lc 注入 dylib。
* 把 `.o` 的 filetype 從 1 改成 6 假造 dylib → dyld 不載入（這是 v8 沒出現 console 的原因）。
* 在 iOS 上 `mprotect(__DATA, PROT_READ|PROT_WRITE|PROT_EXEC)` 會因 W^X 失敗。
* iPhoneOS27.0.sdk 的 `.tbd` 內含 `arm64e.x1-ios` 等此 ld 不認識的架構字串 → 需全域 `sed -i '' -E 's/arm64e\.x[0-9]+-ios/arm64-ios/g'` 修補 SDK（675 個檔）。

---

# v12：修掉「開一陣子就閃退」

## 症狀與定位

v11 注入後繞過功能正常（19:40:08 成功更新照相點），但 App 約每 5 秒就崩一次，19:40:02–19:42:15 共 8 份崩潰報告。裝置崩潰報告（`systemCrashLogs`）反組譯後指向同一個地方：

```
SIGABRT / EXC_BAD_ACCESS(KERN_INVALID_ADDRESS at 0x10)
  libobjc.A.dylib   objc_exception_throw
  CoreFoundation    -[NSObject(NSObject) doesNotRecognizeSelector:]
  CoreFoundation    ___forwarding___ / _CF_forwarding_prep_0
  UIKitCore         +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
  adgatedylib_v11_ios.dylib  ag_show_alert
  adgatedylib_v11_ios.dylib  __ag_ctor_block_invoke      ← 啟動 5 秒後的診斷彈窗
```

8 份報告全部與 `UIAlertController` 有關（另有 2 份是彈窗 AutoLayout 例外）。

## 根因：variadic `objc_msgSend` 的 ABI 錯誤

v11 的 `ag_show_alert()` 這樣呼叫：

```c
id (*msgSend)(id, SEL, id, ...) = (void *)objc_msgSend;
id alert = msgSend((id)uialert, sel_registerName("alertControllerWithTitle:message:preferredStyle:"),
                   title, ms, (long)0);                       // ← 第3個參數走「可變參數」
id act   = msgSend((id)ag_class("UIAlertAction"), sel_registerName("actionWithTitle:style:handler:"),
                   @"OK", (long)0, nil);
```

在 **arm64 上可變參數是放堆疊**，但被呼叫端是非 variadic 方法，它從 `x3` 暫存器讀 `preferredStyle:`（`style:`／`handler:` 同理）→ 讀到垃圾 → UIKit 對垃圾物件送訊息 → `doesNotRecognizeSelector:` → SIGABRT。

**教訓**：用 `objc_msgSend` 呼叫方法時，函式指標的參數型別必須與目標方法簽章完全一致，不能用 `...` 圖方便。

## v12 的修正

1. **完全移除 `ag_show_alert()` 與 5 秒計時器** —— dylib 不再碰 UIKit（`otool -L` 只剩 libSystem / Foundation / libobjc / CoreFoundation，字串中已無 `UIAlertController`）。
2. 9 個 hook 全部包 `@try/@catch`，我們自己的程式碼丟例外時只記錄、不讓 App 崩潰。
3. 其餘 hook 邏輯與 v11 完全相同（v11 已被實機證明能成功繞過）。

產物：`dist/adgatedylib_v12_ios.dylib`（90,864 bytes，sha256 `128128f67a93c24ab27673ab5470a1e323651424a392387b4e168fd67dea7459`），install name `@executable_path/Frameworks/adgatedylib_v12_ios.dylib`，adhoc 已簽。

診斷管道（不依賴 UI）：NSLog、`TMPDIR/adgate12.log`、UDP beacon 到 192.168.68.52:9999 / 192.168.68.61:9999。

---

# v13：修掉「按一次更新照相點卻跑兩輪」

## 原因：三個觸發點在幾秒內各送一次 `REWARD_AD_FINISH`

v11/v12 的 `ag_post_finish()` 沒有去重，而同一輪流程裡有三個地方會送這個通知（v11 實機 log 是鐵證）：

```
19:40:08  btnUpdateCam_OnClick → showRewardAd → post REWARD_AD_FINISH → RewardAdFinish (第1輪) → HTTP 200 → UpdateCamComplete
19:40:09  post REWARD_AD_FINISH (btnUpdate 後備觸發)      → RewardAdFinish (第2輪)   ← 重複
19:40:14  RewardAdFail → post REWARD_AD_FINISH            → RewardAdFinish (第3輪)   ← 重複
```

* 後備觸發（`ag_btnUpdate` 內 1.5 秒後補發）在 `showRewardAd:` 正常被叫用時就是多餘的。
* AdMob 逾時約 6 秒後會走 `RewardAdFail:`，我們把它轉成完成流程 → 又送一次。

## 修正：in-flight 去重

```c
static BOOL g_inflight = NO;
static CFAbsoluteTime g_inflightAt = 0;

static void ag_post_finish(const char *why) {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (g_inflight && (now - g_inflightAt) < 15.0) {   // 正在更新中 → 丟棄重複觸發
        AG("skip REWARD_AD_FINISH (%.2fs 前已觸發…)", now - g_inflightAt);
        return;
    }
    g_inflight = YES; g_inflightAt = now;
    …post @"REWARD_AD_FINISH"…
}
```

`-[vwMain UpdateCamComplete:]` 到達時把 `g_inflight` 清掉（更新真的跑完，下一輪按鍵立刻可用），另有 15 秒保險，避免更新失敗時永久卡住而無法再按。

後備觸發保留：若哪天 `showRewardAd:` 沒被叫用，1.5 秒的補發仍會生效（此時 `g_inflight` 為 NO）。

產物：`dist/adgatedylib_v13_ios.dylib`（91,072 bytes，sha256 `18a590d5e831dec9107419b2b9964b8191604083f4010fcc79eeaea71016a14e`），已上傳到裝置 LCSign `/Downloads/`。

## LCSign(GCDWebUploader) 的 API

* 列目錄：`GET /list?path=%2FDownloads%2F`
* 上傳：`POST /upload`（multipart 欄位 `path`=<目標資料夾>、`files[]`=<檔案>）
* 下載：`GET /download?path=%2FDownloads%2F<檔名>`
