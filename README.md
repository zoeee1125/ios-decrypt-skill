# ios-decrypt-skill

iOS 逆向 / 解鎖付費與廣告閘門的**可重用技能 + 實戰記憶庫**。
內容來自一次真實案例:逆向「目標 App 2.0.9」,繞過「必須看完廣告才能更新照相點」的機制,
產出可在**未越獄 iPhone** 上注入的 arm64 dylib,並完成實機驗證。

> **去識別化聲明**:本 repo 已移除該 App 的所有可辨識字眼(名稱、bundle id、伺服器網域、二進位/類別前綴)。
> 文中一律以佔位符表示:`目標 App`、`com.example.targetapp`、`api.example.com`、`targetapp.%s`。
> 技術內容(機制、位址、掛鉤、工具)完整保留;出貨的 dylib 也是用去識別化原始碼重建的版本。

## 目錄結構

```
skills/ios-dylib-bypass/SKILL.md   技能本體(12 條鐵律 + 六步流程 + 檢查清單)
memory/EXPERIENCE.md               完整經驗匯出:機制、誤區、dylib 設計、編譯/部署/debug SOP
memory/SOLUTION.md                 機制圖 + 掛鉤表 + 版本演進(v1→v13)+ 踩坑
tools/                             自製分析工具(Linux 端,只需 python3 + capstone)
  adis.py        annotated ARM64 反組譯(標註 ObjC IMP / dyld stub / selref / cstring)
  xref.py        掃 __text 的 B/BL/ADRP+ADD/ADRP+LDR 交叉引用
  objcdump2.py   ObjC classlist + relative method list 傾印
  objcdump.py    初版 classlist 傾印(含 chained fixup 遮罩)
  smartdis.py    Mach-O 解析 + chained fixup 解碼(MachO.cfptr())
  scan_refs.py   ADRP+LDR 目標位址掃描
  xssh.py        無 tty 環境的 SSH 執行器(pty.fork + base64 腳本餵遠端 bash)
  inject_dylib.py 手動把 LC_LOAD_DYLIB 注入 Mach-O(注意:相對路徑會被 dyld 拒絕)
case-study/
  dylib-src/     dylib 原始碼(v11 首度成功 / v12 修閃退 / v13 最終版)
  bin/           最終 dylib 產物(sha256 18a590d5…)
  logs/          實機成功軌跡(UDP beacon)
```

## 怎麼用這個技能

```bash
# 安裝到 DSH 技能目錄
cp -r skills/ios-dylib-bypass ~/.dsh/skills/
```

之後任何「幫我繞過某個 iOS App 的廣告/訂閱閘門」「做一個可注入的 iOS dylib」的請求都會自動載入。
技能本身與特定 App 無關;`case-study/` 只是完整案例,供對照與抄pattern。

## 這次案例的核心結論

| 項目 | 值 |
|---|---|
| App | 目標 App 2.0.9 (build 122),bundle id 以 `com.example.targetapp` 表示,Mach-O arm64 |
| 症狀 | 按「更新照相點」→「無法開啟廣告 / 錯誤原因:Code:1 / [O]Request Error: Invalid request」 |
| 真正閘門 | `-[vwSideMenu btnUpdateCam_OnClick:]` → post `ADMOD_REWARD_SHOW` → `-[vwMain showRewardAd:]` → 等 AdMob 成功 → post `REWARD_AD_FINISH` → `-[vwSideMenu RewardAdFinish:]` → 非同步抓 `GetRenewPCams2.php` |
| 繞法 | swizzle `-[vwMain showRewardAd:]`:不呼叫原方法(完全不碰 AdMob),直接補發 `REWARD_AD_FINISH` |
| 關鍵認知 | 那句錯誤是 **Google Mobile Ads SDK 的 `kGADErrorInvalidRequest`**(重簽後 bundle id/憑證與 AdMob 後台對不上),**不是伺服器拒絕** |
| 最大的坑 | 1279 處 `cmn x8,#1 / b.ne` 全是 **Swift lazy-global 的 `swift_once` 守衛**,不是訂閱檢查;`RemoveADValidSub` / `isRewardMissionOk` 根本不是 ObjC 方法(掛了也沒用) |
| 結果 | 未越獄 iPhone 16 Pro / iOS 27.0,LCSign 重簽注入後:無廣告、無錯誤、單輪完成 |

## 12 條鐵律(節錄,完整見 SKILL.md)

1. 從「使用者看到的那句錯誤字串」下手,別先猜訂閱資料欄位
2. 先查錯誤字串出處——若是第三方 SDK,失敗其實來自憑證不符
3. `cmn x8,#1 / b.ne` = `swift_once` 守衛,**不是**未訂閱
4. 掛鉤前確認方法真的在 ObjC method list(Swift 內部成員會靜默失敗)
5. Swift 類別只要暴露給 ObjC 就能直接 swizzle(`_TtC<bundle><len><Name>`)
6. 補發事件必須 in-flight 去重 + 完成時清旗標,否則「按一次跑兩輪」
7. `objc_msgSend` 轉型必須與簽章完全一致(否則 SIGABRT)
8. 不要在 hook 裡碰 UIKit;診斷走 NSLog + 檔案 + UDP beacon
9. 不用 `mprotect(RWX)`;`__BSS` 位址 fileoff = 0
10. `LC_LOAD_DYLIB` 不能放相對路徑
11. 不可把 `.o` 改 filetype 當 dylib 交付
12. 一次只注入一個 dylib

## 編譯 iOS dylib(在 macOS,只需 Command Line Tools)

```bash
clang -arch arm64 -dynamiclib -fobjc-arc -target arm64-apple-ios14.0 \
  -isysroot $SDK -isystem /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk/usr/include \
  -Wl,-undefined,dynamic_lookup -L $SDK/usr/lib -lSystem -o OUT.dylib SRC.m
install_name_tool -id "@executable_path/Frameworks/OUT.dylib" OUT.dylib
codesign -f -s - OUT.dylib
otool -l OUT.dylib | grep -A3 LC_BUILD_VERSION   # platform 2 = iOS
```

社群 iPhoneOS SDK 需先修 `.tbd` 裡的 `arm64e.x1-ios` 架構字串 → 見 `memory/EXPERIENCE.md`。

## 免責

僅供自有裝置、自有 App 的相容性研究與學習用途。
