# 開發期崩潰處理(6-0 範本)

> 規則:**開發/驗證階段的每個 dylib 都必須掛 crash handler;功能跑通、連續幾輪不閃退之後,拿掉再編最終版。**

## 為什麼要自帶

* `.ips` 只在「真的閃退」時才有;App 被系統殺、或 dylib 根本沒載入時,完全沒有證據。
* beacon 需要筆電在線;自帶 handler 把死因**寫進 App 容器**,下次啟動自動 beacon 出來 —— 連 Mac 不在旁邊都拿得到。
* 開發期最常見的三種死因(ABI 不符的 `objc_msgSend`、swizzle 到不存在的方法、`orig` 指向自己造成遞迴)都會在這個記錄裡一眼看到。

## 程式碼(直接貼進 dylib)

```objc
#include <execinfo.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static char g_crashpath[512];
static const char *ag_crash_path(void) {
    if (!g_crashpath[0]) {
        const char *t = getenv("TMPDIR"); if (!t) t = "/tmp";
        snprintf(g_crashpath, sizeof(g_crashpath), "%s/adgate_crash.log", t);
    }
    return g_crashpath;
}
static void ag_crash_append(const char *s, size_t n) {
    int fd = open(ag_crash_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return; write(fd, s, n); close(fd);
}

static void ag_signal_handler(int sig) {
    char hdr[64];
    int n = snprintf(hdr, sizeof(hdr), "\n=== SIGNAL %d ===\n", sig);
    if (n > (int)sizeof(hdr)) n = (int)sizeof(hdr);
    ag_crash_append(hdr, (size_t)n);
    int fd = open(ag_crash_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { void *bt[64]; int c = backtrace(bt, 64); backtrace_symbols_fd(bt, c, fd); close(fd); }
    signal(sig, SIG_DFL); raise(sig);          // 保留原本的崩潰行為
}

static void ag_exception_handler(NSException *e) {
    NSString *rep = [NSString stringWithFormat:@"\n=== OBJC EXCEPTION %@: %@ ===\n%@\n",
                     e.name, e.reason, e.callStackSymbols];
    const char *u = rep.UTF8String; if (u) ag_crash_append(u, strlen(u));
}

static void ag_crash_install(void) {
    NSSetUncaughtExceptionHandler(&ag_exception_handler);
    int sigs[] = {SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) signal(sigs[i], ag_signal_handler);
}

static void ag_crash_flush(void) {             // 啟動時把上次的死因送出來
    const char *p = ag_crash_path();
    int fd = open(p, O_RDONLY); if (fd < 0) return;
    char buf[1024]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        char line[1100]; int m = snprintf(line, sizeof(line), "CRASHLOG> %.*s", (int)n, buf);
        if (m > 0) ag_beacon(line);
    }
    close(fd); unlink(p);                      // 送過就刪,避免重複回報
}
```

## 掛在哪

```objc
static void ag_install(void) {
    static BOOL done = NO; if (done) return; done = YES;
    ag_crash_flush();        // 先把「上一次」的死因送出去
    ag_crash_install();      // 再掛上處理器
    /* ... 你的 swizzle ... */
}
```

## 讀回來的樣子

```
CRASHLOG> === OBJC EXCEPTION NSInvalidArgumentException: -[UIAlertController xxx]: unrecognized selector ===
CRASHLOG> === SIGNAL 11 ===
0   adgatedylib_v13_ios.dylib  0x0000000000002d10 ag_show_alert + 96
```

frame 有你的 dylib 名 + offset + 函式名 → 直接反組譯那個 offset 就知道哪一行。

## 交付前必做

1. 刪掉 `ag_crash_flush();` 與 `ag_crash_install();` 兩個呼叫(函式留著沒關係)。
2. 重新編譯 → `install_name_tool -id` → `codesign -f -s -`(只為可載入)。
3. **重新算 sha256** 並回報「路徑 + bytes + sha256」。
4. 別忘了只注入一個 dylib。

## 注意

* signal handler 內只能用 async-signal-safe 的東西(`open`/`write`/`close`/`backtrace_symbols_fd`/`signal`/`raise`);**不要**碰 Foundation / NSString / NSLog(會死鎖)。
* `snprintf` 嚴格說不在 async-signal-safe 清單,實務可用;要更保守就先填固定 header 再 `write`。
* ObjC 例外常式沒有這個限制,可以自由用 `e.callStackSymbols`。
* 這東西會改變崩潰行為,別留在最終交付版。

## beacon 到底什麼情況下回得來

| 前提 | 說明 |
|---|---|
| 同一網段 | UDP 打到寫死的私有 IP → **手機和接收端必須在同一個 LAN**(同一個 Wi-Fi)。手機走 4G/5G、筆電在家 → 送不出去。手機不需要外網 |
| 接收端開著 | `nc -u -l 9999` 綁 `0.0.0.0`。UDP 沒人聽也回成功 → **永遠無法從 App 端得知有沒有送到** |
| iOS 區域網路權限 | iOS 14+ 需要授權:設定 → 隱私權與安全性 → 區域網路;自己重打包的 IPA 要有 `NSLocalNetworkUsageDescription` |
| 接收端防火牆 | macOS 應用程式防火牆「封鎖所有連入」會讓 `nc` 收不到 |
| 別只寫死一個 IP | DHCP 一換就斷;同時打候選清單 + `<subnet>.255` 廣播 |
| App 在前景 | 被掛起就不送 |

不在同一個 LAN 的替代:① USB `log collect` + `strings`(最穩、不需網路)② 公開端點 `POST https://…`(行動網路也通,注意 ATS)③ 把 payload 塞進 `NSException.reason` 再從 `.ips` 撈回。

**原則:檔案是真相,beacon 是盡力送。**
