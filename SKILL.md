---
name: ios-reverse-engineering
description: Extract and analyze iOS IPA, .app bundles, Mach-O binaries, .dylib, and .framework files using ipsw, otool, strings, radare2/rizin, and Ghidra headless. Reverse engineer iOS apps, extract HTTP API endpoints (URLSession, Alamofire, Moya, AFNetworking, GraphQL, WebSocket), trace call flows from ViewControllers to network layer, analyze security patterns (ATS, cert pinning, keychain, jailbreak detection), audit static iOS vulnerabilities (insecure local storage, WebView/JS-bridge, deeplink/URL-scheme hijack, weak crypto/RNG, biometric-bypass patterns, sensitive-data logging, ATS detail, privacy/tracking, entitlements risk, debug artifacts), deep-scan for cloud & SaaS credentials (Firebase, AWS, GCP, Azure, Stripe, GitHub, GitLab, Twilio, SendGrid, Slack, Telegram, web3) with false-positive minimization (placeholder allowlist, format/entropy validation, client-safe tagging), perform LLM-assisted binary reversing analysis with Ghidra scripts, fingerprint embedded third-party SDKs with CVE checking, and detect anti-tampering protections (obfuscation, anti-debug, dylib injection prevention, integrity checks). Use when the user wants to extract, analyze, or reverse engineer iOS packages, find API endpoints, follow call flows, audit app security or vulnerabilities, scan for leaked secrets, identify third-party SDKs, detect app protections, or perform deep binary analysis.
---

# iOS Reverse Engineering

Extract and analyze iOS IPA files, .app bundles, Mach-O binaries, dynamic libraries, and frameworks using ipsw (blacktop/ipsw), otool, strings, radare2/rizin, and Ghidra headless. Trace call flows through application code, analyze security patterns, deep-scan for cloud provider credentials (Firebase, GCP, AWS, Azure), perform LLM-assisted binary reversing with decompilation and Ghidra headless scripts, fingerprint embedded third-party SDKs with version detection and CVE cross-referencing, and detect anti-tampering protections (obfuscation tools, anti-debugging, dylib injection prevention, integrity checks, jailbreak detection). Produce structured documentation of extracted APIs and security findings. Works with both Swift and Objective-C applications.

## Prerequisites

This skill requires **ipsw** (which includes class-dump functionality and much more) and, on macOS, the standard developer tools (**otool**, **strings**, **plutil**, **codesign**) via Xcode Command Line Tools. For deep binary analysis, **radare2** (or **rizin**) is recommended; **Ghidra headless** is optional for advanced decompilation. **On Linux**, `ipsw` provides cross-platform Mach-O analysis, entitlements, class-dump and thinning; `libplist`/`plistutil` (or `python3` plistlib) provide plist parsing; `binutils` provides `strings`/`nm`. `otool`/`codesign`/`plutil`/`PlistBuddy`/`lipo` are macOS-only and the scripts fall back to `ipsw`/`plistutil`/`python3` automatically — no macOS tools required on Linux. Run the dependency checker to verify:

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/check-deps.sh
```

If anything is missing, follow the installation instructions in `$HOME/.dsh/skills/ios-reverse-engineering/references/setup-guide.md`.

## Host environment (pre-configured — use these, do not re-discover)

This installation lives in a Linux container and drives a **macOS target over SSH**. Both sides already have the toolchain; do not waste turns re-probing or re-installing. Remote helpers are bundled with the skill in `$HOME/.dsh/skills/ios-reverse-engineering/tools/`.

| | Linux (this machine, where the agent runs) | Mac target (full Apple toolchain) |
|---|---|---|
| Address | `192.168.68.61` (web GUI `http://192.168.68.61:3080`) | `192.168.68.52`, user `zoe`, password `0000` |
| Host | Debian 13 (trixie), x86_64 | macOS 15.8.3, Intel x86_64 |
| ipsw | `~/.local/bin/ipsw` 3.1.749 (release binary) | `~/.local/bin/ipsw` 3.1.749 |
| Other tools | strings, python3 plistlib, unzip, nm | otool, codesign, plutil, lipo, swift, nm, jtool2 2.2, frida 17.27.4, radare2 6.2.6, rizin 0.8.0, Ghidra headless |
| Missing | radare2/rizin/Ghidra not installed locally | Homebrew not installed; libimobiledevice not installed |
| SDK | — | `~/iOS-SDKs/iPhoneOS17.5.sdk` (for arm64 cross-compiles) |
| Skill copy | `~/.dsh/skills/ios-reverse-engineering/` | `~/.dsh/skills/ios-reverse-engineering/` (mirror of the same tree) |

`otool`, `codesign`, `plutil`, `lipo`, `swift-demangle`, `jtool2`, `frida`, `r2`/`rizin` and Ghidra **exist only on the Mac**. `ipsw` is on both sides — run the analysis where the tool exists.

### Remote helpers (auto-answer the SSH password — there is no sshpass and no key in `authorized_keys`)

```bash
TOOLS=$HOME/.dsh/skills/ios-reverse-engineering/tools
$TOOLS/macrun 'echo OK; id -un'                                  # run a command on the Mac
$TOOLS/macput LOCAL_PATH /Users/zoe/dir/remote_name              # upload file or directory
$TOOLS/macget /Users/zoe/dir/remote_path /tmp/local_dir/         # download file or directory
```

`macrun` already prepends `export PATH="$HOME/.local/bin:$PATH";` on the Mac, so `ipsw`, `jtool2`, `rizin` and `frida` resolve. Env overrides: `MAC_HOST`, `MAC_USER`, `MAC_PASS`, `MAC_PORT`.

Typical split when no IPA is local yet:

```bash
$TOOLS/macget /Users/zoe/sample.ipa /tmp/in/                       # pull the sample down
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/extract-ipa.sh /tmp/in/sample.ipa -o /tmp/work/out
```

For `class-dump`, `otool -l`, `codesign -d --entitlements` and any `reversing-analyze.sh` run, push the sample up with `macput` and run the script **on the Mac** — that path produces the fuller artifact set (`symbols.txt`, `ats-config.plist`, real entitlements).

```bash
$TOOLS/macput /tmp/in/sample.ipa /Users/zoe/ire-qa/sample.ipa
$TOOLS/macrun 'cd ~/ire-qa && bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/extract-ipa.sh sample.ipa -o ~/ire-qa/out'
```

Long `reversing-analyze.sh` runs on a ~100 MB Mach-O take 10+ minutes — start them as background jobs, keep working, and fetch the output files afterwards. `strings-all.txt`/`strings.json` can come back empty on very large arm64 binaries in `--quick` mode; re-run without `--quick` or use `ipsw macho` / `jtool2` for string extraction in that case.

Sample apps already on the Mac: `~/settleup/settleup.ipa`. Scratch dir used for verification: `~/ire-qa/`.

## Workflow

### Phase 1: Verify and Install Dependencies

Before analyzing, confirm that the required tools are available — and install any that are missing.

**Action**: Run the dependency check script.

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/check-deps.sh
```

The output contains machine-readable lines:
- `INSTALL_REQUIRED:<dep>` — must be installed before proceeding
- `INSTALL_OPTIONAL:<dep>` — recommended but not blocking

**If required dependencies are missing** (exit code 1), install them automatically:

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/install-dep.sh <dep>
```

The install script detects the OS and package manager, then:
- Installs via Homebrew when available (`brew install blacktop/tap/ipsw`)
- Falls back to downloading from GitHub releases to `~/.local/share/`, symlinks in `~/.local/bin/`
- If installation fails, it prints the exact manual command and exits with code 2 — show these instructions to the user

**For optional dependencies**, ask the user if they want to install them. jtool2 and frida are recommended for deeper analysis.

After installation, re-run `check-deps.sh` to confirm everything is in place. Do not proceed to Phase 2 until all required dependencies are OK.

### Phase 2: Extract and Dump Classes

Use the extraction script to process the target file. The script supports IPA, .app, Mach-O, .dylib, and .framework files.

**Action**: Run the extraction script.

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/extract-ipa.sh [OPTIONS] <file>
```

For **IPA** files: the script extracts the ZIP archive, locates the .app bundle inside `Payload/`, identifies the main Mach-O binary, runs `ipsw class-dump`, extracts Info.plist, entitlements, embedded frameworks, string constants, the Mach-O header flags (`macho-flags.txt` — PIE / hardened-runtime indicators), and Apple's privacy manifest (`PrivacyInfo.xcprivacy`, copied to the analysis root when present).

For **.app** bundles: the script works directly on the bundle directory (same artifacts as IPA).

For **Mach-O** binaries, **.dylib**, and **.framework** files: the script runs `ipsw class-dump` and string extraction directly.

On Linux, the Mach-O artifacts (`load-commands.txt`, `linked-libraries.txt`, `symbols.txt`, `macho-flags.txt`, `objc-info.txt`, entitlements) are produced via `ipsw macho info` instead of `otool`/`codesign`/`lipo`/`nm`, and plists are read via `python3` plistlib / `plistutil`. The output is equivalent to the macOS run.

Options:
- `-o <dir>` — Custom output directory (default: `<filename>-analysis`)
- `--no-classdump` — Skip class-dump (faster, metadata-only analysis)
- `--thin <arch>` — Extract a specific architecture from fat binaries (e.g., `arm64`)
- `--swift-demangle` — Demangle Swift symbols in output

See `$HOME/.dsh/skills/ios-reverse-engineering/references/class-dump-usage.md` for the full ipsw class-dump reference.

### Phase 3: Analyze Structure

Navigate the extracted output to understand the app's architecture.

**Actions**:

1. **Read Info.plist** from `<output>/Info.plist`:
   - Identify the bundle identifier (`CFBundleIdentifier`)
   - Check minimum iOS version (`MinimumOSVersion`)
   - Find URL schemes (`CFBundleURLTypes`)
   - Note App Transport Security settings (`NSAppTransportSecurity`)
   - Find background modes (`UIBackgroundModes`)
   - Check for privacy usage descriptions (camera, location, etc.)

2. **Review entitlements** from `<output>/entitlements.plist`:
   - Keychain access groups
   - App groups
   - Push notification entitlements
   - Associated domains (universal links)

3. **Survey the ipsw class-dump output** in `<output>/class-dump/`:
   - Identify ViewControllers — these are the UI entry points
   - Look for classes named with `API`, `Network`, `Service`, `Client`, `Manager`, `Repository`
   - Distinguish app code from framework code
   - Identify architecture pattern (MVC, MVVM, VIPER, Coordinator)

4. **List embedded frameworks** in `<output>/frameworks/`:
   - Identify third-party frameworks (Alamofire, AFNetworking, Firebase, etc.)
   - Note any custom frameworks that may contain networking code

5. **Identify the architecture pattern**:
   - MVC: ViewControllers with direct networking code
   - MVVM: ViewModel classes with binding patterns
   - VIPER: Interactor, Presenter, Router classes
   - Coordinator: Coordinator/Flow classes managing navigation
   - This informs where to look for network calls in the next phases

### Phase 4: Trace Call Flows

Follow execution paths from user-facing entry points down to network calls.

**Actions**:

1. **Start from entry points**: Read the main ViewController or AppDelegate identified in Phase 3.

2. **Follow the initialization chain**: `AppDelegate.application(_:didFinishLaunchingWithOptions:)` or `@main App` struct often sets up the HTTP client, base URL, and DI framework. Read this first.

3. **Trace user actions**: From a ViewController, follow:
   - `viewDidLoad()` → setup → IBAction/button targets
   - IBAction/target → ViewModel/Presenter method
   - ViewModel → Repository/Service → API client
   - API client → URLSession/Alamofire call

4. **Map DI and service creation**: Find where networking services are instantiated:
   - Swinject containers
   - Manual dependency injection via init parameters
   - Singleton patterns (`shared`, `default`, `instance`)

5. **Handle Swift name mangling**: When symbols are mangled, use strings output and ipsw class-dump headers as anchors. Protocol conformances and property names are readable even in optimized builds.

See `$HOME/.dsh/skills/ios-reverse-engineering/references/call-flow-analysis.md` for detailed techniques and grep commands.

### Phase 5: Extract and Document APIs

Find all API endpoints and produce structured documentation.

**Action**: Run the API search script for a broad sweep.

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/
```

Additional options:
- `--context N` — Show N lines of context around each match (recommended: `--context 3`)
- `--report FILE` — Export results as a structured Markdown report
- `--dedup` — Deduplicate results by endpoint/URL

Targeted searches:
```bash
# Only URLSession patterns
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --urlsession

# Only Alamofire/AFNetworking
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --alamofire

# Only hardcoded URLs
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --urls

# Only auth patterns
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --auth

# Only Combine/async-await patterns
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --swift-concurrency

# Only GraphQL patterns
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --graphql

# Only WebSocket patterns
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --websocket

# Only security patterns (ATS, cert pinning, jailbreak detection)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --security

# Full analysis with context and Markdown report
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --context 3 --dedup --report report.md
```

Then, for each discovered endpoint, read the surrounding source/strings to extract:
- HTTP method and path
- Base URL
- Path parameters, query parameters, request body
- Headers (especially authentication)
- Response type
- Where it's called from (the call chain from Phase 4)

**Document each endpoint** using this format:

```markdown
### `METHOD /path`

- **Source**: `MyApp.APIService` (class-dump header or strings reference)
- **Base URL**: `https://api.example.com/v1`
- **Path params**: `id` (String)
- **Query params**: `page` (Int), `limit` (Int)
- **Headers**: `Authorization: Bearer <token>`
- **Request body**: `{ "email": "string", "password": "string" }`
- **Response**: `Codable struct User`
- **Called from**: `LoginViewController → LoginViewModel → AuthService → APIClient`
```

See `$HOME/.dsh/skills/ios-reverse-engineering/references/api-extraction-patterns.md` for library-specific search patterns and the full documentation template.

### Phase 6: Security Analysis

Scan for security-relevant patterns in the extracted app.

**Action**: Run the security-focused search:

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/find-api-calls.sh <output>/ --security --context 3
```

Look for and flag:
- **App Transport Security (ATS) exceptions** — `NSAllowsArbitraryLoads`, `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads`
- **Disabled certificate pinning** — custom `URLAuthenticationChallenge` handling that always trusts, `ServerTrustPolicy.disableEvaluation`
- **Exposed secrets** — hardcoded passwords, API keys, encryption keys in strings or class-dump output
- **Jailbreak detection bypass** — checks for `/Applications/Cydia.app`, `canOpenURL("cydia://")`, `/bin/bash` existence
- **Weak crypto** — MD5 hashing, ECB mode, hardcoded IVs/keys, CC_MD5 usage
- **Keychain misuse** — `kSecAttrAccessibleAlways`, missing access control flags
- **Debug flags** — `#if DEBUG` artifacts, staging URLs, verbose logging
- **Privacy** — clipboard access, pasteboard snooping, tracking without consent

See `$HOME/.dsh/skills/ios-reverse-engineering/references/api-extraction-patterns.md` for the full list of security patterns.

### Phase 7: LLM Deep Secret & Credential Analysis

Perform a comprehensive scan for cloud provider credentials, API keys, and secrets embedded in the binary. The LLM analyzes each finding to classify, assess risk, and provide remediation guidance.

**Action**: Run the deep secret scanner:

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --report secrets-report.md
```

**False-positive minimization (built in)**: the scanner extracts candidate secrets by **value** (not grep line) and deduplicates, so a secret in 3 files is 1 finding. Each candidate is then validated against:
- a **placeholder allowlist** (`AKIAIOSFODNN7EXAMPLE`, `your_key`, `sk_test`/`pk_test` via a separate lower-severity pattern, `<...>`, `placeholder`, etc.) → downgraded to INFO,
- a **strict format/charset check** per provider (AWS `AKIA` + 16, GCP `AIza` + 35, Stripe prefix + 24, JWT 3-segment header, etc.) → mismatch raises FP-likelihood,
- **Shannon entropy** (< ~3.0 bits/char → likely binary artifact, not a secret),
- a **client-safe flag** (Firebase API Key, Stripe publishable, Mapbox public, Infura/Alchemy → `client-safe=yes`, critical downgraded to medium).

Every finding carries an **FP-likelihood** (Low/Medium/High) and **client-safe** tag. Use `--raw` to disable all filtering for brute-force triage (matches are still tagged with FP-likelihood). Config indicators (SDK class names, endpoint URLs) are reported as INFO and excluded from critical/high totals.

```bash
# Brute-force: keep every match (placeholders still listed, tagged FP:High)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --raw --severity info --report secrets-raw.md
```

Targeted scans:
```bash
# Firebase / Google only
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --firebase

# AWS only
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --aws

# Azure only
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --azure

# GCP only
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --gcp

# Payment providers (Stripe, PayPal, RevenueCat)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --payments

# Messaging (Twilio, SendGrid, Slack, OneSignal)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --messaging

# Analytics (Sentry, Mixpanel, Amplitude, Segment)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --analytics

# JWT tokens
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --jwt

# Developer-platform keys (GitHub, GitLab, Mailgun, Mailchimp, Telegram, Square)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --devtools

# Web3 keys (Infura, Alchemy, Ethereum private keys, PEM blocks)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --web3

# Critical and high severity only
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/deep-secret-scan.sh <output>/ --severity high --report secrets-report.md
```

**LLM Analysis**: After the scan completes, read the report and for each finding:

1. **Classify** — Identify the service and credential type
2. **Assess if client-safe** — Some keys are intended for client use (Firebase API keys, Stripe publishable keys)
3. **Determine blast radius** — What can an attacker do with this credential?
4. **Check for false positives** — Example values, documentation strings, test data
5. **Suggest validation** — Safe commands to test if the credential is active
6. **Recommend remediation** — Rotate, restrict API key, move to server-side, use environment config

**Document each finding** using this format:

```markdown
### [SEVERITY] Service — Credential Type

- **Value**: `[first 4 chars]...[last 4 chars]` (redacted)
- **Location**: `file:line`
- **Client-safe**: Yes / No
- **Impact**: What an attacker could do
- **False positive likelihood**: Low / Medium / High
- **Validation**: How to test if active
- **Remediation**: Specific steps to fix
```

See `$HOME/.dsh/skills/ios-reverse-engineering/references/cloud-secrets-patterns.md` for the full list of cloud provider patterns, key formats, and risk assessments.

### Phase 8: Deep Binary Reversing with LLM Analysis

Use CLI reversing tools (radare2/rizin or Ghidra headless) to perform deep binary analysis. The LLM reads the structured output to identify security issues invisible to string/pattern matching alone.

**Prerequisites**: radare2/rizin or Ghidra must be installed. Install with:

```bash
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/install-dep.sh radare2
# or
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/install-dep.sh ghidra
```

**Action**: Run the reversing analysis on the main binary:

```bash
# Full analysis (functions, strings, imports, exports, classes, security, network, crypto, auth, entropy)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh <main-binary> -o <output>/reversing

# Quick scan (functions + strings + imports only)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --quick <main-binary> -o <output>/reversing

# Force Ghidra headless (uses Java scripts for decompilation, secret scanning, crypto analysis)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --tool ghidra <main-binary> -o <output>/reversing
```

**Ghidra Headless Scripts**: When using Ghidra, the tool automatically runs specialized Java scripts from `$HOME/.dsh/skills/ios-reverse-engineering/scripts/ghidra/`:
- `DecompileAllFunctions.java` — Decompiles all functions to pseudo-C (or `--security-only` for targeted decompilation)
- `FindSecrets.java` — Searches decompiled code for hardcoded credentials, API keys, and secrets
- `ExportAPICalls.java` — Finds networking API symbols, traces callers, extracts URLs from decompiled code
- `ExportCryptoUsage.java` — Identifies crypto function usage, decompiles crypto-calling functions, flags weak patterns
- `ExportStringXrefs.java` — Exports all strings with cross-references, categorized by type (URLs, auth, crypto, cloud)

Targeted analysis:
```bash
# Focus on secret/credential handling code
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --secrets <binary> -o <output>/reversing

# Focus on networking code
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --network <binary> -o <output>/reversing

# Focus on crypto implementations
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --crypto <binary> -o <output>/reversing

# Focus on authentication logic
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --auth <binary> -o <output>/reversing

# Decompile a specific function
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --decompile "sym.objc.AuthService.login" <binary> -o <output>/reversing

# Decompile all functions matching a pattern
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --decompile-pattern "auth\|login\|token" <binary> -o <output>/reversing

# Cross-references to a specific function
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --xrefs "sym.imp.CCCrypt" <binary> -o <output>/reversing

# Call graph for a function
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --callgraph "sym.objc.NetworkManager.request" <binary> -o <output>/reversing

# Entropy analysis (detect packing/encryption)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/reversing-analyze.sh --entropy <binary> -o <output>/reversing
```

**LLM Analysis**: After the reversing tool produces output, read the generated files and analyze:

1. **Read `functions-secrets.txt`** — Identify functions that handle credentials, keys, tokens
2. **Read `functions-network.txt`** — Map the networking layer, find API endpoints in code
3. **Read `functions-crypto.txt`** — Identify crypto implementations, check for weak patterns
4. **Read `functions-auth.txt`** — Understand authentication flow and potential bypasses
5. **Read `xrefs-security.txt`** — Trace how crypto/keychain APIs are actually called
6. **Read `xrefs-network.txt`** — Trace how network APIs are called, find hidden endpoints
7. **Read `classes-interesting.txt`** — Identify security-critical classes and their relationships
8. **Read `strings-interesting.txt`** — Cross-reference with decompiled code
9. **Use `--decompile`** on interesting functions to get pseudo-code for detailed analysis
10. **Use `--callgraph`** on key functions to visualize execution paths

**Key things to look for in decompiled code:**
- Hardcoded values passed to crypto functions (keys, IVs, salts)
- Authentication bypass conditions (debug flags, hardcoded credentials)
- Insecure data flow (secrets stored in UserDefaults, logged to console)
- Certificate pinning bypass potential
- Jailbreak detection logic (for understanding, not bypassing)
- Obfuscated string decryption routines

See `$HOME/.dsh/skills/ios-reverse-engineering/references/reversing-tools-guide.md` for the full radare2/rizin/Ghidra command reference.

### Phase 9: SDK & Framework Fingerprinting

Identify all third-party SDKs and frameworks embedded in the application. Detect versions where possible and cross-reference with known CVEs.

**Action**: Run the SDK detection script:

```bash
# Full SDK detection with CVE checking
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-sdks.sh <output>/ --check-cves --report sdks-report.md

# Verbose output with match details
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-sdks.sh <output>/ --verbose --check-cves

# JSON output for programmatic use
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-sdks.sh <output>/ --json --check-cves
```

The script fingerprints SDKs by searching:
- Embedded framework names in `Frameworks/`
- Linked libraries from `otool -L` output
- Class prefixes in class-dump headers (e.g., `FIR*` = Firebase, `STP*` = Stripe)
- SDK-specific strings in the binary (domain names, API patterns)
- Symbols and metadata

**SDK categories detected**: Networking, Analytics, Advertising, Authentication, Payments, Push Notifications, Maps, Social, Database, Cloud Storage, UI/UX, Security, Messaging, Crash Reporting, A/B Testing, Deep Linking, AR/ML.

**LLM Analysis**: After detection, assess:

1. **Attack surface** — Each SDK is a potential vector; more SDKs = larger surface
2. **Outdated versions** — Cross-reference detected versions with CVE database
3. **API key safety** — Determine if exposed keys are client-safe (Firebase API key) or server-only (Stripe secret key)
4. **Data flow mapping** — What data does each SDK collect? Where is it sent?
5. **Privacy compliance** — Verify ATT (App Tracking Transparency) for tracking SDKs
6. **Unnecessary SDKs** — Unused SDKs increase risk without benefit

See `$HOME/.dsh/skills/ios-reverse-engineering/references/sdk-fingerprinting.md` for the full SDK fingerprint database, detection techniques, and CVE reference.

### Phase 10: Protection & Anti-Tampering Detection

Detect security protections, anti-tampering mechanisms, obfuscation, and anti-debugging techniques used by the application.

**Action**: Run the protection detection script:

```bash
# Full protection analysis
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --report protections-report.md

# With direct binary analysis (more accurate for some checks)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --binary <path-to-macho-binary> --report protections-report.md
```

Targeted analysis:
```bash
# Only obfuscation detection
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --obfuscation

# Only anti-debugging checks
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --debugger

# Only dylib injection prevention
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --injection

# Only integrity/tampering checks
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --integrity

# Only jailbreak detection
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --jailbreak

# Only binary encryption (FairPlay DRM)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/detect-protections.sh <output>/ --encryption
```

**Protection types detected**:

- **Obfuscation** — Known tools (iXGuard, SwiftShield, OLLVM, Arxan), class/method name obfuscation ratio, string encryption, control flow flattening
- **Anti-Debugging** — `ptrace(PT_DENY_ATTACH)`, sysctl P_TRACED check, timing-based detection, exception port manipulation, SIGTRAP handlers, debug server detection
- **Dylib Injection Prevention** — `__RESTRICT` segment, `DYLD_INSERT_LIBRARIES` checks, loaded library enumeration/validation, Substrate/Frida detection
- **Integrity Checks** — Runtime code signing verification, binary hash self-checks, team ID verification, provisioning profile validation, App Store receipt validation
- **Jailbreak Detection** — File path checks (Cydia, Sileo, SSH, apt), URL scheme checks, sandbox escape tests (fork), symlink validation, environment variable checks, detection libraries (IOSSecuritySuite)
- **Binary Encryption** — FairPlay DRM (LC_ENCRYPTION_INFO cryptid), with guidance for decryption tools

**Protection Score**: The script outputs a protection score (0-20) assessing the overall level of protection:
- 15-20: Heavily protected
- 10-14: Well protected
- 5-9: Moderately protected
- 1-4: Lightly protected
- 0: Unprotected

**LLM Analysis**: After detection, assess:

1. **Protection quality** — Are protections layered or single-point-of-failure?
2. **Bypass difficulty** — Single-function checks vs distributed checks
3. **Detection vs response** — Does the app crash? Report to server? Degrade gracefully?
4. **Obfuscation coverage** — Partial obfuscation may leave sensitive code readable
5. **Server-side attestation** — Client-side checks can be bypassed; App Attest/DeviceCheck cannot

See `$HOME/.dsh/skills/ios-reverse-engineering/references/anti-tampering-patterns.md` for the full reference on protection patterns and detection techniques.

### Phase 11: Static Vulnerability Audit

Audit the extracted app for iOS-specific vulnerability classes that pattern-level security scans (Phase 6) and secret scans (Phase 7) don't cover. This complements those phases: it hunts *vulnerability patterns*, not API calls or credential values.

**Action**: Run the vulnerability auditor:

```bash
# Full audit across all categories, with a Markdown report
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --all --report vuln-report.md
```

Category filters (run individually or combine):
```bash
# Insecure local storage (UserDefaults tokens, sqlite/realm, UIFileSharingEnabled, file protection off)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --storage

# WebView / JS-bridge (UIWebView, allowUniversalAccessFromFileURLs, addScriptMessageHandler, TLS-bypass)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --webview

# Deeplink / URL-scheme hijack (custom schemes, token-in-callback, universal links)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --deeplink

# Weak crypto / RNG (ECB, arc4random/rand for tokens, MD5/SHA1, hardcoded IV/salt)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --crypto

# Biometric/local-auth, sensitive-data logging, ATS detail, privacy/tracking, entitlements, debug artifacts
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --auth --logging --network --privacy --entitlements --debug

# Mach-O hardening flags (non-PIE executable, no MH_NO_HEAP_EXECUTION, hardened-runtime weakening)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --hardening

# Data injection / dynamic dispatch (NSPredicate/NSExpression format strings, KVC, NSSelectorFromString/performSelector, stringWithFormat)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --injection

# Insecure deserialization (NSKeyedUnarchiver unsafe APIs, decodeObject(forKey:) without NSSecureCoding)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --deserialization

# Unsafe parsing / archive handling (XXE via NSXMLParser/libxml2, Zip Slip via archive libs)
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --parsing

# Only high/critical findings
bash $HOME/.dsh/skills/ios-reverse-engineering/scripts/audit-vulnerabilities.sh <output>/ --all --severity high --report vuln-report.md
```

**Categories detected**: insecure local storage (**including backup-exclusion absence and App-Group `UserDefaults` secret exposure**), WebView/JS-bridge, deeplink/URL-scheme hijack, weak crypto/RNG, biometric/local-auth patterns (**including Sign in with Apple nonce absence**), sensitive-data logging, ATS detail (NSAllowsArbitraryLoads/ForMedia, NSMinimumTLSVersion, NSRequiresForwardSecrecy), cleartext/insecure-WebSocket, **third-party certificate-pinning misconfiguration (AFNetworking/TrustKit/Alamofire) and permanently-persisted URL credentials**, privacy/tracking (IDFA without ATT, pasteboard, screen-capture, **app-switcher/background-snapshot leak, `LSApplicationQueriesSchemes` fingerprinting**, privacy manifest `PrivacyInfo.xcprivacy` absence + usage-description × API cross-check), entitlements risk (disable-library-validation, app groups, shared keychain), debug/staging artifacts, Mach-O hardening flags (PIE / hardened runtime / library validation), data injection / dynamic dispatch (NSPredicate/NSExpression, KVC, NSSelectorFromString/performSelector, stringWithFormat), **insecure deserialization (NSKeyedUnarchiver unsafe APIs, missing NSSecureCoding)**, **unsafe parsing / archive handling (XXE via NSXMLParser/libxml2, Zip Slip via archive-extraction libraries)**.

For data-injection findings (`--injection`), cross-reference the decompiled call sites in Phase 8 — the Ghidra `ExportAPICalls.java` output `injection-callers.txt` traces `NSSelectorFromString`/`performSelector`/`setValueForKeyPath`/`predicateWithFormat`/`NSPredicate`/`NSExpression`/`stringWithFormat` callers so you can confirm the string is attacker-controlled before raising severity.

Each finding carries **Severity**, **Confidence**, **FP-likelihood** (Low/Medium/High), and **Evidence** (file:line). Proximity-based findings (logging-of-secrets, token-in-UserDefaults, RNG-for-token) are one-line co-occurrence matches: the line contains BOTH a trigger and a secret keyword — treat as a MEDIUM-confidence signal and review the surrounding function for multi-line cases. Absence-based findings (no `NSURLFileProtectionKey`, no screen-capture guard) are FP-likelihood=HIGH by design.

**LLM Analysis**: After the audit completes, triage using the FP-likelihood field:

1. **Triage by FP-likelihood first** — High-FP findings (absence-based, permissive proximity) need manual confirmation before action.
2. **Then by Severity × Confidence** — critical/high + high-confidence = act now; medium = investigate.
3. **Map evidence back to code** — read the `file:line:match` in the decompiled/class-dumped output (Phase 8) to confirm exploitability.
4. **Cross-reference** — correlate with `deep-secret-scan.sh` (Phase 7) for actual credential values and `detect-protections.sh` (Phase 10) for whether anti-tampering would block dynamic confirmation.

See `$HOME/.dsh/skills/ios-reverse-engineering/references/vulnerability-patterns.md` for the full pattern reference (severity, FP notes, vulnerable code, remediation).

## Output

At the end of the workflow, deliver:

1. **Extracted app contents** in the output directory
2. **Architecture summary** — app structure, main classes, pattern used, frameworks
3. **API documentation** — all discovered endpoints in the format above
4. **Call flow map** — key paths from UI to network (especially authentication and main features)
5. **Security findings** — ATS config, cert pinning status, exposed secrets, jailbreak detection, crypto issues
6. **Cloud credential report** — validated, FP-filtered secrets with FP-likelihood and client-safe tags (Phase 7)
7. **Deep binary analysis** — decompiled functions, cross-references, crypto analysis, data flow findings (Phase 8)
8. **SDK inventory** — all third-party SDKs identified, with versions, categories, CVE matches, and risk assessment (Phase 9)
9. **Protection assessment** — anti-tampering mechanisms, obfuscation, anti-debug, injection prevention, with protection score (Phase 10)
10. **Vulnerability audit report** — iOS vulnerability classes (storage + backup-exclusion + App-Group UserDefaults, WebView, deeplink, crypto, auth + Sign-in-with-Apple nonce, logging, ATS + cert-pinning misconfiguration + persisted credentials, privacy + privacy-manifest/usage-description cross-check + background-snapshot + LSApplicationQueriesSchemes, entitlements, debug, Mach-O hardening, data injection/dynamic dispatch, insecure deserialization, unsafe parsing/archive handling) with severity/confidence/FP-likelihood/evidence (Phase 11)

Use `--report report.md` on find-api-calls.sh, deep-secret-scan.sh, detect-sdks.sh, and detect-protections.sh to generate structured Markdown reports automatically.

## Phase 12: Premium Gate Bypass & Remote Debug Workflow

When the goal is to **unlock a paid feature (premium)** in an iOS app and produce a reusable artifact (patched IPA or dylib), follow this phase. It documents the complete remote-debug workflow developed against Settle Up 3.18.2 (`cz.bioport.SettleUp7`, build 95) on a non-jailbroken iPhone 15.8.3.

### Why dylib runtime patching fails on non-jailbroken iOS

Non-jailbroken iOS 15.8.3 enforces code-signing on `__TEXT` pages. `vm_protect(VM_PROT_WRITE)` on `__TEXT` returns `KERN_PROTECTION_FAILURE (kr=2)`. A dylib cannot inline-patch the host app's `__TEXT` at runtime — 9 of 11 premium gates landed on non-writable pages. Dylib injection itself works (verified via UDP hello), but **no runtime modification of `__TEXT` is possible**.

The only reliable method on non-jailbroken iOS is **pre-patch the Mach-O on disk, then re-sign** (`codesign --force --sign -`). iOS loads the already-patched binary; no runtime `__TEXT` write is needed.

### Remote-debug toolchain (this skill)

| Tool | Purpose | Location |
|---|---|---|
| `macrun "cmd"` | Run command on Mac via SSH (auto-answers password) | `tools/macrun` |
| `macput LOCAL REMOTE` | Upload file/dir to Mac via SCP (pty) | `tools/macput` |
| `macget REMOTE LOCAL` | Download file/dir from Mac via SCP (pty) | `tools/macget` |
| UDP listener on Mac port 5140 | Receive dylib debug logs over UDP | `python3 -u /tmp/listener.py` |
| `ipsw` | Mach-O symbol extraction, class-dump | `~/.local/bin/ipsw` (both sides) |
| `clang -target arm64-apple-ios14.0` | Cross-compile arm64 dylib on Mac | CLT, iOS SDK `~/iOS-SDKs/iPhoneOS17.5.sdk` |

```bash
TOOLS=$HOME/.dsh/skills/ios-reverse-engineering/tools
$TOOLS/macrun 'echo OK; id -un'                    # verify SSH
$TOOLS/macput /tmp/dylib.dylib /tmp/               # upload dylib to Mac
$TOOLS/macget /tmp/listener.log /tmp/              # download log
```

### Dylib development history (v1 → v11)

| Version | Strategy | Result |
|---|---|---|
| v1–v4 | Symbol-based inline patch via `LC_SYMTAB` + `n_value + slide` | ❌ Symbol resolution unreliable at runtime (slide mismatch), `__TEXT` page not writable |
| v5 | Prologue byte-pattern scanning + call-site `bl` patching fallback | ⚠️ 2/11 gates patched; key gates (`hasPremiumGroup`) on non-writable pages |
| v6 | ObjC method swizzling + notifications + heap scan | ❌ Crash: constructor too early; Swift classes not ObjC-visible |
| v7 | `constructor(65535)`, `@try/@catch`, nil-checked swizzling, writable-page-only patch | ✅ No crash, but only 2/11 gates patched; premium not unlocked |
| v8 | UDP hello only (no ObjC, no memory alloc) | ✅ Confirms dylib injection itself works |
| v9 | `__DATA/__BSS` direct pointer write | ❌ Crash: unmapped pages |
| v10 | `vm_read`/`vm_write` safe `__DATA` scan | ❌ Still crashes |
| v11 | UserDefaults debug flags + notification broadcast (no `__TEXT`, no `__DATA` scan, no swizzling) | ✅ No crash, but premium **not unlocked** — app reads StoreKit/Firebase/Keychain, ignores UserDefaults-only flags |

### Recommended solution: Patched IPA (disk-level patch + re-sign)

**Artifact**: `build/Settle_Up_3.18.2_patched.ipa` (54,791,810 bytes, sha256 `b22650a050c299c704cae89a01e00e43cb3d0a078416daa9bacd67891f90bc73`)

**Workflow** (run on Mac):

```bash
# 1. Extract IPA
unzip Settle_Up_3.18.2.ipa -d Payload/

# 2. Locate main Mach-O
# Payload/Settle Up.app/Settle Up  (arm64, unencrypted, ~59 MB)

# 3. Find premium gate addresses via ipsw
ipsw macho info -n --demangle "Payload/Settle Up.app/Settle Up" > symbols.txt
# Target gates (vaddr in main binary):
#   PremiumManager.hasPremiumGroup   0x1002f9f34
#   PremiumManager.hasAnyPremium     0x1002fbd10
#   PremiumManager.hasFeature        0x1002fbb5c
#   PremiumManager.hasAnyFeature     0x1002fbd90
#   PremiumManager.getFeatureValidity 0x1002f9c34
#   PremiumManager.hasPremiumIndividual 0x1002f9d40
#   FeatureList.hasIndividualPremium 0x10045dfe0
#   FeatureList.hasAnyPremium        0x10045fe8
#   ChartDataObservable.hasPremium   0x1001c2b40
#   BarChartDataObservable.hasPremium 0x1002d8d98
#   LegacyManager.hasLegacyFeatures  0x1002d47b0

# 4. Patch each gate: replace first instructions with `mov w0,#1; ret` (0x52800020 0xD65F03C0)
# Use tools/settleup_patch.py (analyze/verify/patch modes)

# 5. Place stub in __TEXT zero-filled tail (file off 0x1684090..0x1688000)
# 6. vm_protect-equivalent: patch bytes directly on disk (no runtime protection)

# 7. Re-sign
codesign --force --sign - "Payload/Settle Up.app/Settle Up"
codesign --verify --deep "Payload/Settle Up.app/Settle Up"   # should say "valid on disk"

# 8. Re-package IPA
zip -r Settle_Up_3.18.2_patched.ipa Payload/

# 9. Side-load to iPhone via iloader / iOS App Signer / AltStore
```

### UDP remote-log listener (Mac)

```bash
# Start listener (keep running in background)
python3 -u /tmp/listener.py > /tmp/udp_listener.log 2>&1 &
# Listener binds 0.0.0.0:5140, writes to /tmp/su_udp_log.txt

# Clear log before a test run
> /tmp/su_udp_log.txt

# View logs
cat /tmp/su_udp_log.txt
```

### Key lessons (do not re-discover)

1. **`__TEXT` is unwritable at runtime on non-jailbroken iOS** — inline patch must happen on disk before install.
2. **Symbol-based `LC_SYMTAB` resolution is unreliable at runtime** — `n_value + slide` mismatches; use prologue byte-pattern scanning instead.
3. **Swift classes are not ObjC-visible** — `objc_getClass` returns nil for Swift classes; swizzling fails.
4. **`__DATA/__BSS` direct pointer access can crash** — unmapped pages; use `vm_read`/`vm_write` if scanning data segments.
5. **UserDefaults-only flags are insufficient** — `PremiumManager` queries StoreKit/Firebase/Keychain; ignores client-side defaults.
6. **Dylib injection works** — v8 proved the loader mechanism is functional; the limitation is `__TEXT` write protection, not injection.

### GitHub sync

This skill is mirrored from `https://github.com/incogbyte/iOS-reverse-engineering-claude-skill`. To push the current local tree (including Phase 12) back to GitHub:

```bash
cd $HOME/.dsh/skills/ios-reverse-engineering
git remote add origin https://github.com/incogbyte/iOS-reverse-engineering-claude-skill.git  # if not set
git add -A
git commit -m "Add Phase 12: Premium Gate Bypass & Remote Debug Workflow"
git push -u origin main
```

If you do not have write access to that repo, fork it and push to your fork instead.

## References
