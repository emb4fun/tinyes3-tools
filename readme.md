# tinyes3-tools

CLI tools for the **Embedded Secure Signing Server (ES3)**, portable
and built for **Windows (MSYS2-UCRT64, MinGW)** and **Linux (GCC)**.

Originally created with Visual C++ 6.0, later ported to Visual Studio
2019, now converted to CMake/MSYS2-UCRT64 and mbedTLS 4.1.2.

The porting to MSYS2-UCRT64, Linux and mbedTLS 4.1.2 was done with AI
assistance (LLM model used: GLM-5.3).

## Tools

| Tool | Function |
|---|---|
| `es3discover` | Searches for ES3 servers in the local network (TNP, UDP, port 54321) |
| `es3keygen` | Creates a private/public es3 key pair (NIST P-256) in the home directory (`~/.es3/id_es3`, `~/.es3/id_es3.pub`) |
| `es3sign` | Signs a file with a server key slot (`-s slot -f file`) |
| `es3verify` | Verifies a signed `.es3` file locally against a public key (`-k key -f file`) |
| `es3getpub` | Gets the public key of a slot from the server (`-s slot`) |
| `es3getpubsign` | Gets a slot key and has it signed by the server with "root-of-trust" (`-s slot`) |
| `es3slotlist` | Lists the available key slots of the server |

## Project structure

```
tinyes3-tools/
├── CMakeLists.txt          Root build (presets, mbedTLS, tools)
├── CMakePresets.json        Presets "debug" and "release"
├── inc/                    Shared headers (tnp.h, es3_rpc.h, ...)
│   ├── mbedtls_conf.h         mbedTLS configuration (MBEDTLS_CONFIG_FILE)
│   └── mbedtls_psa_config.h   PSA crypto configuration (TF_PSA_CRYPTO_CONFIG_FILE)
├── src/                    Shared sources (tnp.c, libtnp)
├── library/
│   ├── mbedtls/            mbedTLS 4.1.2 (built from source)
│   └── adler32/            CRC32/Adler32 library
├── es3discover/            Tool: server search
├── es3keygen/              Tool: key generation
├── es3getpub/              Tool: get public key of a slot
├── es3sign/                Tool: sign a file
├── es3verify/              Tool: verify a signed file
├── es3getpubsign/          Tool: get signed public key (root-of-trust)
├── es3slotlist/            Tool: list available key slots
├── bin-release/            Finished release tools (generated, in .gitignore)
└── bin-debug/              Finished debug tools (generated, in .gitignore)
```

---

## Prerequisites

### Windows (MSYS2-UCRT64)

The following packages must be installed (UCRT64 shell):

```bash
pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
```

In addition a **Python 3** is required (the mbedTLS build generates
headers with it). Any Python found in the PATH is sufficient.

All commands below must be executed in the **UCRT64 shell**
(`C:\msys64\ucrt64.exe`), so that `cmake`, `ninja` and `gcc` are in the
PATH.

### Linux

Required are `gcc`, `cmake` (>= 3.21), `ninja` and `python3`,
for example on Debian/Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build python3
```

### Linux under WSL2 (Windows Subsystem for Linux)

The tools also work under WSL2 — **prerequisite** is the
*mirrored networking mode* (`%UserProfile%\.wslconfig`):

```ini
[wsl2]
networkingMode=mirrored
```

After changing the file, WSL must be restarted (`wsl --shutdown`).
Background: In mirrored mode, WSL2 only delivers UDP responses to
sockets which are explicitly bound — the tools therefore bind their
sockets explicitly (TNP discovery to `0.0.0.0:54321`, RPC to
`0.0.0.0:54322`), which is compatible on all platforms.
Additionally, incoming communication for WSL may need to be allowed
(PowerShell as administrator):

```powershell
Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow
```

## Building

The build is always started from the workspace root. The build directory
(`build/`) is located centrally in the root and is **shared by all
tools** — mbedTLS is built there only **once per configuration**.

### Debug build

```bash
cmake --preset debug
cmake --build --preset debug
```

### Release build

```bash
cmake --preset release
cmake --build --preset release
```

The executables are automatically **collected** and are then located
directly in the workspace root:

| Build | Windows | Linux |
|---|---|---|
| Release | `bin-release\es3discover.exe` etc. | `bin-release/es3discover` etc. |
| Debug | `bin-debug\es3discover.exe` etc. | `bin-debug/es3discover` etc. |

All 7 tools are located directly next to each other in the respective
directory (`bin-release\` or `bin-debug\`). The build directory (`build\`)
only contains intermediate files and libraries.

### Notes

- The `cmake --preset ...` step (configuration) is only needed once;
  afterwards `cmake --build --preset ...` is sufficient after every
  source code change.
- Debug and Release can exist **in parallel**, because they use separate
  build directories (`build/debug` and `build/release`).
- When configuring without a preset (e.g. manually with
  `cmake -B build`), the build type defaults to `Release`.
- **Expected CMake warnings:** During configuration, two
  `CMake Warning (deprecated)` messages appear regarding
  `cmake_minimum_required` from `library/mbedtls/CMakeLists.txt` and
  `library/mbedtls/tf-psa-crypto/CMakeLists.txt`. These originate from
  the mbedTLS upstream and are harmless — they do not affect this
  project. As of CMake 4.4 (policy CMP0218) they can no longer be
  suppressed via `CMAKE_WARN_DEPRECATED`; if needed, use
  `cmake --preset release -Wno-deprecated` on the command line.

### Building only a single tool

To build only a single tool without touching the others:

```bash
cmake --build --preset debug   --target es3discover
cmake --build --preset release --target es3keygen
```

The `--target` name is the tool name (directory name) respectively.

---

## Clean

### Full clean (Debug and Release)

The easiest and most complete method is to delete the build and output
directories:

```bash
rm -rf build/debug build/release bin-debug bin-release
```

Afterwards the desired configurations must be configured again with
`cmake --preset ...`.

### Single clean (objects only, configuration is kept)

```bash
cmake --build --preset debug   --clean-first
cmake --build --preset release --clean-first
```

`--clean-first` first deletes all existing build artifacts of the
respective build directory and then rebuilds everything.

### Clean without presets (classic)

Alternatively, the classic CMake target `clean` also works:

```bash
cmake --build build/debug   --target clean
cmake --build build/release --target clean
```

---

## Distribution (static linking)

The Windows executables are **statically linked**. They only depend on
DLLs which belong to the operating system (`KERNEL32.dll`, `WS2_32.dll`,
`ADVAPI32.dll`, `bcrypt.dll` and the UCRT API sets `api-ms-win-crt-*.dll`).
So **no additional DLLs** are needed — the `.exe` can simply be
distributed as is.

This is set in the root `CMakeLists.txt` via the linker option `-static`;
release builds are additionally stripped (`-s`) to reduce the file size.

The requirement on the target system is **Windows 10/11**, because the
UCRT (Universal C Runtime) is part of the operating system. For
Windows 7/8 the UCRT would have to be installed separately.

On **Linux** the tools are normally linked dynamically against the
glibc — this is common practice there, as long as the glibc version of
the target system is not older than that of the build system.

---

## mbedTLS configuration

mbedTLS 4.1.2 is built from source under `library/mbedtls`
(especially the crypto library TF-PSA-Crypto) and linked **statically**
into the tools. The configuration is done via two files in `inc/`:

| File | Role |
|---|---|
| `mbedtls_conf.h` | `MBEDTLS_CONFIG_FILE` — configuration of the main library (TLS/X.509 are not needed) |
| `mbedtls_psa_config.h` | `TF_PSA_CRYPTO_CONFIG_FILE` — crypto modules (PK, PEM, Base64, MD, CTR_DRBG) and PSA wants (MD5, SHA-256, ECDSA, NIST P-256) |

---

## Tool usage

### es3discover

```
es3discover
```

Without parameters. Sends a UDP broadcast on port 54321 and lists all
TinyES3 servers found (MAC, IP, firmware version, location).

| Return value | Meaning |
|---|---|
| `0` | OK, at least one server found |
| `-1` | No server found or error on startup |
| `-2` | Bind error (maybe another program is already listening) |

### es3keygen

```
es3keygen [-v] [-f]
```

Without parameters a new key pair is created and saved in the home
directory (`~/.es3/id_es3` = private key in SEC1 PEM format,
`~/.es3/id_es3.pub` = public key as an `es3-nistp256 ...` line).
If a key already exists, the tool asks before overwriting it.

| Option | Function |
|---|---|
| `-v` | Show version information only |
| `-f` | Show the fingerprint (MD5) of the existing public key only |

### es3getpub

```
es3getpub -s slot [-ip a.b.c.d] [-v] [-d]
```

Gets the public key of a key slot from the server and saves it in the
current directory as `<slot>.pub` (PEM format). The request is signed
with the own private key (`~/.es3/id_es3`) — the server checks the
signature and the user (`user@computer`).

| Option | Function |
|---|---|
| `-s slot` | Slot name, e.g. `-s firefly` |
| `-ip a.b.c.d` | Specify the server IP, instead of the automatic search |
| `-v` | Show version information only |
| `-d` | Run the server search (discovery) only |

### es3sign

```
es3sign -s slot -f file [-ip a.b.c.d] [-v] [-d] [-a Alignment]
```

Signs a file with a key slot of the server and writes the result as
`<file>.es3`: 128-byte signature header (`ES3_SIGN_HEAD` with the magic
"TINYES3", slot, ECDSA signature, Adler-32 CRC) followed by the file
data. The request is signed with the own private key — the server
checks the signature and the user.

| Option | Function |
|---|---|
| `-s slot` | Slot name, e.g. `-s firefly` |
| `-f file` | File to sign, e.g. `-f firmware.bin` |
| `-ip a.b.c.d` | Specify the server IP, instead of the automatic search |
| `-v` | Show version information only |
| `-d` | Run the server search (discovery) only |
| `-a Alignment` | Align the output size (0xFF padding), e.g. `-a 128` |

### es3verify

```
es3verify -k key -f file [-v]
```

Verifies a `<file>.es3` file created with es3sign **locally** against a
public key (e.g. `firefly.pub`, fetched with es3getpub). The Adler-32
CRC of the header, the SHA-256 hash of the data and the ECDSA signature
are checked. No network connection is required.

| Option | Function |
|---|---|
| `-k key` | Public key file, e.g. `-k firefly.pub` |
| `-f file` | File to verify, e.g. `-f firefly.es3` |
| `-v` | Show version information only |

| Return value | Meaning |
|---|---|
| `0` | Signature valid |
| `-1` | Public key file is not a valid public key |
| `-2`/`-3` | File not found |
| `-5` | Signature invalid |
| `-6` | CRC in the header is defect |
| `-7` | File has no ES3 signature |

### es3getpubsign

```
es3getpubsign -s slot [-ip a.b.c.d] [-v] [-d]
```

Combines es3getpub and es3sign: gets the public key of a slot and has
it signed by the server with the special slot **"root-of-trust"**.
Result in the current directory:
- `<slot>.pub` — the public key (PEM)
- `<slot>.es3` — 384 bytes: ES3 signature header (slot `root-of-trust`,
  signature, CRC) followed by slot name and key (256 bytes)

| Option | Function |
|---|---|
| `-s slot` | Slot name, e.g. `-s firefly` |
| `-ip a.b.c.d` | Specify the server IP, instead of the automatic search |
| `-v` | Show version information only |
| `-d` | Run the server search (discovery) only |

### es3slotlist

```
es3slotlist [-ip a.b.c.d] [-v] [-d]
```

Lists the key slots available on the server (RPC `GET_LIST`, signed
with the own private key, slot field "root-of-trust").

| Option | Function |
|---|---|
| `-ip a.b.c.d` | Specify the server IP, instead of the automatic search |
| `-v` | Show version information only |
| `-d` | Run the server search (discovery) only |

---

## Some notes about Mbed TLS

Mbed TLS is used in `.\library\mbedtls` and was copied from the following
project: <https://github.com/ARMmbed/mbedtls> (version 4.1.2).

The library is built from source as part of the tools build process
(see "mbedTLS configuration" above) and is linked statically into the
executables.
