# Rake

**A DigiByte CPU miner written in [Unison](https://www.unison-lang.org/), with a C native layer for performance-critical hash primitives.**

Supports two DigiByte mining algorithms:

| Algorithm | DGB algo slot | Hash output | Parallelism |
|---|---|---|---|
| `skein` | Skein-512 | 64 bytes | 4-way AVX2 (auto-detected) |
| `yescryptr16` | yescrypt N=2048 r=16 | 32 bytes | per-thread (memory-hard) |

---

## Table of Contents

- [Requirements](#requirements)
- [Building](#building)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Stats API](#stats-api)
- [Architecture](#architecture)
- [Algorithm Notes](#algorithm-notes)
- [Self-Tests](#self-tests)
- [Contributing](#contributing)

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| [Unison](https://www.unison-lang.org/install/) | ≥ 0.5.26 | `ucm` must be on `PATH` |
| CMake | ≥ 3.16 | For the C native layer |
| C compiler | GCC ≥ 11 / Clang ≥ 14 / MSVC 2022 | C11 required |
| CPU | x86-64 | AVX2 optional (auto-detected at runtime) |

No other runtime dependencies. SHA-256, Salsa20/8, Threefish-512, yescrypt, and all TCP sockets are implemented from scratch in `native/`.

---

## Building

### 1. Build the native layer

```sh
cd native
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
cmake --build build --parallel
```

This produces `native/build/librake_native.a` (Linux/macOS) or `native/build/rake_native.lib` (Windows).

Run the C self-tests before proceeding:

```sh
./native/build/selftest
```

Expected output:

```
[rake] All 5 Skein-1.3 self-test vectors passed.
[sha256d] All 3 SHA-256 vectors passed.
[dispatch] AVX2 detected: using 4-way Threefish-512 path.
[avx2] 4-way self-test PASSED.
[yescrypt] Self-test PASSED.
[selftest] PASS
```

### 2. Build the Unison project

```sh
ucm compile src/Main.u --output rake
```

The compiled binary is `./rake`.

### Debug build

```sh
cmake -DCMAKE_BUILD_TYPE=Debug -S native -B native/build-debug
cmake --build native/build-debug
# AddressSanitizer + UBSan enabled automatically
```

---

## Quick Start

**Skein (default):**

```sh
./rake \
  --wallet DGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --pool   stratum.digibyte.org:3443 \
  --threads 8
```

**yescryptr16:**

```sh
./rake \
  --wallet DGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --algo   yescryptr16 \
  --pool   stratum.dgb-group.com:3061 \
  --threads 4
```

Or use the included launch scripts:

```sh
# Linux / macOS
cp start-mine.sh my-mine.sh
# edit wallet/pool/algo inside
bash my-mine.sh

# Windows
copy start-mine.bat my-mine.bat
# edit wallet/pool/algo inside
my-mine.bat
```

---

## CLI Reference

```
rake [OPTIONS]

Required:
  --wallet  <address>   DigiByte wallet address

Pool:
  --pool    <host:port> Stratum endpoint  (default: stratum.digibyte.org:3443)
  --worker  <name>      Worker name       (default: rake)
  --password <pass>     Stratum password  (default: x)

Algorithm:
  --algo    <name>      skein | yescryptr16  (default: skein)

Performance:
  --threads <n>         Worker thread count  (default: 4)

API:
  --api-port <port>     HTTP stats port      (default: 4067)

Logging:
  --verbose             Enable DEBUG-level output
```

### Recommended thread counts

| Algorithm | Guidance |
|---|---|
| `skein` | Match physical core count; AVX2 gives ~3.5× throughput automatically |
| `yescryptr16` | Each thread uses 4 MB RAM; stay within (RAM - 1 GB) / 4 MB |

---

## Stats API

Rake exposes a local HTTP server on port `4067` (configurable via `--api-port`).

| Endpoint | Description |
|---|---|
| `GET /stats` | Full snapshot (hashrate, shares, uptime, best diff) |
| `GET /hashrate` | `{ "hashrate": 12.34, "unit": "MH/s" }` |
| `GET /shares` | `{ "accepted": 4, "rejected": 0 }` |
| `GET /health` | `{ "status": "ok", "uptime": 453 }` |
| `GET /` | Redirects to `/stats` |

All responses are `Content-Type: application/json` with `Access-Control-Allow-Origin: *`.

Example:

```sh
curl http://localhost:4067/stats
```

```json
{
  "hashrate": 14.21,
  "unit": "MH/s",
  "accepted": 7,
  "rejected": 0,
  "uptime": 312,
  "bestDiff": 2048.0
}
```

---

## Architecture

```
src/
  Main.u              Startup: CLI → validate → selftests → mine
  Config.u            CLI parsing, algo validation
  MinerLoop.u         Stratum event loop, job lifecycle, failover
  Worker.u            Concurrent nonce scan, abort flag, range split
  Algo/
    Dispatch.u        AlgoId type, hashHeader / hashBatch4 dispatch
    YescryptR16.u     FFI wrapper for yescryptr16
  Hash/
    Native.u          FFI wrappers: hash512, hash512_batch4, dispatchInit
  Header.u            80-byte header assembly, coinbase, merkle root
  Target.u            nBits → BigNat, meetsTarget
  Stratum.u           Stratum v1 session (subscribe, authorize, notify, submit)
  StratumMsg.u        JSON message parsing / rendering
  Stats.u             Rolling 60-s hashrate window, share counters
  Api.u               HTTP stats server
  Log.u               Levelled logging (DEBUG/INFO/WARN/ERROR), ANSI colour
  Platform/
    Tcp.u             FFI wrappers: connect, send, recv, listen, accept
    Time.u            UTC timestamp formatter (pure Gregorian arithmetic)

native/
  skein.c / skein.h               Skein-512 reference (vendored)
  skein_bridge.c / .h             Unison ABI shim + 5 KAT vectors
  skein_avx2.c / .h               4-way AVX2 Threefish-512
  skein_dispatch.c / .h           CPUID runtime dispatch
  sha256d.c / .h                  Double-SHA256 (FIPS 180-4, from scratch)
  tcp_bridge.c / .h               POSIX/Winsock2 blocking sockets
  yescrypt.c / .h                 yescrypt-1.0 (PBKDF2+Salsa20/8+SMix)
  yescryptr16_bridge.c / .h       Unison ABI shim
  CMakeLists.txt                  Isolated -mavx2 compilation for AVX2 TU
  selftest_main.c                 Standalone C self-test binary
```

### Data flow (per job)

```
Stratum.tick
  └─ MinerLoop receives NotifyParams + cleanJobs flag
       └─ cleanJobs=true → AbortFlag.set (workers drain within ~1ms)
       └─ Worker.scanJob spawns N threads
            └─ each thread: splitNonceRange → scan batch-of-4 nonces
                 └─ Algo.hashBatch4 (AVX2 or 4×scalar)
                 └─ Target.meetsTarget on each digest
                 └─ first hit → ResultRef.write + AbortFlag.set
       └─ coordinator awaits all threads, sums hash counts
       └─ Stratum.submitShare → Stats.recordShare
```

### AVX2 batch layout

For Skein, four 80-byte headers are hashed simultaneously. Each `__m256i` register holds one Threefish-512 state word from all four blocks in its four 64-bit lanes:

```
v[i] = [ word_i_block0 | word_i_block1 | word_i_block2 | word_i_block3 ]
```

All 72 Threefish rounds, 4 mix operations per round, and 19 subkey injections operate across all four blocks in a single instruction stream. On AVX2 hardware this delivers approximately 3.5× the throughput of a scalar loop.

---

## Algorithm Notes

### Skein-512

DigiByte's Skein algo slot uses a single Skein-512 pass (not double-Skein) on the 80-byte serialised block header. The Skein-1.3 reference implementation is vendored verbatim in `native/skein.c`; only the bridge shim and AVX2 path are original.

### yescryptr16

DGB yescryptr16 uses:

```
yescrypt(passwd=header, salt=header, N=2048, r=16, p=1, t=0, g=0, flags=YESCRYPT_RW)
```

Both password and salt are the same 80-byte header — this is the documented DGB behaviour. `YESCRYPT_RW` enables the anti-ASIC write-back step in SMix: after each lookup of `V[j]`, the current block is written back to `V[j]`, preventing any static precomputation of the V table. Each thread independently allocates and fills its own 4 MB scratch buffer.

---

## Self-Tests

Every primitive runs a known-answer test at startup before the first network connection. Any failure is a hard abort.

| Test | Vectors | Source |
|---|---|---|
| Skein-512 scalar | 5 | Skein-1.3 official test vectors |
| SHA-256 | 3 | FIPS 180-4 / NIST CAVS |
| AVX2 4-way Skein | zero header + 4 distinct nonces | Cross-checked against scalar |
| yescryptr16 | 1 (zero header) | yescrypt-0.9.0 reference |
| Target / nBits | internal | Round-trip nBits → BigNat → meetsTarget |
| Header assembly | internal | 80-byte size + field byte-order checks |

To regenerate the yescrypt KAT vector after any parameter change:

```sh
cd tools
cc -O2 gen_yescrypt_vector.c ../native/yescrypt.c ../native/sha256d.c -o gen_vector
./gen_vector
# paste output into native/yescrypt.c selftest expected[] array
```

---

## Contributing

The project is structured so that each concern is isolated to one file with a clear responsibility boundary. Before opening a PR:

1. Run the C selftests: `./native/build/selftest`
2. The Unison test suite: `ucm test src/`
3. For native changes, build in Debug mode (ASan + UBSan) and run under Valgrind if on Linux
4. New algorithms: add `native/<algo>.c`, a bridge shim, `src/Algo/<Algo>.u`, extend `Algo/Dispatch.u` with a new `AlgoId` variant, update `Config.validate`, and add a KAT vector to `selftest_main.c`

Pool compatibility tested against:
- mining-dutch.nl (Skein)
- dgb-group.com (yescryptr16)
- miningpoolhub.com (both)
