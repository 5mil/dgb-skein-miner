# Rake

A cross-platform **DigiByte Skein** CPU miner written in [Unison](https://www.unison-lang.org/), with a CLI interface intentionally compatible with SRBMiner.

## Status

Current scaffold includes:
- SRBMiner-style CLI parsing and help/version output
- Native hash facade with pure-Unison fallback
- Stratum transport skeleton using newline-delimited JSON-RPC message framing
- Big-integer target comparison helpers
- Pool failover loop with exponential backoff model

## Native hash backend

The native backend is designed around a future FFI bridge. Unison's official docs note that FFI support is still being added, so `src/Hash/Native.u` currently defines the ABI contract and falls back to the pure Unison implementation until the bridge is available.

Planned native pieces:
- `native/skein_bridge.h`
- `native/skein_bridge.c`
- vendor Skein reference/optimized C source
- batch hashing entrypoints for better CPU cache and threading behavior

## Next 30 hashrate steps

1. Replace pure-Unison hashing with a working C Skein-512 backend.
2. Add compile-time CPU feature detection for SSE2/AVX2/AVX-512.
3. Add separate 32-bit and 64-bit optimized Skein paths.
4. Benchmark single-buffer vs batched hashing.
5. Add batch APIs sized for L1/L2 cache sweet spots.
6. Reuse prebuilt block-header prefixes across nonce scans.
7. Precompute invariant Threefish schedule components per job.
8. Avoid repeated heap allocation in the hot loop.
9. Store nonce in a mutable fixed-width buffer instead of rebuilding bytes.
10. Use little-endian word writes matching Skein input layout.
11. Minimize hex conversion to submit-path only.
12. Move target expansion out of the inner loop.
13. Use branch-light target comparison on leading limbs.
14. Unroll Threefish rounds in the native backend.
15. Tune rotation/mix operations for compiler auto-vectorization.
16. Align state buffers to cache-line boundaries.
17. Pin mining threads to physical cores.
18. Prefer physical-core count over logical threads on weak SMT CPUs.
19. NUMA-pin workers and memory on multi-socket systems.
20. Introduce per-thread work stealing only if imbalance appears.
21. Double-buffer incoming jobs vs active mining buffers.
22. Abort stale jobs immediately on `clean_jobs=true` notifications.
23. Separate networking thread from hashing workers.
24. Use a lock-free accepted-share counter.
25. Rate-limit terminal/UI updates.
26. Add hugepage experiments for large batch buffers where useful.
27. Profile branch misses and cache misses with `perf`/VTune.
28. Add architecture-specific optimized implementations behind one ABI.
29. Benchmark compiler flags per platform (`-O3`, `-march=native`, LTO, PGO).
30. Add a synthetic benchmark mode to compare tuning changes job-for-job.
