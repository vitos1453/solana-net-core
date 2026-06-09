# solana-net-core

**Low-latency network primitives for Solana.**
Kernel-bypass packet capture (AF_XDP / DPDK), hardware-level packet filtering on
the NIC, and SIMD-accelerated validator-key matching: building blocks for
high-performance Solana infrastructure that does not depend on paid external
gRPC/RPC subscriptions.

Licensed under **MIT OR Apache-2.0** (your choice), the Rust/Solana standard, so
the primitives can be embedded in proprietary systems without copyleft risk.

---

## Why this exists

Most Solana tooling reads chain data through standard OS sockets: per-packet
syscalls, heap allocations in the hot path, and context-switch jitter. To get
low-latency data, developers end up paying for dedicated gRPC feeds.

`solana-net-core` provides the low-level pieces to capture and pre-filter Solana
traffic on commodity hardware, without the kernel in the hot path:

- **Kernel-bypass capture** via AF_XDP (zero-copy UMEM) and DPDK.
- **Hardware tail-drop**: junk/DDoS traffic is dropped on the NIC (Intel E810
  flow rules) before it ever touches a CPU core or a parser.
- **SIMD validator filtering**: membership checks against the known-validator
  set using AVX-512, so only trusted traffic reaches application logic.

The goal is to make high-performance, self-hosted Solana data access available
to solo developers and small teams, not only to firms that can afford dedicated
infrastructure.

---

## Who is this for?

- **RPC Providers & Validators:** To drop spam at the hardware level and free up CPU cycles for block production.
- **HFT Searchers & Solo Developers:** To access ultra-low latency mempool and TPU data without subscribing to premium institutional feeds.

---
## Status

This crate is under active development. The table below is honest about what is
implemented and verified today versus what is planned.

| Module | What it does | Status |
|---|---|---|
| `whitelist` | AVX-512 validator-key membership check | implemented, correctness-tested, benchmarked |
| `afxdp` | AF_XDP zero-copy capture (UMEM, fill/completion rings) | implemented (capture core) |
| `flow` (DPDK) | Hardware flow rules, tail-drop, RX/TX steering | in tree, being refactored into a clean library API |
| `leader_flow` | Per-leader flow-rule management | depends on `flow` refactor |

The DPDK module currently exposes its hot path tied to an application-specific
consumer. The planned work (see Roadmap) is to invert that dependency behind a
generic `PacketSink` trait so the transport layer is reusable by any consumer,
not just the original application.

---

## Verified benchmarks

Measured on AMD Ryzen 9 9950X (Zen 5). TSC cycles, 1M iterations, black_box-guarded,
with AVX-512 warmup. Numbers are reproducible via the in-crate test (below); they
are measured, not estimated.

**`whitelist::is_trusted_avx512`** (membership in a 512-key set):

| scenario | AVX-512 scan | scalar binary_search |
|---|---|---|
| key at position 0 (early exit) | ~2 cycles | ~104 cycles |
| key mid-list (position 256) | ~188 cycles | ~93 cycles |
| miss (full scan) | ~320 cycles | ~103 cycles |

Throughput of the AVX-512 comparison itself: **~1.25 cycles per key-pair
(~0.63 cycles/key)** on a full scan, close to the practical AVX-512 limit.

Honest takeaway, documented in code: the SIMD comparison is near-optimal, but a
linear scan is O(n). For large sets or miss-heavy workloads, an O(log n) search
wins. The intended deployment is hardware pre-filtering (only trusted traffic
reaches this check), where hits dominate and early-exit is the common case.

Reproduce:
```
cargo test --release whitelist_correctness -- --nocapture   # correctness vs scalar
cargo test --release whitelist_bench_rdtsc  -- --nocapture   # cycle counts
```

---

## Roadmap (milestones)

**M1 - Clean transport API.** Refactor the DPDK core to expose captured packets
through a generic `PacketSink` trait (inversion of dependency), removing all
application-specific coupling. Result: `flow` + `leader_flow` usable as a
standalone library by any consumer.

**M2 - Documentation & examples.** Usage guide, integration example (a minimal
consumer that prints captured/validated packets), and build instructions for
AF_XDP and DPDK paths.

**M3 - Technical write-up & benchmarks.** Public article documenting the
architecture (hardware tail-drop, SIMD filtering, kernel-bypass capture) with
reproducible benchmarks, so others in the ecosystem can learn from and build on
the work.

---

## Building

The kernel-bypass modules are behind feature flags so the crate builds on an
ordinary machine (for review/CI) and enables hardware paths explicitly on the
target server:

```
cargo build                 # core + whitelist, no hardware deps
cargo build --features afxdp
cargo build --features dpdk
```

Hardware paths require: Linux, an AF_XDP-capable NIC (tested on Intel E810),
hugepages, and appropriate privileges. See docs/ (M2) for setup.

> Dependency versions in `Cargo.toml` (xsk-rs, ringbuf, etc.) are starting
> points; pin them to versions verified on your toolchain before release. The
> AF_XDP module also relies on `set_addr` from an xsk-rs fork (see code notes).


---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
