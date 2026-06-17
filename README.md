# solana-net-core

**Low-latency network primitives for Solana.**

Kernel-bypass packet capture (AF_XDP / DPDK), driver-level packet filtering,
and SIMD-accelerated validator-key matching: building blocks for
high-performance Solana infrastructure that eliminates the need for paid
external gRPC/RPC subscriptions.

Licensed under **MIT OR Apache-2.0** (your choice), the Rust/Solana standard,
ensuring these primitives can be embedded in any system without copyleft risk.

---

## Why this exists

Most Solana tooling reads chain data through standard OS sockets: per-packet
syscalls, heap allocations in the hot path, and context-switch jitter. To get
low-latency data, developers end up paying for dedicated gRPC feeds.

Solana breaks transactions into **shreds** — small data fragments distributed
across the network before assembly into full blocks. Capturing these shreds
directly from the Turbine tree or from a Jito ShredStream proxy gives developers
access to transaction data at the lowest possible latency, often saving hundreds
of milliseconds compared to standard RPC paths — a critical advantage in
high-frequency and MEV-sensitive workloads.

`solana-net-core` provides the low-level pieces to capture and pre-filter Solana
traffic on commodity hardware, without the kernel in the hot path:

- **Kernel-bypass capture** via AF_XDP (zero-copy UMEM) and DPDK.
- **Driver-level filtering**: junk/DDoS traffic is dropped at the NIC driver
  level (XDP eBPF on Intel `ice`) before it ever touches a CPU core or a parser.
- **SIMD validator filtering**: membership checks against the known-validator
  set using AVX-512, so only trusted traffic reaches application logic.

The goal: make high-performance, self-hosted Solana data access available to
solo developers and small teams, not only to firms that can afford dedicated
infrastructure.

---

## Who is this for?

- **RPC Providers & Validators:** drop spam at the driver level and free up
  CPU cycles for block production.
- **Searchers, Block Builders & Solo Developers:** ingest ultra-low latency
  TPU and gossip data without paying for premium institutional feeds, using
  accessible commodity hardware.
- **ShredStream Proxy Operators:** decode and filter shreds received from Jito's
  ShredStream service without running a full Solana validator — the SIMD and
  kernel-bypass primitives integrate directly with shred proxy output.
- **Researchers:** capture raw shred streams for analysis without running a
  full Solana validator.

---

## Repository Contents

This crate is under active development. The table below is honest about what
is published today versus what is planned.

### Published modules (verified, tested)

| File | What it does | Status |
|---|---|---|
| `src/whitelist.rs` | AVX-512 validator-key membership check | ✅ Implemented, correctness-tested, benchmarked |
| `src/afxdp.rs` | AF_XDP zero-copy capture (UMEM, fill/completion rings) | ✅ Implemented (capture core); requires patched `xsk-rs` |
| Fork: `github.com/vitos1453/xsk-rs` | Adds public `set_addr()` for hot-path frame recycling | ✅ Published |

### Planned modules (exist in proprietary system, extraction funded by grant)

| File | What it will do | Milestone |
|---|---|---|
| `src/flow.rs` | DPDK hardware flow rules, tail-drop, RX/TX steering | M1 |
| `src/leader_flow.rs` | Per-leader flow-rule management with sliding window | M1 |
| `src/ebpf_lacp.rs` | XDP redirect program to bypass LACP bonds | M2 |
| `src/xdp_filter.rs` | Driver-level DDoS drop via XDP eBPF filter | M2 |
| `examples/basic_ingestion.rs` | Minimal consumer printing captured/validated packets | M2 |
| `docs/deploy.md` | "Deploy on $300/mo commodity server" tutorial | M2 |
| `benches/wire_to_userspace.rs` | Reproducible end-to-end latency suite | M3 |

The planned work (see Roadmap) is to **extract these battle-tested patterns
from a proprietary HFT system into a reusable, documented public library** —
inverting application-specific dependencies behind generic traits so the
transport layer becomes usable by any consumer.

---

## Verified Benchmarks

Measured on AMD Ryzen 9 9950X (Zen 5). TSC cycles, 1M iterations,
`black_box`-guarded, with AVX-512 warmup. Numbers are reproducible via the
in-crate test; they are measured on bare-metal, not estimated.

**`whitelist::is_trusted_avx512`** (membership in a 512-key set):

| scenario | AVX-512 scan | scalar binary_search |
|---|---|---|
| key at position 0 (early exit) | ~2 cycles | ~104 cycles |
| key mid-list (position 256) | ~188 cycles | ~93 cycles |
| miss (full scan) | ~320 cycles | ~103 cycles |

Throughput of the AVX-512 comparison itself: **~1.25 cycles per key-pair
(~0.63 cycles/key)** on a full scan, close to the practical AVX-512 limit.

> **Note on transport benchmarks.** The AF_XDP zero-copy UMEM→descriptor
> adapter measures **~1.71 ns/packet** overhead on the same hardware (TSC
> 4291.937 MHz, 10M iterations, rdtscp+lfence serialization). This is
> **adapter overhead only, not end-to-end wire-to-userspace latency**. Full
> pipeline benchmarks will be published in M3.

Honest takeaway, documented in code: the SIMD comparison is near-optimal, but a
linear scan is O(n). For large sets or miss-heavy workloads, an O(log n) search
wins. The intended deployment is hardware pre-filtering (only trusted traffic
reaches this check), where hits dominate and early-exit is the common case.

Reproduce:

```bash
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512bw" \
cargo test --release whitelist_bench_rdtsc -- --nocapture
```

> **Reproducibility note.** For maximum AVX-512 performance, pass target
> features via `RUSTFLAGS`. Without them the intrinsics are emulated and the
> scan is ~15x slower. The AVX-512 path requires a CPU that supports these
> features (AMD Zen 4+ / Intel Ice Lake+); on other hardware, use the scalar
> `is_trusted` path.

---

## Quick Start

### 1. Add to your `Cargo.toml`

```toml
[dependencies]
solana-net-core = { git = "https://github.com/vitos1453/solana-net-core", features = ["afxdp"] }
```

### 2. Run the AVX-512 validator whitelist benchmark

```bash
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512bw" \
cargo test --release whitelist_bench_rdtsc -- --nocapture
```

### 3. Use the validator whitelist in your code

```rust
use solana_net_core::whitelist::{WHITELIST, update_static_keys};

// Load sorted validator keys
let keys: Vec<[u8; 32]> = load_and_sort_validator_keys();
update_static_keys(&keys);

// AVX-512 membership check (~0.63 cycles/key)
let is_trusted = unsafe { WHITELIST.is_trusted_avx512(&some_pubkey) };

// Or scalar fallback (O(log n))
let is_trusted_safe = WHITELIST.is_trusted(&some_pubkey);
```

### 4. AF_XDP capture (requires root + compatible NIC)

```rust
use solana_net_core::{AfXdpCapture, AfXdpConfig};

let config = AfXdpConfig {
    iface: "enp1s0f0".into(),
    queue_id: 0,
    frame_count: 4096,
    rx_batch_size: 64,
    comp_batch_size: 32,
};
let mut capture = AfXdpCapture::new(config, stop_signal, frame_prod, frame_cons);
let (state, dma_region) = capture.init_sync(core_id)?;
capture.run_loop(state);
```

> **Note:** A high-level `ShredIngestion` API that auto-selects DPDK vs AF_XDP
> and provides a unified `poll_shreds(callback)` interface is planned for M1.
> Current modules expose lower-level primitives suitable for systems programmers
> integrating into custom pipelines.

---

## Roadmap (Milestones)

**M1 — Clean Transport API.** Refactor the capture core to expose packets
through a generic `PacketSink` trait (inversion of dependency), removing all
application-specific coupling. Specific deliverables:

- Extract hardcoded constants (`queue_id`, `frame_count`, `rx_batch_size`,
  `comp_batch_size`) into a configurable `AfXdpConfig` struct
- Replace hardcoded `ringbuf::HeapRb` coupling with a generic `PacketSink`
  trait or callback interface
- Document system requirements (`CAP_NET_ADMIN`, hugepages, kernel 6.1+,
  compatible NICs)

Result: `afxdp` + `flow` + `leader_flow` usable as a standalone library by any
consumer.

**M2 — XDP Toolchain & Documentation.** Implement eBPF/XDP redirect program
for LACP bypass and driver-level DDoS drop. Write usage guide, integration
example (minimal consumer), and "Deploy on $300/mo commodity server" tutorial.
Build instructions for AF_XDP, eBPF, and DPDK paths.

**M3 — DevOps, NUMA-Tuning & eBPF Telemetry.** Development of a
minimal-overhead eBPF monitoring suite for hardware drops, automatic Ansible
deployment scripts (Hugepages, NUMA pinning, isolcpus), and comprehensive
`docs.rs` integration guides with reproducible benchmark suites.

---

## Building

The kernel-bypass modules are behind feature flags so the crate builds on an
ordinary machine (for review/CI) and enables hardware paths explicitly on the
target server:

```bash
cargo build                 # core + whitelist, no hardware deps
cargo build --features afxdp
```

Hardware paths require: Linux 6.1+, an AF_XDP-capable NIC (tested on Intel
E810), hugepages, and `CAP_NET_ADMIN` privileges. Detailed setup is in `docs/`
(M2).

> **Dependency note.** The AF_XDP module depends on a patched `xsk-rs` that
> adds a public `set_addr()` method (used to recycle frame descriptors in the
> hot path without reallocation): https://github.com/vitos1453/xsk-rs — wired
> via `[patch.crates-io]` in `Cargo.toml`. Dependency versions in `Cargo.toml`
> are pinned to the toolchain used here; verify them against yours before
> release.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
