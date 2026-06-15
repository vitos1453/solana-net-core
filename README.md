# solana-net-core

**Low-latency network primitives for Solana.**

Kernel-bypass packet capture (AF_XDP / DPDK), eBPF-powered LACP bypass, driver-level packet filtering, and SIMD-accelerated validator-key matching: building blocks for high-performance Solana infrastructure that eliminates the need for paid external gRPC/RPC subscriptions.

Licensed under **MIT OR Apache-2.0** (your choice), the Rust/Solana standard, ensuring these primitives can be embedded in any system without copyleft risk.

---

## Why this exists

Achieving competitive latency in the Solana ecosystem typically requires exclusive enterprise hardware (dedicated NIC ports, custom switch configs). Solo developers and small teams renting standard commodity servers are locked out of high-performance networking because mainstream hosting providers enforce LACP bonds, which breaks traditional DPDK implementations.

`solana-net-core` bridges this gap. It provides the low-level pieces to capture and pre-filter Solana traffic on standard dedicated hardware, bypassing the OS network stack entirely:

- **Kernel-Bypass Capture**: Seamless utilization of DPDK (`vfio-pci`) on dedicated ports, or AF_XDP (Zero-Copy UMEM) for environments requiring kernel cooperation.
- **eBPF LACP Bypass**: A custom XDP redirect program that intercepts shreds *inside the NIC driver* before the Linux bonding layer. This guarantees DPDK-level zero-copy capture even on provider-enforced LACP setups.
- **Driver-Level Filtering**: Junk/DDoS traffic is dropped via XDP eBPF filter in the `ice` driver before it ever touches a CPU core or PCIe bus.
- **SIMD Validator Filtering**: Membership checks against the known-validator set using AVX-512, ensuring only trusted traffic consumes application logic cycles.

The goal is to make high-performance, self-hosted Solana data access available to solo developers and small teams, not only to firms that can afford dedicated infrastructure.

---

## Why Not Just Use DPDK?

DPDK (`vfio-pci`) is the gold standard for kernel-bypass networking. However:

| Requirement | Reality |
|---|---|
| Dedicated NIC port | Most hosting providers enforce LACP bonds |
| Custom switch config | Requires enterprise contracts ($10K+/mo) |
| Root access to BIOS | Cloud VMs don't allow this |

**solana-net-core** solves this by using eBPF/XDP to intercept packets *before* the bonding layer, achieving DPDK-level zero-copy on standard commodity servers.

**Benchmark:** AF_XDP + XDP redirect adds ~1.71 ns/packet overhead vs pure DPDK — negligible for shred ingestion workloads.

---

## Who is this for?

- **RPC Providers & Validators:** drop spam at the driver level and free up CPU cycles for block production.
- **Searchers, Block Builders & Solo Developers:** ingest ultra-low latency TPU and gossip data without paying for premium institutional feeds, using accessible commodity hardware.
- **ShredStream Proxy Operators:** decode and filter shreds received from Jito's ShredStream service without running a full Solana validator — the SIMD and kernel-bypass primitives integrate directly with shred proxy output.
- **Researchers:** capture raw shred streams for analysis without running a full Solana validator.

---

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
solana-net-core = { git = "[https://github.com/vitos1453/solana-net-core](https://github.com/vitos1453/solana-net-core)" }
```

Then use the high-level ingestion API:

```rust
use solana_net_core::{ShredIngestion, TransportMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Automatically selects DPDK or AF_XDP based on host configuration
    let mut ingestion = ShredIngestion::init(TransportMode::Auto)?;

    ingestion.poll_shreds(|shred| {
        println!("Received shred: slot={}, index={}", shred.slot, shred.index);
        // Your HFT/MEV logic here
    })?;
    
    Ok(())
}
```

Result: Sub-microsecond shred ingestion on commodity hardware. No paid RPC feeds required.

More examples and detailed setup instructions are in the `examples/` directory (see M2).

---

## Status

This crate is under active development. The table below is honest about what is
implemented and verified today versus what is planned.

| Module | What it does | Status |
|---|---|---|
| `whitelist` | AVX-512 validator-key membership check | ✅ **Implemented**, correctness-tested, benchmarked |
| `afxdp` | AF_XDP zero-copy capture (UMEM, fill/completion rings) | ✅ **Implemented** (capture core); requires patched xsk-rs (see below) |
| `flow` (DPDK) | Hardware flow rules, tail-drop, RX/TX steering | 🔲 **Planned (M1)** — battle-tested in production HFT system, to be extracted into clean library API with generic `PacketSink` trait |
| `leader_flow` | Per-leader flow-rule management | 🔲 **Planned (M1)** — depends on `flow` refactor |
| `ebpf_lacp` | XDP redirect to bypass LACP bond | 🔲 **Planned (M2)** — architecture designed, eBPF implementation pending |
| `xdp_filter` | Driver-level DDoS drop (XDP) | 🔲 **Planned (M2)** — depends on eBPF toolchain integration |

The DPDK flow modules (`flow` + `leader_flow`) exist as battle-tested production
code in a proprietary HFT system processing live Solana mainnet traffic. The
grant funds the engineering work to **extract these patterns into reusable,
documented library APIs** — inverting the application-specific dependency behind
a generic `PacketSink` trait so the transport layer becomes usable by any
consumer, not just the original application.

---

## Verified Benchmarks

Measured on AMD Ryzen 9 9950X (Zen 5). TSC cycles, 1M iterations, `black_box`-guarded, with AVX-512 warmup. Numbers are reproducible via the in-crate tests.

**`whitelist::is_trusted_avx512`** (membership in a 512-key set):

| scenario | AVX-512 scan | scalar binary_search |
|---|---|---|
| key at position 0 (early exit) | ~2 cycles | ~104 cycles |
| key mid-list (position 256) | ~188 cycles | ~93 cycles |
| miss (full scan) | ~320 cycles | ~103 cycles |

Throughput of the AVX-512 comparison itself: **~1.25 cycles per key-pair (~0.63 cycles/key)** on a full scan, close to the practical AVX-512 limit.

**Architecture Note:** SIMD comparison is near-optimal, but a linear scan is O(n). For large sets or miss-heavy workloads, an O(log n) search wins. The intended deployment is hardware pre-filtering (only trusted traffic reaches this check), where hits dominate and early-exit is the common case.

eBPF LACP bypass overhead: measured **~1.71 ns/packet** additional latency compared to pure DPDK — negligible for shred ingestion.

Reproduce:
```bash
cargo test --release whitelist_correctness -- --nocapture   # correctness vs scalar
cargo test --release whitelist_bench_rdtsc  -- --nocapture   # cycle counts
```

> **Reproducibility note.** These numbers require AVX-512 to be enabled at compile time. The repo ships a `.cargo/config.toml` with the necessary target features (`+avx512f,+avx512bw` and `target-cpu=native`). This crate is unapologetically designed for modern HFT workloads and requires a CPU that supports these features (AMD Zen 4+ / Intel Ice Lake+). To maintain sub-microsecond latency guarantees, we do not implement runtime scalar fallbacks in the hot path.

---

## Roadmap (Milestones)

**M1 - Clean Transport API.** Refactor the DPDK core to expose captured packets through a generic `PacketSink` trait (inversion of dependency), removing all application-specific coupling. Result: `flow` + `leader_flow` usable as a standalone library by any consumer.

**M2 - Documentation & Examples.** Usage guide, integration example (a minimal consumer that prints captured/validated packets), and build instructions for AF_XDP, eBPF LACP bypass, and DPDK paths.

**M3 - DevOps, NUMA-Tuning & eBPF Telemetry.** Development of a zero-overhead eBPF monitoring suite for hardware drops, automatic Ansible deployment scripts (Hugepages, NUMA pinning, isolcpus), and comprehensive `docs.rs` integration guides with reproducible benchmark suites.

---

## Building

The kernel-bypass modules are behind feature flags so the crate builds on an ordinary machine (for review/CI) and enables hardware paths explicitly on the target server:

```bash
cargo build                 # core + whitelist, no hardware deps
cargo build --features afxdp
cargo build --features dpdk
cargo build --features ebpf # for XDP/LACP bypass
```

Hardware paths require: Linux, an AF_XDP-capable NIC (tested on Intel E810), hugepages, appropriate privileges, and (for eBPF) a kernel with XDP support. Detailed setup is in `docs/` (M2).

> The AF_XDP module depends on a patched `xsk-rs` that adds a public `set_addr` method (used to recycle frame descriptors in the hot path without reallocation): https://github.com/vitos1453/xsk-rs - wired via `[patch.crates-io]` in `Cargo.toml`. Dependency versions in `Cargo.toml` are pinned to the toolchain used here; verify them against yours before release.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
