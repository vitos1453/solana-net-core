//! # solana-net-core
//!
//! Low-latency network primitives for Solana: kernel-bypass packet capture,
//! hardware tail-drop, and SIMD validator filtering.
//!
//! See the [README](https://github.com/vitos1453/solana-net-core) for
//! detailed architecture, benchmarks, and production deployment guides.

/// AVX-512 vector-accelerated validator key membership verification.
/// Compiles unconditionally and operates on all x86_64 targets.
pub mod whitelist;

/// Kernel-bypass packet capture pipeline utilizing Linux AF_XDP zero-copy sockets.
/// Gated behind the `afxdp` feature flag due to OS and hardware dependencies.
#[cfg(feature = "afxdp")]
pub mod afxdp;

// Hardware-dependent DPDK modules will be added under feature flags
// as they are refactored into a clean library API (see roadmap M1).
//
// #[cfg(feature = "dpdk")]
// pub mod flow;