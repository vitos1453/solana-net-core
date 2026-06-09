// SPDX-License-Identifier: MIT OR Apache-2.0

//! # solana-net-core
//!
//! Low-latency network primitives for Solana: kernel-bypass packet capture,
//! hardware tail-drop, and SIMD validator filtering.
//!
//! See the README for architecture, benchmarks, and roadmap.
//!
//! ## Modules
//! - [`whitelist`]: AVX-512 validator-key membership check (implemented, tested).
//! - `afxdp` (feature `afxdp`): AF_XDP zero-copy packet capture.
//!
//! Hardware-dependent modules are gated behind feature flags so the crate's core
//! (whitelist) builds on any machine without pulling in AF_XDP/DPDK toolchains.

pub mod whitelist;

#[cfg(feature = "afxdp")]
pub mod afxdp;

// DPDK flow module is added under the `dpdk` feature once refactored into a
// clean library API (see roadmap M1).
//
// #[cfg(feature = "dpdk")]
// pub mod flow;
