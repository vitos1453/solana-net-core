// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};
use std::arch::x86_64::*;
use std::ptr::addr_of;

/// 128-byte alignment to avoid false sharing of the atomic counter.
#[repr(align(128))]
pub struct ValidatorWhitelist {
    pub count: AtomicUsize,
}
pub static mut WHITELIST_KEYS: [[u8; 32]; 2048] = [[0u8; 32]; 2048];
impl ValidatorWhitelist {
    /// Correct AVX-512 validator membership check.
    /// Tests whether `pubkey` (32 bytes) is present in WHITELIST_KEYS,
    /// processing two keys per iteration.
    ///
    /// Previous buggy version: `_mm512_loadu_si512(pubkey)` read 64 bytes from a
    /// 32-byte key (out-of-bounds, UB), and `mask == 0xFFFF..FF` required TWO
    /// keys to match simultaneously, so it almost always returned false even
    /// for keys that were present.
    ///
    /// Fix: broadcast the 32-byte key into both halves of a ZMM register:
    /// `target = [pubkey | pubkey]`. Comparing against a pair `[key_i | key_{i+1}]`,
    /// the low 32 bits of the mask mean key_i matched, the high 32 bits mean
    /// key_{i+1} matched. Correct for both positions.
    ///
    /// Safety: we use `_mm512_loadu_si512` (unaligned) for `keys_chunk` because
    /// the `[[u8;32];2048]` array is 32-byte aligned, not 64; an aligned load
    /// would risk a fault. The tail beyond `count` is zero-filled (static
    /// buffer), and a zero key never matches a real lookup key, so an odd
    /// `count` is safe.
    #[inline(always)]
    pub unsafe fn is_trusted_avx512(&self, pubkey: &[u8; 32]) -> bool {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 { return false; }

        let base_ptr = addr_of!(WHITELIST_KEYS) as *const [u8; 32];

        // Broadcast the 32-byte key into 64 bytes: target = [pubkey | pubkey].
        // Explicit unsafe blocks (Rust 2024: unsafe_op_in_unsafe_fn) for clean OSS.
        let target = unsafe {
            let target_lo = _mm256_loadu_si256(pubkey.as_ptr() as *const __m256i);
            _mm512_inserti64x4(_mm512_castsi256_si512(target_lo), target_lo, 1)
        };

        let mut i = 0;
        while i < count {
            // Two keys (64 bytes) at a time; unaligned load (no 64-byte align req).
            let mask: u64 = unsafe {
                let keys_chunk = _mm512_loadu_si512(base_ptr.add(i) as *const _);
                _mm512_cmpeq_epi8_mask(keys_chunk, target)
            };
            // Low 32 bits == key_i matched; high 32 bits == key_{i+1} matched.
            if (mask & 0xFFFF_FFFF) == 0xFFFF_FFFF || (mask >> 32) == 0xFFFF_FFFF {
                return true;
            }
            i += 2;
        }
        false
    }
    #[inline(always)]
    pub fn is_trusted(&self, pubkey: &[u8; 32]) -> bool {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 { return false; }
        let slice = unsafe { &WHITELIST_KEYS[..count] };
        slice.binary_search_by(|probe| probe.as_slice().cmp(pubkey.as_slice())).is_ok()
    }
    #[inline(always)]
    pub fn set_count(&self, count: usize) {
        self.count.store(count.min(2048), Ordering::Release);
    }
}
pub static WHITELIST: ValidatorWhitelist = ValidatorWhitelist {
    count: AtomicUsize::new(0),
};
pub fn update_static_keys(sorted_keys: &[[u8; 32]]) {
    let count = sorted_keys.len().min(2048);
    unsafe {
        for i in 0..count {
            WHITELIST_KEYS[i] = sorted_keys[i];
        }
    }
    WHITELIST.set_count(count);
}

#[cfg(test)]
mod whitelist_bench {
    use super::*;
    use std::arch::x86_64::_rdtsc;

    fn make_key(seed: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15);
        for chunk in k.chunks_mut(8) {
            x ^= x >> 30; x = x.wrapping_mul(0xBF58476D1CE4E5B9);
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        k
    }

    fn setup(n: usize) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8;32]> = (0..n as u64).map(make_key).collect();
        keys.sort();
        update_static_keys(&keys);
        keys
    }

    /// Correctness test: compare the AVX-512 path against the scalar
    /// (binary_search) reference on the same data.
    #[test]
    fn whitelist_correctness() {
        let keys = setup(512);
        let mut mismatches = 0;
        let mut avx_found = 0;
        let mut scalar_found = 0;

        // 1. Keys that ARE present: both versions must return true.
        for k in &keys {
            let avx = unsafe { WHITELIST.is_trusted_avx512(k) };
            let scalar = WHITELIST.is_trusted(k);
            if avx { avx_found += 1; }
            if scalar { scalar_found += 1; }
            if avx != scalar {
                mismatches += 1;
                if mismatches <= 5 {
                    println!("[MISMATCH] key in list: avx={} scalar={}", avx, scalar);
                }
            }
        }

        // 2. Keys that are NOT present: both must return false.
        for seed in 100_000..100_512u64 {
            let k = make_key(seed);
            let avx = unsafe { WHITELIST.is_trusted_avx512(&k) };
            let scalar = WHITELIST.is_trusted(&k);
            if avx != scalar {
                mismatches += 1;
                if mismatches <= 10 {
                    println!("[MISMATCH] key NOT in list: avx={} scalar={}", avx, scalar);
                }
            }
        }

        println!("[CORRECTNESS] keys in list: {}", keys.len());
        println!("[CORRECTNESS] avx found {} / scalar found {} (of {} present)",
                 avx_found, scalar_found, keys.len());
        println!("[CORRECTNESS] mismatches (avx vs scalar): {}", mismatches);

        assert_eq!(scalar_found, keys.len(), "scalar binary_search missed keys (setup bug)");
        assert_eq!(mismatches, 0,
            "AVX-512 path disagrees with scalar reference! SIMD logic bug.");
    }

    /// Cycle measurement via rdtsc, with black_box and warmup. Three scenarios
    /// plus a comparison with binary_search: AVX scan is O(n), bin_search O(log n).
    #[test]
    fn whitelist_bench_rdtsc() {
        let keys = setup(512);
        let first   = keys[0];          // early exit after first iteration
        let middle  = keys[256];        // scan to the middle (~128 iterations)
        let absent  = make_key(999_999);// full scan (256 iterations)

        // AVX-512 warmup.
        for _ in 0..100_000 {
            let _ = std::hint::black_box(unsafe {
                WHITELIST.is_trusted_avx512(std::hint::black_box(&middle))
            });
        }

        const ITERS: u64 = 1_000_000;

        macro_rules! bench_avx {
            ($key:expr) => {{
                let t0 = unsafe { _rdtsc() };
                for _ in 0..ITERS {
                    let r = unsafe { WHITELIST.is_trusted_avx512(std::hint::black_box($key)) };
                    std::hint::black_box(r);
                }
                let t1 = unsafe { _rdtsc() };
                (t1 - t0) as f64 / ITERS as f64
            }};
        }
        macro_rules! bench_scalar {
            ($key:expr) => {{
                let t0 = unsafe { _rdtsc() };
                for _ in 0..ITERS {
                    let r = WHITELIST.is_trusted(std::hint::black_box($key));
                    std::hint::black_box(r);
                }
                let t1 = unsafe { _rdtsc() };
                (t1 - t0) as f64 / ITERS as f64
            }};
        }

        let avx_first  = bench_avx!(&first);
        let avx_middle = bench_avx!(&middle);
        let avx_absent = bench_avx!(&absent);
        let sc_first   = bench_scalar!(&first);
        let sc_middle  = bench_scalar!(&middle);
        let sc_absent  = bench_scalar!(&absent);

        println!("=== WHITELIST BENCH: 512 keys, {} iters, TSC cycles/call ===", ITERS);
        println!("                       AVX-512 (O(n) scan)   scalar (O(log n) bin_search)");
        println!("first position [0]:    {:>8.1}             {:>8.1}", avx_first,  sc_first);
        println!("middle       [256]:    {:>8.1}             {:>8.1}", avx_middle, sc_middle);
        println!("miss (absent):         {:>8.1}             {:>8.1}", avx_absent, sc_absent);
        println!();
        println!("AVX throughput on a FULL scan:");
        println!("  {:.1} cycles / 256 pairs = {:.2} cycles per key-pair ({:.2} cycles/key)",
                 avx_absent, avx_absent/256.0, avx_absent/512.0);
        println!();
        println!("rdtsc = reference TSC cycles, not core cycles. ns = cycles / freq_GHz.");
        println!("Run `lscpu | grep MHz` and divide by frequency for nanoseconds.");
        println!();
        println!("NOTE: the AVX comparison is fast (~{:.1} cycles/pair), but the scan is O(n).",
                 avx_absent/256.0);
        println!("For large sets / miss-heavy workloads, O(log n) bin_search wins on misses.");
    }
}
