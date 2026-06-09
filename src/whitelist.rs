use std::sync::atomic::{AtomicUsize, Ordering};
use std::arch::x86_64::*;
use std::ptr::addr_of;
// === TIER 0.1% FIX: Выравнивание на 128 байт для исключения False Sharing ===
#[repr(align(128))]
pub struct ValidatorWhitelist {
    pub count: AtomicUsize,
}
pub static mut WHITELIST_KEYS: [[u8; 32]; 2048] = [[0u8; 32]; 2048];
impl ValidatorWhitelist {
    /// === TIER 0.1% FIX: Корректная AVX-512 проверка валидатора ===
    /// Проверяет, есть ли pubkey (32 байта) в WHITELIST_KEYS, по 2 ключа за итерацию.
    ///
    /// БЫЛО (баг): _mm512_loadu_si512(pubkey) читал 64 байта от 32-байтного ключа
    /// (out-of-bounds, UB), и mask==0xFFFF..FF требовал совпадения ДВУХ ключей
    /// одновременно — функция почти всегда возвращала false даже для своих ключей.
    ///
    /// СТАЛО: broadcast 32-байтного ключа в обе половины ZMM: target=[pubkey|pubkey].
    /// Сравнение с парой [key_i | key_{i+1}]: младшие 32 бита маски = совпал key_i,
    /// старшие 32 бита = совпал key_{i+1}. Корректно для обеих позиций.
    ///
    /// Безопасность: используем _mm512_loadu_si512 (unaligned) для keys_chunk —
    /// массив [[u8;32];2048] выровнен на 32, не на 64; aligned-load дал бы риск.
    /// Хвост за count заполнен нулями (статический буфер), нулевой ключ не совпадёт
    /// с реальным искомым, поэтому нечётный count безопасен.
    #[inline(always)]
    pub unsafe fn is_trusted_avx512(&self, pubkey: &[u8; 32]) -> bool {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 { return false; }

        let base_ptr = addr_of!(WHITELIST_KEYS) as *const [u8; 32];

        // Broadcast 32-байтного ключа в 64 байта: target = [pubkey | pubkey].
        // Явные unsafe-блоки (Rust 2024: unsafe_op_in_unsafe_fn) — чисто для open-source.
        let target = unsafe {
            let target_lo = _mm256_loadu_si256(pubkey.as_ptr() as *const __m256i);
            _mm512_inserti64x4(_mm512_castsi256_si512(target_lo), target_lo, 1)
        };

        let mut i = 0;
        while i < count {
            // 2 ключа (64 байта) за раз; unaligned load — без требования к 64-align.
            let mask: u64 = unsafe {
                let keys_chunk = _mm512_loadu_si512(base_ptr.add(i) as *const _);
                _mm512_cmpeq_epi8_mask(keys_chunk, target)
            };
            // Младшие 32 бита == key_i совпал; старшие 32 бита == key_{i+1} совпал.
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

    /// ТЕСТ КОРРЕКТНОСТИ — сверяем AVX-512 со скалярной (binary_search).
    #[test]
    fn whitelist_correctness() {
        let keys = setup(512);
        let mut mismatches = 0;
        let mut avx_found = 0;
        let mut scalar_found = 0;

        // 1. Присутствующие ключи — обе версии должны вернуть true.
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

        // 2. Отсутствующие ключи — обе должны вернуть false.
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
        println!("[CORRECTNESS] avx found {} / scalar found {} (из {} присутствующих)",
                 avx_found, scalar_found, keys.len());
        println!("[CORRECTNESS] mismatches (avx vs scalar): {}", mismatches);

        assert_eq!(scalar_found, keys.len(), "scalar binary_search не нашёл все ключи — баг setup");
        assert_eq!(mismatches, 0,
            "AVX-512 версия расходится со скалярной! БАГ в SIMD-логике.");
    }

    /// Замер тактов через rdtsc, с black_box и warmup. ТРИ сценария + сравнение
    /// с binary_search, чтобы видеть: AVX-скан это O(n), а bin_search O(log n).
    #[test]
    fn whitelist_bench_rdtsc() {
        let keys = setup(512);
        let first   = keys[0];          // ранний выход после 1-й итерации
        let middle  = keys[256];        // проход до середины (~128 итераций)
        let absent  = make_key(999_999);// полный проход (256 итераций)

        // Warmup AVX-512.
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

        println!("=== WHITELIST BENCH: 512 ключей, {} итераций, TSC-такты/вызов ===", ITERS);
        println!("                       AVX-512 (O(n) скан)   scalar (O(log n) bin_search)");
        println!("первая позиция [0]:    {:>8.1}             {:>8.1}", avx_first,  sc_first);
        println!("середина     [256]:    {:>8.1}             {:>8.1}", avx_middle, sc_middle);
        println!("промах (absent):       {:>8.1}             {:>8.1}", avx_absent, sc_absent);
        println!();
        println!("AVX пропускная способность на ПОЛНОМ скане:");
        println!("  {:.1} тактов / 256 пар = {:.2} такта на пару ключей ({:.2} такта/ключ)",
                 avx_absent, avx_absent/256.0, avx_absent/512.0);
        println!();
        println!("rdtsc = опорные TSC-такты, не такты ядра. нс = такты / частота_ГГц.");
        println!("Запусти `lscpu | grep MHz` и подели на частоту для наносекунд.");
        println!();
        println!("ВЫВОД: AVX-сравнение быстрое (~{:.1} такта/пара), но скан линейный O(n).",
                 avx_absent/256.0);
        println!("Если whitelist большой/частые промахи — bin_search O(log n) обгонит на промахах.");
    }
}
