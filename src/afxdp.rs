// SPDX-License-Identifier: MIT OR Apache-2.0

//! AF_XDP zero-copy packet capture.
//!
//! Binds an AF_XDP socket in zero-copy mode to a specific NIC queue and streams
//! received frame descriptors to a consumer via a lock-free SPSC ring. The UMEM
//! is allocated with hugepages (MADV_HUGEPAGE) and locked (mlock) to avoid page
//! faults in the hot path. No allocations occur in the receive loop.
//!
//! Design notes:
//! - Two-phase startup: `init_sync` performs all blocking setup (socket bind,
//!   UMEM mmap, madvise/mlock) on the calling thread; `run_loop` then moves the
//!   ready state into a worker pinned to an isolated core, so the worker enters
//!   the packet loop with zero initialization cost and no startup race.
//! - The receive loop returns frame descriptors through `g_prod`; the consumer
//!   is expected to return processed descriptors via the `r_cons` ring so frames
//!   can be recycled into the fill queue. The capture layer itself does not
//!   interpret packet contents.
//!
//! TODO (library API): the NIC queue id is currently a module constant
//! (`GOSSIP_QUEUE_ID`). For general reuse it should be a parameter of
//! `AfXdpGossipFilter::new`. Left as-is here to avoid an API change mid-refactor;
//! tracked in the roadmap.

use std::arch::x86_64::*;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::thread;
use core_affinity::CoreId;
use ringbuf::{
    traits::*,
    wrap::caching::{CachingProd, CachingCons},
    HeapRb,
};
use xsk_rs::{
    config::{SocketConfig, UmemConfig, Interface, BindFlags, FrameSize},
    umem::{Umem, frame::FrameDesc},
    socket::Socket,
    FillQueue, CompQueue, RxQueue, TxQueue,
};
use std::ptr::NonNull;

const GOSSIP_QUEUE_ID: u32 = 14;
const UMEM_FRAME_COUNT: u32 = 4096;
const RX_BATCH_SIZE: usize = 64;
const COMP_BATCH_SIZE: usize = 32;
const FRAME_MASK: usize = !4095;

static UMEM_BASE_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

/// A pointer into the zero-copy DMA region (the UMEM base).
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct DmaRegion(pub NonNull<u8>);

unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    #[inline(always)]
    pub fn new(ptr: *mut u8) -> Self {
        let non_null = NonNull::new(ptr).expect("DmaRegion created from null pointer");
        Self(non_null)
    }

    #[inline(always)]
    pub fn as_ptr(self) -> *const u8 {
        self.0.as_ptr()
    }

    /// Prefetch two cache lines at `offset` into L1 (frame header + next line).
    #[inline(always)]
    pub fn prefetch_at(self, offset: usize) {
        unsafe {
            _mm_prefetch(self.0.as_ptr().add(offset) as *const i8, _MM_HINT_T0);
            _mm_prefetch(self.0.as_ptr().add(offset).add(64) as *const i8, _MM_HINT_T0);
        }
    }

    /// View `len` bytes at `offset` as a slice. Caller must ensure the range is
    /// within the mapped UMEM and that the frame is owned for the duration.
    #[inline(always)]
    pub unsafe fn slice(self, offset: usize, len: usize) -> &'static [u8] {
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().add(offset), len) }
    }
}

#[inline(always)]
pub fn get_umem_base_ptr() -> *const u8 {
    UMEM_BASE_PTR.load(Ordering::Acquire) as *const u8
}

#[inline(always)]
pub fn get_umem_base_dma() -> Option<DmaRegion> {
    let ptr = UMEM_BASE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(DmaRegion::new(ptr))
    }
}

/// A small fixed-capacity ring of frame descriptors pending return to the fill
/// queue. Capacity must be a power of two (mask-based wraparound). No heap
/// activity after construction.
struct RingPocket {
    data: Box<[FrameDesc]>,
    head: usize,
    len: usize,
    capacity: usize,
}

impl RingPocket {
    #[inline(always)]
    fn new(capacity: usize) -> Self {
        Self {
            data: vec![FrameDesc::default(); capacity].into_boxed_slice(),
            head: 0,
            len: 0,
            capacity,
        }
    }

    #[inline(always)]
    fn push(&mut self, desc: FrameDesc) {
        let tail = (self.head + self.len) & (self.capacity - 1);
        self.data[tail] = desc;
        self.len += 1;
    }

    /// Drain as many descriptors as the fill queue accepts, handling the ring
    /// wraparound in at most two contiguous slices.
    #[inline(always)]
    fn produce_into(&mut self, fill_q: &mut FillQueue) {
        if self.len == 0 { return; }
        let first_chunk_len = std::cmp::min(self.len, self.capacity - self.head);
        let first_slice = &self.data[self.head..self.head + first_chunk_len];
        let produced_first = unsafe { fill_q.produce(first_slice) };
        if produced_first == 0 { return; }
        if produced_first < first_chunk_len {
            self.head = (self.head + produced_first) & (self.capacity - 1);
            self.len -= produced_first;
            return;
        }
        let remaining_to_produce = self.len - first_chunk_len;
        if remaining_to_produce > 0 {
            let second_slice = &self.data[0..remaining_to_produce];
            let produced_second = unsafe { fill_q.produce(second_slice) };
            let total_produced = produced_first + produced_second;
            self.head = (self.head + total_produced) & (self.capacity - 1);
            self.len -= total_produced;
        } else {
            self.head = (self.head + produced_first) & (self.capacity - 1);
            self.len -= produced_first;
        }
    }
}

/// Fully initialized AF_XDP resources, created on the main thread and moved into
/// the worker. Holds the UMEM (munmap on drop), the four queues, the DMA base,
/// and the initial frame descriptors.
pub struct AfXdpState {
    /// RAII holder: dropping AfXdpState munmaps the UMEM region.
    /// Not read directly; lifetime is managed via Drop.
    _umem: Umem,
    fill_q: FillQueue,
    comp_q: CompQueue,
    rx_q: RxQueue,
    tx_q: TxQueue,
    umem_base: DmaRegion,
    descs: Vec<FrameDesc>,
    iface: String,
    core_id: CoreId,
}

unsafe impl Send for AfXdpState {}

/// AF_XDP capture front-end. Owns the SPSC rings to/from the consumer.
pub struct AfXdpGossipFilter {
    iface: String,
    stop_signal: &'static AtomicBool,
    g_prod: Option<CachingProd<&'static HeapRb<FrameDesc>>>,
    r_cons: Option<CachingCons<&'static HeapRb<FrameDesc>>>,
}

impl AfXdpGossipFilter {
    pub fn new(
        iface: String,
        stop_signal: &'static AtomicBool,
        g_prod: CachingProd<&'static HeapRb<FrameDesc>>,
        r_cons: CachingCons<&'static HeapRb<FrameDesc>>,
    ) -> Self {
        Self {
            iface,
            stop_signal,
            g_prod: Some(g_prod),
            r_cons: Some(r_cons),
        }
    }

    /// Phase 1: synchronous initialization (run on the main thread).
    ///
    /// Performs all blocking setup deterministically: UMEM allocation, zero-copy
    /// socket bind, queue creation, and madvise/mlock of the UMEM region. Returns
    /// a ready `AfXdpState` plus the `DmaRegion` base for the consumer.
    ///
    /// Doing this here (rather than inside the worker) avoids startup races and
    /// keeps madvise/mlock off the isolated core.
    pub fn init_sync(&mut self, core_id: CoreId) -> anyhow::Result<(AfXdpState, DmaRegion)> {
        tracing::info!(
            "AF_XDP sync init on iface {} queue {}",
            self.iface, GOSSIP_QUEUE_ID
        );

        let umem_config = UmemConfig::builder()
            .frame_size(FrameSize::new(4096).expect("Invalid frame size"))
            .build()
            .expect("UmemConfig build failed");

        let (mut umem, descs) = Umem::new(
            umem_config,
            std::num::NonZeroU32::new(UMEM_FRAME_COUNT).unwrap(),
            false,
        ).expect("Umem allocation failed");

        let iface: Interface = self.iface.parse().expect("Invalid interface name");
        let config = SocketConfig::builder()
            .bind_flags(BindFlags::XDP_ZEROCOPY)
            .build();

        let (tx_q, rx_q, queues): (TxQueue, RxQueue, Option<(FillQueue, CompQueue)>) = unsafe {
            Socket::new(config, &mut umem, &iface, GOSSIP_QUEUE_ID)
                .expect("XDP_ZEROCOPY socket binding failed")
        };
        let (fill_q, comp_q) = queues.expect("Queue creation failed");

        // UMEM base accounting for XDP headroom (256 bytes reserved by XDP).
        // umem_base = data.as_ptr() - first_frame.addr() - headroom.len()
        let first_frame = &descs[0];
        let (headroom, data) = unsafe { umem.frame(first_frame) };
        let umem_base_addr = data.as_ptr() as usize
            - first_frame.addr()
            - headroom.len();
        let umem_base = umem_base_addr as *mut u8;

        let last_frame = &descs[descs.len() - 1];
        let (_, d_last) = unsafe { umem.frame(last_frame) };
        let end_ptr = unsafe { d_last.as_ptr().add(d_last.len()) };
        let umem_size = end_ptr as usize - umem_base_addr;

        // Publish base into the global AtomicPtr (compatibility accessor).
        UMEM_BASE_PTR.store(umem_base, Ordering::Release);

        tracing::info!("UMEM base published: {:p}, size: {} bytes", umem_base, umem_size);

        #[cfg(target_os = "linux")]
        unsafe {
            let raw_ptr = umem_base as *mut libc::c_void;
            let ret_madvise = libc::madvise(raw_ptr, umem_size, libc::MADV_HUGEPAGE);
            let ret_mlock = libc::mlock(raw_ptr, umem_size);
            tracing::info!(
                "UMEM THP+mlock: madvise={}, mlock={} (0=OK)",
                ret_madvise, ret_mlock
            );
        }

        let dma_region = DmaRegion::new(umem_base);

        tracing::info!(
            "AF_XDP sync init complete: base={:p}, size={} bytes, RX fd={:?}, TX fd={:?}",
            umem_base, umem_size, rx_q.fd(), tx_q.fd()
        );

        let state = AfXdpState {
            _umem: umem,
            fill_q,
            comp_q,
            rx_q,
            tx_q,
            umem_base: dma_region,
            descs,
            iface: self.iface.clone(),
            core_id,
        };

        Ok((state, dma_region))
    }

    /// Phase 2: spawn the worker, which takes the ready `AfXdpState` by move and
    /// enters the packet loop immediately (zero init cost). The worker pins
    /// itself to `core_id` (intended to be an isolated core).
    ///
    /// Hot loop, per iteration:
    /// 1. Recycle descriptors returned by the consumer (`r_cons`) into pending.
    /// 2. Drain the completion queue into pending.
    /// 3. Consume received frames; forward to the consumer via `g_prod`, or
    ///    recycle if the consumer ring is full (backpressure).
    /// 4. Refill the fill queue from pending.
    /// 5. `pause` when idle to be polite to the core's sibling thread.
    pub fn run_loop(&mut self, mut state: AfXdpState) {
        let stop = self.stop_signal;
        let core_id = state.core_id;
        let iface_name = state.iface.clone();
        let mut gossip_prod = self.g_prod.take().expect("g_prod already consumed");
        let mut return_cons = self.r_cons.take().expect("r_cons already consumed");

        thread::spawn(move || {
            core_affinity::set_for_current(core_id);
            tracing::info!(
                "AF_XDP worker started on core {}: iface {}, queue {}, UMEM base {:p}",
                core_id.id, iface_name, GOSSIP_QUEUE_ID, state.umem_base.as_ptr()
            );

            // Preload pending_fill from the initial descriptors (no allocation).
            let mut pending_fill = RingPocket::new(UMEM_FRAME_COUNT as usize);
            for desc in state.descs {
                pending_fill.push(desc);
            }

            tracing::info!(
                "AF_XDP zero-copy active: iface={}, queue={}, RX fd={:?}, TX fd={:?}, pending={}",
                iface_name, GOSSIP_QUEUE_ID, state.rx_q.fd(), state.tx_q.fd(), pending_fill.len
            );

            let mut batch: [FrameDesc; RX_BATCH_SIZE] = [FrameDesc::default(); RX_BATCH_SIZE];
            let mut comp_batch: [FrameDesc; COMP_BATCH_SIZE] = [FrameDesc::default(); COMP_BATCH_SIZE];

            loop {
                if stop.load(Ordering::Relaxed) { break; }

                // Recycle consumer-returned descriptors (uses set_addr from xsk-rs fork).
                while let Some(mut desc) = return_cons.try_pop() {
                    let clean_addr = desc.addr() & FRAME_MASK;
                    desc.set_addr(clean_addr);
                    pending_fill.push(desc);
                }

                let n_comp = unsafe { state.comp_q.consume(&mut comp_batch) };
                for i in 0..n_comp {
                    let mut desc = comp_batch[i];
                    let clean_addr = desc.addr() & FRAME_MASK;
                    desc.set_addr(clean_addr);
                    pending_fill.push(desc);
                }

                let n_rx = unsafe { state.rx_q.consume(&mut batch) };
                if n_rx > 0 {
                    for i in 0..n_rx {
                        if gossip_prod.try_push(batch[i]).is_err() {
                            // Consumer ring full: recycle the frame instead of dropping silently.
                            let mut desc = batch[i];
                            let clean_addr = desc.addr() & FRAME_MASK;
                            desc.set_addr(clean_addr);
                            pending_fill.push(desc);
                        }
                    }
                }

                pending_fill.produce_into(&mut state.fill_q);

                if n_rx == 0 && n_comp == 0 {
                    std::arch::x86_64::_mm_pause();
                }
            }
        });
    }
}

/// AVX-512 trusted-IP table. 16 u32 IPs compared per instruction.
/// Unlike the 32-byte key case, 4-byte IPs map cleanly onto epi32 lanes, so the
/// comparison is straightforward and correct.
#[repr(C, align(128))]
pub struct AlignedIpTable {
    pub data: [u32; 1024],
}

pub static mut TRUSTED_IPS: AlignedIpTable = AlignedIpTable { data: [0; 1024] };
pub static TRUSTED_IPS_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Returns true if `ip` is in the trusted set. AVX-512 linear scan, 16 IPs per
/// step. Same O(n) caveat as the key whitelist: intended for small trusted sets
/// behind hardware pre-filtering.
#[inline(always)]
pub unsafe fn is_ip_trusted(ip: u32) -> bool {
    let count = TRUSTED_IPS_COUNT.load(Ordering::Relaxed);
    if count == 0 { return false; }
    let target = unsafe { _mm512_set1_epi32(ip as i32) };
    let base_ptr = unsafe { std::ptr::addr_of!(TRUSTED_IPS.data) as *const u32 };
    let mut i = 0;
    unsafe {
        while i < count {
            let chunk = _mm512_load_si512(base_ptr.add(i) as *const _);
            let mask = _mm512_cmpeq_epi32_mask(chunk, target);
            if mask != 0 { return true; }
            i += 16;
        }
    }
    false
}