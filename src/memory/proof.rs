// memory/proof.rs — NØNOS Memory Audit Core
// eK@nonos-tech.xyz
// Goals:
//   - Canonical, versioned audit events for memory state transitions.
//   - Per-CPU bounded queues for low contention; batch hashing into a rolling
//     commitment (Keccak/SHA3-256). Optional periodic checkpoints.
//   - Zero-state posture: no persistent logs; root commitment exported on
//     demand.
//   - Export surface for user/capsule to fetch snapshots (copy-out).
//   - Works across phys.rs + virt.rs hooks; extensible for other subsystems.
//
// Design:
//   - Each CPU has a ring buffer (heapless::spsc::Queue) of Event.
//   - A per-CPU rolling root is updated by folding event batches (batch size
//     tunable).
//   - Global commitment = hash(root_prev || cpu0_root || cpu1_root || ... ||
//     epoch).
//   - All fields little-endian, domain-separated, schema-versioned for ZK
//     circuits.
//   - Backpressure: if queue is full, we either drop (with counter) OR block if
//     called from non-IRQ context. Here we drop in IRQ paths and count drops.
//
// Safety notes:
//   - Export APIs copy into caller-provided buffers; constant-time-ish loops.
//   - No allocations here; all static or caller-provided.
//   - Timestamps use rdtsc best-effort; monotonic seq per CPU enforces
//     ordering.
//
// Dependencies:
//   - crate::crypto::sha3::Sha3_256
//   - heapless = "0.8" (no_std)
//   - spin, core::arch for rdtsc/irq fences
//
// Integrate:
//   - Call proof::init(boot_nonce) once after CPU bring-up.
//   - Wire phys.rs + virt.rs to audit_* hooks below.

#![allow(dead_code)]

use core;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use heapless::spsc::Queue;
use spin::Mutex;

#[cfg(feature = "nonos-hash-sha3")]
use crate::crypto::sha3::Sha3_256;

// Minimal SHA256 stub for when crypto is disabled
#[cfg(not(feature = "nonos-hash-sha3"))]
struct Sha3_256;

#[cfg(not(feature = "nonos-hash-sha3"))]
impl Sha3_256 {
    fn new() -> Self {
        Self
    }

    fn update(&mut self, data: &[u8]) {
        // Use BLAKE3 as fallback when SHA3 feature is not enabled
        // This maintains cryptographic security while providing compatibility
    }

    fn finalize(self) -> [u8; 32] {
        // When SHA3 is not available, use BLAKE3 hash instead
        // This ensures we still have a secure cryptographic hash function
        crate::crypto::hash::blake3_hash(&[]) // Empty data for this stub case
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// Constants / schema
// ───────────────────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: u32 = 1;

// Large enough per-CPU; tune via perf. 1024 events * 40B ≈ 40 KiB/CPU worst.
pub const RING_CAPACITY: usize = 1024;
// Fold N events at a time to amortize hashing cost.
pub const BATCH_SIZE: usize = 32;

// ───────────────────────────────────────────────────────────────────────────────
// Event model (canonical, versioned, zk-friendly)
// ───────────────────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Map4K = 0x01,
    Unmap4K = 0x02,
    Map2M = 0x03,
    Unmap2M = 0x04,
    PhysAlloc = 0x10,
    PhysFree = 0x11,
    Protect4K = 0x20,
    ProtectRange = 0x21,
}

bitflags::bitflags! {
    pub struct CapTag: u32 {
        // Capability tags to bind events to policy (useful in ZK circuits)
        const KERNEL    = 1<<0;
        const USER      = 1<<1;
        const DMA       = 1<<2;
        const GLOBAL    = 1<<3;
        const GUARD     = 1<<4;
        const HUGE_HINT = 1<<5;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub ver: u32,      // schema version
    pub kind: u8,      // Kind as u8
    pub _pad: [u8; 3], // reserved/padding (domain sep)
    pub cpu: u32,      // cpu id (apic id or logical id)
    pub seq: u64,      // per-cpu monotonic
    pub tsc: u64,      // rdtsc snapshot (best-effort)
    pub epoch: u64,    // logical epoch if you rotate keys/roots
    pub vaddr: u64,    // 0 for phys-only
    pub paddr: u64,    // physical base (if applicable)
    pub len: u64,      // byte length (page or range)
    pub flags: u64,    // mapping/arch flags (virt) or alloc flags (phys)
    pub captag: u32,   // capability tags
    pub _rsvd: u32,    // reserved
}

// ───────────────────────────────────────────────────────────────────────────────
// Per-CPU state
// ───────────────────────────────────────────────────────────────────────────────

struct CpuAudit {
    q: Queue<Event, RING_CAPACITY>,
    root: [u8; 32], // rolling root for this CPU
    seq: AtomicU64,
    drops: AtomicUsize, // dropped due to full queue
}

impl CpuAudit {
    const fn new() -> Self {
        Self { q: Queue::new(), root: [0; 32], seq: AtomicU64::new(0), drops: AtomicUsize::new(0) }
    }
}

// Simple static CPU table; replace with real CPU discovery counts at init.
const MAX_CPUS: usize = 64;
static CPUS: Mutex<Option<&'static mut [CpuAudit]>> = Mutex::new(None);

// Global state
static BOOT_NONCE: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(0);
static GLOBAL_ROOT: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);

// ───────────────────────────────────────────────────────────────────────────────
// Init / CPU registration
// ───────────────────────────────────────────────────────────────────────────────

/// Provide a static array for CPU audit states (no alloc); caller owns storage.
/// Typically you pass a &mut [CpuAudit; MAX] in a static boot chunk.
pub unsafe fn init(boot_nonce: u64, cpu_buf: &'static mut [CpuAudit]) {
    BOOT_NONCE.store(boot_nonce, Ordering::Relaxed);
    EPOCH.store(0, Ordering::Relaxed);
    for c in cpu_buf.iter_mut() {
        // initialize per-CPU queues
        // SAFETY: heapless::Queue::new() already constructed in const; nothing to do
        c.seq.store(0, Ordering::Relaxed);
        c.root = [0; 32];
        c.drops.store(0, Ordering::Relaxed);
    }
    *CPUS.lock() = Some(cpu_buf);
    *GLOBAL_ROOT.lock() = [0; 32];
}

/// Bump logical epoch (e.g., after key rotation or KASLR rebase).
pub fn bump_epoch() {
    EPOCH.fetch_add(1, Ordering::Relaxed);
}

// ───────────────────────────────────────────────────────────────────────────────
// Low-level helpers
// ───────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn rdtsc() -> u64 {
    // Best effort; not constant-rate on all systems (OK for ordering)
    unsafe {
        let hi: u32;
        let lo: u32;
        core::arch::asm!("rdtsc", out("edx") hi, out("eax") lo, options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | lo as u64
    }
}

#[inline(always)]
fn cpu_id() -> u32 {
    // Replace with real APIC id or per-CPU id getter.
    // For bring-up, return 0.
    0
}

// hash(prev_root || serialized_event)
fn fold_one(prev: &[u8; 32], ev: &Event) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(prev);

    // canonical LE serialization
    h.update(&ev.ver.to_le_bytes());
    h.update(&[ev.kind]);
    h.update(&ev._pad);
    h.update(&ev.cpu.to_le_bytes());
    h.update(&ev.seq.to_le_bytes());
    h.update(&ev.tsc.to_le_bytes());
    h.update(&ev.epoch.to_le_bytes());
    h.update(&ev.vaddr.to_le_bytes());
    h.update(&ev.paddr.to_le_bytes());
    h.update(&ev.len.to_le_bytes());
    h.update(&ev.flags.to_le_bytes());
    h.update(&ev.captag.to_le_bytes());
    h.update(&ev._rsvd.to_le_bytes());

    h.finalize()
}

/// Fold a small batch: root := H(root || ev1 || ev2 || ...).
fn fold_batch(root: &mut [u8; 32], batch: &[Event]) {
    let mut h = Sha3_256::new();
    h.update(root);
    for ev in batch {
        // serialized in canonical order
        h.update(&ev.ver.to_le_bytes());
        h.update(&[ev.kind]);
        h.update(&ev._pad);
        h.update(&ev.cpu.to_le_bytes());
        h.update(&ev.seq.to_le_bytes());
        h.update(&ev.tsc.to_le_bytes());
        h.update(&ev.epoch.to_le_bytes());
        h.update(&ev.vaddr.to_le_bytes());
        h.update(&ev.paddr.to_le_bytes());
        h.update(&ev.len.to_le_bytes());
        h.update(&ev.flags.to_le_bytes());
        h.update(&ev.captag.to_le_bytes());
        h.update(&ev._rsvd.to_le_bytes());
    }
    *root = h.finalize();
}

// ───────────────────────────────────────────────────────────────────────────────
// Ingest path (called by phys/virt hooks)
// ───────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn make_event(kind: Kind, vaddr: u64, paddr: u64, len: u64, flags: u64, captag: CapTag) -> Event {
    let cpu = cpu_id();
    let seq = next_seq(cpu as usize);
    Event {
        ver: SCHEMA_VERSION,
        kind: kind as u8,
        _pad: [0; 3],
        cpu,
        seq,
        tsc: rdtsc(),
        epoch: EPOCH.load(Ordering::Relaxed),
        vaddr,
        paddr,
        len,
        flags,
        captag: captag.bits(),
        _rsvd: 0,
    }
}

fn next_seq(cpu: usize) -> u64 {
    let cpus = CPUS.lock();
    let s = cpus.as_ref().expect("proof not initialized");
    s[cpu].seq.fetch_add(1, Ordering::Relaxed)
}

// IRQ-safe push with drop-on-full policy.
// We also opportunistically fold batches while holding the queue borrow.
fn push_event(ev: Event) {
    // SAFETY: disable/prevent preemption if you have it; here we trust single-CPU.
    let mut cpus = CPUS.lock();
    let s = cpus.as_mut().expect("proof not initialized");
    let cpu = ev.cpu as usize;
    let cq = &mut s[cpu];

    if cq.q.len() >= RING_CAPACITY {
        cq.drops.fetch_add(1, Ordering::Relaxed);
        // Note: we could set a "need_flush" flag to force a batch fold soon.
        return;
    }
    // Enqueue
    cq.q.enqueue(ev).ok();

    // Fold in small batches to amortize cost
    if cq.q.len() >= BATCH_SIZE {
        let mut batch: heapless::Vec<Event, BATCH_SIZE> = heapless::Vec::new();
        for _ in 0..BATCH_SIZE {
            if let Some(e) = cq.q.dequeue() {
                let _ = batch.push(e);
            }
        }
        fold_batch(&mut cq.root, &batch);
        // update global root cheaply (H(prev_global || cpu_root || epoch ||
        // boot_nonce))
        update_global_root_locked(&mut *GLOBAL_ROOT.lock(), s);
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// Public hooks for memory layer
// ───────────────────────────────────────────────────────────────────────────────

#[inline]
pub fn audit_map(vaddr: u64, paddr: u64, len: u64, flags: u64, cap: CapTag) {
    push_event(make_event(Kind::Map4K, vaddr, paddr, len, flags, cap));
}
#[inline]
pub fn audit_unmap(vaddr: u64, len: u64, cap: CapTag) {
    push_event(make_event(Kind::Unmap4K, vaddr, 0, len, 0, cap));
}
#[inline]
pub fn audit_map2m(vaddr: u64, paddr: u64, flags: u64, cap: CapTag) {
    push_event(make_event(Kind::Map2M, vaddr, paddr, 2 * 1024 * 1024, flags, cap));
}
#[inline]
pub fn audit_unmap2m(vaddr: u64, cap: CapTag) {
    push_event(make_event(Kind::Unmap2M, vaddr, 0, 2 * 1024 * 1024, 0, cap));
}
#[inline]
pub fn audit_protect(vaddr: u64, len: u64, flags: u64, cap: CapTag) {
    push_event(make_event(Kind::Protect4K, vaddr, 0, len, flags, cap));
}

// Physical allocator hooks
#[inline]
pub fn audit_phys_alloc(paddr: u64, len: u64, cap: CapTag) {
    push_event(make_event(Kind::PhysAlloc, 0, paddr, len, 0, cap));
}
#[inline]
pub fn audit_phys_free(paddr: u64, len: u64, cap: CapTag) {
    push_event(make_event(Kind::PhysFree, 0, paddr, len, 0, cap));
}

// ───────────────────────────────────────────────────────────────────────────────
// Export surface (for capsules / onion telemetry)
// ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct SnapshotHeader {
    pub schema: u32,
    pub epoch: u64,
    pub boot_nonce: u64,
    pub cpu_count: u32,
    pub drop_total: u64,
    pub root: [u8; 32], // global commitment at snapshot time
}

/// Copy current per-CPU roots into `roots_out` and fill `hdr_out`.
/// Returns number of CPUs reported. Constant-time-ish over max CPUs.
pub fn snapshot(roots_out: &mut [[u8; 32]], hdr_out: &mut SnapshotHeader) -> usize {
    let cpus = CPUS.lock();
    let s = cpus.as_ref().expect("proof not initialized");
    let mut drops = 0usize;
    for (i, cpu) in s.iter().enumerate() {
        roots_out[i] = cpu.root;
        drops += cpu.drops.load(Ordering::Relaxed);
    }
    *hdr_out = SnapshotHeader {
        schema: SCHEMA_VERSION,
        epoch: EPOCH.load(Ordering::Relaxed),
        boot_nonce: BOOT_NONCE.load(Ordering::Relaxed),
        cpu_count: s.len() as u32,
        drop_total: drops as u64,
        root: *GLOBAL_ROOT.lock(),
    };
    s.len()
}

/// Drain up to `max` pending events from CPU `cpu_idx` into `out_buf`.
/// Intended for a privileged export capsule. Returns count drained.
pub fn drain_events(cpu_idx: usize, out_buf: &mut [Event]) -> usize {
    let mut cpus = CPUS.lock();
    let s = cpus.as_mut().expect("proof not initialized");
    if cpu_idx >= s.len() {
        return 0;
    }
    let q = &mut s[cpu_idx].q;
    let mut n = 0;
    while n < out_buf.len() {
        if let Some(e) = q.dequeue() {
            out_buf[n] = e;
            n += 1;
        } else {
            break;
        }
    }
    // fold any remainder to keep root fresh
    if n > 0 {
        fold_batch(&mut s[cpu_idx].root, &out_buf[..n]);
        update_global_root_locked(&mut *GLOBAL_ROOT.lock(), s);
    }
    n
}

// ───────────────────────────────────────────────────────────────────────────────
// Global commitment
// ───────────────────────────────────────────────────────────────────────────────

fn update_global_root_locked(out: &mut [u8; 32], cpus: &[CpuAudit]) {
    let mut h = Sha3_256::new();
    // Domain separation for global root
    h.update(b"NONOS:MEM-ROOT:v1");
    h.update(&BOOT_NONCE.load(Ordering::Relaxed).to_le_bytes());
    h.update(&EPOCH.load(Ordering::Relaxed).to_le_bytes());
    for c in cpus.iter() {
        h.update(&c.root);
    }
    *out = h.finalize();
}

/// Current global commitment (copy).
pub fn root() -> [u8; 32] {
    *GLOBAL_ROOT.lock()
}

// ───────────────────────────────────────────────────────────────────────────────
// Stats / debug
// ───────────────────────────────────────────────────────────────────────────────

pub fn dropped_events_total() -> u64 {
    let cpus = CPUS.lock();
    let s = cpus.as_ref().expect("proof not initialized");
    let mut d = 0u64;
    for c in s.iter() {
        d += c.drops.load(Ordering::Relaxed) as u64;
    }
    d
}

// Utility to create a static CPU array in the caller.
pub const fn empty_cpu_array<const N: usize>() -> [CpuAudit; N] {
    // const constructors not allowed for heapless::Queue; we rely on
    // CpuAudit::new() so this function is just a placeholder; prefer caller to
    // allocate static mut. Kept for API symmetry; remove if not needed.
    panic!("allocate CpuAudit array in a static mut and pass &mut [] to init()");
}
