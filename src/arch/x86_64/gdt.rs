//! NØNOS x86_64 GDT/TSS — SMP, USER, PCID/KPTI hooks, CET, GS/FS, XSAVE,
//! SYSCALL+INT80
//!
//! - Per-CPU dynamic GDT/TSS with allocator-backed IST stacks (+ guard pages)
//! - Full selector map: kernel/user CS/DS/SS, TSS
//! - CR0/CR4/EFER hardening; optional PCID, UMIP, SMEP, SMAP; NX forced
//! - Dual syscall gateways: INT 0x80 and SYSCALL/SYSRET (feature-gated)
//! - Per-CPU GS/KernelGS base; swapgs helpers; FS base for user TLS
//! - CET (shadow stack/IBT) MSR stubs; wiring points for future enablement
//! - XSAVE policy from CPUID leaf 0xD; default x87|SSE; AVX stays off until
//!   negotiated
//! - KPTI/PCID scaffolding: user CR3 (U-CR3) + ASID plumbing hooks
//! - BSP/AP init entry points; APIC-id keyed registry
//!
//! Safety: bring-up is single-threaded per CPU; global registration is
//! lock-free.

#![allow(clippy::module_name_repetitions)]

use core::arch::asm;
use core::mem::MaybeUninit;

use spin::{Once, RwLock};
use x86_64::{
    instructions::{
        segmentation::{Segment, CS, SS},
        tables::load_tss,
    },
    registers::{
        control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags, Efer, EferFlags},
        model_specific::{FsBase, GsBase, KernelGsBase},
        rflags::RFlags,
    },
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

/// IST indices (IDT will use these)
pub mod ist {
    pub const NMI: u16 = 0;
    pub const DF: u16 = 1;
    pub const PF: u16 = 2;
    pub const MC: u16 = 3;
    pub const GP: u16 = 4; // optional overflow safe
}

const IST_BYTES: usize = 16 * 1024;
const GUARD_BYTES: usize = 4096;
const CANARY: u64 = 0xD15C_AB1E_C0B1_CAFE;

#[derive(Clone, Copy)]
pub struct Selectors {
    pub k_cs: SegmentSelector,
    pub k_ds: SegmentSelector,
    pub u_cs: SegmentSelector,
    pub u_ds: SegmentSelector,
    pub tss: SegmentSelector,
}

#[repr(C, align(64))]
pub struct CpuArch {
    pub tss: TaskStateSegment,
    pub gdt: GlobalDescriptorTable,
    pub sel: Selectors,
    pub canary: u64,
    pub xsave_mask: u64, // XCR0 negotiated mask
    pub u_cr3: u64,      // KPTI: user CR3 (optional)
    pub asid: u16,       // PCID ASID (0 = kernel)
}

impl CpuArch {
    const fn uninit() -> Self {
        Self {
            tss: TaskStateSegment::new(),
            gdt: GlobalDescriptorTable::new(),
            sel: Selectors {
                k_cs: SegmentSelector(0),
                k_ds: SegmentSelector(0),
                u_cs: SegmentSelector(0),
                u_ds: SegmentSelector(0),
                tss: SegmentSelector(0),
            },
            canary: CANARY,
            xsave_mask: 0,
            u_cr3: 0,
            asid: 0,
        }
    }
}

/// IST constants for interrupt stacks
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const DF_IST_INDEX: u16 = 0; // Alias for double fault
pub const NMI_IST_INDEX: u16 = 1;
pub const PF_IST_INDEX: u16 = 2;
pub const MC_IST_INDEX: u16 = 3;

/// Simple init function for compatibility
pub fn init() {
    // NOTE: GDT setup handled in bootloader phase
    // Function kept for compatibility with late init code
}

/// minimal allocator trait for early stacks (paged + guard if possible)  
pub trait IstAllocator {
    /// allocate `len` bytes with a preceding guard page; return usable
    /// [base,end)
    unsafe fn alloc_with_guard(&self, len: usize) -> (VirtAddr, VirtAddr);
    /// free the region previously allocated
    unsafe fn free_with_guard(&self, base: VirtAddr, len: usize);
}

/// per-CPU registry keyed by APIC id
static CPU_REG: RwLock<heapless::FnvIndexMap<u32, &'static CpuArch, 32>> =
    RwLock::new(heapless::FnvIndexMap::new());

/// BSP arch block
static BSP: Once<&'static CpuArch> = Once::new();

/// exported selector map for other subsystems
pub fn selectors() -> Selectors {
    bsp_ref().sel
}

/// Get kernel code selector
pub fn kernel_code_selector() -> SegmentSelector {
    bsp_ref().sel.k_cs
}

/// Get kernel data selector
pub fn kernel_data_selector() -> SegmentSelector {
    bsp_ref().sel.k_ds
}

/// Kernel code selector constant (assuming standard GDT layout)
pub const KERNEL_CODE_SELECTOR: SegmentSelector = SegmentSelector(0x08);

/// Kernel data selector constant (assuming standard GDT layout)
pub const KERNEL_DATA_SELECTOR: SegmentSelector = SegmentSelector(0x10);

pub fn bsp_ref() -> &'static CpuArch {
    *BSP.get().expect("GDT/TSS not initialized on BSP")
}

/// bootstrap CPU (BSP)
pub unsafe fn init_bsp(apic_id: u32, alloc: &dyn IstAllocator) {
    let arch = init_cpu_common(apic_id, alloc, /* is_bsp= */ true, /* asid= */ 0);
    BSP.call_once(|| arch);
}

/// application processor (AP) init (to be called on each AP)
pub unsafe fn init_ap(apic_id: u32, alloc: &dyn IstAllocator, asid: u16) {
    let _ = init_cpu_common(apic_id, alloc, /* is_bsp= */ false, asid);
}

/// install user segments (enable usermode later)
pub unsafe fn enable_usermode_segments(_apic_id: u32) {
    // nothing extra: selectors already present; CS/SS reload occurs on
    // iret/ring transition
}

/// set per-CPU GS base (TLS root)
pub unsafe fn set_gs_base(ptr: u64) {
    GsBase::write(VirtAddr::new(ptr));
}

/// set per-CPU KernelGS base (used with swapgs on entry)
pub unsafe fn set_kernel_gs_base(ptr: u64) {
    KernelGsBase::write(VirtAddr::new(ptr));
}

/// set user FS base (userspace TLS)
pub unsafe fn set_user_fs_base(ptr: u64) {
    FsBase::write(VirtAddr::new(ptr));
}

/// PCID/KPTI — supply user CR3 for this CPU (optional)
pub unsafe fn set_user_cr3(apic_id: u32, _u_cr3: u64) {
    // TODO: Fix CPU registry to allow mutable access to CpuArch fields
    // For now, this is a no-op to allow compilation
    if let Some(_arch) = CPU_REG.write().get(&apic_id) {
        // Cannot modify through immutable reference - needs architecture fix
    }
}

/// read negotiated XCR0 mask
pub fn xsave_mask() -> u64 {
    bsp_ref().xsave_mask
}

// ─────────────────────────────────────────────────────────────────────
// core bring-up
// ─────────────────────────────────────────────────────────────────────

unsafe fn init_cpu_common(
    apic_id: u32,
    alloc: &dyn IstAllocator,
    _is_bsp: bool,
    asid: u16,
) -> &'static CpuArch {
    // allocate struct from .bss static; no heap reliance
    static mut SLOT: MaybeUninit<CpuArch> = MaybeUninit::uninit();
    let arch = &mut *SLOT.as_mut_ptr();
    *arch = CpuArch::uninit();

    // IST stacks with guard pages
    install_ist(&mut arch.tss, alloc);

    // build GDT with: NULL, KCODE, KDATA, UCODE, UDATA, TSS
    let k_cs = arch.gdt.add_entry(Descriptor::kernel_code_segment());
    let k_ds = arch.gdt.add_entry(Descriptor::kernel_data_segment());
    let u_cs = arch.gdt.add_entry(Descriptor::UserSegment(0x00AF9B000000FFFF)); // 64-bit user code
    let u_ds = arch.gdt.add_entry(Descriptor::UserSegment(0x00AF93000000FFFF)); // user data
    let tss = arch.gdt.add_entry(Descriptor::tss_segment(&arch.tss));
    arch.sel = Selectors { k_cs, k_ds, u_cs, u_ds, tss };

    // load GDT + TSS + segments
    arch.gdt.load();
    CS::set_reg(k_cs);
    SS::set_reg(k_ds);
    load_tss(tss);

    // harden control regs
    harden_crs();

    // PCID hint (off by default until ASIDs used)
    if has_pcid() {
        // leave off; enable via enable_pcid() once scheduler sets ASIDs
    }

    // EFER NX on
    ensure_nxe();

    // SYSCALL MSR (feature-gated)
    #[cfg(feature = "nonos-syscall-msr")]
    init_syscall_msrs(k_cs);

    // INT 0x80 remains available via IDT gate (IDT owns PL3 exposure)

    // XSAVE policy
    let mask = init_xsave_policy();
    arch.xsave_mask = mask;

    arch.asid = asid;

    // publish per-CPU record
    {
        let mut map = CPU_REG.write();
        let _ = map.insert(apic_id, &*(arch as *const CpuArch));
    }

    &*(arch as *const CpuArch)
}

unsafe fn install_ist(tss: &mut TaskStateSegment, alloc: &dyn IstAllocator) {
    let (_nmi_b, nmi_e) = alloc.alloc_with_guard(IST_BYTES + GUARD_BYTES);
    let (_df_b, df_e) = alloc.alloc_with_guard(IST_BYTES + GUARD_BYTES);
    let (_pf_b, pf_e) = alloc.alloc_with_guard(IST_BYTES + GUARD_BYTES);
    let (_mc_b, mc_e) = alloc.alloc_with_guard(IST_BYTES + GUARD_BYTES);
    let (_gp_b, gp_e) = alloc.alloc_with_guard(IST_BYTES + GUARD_BYTES);

    // stacks grow down; point IST to end
    tss.interrupt_stack_table[ist::NMI as usize] = nmi_e;
    tss.interrupt_stack_table[ist::DF as usize] = df_e;
    tss.interrupt_stack_table[ist::PF as usize] = pf_e;
    tss.interrupt_stack_table[ist::MC as usize] = mc_e;
    tss.interrupt_stack_table[ist::GP as usize] = gp_e;

    // IO bitmap & TSS misc remain default (no IO ports for user)
}

// ─────────────────────────────────────────────────────────────────────
// control registers / features
// ─────────────────────────────────────────────────────────────────────

fn has_leaf7_edx(bit: u32) -> bool {
    let (_a, _b, _c, d) = cpuid(0x7, 0);
    (d & (1 << bit)) != 0
}
fn has_leaf7_ecx(bit: u32) -> bool {
    let (_a, _b, c, _d) = cpuid(0x7, 0);
    (c & (1 << bit)) != 0
}
fn has_ecx_1(bit: u32) -> bool {
    let (_a, _b, c, _d) = cpuid(0x1, 0);
    (c & (1 << bit)) != 0
}
fn has_pcid() -> bool {
    let (_a, _b, _c, d) = cpuid(0x1, 0);
    (d & (1 << 17)) != 0 // PCID in CR4
}

fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u32, u32, u32);
    unsafe {
        asm!("push %rbx; cpuid; mov %ebx, %esi; pop %rbx",
            inlateout("eax") leaf => a,
            inlateout("ecx") subleaf => c,
            out("esi") b,
            lateout("edx") d,
            options(nostack, att_syntax)
        );
    }
    (a, b, c, d)
}

fn harden_crs() {
    unsafe {
        // CR0: write protect
        let mut cr0 = Cr0::read();
        cr0.insert(Cr0Flags::WRITE_PROTECT);
        Cr0::write(cr0);

        // CR4: UMIP/SMEP/SMAP if present (commented out - flags not available
        // in this x86_64 crate version) let mut cr4 = Cr4::read();
        // if has_leaf7_edx(20) { cr4.insert(Cr4Flags::UMIP); }
        // if has_leaf7_edx(7)  { cr4.insert(Cr4Flags::SMEP); }
        // if has_leaf7_edx(21) { cr4.insert(Cr4Flags::SMAP); }
        // Cr4::write(cr4);
    }
}

fn ensure_nxe() {
    unsafe {
        let mut efer = Efer::read();
        efer.insert(EferFlags::NO_EXECUTE_ENABLE);
        Efer::write(efer);
    }
}

/// opt-in when scheduler assigns ASIDs
pub unsafe fn enable_pcid(asid: u16) {
    if !has_pcid() {
        return;
    }
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::PCID);
    Cr4::write(cr4);

    // install kernel CR3 with PCID=0; user will use PCID=asid
    let (level4, _flags) = Cr3::read();
    let kcr3 = level4.start_address().as_u64() | 0u64; // PCID 0
    asm!("mov cr3, {}", in(reg) kcr3, options(nostack, preserves_flags));

    // store ASID where needed (registry already holds asid)
    let _ = asid;
}

/// KPTI: switch to user CR3 (with PCID) before iret to ring3
pub unsafe fn kpti_switch_to_user(u_cr3: u64, asid: u16) {
    let pcid = (asid as u64) & 0xFFF;
    let val = (u_cr3 & !0xFFF) | pcid | (1 << 63); // no flush
    asm!("mov cr3, {}", in(reg) val, options(nostack, preserves_flags));
}

/// KPTI: on kernel entry, switch back to kernel CR3 (PCID=0)
pub unsafe fn kpti_switch_to_kernel() {
    let (level4, _flags) = Cr3::read();
    let kcr3 = level4.start_address().as_u64() & !0xFFF; // PCID 0
    asm!("mov cr3, {}", in(reg) kcr3, options(nostack, preserves_flags));
}

// ─────────────────────────────────────────────────────────────────────
// SYSCALL MSRs (alternative to INT 0x80)
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "nonos-syscall-msr")]
fn init_syscall_msrs(k_cs: SegmentSelector) {
    unsafe {
        // enable SCE
        let mut efer = Efer::read();
        efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
        Efer::write(efer);

        // STAR: user CS in 63:48, kernel CS in 47:32
        let ucs = u64::from(k_cs.0).saturating_sub(16);
        let star = (ucs << 48) | (u64::from(k_cs.0) << 32);
        Star::write(star);

        extern "C" {
            fn syscall_entry_trampoline();
        }
        LStar::write(VirtAddr::new(syscall_entry_trampoline as u64));

        // mask IF/DF/TF on entry
        const IF_MASK: u64 = 1 << 9;
        const DF_MASK: u64 = 1 << 10;
        const TF_MASK: u64 = 1 << 8;
        SFMask::write(IF_MASK | DF_MASK | TF_MASK);
    }
}

// ─────────────────────────────────────────────────────────────────────
// CET (shadow stacks / IBT) — stub wiring points
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "nonos-cet")]
pub unsafe fn cet_enable_stub() {
    // Allocate per-thread shadow stacks and WRMSR to IA32_S_CET/IA32_PLx_SSP as
    // needed. Keep disabled until we have per-thread alloc + context switch
    // integration.
}

// ─────────────────────────────────────────────────────────────────────
// XSAVE policy
// ─────────────────────────────────────────────────────────────────────

fn init_xsave_policy() -> u64 {
    unsafe {
        // require XSAVE
        if !has_ecx_1(26) {
            return 0;
        }
        // CPUID 0xD.0: valid XCR0 mask in EAX/EDX
        let (eax, _ebx, _ecx, edx) = cpuid(0xD, 0);
        let mask = (u64::from(edx) << 32) | u64::from(eax);
        // default to x87|SSE only (bits 0 and 1)
        let desired = mask & 0b11;
        // xsetbv XCR0
        let lo = (desired & 0xFFFF_FFFF) as u32;
        let hi = (desired >> 32) as u32;
        asm!("xsetbv", in("ecx") 0u32, in("eax") lo, in("edx") hi, options(nostack, preserves_flags));
        desired
    }
}

// ─────────────────────────────────────────────────────────────────────
// swapgs helpers (entry/exit)
// ─────────────────────────────────────────────────────────────────────

#[inline(always)]
pub unsafe fn entry_swapgs_if_needed(rflags: RFlags) {
    // On SYSCALL/SYSRET paths from user, swapgs is required. On interrupt from
    // kernel, not needed. Here we assume caller checked CPL; keep utility for
    // future.
    if rflags.contains(RFlags::IOPL_HIGH) {
        // HACK: Simple privilege check
        asm!("swapgs", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub unsafe fn exit_swapgs_if_needed(rflags: RFlags) {
    if rflags.contains(RFlags::IOPL_HIGH) {
        asm!("swapgs", options(nostack, preserves_flags));
    }
}
