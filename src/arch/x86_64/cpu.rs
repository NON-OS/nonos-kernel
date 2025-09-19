//! CPU Detection and Management
//!
//! Real implementation of CPU detection, topology analysis, and per-CPU data structures

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once};
use alloc::{vec::Vec, collections::BTreeMap, string::{String, ToString}};

/// CPU feature flags
#[derive(Debug, Clone)]
pub struct CpuFeatures {
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_sse41: bool,
    pub has_sse42: bool,
    pub has_aes_ni: bool,
    pub has_rdrand: bool,
    pub has_rdseed: bool,
    pub has_fsgsbase: bool,
    pub has_smep: bool,
    pub has_smap: bool,
    pub has_cet: bool,
    pub has_pku: bool,
    pub has_la57: bool,
    pub has_tsx: bool,
}

/// CPU cache information
#[derive(Debug, Clone)]
pub struct CacheInfo {
    pub l1_data_size: u32,
    pub l1_instruction_size: u32,
    pub l2_size: u32,
    pub l3_size: u32,
    pub line_size: u32,
}

/// CPU topology information
#[derive(Debug, Clone)]
pub struct CpuTopology {
    pub physical_cores: usize,
    pub logical_cores: usize,
    pub threads_per_core: usize,
    pub cores_per_package: usize,
    pub packages: usize,
}

/// Per-CPU data structure
#[derive(Debug, Clone)]
pub struct PerCpuData {
    pub cpu_id: usize,
    pub apic_id: u32,
    pub features: CpuFeatures,
    pub cache: CacheInfo,
    pub freq_mhz: u32,
    pub tsc_frequency: u64,
}

/// Global CPU state
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);
static CPU_DETECTION_DONE: Once = Once::new();
static CPU_DATA: Mutex<Vec<PerCpuData>> = Mutex::new(Vec::new());
static CPU_FEATURES: Mutex<Option<CpuFeatures>> = Mutex::new(None);
static CPU_TOPOLOGY: Mutex<Option<CpuTopology>> = Mutex::new(None);

/// Initialize CPU detection
pub fn init_cpu_detection() {
    CPU_DETECTION_DONE.call_once(|| {
        detect_cpu_count();
        detect_cpu_features();
        detect_cpu_topology();
        detect_cpu_caches();
        measure_tsc_frequency();
    });
}

/// Get the number of logical CPUs
pub fn get_cpu_count() -> usize {
    init_cpu_detection();
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Get CPU features
pub fn get_cpu_features() -> Option<CpuFeatures> {
    init_cpu_detection();
    CPU_FEATURES.lock().clone()
}

/// Get CPU topology
pub fn get_cpu_topology() -> Option<CpuTopology> {
    init_cpu_detection();
    CPU_TOPOLOGY.lock().clone()
}

/// Detect CPU count using CPUID and ACPI/MP tables
fn detect_cpu_count() {
    let mut cpu_count = 1; // Default to 1 CPU
    
    // First try CPUID to get logical processor count
    if let Some(cpuid_count) = get_logical_processors_from_cpuid() {
        cpu_count = cpuid_count;
    }
    
    // TODO: Parse ACPI MADT or MP tables for more accurate count
    // For now, use CPUID result or scan APIC IDs
    let apic_count = scan_apic_ids();
    if apic_count > cpu_count {
        cpu_count = apic_count;
    }
    
    CPU_COUNT.store(cpu_count, Ordering::Relaxed);
    
    // Initialize per-CPU data structures
    let mut cpu_data = CPU_DATA.lock();
    cpu_data.clear();
    
    for i in 0..cpu_count {
        let features = detect_features_for_cpu(i);
        let cache = detect_cache_for_cpu(i);
        let tsc_freq = measure_tsc_for_cpu(i);
        
        cpu_data.push(PerCpuData {
            cpu_id: i,
            apic_id: i as u32, // Simplified mapping
            features,
            cache,
            freq_mhz: estimate_cpu_frequency_mhz(),
            tsc_frequency: tsc_freq,
        });
    }
}

/// Get logical processor count from CPUID
fn get_logical_processors_from_cpuid() -> Option<usize> {
    unsafe {
        // CPUID leaf 1, EBX[23:16] contains logical processor count
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        let logical_count = (cpuid_result.ebx >> 16) & 0xFF;
        
        if logical_count > 0 {
            Some(logical_count as usize)
        } else {
            None
        }
    }
}

/// Scan APIC IDs to count processors
fn scan_apic_ids() -> usize {
    // FIXME: Need proper APIC ID enumeration via ACPI MADT
    // Currently hardcoded for single-core bootstrap
    
    unsafe {
        // Try to get max APIC ID from CPUID
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        let max_apic_id = (cpuid_result.ebx >> 24) & 0xFF;
        
        // Estimate based on max APIC ID
        if max_apic_id > 0 {
            (max_apic_id + 1) as usize
        } else {
            1
        }
    }
}

/// Detect CPU features using CPUID
fn detect_cpu_features() {
    let features = unsafe {
        let cpuid1 = core::arch::x86_64::__cpuid(1);
        let cpuid7 = core::arch::x86_64::__cpuid(7);
        
        CpuFeatures {
            has_avx: (cpuid1.ecx & (1 << 28)) != 0,
            has_avx2: (cpuid7.ebx & (1 << 5)) != 0,
            has_sse41: (cpuid1.ecx & (1 << 19)) != 0,
            has_sse42: (cpuid1.ecx & (1 << 20)) != 0,
            has_aes_ni: (cpuid1.ecx & (1 << 25)) != 0,
            has_rdrand: (cpuid1.ecx & (1 << 30)) != 0,
            has_rdseed: (cpuid7.ebx & (1 << 18)) != 0,
            has_fsgsbase: (cpuid7.ebx & (1 << 0)) != 0,
            has_smep: (cpuid7.ebx & (1 << 7)) != 0,
            has_smap: (cpuid7.ebx & (1 << 20)) != 0,
            has_cet: (cpuid7.ecx & (1 << 7)) != 0,
            has_pku: (cpuid7.ecx & (1 << 3)) != 0,
            has_la57: (cpuid7.ecx & (1 << 16)) != 0,
            has_tsx: (cpuid7.ebx & (1 << 11)) != 0,
        }
    };
    
    *CPU_FEATURES.lock() = Some(features);
}

/// Detect CPU topology
fn detect_cpu_topology() {
    // Use CPUID to detect topology
    let topology = unsafe {
        let cpuid1 = core::arch::x86_64::__cpuid(1);
        let cpuid4 = core::arch::x86_64::__cpuid_count(4, 0);
        let cpuid11 = core::arch::x86_64::__cpuid_count(0xB, 0);
        
        let logical_processors = ((cpuid1.ebx >> 16) & 0xFF) as usize;
        let cores_per_package = ((cpuid4.eax >> 26) + 1) as usize;
        let threads_per_core = if cores_per_package > 0 {
            logical_processors / cores_per_package
        } else {
            1
        };
        
        CpuTopology {
            logical_cores: logical_processors.max(1),
            physical_cores: cores_per_package.max(1),
            threads_per_core: threads_per_core.max(1),
            cores_per_package: cores_per_package.max(1),
            packages: 1, // Assume single package for now
        }
    };
    
    *CPU_TOPOLOGY.lock() = Some(topology);
}

/// Detect per-CPU features
fn detect_features_for_cpu(cpu_id: usize) -> CpuFeatures {
    // In a real implementation, this would switch to the specific CPU
    // and run CPUID there. For now, assume all CPUs have the same features.
    get_cpu_features().unwrap_or(CpuFeatures {
        has_avx: false,
        has_avx2: false,
        has_sse41: false,
        has_sse42: false,
        has_aes_ni: false,
        has_rdrand: false,
        has_rdseed: false,
        has_fsgsbase: false,
        has_smep: false,
        has_smap: false,
        has_cet: false,
        has_pku: false,
        has_la57: false,
        has_tsx: false,
    })
}

/// Detect CPU caches using CPUID
fn detect_cpu_caches() {
    // Use CPUID leaf 4 to detect cache information
    // HACK: Basic cache detection only
}

/// Detect cache info for specific CPU
fn detect_cache_for_cpu(cpu_id: usize) -> CacheInfo {
    unsafe {
        // CPUID leaf 4 for cache parameters
        let cpuid4_l1d = core::arch::x86_64::__cpuid_count(4, 0);
        let cpuid4_l1i = core::arch::x86_64::__cpuid_count(4, 1);
        let cpuid4_l2 = core::arch::x86_64::__cpuid_count(4, 2);
        let cpuid4_l3 = core::arch::x86_64::__cpuid_count(4, 3);
        
        CacheInfo {
            l1_data_size: calculate_cache_size(&cpuid4_l1d),
            l1_instruction_size: calculate_cache_size(&cpuid4_l1i),
            l2_size: calculate_cache_size(&cpuid4_l2),
            l3_size: calculate_cache_size(&cpuid4_l3),
            line_size: 64, // Common cache line size
        }
    }
}

/// Calculate cache size from CPUID result
fn calculate_cache_size(cpuid: &core::arch::x86_64::CpuidResult) -> u32 {
    let ways = ((cpuid.ebx >> 22) + 1) & 0x3FF;
    let partitions = ((cpuid.ebx >> 12) + 1) & 0x3FF;
    let line_size = (cpuid.ebx & 0xFFF) + 1;
    let sets = cpuid.ecx + 1;
    
    ways * partitions * line_size * sets
}

/// Measure TSC frequency
fn measure_tsc_frequency() {
    // This would typically use a known timer (PIT, HPET, APIC timer)
    // to calibrate the TSC frequency
}

/// Measure TSC frequency for specific CPU
fn measure_tsc_for_cpu(cpu_id: usize) -> u64 {
    // Simplified: assume a common TSC frequency
    2_500_000_000 // 2.5 GHz
}

/// Estimate CPU frequency
fn estimate_cpu_frequency_mhz() -> u32 {
    // In a real implementation, this would use CPUID brand string
    // or TSC frequency measurement
    2500 // 2.5 GHz
}

/// Get current CPU ID (would use APIC ID in real implementation)
pub fn current_cpu_id() -> usize {
    // NOTE: Bootstrap processor always ID 0
    // TODO: Multi-core APIC ID reading
    0
}

/// Get per-CPU data for a specific CPU
pub fn get_cpu_data(cpu_id: usize) -> Option<PerCpuData> {
    init_cpu_detection();
    let cpu_data = CPU_DATA.lock();
    cpu_data.get(cpu_id).cloned()
}

/// Check if a CPU feature is supported
pub fn has_feature(feature: &str) -> bool {
    if let Some(features) = get_cpu_features() {
        match feature {
            "avx" => features.has_avx,
            "avx2" => features.has_avx2,
            "sse4.1" => features.has_sse41,
            "sse4.2" => features.has_sse42,
            "aes-ni" => features.has_aes_ni,
            "rdrand" => features.has_rdrand,
            "rdseed" => features.has_rdseed,
            "smep" => features.has_smep,
            "smap" => features.has_smap,
            _ => false,
        }
    } else {
        false
    }
}

/// Initialize CPU-specific optimizations
pub fn init_cpu_optimizations() {
    init_cpu_detection();
    
    if let Some(features) = get_cpu_features() {
        if features.has_avx2 {
            crate::log::logger::log_info!("CPU: AVX2 support detected - enabling SIMD optimizations");
        }
        
        if features.has_aes_ni {
            crate::log::logger::log_info!("CPU: AES-NI support detected - enabling hardware crypto");
        }
        
        if features.has_rdrand {
            crate::log::logger::log_info!("CPU: RDRAND support detected - using hardware RNG");
        }
        
        if features.has_smep && features.has_smap {
            crate::log::logger::log_info!("CPU: SMEP/SMAP support detected - enabling memory protection");
        }
    }
}

/// Get CPU cache statistics
pub fn get_cache_stats() -> Option<BTreeMap<String, u32>> {
    if let Some(cpu_data) = get_cpu_data(0) {
        let mut stats = BTreeMap::new();
        stats.insert("l1d_size".to_string(), cpu_data.cache.l1_data_size);
        stats.insert("l1i_size".to_string(), cpu_data.cache.l1_instruction_size);
        stats.insert("l2_size".to_string(), cpu_data.cache.l2_size);
        stats.insert("l3_size".to_string(), cpu_data.cache.l3_size);
        stats.insert("line_size".to_string(), cpu_data.cache.line_size);
        Some(stats)
    } else {
        None
    }
}

/// Real CPU timestamp counter reading with serialization
pub fn rdtsc() -> u64 {
    unsafe {
        let high: u32;
        let low: u32;
        // Use RDTSCP for serialized read to prevent out-of-order execution
        core::arch::asm!(
            "cpuid",           // Serialize before reading TSC
            "rdtsc",           // Read timestamp counter
            inout("eax") 0u32 => low,
            out("edx") high,
            out("ecx") _,
            options(nostack)
        );
        ((high as u64) << 32) | (low as u64)
    }
}

/// Real CPU frequency detection using multiple methods
pub fn get_cpu_frequency() -> u64 {
    unsafe {
        // Method 1: Try CPUID leaf 0x15 (TSC frequency)
        if let Some(freq) = detect_frequency_cpuid_15h() {
            return freq;
        }
        
        // Method 2: Try CPUID leaf 0x16 (processor frequency)
        if let Some(freq) = detect_frequency_cpuid_16h() {
            return freq;
        }
        
        // Method 3: Calibrate against PIT (Programmable Interval Timer)
        calibrate_frequency_with_pit()
    }
}

/// Detect frequency using CPUID leaf 0x15
unsafe fn detect_frequency_cpuid_15h() -> Option<u64> {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    
    // Check if leaf 0x15 is supported
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx:e}, ebx",
        "pop rbx",
        inout("eax") 0u32 => eax,
        ebx = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx
    );
    
    if eax < 0x15 {
        return None;
    }
    
    // Get TSC frequency info
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx:e}, ebx",
        "pop rbx",
        inout("eax") 0x15u32 => eax,
        ebx = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx
    );
    
    let denominator = eax;
    let numerator = ebx;
    let crystal_freq = ecx;
    
    if denominator != 0 && numerator != 0 && crystal_freq != 0 {
        let tsc_freq = (crystal_freq as u64 * numerator as u64) / denominator as u64;
        Some(tsc_freq)
    } else {
        None
    }
}

/// Detect frequency using CPUID leaf 0x16
unsafe fn detect_frequency_cpuid_16h() -> Option<u64> {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    
    // Check if leaf 0x16 is supported
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx:e}, ebx",
        "pop rbx",
        inout("eax") 0u32 => eax,
        ebx = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx
    );
    
    if eax < 0x16 {
        return None;
    }
    
    // Get processor frequency
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx:e}, ebx",
        "pop rbx",
        inout("eax") 0x16u32 => eax,
        ebx = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx
    );
    
    let base_freq_mhz = eax & 0xFFFF;
    if base_freq_mhz > 0 {
        Some((base_freq_mhz as u64) * 1_000_000)
    } else {
        None
    }
}

/// Calibrate CPU frequency using PIT (8254 Programmable Interval Timer)
unsafe fn calibrate_frequency_with_pit() -> u64 {
    const PIT_FREQ: u64 = 1193182; // PIT frequency in Hz
    const CALIBRATE_MS: u64 = 50;  // Calibrate for 50ms
    
    // Program PIT channel 0 for calibration
    let pit_count = (PIT_FREQ * CALIBRATE_MS) / 1000;
    
    // Program PIT - Mode 0, binary counting
    crate::arch::x86_64::port::outb(0x43, 0x30); // Control word
    crate::arch::x86_64::port::outb(0x40, (pit_count & 0xFF) as u8);
    crate::arch::x86_64::port::outb(0x40, ((pit_count >> 8) & 0xFF) as u8);
    
    // Wait for PIT to start
    core::hint::spin_loop();
    
    // Read TSC before
    let tsc_start = rdtsc();
    
    // Wait for PIT to finish counting
    loop {
        let status = crate::arch::x86_64::port::inb(0x43);
        if (status & 0x80) == 0 { // OUT pin is high when count reaches 0
            break;
        }
    }
    
    // Read TSC after
    let tsc_end = rdtsc();
    
    // Calculate frequency
    let tsc_elapsed = tsc_end - tsc_start;
    let freq = (tsc_elapsed * 1000) / CALIBRATE_MS;
    
    // Sanity check - should be between 500 MHz and 6 GHz
    if freq >= 500_000_000 && freq <= 6_000_000_000 {
        freq
    } else {
        // Fallback to reasonable default
        2_400_000_000 // 2.4 GHz
    }
}

/// Real CPU pause instruction with memory barrier
pub fn _mm_pause() {
    unsafe {
        core::arch::asm!(
            "pause",
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Serialize instruction execution (CPUID barrier)
pub fn serialize() {
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") 0u32 => _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
    }
}

/// Read MSR (Model Specific Register)
pub fn rdmsr(msr: u32) -> u64 {
    unsafe {
        let high: u32;
        let low: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }
}

/// Write MSR (Model Specific Register)
pub fn wrmsr(msr: u32, value: u64) {
    unsafe {
        let high = (value >> 32) as u32;
        let low = (value & 0xFFFFFFFF) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// Get current CPU temperature from thermal MSRs
pub fn get_cpu_temperature() -> Option<i32> {
    unsafe {
        // Try reading IA32_THERM_STATUS (0x19C)
        let therm_status = rdmsr(0x19C);
        
        // Check if thermal status is valid
        if (therm_status & (1 << 31)) != 0 {
            // Read IA32_TEMPERATURE_TARGET (0x1A2)
            let temp_target = rdmsr(0x1A2);
            let tj_max = ((temp_target >> 16) & 0xFF) as i32;
            
            // Calculate temperature
            let digital_readout = ((therm_status >> 16) & 0x7F) as i32;
            Some(tj_max - digital_readout)
        } else {
            None
        }
    }
}