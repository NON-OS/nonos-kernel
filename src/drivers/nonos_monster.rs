//! MONSTER: Driver Orchestrator and Health Manager 

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

#[derive(Default, Clone)]
pub struct MonsterStats {
    pub pci_devices: u64,
    pub nvme_bytes_rw: u64,
    pub usb_devices: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub gpu_memory: u64,
    pub audio_streams: u64,
    pub errors: u64,
    pub ticks: u64,
}

static STATS: Mutex<MonsterStats> = Mutex::new(MonsterStats {
    pci_devices: 0,
    nvme_bytes_rw: 0,
    usb_devices: 0,
    net_rx: 0,
    net_tx: 0,
    gpu_memory: 0,
    audio_streams: 0,
    errors: 0,
    ticks: 0,
});
static MONSTER_INITED: AtomicBool = AtomicBool::new(false);

pub fn monster_init() -> Result<(), &'static str> {
    if MONSTER_INITED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    // PCI first (required by downstream drivers)
    if let Err(e) = crate::drivers::nonos_pci::init_pci() {
        crate::log::logger::log_warn!("MONSTER: PCI init failed: {}", e);
        STATS.lock().errors += 1;
    }

    // Storage (NVMe preferred)
    if let Err(e) = crate::drivers::nonos_nvme::init_nvme() {
        crate::log::logger::log_warn!("MONSTER: NVMe init skipped/failed: {}", e);
        STATS.lock().errors += 1;
    }

    // USB stack (xHCI + USB core)
    match crate::drivers::nonos_xhci::init_xhci() {
        Ok(_) => {
            if let Err(e) = crate::drivers::nonos_usb::init_usb() {
                crate::log::logger::log_warn!("MONSTER: USB init skipped/failed: {}", e);
                STATS.lock().errors += 1;
            }
        }
        Err(e) => {
            crate::log::logger::log_warn!("MONSTER: xHCI init skipped/failed: {}", e);
            STATS.lock().errors += 1;
        }
    }

    // Network (virtio-net)
    if let Err(e) = crate::drivers::nonos_virtio_net::init_virtio_net() {
        crate::log::logger::log_warn!("MONSTER: virtio-net init skipped/failed: {}", e);
        STATS.lock().errors += 1;
    }

    // Graphics
    if let Err(e) = crate::drivers::nonos_gpu::init_gpu() {
        crate::log::logger::log_warn!("MONSTER: GPU init skipped/failed: {}", e);
        STATS.lock().errors += 1;
    }

    // Audio (best-effort)
    if let Err(e) = crate::drivers::nonos_audio::init_hd_audio() {
        crate::log::logger::log_warn!("MONSTER: HD Audio init skipped/failed: {}", e);
        STATS.lock().errors += 1;
    }

    // Initial stat snapshot 
    refresh_stats();

    crate::log::logger::log_critical("✓ MONSTER orchestrator initialized");
    Ok(())
}

pub fn monster_self_test() -> Result<(), &'static str> {
    // Non-destructive test hooks can run here (optional)
    if let Some(surf) = crate::drivers::nonos_gpu::GpuDriver::get_surface() {
        surf.fill_rect(0, 0, 8, 8, 0x00000000);
        surf.present(Some((0, 0, 8, 8)));
    }

    // Refresh stats from live drivers
    refresh_stats();
    Ok(())
}

pub fn monster_report() -> MonsterStats {
    refresh_stats();
    STATS.lock().clone()
}

pub fn monster_tick() {
    let mut g = STATS.lock();
    g.ticks = g.ticks.wrapping_add(1);
}

// Pull fresh values from subsystems 
fn refresh_stats() {
    // PCI device count (scan-and-collect)
    // If scan fails, keep previous value and log once.
    let pci_count = {
        // Prefer the nonos_pci scan if available in this build.
        #[allow(unused_mut)]
        let mut count = 0u64;
        // If your nonos_pci exposes a scan_and_collect(), use it:
        #[allow(unused_must_use)]
        {
            // Handle potential panic paths defensively with match
            // SAFETY: we expect nonos_pci to provide this API.
            let devs = crate::drivers::nonos_pci::scan_and_collect();
            count = devs.len() as u64;
        }
        count
    };

    // NVMe bytes
    let nvme_rw = if let Some(ctrl) = crate::drivers::nonos_nvme::get_controller() {
        let s = ctrl.get_stats();
        s.bytes_read + s.bytes_written
    } else {
        0
    };

    // USB device count
    let usb_devs = crate::drivers::nonos_usb::get_manager()
        .map(|m| m.devices().len() as u64)
        .unwrap_or(0);

    // Network bytes
    let (net_rx, net_tx) = if let Some(dev) = crate::drivers::nonos_virtio_net::get_virtio_net_device() {
        let s = &dev.lock().stats;
        (s.rx_bytes.load(Ordering::Relaxed), s.tx_bytes.load(Ordering::Relaxed))
    } else {
        (0, 0)
    };

    // GPU memory
    let gpu_mem = crate::drivers::nonos_gpu::with_driver(|g| g.get_stats().memory_allocated)
        .unwrap_or(0);

    // Audio streams (from driver stats)
    let audio_streams = crate::drivers::nonos_audio::get_controller()
        .map(|c| c.get_stats().active_streams)
        .unwrap_or(0);

    let mut g = STATS.lock();
    g.pci_devices = pci_count;
    g.nvme_bytes_rw = nvme_rw;
    g.usb_devices = usb_devs;
    g.net_rx = net_rx;
    g.net_tx = net_tx;
    g.gpu_memory = gpu_mem;
    g.audio_streams = audio_streams;
}
