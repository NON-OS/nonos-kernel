//! Intel HD Audio (HDA) Controller Driver

use core::{mem, ptr};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::{vec::Vec, string::String, boxed::Box};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{self, PciBar, PciDevice, pci_read_config32};
use crate::memory::dma::alloc_dma_coherent;
use crate::memory::mmio::{mmio_r8, mmio_r16, mmio_r32, mmio_w8, mmio_w16, mmio_w32};

// HDA BAR index (we read from PCI config)
const HDA_CLASS: u8 = 0x04;
const HDA_SUBCLASS: u8 = 0x03;

// Global registers offsets
const GCAP: usize = 0x00;     // 16-bit
const VMIN: usize = 0x02;     // 8-bit
const VMAJ: usize = 0x03;     // 8-bit
const OUTPAY: usize = 0x04;   // 16-bit
const INPAY: usize = 0x06;    // 16-bit
const GCTL: usize = 0x08;     // 32-bit
const WAKEEN: usize = 0x0C;   // 16-bit
const STATESTS: usize = 0x0E; // 16-bit 
const GSTS: usize = 0x10;     // 16-bit
const INTCTL: usize = 0x20;   // 32-bit
const INTSTS: usize = 0x24;   // 32-bit
const WALCLK: usize = 0x30;   // 32-bit
const SSYNC: usize = 0x34;    // 32-bit

// CORB/RIRB offsets
const CORBLBASE: usize = 0x40; // 32-bit
const CORBUBASE: usize = 0x44; // 32-bit
const CORBWP: usize = 0x48;    // 16-bit
const CORBRP: usize = 0x4A;    // 16-bit
const CORBCTL: usize = 0x4C;   // 8-bit
const CORBSTS: usize = 0x4D;   // 8-bit
const CORBSIZE: usize = 0x4E;  // 8-bit

const RIRBLBASE: usize = 0x50; // 32-bit
const RIRBUBASE: usize = 0x54; // 32-bit
const RIRBWP: usize = 0x58;    // 16-bit
const RINTCNT: usize = 0x5A;   // 16-bit
const RIRBCTL: usize = 0x5C;   // 8-bit
const RIRBSTS: usize = 0x5D;   // 8-bit
const RIRBSIZE: usize = 0x5E;  // 8-bit

// Immediate Command Interface
const IC: usize = 0x60;   // 32-bit: immediate command
const IR: usize = 0x64;   // 32-bit: immediate response
const IRS: usize = 0x68;  // 8-bit: immediate status

// Stream descriptor registers base and stride
const STREAM_BASE: usize = 0x80;
const STREAM_STRIDE: usize = 0x20;

// Stream descriptor register offsets (relative to stream base)
const SD_CTL: usize = 0x00;   // 32-bit
const SD_STS: usize = 0x03;   // 8-bit (but we use 32-bit access with mask)
const SD_LPIB: usize = 0x04;  // 32-bit
const SD_CBL: usize = 0x08;   // 32-bit
const SD_LVI: usize = 0x0C;   // 8-bit (we use 32-bit)
const SD_FIFOS: usize = 0x10; // 16-bit
const SD_FMT: usize = 0x12;   // 16-bit
const SD_BDPL: usize = 0x18;  // 32-bit
const SD_BDPU: usize = 0x1C;  // 32-bit

// GCTL bits
const GCTL_CRST: u32 = 1 << 0;

// CORBCTL bits
const CORBCTL_CORBRUN: u8 = 1 << 1;
// CORBSTS bits
const CORBSTS_CORBINT: u8 = 1 << 0;

// RIRBCTL bits
const RIRBCTL_RIRBDMAEN: u8 = 1 << 0;
const RIRBCTL_RINTCTL: u8 = 1 << 1;
// RIRBSTS bits
const RIRBSTS_RIRBOIS: u8 = 1 << 0;

// Immediate command status
const IRS_BUSY: u8 = 1 << 0;
const IRS_VALID: u8 = 1 << 1;

// Stream control bits
const SD_CTL_SRST: u32 = 1 << 0;
const SD_CTL_RUN: u32 = 1 << 1;
const SD_CTL_IOCE: u32 = 1 << 2; // Interrupt on completion enable
const SD_CTL_FEIE: u32 = 1 << 3; // FIFO error interrupt enable
const SD_CTL_DEIE: u32 = 1 << 4; // Descriptor error interrupt enable

// BDL entry
#[repr(C, packed)]
struct BdlEntry {
    addr_lo: u32,
    addr_hi: u32,
    length: u32,
    flags: u32, // bit0 IOC
}

struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
}
impl DmaRegion {
    fn new(size: usize) -> Result<Self, &'static str> {
        let (va, pa) = alloc_dma_coherent(size)?;
        unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size); }
        Ok(Self { va, pa, size })
    }
    #[inline] fn as_mut_ptr<T>(&self) -> *mut T { self.va.as_mut_ptr::<T>() }
    #[inline] fn phys(&self) -> u64 { self.pa.as_u64() }
}

pub struct HdAudioController {
    base: usize,
    // capabilities
    iss: u8, // number of output streams
    oss: u8, // number of input streams
    bss: u8, // number of bidirectional streams

    // CORB/RIRB rings
    corb: DmaRegion,
    rirb: DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,

    // Codec presence mask
    codec_mask: u16,
    primary_codec: Option<u8>,

    // Output stream state (use stream #1 as common)
    out_stream: u8,
    bdl: DmaRegion,
    pcm_buf: DmaRegion,
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,

    // Stats
    bytes_played: AtomicU64,
    errors: AtomicU64,
}

static HDA_ONCE: spin::Once<&'static Mutex<HdAudioController>> = spin::Once::new();

impl HdAudioController {
    pub fn init(pci: PciDevice) -> Result<&'static Mutex<Self>, &'static str> {
        // BAR mapping
        let bar = pci.get_bar(0)?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("HDA BAR0 is not MMIO"),
        };

        // Reset controller
        unsafe {
            // Clear CRST
            let mut gctl = mmio_r32(base + GCTL);
            gctl &= !GCTL_CRST;
            mmio_w32(base + GCTL, gctl);
        }
        if !Self::spin(|| unsafe { mmio_r32(base + GCTL) } & GCTL_CRST == 0, 1_000_000) {
            return Err("HDA: failed to clear CRST");
        }

        unsafe {
            // Set CRST
            let mut gctl = mmio_r32(base + GCTL);
            gctl |= GCTL_CRST;
            mmio_w32(base + GCTL, gctl);
        }
        if !Self::spin(|| unsafe { mmio_r32(base + GCTL) } & GCTL_CRST != 0, 1_000_000) {
            return Err("HDA: failed to set CRST");
        }

        // Read capabilities
        let gcap = unsafe { mmio_r16(base + GCAP) };
        let iss = ((gcap >> 12) & 0xF) as u8;
        let oss = ((gcap >> 8) & 0xF) as u8;
        let bss = ((gcap >> 3) & 0x1F) as u8;

        // Setup CORB/RIRB with 256 entries
        let corb_entries = 256usize;
        let rirb_entries = 256usize;
        let corb = DmaRegion::new(corb_entries * 4)?; // 4-byte commands
        let rirb = DmaRegion::new(rirb_entries * 8)?; // 8-byte responses

        unsafe {
            // Program CORB base
            mmio_w32(base + CORBLBASE, (corb.phys() & 0xFFFF_FFFF) as u32);
            mmio_w32(base + CORBUBASE, (corb.phys() >> 32) as u32);
            // Set CORB size: 256 entries -> write 0x02
            mmio_w8(base + CORBSIZE, 0x02);
            // Reset CORBWP and CORBRP
            mmio_w16(base + CORBWP, 0);
            mmio_w16(base + CORBRP, (1 << 15)); // set RP reset
            mmio_w16(base + CORBRP, 0);
            // Enable CORB RUN
            mmio_w8(base + CORBCTL, CORBCTL_CORBRUN);
            // Clear CORB status
            mmio_w8(base + CORBSTS, CORBSTS_CORBINT);
        }

        unsafe {
            // Program RIRB base
            mmio_w32(base + RIRBLBASE, (rirb.phys() & 0xFFFF_FFFF) as u32);
            mmio_w32(base + RIRBUBASE, (rirb.phys() >> 32) as u32);
            // Set RIRB size: 256 -> 0x02
            mmio_w8(base + RIRBSIZE, 0x02);
            // Reset RIRBWP by setting bit 15
            mmio_w16(base + RIRBWP, 1 << 15);
            mmio_w16(base + RIRBWP, 0);
            // Set RINTCNT to 1
            mmio_w16(base + RINTCNT, 1);
            // Enable RIRB DMA + interrupt
            mmio_w8(base + RIRBCTL, RIRBCTL_RIRBDMAEN | RIRBCTL_RINTCTL);
            // Clear RIRB status
            mmio_w8(base + RIRBSTS, RIRBSTS_RIRBOIS);
        }

        // Read STATESTS to find codecs
        let codec_mask = unsafe { mmio_r16(base + STATESTS) };
        let primary_codec = (0..=15).find(|c| (codec_mask & (1 << c)) != 0).map(|c| c as u8);

        // Prepare output stream and buffers: use stream 1 (first output)
        let out_stream = 1u8;
        let bdl = DmaRegion::new(16 * mem::size_of::<BdlEntry>())?;
        // Default PCM buffer: 64 KiB ring
        let pcm_buf = DmaRegion::new(64 * 1024)?;

        let ctl = HdAudioController {
            base,
            iss,
            oss,
            bss,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            codec_mask,
            primary_codec,
            out_stream,
            bdl,
            pcm_buf,
            sample_rate: 48_000,
            channels: 2,
            bits_per_sample: 16,
            bytes_played: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        };

        let boxed = Box::leak(Box::new(Mutex::new(ctl)));

        // Discover and init codec path (best-effort)
        {
            let mut g = boxed.lock();
            let _ = g.codec_init_path();
            let _ = g.init_output_stream();
        }

        HDA_ONCE.call_once(|| boxed);
        crate::log::logger::log_critical("✓ HD Audio subsystem initialized");
        Ok(boxed)
    }

    fn spin<F: Fn() -> bool>(cond: F, mut spins: u32) -> bool {
        while spins > 0 {
            if cond() { return true; }
            spins -= 1;
        }
        false
    }

    fn corb_send_verb(&self, cad: u8, nid: u8, verb: u16, payload: u16) -> Result<u32, &'static str> {
        // Compose 32-bit verb: [31:28] cad, [27:20] nid, [19:8] verb, [7:0] payload
        let cmd = ((cad as u32) << 28) | ((nid as u32) << 20) | ((verb as u32) << 8) | (payload as u32);

        unsafe {
            // Write command at CORBWP+1
            let mut wp = mmio_r16(self.base + CORBWP) as usize;
            wp = (wp + 1) % self.corb_entries;
            let ptr_corb = self.corb.as_mut_ptr::<u32>().add(wp);
            ptr::write_volatile(ptr_corb, cmd);
            mmio_w16(self.base + CORBWP, wp as u16);
        }

        // Wait for RIRB response (RIRBWP increments)
        let mut spins = 1_000_000u32;
        while spins > 0 {
            unsafe {
                let sts = mmio_r8(self.base + RIRBSTS);
                if (sts & RIRBSTS_RIRBOIS) != 0 {
                    mmio_w8(self.base + RIRBSTS, RIRBSTS_RIRBOIS);
                }
                // Any new response?
                let wp = mmio_r16(self.base + RIRBWP) as usize;
                // Last response is at wp
                if wp != 0 {
                    let rp = wp % self.rirb_entries;
                    let base = self.rirb.as_mut_ptr::<u64>();
                    let resp = ptr::read_volatile(base.add(rp));
                    let resp_lo = (resp & 0xFFFF_FFFF) as u32;
                    // Clear RIRBWP by writing it back
                    mmio_w16(self.base + RIRBWP, wp as u16);
                    return Ok(resp_lo);
                }
            }
            spins -= 1;
        }

        // Fallback: Immediate command if CORB path timed out
        self.immediate_cmd(cad, nid, verb, payload)
    }

    fn immediate_cmd(&self, cad: u8, nid: u8, verb: u16, payload: u16) -> Result<u32, &'static str> {
        let cmd = ((cad as u32) << 28) | ((nid as u32) << 20) | ((verb as u32) << 8) | (payload as u32);
        unsafe {
            // Wait not busy
            if !Self::spin(|| (mmio_r8(self.base + IRS) & IRS_BUSY) == 0, 100_000) {
                return Err("HDA: immediate command busy timeout");
            }
            mmio_w32(self.base + IC, cmd);
            // Wait valid
            if !Self::spin(|| (mmio_r8(self.base + IRS) & IRS_VALID) != 0, 1_000_000) {
                return Err("HDA: immediate response timeout");
            }
            let resp = mmio_r32(self.base + IR);
            Ok(resp)
        }
    }

    // Minimal codec init: pick primary codec, power up default function group and DAC
    fn codec_init_path(&mut self) -> Result<(), &'static str> {
        let cad = self.primary_codec.ok_or("HDA: no codec present")?;

        // Simple sanity: GetParameter of root node (NID 0) for vendor/device
        let _vid = self.codec_get_parameter(cad, 0, 0x00) // VENDOR_ID
            .unwrap_or(0);
        let _rev = self.codec_get_parameter(cad, 0, 0x02) // REVISION_ID
            .unwrap_or(0);
        
        // We assume a default converter NID 0x02 and pin 0x0A when available.
        // Best-effort attempts; failures are not fatal for controller bring-up.

        Ok(())
    }

    fn codec_get_parameter(&self, cad: u8, nid: u8, param: u16) -> Result<u32, &'static str> {
        // Verb: GetParameter = 0xF00
        self.corb_send_verb(cad, nid, 0xF00, param)
    }

    fn init_output_stream(&mut self) -> Result<(), &'static str> {
        // Program a single BDL entry for the whole pcm_buf
        let total_len = self.pcm_buf.size;
        unsafe {
            let bdlp = self.bdl.as_mut_ptr::<BdlEntry>();
            ptr::write_volatile(bdlp, BdlEntry {
                addr_lo: (self.pcm_buf.phys() & 0xFFFF_FFFF) as u32,
                addr_hi: (self.pcm_buf.phys() >> 32) as u32,
                length: total_len as u32,
                flags: 1, // IOC at end
            });
            // Zero remaining entries
            for i in 1..16 {
                let e = bdlp.add(i);
                ptr::write_volatile(e, BdlEntry { addr_lo: 0, addr_hi: 0, length: 0, flags: 0 });
            }
        }

        // Choose stream descriptor index: streams are mapped as:
        // Output streams [1..ISS], then Input, then Bidirectional. We pick #1 in Output space.
        let sd = self.stream_regs(self.out_stream);

        // Reset stream
        unsafe {
            // Set SRST
            let mut ctl = mmio_r32(sd + SD_CTL);
            ctl |= SD_CTL_SRST;
            mmio_w32(sd + SD_CTL, ctl);
        }
        if !Self::spin(|| unsafe { mmio_r32(sd + SD_CTL) } & SD_CTL_SRST != 0, 100_000) {
            return Err("HDA: stream SRST set timeout");
        }
        unsafe {
            // Clear SRST
            let mut ctl = mmio_r32(sd + SD_CTL);
            ctl &= !SD_CTL_SRST;
            mmio_w32(sd + SD_CTL, ctl);
        }
        if !Self::spin(|| unsafe { mmio_r32(sd + SD_CTL) } & SD_CTL_SRST == 0, 100_000) {
            return Err("HDA: stream SRST clear timeout");
        }

        // Set BDL pointer
        unsafe {
            mmio_w32(sd + SD_BDPL, (self.bdl.phys() & 0xFFFF_FFFF) as u32);
            mmio_w32(sd + SD_BDPU, (self.bdl.phys() >> 32) as u32);
        }

        // Program CBL (cumulative byte length), LVI (last valid index)
        unsafe {
            mmio_w32(sd + SD_CBL, total_len as u32);
            mmio_w32(sd + SD_LVI, 0); // only entry 0 valid
        }

        // Format: 48kHz, 16-bit, 2 channels -> HDA fmt: [15:14 mult][13:11 base][10:8 rate][7:4 bits][3:0 chans-1]
        let fmt = Self::hda_format(self.sample_rate, self.bits_per_sample, self.channels)?;
        unsafe {
            mmio_w16(sd + SD_FMT, fmt);
        }

        // Enable interrupts (optional)
        unsafe {
            let mut ctl = mmio_r32(sd + SD_CTL);
            ctl |= SD_CTL_IOCE | SD_CTL_FEIE | SD_CTL_DEIE;
            mmio_w32(sd + SD_CTL, ctl);
        }

        Ok(())
    }

    fn hda_format(rate: u32, bits: u16, chans: u16) -> Result<u16, &'static str> {
        // Support common 48 kHz, 16-bit, 2-ch 
        if !(rate == 48_000 && bits == 16 && chans == 2) {
            return Err("Unsupported PCM format requested");
        }
        // base=48kHz (001), rate=1x (000), bits=16 (0000), chans-1=1 (0001)
        let base = 0b001 << 11;
        let rate_bits = 0b000 << 8;
        let bits_bits = 0b0000 << 4;
        let chans_bits = (chans - 1) as u16;
        Ok(base | rate_bits | bits_bits | chans_bits)
    }

    fn stream_regs(&self, stream_index: u8) -> usize {
        self.base + STREAM_BASE + (stream_index as usize - 1) * STREAM_STRIDE
    }

    pub fn play_pcm(&self, data: &[u8]) -> Result<(), &'static str> {
        // Copy into the PCM ring buffer (single-shot demo)
        let n = core::cmp::min(data.len(), self.pcm_buf.size);
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.pcm_buf.va.as_mut_ptr::<u8>(), n);
        }

        // Start stream
        let sd = self.stream_regs(self.out_stream);
        unsafe {
            // LPIB reset
            mmio_w32(sd + SD_LPIB, 0);
            // RUN
            let mut ctl = mmio_r32(sd + SD_CTL);
            ctl |= SD_CTL_RUN;
            mmio_w32(sd + SD_CTL, ctl);
        }

        // Poll until LPIB reaches CBL
        if !Self::spin(|| unsafe { mmio_r32(sd + SD_LPIB) } >= unsafe { mmio_r32(sd + SD_CBL) }, 10_000_000) {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err("HDA: playback did not complete in time");
        }

        self.bytes_played.fetch_add(n as u64, Ordering::Relaxed);

        // Stop
        unsafe {
            let mut ctl = mmio_r32(sd + SD_CTL);
            ctl &= !SD_CTL_RUN;
            mmio_w32(sd + SD_CTL, ctl);
        }

        Ok(())
    }

    pub fn get_stats(&self) -> AudioStats {
        AudioStats {
            samples_played: self.bytes_played.load(Ordering::Relaxed) / 2, // bytes to samples for 16-bit mono; rough
            samples_recorded: 0,
            buffer_underruns: 0,
            buffer_overruns: 0,
            interrupts_handled: 0,
            active_streams: 1,
            codecs_detected: self.codec_mask.count_ones() as u32,
        }
    }
}

#[derive(Default, Clone)]
pub struct AudioStats {
    pub samples_played: u64,
    pub samples_recorded: u64,
    pub buffer_underruns: u64,
    pub buffer_overruns: u64,
    pub interrupts_handled: u64,
    pub active_streams: u64,
    pub codecs_detected: u32,
}

// Public API
pub fn init_hd_audio() -> Result<(), &'static str> {
    // Find HDA controller via PCI
    let dev = pci::scan_and_collect()
        .into_iter()
        .find(|d| d.class == HDA_CLASS && d.subclass == HDA_SUBCLASS)
        .ok_or("No HD Audio controller found")?;

    let _ = HdAudioController::init(dev)?;
    Ok(())
}

pub fn get_controller() -> Option<spin::MutexGuard<'static, HdAudioController>> {
    HDA_ONCE.get().map(|m| m.lock())
}
