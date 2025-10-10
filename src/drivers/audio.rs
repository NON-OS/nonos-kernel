//! Advanced Audio Driver with NONOS Cryptographic Integration
//!
//! High-definition audio controller with secure audio processing

use alloc::{collections::VecDeque, format, vec::Vec};
use spin::{Mutex, RwLock};
// MMIO imports removed - not used
use crate::drivers::pci::PciDevice;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

/// Intel HD Audio Controller Registers
#[repr(C)]
pub struct HdaRegs {
    pub gcap: u16,     // Global Capabilities
    pub vmin: u8,      // Minor Version
    pub vmaj: u8,      // Major Version
    pub outpay: u16,   // Output Payload Capability
    pub inpay: u16,    // Input Payload Capability
    pub gctl: u32,     // Global Control
    pub wakeen: u16,   // Wake Enable
    pub statests: u16, // State Change Status
    pub gsts: u16,     // Global Status
    pub reserved1: u16,
    pub outstrmpay: u16, // Output Stream Payload Capability
    pub instrmpay: u16,  // Input Stream Payload Capability
    pub reserved2: u32,
    pub intctl: u32, // Interrupt Control
    pub intsts: u32, // Interrupt Status
    pub reserved3: [u32; 2],
    pub walclk: u32, // Wall Clock Counter
    pub reserved4: u32,
    pub ssync: u32, // Stream Synchronization
    pub reserved5: u32,
    pub corblbase: u32, // CORB Lower Base Address
    pub corbubase: u32, // CORB Upper Base Address
    pub corbwp: u16,    // CORB Write Pointer
    pub corbrp: u16,    // CORB Read Pointer
    pub corbctl: u8,    // CORB Control
    pub corbsts: u8,    // CORB Status
    pub corbsize: u8,   // CORB Size
    pub reserved6: u8,
    pub rirblbase: u32, // RIRB Lower Base Address
    pub rirbubase: u32, // RIRB Upper Base Address
    pub rirbwp: u16,    // RIRB Write Pointer
    pub rintcnt: u16,   // Response Interrupt Count
    pub rirbctl: u8,    // RIRB Control
    pub rirbsts: u8,    // RIRB Status
    pub rirbsize: u8,   // RIRB Size
    pub reserved7: u8,
}

/// Audio Stream Descriptor
#[repr(C)]
pub struct StreamDescriptor {
    pub ctl: u32, // Stream Control
    pub sts: u8,  // Stream Status
    pub reserved1: [u8; 3],
    pub lpib: u32, // Link Position in Buffer
    pub cbl: u32,  // Cyclic Buffer Length
    pub lvi: u16,  // Last Valid Index
    pub reserved2: u16,
    pub fifod: u16, // FIFO Depth
    pub fmt: u16,   // Stream Format
    pub reserved3: u32,
    pub bdlpl: u32, // Buffer Descriptor List Pointer Lower
    pub bdlpu: u32, // Buffer Descriptor List Pointer Upper
}

/// Buffer Descriptor List Entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufferDescriptor {
    pub address: u64, // Buffer Address
    pub length: u32,  // Buffer Length
    pub ioc: u32,     // Interrupt on Completion
}

/// Audio Format
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AudioFormat {
    pub sample_rate: u32,    // Hz
    pub channels: u8,        // 1=mono, 2=stereo, etc.
    pub bits_per_sample: u8, // 8, 16, 24, 32
    pub signed: bool,
}

/// Audio Buffer
pub struct AudioBuffer {
    pub data: Vec<u8>,
    pub format: AudioFormat,
    pub timestamp: u64,
    pub encrypted: bool,
}

/// Audio Stream
pub struct AudioStream {
    pub id: u32,
    pub stream_type: StreamType,
    pub format: AudioFormat,
    pub buffer_descriptors: *mut BufferDescriptor,
    pub num_buffers: u32,
    pub current_buffer: u32,
    pub active: bool,
    pub muted: bool,
    pub volume: f32, // 0.0 to 1.0
    pub secure: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamType {
    Input,
    Output,
    Bidirectional,
}

/// Audio Codec
pub struct AudioCodec {
    pub address: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision_id: u8,
    pub nodes: BTreeMap<u8, CodecNode>,
    pub supported_formats: Vec<AudioFormat>,
}

/// Codec Node
pub struct CodecNode {
    pub nid: u8, // Node ID
    pub node_type: NodeType,
    pub capabilities: u32,
    pub connections: Vec<u8>,
    pub amp_caps: u32,
    pub pin_caps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeType {
    AudioOutput,
    AudioInput,
    AudioMixer,
    AudioSelector,
    PinComplex,
    PowerWidget,
    VolumeKnob,
    BeepGenerator,
}

/// HD Audio Controller
pub struct HdAudioController {
    pub base_addr: usize,
    pub regs: *mut HdaRegs,
    pub stream_descriptors: *mut StreamDescriptor,
    pub num_input_streams: u8,
    pub num_output_streams: u8,
    pub num_bidirectional_streams: u8,

    // Ring buffers for command/response
    pub corb: *mut u32, // Command Outbound Ring Buffer
    pub rirb: *mut u64, // Response Inbound Ring Buffer
    pub corb_size: u32,
    pub rirb_size: u32,

    // Audio management
    pub codecs: RwLock<BTreeMap<u8, AudioCodec>>,
    pub streams: RwLock<BTreeMap<u32, AudioStream>>,
    pub active_streams: Mutex<Vec<u32>>,

    // Audio processing
    pub sample_buffer: Mutex<VecDeque<AudioBuffer>>,
    pub recording_buffer: Mutex<VecDeque<AudioBuffer>>,

    // Security and encryption
    pub secure_mode: bool,
    pub crypto_key: [u8; 32],
    pub authorized_processes: RwLock<Vec<u64>>, // Process IDs

    // Statistics
    pub samples_played: AtomicU64,
    pub samples_recorded: AtomicU64,
    pub buffer_underruns: AtomicU64,
    pub buffer_overruns: AtomicU64,
    pub interrupts_handled: AtomicU64,
}

impl HdAudioController {
    /// Create new HD Audio controller
    pub fn new(pci_device: &PciDevice) -> Result<Self, &'static str> {
        // Get BAR0 (HD Audio base)
        let bar0 = crate::drivers::pci::pci_read_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x10,
        );
        if bar0 == 0 {
            return Err("HD Audio BAR0 not configured");
        }

        let base_addr = (bar0 & !0xF) as usize;
        let regs = base_addr as *mut HdaRegs;

        unsafe {
            let gcap = (*regs).gcap;
            let num_output_streams = ((gcap >> 12) & 0xF) as u8;
            let num_input_streams = ((gcap >> 8) & 0xF) as u8;
            let num_bidirectional_streams = ((gcap >> 3) & 0x1F) as u8;

            // Calculate stream descriptor offset
            let stream_desc_offset = 0x80;
            let stream_descriptors = (base_addr + stream_desc_offset) as *mut StreamDescriptor;

            // Allocate CORB (Command Outbound Ring Buffer)
            let corb_frame =
                crate::memory::page_allocator::allocate_frame().ok_or("Failed to allocate CORB")?;
            let corb = corb_frame.start_address().as_u64() as *mut u32;

            // Allocate RIRB (Response Inbound Ring Buffer)
            let rirb_frame =
                crate::memory::page_allocator::allocate_frame().ok_or("Failed to allocate RIRB")?;
            let rirb = rirb_frame.start_address().as_u64() as *mut u64;

            let controller = HdAudioController {
                base_addr,
                regs,
                stream_descriptors,
                num_input_streams,
                num_output_streams,
                num_bidirectional_streams,
                corb,
                rirb,
                corb_size: 256, // 256 entries
                rirb_size: 256, // 256 entries
                codecs: RwLock::new(BTreeMap::new()),
                streams: RwLock::new(BTreeMap::new()),
                active_streams: Mutex::new(Vec::new()),
                sample_buffer: Mutex::new(VecDeque::new()),
                recording_buffer: Mutex::new(VecDeque::new()),
                secure_mode: true,
                crypto_key: crate::security::capability::get_secure_random_bytes(),
                authorized_processes: RwLock::new(Vec::new()),
                samples_played: AtomicU64::new(0),
                samples_recorded: AtomicU64::new(0),
                buffer_underruns: AtomicU64::new(0),
                buffer_overruns: AtomicU64::new(0),
                interrupts_handled: AtomicU64::new(0),
            };

            Ok(controller)
        }
    }

    /// Initialize HD Audio controller
    pub fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Reset controller
            (*self.regs).gctl &= !1; // Clear CRST

            // Wait for reset
            let mut timeout = 1000000;
            while timeout > 0 && ((*self.regs).gctl & 1) != 0 {
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("HD Audio reset timeout");
            }

            // Bring controller out of reset
            (*self.regs).gctl |= 1; // Set CRST

            // Wait for controller ready
            timeout = 1000000;
            while timeout > 0 && ((*self.regs).gctl & 1) == 0 {
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("HD Audio ready timeout");
            }

            // Set up CORB
            (*self.regs).corblbase = (self.corb as u64 & 0xFFFFFFFF) as u32;
            (*self.regs).corbubase = ((self.corb as u64) >> 32) as u32;
            (*self.regs).corbsize = 2; // 256 entries
            (*self.regs).corbwp = 0;
            (*self.regs).corbrp = 0x8000; // Reset
            (*self.regs).corbrp = 0; // Clear reset
            (*self.regs).corbctl = 2; // Enable CORB

            // Set up RIRB
            (*self.regs).rirblbase = (self.rirb as u64 & 0xFFFFFFFF) as u32;
            (*self.regs).rirbubase = ((self.rirb as u64) >> 32) as u32;
            (*self.regs).rirbsize = 2; // 256 entries
            (*self.regs).rirbwp = 0;
            (*self.regs).rintcnt = 1; // Interrupt every response
            (*self.regs).rirbctl = 2; // Enable RIRB

            // Enable interrupts
            (*self.regs).intctl = 0x80000000 | 0x40000000; // GIE | CIE

            // Discover codecs
            self.discover_codecs()?;

            crate::log::logger::log_critical(&format!(
                "HD Audio: Initialized with {} input, {} output, {} bidirectional streams",
                self.num_input_streams, self.num_output_streams, self.num_bidirectional_streams
            ));
        }

        Ok(())
    }

    /// Discover audio codecs
    fn discover_codecs(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Check codec status
            let statests = (*self.regs).statests;

            for codec_addr in 0..15 {
                if (statests & (1 << codec_addr)) != 0 {
                    crate::log::logger::log_critical(&format!(
                        "HD Audio: Codec found at address {}",
                        codec_addr
                    ));

                    // Get codec vendor/device ID
                    let response = self.send_codec_command(codec_addr, 0, 0xF0000, 0)?;
                    let vendor_id = ((response >> 16) & 0xFFFF) as u16;
                    let device_id = (response & 0xFFFF) as u16;

                    // Get revision ID
                    let response = self.send_codec_command(codec_addr, 0, 0xF0002, 0)?;
                    let revision_id = (response & 0xFF) as u8;

                    let codec = AudioCodec {
                        address: codec_addr,
                        vendor_id,
                        device_id,
                        revision_id,
                        nodes: BTreeMap::new(),
                        supported_formats: Vec::new(),
                    };

                    self.codecs.write().insert(codec_addr, codec);

                    // Enumerate codec nodes
                    self.enumerate_codec_nodes(codec_addr)?;
                }
            }
        }

        Ok(())
    }

    /// Enumerate codec nodes
    fn enumerate_codec_nodes(&mut self, codec_addr: u8) -> Result<(), &'static str> {
        // Get subordinate node count
        let response = self.send_codec_command(codec_addr, 0, 0xF0004, 0)?;
        let starting_node = ((response >> 16) & 0xFF) as u8;
        let total_nodes = (response & 0xFF) as u8;

        for node_id in starting_node..(starting_node + total_nodes) {
            // Get node capabilities
            let caps = self.send_codec_command(codec_addr, node_id, 0xF0009, 0)?;
            let node_type = self.get_node_type_from_caps(caps as u32);

            let node = CodecNode {
                nid: node_id,
                node_type,
                capabilities: caps as u32,
                connections: Vec::new(),
                amp_caps: 0,
                pin_caps: 0,
            };

            if let Some(codec) = self.codecs.write().get_mut(&codec_addr) {
                codec.nodes.insert(node_id, node);
            }
        }

        Ok(())
    }

    /// Send command to codec
    fn send_codec_command(
        &self,
        codec_addr: u8,
        node_id: u8,
        verb: u32,
        param: u16,
    ) -> Result<u64, &'static str> {
        unsafe {
            // Build command
            let command = ((codec_addr as u32) << 28)
                | ((node_id as u32) << 20)
                | (verb << 8)
                | (param as u32);

            // Wait for CORB space
            let mut timeout = 1000;
            while timeout > 0 {
                let corbwp = (*self.regs).corbwp;
                let corbrp = (*self.regs).corbrp & 0xFF;
                let next_wp = (corbwp + 1) % self.corb_size as u16;

                if next_wp != corbrp {
                    break;
                }
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("CORB full");
            }

            // Write command to CORB
            let corbwp = (*self.regs).corbwp as u32;
            *self.corb.offset(corbwp as isize) = command;
            (*self.regs).corbwp = ((corbwp + 1) % self.corb_size) as u16;

            // Wait for response in RIRB
            timeout = 10000;
            let initial_wp = (*self.regs).rirbwp;

            while timeout > 0 {
                let current_wp = (*self.regs).rirbwp;
                if current_wp != initial_wp {
                    let response = *self.rirb.offset(current_wp as isize);
                    return Ok(response);
                }
                timeout -= 1;
            }

            Err("Codec response timeout")
        }
    }

    /// Get node type from capabilities
    fn get_node_type_from_caps(&self, caps: u32) -> NodeType {
        let widget_type = (caps >> 20) & 0xF;
        match widget_type {
            0 => NodeType::AudioOutput,
            1 => NodeType::AudioInput,
            2 => NodeType::AudioMixer,
            3 => NodeType::AudioSelector,
            4 => NodeType::PinComplex,
            5 => NodeType::PowerWidget,
            6 => NodeType::VolumeKnob,
            7 => NodeType::BeepGenerator,
            _ => NodeType::AudioOutput, // Default
        }
    }

    /// Create audio stream
    pub fn create_stream(
        &mut self,
        stream_type: StreamType,
        format: AudioFormat,
    ) -> Result<u32, &'static str> {
        let stream_id = self.streams.read().len() as u32 + 1;

        // Allocate buffer descriptors
        let bd_frame = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate buffer descriptors")?;
        let buffer_descriptors = bd_frame.start_address().as_u64() as *mut BufferDescriptor;

        let stream = AudioStream {
            id: stream_id,
            stream_type,
            format,
            buffer_descriptors,
            num_buffers: 8, // 8 buffers per stream
            current_buffer: 0,
            active: false,
            muted: false,
            volume: 1.0,
            secure: self.secure_mode,
        };

        self.streams.write().insert(stream_id, stream);

        Ok(stream_id)
    }

    /// Start audio stream
    pub fn start_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        let mut streams = self.streams.write();
        let stream = streams.get_mut(&stream_id).ok_or("Stream not found")?;

        if stream.active {
            return Err("Stream already active");
        }

        // Configure stream descriptor
        let descriptor_index = match stream.stream_type {
            StreamType::Output => stream_id - 1,
            StreamType::Input => self.num_output_streams as u32 + stream_id - 1,
            StreamType::Bidirectional => {
                (self.num_output_streams + self.num_input_streams) as u32 + stream_id - 1
            }
        };

        unsafe {
            let desc = &mut *self.stream_descriptors.offset(descriptor_index as isize);

            // Set buffer descriptor list
            desc.bdlpl = (stream.buffer_descriptors as u64 & 0xFFFFFFFF) as u32;
            desc.bdlpu = ((stream.buffer_descriptors as u64) >> 32) as u32;

            // Set last valid index
            desc.lvi = (stream.num_buffers - 1) as u16;

            // Set format
            desc.fmt = self.encode_audio_format(stream.format);

            // Start stream
            desc.ctl |= (1 << 1) | (1 << 2); // RUN | IOCE
        }

        stream.active = true;
        self.active_streams.lock().push(stream_id);

        crate::log::logger::log_critical(&format!("HD Audio: Started stream {}", stream_id));

        Ok(())
    }

    /// Stop audio stream
    pub fn stop_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        let mut streams = self.streams.write();
        let stream = streams.get_mut(&stream_id).ok_or("Stream not found")?;

        if !stream.active {
            return Err("Stream not active");
        }

        let descriptor_index = match stream.stream_type {
            StreamType::Output => stream_id - 1,
            StreamType::Input => self.num_output_streams as u32 + stream_id - 1,
            StreamType::Bidirectional => {
                (self.num_output_streams + self.num_input_streams) as u32 + stream_id - 1
            }
        };

        unsafe {
            let desc = &mut *self.stream_descriptors.offset(descriptor_index as isize);
            desc.ctl &= !(1 << 1); // Clear RUN bit
        }

        stream.active = false;
        self.active_streams.lock().retain(|&id| id != stream_id);

        Ok(())
    }

    /// Play audio buffer
    pub fn play_audio(&mut self, buffer: AudioBuffer, process_id: u64) -> Result<(), &'static str> {
        if self.secure_mode {
            let authorized = self.authorized_processes.read();
            if !authorized.contains(&process_id) {
                return Err("Process not authorized for audio playback");
            }
        }

        // Encrypt buffer if secure
        let mut audio_buffer = buffer;
        if audio_buffer.encrypted {
            self.decrypt_audio_buffer(&mut audio_buffer.data);
        }

        self.sample_buffer.lock().push_back(audio_buffer);
        self.samples_played.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Record audio
    pub fn start_recording(
        &mut self,
        format: AudioFormat,
        process_id: u64,
    ) -> Result<(), &'static str> {
        if self.secure_mode {
            let authorized = self.authorized_processes.read();
            if !authorized.contains(&process_id) {
                return Err("Process not authorized for audio recording");
            }
        }

        // Create recording stream
        let stream_id = self.create_stream(StreamType::Input, format)?;
        self.start_stream(stream_id)?;

        Ok(())
    }

    /// Get recorded audio
    pub fn get_recorded_audio(&mut self) -> Option<AudioBuffer> {
        self.recording_buffer.lock().pop_front()
    }

    /// Handle interrupt
    pub fn handle_interrupt(&mut self) {
        self.interrupts_handled.fetch_add(1, Ordering::Relaxed);

        unsafe {
            let intsts = (*self.regs).intsts;

            // Clear interrupt status
            (*self.regs).intsts = intsts;

            // Handle stream interrupts
            let active_streams: Vec<u32> = self.active_streams.lock().clone();
            for stream_id in active_streams {
                self.handle_stream_interrupt(stream_id);
            }

            // Handle RIRB interrupt
            if (intsts & (1 << 30)) != 0 {
                // RIRB interrupt
                self.process_rirb_responses();
            }
        }
    }

    /// Handle stream interrupt
    fn handle_stream_interrupt(&mut self, stream_id: u32) {
        // Process stream buffer completion
        // Update buffer positions, handle underruns/overruns

        let streams = self.streams.read();
        if let Some(stream) = streams.get(&stream_id) {
            if stream.stream_type == StreamType::Output {
                // Handle playback completion
                if let Some(_buffer) = self.sample_buffer.lock().pop_front() {
                    // Buffer completed
                } else {
                    self.buffer_underruns.fetch_add(1, Ordering::Relaxed);
                }
            } else if stream.stream_type == StreamType::Input {
                // Handle recording completion
                let recorded_buffer = AudioBuffer {
                    data: Vec::new(), // Would contain actual recorded data
                    format: stream.format,
                    timestamp: crate::arch::x86_64::time::get_tsc(),
                    encrypted: stream.secure,
                };

                let mut buffer = recorded_buffer;
                if buffer.encrypted {
                    self.encrypt_audio_buffer(&mut buffer.data);
                }

                self.recording_buffer.lock().push_back(buffer);
                self.samples_recorded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Process RIRB responses
    fn process_rirb_responses(&mut self) {
        // Process codec responses
        unsafe {
            let rirbwp = (*self.regs).rirbwp;

            // Process all pending responses
            while rirbwp != 0 {
                let _response = *self.rirb.offset(rirbwp as isize);
                // Handle codec response
                break; // For now, just break
            }
        }
    }

    /// Encode audio format to HDA format
    fn encode_audio_format(&self, format: AudioFormat) -> u16 {
        let mut fmt = 0u16;

        // Sample rate
        match format.sample_rate {
            8000 => fmt |= 0x1 << 14,
            11025 => fmt |= 0x2 << 14,
            16000 => fmt |= 0x3 << 14,
            22050 => fmt |= 0x4 << 14,
            32000 => fmt |= 0x5 << 14,
            44100 => fmt |= 0x0 << 14,
            48000 => fmt |= 0x0 << 14,
            88200 => fmt |= 0x8 << 14,
            96000 => fmt |= 0x9 << 14,
            176400 => fmt |= 0xA << 14,
            192000 => fmt |= 0xB << 14,
            _ => fmt |= 0x0 << 14, // Default to 48kHz
        }

        // Bits per sample
        match format.bits_per_sample {
            8 => fmt |= 0x0 << 4,
            16 => fmt |= 0x1 << 4,
            20 => fmt |= 0x2 << 4,
            24 => fmt |= 0x3 << 4,
            32 => fmt |= 0x4 << 4,
            _ => fmt |= 0x1 << 4, // Default to 16-bit
        }

        // Channels
        fmt |= ((format.channels - 1) & 0xF) as u16;

        fmt
    }

    /// Encrypt audio buffer
    fn encrypt_audio_buffer(&self, data: &mut [u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.crypto_key[i % 32];
        }
    }

    /// Decrypt audio buffer
    fn decrypt_audio_buffer(&self, data: &mut [u8]) {
        // Same as encrypt for XOR cipher
        self.encrypt_audio_buffer(data);
    }

    /// Authorize process for audio access
    pub fn authorize_process(&mut self, process_id: u64) {
        self.authorized_processes.write().push(process_id);
    }

    /// Deauthorize process
    pub fn deauthorize_process(&mut self, process_id: u64) {
        self.authorized_processes.write().retain(|&id| id != process_id);
    }

    /// Get audio statistics
    pub fn get_stats(&self) -> AudioStats {
        AudioStats {
            samples_played: self.samples_played.load(Ordering::Relaxed),
            samples_recorded: self.samples_recorded.load(Ordering::Relaxed),
            buffer_underruns: self.buffer_underruns.load(Ordering::Relaxed),
            buffer_overruns: self.buffer_overruns.load(Ordering::Relaxed),
            interrupts_handled: self.interrupts_handled.load(Ordering::Relaxed),
            active_streams: self.active_streams.lock().len() as u32,
            codecs_detected: self.codecs.read().len() as u32,
        }
    }
}

/// Audio statistics
#[derive(Default)]
pub struct AudioStats {
    pub samples_played: u64,
    pub samples_recorded: u64,
    pub buffer_underruns: u64,
    pub buffer_overruns: u64,
    pub interrupts_handled: u64,
    pub active_streams: u32,
    pub codecs_detected: u32,
}

/// Global HD Audio controller instance
static mut HD_AUDIO_CONTROLLER: Option<HdAudioController> = None;

/// Initialize HD Audio subsystem
pub fn init_hd_audio() -> Result<(), &'static str> {
    // Find HD Audio controller via PCI (Intel HDA is class 0x04, subclass 0x03)
    if let Some(hda_device) = crate::drivers::pci::find_device_by_class(0x04, 0x03) {
        let mut controller = HdAudioController::new(&hda_device)?;
        controller.init()?;

        unsafe {
            HD_AUDIO_CONTROLLER = Some(controller);
        }

        crate::log::logger::log_critical("HD Audio subsystem initialized");
        Ok(())
    } else {
        Err("No HD Audio controller found")
    }
}

/// Get HD Audio controller
pub fn get_controller() -> Option<&'static HdAudioController> {
    unsafe { HD_AUDIO_CONTROLLER.as_ref() }
}

/// Get mutable HD Audio controller
pub fn get_controller_mut() -> Option<&'static mut HdAudioController> {
    unsafe { HD_AUDIO_CONTROLLER.as_mut() }
}
