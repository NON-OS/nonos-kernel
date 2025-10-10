//! xHCI (eXtensible Host Controller Interface) USB 3.0 Driver  
//!
//! Advanced USB 3.0 controller with NONOS security integration

use crate::drivers::pci::PciDevice;
use alloc::collections::BTreeMap;
use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

/// xHCI Capability Registers
#[repr(C)]
pub struct XhciCapRegs {
    pub caplength: u8, // Capability Register Length
    pub reserved: u8,
    pub hciversion: u16, // Host Controller Interface Version
    pub hcsparams1: u32, // Structural Parameters 1
    pub hcsparams2: u32, // Structural Parameters 2
    pub hcsparams3: u32, // Structural Parameters 3
    pub hccparams1: u32, // Capability Parameters 1
    pub dboff: u32,      // Doorbell Offset
    pub rtsoff: u32,     // Runtime Register Space Offset
    pub hccparams2: u32, // Capability Parameters 2
}

/// xHCI Operational Registers
#[repr(C)]
pub struct XhciOpRegs {
    pub usbcmd: u32,   // USB Command
    pub usbsts: u32,   // USB Status
    pub pagesize: u32, // Page Size
    pub reserved1: [u32; 2],
    pub dnctrl: u32, // Device Notification Control
    pub crcr: u64,   // Command Ring Control Register
    pub reserved2: [u32; 4],
    pub dcbaap: u64, // Device Context Base Address Array Pointer
    pub config: u32, // Configure
    pub reserved3: [u32; 241],
    pub portsc: [u32; 256], // Port Status and Control
}

/// xHCI Runtime Registers
#[repr(C)]
pub struct XhciRuntimeRegs {
    pub mfindex: u32, // Microframe Index
    pub reserved: [u32; 7],
    pub iman: [u32; 1024],   // Interrupter Management
    pub imod: [u32; 1024],   // Interrupter Moderation
    pub erstsz: [u32; 1024], // Event Ring Segment Table Size
    pub reserved2: [u32; 1024],
    pub erstba: [u64; 1024], // Event Ring Segment Table Base Address
    pub erdp: [u64; 1024],   // Event Ring Dequeue Pointer
}

/// Transfer Ring Buffer (TRB)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

/// Command Ring
pub struct CommandRing {
    pub trbs: *mut Trb,
    pub size: u32,
    pub enqueue: u32,
    pub dequeue: u32,
    pub cycle_state: bool,
}

/// Event Ring
pub struct EventRing {
    pub trbs: *mut Trb,
    pub size: u32,
    pub dequeue: u32,
    pub cycle_state: bool,
}

/// USB Device Context
#[repr(C)]
pub struct DeviceContext {
    pub slot_context: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

/// Slot Context
#[repr(C)]
pub struct SlotContext {
    pub route_string: u32,
    pub speed_entries: u32,
    pub tt_info: u32,
    pub device_state: u32,
    pub reserved: [u32; 4],
}

/// Endpoint Context
#[repr(C)]
pub struct EndpointContext {
    pub ep_info: u32,
    pub ep_info2: u32,
    pub dequeue_ptr: u64,
    pub transfer_info: u32,
    pub reserved: [u32; 3],
}

/// USB Device
pub struct UsbDevice {
    pub slot_id: u32,
    pub device_address: u8,
    pub port: u8,
    pub speed: UsbSpeed,
    pub device_class: u8,
    pub device_subclass: u8,
    pub protocol: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: alloc::string::String,
    pub product: alloc::string::String,
    pub serial_number: alloc::string::String,
    pub device_context: *mut DeviceContext,
    pub authenticated: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UsbSpeed {
    FullSpeed = 1,      // 12 Mbps
    LowSpeed = 2,       // 1.5 Mbps
    HighSpeed = 3,      // 480 Mbps
    SuperSpeed = 4,     // 5 Gbps
    SuperSpeedPlus = 5, // 10+ Gbps
}

/// xHCI Controller
pub struct XhciController {
    pub base_addr: usize,
    pub cap_regs: *const XhciCapRegs,
    pub op_regs: *mut XhciOpRegs,
    pub runtime_regs: *mut XhciRuntimeRegs,
    pub doorbell_regs: *mut u32,

    // Ring structures
    pub command_ring: Mutex<CommandRing>,
    pub event_ring: Mutex<EventRing>,

    // Device management
    pub devices: RwLock<BTreeMap<u32, UsbDevice>>,
    pub device_contexts: *mut u64, // Device Context Base Address Array
    pub max_slots: u32,
    pub max_ports: u32,

    // Statistics
    pub transfers: AtomicU64,
    pub errors: AtomicU64,
    pub interrupts: AtomicU64,
    pub bytes_transferred: AtomicU64,

    // Security
    pub security_enabled: bool,
    pub device_whitelist: RwLock<Vec<(u16, u16)>>, // (vendor_id, product_id)
    pub crypto_key: [u8; 32],
}

impl XhciController {
    /// Create new xHCI controller
    pub fn new(pci_device: &PciDevice) -> Result<Self, &'static str> {
        // Get BAR0 (xHCI base)
        let bar0 = crate::drivers::pci::pci_read_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x10,
        );
        if bar0 == 0 {
            return Err("xHCI BAR0 not configured");
        }

        let base_addr = (bar0 & !0xF) as usize;
        let cap_regs = base_addr as *const XhciCapRegs;

        unsafe {
            let caplength = (*cap_regs).caplength as usize;
            let op_regs = (base_addr + caplength) as *mut XhciOpRegs;
            let rtsoff = (*cap_regs).rtsoff as usize;
            let runtime_regs = (base_addr + rtsoff) as *mut XhciRuntimeRegs;
            let dboff = (*cap_regs).dboff as usize;
            let doorbell_regs = (base_addr + dboff) as *mut u32;

            let hcsparams1 = (*cap_regs).hcsparams1;
            let max_slots = hcsparams1 & 0xFF;
            let max_ports = (hcsparams1 >> 24) & 0xFF;

            // Allocate command ring
            let cmd_ring_frame = crate::memory::page_allocator::allocate_frame()
                .ok_or("Failed to allocate command ring")?;
            let cmd_ring_addr = cmd_ring_frame.start_address().as_u64() as *mut Trb;

            // Allocate event ring
            let event_ring_frame = crate::memory::page_allocator::allocate_frame()
                .ok_or("Failed to allocate event ring")?;
            let event_ring_addr = event_ring_frame.start_address().as_u64() as *mut Trb;

            // Allocate device contexts array
            let dcbaa_frame = crate::memory::page_allocator::allocate_frame()
                .ok_or("Failed to allocate DCBAA")?;
            let device_contexts = dcbaa_frame.start_address().as_u64() as *mut u64;

            let controller = XhciController {
                base_addr,
                cap_regs,
                op_regs,
                runtime_regs,
                doorbell_regs,
                command_ring: Mutex::new(CommandRing {
                    trbs: cmd_ring_addr,
                    size: 256,
                    enqueue: 0,
                    dequeue: 0,
                    cycle_state: true,
                }),
                event_ring: Mutex::new(EventRing {
                    trbs: event_ring_addr,
                    size: 256,
                    dequeue: 0,
                    cycle_state: true,
                }),
                devices: RwLock::new(BTreeMap::new()),
                device_contexts,
                max_slots,
                max_ports,
                transfers: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                interrupts: AtomicU64::new(0),
                bytes_transferred: AtomicU64::new(0),
                security_enabled: true,
                device_whitelist: RwLock::new(Vec::new()),
                crypto_key: crate::security::capability::get_secure_random_bytes(),
            };

            Ok(controller)
        }
    }

    /// Initialize xHCI controller
    pub fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Check if controller is halted
            let usbsts = (*self.op_regs).usbsts;
            if (usbsts & (1 << 0)) == 0 {
                return Err("xHCI controller not halted");
            }

            // Reset controller
            (*self.op_regs).usbcmd = 1 << 1; // Host Controller Reset

            // Wait for reset complete
            let mut timeout = 1000000;
            while timeout > 0 {
                let usbcmd = (*self.op_regs).usbcmd;
                if (usbcmd & (1 << 1)) == 0 {
                    break;
                }
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("xHCI reset timeout");
            }

            // Wait for controller ready
            timeout = 1000000;
            while timeout > 0 {
                let usbsts = (*self.op_regs).usbsts;
                if (usbsts & (1 << 11)) == 0 {
                    // Controller Not Ready
                    break;
                }
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("xHCI ready timeout");
            }

            // Set max device slots
            (*self.op_regs).config = self.max_slots;

            // Set Device Context Base Address Array
            (*self.op_regs).dcbaap = self.device_contexts as u64;

            // Initialize command ring
            let cmd_ring = self.command_ring.lock();
            (*self.op_regs).crcr = (cmd_ring.trbs as u64) | 1; // Ring Cycle State
            drop(cmd_ring);

            // Initialize event ring
            self.init_event_ring()?;

            // Enable interrupts
            (*self.runtime_regs).iman[0] = (1 << 1) | (1 << 0); // IP | IE

            // Start controller
            (*self.op_regs).usbcmd = (1 << 2) | (1 << 3) | (1 << 0); // EWE | HSEE | RS

            // Wait for controller running
            timeout = 1000000;
            while timeout > 0 {
                let usbsts = (*self.op_regs).usbsts;
                if (usbsts & (1 << 0)) == 0 {
                    // HCH - HC Halted
                    break;
                }
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("xHCI start timeout");
            }

            // Scan ports for devices
            self.scan_ports();

            crate::log::logger::log_critical(&format!(
                "xHCI: Controller initialized with {} slots, {} ports",
                self.max_slots, self.max_ports
            ));
        }

        Ok(())
    }

    /// Initialize event ring
    fn init_event_ring(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Allocate Event Ring Segment Table
            let erstsz_frame = crate::memory::page_allocator::allocate_frame()
                .ok_or("Failed to allocate ERSTSZ")?;
            let erst_addr = erstsz_frame.start_address().as_u64();

            // Set up Event Ring Segment Table entry
            let erst_entry = erst_addr as *mut u64;
            *erst_entry.offset(0) = self.event_ring.lock().trbs as u64; // Ring Segment Base Address
            *erst_entry.offset(1) = 256 | (0 << 16); // Ring Segment Size | Reserved

            // Configure event ring
            (*self.runtime_regs).erstsz[0] = 1; // 1 segment
            (*self.runtime_regs).erstba[0] = erst_addr;
            (*self.runtime_regs).erdp[0] = self.event_ring.lock().trbs as u64;
        }

        Ok(())
    }

    /// Scan ports for connected devices
    fn scan_ports(&mut self) {
        unsafe {
            for port in 1..=self.max_ports {
                let portsc = (*self.op_regs).portsc[(port - 1) as usize];

                // Check if device connected
                if (portsc & (1 << 0)) != 0 {
                    // Current Connect Status
                    crate::log::logger::log_critical(&format!(
                        "xHCI: Device detected on port {}",
                        port
                    ));

                    // Reset port
                    (*self.op_regs).portsc[(port - 1) as usize] = portsc | (1 << 4); // Port Reset

                    // Wait for reset complete
                    let mut timeout = 1000000;
                    while timeout > 0 {
                        let portsc = (*self.op_regs).portsc[(port - 1) as usize];
                        if (portsc & (1 << 4)) == 0 {
                            // Port Reset Clear
                            break;
                        }
                        timeout -= 1;
                    }

                    if timeout > 0 {
                        // Device enumeration would continue here
                        self.enumerate_device(port as u8);
                    }
                }
            }
        }
    }

    /// Enumerate USB device
    fn enumerate_device(&mut self, port: u8) {
        // This would perform the full USB enumeration process:
        // 1. Enable slot
        // 2. Address device
        // 3. Get device descriptor
        // 4. Set configuration
        // 5. Security validation

        crate::log::logger::log_critical(&format!("xHCI: Enumerating device on port {}", port));

        // For now, just log that enumeration would happen
        // Full implementation would require proper TRB handling
    }

    /// Transfer data to/from USB device
    pub fn transfer_data(
        &mut self,
        slot_id: u32,
        endpoint: u8,
        data: &[u8],
        direction: TransferDirection,
    ) -> Result<usize, &'static str> {
        if !self.devices.read().contains_key(&slot_id) {
            return Err("Device not found");
        }

        // Security check
        if self.security_enabled {
            let device = &self.devices.read()[&slot_id];
            if !device.authenticated {
                return Err("Device not authenticated");
            }

            // Check whitelist
            let whitelist = self.device_whitelist.read();
            let allowed = whitelist
                .iter()
                .any(|(vid, pid)| *vid == device.vendor_id && *pid == device.product_id);

            if !allowed && !whitelist.is_empty() {
                return Err("Device not in whitelist");
            }
        }

        // Build transfer TRB
        self.build_transfer_trb(slot_id, endpoint, data, direction)?;

        // Ring doorbell
        unsafe {
            *self.doorbell_regs.offset(slot_id as isize) = endpoint as u32;
        }

        self.transfers.fetch_add(1, Ordering::Relaxed);
        self.bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    /// Build transfer TRB
    fn build_transfer_trb(
        &mut self,
        _slot_id: u32,
        _endpoint: u8,
        _data: &[u8],
        _direction: TransferDirection,
    ) -> Result<(), &'static str> {
        // This would build the actual Transfer TRB
        // Implementation would handle proper TRB construction
        Ok(())
    }

    /// Handle interrupt
    pub fn handle_interrupt(&mut self) {
        self.interrupts.fetch_add(1, Ordering::Relaxed);

        unsafe {
            // Check interrupt status
            let usbsts = (*self.op_regs).usbsts;
            if (usbsts & (1 << 3)) != 0 {
                // Event Interrupt
                self.process_events();
                (*self.op_regs).usbsts = 1 << 3; // Clear interrupt
            }
        }
    }

    /// Process event ring events
    fn process_events(&self) {
        let mut event_ring = self.event_ring.lock();

        loop {
            let trb = unsafe { &*event_ring.trbs.offset(event_ring.dequeue as isize) };

            // Check cycle bit
            let cycle_bit = (trb.control & (1 << 0)) != 0;
            if cycle_bit != event_ring.cycle_state {
                break; // No more events
            }

            // Process event
            let trb_type = (trb.control >> 10) & 0x3F;
            match trb_type {
                32 => self.handle_transfer_event(trb),     // Transfer Event
                33 => self.handle_command_completion(trb), // Command Completion Event
                34 => self.handle_port_status_change(trb), // Port Status Change Event
                _ => {}                                    // Unknown event
            }

            // Advance dequeue pointer
            event_ring.dequeue = (event_ring.dequeue + 1) % event_ring.size;
            if event_ring.dequeue == 0 {
                event_ring.cycle_state = !event_ring.cycle_state;
            }
        }

        // Update event ring dequeue pointer
        unsafe {
            (*self.runtime_regs).erdp[0] = (event_ring.trbs as u64)
                + (event_ring.dequeue as u64 * core::mem::size_of::<Trb>() as u64);
        }
    }

    fn handle_transfer_event(&self, trb: &Trb) {
        // Handle transfer completion
        let completion_code = (trb.status >> 24) & 0xFF;
        if completion_code != 1 {
            // Not success
            self.errors.fetch_add(1, Ordering::Relaxed);
            crate::log::logger::log_critical(&format!("xHCI: Transfer error: {}", completion_code));
        }
    }

    fn handle_command_completion(&self, trb: &Trb) {
        // Handle command completion
        let completion_code = (trb.status >> 24) & 0xFF;
        if completion_code != 1 {
            // Not success
            self.errors.fetch_add(1, Ordering::Relaxed);
            crate::log::logger::log_critical(&format!("xHCI: Command error: {}", completion_code));
        }
    }

    fn handle_port_status_change(&self, trb: &Trb) {
        // Handle port status change
        let port_id = (trb.parameter >> 24) & 0xFF;
        crate::log::logger::log_critical(&format!("xHCI: Port {} status changed", port_id));
    }

    /// Add device to whitelist
    pub fn add_to_whitelist(&mut self, vendor_id: u16, product_id: u16) {
        self.device_whitelist.write().push((vendor_id, product_id));
    }

    /// Remove device from whitelist
    pub fn remove_from_whitelist(&mut self, vendor_id: u16, product_id: u16) {
        self.device_whitelist
            .write()
            .retain(|(vid, pid)| !(*vid == vendor_id && *pid == product_id));
    }

    /// Get controller statistics
    pub fn get_stats(&self) -> XhciStats {
        XhciStats {
            transfers: self.transfers.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            interrupts: self.interrupts.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            devices_connected: self.devices.read().len() as u32,
            max_slots: self.max_slots,
            max_ports: self.max_ports,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransferDirection {
    In,
    Out,
}

/// xHCI Statistics
#[derive(Default)]
pub struct XhciStats {
    pub transfers: u64,
    pub errors: u64,
    pub interrupts: u64,
    pub bytes_transferred: u64,
    pub devices_connected: u32,
    pub max_slots: u32,
    pub max_ports: u32,
}

/// Global xHCI controller instance
static mut XHCI_CONTROLLER: Option<XhciController> = None;

/// Initialize xHCI subsystem
pub fn init_xhci() -> Result<(), &'static str> {
    // Find xHCI controller via PCI
    if let Some(xhci_device) = crate::drivers::pci::find_device_by_class(0x0C, 0x03) {
        let mut controller = XhciController::new(&xhci_device)?;
        controller.init()?;

        unsafe {
            XHCI_CONTROLLER = Some(controller);
        }

        crate::log::logger::log_critical("xHCI subsystem initialized");
        Ok(())
    } else {
        Err("No xHCI controller found")
    }
}

/// Get xHCI controller
pub fn get_controller() -> Option<&'static XhciController> {
    unsafe { XHCI_CONTROLLER.as_ref() }
}

/// Get mutable xHCI controller
pub fn get_controller_mut() -> Option<&'static mut XhciController> {
    unsafe { XHCI_CONTROLLER.as_mut() }
}
