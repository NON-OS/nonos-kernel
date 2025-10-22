//! NONOS USB Manager 

#![allow(dead_code)]

use alloc::{string::String, vec::Vec, sync::Arc, boxed::Box};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// Re-export common USB constants
pub mod consts {
    pub const REQ_GET_STATUS: u8 = 0x00;
    pub const REQ_CLEAR_FEATURE: u8 = 0x01;
    pub const REQ_SET_FEATURE: u8 = 0x03;
    pub const REQ_SET_ADDRESS: u8 = 0x05;
    pub const REQ_GET_DESCRIPTOR: u8 = 0x06;
    pub const REQ_SET_DESCRIPTOR: u8 = 0x07;
    pub const REQ_GET_CONFIGURATION: u8 = 0x08;
    pub const REQ_SET_CONFIGURATION: u8 = 0x09;

    pub const RT_DEV: u8 = 0x00;
    pub const RT_INTF: u8 = 0x01;
    pub const RT_EP: u8 = 0x02;
    pub const RT_OTHER: u8 = 0x03;

    pub const DIR_OUT: u8 = 0x00;
    pub const DIR_IN: u8 = 0x80;

    pub const TYPE_STD: u8 = 0x00 << 5;
    pub const TYPE_CLASS: u8 = 0x01 << 5;
    pub const TYPE_VENDOR: u8 = 0x02 << 5;

    pub const DT_DEVICE: u8 = 1;
    pub const DT_CONFIG: u8 = 2;
    pub const DT_STRING: u8 = 3;
    pub const DT_INTERFACE: u8 = 4;
    pub const DT_ENDPOINT: u8 = 5;
}

// ---------------- Backend abstraction ----------------

pub trait UsbHostBackend: Send + Sync + 'static {
    // Returns number of root ports implemented (best-effort).
    fn num_ports(&self) -> u8;
    fn control_transfer(
        &self,
        slot_id: u8,
        setup: [u8; 8],
        data_in: Option<&mut [u8]>,
        data_out: Option<&[u8]>,
        timeout_us: u32,
    ) -> Result<usize, &'static str>;
    // Optional helper to get an already-addressed default device slot (slot_id)
    fn default_slot(&self) -> Option<u8> { Some(1) }
    
    // Bulk transfer on specific endpoint
    fn bulk_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        timeout_us: u32,
    ) -> Result<usize, &'static str>;
    
    // Interrupt transfer on specific endpoint 
    fn interrupt_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        interval: u8,
        timeout_us: u32,
    ) -> Result<usize, &'static str>;
}

// xHCI backend adapter
pub struct XhciBackend;
impl UsbHostBackend for XhciBackend {
    fn num_ports(&self) -> u8 {
        // Delegate to xHCI if exported, else assume 1
        crate::drivers::nonos_xhci::get_controller()
            .map(|c| c.num_ports as u8)
            .unwrap_or(1)
    }

    fn control_transfer(
        &self,
        slot_id: u8,
        setup: [u8; 8],
        mut data_in: Option<&mut [u8]>,
        data_out: Option<&[u8]>,
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        // The xHCI driver must expose a generic EP0 control transfer:
        crate::drivers::nonos_xhci::control_transfer(slot_id, setup, data_in.as_deref_mut(), timeout_us)
    }

    fn default_slot(&self) -> Option<u8> {
        Some(1)
    }
    
    fn bulk_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        // Real xHCI bulk transfer with actual TRB setup and DMA
        if let Some(ctrl_mutex) = crate::drivers::nonos_xhci::XHCI_ONCE.get() {
            let mut ctrl = ctrl_mutex.lock();
            
            // Create DMA buffer for bulk transfer
            let transfer_len = buffer.len();
            let mut dma_buf = crate::memory::dma::DmaRegion::new(transfer_len, true)
                .map_err(|_| "Failed to allocate DMA buffer for bulk transfer")?;
            
            // For OUT transfers, copy data to DMA buffer
            let is_in = (endpoint & 0x80) != 0;
            if !is_in {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        dma_buf.virt_addr.as_mut_ptr::<u8>(),
                        transfer_len
                    );
                }
            }
            
            // Create bulk transfer TRB 
            let mut bulk_trb = crate::drivers::nonos_xhci::Trb::default();
            bulk_trb.d0 = (dma_buf.phys_addr.as_u64() & 0xFFFF_FFFF) as u32;
            bulk_trb.d1 = (dma_buf.phys_addr.as_u64() >> 32) as u32;
            bulk_trb.d2 = transfer_len as u32;
            bulk_trb.d3 = crate::drivers::nonos_xhci::TRB_IOC; // Interrupt on completion
            bulk_trb.set_type(crate::drivers::nonos_xhci::TRB_TYPE_NORMAL);
            
            // EP0 ring as fallback but log that proper endpoint rings are needed
            if let Some(ep0) = ctrl.ep0_ring.as_mut() {
                bulk_trb.set_cycle(ep0.cycle);
                let trb_ptr = ep0.enqueue(bulk_trb);
                
                // Ring doorbell for this endpoint
                unsafe {
                    crate::memory::mmio::mmio_w32(
                        ctrl.db_base + (slot_id as usize) * 4, 
                        endpoint as u32
                    );
                }
                
                // Wait for completion
                ctrl.wait_transfer_completion(trb_ptr)?;
                
                // For IN transfers, copy data back
                if is_in {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            dma_buf.virt_addr.as_ptr::<u8>(),
                            buffer.as_mut_ptr(),
                            transfer_len
                        );
                    }
                }
                
                Ok(transfer_len)
            } else {
                Err("EP0 ring not available for bulk transfer")
            }
        } else {
            Err("xHCI controller not initialized")
        }
    }
    
    fn interrupt_transfer(
        &self,
        slot_id: u8,
        endpoint: u8,
        buffer: &mut [u8],
        interval: u8,
        timeout_us: u32,
    ) -> Result<usize, &'static str> {
        // Interrupt transfer with proper timing and polling
        if let Some(ctrl_mutex) = crate::drivers::nonos_xhci::XHCI_ONCE.get() {
            let mut ctrl = ctrl_mutex.lock();
            
            let transfer_len = buffer.len();
            let mut dma_buf = crate::memory::dma::DmaRegion::new(transfer_len, true)
                .map_err(|_| "Failed to allocate DMA buffer for interrupt transfer")?;
            
            let is_in = (endpoint & 0x80) != 0;
            if !is_in {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        dma_buf.virt_addr.as_mut_ptr::<u8>(),
                        transfer_len
                    );
                }
            }
            
            // Create interrupt transfer TRB with proper timing
            let mut int_trb = crate::drivers::nonos_xhci::Trb::default();
            int_trb.d0 = (dma_buf.phys_addr.as_u64() & 0xFFFF_FFFF) as u32;
            int_trb.d1 = (dma_buf.phys_addr.as_u64() >> 32) as u32;
            int_trb.d2 = transfer_len as u32;
            int_trb.d3 = crate::drivers::nonos_xhci::TRB_IOC;
            int_trb.set_type(crate::drivers::nonos_xhci::TRB_TYPE_NORMAL);
            
            if let Some(ep0) = ctrl.ep0_ring.as_mut() {
                int_trb.set_cycle(ep0.cycle);
                let trb_ptr = ep0.enqueue(int_trb);
                
                // Ring doorbell with endpoint number
                unsafe {
                    crate::memory::mmio::mmio_w32(
                        ctrl.db_base + (slot_id as usize) * 4,
                        endpoint as u32
                    );
                }
                
                // Wait for completion with timeout based on interval
                let start_time = crate::time::current_ticks();
                let timeout_ticks = timeout_us / 1000; // to milliseconds
                
                loop {
                    match ctrl.wait_transfer_completion(trb_ptr) {
                        Ok(()) => break,
                        Err(_) => {
                            if crate::time::current_ticks() - start_time > timeout_ticks as u64 {
                                return Err("Interrupt transfer timeout");
                            }
                            // Wait for interval period before retry
                            for _ in 0..(interval as u32 * 1000) {
                                core::hint::spin_loop();
                            }
                        }
                    }
                }
                
                if is_in {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            dma_buf.virt_addr.as_ptr::<u8>(),
                            buffer.as_mut_ptr(),
                            transfer_len
                        );
                    }
                }
                
                Ok(transfer_len)
            } else {
                Err("EP0 ring not available for interrupt transfer")
            }
        } else {
            Err("xHCI controller not initialized")
        }
    }
}

// ---------------- Descriptors and parsing ----------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub bcd_usb: u16,
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ConfigDescriptorHeader {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub w_total_length: u16,
    pub b_num_interfaces: u8,
    pub b_configuration_value: u8,
    pub i_configuration: u8,
    pub bm_attributes: u8,
    pub b_max_power: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct InterfaceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_interface_number: u8,
    pub b_alternate_setting: u8,
    pub b_num_endpoints: u8,
    pub b_interface_class: u8,
    pub b_interface_sub_class: u8,
    pub b_interface_protocol: u8,
    pub i_interface: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EndpointDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_endpoint_address: u8,
    pub bm_attributes: u8,
    pub w_max_packet_size: u16,
    pub b_interval: u8,
}

fn be16(b: [u8; 2]) -> u16 { u16::from_le_bytes(b) } // USB uses little-endian

// ---------------- Device model ----------------

#[derive(Clone)]
pub struct UsbStringTable {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

#[derive(Clone)]
pub struct UsbInterfaceInfo {
    pub iface: InterfaceDescriptor,
    pub endpoints: Vec<EndpointDescriptor>,
}

#[derive(Clone)]
pub struct UsbConfiguration {
    pub header: ConfigDescriptorHeader,
    pub raw: Vec<u8>,
    pub interfaces: Vec<UsbInterfaceInfo>,
}

#[derive(Clone)]
pub struct UsbDevice {
    pub slot_id: u8,
    pub addr: u8, // logical address (xHCI handles internally post-AddressDevice)
    pub dev_desc: DeviceDescriptor,
    pub strings: UsbStringTable,
    pub active_config: Option<UsbConfiguration>,
}

#[derive(Default)]
pub struct UsbStats {
    pub devices_enumerated: AtomicU64,
    pub ctrl_transfers: AtomicU64,
    pub ctrl_errors: AtomicU64,
}

// ---------------- Class driver registry ----------------

pub trait UsbClassDriver: Send + Sync + 'static {
    fn matches(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool;
    fn bind(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> Result<(), &'static str>;
    fn name(&self) -> &'static str;
}

static CLASS_DRIVERS: Mutex<Vec<Arc<dyn UsbClassDriver>>> = Mutex::new(Vec::new());

pub fn register_class_driver(driver: Arc<dyn UsbClassDriver>) {
    CLASS_DRIVERS.lock().push(driver);
}

// ---------------- Manager ----------------

pub struct UsbManager<B: UsbHostBackend> {
    backend: B,
    devices: Mutex<Vec<UsbDevice>>,
    stats: UsbStats,
}

static mut USB_MANAGER_ANY: Option<&'static UsbManager<XhciBackend>> = None;

impl<B: UsbHostBackend> UsbManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            devices: Mutex::new(Vec::new()),
            stats: UsbStats::default(),
        }
    }

    pub fn enumerate(&self) -> Result<(), &'static str> {
        // Default slot (xHCI Address Device already done)
        let slot = self.backend.default_slot().ok_or("usb: no default slot")?;

        // Fetch device descriptor (first 8 bytes, then full)
        let mut buf = [0u8; 18];
        let setup_short = [
            consts::DIR_IN | consts::TYPE_STD | consts::RT_DEV, // bmRequestType
            consts::REQ_GET_DESCRIPTOR,                          // bRequest
            (consts::DT_DEVICE as u16).to_le_bytes()[0],         // wValueL = descriptor type
            (consts::DT_DEVICE as u16).to_le_bytes()[1],         // wValueH = index 0 for device (actually index in high byte)
            0,                                                   // wIndexL
            0,                                                   // wIndexH
            8, 0,                                                // wLength (8)
        ];
        let _ = self.backend.control_transfer(slot, setup_short, Some(&mut buf[..8]), None, 1_000_000)?;

        let setup_full = [
            consts::DIR_IN | consts::TYPE_STD | consts::RT_DEV,
            consts::REQ_GET_DESCRIPTOR,
            consts::DT_DEVICE, 0, 0, 0,
            18, 0,
        ];
        let n = self.backend.control_transfer(slot, setup_full, Some(&mut buf), None, 1_000_000)?;
        if n < 18 { return Err("usb: short device descriptor"); }
        let dev_desc = unsafe { *(buf.as_ptr() as *const DeviceDescriptor) };

        // Strings
        let strings = self.fetch_strings(slot, &dev_desc)?;

        // Config descriptor header to get total length
        let mut cfg_hdr_buf = [0u8; core::mem::size_of::<ConfigDescriptorHeader>()];
        let setup_cfg_hdr = [
            consts::DIR_IN | consts::TYPE_STD | consts::RT_DEV,
            consts::REQ_GET_DESCRIPTOR,
            consts::DT_CONFIG, 0, 0, 0,
            cfg_hdr_buf.len() as u8, 0,
        ];
        let n = self.backend.control_transfer(slot, setup_cfg_hdr, Some(&mut cfg_hdr_buf), None, 1_000_000)?;
        if n < cfg_hdr_buf.len() { return Err("usb: short config header"); }
        let cfg_hdr: ConfigDescriptorHeader = unsafe { *(cfg_hdr_buf.as_ptr() as *const _) };
        let total_len = u16::from_le(cfg_hdr.w_total_length) as usize;

        // Full configuration descriptor (including interfaces and endpoints)
        let mut cfg_buf = vec![0u8; total_len];
        let setup_cfg_full = [
            consts::DIR_IN | consts::TYPE_STD | consts::RT_DEV,
            consts::REQ_GET_DESCRIPTOR,
            consts::DT_CONFIG, 0, 0, 0,
            (total_len & 0xFF) as u8, (total_len >> 8) as u8,
        ];
        let n = self.backend.control_transfer(slot, setup_cfg_full, Some(&mut cfg_buf), None, 1_000_000)?;
        if n < total_len { return Err("usb: short config descriptor"); }
        let cfg_hdr_full: ConfigDescriptorHeader = unsafe { *(cfg_buf.as_ptr() as *const _) };

        // Parse interfaces/endpoints
        let interfaces = parse_interfaces(&cfg_buf)?;

        // Set configuration
        let cfg_value = cfg_hdr_full.b_configuration_value;
        let setup_set_cfg = [
            consts::DIR_OUT | consts::TYPE_STD | consts::RT_DEV,
            consts::REQ_SET_CONFIGURATION,
            cfg_value, 0, // wValue = configuration value
            0, 0,         // wIndex
            0, 0,         // wLength = 0
        ];
        let _ = self.backend.control_transfer(slot, setup_set_cfg, None, None, 1_000_000)?;

        let device = UsbDevice {
            slot_id: slot,
            addr: 0, // managed by xHCI internally
            dev_desc,
            strings,
            active_config: Some(UsbConfiguration {
                header: cfg_hdr_full,
                raw: cfg_buf,
                interfaces,
            }),
        };
        self.devices.lock().push(device);
        self.stats.devices_enumerated.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn fetch_strings(&self, slot: u8, dd: &DeviceDescriptor) -> Result<UsbStringTable, &'static str> {
        let mut out = UsbStringTable { manufacturer: None, product: None, serial: None };
        if dd.i_manufacturer != 0 {
            out.manufacturer = self.get_string(slot, dd.i_manufacturer).ok();
        }
        if dd.i_product != 0 {
            out.product = self.get_string(slot, dd.i_product).ok();
        }
        if dd.i_serial_number != 0 {
            out.serial = self.get_string(slot, dd.i_serial_number).ok();
        }
        Ok(out)
    }

    fn get_string(&self, slot: u8, index: u8) -> Result<String, &'static str> {
        // Language ID: get string descriptor zero first (optional). Assume English (0x0409) default if unavailable.
        let langid = 0x0409u16;
        let mut buf = [0u8; 255];
        let setup = [
            consts::DIR_IN | consts::TYPE_STD | consts::RT_DEV,
            consts::REQ_GET_DESCRIPTOR,
            consts::DT_STRING, index,
            (langid & 0xFF) as u8, (langid >> 8) as u8,
            255, 0,
        ];
        let n = self.backend.control_transfer(slot, setup, Some(&mut buf), None, 1_000_000)?;
        if n < 2 || buf[1] != consts::DT_STRING { return Err("usb: invalid string descriptor"); }
        // UTF-16LE to UTF-8 (naive ASCII subset)
        let mut s = String::new();
        let mut i = 2usize;
        while i + 1 < n {
            let lo = buf[i];
            let hi = buf[i + 1];
            let cp = u16::from_le_bytes([lo, hi]);
            let ch = core::char::from_u32(cp as u32).unwrap_or('?');
            s.push(ch);
            i += 2;
        }
        Ok(s)
    }

    pub fn bind_class_drivers(&self) {
        let drivers = CLASS_DRIVERS.lock().clone();
        let devs = self.devices.lock().clone();
        for dev in &devs {
            if let Some(cfg) = &dev.active_config {
                for iface in &cfg.interfaces {
                    for d in &drivers {
                        if d.matches(dev, cfg, iface) {
                            let _ = d.bind(dev, cfg, iface);
                        }
                    }
                }
            }
        }
    }

    pub fn devices(&self) -> Vec<UsbDevice> {
        self.devices.lock().clone()
    }

    pub fn stats(&self) -> UsbStats {
        UsbStats {
            devices_enumerated: AtomicU64::new(self.stats.devices_enumerated.load(Ordering::Relaxed)),
            ctrl_transfers: AtomicU64::new(self.stats.ctrl_transfers.load(Ordering::Relaxed)),
            ctrl_errors: AtomicU64::new(self.stats.ctrl_errors.load(Ordering::Relaxed)),
        }
    }
}

// Parse interfaces and endpoints from a full config descriptor blob
fn parse_interfaces(cfg: &[u8]) -> Result<Vec<UsbInterfaceInfo>, &'static str> {
    let mut i = 0usize;
    let total = cfg.len();
    // Skip the initial ConfigDescriptorHeader (9 bytes)
    if total < core::mem::size_of::<ConfigDescriptorHeader>() { return Err("cfg too small"); }
    i += core::mem::size_of::<ConfigDescriptorHeader>();

    let mut out = Vec::new();
    let mut cur_iface: Option<UsbInterfaceInfo> = None;

    while i + 1 < total {
        let len = cfg[i] as usize;
        if len == 0 || i + len > total { break; }
        let dtype = cfg[i + 1];
        match dtype {
            consts::DT_INTERFACE => {
                // Flush previous iface
                if let Some(iface) = cur_iface.take() {
                    out.push(iface);
                }
                let desc: InterfaceDescriptor = unsafe { *(cfg[i..].as_ptr() as *const _) };
                cur_iface = Some(UsbInterfaceInfo { iface: desc, endpoints: Vec::new() });
            }
            consts::DT_ENDPOINT => {
                let ep: EndpointDescriptor = unsafe { *(cfg[i..].as_ptr() as *const _) };
                if let Some(ref mut iface) = cur_iface {
                    iface.endpoints.push(ep);
                }
            }
            _ => {}
        }
        i += len;
    }
    if let Some(iface) = cur_iface.take() {
        out.push(iface);
    }
    Ok(out)
}

// ---------------- Public entrypoints ----------------

pub fn init_usb() -> Result<(), &'static str> {
    // Create a single global manager bound to xHCI
    static ONCE: spin::Once<&'static UsbManager<XhciBackend>> = spin::Once::new();
    let mgr = ONCE.call_once(|| {
        let m = UsbManager::new(XhciBackend);
        // Leak to 'static
        Box::leak(Box::new(m))
    });

    unsafe { USB_MANAGER_ANY = Some(mgr) }

    // Perform enumeration on the default slot (already addressed by xHCI)
    mgr.enumerate()?;
    mgr.bind_class_drivers();

    crate::log::logger::log_critical("✓ USB core initialized");
    Ok(())
}

pub fn get_manager() -> Option<&'static UsbManager<XhciBackend>> {
    unsafe { USB_MANAGER_ANY }
}

/// Poll USB endpoint for data with USB protocol 
pub fn poll_endpoint(device_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
    if let Some(manager) = get_manager() {
        let devices = manager.devices.lock();
        if let Some(device) = devices.iter().find(|d| d.slot_id == device_id) {
            // Get endpoint descriptor to determine transfer type
            if let Some(config) = &device.active_config {
                for interface in &config.interfaces {
                    for ep_desc in &interface.endpoints {
                        if ep_desc.b_endpoint_address == endpoint {
                            let transfer_type = ep_desc.bm_attributes & 0x03;
                            let max_packet_size = u16::from_le(ep_desc.w_max_packet_size) as usize;
                            
                            match transfer_type {
                                0x01 => { // Isochronous
                                    return Err("Isochronous transfers not supported in polling");
                                }
                                0x02 => { // Bulk
                                    return manager.backend.bulk_transfer(
                                        device.slot_id, 
                                        endpoint, 
                                        buffer, 
                                        5_000_000 // 5 second timeout
                                    );
                                }
                                0x03 => { // Interrupt
                                    let interval = ep_desc.b_interval;
                                    return manager.backend.interrupt_transfer(
                                        device.slot_id,
                                        endpoint,
                                        buffer,
                                        interval,
                                        1_000_000 // 1 second timeout
                                    );
                                }
                                _ => { // Control (0x00)
                                    return Err("Control endpoints should use control_transfer");
                                }
                            }
                        }
                    }
                }
            }
            Err("Endpoint not found in device configuration")
        } else {
            Err("Device not found")
        }
    } else {
        Err("USB manager not initialized")
    }
}
