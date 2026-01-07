// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


use super::constants::*;
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotContext {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
    reserved: [u32; 4],
}

impl SlotContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route_string(&self) -> u32 {
        self.dw0 & 0xFFFFF
    }

    pub fn set_route_string(&mut self, route: u32) {
        self.dw0 = (self.dw0 & !0xFFFFF) | (route & 0xFFFFF);
    }

    pub fn speed(&self) -> u8 {
        ((self.dw0 >> 20) & 0xF) as u8
    }

    pub fn set_speed(&mut self, speed: u8) {
        self.dw0 = (self.dw0 & !(0xF << 20)) | (((speed & 0xF) as u32) << 20);
    }

    pub fn mtt(&self) -> bool {
        (self.dw0 & (1 << 25)) != 0
    }

    pub fn set_mtt(&mut self, mtt: bool) {
        if mtt {
            self.dw0 |= 1 << 25;
        } else {
            self.dw0 &= !(1 << 25);
        }
    }

    pub fn hub(&self) -> bool {
        (self.dw0 & (1 << 26)) != 0
    }

    pub fn set_hub(&mut self, hub: bool) {
        if hub {
            self.dw0 |= 1 << 26;
        } else {
            self.dw0 &= !(1 << 26);
        }
    }

    pub fn context_entries(&self) -> u8 {
        ((self.dw0 >> 27) & 0x1F) as u8
    }

    pub fn set_context_entries(&mut self, entries: u8) {
        self.dw0 = (self.dw0 & !(0x1F << 27)) | (((entries & 0x1F) as u32) << 27);
    }

    pub fn max_exit_latency(&self) -> u16 {
        (self.dw1 & 0xFFFF) as u16
    }

    pub fn set_max_exit_latency(&mut self, latency: u16) {
        self.dw1 = (self.dw1 & !0xFFFF) | (latency as u32);
    }

    pub fn root_hub_port(&self) -> u8 {
        ((self.dw1 >> 16) & 0xFF) as u8
    }

    pub fn set_root_hub_port(&mut self, port: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 16)) | ((port as u32) << 16);
    }

    pub fn num_ports(&self) -> u8 {
        ((self.dw1 >> 24) & 0xFF) as u8
    }

    pub fn set_num_ports(&mut self, ports: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 24)) | ((ports as u32) << 24);
    }

    pub fn tt_hub_slot_id(&self) -> u8 {
        (self.dw2 & 0xFF) as u8
    }

    pub fn set_tt_hub_slot_id(&mut self, slot: u8) {
        self.dw2 = (self.dw2 & !0xFF) | (slot as u32);
    }

    pub fn tt_port_number(&self) -> u8 {
        ((self.dw2 >> 8) & 0xFF) as u8
    }

    pub fn set_tt_port_number(&mut self, port: u8) {
        self.dw2 = (self.dw2 & !(0xFF << 8)) | ((port as u32) << 8);
    }

    pub fn ttt(&self) -> u8 {
        ((self.dw2 >> 16) & 0x3) as u8
    }

    pub fn set_ttt(&mut self, ttt: u8) {
        self.dw2 = (self.dw2 & !(0x3 << 16)) | (((ttt & 0x3) as u32) << 16);
    }

    pub fn interrupter_target(&self) -> u16 {
        ((self.dw2 >> 22) & 0x3FF) as u16
    }

    pub fn set_interrupter_target(&mut self, target: u16) {
        self.dw2 = (self.dw2 & !(0x3FF << 22)) | (((target & 0x3FF) as u32) << 22);
    }

    pub fn usb_device_address(&self) -> u8 {
        (self.dw3 & 0xFF) as u8
    }

    pub fn set_usb_device_address(&mut self, addr: u8) {
        self.dw3 = (self.dw3 & !0xFF) | (addr as u32);
    }

    pub fn slot_state(&self) -> SlotState {
        SlotState::from_raw(((self.dw3 >> 27) & 0x1F) as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Disabled,
    Default,
    Addressed,
    Configured,
    Reserved(u8),
}

impl SlotState {
    fn from_raw(val: u8) -> Self {
        match val {
            0 => SlotState::Disabled,
            1 => SlotState::Default,
            2 => SlotState::Addressed,
            3 => SlotState::Configured,
            v => SlotState::Reserved(v),
        }
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpContext {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
    dw4: u32,
    reserved: [u32; 3],
}

impl EpContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ep_state(&self) -> EpState {
        EpState::from_raw((self.dw0 & 0x7) as u8)
    }

    pub fn set_ep_state(&mut self, state: EpState) {
        self.dw0 = (self.dw0 & !0x7) | (state.to_raw() as u32);
    }

    pub fn mult(&self) -> u8 {
        ((self.dw0 >> 8) & 0x3) as u8
    }

    pub fn set_mult(&mut self, mult: u8) {
        self.dw0 = (self.dw0 & !(0x3 << 8)) | (((mult & 0x3) as u32) << 8);
    }

    pub fn max_primary_streams(&self) -> u8 {
        ((self.dw0 >> 10) & 0x1F) as u8
    }

    pub fn set_max_primary_streams(&mut self, streams: u8) {
        self.dw0 = (self.dw0 & !(0x1F << 10)) | (((streams & 0x1F) as u32) << 10);
    }

    pub fn lsa(&self) -> bool {
        (self.dw0 & (1 << 15)) != 0
    }

    pub fn set_lsa(&mut self, lsa: bool) {
        if lsa {
            self.dw0 |= 1 << 15;
        } else {
            self.dw0 &= !(1 << 15);
        }
    }

    pub fn interval(&self) -> u8 {
        ((self.dw0 >> 16) & 0xFF) as u8
    }

    pub fn set_interval(&mut self, interval: u8) {
        self.dw0 = (self.dw0 & !(0xFF << 16)) | ((interval as u32) << 16);
    }

    pub fn cerr(&self) -> u8 {
        ((self.dw1 >> 1) & 0x3) as u8
    }

    pub fn set_cerr(&mut self, cerr: u8) {
        self.dw1 = (self.dw1 & !(0x3 << 1)) | (((cerr & 0x3) as u32) << 1);
    }

    pub fn ep_type(&self) -> u8 {
        ((self.dw1 >> 3) & 0x7) as u8
    }

    pub fn set_ep_type(&mut self, ep_type: u8) {
        self.dw1 = (self.dw1 & !(0x7 << 3)) | (((ep_type & 0x7) as u32) << 3);
    }

    pub fn hid(&self) -> bool {
        (self.dw1 & (1 << 7)) != 0
    }

    pub fn set_hid(&mut self, hid: bool) {
        if hid {
            self.dw1 |= 1 << 7;
        } else {
            self.dw1 &= !(1 << 7);
        }
    }

    pub fn max_burst_size(&self) -> u8 {
        ((self.dw1 >> 8) & 0xFF) as u8
    }

    pub fn set_max_burst_size(&mut self, burst: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 8)) | ((burst as u32) << 8);
    }

    pub fn max_packet_size(&self) -> u16 {
        ((self.dw1 >> 16) & 0xFFFF) as u16
    }

    pub fn set_max_packet_size(&mut self, mps: u16) {
        self.dw1 = (self.dw1 & !0xFFFF0000) | ((mps as u32) << 16);
    }

    pub fn tr_dequeue_pointer(&self) -> u64 {
        ((self.dw2 as u64) & !0xF) | ((self.dw3 as u64) << 32)
    }

    pub fn set_tr_dequeue_pointer(&mut self, ptr: u64, dcs: bool) {
        let low = ((ptr & 0xFFFF_FFF0) as u32) | (if dcs { 1 } else { 0 });
        self.dw2 = low;
        self.dw3 = (ptr >> 32) as u32;
    }

    pub fn dcs(&self) -> bool {
        (self.dw2 & 1) != 0
    }

    pub fn average_trb_length(&self) -> u16 {
        (self.dw4 & 0xFFFF) as u16
    }

    pub fn set_average_trb_length(&mut self, len: u16) {
        self.dw4 = (self.dw4 & !0xFFFF) | (len as u32);
    }

    pub fn max_esit_payload(&self) -> u32 {
        let lo = ((self.dw4 >> 16) & 0xFFFF) as u32;
        let hi = ((self.dw0 >> 24) & 0xFF) as u32;
        lo | (hi << 16)
    }

    pub fn set_max_esit_payload(&mut self, payload: u32) {
        let lo = (payload & 0xFFFF) as u32;
        let hi = ((payload >> 16) & 0xFF) as u32;
        self.dw4 = (self.dw4 & 0xFFFF) | (lo << 16);
        self.dw0 = (self.dw0 & !(0xFF << 24)) | (hi << 24);
    }

    pub fn configure_control(&mut self, max_packet_size: u16) {
        self.set_ep_type(EP_TYPE_CONTROL);
        self.set_max_packet_size(max_packet_size);
        self.set_cerr(3);
        self.set_max_burst_size(0);
        self.set_average_trb_length(8);
    }

    pub fn configure_bulk(&mut self, is_in: bool, max_packet_size: u16, max_burst: u8) {
        let ep_type = if is_in {
            EP_TYPE_BULK_IN
        } else {
            EP_TYPE_BULK_OUT
        };
        self.set_ep_type(ep_type);
        self.set_max_packet_size(max_packet_size);
        self.set_max_burst_size(max_burst);
        self.set_cerr(3);
        self.set_average_trb_length(max_packet_size);
    }

    pub fn configure_interrupt(&mut self, is_in: bool, max_packet_size: u16, interval: u8) {
        let ep_type = if is_in {
            EP_TYPE_INTERRUPT_IN
        } else {
            EP_TYPE_INTERRUPT_OUT
        };
        self.set_ep_type(ep_type);
        self.set_max_packet_size(max_packet_size);
        self.set_interval(interval);
        self.set_cerr(3);
        self.set_average_trb_length(max_packet_size);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpState {
    Disabled,
    Running,
    Halted,
    Stopped,
    Error,
    Reserved(u8),
}

impl EpState {
    fn from_raw(val: u8) -> Self {
        match val {
            0 => EpState::Disabled,
            1 => EpState::Running,
            2 => EpState::Halted,
            3 => EpState::Stopped,
            4 => EpState::Error,
            v => EpState::Reserved(v),
        }
    }

    fn to_raw(self) -> u8 {
        match self {
            EpState::Disabled => 0,
            EpState::Running => 1,
            EpState::Halted => 2,
            EpState::Stopped => 3,
            EpState::Error => 4,
            EpState::Reserved(v) => v,
        }
    }
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct DeviceContext {
    pub slot: SlotContext,
    _slot_pad: [u8; 32],
    pub ep0: EpContext,
    _ep0_pad: [u8; 32],
    pub endpoints: [EpContextWithPad; 30],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpContextWithPad {
    pub context: EpContext,
    _pad: [u8; 32],
}

impl Default for EpContextWithPad {
    fn default() -> Self {
        Self {
            context: EpContext::default(),
            _pad: [0; 32],
        }
    }
}

impl Default for DeviceContext {
    fn default() -> Self {
        Self {
            slot: SlotContext::default(),
            _slot_pad: [0; 32],
            ep0: EpContext::default(),
            _ep0_pad: [0; 32],
            endpoints: [EpContextWithPad::default(); 30],
        }
    }
}

impl DeviceContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_endpoint(&self, dci: u8) -> Option<&EpContext> {
        match dci {
            0 => None,
            1 => Some(&self.ep0),
            2..=31 => Some(&self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn get_endpoint_mut(&mut self, dci: u8) -> Option<&mut EpContext> {
        match dci {
            0 => None,
            1 => Some(&mut self.ep0),
            2..=31 => Some(&mut self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn ep_addr_to_dci(ep_addr: u8) -> u8 {
        let ep_num = ep_addr & 0x0F;
        let is_in = (ep_addr & 0x80) != 0;
        if ep_num == 0 {
            1
        } else {
            ep_num * 2 + if is_in { 1 } else { 0 }
        }
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputControlContext {
    pub drop_flags: u32,
    pub add_flags: u32,
    reserved: [u32; 5],
    dw7: u32,
}

impl InputControlContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_context(&mut self, index: u8) {
        if index < 32 {
            self.add_flags |= 1 << index;
        }
    }

    pub fn drop_context(&mut self, index: u8) {
        if index < 32 {
            self.drop_flags |= 1 << index;
        }
    }

    pub fn is_adding(&self, index: u8) -> bool {
        if index < 32 {
            (self.add_flags & (1 << index)) != 0
        } else {
            false
        }
    }

    pub fn is_dropping(&self, index: u8) -> bool {
        if index < 32 {
            (self.drop_flags & (1 << index)) != 0
        } else {
            false
        }
    }

    pub fn configuration_value(&self) -> u8 {
        (self.dw7 & 0xFF) as u8
    }

    pub fn set_configuration_value(&mut self, value: u8) {
        self.dw7 = (self.dw7 & !0xFF) | (value as u32);
    }

    pub fn interface_number(&self) -> u8 {
        ((self.dw7 >> 8) & 0xFF) as u8
    }

    pub fn set_interface_number(&mut self, num: u8) {
        self.dw7 = (self.dw7 & !(0xFF << 8)) | ((num as u32) << 8);
    }

    pub fn alternate_setting(&self) -> u8 {
        ((self.dw7 >> 16) & 0xFF) as u8
    }

    pub fn set_alternate_setting(&mut self, setting: u8) {
        self.dw7 = (self.dw7 & !(0xFF << 16)) | ((setting as u32) << 16);
    }
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct InputContext {
    pub icc: InputControlContext,
    _icc_pad: [u8; 32],
    pub slot: SlotContext,
    _slot_pad: [u8; 32],
    pub ep0: EpContext,
    _ep0_pad: [u8; 32],
    pub endpoints: [EpContextWithPad; 30],
}

impl Default for InputContext {
    fn default() -> Self {
        Self {
            icc: InputControlContext::default(),
            _icc_pad: [0; 32],
            slot: SlotContext::default(),
            _slot_pad: [0; 32],
            ep0: EpContext::default(),
            _ep0_pad: [0; 32],
            endpoints: [EpContextWithPad::default(); 30],
        }
    }
}

impl InputContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_endpoint_mut(&mut self, dci: u8) -> Option<&mut EpContext> {
        match dci {
            0 => None,
            1 => Some(&mut self.ep0),
            2..=31 => Some(&mut self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn configure_for_address_device(&mut self, port: u8, speed: u8, max_packet_size: u16) {
        self.icc.add_flags = 0b11;
        self.icc.drop_flags = 0;

        self.slot.set_route_string(0);
        self.slot.set_speed(speed);
        self.slot.set_root_hub_port(port);
        self.slot.set_context_entries(1);

        self.ep0.set_ep_type(EP_TYPE_CONTROL);
        self.ep0.set_max_packet_size(max_packet_size);
        self.ep0.set_cerr(3);
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ErstEntry {
    pub ring_base_lo: u32,
    pub ring_base_hi: u32,
    pub ring_size: u32,
    pub reserved: u32,
}

impl ErstEntry {
    pub fn new(base_addr: u64, size: u32) -> Self {
        Self {
            ring_base_lo: (base_addr & 0xFFFF_FFFF) as u32,
            ring_base_hi: (base_addr >> 32) as u32,
            ring_size: size,
            reserved: 0,
        }
    }

    pub fn ring_base(&self) -> u64 {
        (self.ring_base_lo as u64) | ((self.ring_base_hi as u64) << 32)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct XhciConfig {
    pub command_timeout_spins: u32,
    pub transfer_timeout_spins: u32,
    pub enable_enumeration_rate_limit: bool,
    pub max_enumeration_attempts: u32,
    pub security_logging: bool,
}

impl Default for XhciConfig {
    fn default() -> Self {
        Self {
            command_timeout_spins: DEFAULT_TIMEOUT_SPINS,
            transfer_timeout_spins: DEFAULT_TIMEOUT_SPINS,
            enable_enumeration_rate_limit: true,
            max_enumeration_attempts: MAX_ENUMERATION_ATTEMPTS,
            security_logging: true,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_number_index: u8,
    pub num_configurations: u8,
}

impl UsbDeviceDescriptor {
    pub fn validate(&self) -> bool {
        self.length == 18 && self.descriptor_type == DESC_TYPE_DEVICE
    }

    pub fn usb_version(&self) -> (u8, u8) {
        let major = ((self.bcd_usb >> 8) & 0xFF) as u8;
        let minor = (self.bcd_usb & 0xFF) as u8;
        (major, minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_slot_context_size() {
        assert_eq!(mem::size_of::<SlotContext>(), 32);
    }

    #[test]
    fn test_ep_context_size() {
        assert_eq!(mem::size_of::<EpContext>(), 32);
    }

    #[test]
    fn test_device_context_alignment() {
        assert_eq!(mem::align_of::<DeviceContext>(), 64);
    }

    #[test]
    fn test_slot_context_fields() {
        let mut slot = SlotContext::new();
        slot.set_speed(4);
        assert_eq!(slot.speed(), 4);

        slot.set_root_hub_port(3);
        assert_eq!(slot.root_hub_port(), 3);
    }

    #[test]
    fn test_ep_context_dequeue_pointer() {
        let mut ep = EpContext::new();
        ep.set_tr_dequeue_pointer(0x1000_0010, true);
        assert_eq!(ep.tr_dequeue_pointer(), 0x1000_0010);
        assert!(ep.dcs());
    }

    #[test]
    fn test_ep_addr_to_dci() {
        assert_eq!(DeviceContext::ep_addr_to_dci(0x00), 1);
        assert_eq!(DeviceContext::ep_addr_to_dci(0x80), 1);
        assert_eq!(DeviceContext::ep_addr_to_dci(0x01), 2);
        assert_eq!(DeviceContext::ep_addr_to_dci(0x81), 3);
        assert_eq!(DeviceContext::ep_addr_to_dci(0x02), 4);
        assert_eq!(DeviceContext::ep_addr_to_dci(0x82), 5);
    }
}
