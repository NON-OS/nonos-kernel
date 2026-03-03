// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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
