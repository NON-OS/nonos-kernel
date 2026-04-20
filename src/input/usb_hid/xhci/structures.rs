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

#[repr(C, align(4096))]
pub(crate) struct DcbaaArray { pub entries: [u64; 17] }
pub(crate) static mut DCBAA: DcbaaArray = DcbaaArray { entries: [0; 17] };

#[repr(C, align(64))]
pub(crate) struct EventRingSegmentTable {
    pub ring_base: u64,
    pub ring_size: u16,
    pub _rsvd: [u16; 3],
}
pub(crate) static mut ERST: EventRingSegmentTable = EventRingSegmentTable {
    ring_base: 0, ring_size: 256, _rsvd: [0; 3],
};

// Scratchpad buffers for xHCI controllers that require them
#[repr(C, align(4096))]
pub(crate) struct ScratchpadPage { pub data: [u8; 4096] }
#[repr(C, align(4096))]
pub(crate) struct ScratchpadArray { pub entries: [u64; 16] }
pub(crate) static mut SCRATCHPAD_ARRAY: ScratchpadArray = ScratchpadArray { entries: [0; 16] };
pub(crate) static mut SCRATCHPAD_PAGES: [ScratchpadPage; 16] = [
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
    ScratchpadPage { data: [0; 4096] }, ScratchpadPage { data: [0; 4096] },
];

#[repr(C, align(4096))]
pub(crate) struct DeviceContext {
    pub slot: [u32; 8],
    pub ep: [[u32; 8]; 31],
}
pub(crate) static mut DEV_CTX: DeviceContext = DeviceContext { slot: [0; 8], ep: [[0; 8]; 31] };

#[repr(C, align(4096))]
pub(crate) struct InputContext {
    pub ctrl: [u32; 8],
    pub slot: [u32; 8],
    pub ep: [[u32; 8]; 31],
}
pub(crate) static mut INPUT_CTX: InputContext = InputContext {
    ctrl: [0; 8], slot: [0; 8], ep: [[0; 8]; 31],
};

#[repr(C, align(4096))]
pub(crate) struct UsbBuffer { pub data: [u8; 4096] }
pub(crate) static mut USB_BUF: UsbBuffer = UsbBuffer { data: [0; 4096] };
