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

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct E1000RxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

impl E1000RxDesc {
    pub const STATUS_DD: u8 = 0x01;
    pub const STATUS_EOP: u8 = 0x02;
    pub const STATUS_IXSM: u8 = 0x04;
    pub const STATUS_VP: u8 = 0x08;
    pub const STATUS_TCPCS: u8 = 0x20;
    pub const STATUS_IPCS: u8 = 0x40;

    #[inline]
    pub fn is_done(&self) -> bool {
        self.status & Self::STATUS_DD != 0
    }

    #[inline]
    pub fn is_eop(&self) -> bool {
        self.status & Self::STATUS_EOP != 0
    }

    #[inline]
    pub fn has_error(&self) -> bool {
        self.errors != 0
    }

    #[inline]
    pub fn is_vlan(&self) -> bool {
        self.status & Self::STATUS_VP != 0
    }

    #[inline]
    pub fn vlan_tag(&self) -> Option<u16> {
        if self.is_vlan() {
            Some(self.special)
        } else {
            None
        }
    }

    #[inline]
    pub fn packet_len(&self) -> usize {
        self.length as usize
    }

    #[inline]
    pub fn reset(&mut self) {
        self.status = 0;
        self.length = 0;
        self.errors = 0;
        self.checksum = 0;
        self.special = 0;
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct E1000TxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

impl E1000TxDesc {
    pub const STATUS_DD: u8 = 0x01;
    pub const STATUS_EC: u8 = 0x02;
    pub const STATUS_LC: u8 = 0x04;

    #[inline]
    pub fn is_done(&self) -> bool {
        self.status & Self::STATUS_DD != 0
    }

    #[inline]
    pub fn had_excess_collisions(&self) -> bool {
        self.status & Self::STATUS_EC != 0
    }

    #[inline]
    pub fn had_late_collision(&self) -> bool {
        self.status & Self::STATUS_LC != 0
    }

    #[inline]
    pub fn has_error(&self) -> bool {
        self.status & (Self::STATUS_EC | Self::STATUS_LC) != 0
    }

    pub fn setup(&mut self, buffer_phys: u64, len: u16, cmd: u8) {
        self.buffer_addr = buffer_phys;
        self.length = len;
        self.cso = 0;
        self.cmd = cmd;
        self.status = 0;
        self.css = 0;
        self.special = 0;
    }

    pub fn reset(&mut self) {
        self.length = 0;
        self.cmd = 0;
        self.status = Self::STATUS_DD;
        self.cso = 0;
        self.css = 0;
        self.special = 0;
    }
}

const _: () = {
    assert!(core::mem::size_of::<E1000RxDesc>() == 16);
    assert!(core::mem::size_of::<E1000TxDesc>() == 16);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx_desc_size() {
        assert_eq!(core::mem::size_of::<E1000RxDesc>(), 16);
    }

    #[test]
    fn test_tx_desc_size() {
        assert_eq!(core::mem::size_of::<E1000TxDesc>(), 16);
    }

    #[test]
    fn test_rx_desc_status() {
        let mut desc = E1000RxDesc::default();
        assert!(!desc.is_done());
        assert!(!desc.is_eop());

        desc.status = E1000RxDesc::STATUS_DD | E1000RxDesc::STATUS_EOP;
        assert!(desc.is_done());
        assert!(desc.is_eop());
    }

    #[test]
    fn test_tx_desc_status() {
        let mut desc = E1000TxDesc::default();
        assert!(!desc.is_done());

        desc.status = E1000TxDesc::STATUS_DD;
        assert!(desc.is_done());
    }
}
