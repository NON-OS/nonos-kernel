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

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn test_device_id_detection() {
        assert!(RTL8139_DEVICE_IDS.contains(&0x8139));
        assert!(RTL8139_DEVICE_IDS.contains(&0x8138));
        assert!(!RTL8139_DEVICE_IDS.contains(&0x0000));
    }

    #[test]
    fn test_register_offsets() {
        assert_eq!(reg::CR, 0x37);
        assert_eq!(reg::ISR, 0x3E);
        assert_eq!(reg::RCR, 0x44);
        assert_eq!(reg::TCR, 0x40);
    }

    #[test]
    fn test_command_register_bits() {
        assert_eq!(cmd::RST, 1 << 4);
        assert_eq!(cmd::TE, 1 << 2);
        assert_eq!(cmd::RE, 1 << 3);
    }

    #[test]
    fn test_interrupt_bits() {
        assert_eq!(int::ROK, 1 << 0);
        assert_eq!(int::TOK, 1 << 2);
        assert_eq!(int::RER, 1 << 1);
        assert_eq!(int::TER, 1 << 3);
    }

    #[test]
    fn test_constants() {
        assert_eq!(TX_DESC_COUNT, 4);
        assert_eq!(TX_BUFFER_SIZE, 1536);
        assert!(RX_BUFFER_SIZE > 8192);
        assert_eq!(MIN_FRAME_SIZE, 14);
        assert_eq!(MAX_MTU, 1500);
    }

    #[test]
    fn test_rtl8139_stats_default() {
        let stats = Rtl8139Stats::default();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.total_packets(), 0);
        assert!(!stats.link_up);
    }

    #[test]
    fn test_vendor_id() {
        assert_eq!(REALTEK_VENDOR_ID, 0x10EC);
    }
}
