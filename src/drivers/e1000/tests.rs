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
        assert!(E1000_DEVICE_IDS.contains(&0x100E));
        assert!(E1000_DEVICE_IDS.contains(&0x10D3));
        assert!(E1000_DEVICE_IDS.contains(&0x1533));
        assert!(!E1000_DEVICE_IDS.contains(&0x0000));
    }

    #[test]
    fn test_rx_desc_size() {
        assert_eq!(core::mem::size_of::<E1000RxDesc>(), 16);
    }

    #[test]
    fn test_tx_desc_size() {
        assert_eq!(core::mem::size_of::<E1000TxDesc>(), 16);
    }

    #[test]
    fn test_rx_desc_status_flags() {
        let mut desc = E1000RxDesc::default();
        assert!(!desc.is_done());
        assert!(!desc.is_eop());
        assert!(!desc.has_error());

        desc.status = 0x01;
        assert!(desc.is_done());

        desc.status = 0x03;
        assert!(desc.is_done());
        assert!(desc.is_eop());

        desc.errors = 0x01;
        assert!(desc.has_error());
    }

    #[test]
    fn test_tx_desc_status_flags() {
        let mut desc = E1000TxDesc::default();
        assert!(!desc.is_done());

        desc.status = 0x01;
        assert!(desc.is_done());

        desc.status = 0x02;
        assert!(desc.had_excess_collisions());
        assert!(desc.has_error());

        desc.status = 0x04;
        assert!(desc.had_late_collision());
        assert!(desc.has_error());
    }

    #[test]
    fn test_register_offsets() {
        assert_eq!(reg::CTRL, 0x0000);
        assert_eq!(reg::STATUS, 0x0008);
        assert_eq!(reg::RDBAL, 0x2800);
        assert_eq!(reg::TDBAL, 0x3800);
        assert_eq!(reg::RAL0, 0x5400);
    }

    #[test]
    fn test_ctrl_bits() {
        assert_eq!(ctrl::RST, 1 << 26);
        assert_eq!(ctrl::SLU, 1 << 6);
        assert_eq!(ctrl::ASDE, 1 << 5);
    }

    #[test]
    fn test_status_bits() {
        assert_eq!(status::LU, 1 << 1);
        assert_eq!(status::SPEED_10, 0 << 6);
        assert_eq!(status::SPEED_100, 1 << 6);
        assert_eq!(status::SPEED_1000, 2 << 6);
    }

    #[test]
    fn test_constants() {
        assert_eq!(RX_DESC_COUNT, 32);
        assert_eq!(TX_DESC_COUNT, 32);
        assert_eq!(BUFFER_SIZE, 2048);
        assert_eq!(MIN_FRAME_SIZE, 14);
        assert_eq!(MAX_MTU, 1500);
    }

    #[test]
    fn test_e1000_stats_default() {
        let stats = E1000Stats::default();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.total_packets(), 0);
        assert!(!stats.link_up);
    }
}
