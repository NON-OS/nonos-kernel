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

use alloc::vec::Vec;
use super::super::constants::*;
use super::super::error::WifiError;
use super::super::wpa::parse_eapol_frame;
use super::intel::IntelWifiDevice;
use super::types::WifiState;

impl IntelWifiDevice {
    pub(crate) fn process_rx(&mut self) -> Result<(), WifiError> {
        let (mut read_ptr, hw_ptr) = {
            let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
            (rx_queue.write_ptr(), rx_queue.hw_read_ptr())
        };

        while read_ptr != hw_ptr {
            let packet_data = {
                let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
                rx_queue.get_buffer(read_ptr as usize).to_vec()
            };

            self.handle_rx_packet(&packet_data)?;

            {
                let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
                rx_queue.replenish(read_ptr as usize)?;
            }

            read_ptr = (read_ptr + 1) % RX_QUEUE_SIZE as u32;
        }

        {
            let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
            rx_queue.set_write_ptr(read_ptr);
        }

        self.trans.grab_nic_access()?;
        self.trans.regs.write32(fh::RSCSR_CHNL0_WPTR, read_ptr);
        self.trans.release_nic_access();

        Ok(())
    }

    pub(crate) fn handle_rx_packet(&mut self, buf: &[u8]) -> Result<(), WifiError> {
        if buf.len() < 4 {
            return Ok(());
        }

        let cmd_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

        match cmd_id {
            cmd::SCAN_COMPLETE_UMAC => {
                self.state = WifiState::Ready;
            }
            cmd::SCAN_ITERATION_COMPLETE_UMAC => {
                if buf.len() >= 64 {
                    let result = self.parse_scan_result(&buf[8..])?;
                    self.scan_results.push(result);
                }
            }
            cmd::BEACON_NOTIFICATION => {
                if self.state == WifiState::Connected && buf.len() >= 16 {
                    self.rssi = buf[12] as i8;
                }
            }
            cmd::REPLY_RX_MPDU_CMD => {
                if buf.len() >= 32 {
                    self.handle_rx_mpdu(&buf[8..])?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn handle_rx_mpdu(&mut self, mpdu: &[u8]) -> Result<(), WifiError> {
        if mpdu.len() < 24 {
            return Ok(());
        }

        let llc_offset = self.get_mac_header_len(mpdu);
        if mpdu.len() < llc_offset + 8 {
            return Ok(());
        }

        let llc = &mpdu[llc_offset..];
        if llc.len() >= 8 && llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 {
            let ether_type = u16::from_be_bytes([llc[6], llc[7]]);
            if ether_type == 0x888E {
                return self.handle_eapol_frame(&llc[8..]);
            }
        }

        Ok(())
    }

    pub(crate) fn get_mac_header_len(&self, mpdu: &[u8]) -> usize {
        if mpdu.len() < 2 {
            return 24;
        }

        let frame_control = u16::from_le_bytes([mpdu[0], mpdu[1]]);
        let mut len = 24;

        if (frame_control & 0x00F0) == 0x0080 {
            len += 2;
        }

        if (frame_control & 0x8000) != 0 {
            len += 4;
        }

        len
    }

    pub(crate) fn handle_eapol_frame(&mut self, eapol_data: &[u8]) -> Result<(), WifiError> {
        let frame = parse_eapol_frame(eapol_data)?;

        let wpa = match self.wpa_context.as_mut() {
            Some(ctx) => ctx,
            None => {
                crate::log_warn!("iwlwifi: Received EAPOL frame but no WPA context");
                return Ok(());
            }
        };

        if frame.is_msg1() {
            crate::log::info!("iwlwifi: Received EAPOL Message 1 (ANonce)");

            let msg2 = wpa.process_msg1(&frame.nonce, frame.replay_counter)?;

            self.send_eapol_frame(&msg2)?;

            crate::log::info!("iwlwifi: Sent EAPOL Message 2 (SNonce + MIC)");
        } else if frame.is_msg3() {
            crate::log::info!("iwlwifi: Received EAPOL Message 3 (GTK)");

            let msg4 = wpa.process_msg3(eapol_data, &frame.key_data, &frame.mic, frame.replay_counter)?;

            self.send_eapol_frame(&msg4)?;

            crate::log::info!("iwlwifi: Sent EAPOL Message 4 (acknowledgment)");
        }

        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<Vec<u8>>, WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        let (mut read_ptr, hw_ptr) = {
            let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
            (rx_queue.write_ptr(), rx_queue.hw_read_ptr())
        };

        if read_ptr == hw_ptr {
            return Ok(None);
        }

        let frame = {
            let rx_queue = self.rx_queue.as_ref().ok_or(WifiError::InvalidState)?;
            rx_queue.get_buffer(read_ptr as usize).to_vec()
        };

        {
            let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
            rx_queue.replenish(read_ptr as usize)?;
        }

        read_ptr = (read_ptr + 1) % RX_QUEUE_SIZE as u32;
        {
            let rx_queue = self.rx_queue.as_mut().ok_or(WifiError::InvalidState)?;
            rx_queue.set_write_ptr(read_ptr);
        }

        self.trans.grab_nic_access()?;
        self.trans.regs.write32(fh::RSCSR_CHNL0_WPTR, read_ptr);
        self.trans.release_nic_access();

        if frame.len() < 24 {
            return Ok(None);
        }

        let frame_type = (frame[0] >> 2) & 0x03;
        if frame_type != 2 {
            self.handle_rx_packet(&frame)?;
            return Ok(None);
        }

        let protected = (frame[1] & 0x40) != 0;

        if protected {
            if let Some(ref mut ccmp) = self.ccmp_context {
                let header = &frame[..24];
                let ccmp_data = &frame[24..];

                match ccmp.decrypt(header, ccmp_data) {
                    Ok(plaintext) => return Ok(Some(plaintext)),
                    Err(_) => return Err(WifiError::DecryptionFailed),
                }
            } else {
                return Err(WifiError::DecryptionFailed);
            }
        } else {
            return Ok(Some(frame[24..].to_vec()));
        }
    }
}
