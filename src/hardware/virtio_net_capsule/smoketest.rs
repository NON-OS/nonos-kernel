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

//! Boot-time runtime proof for the virtio-net driver capsule.
//! Drives the five client ops in order: healthcheck, mac_address
//! (must be stable), link_status (deterministic byte), tx_packet
//! (bounded Ethernet frame accepted), rx_packet (empty queue
//! handled cleanly), oversized rejection. Emits the marker set
//! `tests/boot/virtio_net_round_trip.sh` greps for. Gated on
//! `nonos-driver-virtio-net-smoketest`.

use alloc::vec;

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::DriverNetError;
use super::state;

const TAG: &[u8] = b"[DRIVER-NET-TEST] ";

const MIN_ETHERNET_FRAME: usize = 60;
const MAX_ETHERNET_FRAME: usize = 1514;

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    if let Err(e) = client::healthcheck() {
        return fail(b"healthcheck", e);
    }
    mark(b"healthcheck ok");

    let mac1 = match client::mac_address() {
        Ok(m) => m,
        Err(e) => return fail(b"mac", e),
    };
    let mac2 = match client::mac_address() {
        Ok(m) => m,
        Err(e) => return fail(b"mac stable", e),
    };
    if mac1 != mac2 {
        return fail_msg(b"mac changed between reads");
    }
    mark(b"mac ok");

    match client::link_status() {
        Ok(_) => mark(b"link_status ok"),
        Err(e) => return fail(b"link_status", e),
    }

    let mut frame = vec![0u8; MIN_ETHERNET_FRAME];
    // Broadcast destination, our MAC as source, EtherType 0x88B5
    // (locally administered experimental). The capsule does not
    // care about the bytes, but a real-shape header keeps a
    // sniffer-side proof honest.
    for b in frame[0..6].iter_mut() {
        *b = 0xFF;
    }
    frame[6..12].copy_from_slice(&mac1);
    frame[12] = 0x88;
    frame[13] = 0xB5;
    if let Err(e) = client::tx_packet(&frame) {
        return fail(b"tx_packet", e);
    }
    mark(b"tx_packet ok");

    match client::rx_packet() {
        Ok(_) => mark(b"rx_packet (frame ready) ok"),
        Err(DriverNetError::RxQueueEmpty) => mark(b"rx_packet (empty) ok"),
        Err(e) => return fail(b"rx_packet", e),
    }

    let oversized = vec![0u8; MAX_ETHERNET_FRAME + 1];
    match client::tx_packet(&oversized) {
        Err(DriverNetError::OversizedRequest) => mark(b"oversized denied"),
        Ok(()) => return fail_msg(b"oversized: must be denied"),
        Err(e) => return fail(b"oversized", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: DriverNetError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn err_name(e: DriverNetError) -> &'static [u8] {
    match e {
        DriverNetError::Dead => b"Dead",
        DriverNetError::Stale => b"Stale",
        DriverNetError::AccessDenied => b"AccessDenied",
        DriverNetError::InvalidArgument => b"InvalidArgument",
        DriverNetError::OversizedRequest => b"OversizedRequest",
        DriverNetError::DeviceFailure => b"DeviceFailure",
        DriverNetError::RxQueueEmpty => b"RxQueueEmpty",
        DriverNetError::NoCallerPid => b"NoCallerPid",
        DriverNetError::TransportFailure => b"TransportFailure",
        DriverNetError::ProtocolMismatch => b"ProtocolMismatch",
    }
}
