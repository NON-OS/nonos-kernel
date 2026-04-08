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

pub const CAP_NET_TCP_OUT: u64 = 1 << 0;
pub const CAP_NET_TCP_LISTEN: u64 = 1 << 1;
pub const CAP_NET_UDP: u64 = 1 << 2;
pub const CAP_NET_DNS: u64 = 1 << 3;
pub const CAP_STORAGE_EPHEMERAL: u64 = 1 << 8;
pub const CAP_STORAGE_IPFS_READ: u64 = 1 << 9;
pub const CAP_STORAGE_IPFS_WRITE: u64 = 1 << 10;
pub const CAP_IPC_CLIPBOARD_READ: u64 = 1 << 16;
pub const CAP_IPC_CLIPBOARD_WRITE: u64 = 1 << 17;
pub const CAP_IPC: u64 = 1 << 18;
pub const CAP_GPU_RENDER: u64 = 1 << 24;
pub const CAP_GPU_COMPUTE: u64 = 1 << 25;
pub const CAP_WALLET_SIGN: u64 = 1 << 32;
pub const CAP_WALLET_READ: u64 = 1 << 33;
pub const CAP_ALL: u64 = u64::MAX;

pub fn cap_from_str(s: &str) -> u64 {
    match s {
        "net.tcp.outbound" => CAP_NET_TCP_OUT,
        "net.tcp.listen" => CAP_NET_TCP_LISTEN,
        "net.udp" => CAP_NET_UDP,
        "net.dns.resolve" => CAP_NET_DNS,
        "storage.ephemeral" => CAP_STORAGE_EPHEMERAL,
        "storage.ipfs.read" => CAP_STORAGE_IPFS_READ,
        "storage.ipfs.write" => CAP_STORAGE_IPFS_WRITE,
        "ipc.clipboard.read" => CAP_IPC_CLIPBOARD_READ,
        "ipc.clipboard.write" => CAP_IPC_CLIPBOARD_WRITE,
        "ipc.capsule" => CAP_IPC,
        "gpu.render" => CAP_GPU_RENDER,
        "gpu.compute" => CAP_GPU_COMPUTE,
        "wallet.sign" => CAP_WALLET_SIGN,
        "wallet.read" => CAP_WALLET_READ,
        _ => 0,
    }
}
