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

use crate::capabilities::*;

#[test]
fn test_capability_bit_values() {
    assert_eq!(Capability::CoreExec.bit(), 1);
    assert_eq!(Capability::IO.bit(), 2);
    assert_eq!(Capability::Network.bit(), 4);
    assert_eq!(Capability::IPC.bit(), 8);
    assert_eq!(Capability::Memory.bit(), 16);
    assert_eq!(Capability::Crypto.bit(), 32);
    assert_eq!(Capability::FileSystem.bit(), 64);
    assert_eq!(Capability::Hardware.bit(), 128);
    assert_eq!(Capability::Debug.bit(), 256);
    assert_eq!(Capability::Admin.bit(), 512);
    assert_eq!(Capability::RegisterService.bit(), 1024);
}

#[test]
fn test_capability_bits_are_powers_of_two() {
    for cap in Capability::all() {
        let bit = cap.bit();
        assert!(bit.is_power_of_two());
    }
}

#[test]
fn test_capability_bits_are_unique() {
    let all = Capability::all();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i].bit(), all[j].bit());
        }
    }
}

#[test]
fn test_capability_all_returns_11_items() {
    assert_eq!(Capability::all().len(), 11);
}

#[test]
fn test_capability_count_matches_all_len() {
    assert_eq!(Capability::count(), Capability::all().len());
}

#[test]
fn test_capability_as_str_core_exec() {
    assert_eq!(Capability::CoreExec.as_str(), "CoreExec");
}

#[test]
fn test_capability_as_str_io() {
    assert_eq!(Capability::IO.as_str(), "IO");
}

#[test]
fn test_capability_as_str_network() {
    assert_eq!(Capability::Network.as_str(), "Network");
}

#[test]
fn test_capability_as_str_ipc() {
    assert_eq!(Capability::IPC.as_str(), "IPC");
}

#[test]
fn test_capability_as_str_memory() {
    assert_eq!(Capability::Memory.as_str(), "Memory");
}

#[test]
fn test_capability_as_str_crypto() {
    assert_eq!(Capability::Crypto.as_str(), "Crypto");
}

#[test]
fn test_capability_as_str_filesystem() {
    assert_eq!(Capability::FileSystem.as_str(), "FileSystem");
}

#[test]
fn test_capability_as_str_hardware() {
    assert_eq!(Capability::Hardware.as_str(), "Hardware");
}

#[test]
fn test_capability_as_str_debug() {
    assert_eq!(Capability::Debug.as_str(), "Debug");
}

#[test]
fn test_capability_as_str_admin() {
    assert_eq!(Capability::Admin.as_str(), "Admin");
}

#[test]
fn test_capability_as_str_register_service() {
    assert_eq!(Capability::RegisterService.as_str(), "RegisterService");
}

#[test]
fn test_capability_display_matches_as_str() {
    use alloc::string::ToString;
    for cap in Capability::all() {
        assert_eq!(cap.to_string(), cap.as_str());
    }
}

#[test]
fn test_capability_clone() {
    let cap = Capability::Admin;
    let cloned = cap.clone();
    assert_eq!(cap, cloned);
}

#[test]
fn test_capability_copy() {
    let cap = Capability::Network;
    let copied: Capability = cap;
    assert_eq!(cap, copied);
}

#[test]
fn test_capability_equality() {
    assert_eq!(Capability::Admin, Capability::Admin);
    assert_ne!(Capability::Admin, Capability::Debug);
}

#[test]
fn test_capability_debug_format() {
    let cap = Capability::Memory;
    let debug_str = alloc::format!("{:?}", cap);
    assert!(debug_str.contains("Memory"));
}
