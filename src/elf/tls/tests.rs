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
use x86_64::VirtAddr;

#[test]
fn test_tls_info_new() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 256, 512, 16);
    assert_eq!(info.template_addr, VirtAddr::new(0x1000));
    assert_eq!(info.template_size, 256);
    assert_eq!(info.memory_size, 512);
    assert_eq!(info.alignment, 16);
}

#[test]
fn test_tls_info_bss_size() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 256, 512, 16);
    assert_eq!(info.bss_size(), 256);

    let info_no_bss = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 16);
    assert_eq!(info_no_bss.bss_size(), 0);
}

#[test]
fn test_tls_info_has_bss() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 256, 512, 16);
    assert!(info.has_bss());

    let info_no_bss = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 16);
    assert!(!info_no_bss.has_bss());
}

#[test]
fn test_tls_info_effective_alignment() {
    let info_small = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 8);
    assert_eq!(info_small.effective_alignment(), DEFAULT_TLS_ALIGNMENT);

    let info_large = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 64);
    assert_eq!(info_large.effective_alignment(), 64);
}

#[test]
fn test_tls_info_allocation_size() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 100, 100, 16);
    assert_eq!(info.allocation_size(), 112);

    let info_aligned = TlsInfo::new(VirtAddr::new(0x1000), 128, 128, 16);
    assert_eq!(info_aligned.allocation_size(), 128);
}

#[test]
fn test_tls_info_total_size_with_tcb() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 128, 128, 16);
    assert_eq!(info.total_size_with_tcb(), 128 + TCB_SIZE);
}

#[test]
fn test_tls_info_is_empty() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 0, 0, 16);
    assert!(info.is_empty());

    let info_not_empty = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 16);
    assert!(!info_not_empty.is_empty());
}

#[test]
fn test_tls_info_template_end() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 256, 512, 16);
    assert_eq!(info.template_end(), VirtAddr::new(0x1100));
}

#[test]
fn test_tls_info_default() {
    let info = TlsInfo::default();
    assert_eq!(info.template_addr, VirtAddr::new(0));
    assert_eq!(info.template_size, 0);
    assert_eq!(info.memory_size, 0);
    assert_eq!(info.alignment, DEFAULT_TLS_ALIGNMENT);
}

#[test]
fn test_tls_info_zero_alignment() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 256, 256, 0);
    assert_eq!(info.alignment, 1);
}

#[test]
fn test_calculate_tp_offset() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 128, 128, 16);
    assert_eq!(calculate_tp_offset(&info), 128);
}

#[test]
fn test_variable_offset() {
    let info = TlsInfo::new(VirtAddr::new(0x1000), 128, 128, 16);
    assert_eq!(variable_offset(&info, 64), -64);
}

#[test]
fn test_constants() {
    assert_eq!(DEFAULT_TLS_ALIGNMENT, 16);
    assert_eq!(TCB_SIZE, 16);
}
