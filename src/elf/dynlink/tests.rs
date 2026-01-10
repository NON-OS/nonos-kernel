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
fn test_dyn_link_info_new() {
    let info = DynLinkInfo::new();
    assert!(info.needed_libraries.is_empty());
    assert!(info.symbol_table.is_none());
    assert!(info.string_table.is_none());
    assert_eq!(info.string_table_size, 0);
    assert!(info.is_empty());
}

#[test]
fn test_dyn_link_info_default() {
    let info = DynLinkInfo::default();
    assert!(info.is_empty());
}

#[test]
fn test_needs_libraries() {
    let mut info = DynLinkInfo::new();
    assert!(!info.needs_libraries());
    assert_eq!(info.library_count(), 0);

    info.add_needed("libc.so.6".into());
    assert!(info.needs_libraries());
    assert_eq!(info.library_count(), 1);
}

#[test]
fn test_needs_library() {
    let mut info = DynLinkInfo::new();
    info.add_needed("libc.so.6".into());
    info.add_needed("libm.so.6".into());

    assert!(info.needs_library("libc.so.6"));
    assert!(info.needs_library("libm.so.6"));
    assert!(!info.needs_library("libpthread.so.0"));
}

#[test]
fn test_has_relocations() {
    let mut info = DynLinkInfo::new();
    assert!(!info.has_relocations());

    info.rela_table = Some(VirtAddr::new(0x1000));
    assert!(info.has_relocations());

    info.rela_table = None;
    info.plt_relocations = Some(VirtAddr::new(0x2000));
    assert!(info.has_relocations());
}

#[test]
fn test_has_symbols() {
    let mut info = DynLinkInfo::new();
    assert!(!info.has_symbols());

    info.symbol_table = Some(VirtAddr::new(0x1000));
    assert!(info.has_symbols());
}

#[test]
fn test_has_strings() {
    let mut info = DynLinkInfo::new();
    assert!(!info.has_strings());

    info.string_table = Some(VirtAddr::new(0x1000));
    assert!(!info.has_strings());

    info.string_table_size = 1024;
    assert!(info.has_strings());
}

#[test]
fn test_has_init_fini() {
    let mut info = DynLinkInfo::new();
    assert!(!info.has_init());
    assert!(!info.has_fini());

    info.init_function = Some(VirtAddr::new(0x1000));
    assert!(info.has_init());

    info.fini_function = Some(VirtAddr::new(0x2000));
    assert!(info.has_fini());
}

#[test]
fn test_rela_count() {
    let mut info = DynLinkInfo::new();
    assert_eq!(info.rela_count(), 0);

    info.rela_size = 72;
    assert_eq!(info.rela_count(), 3);
}

#[test]
fn test_plt_rela_count() {
    let mut info = DynLinkInfo::new();
    assert_eq!(info.plt_rela_count(), 0);

    info.plt_rela_size = 48;
    assert_eq!(info.plt_rela_count(), 2);
}

#[test]
fn test_total_relocation_count() {
    let mut info = DynLinkInfo::new();
    info.rela_size = 72;
    info.plt_rela_size = 48;
    assert_eq!(info.total_relocation_count(), 5);
}

#[test]
fn test_string_table_end() {
    let mut info = DynLinkInfo::new();
    assert!(info.string_table_end().is_none());

    info.string_table = Some(VirtAddr::new(0x1000));
    info.string_table_size = 0x200;
    assert_eq!(info.string_table_end(), Some(VirtAddr::new(0x1200)));
}

#[test]
fn test_is_empty() {
    let mut info = DynLinkInfo::new();
    assert!(info.is_empty());

    info.add_needed("libc.so.6".into());
    assert!(!info.is_empty());

    let mut info2 = DynLinkInfo::new();
    info2.symbol_table = Some(VirtAddr::new(0x1000));
    assert!(!info2.is_empty());

    let mut info3 = DynLinkInfo::new();
    info3.init_function = Some(VirtAddr::new(0x1000));
    assert!(!info3.is_empty());
}
