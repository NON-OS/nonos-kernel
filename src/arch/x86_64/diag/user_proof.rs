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

//! Pre-iretq audit. Walks the target CR3 through the directmap and
//! proves the architectural preconditions for entering CPL=3:
//! kernel-half PML4 entries (256 directmap, 511 kernel text) are
//! present, the user RIP leaf is present + user-accessible +
//! executable, the user RSP leaf is present + user-accessible +
//! writable + NX, and the trap substrate (TSS.RSP0 plus the IST
//! slots used by #DF, #PF, #GP) is non-zero.
//!
//! On any failure prints `[USER-PROOF] FAIL <reason>` and refuses
//! to iretq. Production builds compile this path out; smoketest
//! profiles enable `nonos-user-entry-proof`.

use super::print_hex::print_hex_u64;
use crate::arch::x86_64::gdt::{
    constants::{IST_DOUBLE_FAULT, IST_GP, IST_PAGE_FAULT},
    get_ist, get_kernel_stack,
};
use crate::memory::layout::DIRECTMAP_BASE;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const PML4_DIRECTMAP: usize = 256;
const PML4_KERNEL_TEXT: usize = 511;

#[derive(Clone, Copy)]
pub struct LeafReq {
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
}

pub fn assert_user_entry(cr3: u64, user_rip: u64, user_rsp: u64, cpu_id: u32) -> bool {
    let ok_directmap = pml4_present(cr3, PML4_DIRECTMAP);
    if !ok_directmap {
        fail(b"PML4[256] missing", cr3);
        return false;
    }
    if !pml4_present(cr3, PML4_KERNEL_TEXT) {
        fail(b"PML4[511] missing", cr3);
        return false;
    }

    let rip_req = LeafReq { user: true, writable: false, executable: true };
    if !leaf_satisfies(cr3, user_rip, rip_req) {
        fail(b"user RIP leaf bad", user_rip);
        return false;
    }

    let rsp_req = LeafReq { user: true, writable: true, executable: false };
    if !leaf_satisfies(cr3, user_rsp - 8, rsp_req) {
        fail(b"user RSP leaf bad", user_rsp);
        return false;
    }

    let rsp0 = get_kernel_stack(cpu_id).unwrap_or(0);
    if rsp0 == 0 {
        fail(b"TSS.RSP0 zero", 0);
        return false;
    }
    let ist_df = get_ist(cpu_id, IST_DOUBLE_FAULT).unwrap_or(0);
    let ist_pf = get_ist(cpu_id, IST_PAGE_FAULT).unwrap_or(0);
    let ist_gp = get_ist(cpu_id, IST_GP).unwrap_or(0);
    if ist_df == 0 || ist_pf == 0 || ist_gp == 0 {
        fail(b"IST slot zero", 0);
        return false;
    }

    print_ok(cr3, user_rip, user_rsp, rsp0, ist_df, ist_pf, ist_gp);
    true
}

fn pml4_present(cr3: u64, idx: usize) -> bool {
    let pml4 = (DIRECTMAP_BASE + (cr3 & PHYS_MASK)) as *const u64;
    let entry = unsafe { core::ptr::read_volatile(pml4.add(idx)) };
    entry & PRESENT != 0
}

fn leaf_satisfies(cr3: u64, va: u64, req: LeafReq) -> bool {
    let i4 = ((va >> 39) & 0x1FF) as usize;
    let i3 = ((va >> 30) & 0x1FF) as usize;
    let i2 = ((va >> 21) & 0x1FF) as usize;
    let i1 = ((va >> 12) & 0x1FF) as usize;

    let pml4 = (DIRECTMAP_BASE + (cr3 & PHYS_MASK)) as *const u64;
    let e4 = unsafe { core::ptr::read_volatile(pml4.add(i4)) };
    if e4 & PRESENT == 0 {
        return false;
    }
    let e3_tbl = (DIRECTMAP_BASE + (e4 & PHYS_MASK)) as *const u64;
    let e3 = unsafe { core::ptr::read_volatile(e3_tbl.add(i3)) };
    if e3 & PRESENT == 0 {
        return false;
    }
    if e3 & HUGE != 0 {
        return matches_perms(e3, req);
    }
    let e2_tbl = (DIRECTMAP_BASE + (e3 & PHYS_MASK)) as *const u64;
    let e2 = unsafe { core::ptr::read_volatile(e2_tbl.add(i2)) };
    if e2 & PRESENT == 0 {
        return false;
    }
    if e2 & HUGE != 0 {
        return matches_perms(e2, req);
    }
    let e1_tbl = (DIRECTMAP_BASE + (e2 & PHYS_MASK)) as *const u64;
    let e1 = unsafe { core::ptr::read_volatile(e1_tbl.add(i1)) };
    if e1 & PRESENT == 0 {
        return false;
    }
    matches_perms(e1, req)
}

fn matches_perms(entry: u64, req: LeafReq) -> bool {
    if req.user && entry & USER == 0 {
        return false;
    }
    if req.writable && entry & WRITABLE == 0 {
        return false;
    }
    if req.executable && entry & NX != 0 {
        return false;
    }
    if !req.executable && entry & NX == 0 {
        return false;
    }
    true
}

fn fail(reason: &[u8], v: u64) {
    crate::sys::serial::print(b"[USER-PROOF] FAIL ");
    crate::sys::serial::print(reason);
    crate::sys::serial::print(b" v=");
    print_hex_u64(v);
    crate::sys::serial::println(b"");
}

fn print_ok(cr3: u64, rip: u64, rsp: u64, rsp0: u64, df: u64, pf: u64, gp: u64) {
    crate::sys::serial::print(b"[USER-PROOF] OK cr3=");
    print_hex_u64(cr3);
    crate::sys::serial::print(b" rip=");
    print_hex_u64(rip);
    crate::sys::serial::print(b" rsp=");
    print_hex_u64(rsp);
    crate::sys::serial::print(b" rsp0=");
    print_hex_u64(rsp0);
    crate::sys::serial::print(b" istDF=");
    print_hex_u64(df);
    crate::sys::serial::print(b" istPF=");
    print_hex_u64(pf);
    crate::sys::serial::print(b" istGP=");
    print_hex_u64(gp);
    crate::sys::serial::println(b"");
}
