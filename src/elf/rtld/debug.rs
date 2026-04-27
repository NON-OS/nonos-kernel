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

extern crate alloc;
use alloc::boxed::Box;
use core::ptr;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RDebugState {
    Consistent = 0,
    Add = 1,
    Delete = 2,
}

#[repr(C)]
pub struct RDebug {
    pub r_version: i32,
    pub r_map: *mut LinkMapEntry,
    pub r_brk: usize,
    pub r_state: RDebugState,
    pub r_ldbase: usize,
}

// Safety: RDebug contains raw pointers but is only accessed under a mutex lock
// and the pointers point to kernel-allocated memory that outlives any single access
unsafe impl Send for RDebug {}

#[repr(C)]
pub struct LinkMapEntry {
    pub l_addr: usize,
    pub l_name: *const u8,
    pub l_ld: usize,
    pub l_next: *mut LinkMapEntry,
    pub l_prev: *mut LinkMapEntry,
}

// Safety: LinkMapEntry contains raw pointers but is only accessed under a mutex lock
unsafe impl Send for LinkMapEntry {}

// Wrapper type for raw pointer to make it Send-safe for use in static Mutex
struct SendPtr(*mut LinkMapEntry);
unsafe impl Send for SendPtr {}

static R_DEBUG: Mutex<Option<Box<RDebug>>> = Mutex::new(None);
static LINK_MAP_HEAD: Mutex<SendPtr> = Mutex::new(SendPtr(ptr::null_mut()));

pub fn init_r_debug() {
    let mut guard = R_DEBUG.lock();
    if guard.is_none() {
        *guard = Some(Box::new(RDebug {
            r_version: 1,
            r_map: ptr::null_mut(),
            r_brk: r_debug_break as *const () as usize,
            r_state: RDebugState::Consistent,
            r_ldbase: 0,
        }));
    }
}

pub fn get_r_debug() -> *mut RDebug {
    let guard = R_DEBUG.lock();
    match guard.as_ref() {
        Some(b) => &**b as *const RDebug as *mut RDebug,
        None => ptr::null_mut(),
    }
}

pub fn update_debug_state(state: RDebugState) {
    if let Some(ref mut r) = *R_DEBUG.lock() {
        r.r_state = state;
        r_debug_break();
    }
}

#[no_mangle]
pub extern "C" fn r_debug_break() {}

pub fn add_link_map(obj: &super::load::LoadedObject) {
    let name_ptr = obj.name.as_ptr();
    let entry = Box::into_raw(Box::new(LinkMapEntry {
        l_addr: obj.base,
        l_name: name_ptr,
        l_ld: obj.dynamic,
        l_next: ptr::null_mut(),
        l_prev: ptr::null_mut(),
    }));
    let mut head = LINK_MAP_HEAD.lock();
    if head.0.is_null() {
        head.0 = entry;
    } else {
        let mut p = head.0;
        while !unsafe { (*p).l_next.is_null() } {
            p = unsafe { (*p).l_next };
        }
        unsafe {
            (*p).l_next = entry;
            (*entry).l_prev = p;
        }
    }
    if let Some(ref mut r) = *R_DEBUG.lock() {
        r.r_map = head.0;
    }
    super::audit::audit_activity(super::audit::AuditEvent::ActivityAdd);
}

pub fn remove_link_map(base: usize) {
    let mut head = LINK_MAP_HEAD.lock();
    let mut p = head.0;
    while !p.is_null() {
        if unsafe { (*p).l_addr } == base {
            let prev = unsafe { (*p).l_prev };
            let next = unsafe { (*p).l_next };
            if !prev.is_null() {
                unsafe {
                    (*prev).l_next = next;
                }
            } else {
                head.0 = next;
            }
            if !next.is_null() {
                unsafe {
                    (*next).l_prev = prev;
                }
            }
            unsafe {
                let _ = Box::from_raw(p);
            }
            break;
        }
        p = unsafe { (*p).l_next };
    }
    if let Some(ref mut r) = *R_DEBUG.lock() {
        r.r_map = head.0;
    }
    super::audit::audit_activity(super::audit::AuditEvent::ActivityDelete);
}

#[no_mangle]
pub static mut _r_debug: *mut RDebug = ptr::null_mut();

pub fn export_r_debug() {
    unsafe {
        _r_debug = get_r_debug();
    }
}
