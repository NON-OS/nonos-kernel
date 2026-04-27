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
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    ObjectOpen,
    ObjectLoaded,
    ObjectClose,
    SymbolBind,
    PltEnter,
    PltExit,
    ActivityConsistent,
    ActivityAdd,
    ActivityDelete,
}

pub type AuditCallback = fn(AuditEvent, &str, usize) -> bool;

pub struct AuditInterface {
    pub name: String,
    pub callback: AuditCallback,
    pub flags: u32,
}

static AUDIT_MODULES: Mutex<Vec<AuditInterface>> = Mutex::new(Vec::new());

pub const LA_FLG_BINDTO: u32 = 0x01;
pub const LA_FLG_BINDFROM: u32 = 0x02;

pub fn register_audit(name: &str, callback: AuditCallback, flags: u32) {
    AUDIT_MODULES.lock().push(AuditInterface { name: String::from(name), callback, flags });
}

pub fn unregister_audit(name: &str) {
    AUDIT_MODULES.lock().retain(|a| a.name != name);
}

pub fn notify_audit(event: AuditEvent, name: &str, addr: usize) -> bool {
    let modules = AUDIT_MODULES.lock();
    for audit in modules.iter() {
        if !(audit.callback)(event, name, addr) {
            return false;
        }
    }
    true
}

pub fn audit_objopen(name: &str, base: usize) -> bool {
    notify_audit(AuditEvent::ObjectOpen, name, base)
}

pub fn audit_objclose(name: &str, base: usize) {
    notify_audit(AuditEvent::ObjectClose, name, base);
}

pub fn audit_symbind(name: &str, addr: usize) -> usize {
    if notify_audit(AuditEvent::SymbolBind, name, addr) {
        addr
    } else {
        0
    }
}

pub fn audit_pltenter(name: &str, addr: usize) -> usize {
    if notify_audit(AuditEvent::PltEnter, name, addr) {
        addr
    } else {
        0
    }
}

pub fn audit_pltexit(name: &str, addr: usize, retval: usize) -> usize {
    notify_audit(AuditEvent::PltExit, name, addr);
    retval
}

pub fn audit_activity(event: AuditEvent) {
    notify_audit(event, "", 0);
}

pub fn get_audit_count() -> usize {
    AUDIT_MODULES.lock().len()
}

pub fn parse_ld_audit(env_val: &str) {
    for lib in env_val.split(':') {
        if !lib.is_empty() {
            load_audit_library(lib);
        }
    }
}

fn load_audit_library(_path: &str) {}
