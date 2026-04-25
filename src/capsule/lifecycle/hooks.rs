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
use crate::capsule::CapsuleId;
use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::RwLock;

type HookFn = Box<dyn Fn(CapsuleId) + Send + Sync>;
type ExitHookFn = Box<dyn Fn(CapsuleId, i32) + Send + Sync>;

struct Hooks {
    on_start: Vec<HookFn>,
    on_suspend: Vec<HookFn>,
    on_resume: Vec<HookFn>,
    on_exit: Vec<ExitHookFn>,
    on_fault: Vec<HookFn>,
}

static HOOKS: RwLock<Option<Hooks>> = RwLock::new(None);

pub fn init() {
    *HOOKS.write() = Some(Hooks {
        on_start: Vec::new(),
        on_suspend: Vec::new(),
        on_resume: Vec::new(),
        on_exit: Vec::new(),
        on_fault: Vec::new(),
    });
}

pub fn register_start<F: Fn(CapsuleId) + Send + Sync + 'static>(f: F) {
    if let Some(h) = HOOKS.write().as_mut() {
        h.on_start.push(Box::new(f));
    }
}

pub fn register_suspend<F: Fn(CapsuleId) + Send + Sync + 'static>(f: F) {
    if let Some(h) = HOOKS.write().as_mut() {
        h.on_suspend.push(Box::new(f));
    }
}

pub fn register_resume<F: Fn(CapsuleId) + Send + Sync + 'static>(f: F) {
    if let Some(h) = HOOKS.write().as_mut() {
        h.on_resume.push(Box::new(f));
    }
}

pub fn register_exit<F: Fn(CapsuleId, i32) + Send + Sync + 'static>(f: F) {
    if let Some(h) = HOOKS.write().as_mut() {
        h.on_exit.push(Box::new(f));
    }
}

pub fn register_fault<F: Fn(CapsuleId) + Send + Sync + 'static>(f: F) {
    if let Some(h) = HOOKS.write().as_mut() {
        h.on_fault.push(Box::new(f));
    }
}

pub fn on_start(id: CapsuleId) {
    if let Some(h) = HOOKS.read().as_ref() {
        for f in &h.on_start {
            f(id);
        }
    }
}

pub fn on_suspend(id: CapsuleId) {
    if let Some(h) = HOOKS.read().as_ref() {
        for f in &h.on_suspend {
            f(id);
        }
    }
}

pub fn on_resume(id: CapsuleId) {
    if let Some(h) = HOOKS.read().as_ref() {
        for f in &h.on_resume {
            f(id);
        }
    }
}

pub fn on_exit(id: CapsuleId, code: i32) {
    if let Some(h) = HOOKS.read().as_ref() {
        for f in &h.on_exit {
            f(id, code);
        }
    }
}

pub fn on_fault(id: CapsuleId) {
    if let Some(h) = HOOKS.read().as_ref() {
        for f in &h.on_fault {
            f(id);
        }
    }
}
