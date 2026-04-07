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
use alloc::vec::Vec;
use spin::Mutex;
use core::ptr;

#[derive(Debug, Clone)]
pub struct TlsModule {
    pub id: usize,
    pub base: usize,
    pub size: usize,
    pub align: usize,
    pub init_image: usize,
    pub init_size: usize,
    pub offset: isize,
}

#[derive(Debug, Clone)]
pub struct TlsDescriptor {
    pub arg: usize,
    pub entry: usize,
}

static TLS_MODULES: Mutex<Vec<TlsModule>> = Mutex::new(Vec::new());
static NEXT_TLS_ID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(1);
static TLS_SIZE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn init_tls() -> Result<(), i32> {
    init_static_tls();
    let tls_block = allocate_tls_block();
    if tls_block.is_null() && get_tls_size() > 0 {
        return Err(-12);
    }
    if !tls_block.is_null() {
        let tcb_size = core::mem::size_of::<usize>() * 2;
        let tp = unsafe { tls_block.add(get_tls_size()).add(tcb_size) };
        unsafe { *(tp.sub(core::mem::size_of::<usize>()) as *mut usize) = tp as usize; }
        set_thread_pointer(tp as usize);
    }
    Ok(())
}

pub fn init_static_tls() {
    let objects = super::load::get_loaded_objects();
    for obj in &objects { register_tls_module(&obj); }
}

pub fn register_tls_module(obj: &super::load::LoadedObject) {
    if obj.dynamic == 0 { return; }
    let mut tls_addr = 0usize;
    let mut tls_size = 0usize;
    let mut tls_align = 0usize;
    let mut tls_filesz = 0usize;
    let mut dyn_ptr = obj.dynamic as *const crate::elf::types::DynamicEntry;
    unsafe {
        while (*dyn_ptr).d_tag != 0 {
            match (*dyn_ptr).d_tag {
                29 => tls_addr = obj.base + (*dyn_ptr).value as usize,
                30 => tls_size = (*dyn_ptr).value as usize,
                32 => tls_align = (*dyn_ptr).value as usize,
                31 => tls_filesz = (*dyn_ptr).value as usize,
                _ => {}
            }
            dyn_ptr = dyn_ptr.add(1);
        }
    }
    if tls_size == 0 { return; }
    let id = NEXT_TLS_ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let current_size = TLS_SIZE.load(core::sync::atomic::Ordering::SeqCst);
    let aligned_offset = ((current_size + tls_align - 1) & !(tls_align - 1)) as isize;
    TLS_SIZE.store(aligned_offset as usize + tls_size, core::sync::atomic::Ordering::SeqCst);
    let module = TlsModule {
        id,
        base: tls_addr,
        size: tls_size,
        align: tls_align.max(1),
        init_image: tls_addr,
        init_size: tls_filesz,
        offset: -aligned_offset - tls_size as isize,
    };
    TLS_MODULES.lock().push(module);
}

pub fn allocate_tls_block() -> *mut u8 {
    let total_size = TLS_SIZE.load(core::sync::atomic::Ordering::SeqCst);
    if total_size == 0 { return ptr::null_mut(); }
    let aligned_size = (total_size + 15) & !15;
    let block = unsafe { crate::libc::stdlib::malloc::malloc(aligned_size + 16) };
    if block.is_null() { return ptr::null_mut(); }
    let modules = TLS_MODULES.lock();
    for m in modules.iter() {
        if m.init_image != 0 && m.init_size > 0 {
            let dest = unsafe { block.offset(m.offset) };
            unsafe { ptr::copy_nonoverlapping(m.init_image as *const u8, dest, m.init_size); }
        }
    }
    block
}

pub fn get_tls_module(id: usize) -> Option<TlsModule> {
    TLS_MODULES.lock().iter().find(|m| m.id == id).cloned()
}

pub fn tls_get_addr(ti: *const TlsDescriptor) -> *mut u8 {
    let desc = unsafe { &*ti };
    let tp = get_thread_pointer();
    if desc.arg == 0 { return ptr::null_mut(); }
    let module = match get_tls_module(desc.arg) { Some(m) => m, None => return ptr::null_mut() };
    unsafe { (tp as *mut u8).offset(module.offset).add(desc.entry) }
}

fn get_thread_pointer() -> usize {
    let mut tp: usize;
    unsafe { core::arch::asm!("mov {}, fs:0", out(reg) tp); }
    tp
}

pub fn set_thread_pointer(tp: usize) {
    crate::syscall::core::sys_arch_prctl(0x1002, tp);
}

pub fn get_tls_size() -> usize { TLS_SIZE.load(core::sync::atomic::Ordering::SeqCst) }

#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(ti: *const TlsDescriptor) -> *mut u8 { tls_get_addr(ti) }
