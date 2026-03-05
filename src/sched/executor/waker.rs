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

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use core::task::{RawWaker, RawWakerVTable, Waker};

use super::types::WakerData;
use super::state::{EXECUTOR_STATS, WOKEN_TASKS};

impl WakerData {
    pub(super) fn new(task_id: u64) -> Arc<Self> {
        Arc::new(Self {
            task_id,
            woken: core::sync::atomic::AtomicBool::new(false),
        })
    }
}

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // SAFETY: Data pointer is a valid Arc<WakerData>.
    unsafe {
        let arc = Arc::from_raw(data as *const WakerData);
        let cloned = arc.clone();
        core::mem::forget(arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &WAKER_VTABLE)
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: Data pointer is a valid Arc<WakerData>.
    unsafe {
        let arc = &*(data as *const WakerData);
        wake_task_internal(arc.task_id);
        arc.woken.store(true, Ordering::SeqCst);
    }
}

unsafe fn waker_wake(data: *const ()) {
    // SAFETY: Data pointer is a valid Arc<WakerData>.
    unsafe {
        waker_wake_by_ref(data);
        waker_drop(data);
    }
}

unsafe fn waker_drop(data: *const ()) {
    // SAFETY: Data pointer is a valid Arc<WakerData>.
    unsafe {
        drop(Arc::from_raw(data as *const WakerData));
    }
}

pub(super) static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    waker_clone,
    waker_wake,
    waker_wake_by_ref,
    waker_drop,
);

pub(super) fn wake_task_internal(task_id: u64) {
    EXECUTOR_STATS.wakeups_triggered.fetch_add(1, Ordering::Relaxed);

    let mut woken = WOKEN_TASKS.write();
    if !woken.contains(&task_id) {
        woken.push(task_id);
    }

    crate::sched::wakeup();
}

pub(super) fn create_waker(task_id: u64) -> Waker {
    let data = WakerData::new(task_id);
    let raw = RawWaker::new(Arc::into_raw(data) as *const (), &WAKER_VTABLE);
    // SAFETY: RawWaker is properly constructed with valid vtable.
    unsafe { Waker::from_raw(raw) }
}

pub fn wake_task(task_id: u64) {
    wake_task_internal(task_id);
}
