# NØNOS Kernel Scheduler Subsystem

## Overview

The NØNOS scheduler subsystem is designed for secure, RAM-only, zero-state multitasking in kernel environments.  
It provides robust support for cooperative and preemptive scheduling, real-time task handling, async/future execution, and explicit context switching.

All code is written and maintained (at this stage) by eK team@nonos.systems.

---

## Features

- **RAM-only, zero-state:** All task and scheduling structures reside in memory with no persistent state.
- **Cooperative and preemptive scheduling:** Supports both task-driven and timer-driven switching.
- **Real-time task support:** Dedicated logic and run queue for minimal-latency, high-priority tasks.
- **Async/future execution:** Optional, integrated executor for polling kernel async tasks.
- **Explicit context switching:** Full CPU state save/restore with support for future SMP and advanced features.
---

## File Structure

- `mod.rs` — Entry point and API re-exports for the scheduler subsystem
- `task.rs` — Task definitions, priority, affinity, and spawning
- `runqueue.rs` — RAM-only run queue implementation
- `context.rs` — Full CPU context switching (x86_64)
- `executor.rs` — Asynchronous kernel task executor (optional)
- `realtime.rs` — Real-time task management and execution
- `nonos_scheduler.rs` — Main scheduler logic and kernel entry points

---

## Quick Start

To integrate the scheduler subsystem:

1. **Initialize the scheduler:**
    ```rust
    use nonos_kernel::sched::init;
    init();
    ```

2. **Spawn tasks:**
    ```rust
    use nonos_kernel::sched::{spawn, Task, Priority, CpuAffinity};
    let my_task = Task::spawn("example", || { /* task body */ }, Priority::Normal, CpuAffinity::any());
    spawn(my_task);
    ```

3. **Start the scheduler loop:**
    ```rust
    use nonos_kernel::sched::enter;
    enter(); // Never returns
    ```

4. **Real-time tasks:**
    ```rust
    use nonos_kernel::sched::{spawn_realtime, run_realtime_tasks};
    let rt_task = Task::spawn("rt", || { /* rt body */ }, Priority::RealTime, CpuAffinity::any());
    spawn_realtime(rt_task);
    run_realtime_tasks();
    ```

5. **Async tasks:**
    ```rust
    use nonos_kernel::sched::{spawn_async, poll_async_tasks};
    spawn_async("async_example", Box::pin(async { /* async body */ }));
    poll_async_tasks();
    ```

---

## Contributor Credits

All code, documentation and integration for the scheduler subsystem are written and maintained by:

**eK team@nonos.systems**

If you wish to contribute, please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This codebase is released under a professional open source license.  
See [LICENSE](../LICENSE) for details.
