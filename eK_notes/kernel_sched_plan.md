# Kernel-core scheduler rebuild plan

## Where this starts

Four scheduler-authority lifts are already on `origin/main`. The PID run queue and sleep table moved to `src/process/scheduler/dispatch`. The preemption atomics and mechanics (SCHEDULER_STATS, NEED_RESCHEDULE, CURRENT_TIME_SLICE, plus tick, switch and yield_impl) moved to `src/process/scheduler/preemption`. Task selection moved to `src/process/scheduler/selection`. The scheduler types (Scheduler, SchedulerStats, SchedulerStatsSnapshot, ModuleTaskError) moved to `src/process/scheduler/types`. Each cut is its own commit, git-detected as a rename. Legacy `crate::sched::scheduler::*` paths still resolve through forwarding aliases inside `src/sched/scheduler/mod.rs` so external callers were never broken.

What is left in `src/sched` is no longer cleanup. It is the dispatcher itself plus the things tightly coupled to it.

## Current map

Inside `src/sched/scheduler/`:

- `core.rs` holds GLOBAL_SCHEDULER, the per-task RUNQUEUE (Mutex<RunQueue>) and the `run()` loop the kernel enters at the end of boot and never leaves.
- `module_tasks/` wraps spawn/terminate for module-tagged kernel tasks. Its only consumer is canonical `src/modules/runner/helpers.rs`. That edge points the wrong way.
- `smp/` owns the per-CPU queues, the load balancer and init_ap_scheduler. core::init calls into it.
- `stats.rs` aggregates the SchedulerStatsSnapshot.
- `mod.rs` is now mostly forwarding aliases.

Top-level `src/sched/`:

- `api.rs`: four thin wrappers (current_cpu_id, current_scheduler, schedule, yield_cpu). 15 yield_cpu callers and 8 schedule callers point at it.
- `cpu_stats.rs`: synthetic procfs stats with two callers.
- `context/`: the Context type (x86_64 register layout) and a pid-keyed BTreeMap of saved contexts. Eight external callers including arch-side code and ptrace.
- `deadline/` and `realtime/`: scheduler tiers, both called from inside core::run.
- `runqueue/`: the per-task RunQueue struct used by core::RUNQUEUE.
- `task/`: Task, Priority, CpuAffinity, DeadlineParams, SchedPolicy. Priority has 1 external caller.
- `executor/`: async kernel executor. Zero external callers per the histogram.

## The end state worth aiming for

`src/process/scheduler/` becomes the canonical home for everything that constitutes scheduler authority over process lifecycle. The dispatcher loop, the per-CPU queues, both tier schedulers, the data types the scheduler operates on (Task, Priority, RunQueue), the module-task spawn interface, the stats aggregator and the policy registry. Everything the syscall layer reaches for as "the scheduler" lives there.

`src/sched/` does not fully empty. It stays as the home for kernel execution primitives that are not process-scheduler authority. Specifically `context/` (register and FPU save/restore) and `executor/` (futures-based async work). These are different concerns from preemptive process scheduling. Whether the directory eventually gets renamed to something more honest about what it became is a separate cosmetic call and not in scope here.

## The cluster

`core.rs` cannot move alone. The `run()` loop reads from realtime, deadline and the per-task RUNQUEUE inside its hot path. `init()` initializes core, realtime, deadline and smp. `spawn()` dispatches by Task priority into deadline, realtime or the default queue. Pulling out any one of those subtrees without the rest reopens cross-tree edges that only close when the others follow. So the dispatcher, the SMP layer, both tier schedulers and the data types they operate on (Task, RunQueue) move as one architectural unit. That is what makes this the kernel-core rebuild and not another casual cut.

## Module_tasks goes to canonical scheduler, not canonical runner

`module_tasks` wraps the scheduler's spawn primitive specifically for module-tagged kernel tasks. The interface it presents is scheduler-level. The canonical runner consumes it from above. Putting module_tasks under the runner would invert the dependency. Cleaner home is canonical scheduler, alongside core::spawn.

## Stats lifts with core

`stats.rs` reads core::get_queue (in sched), the SCHEDULER_STATS atomics (already canonical), the SchedulerStatsSnapshot type (already canonical) and dispatch::runnable_process_count (already canonical). The only sched-side dependency is core::get_queue. It moves with core.

## api.rs and cpu_stats.rs

`api.rs` is four wrappers over names already exported elsewhere. The wrappers themselves have value given the caller count. The indirection is cosmetic. Move it with the dispatcher cluster. After the move it can be collapsed into direct re-exports if the wrappers prove redundant.

`cpu_stats.rs` is two procfs callers reading synthetic stats. Self-contained. Rides with the cluster.

## context/ stays in src/sched

The Context type is x86_64 register layout. The save/restore plumbing is consumed by the scheduler, ptrace and process suspend/resume. Multiple subsystems reach for it. Moving Context under `src/process/context/` would chase symmetry without earning clarity. The canonical scheduler reading from a kernel primitive is not a wrong-direction edge. It is what kernel primitives are for. Leave Context where it is.

## executor/ stays for now

Zero external callers. The async executor schedules futures, not processes. Different concern. Whether it eventually gets deleted (if confirmed unused) or stays as a separate kernel-execution facility is independent of the scheduler convergence and should not block it.

## Wrong-direction edges and how they close

After the cluster move:

- canonical preemption reaching `crate::sched::realtime` becomes a same-tree call. Closed.
- canonical preemption reaching `crate::sched::Context` stays cross-tree. This is intentional. Context is a kernel primitive that the scheduler consumes.
- canonical runner reaching `crate::sched::scheduler::module_tasks` becomes a same-tree call (or a `crate::process::scheduler::module_tasks` call). Closed.
- canonical scheduler core reaching `crate::sched::deadline` and `crate::sched::realtime` becomes same-tree. Closed.
- canonical scheduler core reaching `crate::arch::idle_cpu` and arch-side cpu/fpu helpers stays cross-tree. These are arch boundaries, not authority duplicates.

After all four cuts there are no remaining wrong-direction edges between scheduler authority and `src/sched`. What remains is the canonical scheduler reading from arch-near primitives, which is the right shape.

## Execution sequence

Four cuts, in this order. Each is its own commit on its own branch session.

**Cut 1: lift `module_tasks/`.** Smallest. Self-contained. Closes the runner-to-sched edge. Four files. Path adjustments inside the module are minimal because module_tasks only reaches into core::spawn (which is still in sched at this point, so the lifted module reaches back via absolute path during the intermediate state). After Cut 4 that absolute path becomes a sibling reference.

**Cut 2: lift `scheduler/stats.rs`, `api.rs` and `cpu_stats.rs`.** Small bundle. The three are loosely related (scheduler info surface), all small, all with manageable consumer paths. Closes a few minor cross-tree reads. After this cut, the dispatcher cluster is the only remaining substantive thing in `src/sched/scheduler/` plus `realtime/deadline/runqueue/task/`.

**Cut 3: lift `realtime/`, `deadline/`, `runqueue/` and `task/` together.** The tier schedulers and the data types they operate on. Substantive. The two tier schedulers each have their own queue, admission and runtime accounting and lift with their internals intact. Path adjustments mostly point Task and Priority references at the canonical location. Sched-side aliases preserve the existing `crate::sched::Task`, `crate::sched::Priority`, `crate::sched::RunQueue` external callers. This is the cut where scheduler-tier authority finishes moving.

**Cut 4: lift `scheduler/core.rs` and `scheduler/smp/`.** The dispatcher itself. This is the kernel-core rebuild. After this cut, `src/sched/scheduler/` is gone or reduced to a forwarding shim. Top-level `src/sched/` retains only `context/` and `executor/`. The boot path's `crate::sched::enter()` and `crate::sched::init()` continue to resolve through aliases until external callers retarget at leisure.

The order matters. Cuts 1 and 2 are warmup that close minor wrong-direction edges and reduce blast radius for the bigger moves. Cut 3 establishes the tier-scheduler authority shape that Cut 4 needs in order to land cleanly. Cut 4 is the dispatcher.

## First cut, files involved

For Cut 1 specifically, the files are:

- `src/sched/scheduler/module_tasks/mod.rs`, `lifecycle.rs`, `spawn.rs`, `state.rs` move to `src/process/scheduler/module_tasks/`.
- `src/process/scheduler/mod.rs` adds `pub mod module_tasks;`.
- `src/sched/scheduler/mod.rs` replaces `pub mod module_tasks;` with `pub use crate::process::scheduler::module_tasks;`. Existing downstream `pub use module_tasks::{...}` keeps working through the alias.
- Inside the lifted files, internal paths to `crate::sched::scheduler::core` (if any) become absolute paths during the intermediate state. After Cut 4 they become sibling references.

Five files moved or modified. One commit. Same shape as every previous lift.

## What not to touch casually

`core.rs::run()` is the dispatcher loop. The kernel enters this at the end of boot and never leaves. Any reorder of its `realtime → deadline → default → idle` cycle, any missed init call, any wrong arc into `idle_cpu` can wedge the system. The lift in Cut 4 must preserve all invariants exactly.

`context/types/save.rs` and `restore.rs` are hardware-specific. Touching them means touching register save/restore semantics. Leave alone.

The 72 callers of `crate::sched::yield_now` and the 8 callers of `crate::sched::Context`. Do not migrate them in this phase. The alias chain handles them. Migrate at leisure once the cluster has settled.

Tier scheduler internals (admission control, RT priority bands, deadline replenishment). The lift moves the trees. It does not change scheduling semantics. If the lift accidentally invites changes to those internals, stop and revert.

## Risks

Cut 4 is the riskiest cut in the entire scheduler convergence. core.rs::run() running incorrectly means the kernel does not boot or hangs immediately. There is no way to verify without a build. The project is not building yet. The execution rule for Cut 4 is therefore explicit: write the lift, review the lift, build before pushing. That gate is non-negotiable for the dispatcher move. Cuts 1 through 3 are safer but the same gate is still the right discipline.

## What this plan deliberately does not address

Memory consolidation. Vault migration. Trust-path rebuild. Boot chain rewrite. Each is a separate later phase. Pulling on any of them while the scheduler is still moving would entangle two big rebuilds at once. Finish the scheduler first.
