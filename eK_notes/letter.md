# A note about NONOS

NONOS is an attempt at a true from-scratch microkernel. RAM-first, ephemeral by default, capability-based. Not Linux-shaped. Not a mass of features bolted onto each other. The base has to be right or nothing built on top of it can be. It boots and runs. That part is proved.

What hasn't been proved is whether it can become stable, coherent and trustworthy enough to take seriously. That is what this phase is about.

For a long time the repository accumulated faster than it consolidated. The same authority got owned in two or three places at once. Trust paths existed in name but could be bypassed in practice. Some subsystems looked complete and turned out to point at functions that didn't exist anywhere. CPU statistics were being calculated by dividing a millisecond clock by two. There were three different `Task` types living in three different files, two of them dead. None of this is malice or carelessness. It is what happens to a project moving fast without pausing to enforce the architecture it claims to have.

The constitution this project commits to is short. The kernel's permitted list is small. CPU bring-up, memory, address spaces, threads, the scheduler, IPC, capabilities, interrupts, timers, plus whatever minimal mediation is needed to start user-space services. Nothing else. Storage, filesystems, the network stack, graphics, the vault, the module runtime, all of that lives outside the kernel trust base. If two parts of a codebase both think they own memory or scheduling or vault custody, the project doesn't actually have a kernel yet.

The work happening now is not planning. It is not analysis. It is deletion and consolidation. `src/ui` was orphan code. Never declared as a module, gated behind a feature flag, holding a CLI loop with no prompt. Now gone. `src/sys/process` was a third scheduler universe with its own `Task` types and an 800-line test file backing it. Also gone. Six duplicate `nonos_*` module trees were deleted in a dependency-ordered cascade. The PID run queue, the preemption mechanics, the task selection logic and the scheduler types have all been physically lifted out of `src/sched` into the canonical scheduler under `src/process/scheduler`. The repo is materially different now from what it was a week ago.

The point of all this is structural honesty. Two-thirds of the difficulty of turning a working prototype into a real production kernel comes from things you said you would do but quietly didn't. We're doing them now.

eK
