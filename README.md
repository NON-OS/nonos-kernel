> ## ⚠️ Development Status
>
> *a note from the team.*
>
> NØNOS is currently undergoing a deep architectural transition toward a **microkernel design**.
> This transition is recent and still under active validation at the execution level.
>
> The system **boots, runs and spawns services** but correctness, isolation guarantees and full runtime behavior are still being refined.
>
> This system it is a **live build phase** where foundations are being moved and built properly.
>
> If you are testing or exploring NØNOS, expect instability and rapid iteration from source code.
>
> A full development note is included below.

---

# NØNOS MICROKERNEL

**Zero-State · Capability-Based · Security-First Operating System**

[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://rustlang.org)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/arch-x86__64-blue.svg)](x86_64-nonos.json)

**Repository:** https://github.com/NON-OS/nonos-kernel

---

## Overview

**NØNOS** is a from-scratch operating system built around a simple but strict idea:

> A computing session should begin from a clean state and end without leaving persistent traces.

The system is designed as a **microkernel-oriented architecture** written in **Rust**, combining:

- capability-based security  
- explicit process isolation  
- IPC-driven service communication  
- cryptographic integrity across the boot chain  

Unlike traditional operating systems that accumulate state over time, NØNOS follows a **Zero-State execution model**.

The system is designed to run in memory and return to a clean baseline when power is removed.

This repository contains the **core kernel, boot integration and low-level runtime** that define the foundation of the NØNOS system.

---

## Architecture Direction

NØNOS is actively evolving toward a **capability-based microkernel model**.

The core idea is to minimize what runs in kernel space and move everything else into isolated services.

In practice, this means:

- services execute as **independent processes**  
- each service operates within its own **address space (CR3 separation)**  
- communication is handled through **kernel-mediated IPC**  
- access is enforced via **explicit capabilities**, not implicit privilege  

This transition is currently in progress and under validation.

---

## Design Principles

### Zero-State Execution

NØNOS does not maintain persistent operating system state between sessions by default.

There is no swap, no background persistence, and no hibernation model.  
When power is removed, the system returns to a clean state.

### Capability-Based Security

Access to resources is controlled through explicit capability assignment.

There is no global “root” model — permissions are defined at the boundary and enforced by the kernel.

### Minimal Trusted Core

The kernel is designed to remain as small and auditable as possible.

All non-essential functionality is moved into userspace services.

### Cryptographic Integrity

Kernel artifacts are verified during boot.

The boot chain enforces integrity from firmware handoff through kernel execution.

---

## From the Team

Hey, eK here.

The last weeks have been intense. Not in a visible way but in the kind where you realize the system works… just not in the way it should and you decide to move onto next step while followed the process and validated some important stuffs at first.

That’s where the microkernel transition began.

We’ve moved from a tightly coupled kernel toward a stricter model where services are real processes, isolated in their own address spaces, communicating through IPC, with access enforced explicitly.

That sounds clean on paper but in reality it means removing every shortcut the system previously relied on.

Today most parts work exactly as intended. 

Service spawn, address spaces are created, the scheduler switches execution, IPC flows through the kernel.

Other parts still need correction.

At this level, things don’t “kind of work”.

Either context switching is correct or it isn’t. Either isolation holds or it doesn’t.

This phase is about proving correctness.

Not adding features.

The next release (**v0.8.4**) is focused on bringing everything back together into a usable system again not just architecturally correct but something you can actually run and rely on day-to-use.

Alpha exposed real-world issues across hardware, networking and execution paths. 

That feedback is now shaping what’s being rebuilt.

From the outside, progress might not look obvious but internally, a lot has changed. If you’ve been following or supporting quietly tgen that matters.

We’re getting there.

---

## Documentation

Full documentation is available at:

**https://nonos.software/docs**

Includes:

- architecture specifications  
- kernel internals  
- memory and hardware model  
- boot chain design  
- build and installation guides  
- development roadmap  

---

## Getting Started

For building, running, or testing NØNOS:

### Build Manual
https://nonos.software/docs/development/build-manual/

### Installation Guide
https://nonos.software/docs/getting-started/full-installation-guide/

### Architecture
https://nonos.software/docs/architecture/

### Roadmap
https://nonos.software/roadmap/

---

## Current Status

**Stage:** Alpha → Pre-Beta Transition  
**Architecture:** Microkernel (in progress)  
**Stability:** Experimental testing phase

Focus areas:

- process execution correctness  
- memory isolation validation  
- IPC reliability  
- scheduler stability  
- hardware compatibility  
- networking stack refinement  

---

## Contributing

NØNOS is an open system.

Contributions are welcome across:

- kernel development  
- services and runtime  
- networking  
- documentation  
- testing and validation  

Start here:

https://nonos.software/docs

---

## License

NØNOS is released under the **GNU AGPL-3.0 License**.

See `LICENSE` for details.

---

## Project Mission

NØNOS explores a different model of computing.

One where privacy and integrity are not features added later but properties defined at the architectural level. It’s about building a system that behaves differently by design.

---

**NØNOS — Sovereignty from ∅**
