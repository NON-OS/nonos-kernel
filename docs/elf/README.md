# NØNOS ELF Loader Subsystem

## Overview

The NØNOS ELF loader is a  module for secure, robust kernel-level ELF executable loading and mapping.  
It supports dynamic linking, full address space layout randomization (ASLR), Thread-Local Storage (TLS), and interpreter handoff—making it ideal for modern, secure, and high-performance OS kernels.

All code is written and maintained in accordance with kernel engineering standards.  
---

## Features

- **RAM-only, zero-state:** All ELF parsing, mapping, and runtime structures reside in RAM.
- **Full ELF64 support:** Loads both static and PIE (position-independent) x86_64 binaries.
- **ASLR:** Secure randomization of base, stack, and heap addresses for all loaded executables.
- **Dynamic linking:** Robust support for shared libraries (DT_NEEDED), relocation tables, and symbol resolution.
- **TLS:** Explicit support for Thread-Local Storage segment parsing and mapping.
- **Interpreter handoff:** PT_INTERP parsing and dynamic handoff to system interpreters (e.g., dynamic linkers).
- **Error handling:** Every failure scenario is handled with explicit, meaningful errors.

---

## File Structure

- `mod.rs` — Entry point and API re-exports for the ELF loader subsystem
- `types.rs` — ELF headers, program/section headers, symbol and relocation types
- `errors.rs` — All error types used for error handling/reporting
- `aslr.rs` — ASLR manager
- `reloc.rs` — All relocation routines
- `loader.rs` — Main loader: parsing, mapping, ASLR, relocations, TLS, interpreter
- `tls.rs` — Thread-Local Storage support
- `dynlink.rs` — Dynamic linking helpers: library dependencies, symbol/string tables
- `interpreter.rs` — Interpreter logic for PT_INTERP (dynamic linker handoff)

---

## Quick Start

1. **Initialize the ELF loader:**
    ```rust
    use nonos_kernel::elf::init_elf_loader;
    init_elf_loader();
    ```

2. **Load an ELF executable from memory:**
    ```rust
    use nonos_kernel::elf::load_elf_executable;
    let image = load_elf_executable(&elf_bytes)?;
    ```

3. **Access mapped segments and entrypoint:**
    ```rust
    let entry = image.entry_point;
    let segments = &image.segments;
    ```

4. **Handle dynamic linking and TLS:**
    ```rust
    if let Some(dynamic) = &image.dynamic_info {
        // Access DT_NEEDED libs, symbol tables, etc.
    }
    if let Some(tls) = &image.tls_info {
        // Setup thread-local storage for process
    }
    ```

5. **Interpreter handoff:**
    ```rust
    if let Some(path) = &image.interpreter {
        // Launch dynamic linker as needed
    }
    ```

---

## Contributor Credits

All code and documentation for the ELF loader subsystem are written and maintained by:

**eK team@nonos.systems**

We welcome contributors.  
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This subsystem is released under an open source license.  
See [LICENSE](../LICENSE) for details.

---

## Support & Contact

For questions, professional support, or to contribute, reach out to:

- eK team@nonos.systems
- Or open a GitHub discussion
