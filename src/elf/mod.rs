//! NØNOS ELF Loader Subsystem 

pub mod types;
pub mod errors;
pub mod aslr;
pub mod reloc;
pub mod loader;
pub mod tls;
pub mod dynlink;
pub mod interpreter;
pub mod minimal;

// Public API exports for kernel integration
pub use loader::{
    ElfLoader, ElfImage, LoadedSegment, DynamicInfo, init_elf_loader, get_elf_loader, load_elf_executable
};
pub use types::{ElfHeader, ProgramHeader, SectionHeader, Symbol, RelaEntry};
pub use aslr::AslrManager;
pub use errors::ElfError;
pub use tls::TlsInfo;
pub use dynlink::DynLinkInfo;
pub use interpreter::InterpreterInfo;
