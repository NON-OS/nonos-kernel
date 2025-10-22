//! ELF Loader Errors for NØNOS Kernel

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// ELF file does not start with the correct magic number.
    InvalidMagic,
    /// ELF class is not 64-bit.
    InvalidClass,
    /// ELF endianness is not little-endian.
    InvalidEndian,
    /// ELF version is not supported.
    InvalidVersion,
    /// ELF machine type is not x86-64.
    InvalidMachine,
    /// ELF type is not EXEC or DYN.
    InvalidType,
    /// ELF file is too small for expected header or data.
    FileTooSmall,
    /// Program headers exceed file size or are out of bounds.
    ProgramHeadersOutOfBounds,
    /// Segment data exceeds file size.
    SegmentDataOutOfBounds,
    /// Failed to allocate memory for a segment, section, or stack.
    MemoryAllocationFailed,
    /// Relocation processing failed (unsupported or corrupted).
    RelocationFailed,
    /// Interpreter path (PT_INTERP) is missing or invalid.
    InterpreterNotFound,
    /// TLS section is missing or invalid.
    TlsSectionError,
    /// Dynamic section is missing or invalid.
    DynamicSectionError,
    /// Symbol table is missing or invalid.
    SymbolTableError,
    /// String table is missing or invalid.
    StringTableError,
    /// Unknown or unsupported ELF format.
    UnknownFormat,
    /// Any other error (use .into() for details).
    Other(&'static str),
}

impl From<&'static str> for ElfError {
    fn from(s: &'static str) -> Self {
        ElfError::Other(s)
    }
}
