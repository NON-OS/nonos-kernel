extern crate alloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CssError {
    UnexpectedToken,
    UnexpectedEof,
    InvalidSelector,
    InvalidValue,
    InvalidColor,
    UnclosedString,
    UnclosedBlock,
    InvalidMediaQuery,
}

impl CssError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedToken => "unexpected token",
            Self::UnexpectedEof => "unexpected end of input",
            Self::InvalidSelector => "invalid selector",
            Self::InvalidValue => "invalid css value",
            Self::InvalidColor => "invalid color",
            Self::UnclosedString => "unclosed string",
            Self::UnclosedBlock => "unclosed block",
            Self::InvalidMediaQuery => "invalid media query",
        }
    }

    pub fn code(&self) -> u32 {
        match self {
            Self::UnexpectedToken => 0x5001,
            Self::UnexpectedEof => 0x5002,
            Self::InvalidSelector => 0x5003,
            Self::InvalidValue => 0x5004,
            Self::InvalidColor => 0x5005,
            Self::UnclosedString => 0x5006,
            Self::UnclosedBlock => 0x5007,
            Self::InvalidMediaQuery => 0x5008,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        !matches!(self, Self::UnclosedBlock)
    }
}

impl core::fmt::Display for CssError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
