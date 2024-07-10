#![no_std]

#[cfg(feature = "aya")]
use aya::Pod;

use bitflags::bitflags;

pub enum OpenMode {
    Read,
    Write,
    LSeek,
    PRead,
    PWrite,
    Exec,
    WriteRestricted,
    Hash32,
    Hash64,
}

pub enum FileOperation {
    Open,
    Create,
    Delete,
    LinkAt,
    Lookup,
    FollowLink,
}

bitflags! {
    #[derive(PartialEq, Clone, Copy)]
    pub struct Access: u32 {

        // open modes
        const READ              = 0b1;
        const WRITE             = 0b10;
        const LSEEK             = 0b100;
        const PREAD             = 0b1000;
        const PWRITE            = 0b10000;
        const EXEC              = 0b100000;
        const WRITE_RESTRICTED  = 0b1000000;
        const HASH32            = 0b10000000;
        const HASH64            = 0b100000000;

        // File operations
        const OPEN              = 0b1000000000;
        const CREATE            = 0b10000000000;
        const DELETE            = 0b100000000000;
        const LINKAT            = 0b1000000000000;
        const LOOKUP            = 0b10000000000000;
        const FOLLOW_LINK       = 0b100000000000000;
    }
}

pub type NsId = u32;

impl Access {
    pub fn open_mode(&self) -> Option<OpenMode> {
        match self {
            &Self::READ => Some(OpenMode::Read),
            &Self::WRITE => Some(OpenMode::Write),
            &Self::LSEEK => Some(OpenMode::LSeek),
            &Self::PREAD => Some(OpenMode::PRead),
            &Self::PWRITE => Some(OpenMode::PWrite),
            &Self::EXEC => Some(OpenMode::Exec),
            &Self::WRITE_RESTRICTED => Some(OpenMode::WriteRestricted),
            &Self::HASH32 => Some(OpenMode::Hash32),
            &Self::HASH64 => Some(OpenMode::Hash64),
            //ignore others
            _ => None,
        }
    }

    pub fn file_operation(&self) -> Option<FileOperation> {
        match self {
            &Self::OPEN => Some(FileOperation::Open),
            &Self::CREATE => Some(FileOperation::Create),
            &Self::DELETE => Some(FileOperation::Delete),
            &Self::LINKAT => Some(FileOperation::LinkAt),
            &Self::LOOKUP => Some(FileOperation::Lookup),
            &Self::FOLLOW_LINK => Some(FileOperation::FollowLink),
            //ignore others
            _ => None,
        }
    }
}



#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub f_mode: Access,
    pub f_path: [u8; 8188],
}

#[cfg(feature = "aya")]
unsafe impl Pod for Request {}
