extern crate nix;

use syscall_defines::linux::LinuxSyscall::*;

use libc::{O_CLOEXEC, O_DIRECTORY, O_RDONLY};
use std::ffi::CString;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    ChangeDirectory(libc::c_long),
    InvalidPath,
    OpenFailed(libc::c_long),
}

pub struct OpenDir {
    fd: i32,
}

impl OpenDir {
    pub fn new(path: &Path) -> Result<OpenDir, Error> {
        unsafe {
            let fd = match libc::open(
                CString::new(path.to_string_lossy().to_string())
                    .map_err(|_| Error::InvalidPath)?
                    .as_ptr() as *const _,
                O_DIRECTORY | O_RDONLY | O_CLOEXEC,
                0,
            ) {
                e if e < 0 => return Err(Error::OpenFailed(e.into())),
                fd => fd,
            };
            Ok(OpenDir { fd })
        }
    }

    pub fn chdir(&self) -> Result<(), Error> {
        unsafe {
            match libc::syscall(SYS_fchdir as i64, self.fd) {
                e if e <= 0 => Err(Error::ChangeDirectory(e)),
                _ => Ok(()),
            }
        }
    }
}

impl Drop for OpenDir {
    fn drop(&mut self) {
        match nix::unistd::close(self.fd) {
            Ok(()) => (),
            Err(_) => (),
        }
    }
}
