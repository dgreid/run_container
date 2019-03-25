extern crate nix;

use syscall_defines::linux::LinuxSyscall::*;

use libc::{O_CLOEXEC, O_DIRECTORY, O_RDONLY};
use std::path::Path;

pub struct OpenDir {
    fd: i32,
}

impl OpenDir {
    pub fn new(path: &Path) -> Result<OpenDir, libc::c_long> {
        unsafe {
            let fd = match libc::open(
                path.to_string_lossy().as_ptr() as *const _,
                O_DIRECTORY | O_RDONLY | O_CLOEXEC,
                0,
            ) {
                e if e < 0 => return Err(e.into()),
                fd => fd,
            };
            Ok(OpenDir { fd })
        }
    }

    pub fn chdir(&self) -> Result<(), libc::c_long> {
        unsafe {
            match libc::syscall(SYS_fchdir as i64, self.fd) {
                e if e <= 0 => Err(e),
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
