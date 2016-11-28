extern crate nix;

use syscall_defines::linux::LinuxSyscall::*;

use self::nix::fcntl::*;
use std::path::Path;

pub struct OpenDir {
    fd: i32,
}

impl OpenDir {
    pub fn new(path: &Path) -> Result<OpenDir, nix::Error> {
        let d = OpenDir {
            fd: try!(nix::fcntl::open(path,
                                      O_DIRECTORY | O_RDONLY | O_CLOEXEC,
                                      nix::sys::stat::Mode::empty())),
        };
        Ok(d)
    }

    pub fn chdir(&self) -> Result<(), nix::Error> {
        unsafe {
            if nix::sys::syscall::syscall(SYS_fchdir as i64, self.fd) < 0 {
                Err(nix::Error::Sys(nix::Errno::UnknownErrno))
            } else {
                Ok(())
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
