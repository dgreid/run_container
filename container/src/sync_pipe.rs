extern crate nix;

use self::nix::unistd::{pipe, read, write, close};
use std;
use std::os::unix::io::RawFd;

pub type Result<T> = std::result::Result<T, nix::Error>;

pub struct SyncPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl SyncPipe {
    pub fn new() -> Result<SyncPipe> {
        pipe().map(|fds| {
                       SyncPipe {
                           read_fd: fds.0,
                           write_fd: fds.1,
                       }
                   })
    }

    pub fn wait(&self) -> Result<()> {
        let mut buf = [0u8; 1];
        loop {
            match read(self.read_fd, &mut buf) {
                Ok(0) | Err(nix::Error::Sys(nix::Errno::EINTR)) => continue,
                Ok(_) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn signal(&self) -> Result<()> {
        let buf = [1u8; 1];
        write(self.write_fd, &buf).map(|_| ())
    }
}

impl Drop for SyncPipe {
    fn drop(&mut self) {
        match close(self.read_fd) {
            _ => (),
        }
        match close(self.write_fd) {
            _ => (),
        }
    }
}

#[cfg(test)]
mod test {
    use super::SyncPipe;

    #[test]
    fn basic_sync() {
        let s = SyncPipe::new().unwrap();
        assert!(s.signal().is_ok());
        assert!(s.wait().is_ok());
    }
}
