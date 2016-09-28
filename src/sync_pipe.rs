extern crate nix;

use self::nix::unistd::{ pipe, read, write, close };
use std::os::unix::io::RawFd;

pub struct SyncPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl SyncPipe {
    pub fn new() -> Result<SyncPipe, nix::Error> {
        pipe().map(| fds | {
            SyncPipe { read_fd: fds.0, write_fd: fds.1 }
        })
    }

    pub fn wait(&self) -> Result<(), nix::Error> {
        let mut buf = [0u8; 1];
        loop {
            match read(self.read_fd, &mut buf) {
                Ok(0) => continue,
                Ok(_) => return Ok(()),
                Err(nix::Error::Sys(nix::Errno::EINTR)) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn signal(&self) -> Result<(), nix::Error> {
        let mut buf = [1u8; 1];
        write(self.write_fd, &mut buf).map(|_| ())
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
