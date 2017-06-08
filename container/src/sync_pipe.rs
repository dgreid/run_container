extern crate libc;
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
                Ok(0) |
                Err(nix::Error::Sys(nix::Errno::EINTR)) => continue,
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

impl Clone for SyncPipe {
    fn clone(&self) -> SyncPipe {
        unsafe {
            // Calling dup is OK, it only creates a new fd and that fd's lifetime is
            // managed by the SyncPipe created here.
            SyncPipe {
                read_fd: libc::dup(self.read_fd),
                write_fd: libc::dup(self.write_fd),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::SyncPipe;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn basic_sync() {
        let s = SyncPipe::new().unwrap();
        assert!(s.signal().is_ok());
        assert!(s.wait().is_ok());
    }

    #[test]
    fn multi_sync() {
        let one = SyncPipe::new().unwrap();
        let two = SyncPipe::new().unwrap();
        let count = Arc::new(AtomicUsize::new(0));

        let their_one = one.clone();
        let their_two = two.clone();
        let their_count = count.clone();
        thread::spawn(move || {
            their_one.wait().unwrap();
            let c = their_count.fetch_add(1, Ordering::SeqCst);
            assert_eq!(0, c);
            their_two.signal().unwrap();
            their_one.wait().unwrap();
            let c = their_count.fetch_add(1, Ordering::SeqCst);
            assert_eq!(2, c);
        });

        assert_eq!(count.load(Ordering::SeqCst), 0);
        one.signal().unwrap();
        two.wait().unwrap();
        let c = count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(1, c);
        one.signal().unwrap();
    }
}
