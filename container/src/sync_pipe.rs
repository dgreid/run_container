extern crate libc;

use std;
use std::os::unix::io::RawFd;

#[derive(Debug)]
pub enum Error {
    PipeCreation(i32),
    ReadingPipe(i32),
    WritingPipe(i32),
}
pub type Result<T> = std::result::Result<T, Error>;

pub struct SyncPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl SyncPipe {
    pub fn new() -> Result<SyncPipe> {
        let fds = unsafe {
            // Safe because pipe will fill the fds on success.
            let mut fds: [libc::c_int; 2] = std::mem::uninitialized();
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return Err(Error::PipeCreation(*libc::__errno_location()));
            }
            fds
        };

        Ok(SyncPipe {
               read_fd: fds[0],
               write_fd: fds[1],
           })
    }

    pub fn wait(&self) -> Result<()> {
        let mut buf = [0u8; 1];
        loop {
            let rc = unsafe {
                // Reading is safe as we will read at most one byte which fits in buf.
                libc::read(self.read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1)
            };
            match rc {
                0 => continue,
                1 => return Ok(()),
                _ => {
                    // Reading errno is safe as it will have been set by read above.
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(Error::ReadingPipe(errno as i32));
                }
            }
        }
    }

    pub fn signal(&self) -> Result<()> {
        let buf = [1u8; 1];
        loop {
            let rc = unsafe {
                // Writing is safe, it only reads one byte from the pointer.
                libc::write(self.write_fd, buf.as_ptr() as *mut libc::c_void, 1)
            };
            match rc {
                0 => continue,
                1 => return Ok(()),
                _ => {
                    // Reading errno is safe as it will have been set by write above.
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(Error::WritingPipe(errno as i32));
                }
            }
        }
    }
}

impl Drop for SyncPipe {
    fn drop(&mut self) {
        unsafe {
            // Calling close is safe because we know all reference to this object
            // have been dropped.
            match libc::close(self.read_fd) {
                _ => (),
            }
            match libc::close(self.write_fd) {
                _ => (),
            }
        }
    }
}

impl Clone for SyncPipe {
    fn clone(&self) -> SyncPipe {
        unsafe {
            // Calling dup is OK, it creates a new fd and that fd's lifetime is
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
