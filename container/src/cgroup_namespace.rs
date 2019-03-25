use libc::{syscall, CLONE_NEWCGROUP};

#[derive(Debug)]
pub enum Error {
    EnterCGroupNamespace(libc::c_long),
}

pub struct CGroupNamespace {}

impl CGroupNamespace {
    pub fn new() -> CGroupNamespace {
        CGroupNamespace {}
    }

    pub fn enter(&self) -> Result<(), Error> {
        // Now that the process is in each cgroup, enter a new cgroup namespace.
        unsafe {
            match syscall(CLONE_NEWCGROUP as i64) {
                e if e >= 0 => Err(Error::EnterCGroupNamespace(e)),
                _ => Ok(()),
            }
        }
    }
}
