extern crate nix;

use self::nix::sched::*;

#[derive(Debug)]
pub enum Error {
    EnterCGroupNamespace(nix::Error),
}

pub struct CGroupNamespace {}

impl CGroupNamespace {
    pub fn new() -> CGroupNamespace {
        CGroupNamespace {}
    }

    pub fn enter(&self) -> Result<(), Error> {
        // Now that the process is in each cgroup, enter a new cgroup namespace.
        nix::sched::unshare(CLONE_NEWCGROUP)
            .map_err(Error::EnterCGroupNamespace)?;
        Ok(())
    }
}
