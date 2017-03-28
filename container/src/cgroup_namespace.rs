extern crate nix;

use self::nix::sched::*;

use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Nix(nix::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::Nix(err)
    }
}

pub struct CGroupNamespace {}

impl CGroupNamespace {
    pub fn new() -> CGroupNamespace {
        CGroupNamespace {}
    }

    pub fn enter(&self) -> Result<(), Error> {
        // Now that the process is in each cgroup, enter a new cgroup namespace.
        nix::sched::unshare(CLONE_NEWCGROUP)?;
        Ok(())
    }
}
