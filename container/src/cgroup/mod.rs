extern crate nix;

pub mod cgroup_configuration;
mod cgroup_directory;

use cgroup::cgroup_configuration::CGroupConfiguration;
use cgroup::cgroup_directory::CGroupDirectory;

use self::nix::libc::{pid_t, uid_t};
use std;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    CGroupDirectoryFailed(cgroup_directory::Error),
    CGroupConfigurationFailed(cgroup_configuration::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<cgroup_configuration::Error> for Error {
    fn from(err: cgroup_configuration::Error) -> Error {
        Error::CGroupConfigurationFailed(err)
    }
}

impl From<cgroup_directory::Error> for Error {
    fn from(err: cgroup_directory::Error) -> Error {
        Error::CGroupDirectoryFailed(err)
    }
}

pub struct CGroup {
    dir: CGroupDirectory,
    configuration: Box<CGroupConfiguration>,
}

impl CGroup {
    pub fn new(name: &str,
               parent: &str,
               base_path: &Path,
               configuration: Box<CGroupConfiguration>,
               uid: Option<uid_t>)
               -> Result<CGroup> {
        let dir = CGroupDirectory::new(base_path, parent, name, configuration.cgroup_type())?;
        dir.chown(uid, uid)?; // TODO allow different gid
        Ok(CGroup {
               dir: dir,
               configuration: configuration,
           })
    }

    pub fn configure(&self) -> Result<()> {
        self.configuration.configure(&self.dir)?;
        Ok(())
    }

    pub fn add_pid(&self, pid: pid_t) -> Result<()> {
        self.dir.add_pid(pid)?;
        Ok(())
    }
}
