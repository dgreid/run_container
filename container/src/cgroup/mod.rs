extern crate libc;
extern crate nix;

pub mod cgroup_configuration;
mod cgroup_directory;

use cgroup::cgroup_configuration::CGroupConfiguration;
use cgroup::cgroup_directory::CGroupDirectory;

use self::libc::{pid_t, uid_t};
use std;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    CreatingCGroupDirectory(cgroup_directory::Error),
    ChownCGroup(cgroup_directory::Error),
    CGroupDirectoryFailed(cgroup_directory::Error),
    CGroupConfigurationFailed(cgroup_configuration::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

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
        let dir = CGroupDirectory::new(base_path, parent, name, configuration.cgroup_type())
            .map_err(Error::CreatingCGroupDirectory)?;
        // TODO allow different gid
        dir.chown(uid, uid).map_err(Error::ChownCGroup)?;
        Ok(CGroup {
               dir: dir,
               configuration: configuration,
           })
    }

    pub fn configure(&self) -> Result<()> {
        self.configuration.configure(&self.dir)
            .map_err(Error::CGroupConfigurationFailed)?;
        Ok(())
    }

    pub fn add_pid(&self, pid: pid_t) -> Result<()> {
        self.dir.add_pid(pid)
            .map_err(Error::CGroupDirectoryFailed)?;
        Ok(())
    }
}
