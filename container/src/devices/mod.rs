extern crate nix;
extern crate tempdir;

mod device;

use devices::device::Device;
pub use devices::device::DeviceType;

use self::tempdir::TempDir;
use self::nix::mount::{MS_BIND, MS_REC, MS_NOSUID};

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum Error {
    DeviceDirCreation,
    DeviceCreation(device::Error),
    DirectoryCreation(io::Error),
    BindPathInvalid,
    BindMount(nix::Error),
}

impl From<device::Error> for Error {
    fn from(err: device::Error) -> Error {
        Error::DeviceCreation(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::DirectoryCreation(err)
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::BindMount(err)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NodeCreateMethod {
    MakeNode,
    BindMount,
}

pub struct DeviceConfig {
    method: NodeCreateMethod,
    devices: Vec<Device>,
    dev_dir: Option<TempDir>,
}

impl DeviceConfig {
    pub fn new() -> DeviceConfig {
        DeviceConfig {
            method: NodeCreateMethod::BindMount,
            devices: Vec::new(),
            dev_dir: None,
        }
    }

    pub fn add_device(&mut self,
                      dev_type: DeviceType,
                      path: &Path,
                      major: Option<u32>,
                      minor: Option<u32>,
                      file_mode: Option<u32>,
                      uid: Option<u64>,
                      gid: Option<u64>)
                      -> Result<(), Error> {
        self.devices
            .push(Device::new(dev_type, path, major, minor, file_mode, uid, gid)?);
        Ok(())
    }

    // For MakeNode this is where the nodes are created.  For BindMount, this is
    // a nop.
    pub fn pre_fork_setup(&mut self, method: NodeCreateMethod) -> Result<(), Error> {
        self.method = method;
        if method == NodeCreateMethod::BindMount {
            return Ok(());
        }

        let dev_dir = TempDir::new("container_dev")?;

        nix::mount::mount(None::<&Path>,
                          dev_dir.path(),
                          Some(&PathBuf::from("tmpfs")),
                          MS_NOSUID | MS_REC,
                          None::<&Path>)?;

        for d in &self.devices {
            d.mknod(dev_dir.path())?;
        }

        self.dev_dir = Some(dev_dir); // Hold ref to tempdir.

        Ok(())
    }

    // Configure /dev in the new mount namespace.
    // For MkNode, bind mount the directory created in |pre_fork_setup|.
    // For BindMount, bind mount each node in to the dev directory.
    pub fn setup_in_namespace(&self,
                              dev_path: &Path,
                              bind_dir: Option<&Path>)
                              -> Result<(), Error> {
        match self.method {
            NodeCreateMethod::MakeNode => self.setup_in_namespace_mknod(dev_path),
            NodeCreateMethod::BindMount => {
                if let Some(bind_dir) = bind_dir {
                    return self.setup_in_namespace_bind(dev_path, bind_dir);
                } else {
                    return Err(Error::BindPathInvalid);
                }
            }
        }
    }

    fn setup_in_namespace_mknod(&self, dev_path: &Path) -> Result<(), Error> {
        if let Some(ref dev_dir) = self.dev_dir {
            nix::mount::mount(Some(dev_dir.path()),
                              dev_path,
                              None::<&Path>,
                              MS_BIND | MS_REC,
                              None::<&Path>)?;
            Ok(())
        } else {
            Err(Error::DeviceDirCreation)
        }
    }

    fn setup_in_namespace_bind(&self, dev_path: &Path, bind_dir: &Path) -> Result<(), Error> {
        for d in &self.devices {
            d.bind_mount(dev_path, bind_dir)?;
        }

        Ok(())
    }
}

//TODO(dgreid) - Add test for mknod but need to run as root.
#[cfg(test)]
mod test {
    extern crate nix;
    extern crate tempdir;
    use self::nix::sched::*;
    use self::nix::sys::ioctl::libc::pid_t;
    use self::nix::sys::wait;
    use self::tempdir::TempDir;
    use std::fs;
    use std::path::PathBuf;
    use super::{DeviceType, NodeCreateMethod, DeviceConfig};
    use syscall_defines::linux::LinuxSyscall::*;

    fn do_clone() -> Result<pid_t, nix::Error> {
        nix::unistd::setpgid(0, 0)?;

        unsafe {
            let clone_flags = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS;
            let pid = nix::sys::syscall::syscall(SYS_clone as i64,
                                                 clone_flags.bits() |
                                                 nix::sys::signal::SIGCHLD as i32,
                                                 0);
            if pid < 0 {
                Err(nix::Error::Sys(nix::Errno::UnknownErrno))
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    #[test]
    fn bind_mount_one() {
        let mut dc = DeviceConfig::new();
        dc.add_device(DeviceType::Character,
                        &PathBuf::from("/dev/null"),
                        Some(1),
                        Some(13),
                        Some(0o666),
                        Some(0),
                        Some(0))
            .unwrap();
        dc.pre_fork_setup(NodeCreateMethod::BindMount).unwrap();

        let pid = do_clone().unwrap();
        match pid {
            0 => {
                // child
                let new_dev_dir = TempDir::new("device_test").unwrap();
                dc.setup_in_namespace(&PathBuf::from("/dev"), Some(new_dev_dir.path()))
                    .unwrap();
                assert!(fs::metadata(new_dev_dir.path().join("null")).is_ok());
            }
            _ => {
                //parent
                assert!(wait::waitpid(pid, Some(wait::__WALL)).is_ok());
            }
        }

    }
}
