extern crate libc;
extern crate nix;
extern crate tempdir;

mod device;

use devices::device::Device;
pub use devices::device::DeviceType;

use self::tempdir::TempDir;
use libc::{MS_BIND, MS_NOSUID, MS_REC};

use std::ffi::CString;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    BindPathInvalid,
    BindMount(nix::Error),
    BindMountingDevice(device::Error),
    CreateTmpFs(io::Error),
    DeviceCreation(device::Error),
    DeviceDirCreation,
    InvalidDevPath,
    MountTmpFs(nix::Error),
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

    pub fn add_device(
        &mut self,
        dev_type: DeviceType,
        path: &Path,
        major: Option<u32>,
        minor: Option<u32>,
        file_mode: Option<u32>,
        uid: Option<u64>,
        gid: Option<u64>,
    ) -> Result<(), Error> {
        self.devices.push(
            Device::new(dev_type, path, major, minor, file_mode, uid, gid)
                .map_err(Error::DeviceCreation)?,
        );
        Ok(())
    }

    // For MakeNode this is where the nodes are created.  For BindMount, this is
    // a nop.
    pub fn pre_fork_setup(&mut self, method: NodeCreateMethod) -> Result<(), Error> {
        self.method = method;
        if method == NodeCreateMethod::BindMount {
            return Ok(());
        }

        let dev_dir = TempDir::new("container_dev").map_err(Error::CreateTmpFs)?;

        // unwrap can't fail as the tempdir path is guaranteed to be a valid string.
        let dev_dir_c = CString::new(dev_dir.path().to_string_lossy().to_string()).unwrap();
        let tmpfs_c = CString::new("tmpfs").unwrap();
        unsafe {
            libc::mount(
                std::ptr::null_mut(),
                dev_dir_c.as_ptr(),
                tmpfs_c.as_ptr(),
                MS_NOSUID | MS_REC,
                std::ptr::null_mut(),
            ); // TODO - check error
        }

        for d in &self.devices {
            d.mknod(dev_dir.path()).map_err(Error::DeviceCreation)?;
        }

        self.dev_dir = Some(dev_dir); // Hold ref to tempdir.

        Ok(())
    }

    // Configure /dev in the new mount namespace.
    // For MkNode, bind mount the directory created in |pre_fork_setup|.
    // For BindMount, bind mount each node in to the dev directory.
    pub fn setup_in_namespace(
        &self,
        dev_path: &Path,
        bind_dir: Option<&Path>,
    ) -> Result<(), Error> {
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
        let dev_path_c = CString::new(dev_path.to_string_lossy().to_string())
            .map_err(|_| Error::InvalidDevPath)?;
        if let Some(ref dev_dir) = self.dev_dir {
            let dev_dir_c = CString::new(dev_dir.path().to_string_lossy().to_string()).unwrap();
            unsafe {
                libc::mount(
                    dev_dir_c.as_ptr(),
                    dev_path_c.as_ptr(),
                    std::ptr::null_mut(),
                    MS_BIND | MS_REC,
                    std::ptr::null_mut(),
                ); // TODO - handle error
            }
            Ok(())
        } else {
            Err(Error::DeviceDirCreation)
        }
    }

    fn setup_in_namespace_bind(&self, dev_path: &Path, bind_dir: &Path) -> Result<(), Error> {
        for d in &self.devices {
            d.bind_mount(dev_path, bind_dir)
                .map_err(Error::BindMountingDevice)?;
        }

        Ok(())
    }
}

//TODO(dgreid) - Add test for mknod but need to run as root.
#[cfg(test)]
mod test {
    extern crate libc;
    extern crate nix;
    extern crate tempdir;
    use self::libc::pid_t;
    use self::tempdir::TempDir;
    use super::*;
    use libc::{SYS_clone, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS};
    use std::fs;
    use std::path::PathBuf;

    fn do_clone() -> Result<pid_t, libc::c_long> {
        unsafe {
            if libc::setpgid(0, 0) < 0 {
                return Err(-1);
            }
        }

        unsafe {
            let clone_flags = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS;
            let pid = libc::syscall(
                SYS_clone as i64,
                clone_flags | nix::sys::signal::SIGCHLD as i32,
                0,
            );
            if pid < 0 {
                Err(-1)
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    #[test]
    fn bind_mount_one() {
        let mut dc = DeviceConfig::new();
        dc.add_device(
            DeviceType::Character,
            &PathBuf::from("/dev/null"),
            Some(1),
            Some(13),
            Some(0o666),
            Some(0),
            Some(0),
        )
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
                let mut status: libc::c_int = 0;
                unsafe {
                    assert!(libc::waitpid(pid, &mut status as *mut _, 0) > 0);
                }
            }
        }
    }
}
