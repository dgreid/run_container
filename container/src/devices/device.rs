extern crate libc;
extern crate nix;

use self::nix::mount::{MS_BIND, MS_REC};
use self::nix::sys::stat::{Mode, SFlag};
use std::io;
use std::ffi::{CString, NulError};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{StripPrefixError, Path, PathBuf};

#[derive(Debug)]
pub enum Error {
    BindMountingDevice(nix::Error),
    Chmod(i32),
    Chown(i32),
    CreateDeviceDirectory(io::Error),
    CreateTargetBindPath(io::Error),
    InvalidPath(NulError),
    MknodFailed(nix::Error),
    NoMajor,
    NoMinor,
    PathNullError(NulError),
    DevicePath(StripPrefixError),
    InvalidDevicePath,
}

pub enum DeviceType {
    Character,
    Block,
}

pub struct Device {
    dev_type: DeviceType,
    path: PathBuf,
    major: Option<u32>,
    minor: Option<u32>,
    file_mode: Option<u32>,
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
}

impl Device {
    pub fn new(dev_type: DeviceType,
               path: &Path,
               major: Option<u32>,
               minor: Option<u32>,
               file_mode: Option<u32>,
               uid: Option<u64>,
               gid: Option<u64>)
               -> Result<Device, Error> {
        let relative_path = PathBuf::from(path.strip_prefix("/dev/")
            .map_err(Error::DevicePath)?);

        Ok(Device {
               dev_type: dev_type,
               path: relative_path,
               major: major,
               minor: minor,
               file_mode: file_mode,
               uid: uid.map(|u| u as libc::uid_t),
               gid: gid.map(|g| g as libc::gid_t),
           })
    }

    pub fn mknod(&self, dev_dir: &Path) -> Result<(), Error> {
        let dev_path = dev_dir.join(&self.path);

        if self.major.is_none() {
            return Err(Error::NoMajor);
        }
        if self.minor.is_none() {
            return Err(Error::NoMinor);
        }

        let parent_dir = dev_path.parent().ok_or(Error::InvalidDevicePath)?;
        fs::create_dir_all(parent_dir).map_err(Error::CreateDeviceDirectory)?;

        nix::sys::stat::mknod(&dev_path,
                              Device::flag_from_type(&self.dev_type),
                              Mode::from_bits(self.file_mode.unwrap_or(0))
                                  .unwrap_or_else(Mode::empty),
                              nix::sys::stat::makedev(self.major.unwrap() as u64,
                                                      self.minor.unwrap() as u64))
            .map_err(Error::MknodFailed)?;
        let cpath = CString::new(dev_path.as_os_str().as_bytes())
            .map_err(Error::InvalidPath)?;
        unsafe {
            // chown and chmod only read the path from memory.
            if libc::chmod(cpath.as_ptr(), self.file_mode.unwrap_or(0)) < 0 {
                return Err(Error::Chmod(*libc::__errno_location()));
            }
            if libc::chown(cpath.as_ptr() as *const i8,
                           self.uid.unwrap_or(-1i32 as libc::uid_t),
                           self.gid.unwrap_or(-1i32 as libc::gid_t)) < 0 {
                return Err(Error::Chown(*libc::__errno_location()));
            }
        }
        Ok(())
    }

    fn flag_from_type(dev_type: &DeviceType) -> SFlag {
        SFlag::from_bits(match *dev_type {
                             DeviceType::Character => nix::libc::S_IFCHR,
                             DeviceType::Block => nix::libc::S_IFBLK,
                         })
                .unwrap()
    }

    pub fn bind_mount(&self, dev_dir: &Path, bind_dir: &Path) -> Result<(), Error> {
        let node_path = dev_dir.join(&self.path);
        fs::create_dir_all(node_path.parent().unwrap())
            .map_err(Error::CreateTargetBindPath)?;
        let orig_path = bind_dir.join(&self.path);
        nix::mount::mount(Some(&orig_path),
                          &node_path,
                          None::<&Path>,
                          MS_BIND | MS_REC,
                          None::<&Path>)
            .map_err(Error::BindMountingDevice)?;
        Ok(())
    }
}
