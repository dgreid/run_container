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
    NoMajor,
    NoMinor,
    MknodFailed(nix::Error),
    DevDirectory(io::Error),
    PathNullError(NulError),
    DevicePath(StripPrefixError),
    InvalidDevicePath,
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::MknodFailed(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::DevDirectory(err)
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Error {
        Error::PathNullError(err)
    }
}

impl From<StripPrefixError> for Error {
    fn from(err: StripPrefixError) -> Error {
        Error::DevicePath(err)
    }
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
        let relative_path = PathBuf::from(path.strip_prefix("/dev/")?);

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
        fs::create_dir_all(parent_dir)?;

        nix::sys::stat::mknod(&dev_path,
                              Device::flag_from_type(&self.dev_type),
                              Mode::from_bits(self.file_mode.unwrap_or(0))
                                  .unwrap_or_else(Mode::empty),
                              nix::sys::stat::makedev(self.major.unwrap() as u64,
                                                      self.minor.unwrap() as u64))?;
        let cpath = CString::new(dev_path.as_os_str().as_bytes());
        cpath.map(|cstr| unsafe {
                     nix::sys::ioctl::libc::chmod(cstr.as_ptr(), self.file_mode.unwrap_or(0));
                 })?;
        nix::unistd::chown(&dev_path, self.uid, self.gid)?;
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
        fs::create_dir_all(node_path.parent().unwrap())?;
        let orig_path = bind_dir.join(&self.path);
        nix::mount::mount(Some(&orig_path),
                          &node_path,
                          None::<&Path>,
                          MS_BIND | MS_REC,
                          None::<&Path>)?;
        Ok(())
    }
}
