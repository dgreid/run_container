extern crate nix;

mod open_dir;

use self::nix::mount::*;
use self::open_dir::OpenDir;
use std;
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use libc::{MNT_DETACH, MS_BIND, MS_PRIVATE, MS_REC};

#[derive(Debug)]
pub enum Error {
    CreateTarget(io::Error),
    EnterMountNamespace(nix::Error),
    EnterPivotRoot(nix::Error),
    InvalidFsType,
    InvalidMountSource,
    InvalidRootPath,
    InvalidTargetPath,
    MountCommand(libc::c_int, Option<String>, PathBuf),
    PostSetupCallback,
    RemountPrivate(nix::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

struct ContainerMount {
    source: Option<PathBuf>,
    target: PathBuf,
    fstype: Option<CString>,
    flags: libc::c_ulong,
    options: Vec<String>,
}

pub struct MountNamespace {
    root: PathBuf,
    mounts: Vec<ContainerMount>,
}

impl MountNamespace {
    pub fn new(root: PathBuf) -> Self {
        MountNamespace {
            root: root,
            mounts: Vec::new(),
        }
    }

    // target path must be relative, no leading '/'.
    pub fn add_mount(
        &mut self,
        source: Option<PathBuf>,
        target: PathBuf,
        fstype: Option<String>,
        flags: libc::c_ulong, // TODO store in a better type.
        options: Vec<String>,
    ) -> Result<()> {
        if target.is_absolute() {
            return Err(Error::InvalidTargetPath);
        }

        let fstype_c = match fstype {
            Some(f) => Some(CString::new(f).map_err(|_| Error::InvalidFsType)?),
            None => None,
        };
        let new_mount = ContainerMount {
            source,
            target,
            fstype: fstype_c,
            flags,
            options,
        };
        self.mounts.push(new_mount);
        Ok(())
    }

    // post_setup is called after mounts are made but before pivot root
    //  The path to the root fs is passed in to post_setup.
    pub fn enter<F>(&self, post_setup: F) -> Result<()>
    where
        F: Fn(&Path) -> std::result::Result<(), ()>,
    {
        if !self.root.exists() {
            return Err(Error::InvalidRootPath);
        }

        unsafe {
            libc::unshare(libc::CLONE_NEWNS);
        } //TODO - check error
        self.remount_private().map_err(Error::RemountPrivate)?;

        if post_setup(&self.root).is_err() {
            return Err(Error::PostSetupCallback);
        }

        for m in &self.mounts {
            let mut target = self.root.clone();
            target.push(m.target.as_path());
            self.prepare_mount_target(&m.source, &target)?;
            let source = m
                .source
                .as_ref()
                .map(|s| CString::new(s.to_string_lossy().to_string()).unwrap());
            let options = CString::new(m.options.join(",")).unwrap();

            unsafe {
                let ret = libc::mount(
                    source
                        .as_ref()
                        .map(|s| s.as_ptr())
                        .unwrap_or(std::ptr::null_mut() as *const _),
                    CString::new(target.to_string_lossy().to_string())
                        .map_err(|_| Error::InvalidTargetPath)?
                        .as_ptr() as *const _,
                    match m.fstype.as_ref() {
                        Some(s) => s.as_ptr() as *const _,
                        None => std::ptr::null_mut() as *const _,
                    },
                    m.flags as u64,
                    options.as_ptr() as *const _,
                );
                if ret < 0 {
                    return Err(Error::MountCommand(
                        unsafe { *libc::__errno_location() },
                        source.as_ref().map(|s| s.to_string_lossy().to_string()),
                        target,
                    ));
                }
            }
        }

        self.enter_pivot_root().map_err(Error::EnterPivotRoot)?;

        Ok(())
    }

    fn prepare_mount_target(&self, source: &Option<PathBuf>, target: &PathBuf) -> Result<()> {
        if target.exists() {
            return Ok(());
        }
        if let Some(ref s) = *source {
            if s.exists() && !s.is_dir() {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(target.as_path())
                    .map_err(Error::CreateTarget)?;
                return Ok(());
            }
        }
        fs::create_dir(target.as_path()).map_err(Error::CreateTarget)?;
        Ok(())
    }

    // Enter the pivot root root fs for the jailed app
    fn enter_pivot_root(&self) -> nix::Result<()> {
        // Keep both old and new root open to fchdir into later.
        let old_root = OpenDir::new(Path::new("/")).unwrap(); // TODO handle error
        let new_root = OpenDir::new(self.root.as_path()).unwrap(); // TODO handle error

        let c_root = CString::new(self.root.to_string_lossy().to_string()).unwrap();

        // To ensure j->chrootdir is the root of a filesystem,
        // do a self bind mount.
        unsafe {
            libc::mount(
                c_root.as_ptr(),
                c_root.as_ptr(),
                std::ptr::null_mut(),
                MS_BIND | MS_REC,
                std::ptr::null_mut(),
            ); // TODO handle error
        }
        nix::unistd::chdir(self.root.as_path())?;
        nix::unistd::pivot_root(".", ".")?;

        // unmount old root
        // Now the old root is mounted on top of the new root. Use fchdir(2) to
        // change to the old root and unmount it.
        old_root.chdir(); // TODO handle error

        // The old root might be busy, so use lazy unmount.
        unsafe {
            libc::umount2(".".as_ptr() as *const _, MNT_DETACH); //TODO handle error
        }

        // Change back to the new root.
        new_root.chdir(); //TODO handle error

        // Close open directories before setting cwd to /.
        drop(old_root);
        drop(new_root);

        nix::unistd::chroot("/")?;
        // Set correct CWD for getcwd(3).
        nix::unistd::chdir("/")?;

        Ok(())
    }

    // Remount everything as private so new mounts and unmounts don't propagate
    // to the parent's namespace.
    fn remount_private(&self) -> nix::Result<()> {
        unsafe {
            libc::mount(
                std::ptr::null_mut(),
                CString::new("/").unwrap().as_ptr() as *const _,
                std::ptr::null_mut(),
                MS_REC | MS_PRIVATE,
                std::ptr::null_mut(),
            ); //TODO handle error
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    extern crate nix;
    extern crate tempdir;
    use self::nix::sched::*;
    use self::nix::sys::wait;
    use self::nix::sys::wait::WaitStatus;
    use self::tempdir::TempDir;
    use super::*;
    use libc::{CLONE_NEWUSER, MS_BIND, MS_REC};
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    fn wait_child_exit(pid: nix::unistd::Pid) {
        loop {
            match wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL)) {
                Ok(WaitStatus::Exited(..)) => break,
                Ok(WaitStatus::Signaled(..)) => break,
                Ok(WaitStatus::Stopped(..)) => (),
                Ok(WaitStatus::Continued(..)) => (),
                Ok(WaitStatus::StillAlive) => (),
                Ok(WaitStatus::PtraceEvent(..)) => (),
                Ok(WaitStatus::PtraceSyscall(..)) => (),
                Err(_) => break,
            }
        }
    }

    #[test]
    fn invalid_target() {
        let root_dir = TempDir::new("two_mount_test").unwrap();
        let root_path = root_dir.into_path();
        let tmp_dir = TempDir::new("/tmp/one").unwrap();
        let source = tmp_dir.into_path();

        let target = PathBuf::from("/one"); // Invalid absolute path
        let fstype = None;
        let options = Vec::new();

        let mut m = MountNamespace::new(root_path);
        assert_eq!(
            m.add_mount(Some(source), target, fstype, MS_BIND, options)
                .is_ok(),
            false
        );
    }

    #[test]
    fn two_mounts() {
        // Have to run this test in it's own user ns so it can unshare
        let mut stack = [0; 0x1000];
        // Create a tmpfs in the parent, pass its path in to the child, can't
        // pass the TempDir object because moving it causes it to be deleted
        // moving the path is safe and the temp directory will be deleted when
        // it goes out of scope, after the child exits and unmounts everyuthing.
        let root_dir = TempDir::new("two_mount_test").unwrap();
        let root_path = root_dir.path();
        let tmp_dir = TempDir::new("/tmp/one").unwrap();
        let source = tmp_dir.path();
        let tmp_dir2 = TempDir::new("/tmp/filedir").unwrap();
        let mut file_source = PathBuf::from(tmp_dir2.path());
        file_source.push("test_source");
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(file_source.as_path())
            .unwrap();

        let pid = clone(
            Box::new(move || {
                let target = PathBuf::from("one");
                let fstype = None;
                let options = Vec::new();

                let target2 = PathBuf::from("two");
                let fstype2 = Some("tmpfs".to_string());
                let options2 = Vec::new();

                let mut m = MountNamespace::new(root_path.to_path_buf());
                m.add_mount(Some(source.to_path_buf()), target, fstype, MS_BIND, options)
                    .unwrap();
                m.add_mount(None, target2, fstype2, MS_REC, options2)
                    .unwrap();
                m.add_mount(
                    Some(file_source.clone()),
                    PathBuf::from("three"),
                    None,
                    MS_BIND | MS_REC,
                    Vec::new(),
                )
                .unwrap();
                m.enter(|_| Ok(())).unwrap();
                assert!(PathBuf::from("/one").is_dir());
                assert!(PathBuf::from("/two").is_dir());
                assert!(PathBuf::from("/three").is_file());
                0
            }),
            &mut stack,
            nix::sched::CloneFlags::from_bits(CLONE_NEWUSER).unwrap(),
            None,
        )
        .unwrap();
        wait_child_exit(pid);
    }

    #[test]
    fn tmpfs_option() {
        // Have to run this test in it's own user ns so it can unshare
        let mut stack = [0; 0x1000];
        let root_dir = TempDir::new("tmpfs_option_test").unwrap();
        let root_path = root_dir.path();

        let pid = clone(
            Box::new(move || {
                let source = PathBuf::from("tmpfssrc");
                let target = PathBuf::from("tmpfs");
                let fstype = Some("tmpfs".to_string());
                let options = vec!["size=16k".to_owned()];

                let mut m = MountNamespace::new(root_path.to_path_buf());
                m.add_mount(Some(source), target, fstype, MS_REC, options)
                    .unwrap();
                m.enter(|_| Ok(())).unwrap();
                assert!(PathBuf::from("/tmpfs").exists());
                0
            }),
            &mut stack,
            nix::sched::CloneFlags::from_bits(CLONE_NEWUSER).unwrap(),
            None,
        )
        .unwrap();
        wait_child_exit(pid);
    }
}
