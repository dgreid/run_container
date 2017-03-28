extern crate nix;

mod open_dir;

use self::nix::mount::*;
use self::open_dir::OpenDir;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug)]
pub enum MountError {
    Io(io::Error),
    Nix(nix::Error),
    InvalidTargetPath,
    PostSetupCallback,
}

impl From<io::Error> for MountError {
    fn from(err: io::Error) -> MountError {
        MountError::Io(err)
    }
}

impl From<nix::Error> for MountError {
    fn from(err: nix::Error) -> MountError {
        MountError::Nix(err)
    }
}

struct ContainerMount {
    source: Option<PathBuf>,
    target: PathBuf,
    fstype: Option<String>,
    flags: MsFlags,
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
    pub fn add_mount(&mut self,
                     source: Option<PathBuf>,
                     target: PathBuf,
                     fstype: Option<String>,
                     flags: MsFlags,
                     options: Vec<String>)
                     -> Result<(), MountError> {
        if target.is_absolute() {
            return Err(MountError::InvalidTargetPath);
        }

        let new_mount = ContainerMount {
            source: source,
            target: target,
            fstype: fstype,
            flags: flags,
            options: options,
        };
        self.mounts.push(new_mount);
        Ok(())
    }

    // post_setup is called after mounts are made but before pivot root
    //  The path to the root fs is passed in to post_setup.
    pub fn enter<F>(&self, post_setup: F) -> Result<(), MountError>
        where F: Fn(&Path) -> Result<(), ()>
    {
        if !self.root.exists() {
            return Err(MountError::Nix(nix::Error::InvalidPath));
        }

        try!(nix::sched::unshare(nix::sched::CLONE_NEWNS));
        try!(self.remount_private());

        if post_setup(&self.root).is_err() {
            return Err(MountError::PostSetupCallback);
        }

        for m in self.mounts.iter() {
            let mut target = self.root.clone();
            target.push(m.target.as_path());
            self.prepare_mount_target(&m.source, &target)?;
            try!(nix::mount::mount(m.source.as_ref(),
                                   target.as_path(),
                                   m.fstype.as_ref().map(|t| &**t),
                                   m.flags,
                                   Some(&m.options.join(",")[..])));
        }

        try!(self.enter_pivot_root());

        Ok(())
    }

    fn prepare_mount_target(&self,
                            source: &Option<PathBuf>,
                            target: &PathBuf)
                            -> Result<(), MountError> {
        if target.exists() {
            return Ok(());
        }
        if let &Some(ref s) = source {
            if s.exists() && !s.is_dir() {
                OpenOptions::new().create(true)
                    .write(true)
                    .open(target.as_path())?;
                return Ok(());
            }
        }
        fs::create_dir(target.as_path())?;
        Ok(())
    }

    // Enter the pivot root root fs for the jailed app
    fn enter_pivot_root(&self) -> nix::Result<()> {
        // Keep both old and new root open to fchdir into later.
        let old_root = try!(OpenDir::new(Path::new("/")));
        let new_root = try!(OpenDir::new(self.root.as_path()));

        // To ensure j->chrootdir is the root of a filesystem,
        // do a self bind mount.
        try!(nix::mount::mount(Some(self.root.as_path()),
                               self.root.as_path(),
                               None::<&Path>,
                               MS_BIND | MS_REC,
                               None::<&Path>));
        try!(nix::unistd::chdir(self.root.as_path()));
        try!(nix::unistd::pivot_root(".", "."));

        // unmount old root
        // Now the old root is mounted on top of the new root. Use fchdir(2) to
        // change to the old root and unmount it.
        try!(old_root.chdir());
        // The old root might be busy, so use lazy unmount.
        try!(nix::mount::umount2(".", MNT_DETACH));

        // Change back to the new root.
        try!(new_root.chdir());

        // Close open directories before setting cwd to /.
        drop(old_root);
        drop(new_root);

        try!(nix::unistd::chroot("/"));
        // Set correct CWD for getcwd(3).
        try!(nix::unistd::chdir("/"));

        Ok(())
    }

    // Remount everything as private so new mounts and unmounts don't propagate
    // to the parent's namespace.
    fn remount_private(&self) -> nix::Result<()> {
        nix::mount::mount(None::<&Path>,
                          "/",
                          None::<&Path>,
                          MS_REC | MS_PRIVATE,
                          None::<&Path>)
    }
}

#[cfg(test)]
mod test {
    extern crate nix;
    extern crate tempdir;
    use self::nix::libc::pid_t;
    use self::nix::mount::*;
    use self::nix::sched::*;
    use self::nix::sys::wait;
    use self::nix::sys::wait::WaitStatus;
    use self::tempdir::TempDir;
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use super::MountNamespace;

    fn wait_child_exit(pid: pid_t) {
        loop {
            match wait::waitpid(pid, Some(wait::__WALL)) {
                Ok(WaitStatus::Exited(..)) => break,
                Ok(WaitStatus::Signaled(..)) => break,
                Ok(WaitStatus::Stopped(..)) => (),
                Ok(WaitStatus::Continued(..)) => (),
                Ok(WaitStatus::StillAlive) => (),
                Ok(WaitStatus::PtraceEvent(..)) => (),
                Err(nix::Error::Sys(nix::Errno::EINTR)) => (), // Try again.
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
        assert_eq!(m.add_mount(Some(source), target, fstype, MS_BIND, options)
                       .is_ok(),
                   false);
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

        let pid = clone(Box::new(move || {
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
            m.add_mount(Some(file_source.clone()),
                           PathBuf::from("/three"),
                           None,
                           MS_BIND | MS_REC,
                           Vec::new())
                .unwrap();
            assert_eq!(m.enter(|_| Ok(())).is_ok(), true);
            assert!(PathBuf::from("/one").is_dir());
            assert!(PathBuf::from("/two").is_dir());
            assert!(PathBuf::from("/three").is_file());
            0
        }),
                        &mut stack,
                        CLONE_NEWUSER,
                        None)
                .unwrap();
        wait_child_exit(pid);
    }

    #[test]
    fn tmpfs_option() {
        // Have to run this test in it's own user ns so it can unshare
        let mut stack = [0; 0x1000];
        let root_dir = TempDir::new("tmpfs_option_test").unwrap();
        let root_path = root_dir.path();

        let pid = clone(Box::new(move || {

            let source = PathBuf::from("tmpfssrc");
            let target = PathBuf::from("tmpfs");
            let fstype = Some("tmpfs".to_string());
            let options = vec!["size=16k".to_owned()];

            let mut m = MountNamespace::new(root_path.to_path_buf());
            m.add_mount(Some(source), target, fstype, MS_REC, options)
                .unwrap();
            assert_eq!(m.enter(|_| Ok(())).is_ok(), true);
            assert!(PathBuf::from("/tmpfs").exists());
            0
        }),
                        &mut stack,
                        CLONE_NEWUSER,
                        None)
                .unwrap();
        wait_child_exit(pid);
    }
}
