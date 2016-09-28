extern crate nix;

mod open_dir;

use self::nix::mount::*;
use self::open_dir::OpenDir;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug)]
pub enum MountError {
    Io(io::Error),
    Nix(nix::Error),
    InvalidTargetPath,
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

struct ContainerMount<'a> {
    source: Option<&'a Path>,
    target: &'a Path,
    fstype: Option<&'a str>,
    flags: MsFlags,
    options: &'a Vec<&'a str>,
}

pub struct MountNamespace<'a> {
    root: &'a Path,
    mounts: Vec<ContainerMount<'a>>,
}

impl<'a> MountNamespace<'a> {
    pub fn new(root: &'a Path) -> Self {
        MountNamespace { root: root, mounts: Vec::new(), }
    }

    // target path must be relative, no leading '/'.
    pub fn add_mount(&mut self, source: Option<&'a Path>, target: &'a Path,
                    fstype: Option<&'a str>, flags: MsFlags,
                    options: &'a Vec<&'a str>) -> Result<(), MountError> {
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

    pub fn enter(&self) -> Result<(), MountError> {
        if !self.root.exists() {
            return Err(MountError::Nix(nix::Error::InvalidPath));
        }

        try!(nix::sched::unshare(nix::sched::CLONE_NEWNS));
        try!(self.remount_private());

        for m in self.mounts.iter() {
            let mut target = PathBuf::from(self.root);
            target.push(m.target);
            if !target.exists() {
                try!(fs::create_dir(target.as_path()));
            }
            try!(nix::mount::mount(m.source, target.as_path(), m.fstype,
                                   m.flags,
                                   Some(&m.options.join(",")[..])));
        }

        try!(self.enter_pivot_root());

        Ok(())
    }

    // Enter the pivot root root fs for the jailed app
    fn enter_pivot_root(&self) -> nix::Result<()> {
        // Keep both old and new root open to fchdir into later.
        let old_root = try!(OpenDir::new(Path::new("/")));
        let new_root = try!(OpenDir::new(self.root));

	// To ensure j->chrootdir is the root of a filesystem,
	// do a self bind mount.
        try!(nix::mount::mount(Some(self.root), self.root, None::<&Path>,
                   MS_BIND | MS_REC, None::<&Path>));
        try!(nix::unistd::chdir(self.root));
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
        nix::mount::mount(None::<&Path>, "/", None::<&Path>,
                          MS_REC | MS_PRIVATE, None::<&Path>)
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
                Err(nix::Error::Sys(nix::Errno::EINTR)) => (), // Try again.
                Err(_) => break,
            }
        }
    }

    #[test]
    fn invalid_target() {
        let root_dir = TempDir::new("two_mount_test").unwrap();
        let root_path = root_dir.path();
	let tmp_dir = TempDir::new("/tmp/one").unwrap();
	let source = tmp_dir.path();

        let target = PathBuf::from("/one"); // Invalid absolute path
        let fstype = None;
        let options = Vec::new();

        let mut m = MountNamespace::new(root_path);
        assert_eq!(m.add_mount(Some(&source), &target, fstype, MS_BIND, &options).is_ok(), false);
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

        let pid = clone(Box::new(move || {
                let target = PathBuf::from("one");
                let fstype = None;
                let options = Vec::new();

                let target2 = PathBuf::from("two");
                let fstype2 = Some("tmpfs");
                let options2 = Vec::new();

                let mut m = MountNamespace::new(root_path);
                m.add_mount(Some(&source), &target, fstype, MS_BIND, &options).unwrap();
                m.add_mount(None, &target2, fstype2, MS_REC, &options2).unwrap();
                assert_eq!(m.enter().is_ok(), true);
                assert!(PathBuf::from("/one").exists());
                assert!(PathBuf::from("/two").exists());
                0
            }), &mut stack, CLONE_NEWUSER, None).unwrap();
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
                let fstype = Some("tmpfs");
                let options = vec![ "size=16k" ];

                let mut m = MountNamespace::new(root_path);
                m.add_mount(Some(&source), &target, fstype, MS_REC, &options).unwrap();
                assert_eq!(m.enter().is_ok(), true);
                assert!(PathBuf::from("/tmpfs").exists());
                0
            }), &mut stack, CLONE_NEWUSER, None).unwrap();
        wait_child_exit(pid);
    }
}