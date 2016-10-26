extern crate nix;

use cgroup_namespace::{self, CGroupNamespace};
use mount_namespace::*;
use net_namespace;
use net_namespace::NetNamespace;
use sync_pipe::*;
use user_namespace::UserNamespace;

use self::nix::sys::ioctl::libc::pid_t;
use self::nix::sched::*;
use self::nix::sys::wait;
use self::nix::sys::wait::WaitStatus;
use std::ffi::CString;
use std::fs;
use std::io;
use std::io::Write;

pub struct Container {
    name: String,
    argv: Vec<CString>,
    cgroup_namespace: Option<CGroupNamespace>,
    mount_namespace: MountNamespace,
    user_namespace: UserNamespace,
    net_namespace: Box<NetNamespace>,
    pid: pid_t,
}

#[derive(Debug)]
pub enum ContainerError {
    Io(io::Error),
    Nix(nix::Error),
    WaitPidFailed,
    InvalidMountTarget,
    NetworkNamespaceConfigError,
    CGroupCreateError,
}

impl From<nix::Error> for ContainerError {
    fn from(err: nix::Error) -> ContainerError {
        ContainerError::Nix(err)
    }
}

impl From<io::Error> for ContainerError {
    fn from(err: io::Error) -> ContainerError {
        ContainerError::Io(err)
    }
}

impl From<MountError> for ContainerError {
    fn from(err: MountError) -> ContainerError {
        match err {
            MountError::Io(e) => ContainerError::Io(e),
            MountError::Nix(e) => ContainerError::Nix(e),
            MountError::InvalidTargetPath => ContainerError::InvalidMountTarget,
        }
    }
}

impl From<net_namespace::Error> for ContainerError {
    fn from(err: net_namespace::Error) -> ContainerError {
        match err {
            net_namespace::Error::NetNamespaceDeviceSetupFailed =>
                    ContainerError::NetworkNamespaceConfigError,
            net_namespace::Error::Io(_) =>
                    ContainerError::NetworkNamespaceConfigError,
        }
    }
}

impl From<cgroup_namespace::Error> for ContainerError {
    fn from(err: cgroup_namespace::Error) -> ContainerError {
        match err {
            cgroup_namespace::Error::CGroupCreateError => ContainerError::CGroupCreateError,
            cgroup_namespace::Error::Io(e) => ContainerError::Io(e),
            cgroup_namespace::Error::Nix(e) => ContainerError::Nix(e),
        }
    }
}

impl Container {
    pub fn new(name: &str, argv: Vec<CString>,
               cgroup_namespace: Option<CGroupNamespace>,
               mount_namespace: MountNamespace,
	       net_namespace: Box<NetNamespace>,
               user_namespace: UserNamespace) -> Self {
        Container {
            name: name.to_string(),
            argv: argv,
            cgroup_namespace: cgroup_namespace,
            mount_namespace: mount_namespace,
            net_namespace: net_namespace,
            user_namespace: user_namespace,
            pid: 0,
        }
    }

    pub fn set_cgroup_namespace(&mut self, cgroup_namespace: Option<CGroupNamespace>) {
      self.cgroup_namespace = cgroup_namespace;
    }

    pub fn set_net_namespace(&mut self, net_namespace: Box<NetNamespace>) {
      self.net_namespace = net_namespace;
    }

    pub fn set_user_namespace(&mut self, user_namespace: UserNamespace) {
      self.user_namespace = user_namespace;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn enter_jail(&self) -> Result<(), ContainerError> {
        try!(nix::unistd::setresuid(0, 0, 0));
        try!(nix::unistd::setresgid(0, 0, 0));
        try!(self.net_namespace.configure_in_child());
        if let Some(ref cgroup_namespace) = self.cgroup_namespace {
          try!(cgroup_namespace.enter());
        }
        try!(self.mount_namespace.enter());
        Ok(())
    }

    fn do_clone() -> Result<pid_t, nix::Error> {
        nix::unistd::setpgid(0, 0);

        unsafe {
            // TODO(dgreid) - hard coded x86_64 syscall value for clone
	    let clone_flags  = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC
                               | CLONE_NEWUTS | CLONE_NEWNET;
	    let pid = nix::sys::syscall::syscall(
                    56, clone_flags.bits() | nix::sys::signal::SIGCHLD as i32, 0);
	    if pid < 0 {
                Err(nix::Error::Sys(nix::Errno::UnknownErrno))
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    pub fn parent_setup(&mut self, sync_pipe: SyncPipe) -> Result<(), ContainerError> {
        let mut uid_file = try!(fs::OpenOptions::new().write(true).read(false).create(false)
                                                      .open(format!("/proc/{}/uid_map", self.pid)));
        let mut gid_file = try!(fs::OpenOptions::new().write(true).read(false).create(false)
                                                      .open(format!("/proc/{}/gid_map", self.pid)));
        try!(uid_file.write_all(self.user_namespace.uid_config_string().as_bytes()));
        try!(gid_file.write_all(self.user_namespace.gid_config_string().as_bytes()));
        drop(uid_file);
        drop(gid_file); // ick, but dropping the file causes a flush.

        try!(self.net_namespace.configure_for_pid(self.pid));
        if let Some(ref mut cgroup_namespace) = self.cgroup_namespace {
          try!(cgroup_namespace.join_cgroups(self.pid));
        }

        try!(sync_pipe.signal());
        Ok(())
    }

    // The client should panic on all failures
    pub fn run_child(&self, sync_pipe: SyncPipe) {
        sync_pipe.wait().unwrap();
        self.enter_jail().unwrap();
        nix::unistd::execv(&self.argv[0], &self.argv).unwrap();
        panic!("Failed to execute program");
    }

    pub fn start(&mut self) -> Result<(), ContainerError> {
        let sync_pipe = try!(SyncPipe::new());

        let pid = try!(Container::do_clone());
        match pid {
            0 => { // child
                self.run_child(sync_pipe);
            },
            _ => { // parent
                self.pid = pid;
                try!(self.parent_setup(sync_pipe));
            },
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Result<(), ContainerError> {
        loop {
            match wait::waitpid(self.pid, Some(wait::__WALL)) {
                Ok(WaitStatus::Exited(..)) => { self.pid = -1; return Ok(()); },
                Ok(WaitStatus::Signaled(..)) => { self.pid = -1; return Ok(()); },
                Ok(WaitStatus::Stopped(..)) => (), // Child being traced?  Try again.
                Ok(WaitStatus::Continued(..)) => (),
                Ok(WaitStatus::StillAlive) => (),
                Err(nix::Error::Sys(nix::Errno::EINTR)) => (), // Try again.
                Err(_) => return Err(ContainerError::WaitPidFailed),
            }
        }
    }
}

#[cfg(test)]
mod test {
    extern crate nix;
    extern crate tempdir;

    use super::Container;
    use cgroup_namespace::*;
    use mount_namespace::*;
    use net_namespace::EmptyNetNamespace;
    use std::path::Path;
    use std::path::PathBuf;
    use std::ffi::CString;
    use user_namespace::*;
    use self::nix::unistd::getuid;
    use self::tempdir::TempDir;
    use std::fs;

    fn create_cgroup_type(cg_base: &Path, t: &str) {
        let mut cg_path = PathBuf::from(&cg_base);
        cg_path.push(t);
        fs::create_dir(cg_path.as_path()).unwrap();
        cg_path.push("containers");
        fs::create_dir(cg_path.as_path()).unwrap();
    }

    fn setup_cgroups(temp_dir: &TempDir) -> CGroupNamespace {
        // Cgroup Name
        let temp_path = temp_dir.path();
        create_cgroup_type(&temp_path, "cpu");
        create_cgroup_type(&temp_path, "cpuacct");
        create_cgroup_type(&temp_path, "cpuset");
        create_cgroup_type(&temp_path, "devices");
        create_cgroup_type(&temp_path, "freezer");
        CGroupNamespace::new(temp_path, Path::new("containers"),
                             Path::new("testapp")).unwrap()
    }

    #[test]
    fn start_test() {
        let temp_cgdir = TempDir::new("fake_cg").unwrap();
        let argv = vec![ CString::new("/bin/ls").unwrap(), CString::new("-l").unwrap() ];
        let cgroup_namespace = setup_cgroups(&temp_cgdir);
        let mount_namespace = MountNamespace::new(PathBuf::from("/tmp/foo"));
        let mut user_namespace = UserNamespace::new();
        user_namespace.add_uid_mapping(0, getuid() as usize, 1);
	// TODO(dgreid) - add test with each network namespace
        let mut c = Container::new("asdf", argv, Some(cgroup_namespace), mount_namespace,
                                   Box::new(EmptyNetNamespace::new()), user_namespace);
	assert_eq!("asdf", c.name());
        assert!(c.start().is_ok());
        assert!(c.wait().is_ok());
    }
}
