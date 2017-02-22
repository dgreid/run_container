extern crate nix;

use cgroup::cgroup::{self, CGroup};
use cgroup_namespace::{self, CGroupNamespace};
use mount_namespace::*;
use net_namespace;
use net_namespace::NetNamespace;
use seccomp_jail;
use seccomp_jail::SeccompJail;
use sysctls;
use sysctls::Sysctls;
use sync_pipe::*;
use syscall_defines::linux::LinuxSyscall::*;
use user_namespace::UserNamespace;

use self::nix::sys::ioctl::libc::pid_t;
use self::nix::sched::*;
use self::nix::sys::wait;
use self::nix::sys::wait::WaitStatus;
use std::ffi::CString;
use std::io;

pub struct Container {
    name: String,
    alt_syscall_table: Option<CString>,
    argv: Vec<CString>,
    cgroups: Vec<CGroup>,
    cgroup_namespace: Option<CGroupNamespace>,
    mount_namespace: Option<MountNamespace>,
    user_namespace: Option<UserNamespace>,
    net_namespace: Option<Box<NetNamespace>>,
    seccomp_jail: Option<SeccompJail>,
    sysctls: Option<Sysctls>,
    additional_groups: Vec<u32>,
    privileged: bool,
    pid: pid_t,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Nix(nix::Error),
    WaitPidFailed,
    InvalidMountTarget,
    NetworkNamespaceConfigError,
    CGroupCreateError,
    InvalidCGroup,
    AltSyscallError,
    SetGroupsError,
    SeccompError(seccomp_jail::Error),
    SysctlError(sysctls::Error),
    CGroupFailure(cgroup::Error),
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::Nix(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<MountError> for Error {
    fn from(err: MountError) -> Error {
        match err {
            MountError::Io(e) => Error::Io(e),
            MountError::Nix(e) => Error::Nix(e),
            MountError::InvalidTargetPath => Error::InvalidMountTarget,
        }
    }
}

impl From<net_namespace::Error> for Error {
    fn from(err: net_namespace::Error) -> Error {
        match err {
            net_namespace::Error::NetNamespaceDeviceSetupFailed => {
                Error::NetworkNamespaceConfigError
            }
            net_namespace::Error::Io(_) => Error::NetworkNamespaceConfigError,
        }
    }
}

impl From<cgroup::Error> for Error {
    fn from(err: cgroup::Error) -> Error {
        Error::CGroupFailure(err)
    }
}

impl From<cgroup_namespace::Error> for Error {
    fn from(err: cgroup_namespace::Error) -> Error {
        match err {
            cgroup_namespace::Error::Io(e) => Error::Io(e),
            cgroup_namespace::Error::Nix(e) => Error::Nix(e),
        }
    }
}

impl From<seccomp_jail::Error> for Error {
    fn from(err: seccomp_jail::Error) -> Error {
        Error::SeccompError(err)
    }
}

impl From<sysctls::Error> for Error {
    fn from(err: sysctls::Error) -> Error {
        Error::SysctlError(err)
    }
}

impl Container {
    pub fn new(name: &str,
               argv: Vec<CString>,
               cgroups: Vec<CGroup>,
               cgroup_namespace: Option<CGroupNamespace>,
               mount_namespace: Option<MountNamespace>,
               net_namespace: Option<Box<NetNamespace>>,
               user_namespace: Option<UserNamespace>,
               additional_groups: Vec<u32>,
               seccomp_jail: Option<SeccompJail>,
               sysctls: Option<Sysctls>,
               privileged: bool)
               -> Self {
        Container {
            name: name.to_string(),
            alt_syscall_table: None,
            argv: argv,
            cgroups: cgroups,
            cgroup_namespace: cgroup_namespace,
            mount_namespace: mount_namespace,
            net_namespace: net_namespace,
            user_namespace: user_namespace,
            additional_groups: additional_groups,
            seccomp_jail: seccomp_jail,
            sysctls: sysctls,
            privileged: privileged,
            pid: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn enter_alt_syscall_table(&self) -> Result<(), Error> {
        self.alt_syscall_table.as_ref().map_or(Ok(()), |t| {
            unsafe {
                match nix::sys::syscall::syscall(SYS_prctl as i64,
                                                 0x43724f53, // PR_ALT_SYSCALL
                                                 1,
                                                 t.as_ptr()) {
                    0 => Ok(()),
                    _ => Err(Error::AltSyscallError),
                }
            }
        })
    }

    fn set_additional_gids(&self) -> Result<(), Error> {
        if self.additional_groups.is_empty() {
            return Ok(());
        }

        unsafe {
            match nix::sys::ioctl::libc::setgroups(self.additional_groups.len(),
                                                   self.additional_groups.as_ptr()) {
                0 => Ok(()),
                _ => Err(Error::SetGroupsError),
            }
        }
    }

    fn enter_jail(&self) -> Result<(), Error> {
        nix::unistd::setresuid(0, 0, 0)?;
        nix::unistd::setresgid(0, 0, 0)?;
        self.set_additional_gids()?;
        self.net_namespace.as_ref().map_or(Ok(()), |n| n.configure_in_child())?;
        self.cgroup_namespace.as_ref().map_or(Ok(()), |c| c.enter())?;
        self.mount_namespace.as_ref().map_or(Ok(()), |m| m.enter())?;
        self.sysctls.as_ref().map_or(Ok(()), |s| s.configure())?;
        nix::unistd::sethostname(&self.name)?;
        self.enter_alt_syscall_table()?;
        self.seccomp_jail.as_ref().map_or(Ok(()), |s| s.enter())?;
        Ok(())
    }

    fn clone_flags(&self) -> nix::sched::CloneFlags {
        let base_flags = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS;
        if self.net_namespace.is_some() {
            base_flags | CLONE_NEWNET
        } else {
            base_flags
        }
    }

    fn do_clone(&self) -> Result<pid_t, nix::Error> {
        nix::unistd::setpgid(0, 0)?;

        unsafe {
            let pid = nix::sys::syscall::syscall(SYS_clone as i64,
                                                 self.clone_flags().bits() |
                                                 nix::sys::signal::SIGCHLD as i32,
                                                 0);
            if pid < 0 {
                Err(nix::Error::Sys(nix::Errno::UnknownErrno))
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    pub fn parent_setup(&mut self, sync_pipe: SyncPipe) -> Result<(), Error> {
        self.user_namespace.as_ref().map_or(Ok(()), |u| u.configure(self.pid, !self.privileged))?;
        self.net_namespace.as_ref().map_or(Ok(()), |n| n.configure_for_pid(self.pid))?;

        for cgroup in &self.cgroups {
            cgroup.configure()?;
            cgroup.add_pid(self.pid)?;
        }

        sync_pipe.signal()?;
        Ok(())
    }

    // The client should panic on all failures
    pub fn run_child(&self, sync_pipe: SyncPipe) {
        sync_pipe.wait().unwrap();
        self.enter_jail().unwrap();
        nix::unistd::execv(&self.argv[0], &self.argv).unwrap();
        panic!("Failed to execute program");
    }

    pub fn start(&mut self) -> Result<(), Error> {
        let sync_pipe = SyncPipe::new()?;

        let pid = self.do_clone()?;
        match pid {
            0 => {
                // child
                // Reminder that because we call clone, glibc's stupid getpid
                // cache is not correct.
                // unsafe {
                // println!("child pid is {} instead of {}", nix::unistd::getpid(),
                // nix::sys::syscall::syscall(SYS_getpid as i64));
                // }
                //
                self.run_child(sync_pipe);
            }
            _ => {
                // parent
                self.pid = pid;
                self.parent_setup(sync_pipe)?;
            }
        }
        Ok(())
    }

    pub fn wait(&mut self) -> Result<(), Error> {
        loop {
            match wait::waitpid(self.pid, Some(wait::__WALL)) {
                Ok(WaitStatus::Exited(..)) => {
                    self.pid = -1;
                    return Ok(());
                }
                Ok(WaitStatus::Signaled(..)) => {
                    self.pid = -1;
                    return Ok(());
                }
                Ok(WaitStatus::Stopped(..)) => (), // Child being traced?  Try again.
                Ok(WaitStatus::Continued(..)) => (),
                Ok(WaitStatus::StillAlive) => (),
                Err(nix::Error::Sys(nix::Errno::EINTR)) => (), // Try again.
                Err(_) => return Err(Error::WaitPidFailed),
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
    use seccomp_jail::SeccompConfig;
    use seccomp_jail::SeccompJail;
    use std::path::Path;
    use std::path::PathBuf;
    use std::ffi::CString;
    use user_namespace::*;
    use self::nix::unistd::getuid;
    use self::nix::unistd::getgid;
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
        CGroupNamespace::new()
    }

    #[test]
    fn start_test() {
        let temp_cgdir = TempDir::new("fake_cg").unwrap();
        let argv = vec![CString::new("/bin/ls").unwrap(), CString::new("-l").unwrap()];
        let cgroup_namespace = setup_cgroups(&temp_cgdir);
        let mount_namespace = MountNamespace::new(PathBuf::from("/tmp/foo"));
        let mut user_namespace = UserNamespace::new();
        let seccomp_config = SeccompConfig::new("SCMP_ACT_ALLOW").unwrap();
        let seccomp_jail = SeccompJail::new(&seccomp_config).unwrap();
        user_namespace.add_uid_mapping(0, getuid() as usize, 1);
        user_namespace.add_gid_mapping(0, getgid() as usize, 1);
        // TODO(dgreid) - add test with each network namespace
        let mut c = Container::new("asdf",
                                   argv,
                                   Vec::new(),
                                   Some(cgroup_namespace),
                                   Some(mount_namespace),
                                   Some(Box::new(EmptyNetNamespace::new())),
                                   Some(user_namespace),
                                   Vec::new(),
                                   Some(seccomp_jail),
                                   None,
                                   true);
        assert_eq!("asdf", c.name());
        assert!(c.start().is_ok());
        assert!(c.wait().is_ok());
    }
}
