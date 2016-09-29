extern crate nix;

use mount_namespace::*;
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

pub struct Container<'a> {
    name: String,
    argv: Vec<CString>,
    mount_namespace: &'a MountNamespace<'a>,
    user_namespace: &'a UserNamespace,
    pid: pid_t,
}

#[derive(Debug)]
pub enum ContainerError {
    Io(io::Error),
    Nix(nix::Error),
    WaitPidFailed,
    InvalidMountTarget,
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

impl<'a> Container<'a> {
    pub fn new(name: &str, argv: Vec<CString>,
               mount_namespace: &'a MountNamespace,
               user_namespace: &'a UserNamespace) -> Self {
        Container {
            name: name.to_string(),
            argv: argv,
            mount_namespace: mount_namespace,
            user_namespace: user_namespace,
            pid: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn enter_jail(&self) -> Result<(), ContainerError> {
        try!(self.mount_namespace.enter());
        Ok(())
    }

    fn do_clone() -> Result<pid_t, nix::Error> {
        unsafe {
            // TODO(dgreid) - hard coded x86_64 syscall value for clone
	    let clone_flags  = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC;
	    let pid = nix::sys::syscall::syscall(
                    56, clone_flags.bits() | nix::sys::signal::SIGCHLD, 0);
	    if pid < 0 {
                Err(nix::Error::Sys(nix::Errno::UnknownErrno))
            } else {
                Ok(pid as pid_t)
            }
        }
    }

    pub fn parent_setup(&self, sync_pipe: SyncPipe) -> Result<(), ContainerError> {
        let mut uid_file = try!(fs::File::create(format!("/proc/{}/uid_map", self.pid)));
        let mut gid_file = try!(fs::File::create(format!("/proc/{}/gid_map", self.pid)));
        try!(uid_file.write_all(self.user_namespace.uid_config_string().as_bytes()));
        try!(gid_file.write_all(self.user_namespace.gid_config_string().as_bytes()));
        drop(uid_file);
        drop(gid_file); // ick, but dropping the file causes a flush.

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
    use super::Container;
    use mount_namespace::*;
    use std::path::Path;
    use std::ffi::CString;
    use user_namespace::*;
    use nix::unistd::getuid;

    #[test]
    fn start_test() {
        let argv = vec![ CString::new("/bin/ls").unwrap(), CString::new("-l").unwrap() ];
        let mount_namespace = MountNamespace::new(Path::new("/tmp/foo"));
        let mut user_namespace = UserNamespace::new();
        user_namespace.add_uid_mapping(0, getuid() as usize, 1);
        let mut c = Container::new("asdf", argv, &mount_namespace, &user_namespace);
        assert!(c.start().is_ok());
        assert!(c.wait().is_ok());
    }
}
