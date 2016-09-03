extern crate nix;

use self::nix::sys::ioctl::libc::pid_t;
use self::nix::sched::*;
use self::nix::sys::wait;
use self::nix::sys::wait::WaitStatus;

pub struct Container {
    name: String,
    pid: pid_t,
}

impl Container {
    pub fn new(name: &str) -> Self {
        Container { name: name.to_string(), pid: 0 }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn child_proc() -> isize {
        0
    }

    pub fn start(&mut self) -> Result<(), String> { // TODO(dgreid) - use real error code
        let mut stack = [0; 0x1000];
        clone(Box::new(Container::child_proc), &mut stack,
               CLONE_NEWUSER, None).map(|pid| self.pid = pid).unwrap();
        Ok(())
    }

    pub fn wait(&mut self) -> Result<(), String> { // TODO(dgreid) - use real error code
        loop {
            match wait::waitpid(self.pid, Some(wait::__WALL)) {
                Ok(WaitStatus::Exited(..)) => { self.pid = -1; return Ok(()); },
                Ok(WaitStatus::Signaled(..)) => { self.pid = -1; return Ok(()); },
                Ok(WaitStatus::Stopped(..)) => (), // Child being traced?  Try again.
                Ok(WaitStatus::Continued(..)) => (),
                Ok(WaitStatus::StillAlive) => (),
                Err(nix::Error::Sys(nix::Errno::EINTR)) => (), // Try again.
                Err(_) => return Err("Error from waitpid".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Container;

    #[test]
    fn start_test() {
        let mut c = Container::new("asdf");
        assert_eq!(c.start(), Ok(()));
        assert_eq!(c.wait(), Ok(()));
    }
}
