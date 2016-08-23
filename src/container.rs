extern crate nix;

use self::nix::sys::ioctl::libc::pid_t;
use self::nix::sched::*;

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

    pub fn start(&mut self) -> Result<(), String> {
        let mut stack = [0; 0x1000];
        clone(Box::new(child_proc), &mut stack,
               CloneFlags::empty(), None).map(|pid| self.pid = pid).unwrap();
        Ok(())
    }
}

fn child_proc() -> isize {
    0
}

#[cfg(test)]
mod test {
    use super::Container;

    #[test]
    fn start_test() {
        let mut c = Container::new("asdf");
        assert_eq!(c.start(), Ok(()));
    }
}
