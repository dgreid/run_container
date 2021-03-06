extern crate wait_timeout;

use self::wait_timeout::ChildExt;

use std;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::string::ToString;

#[derive(Debug, PartialEq)]
pub enum Error {
    CommandFailed(i32),
    CommandKilledBySignal,
    StartingCommand,
    TimedOut,
    WaitingForCommand,
    WriteStdIn,
}
pub type Result<T> = std::result::Result<T, Error>;

#[allow(unused_variables)]
pub trait HookState {
    fn to_string(&self,
                 pid: Option<u64>,
                 status: &str) -> String {
        String::new()
    }
}

pub struct Hook {
    path: PathBuf,
    args: Vec<String>,
    env: HashMap<OsString, OsString>,
    timeout: Option<std::time::Duration>,
}

impl Hook {
    pub fn new(path: &Path) -> Hook {
        Hook {
            path: PathBuf::from(path),
            args: Vec::new(),
            env: HashMap::new(),
            timeout: None,
        }
    }

    pub fn args<T: AsRef<str> + ToString>(mut self, args: &[T]) -> Hook {
        self.args = args.iter().map(|a| a.to_string()).collect();
        self
    }

    pub fn envs(mut self, env: &[String]) -> Hook {
        let mut env_map: HashMap<OsString, OsString> = HashMap::new();

        for s in env.iter() {
            let mut args = s.split('=');
            if let Some(key) = args.next() {
                if let Some(val) = args.next() {
                    env_map.insert(OsString::from(key),
                                   OsString::from(val));
                }
            }
        }

        self.env = env_map;
        self
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Hook {
        self.timeout = timeout;
        self
    }

    pub fn run(&self, status: Option<String>) -> Result<()> {
        let mut child = process::Command::new(&self.path)
            .stdin(process::Stdio::piped())
            .args(&self.args)
            .envs(&self.env)
            .spawn()
            .map_err(|_| Error::StartingCommand)?;

        // Give the program the state on stdin.
        // unwrap is OK as we know we set stdin above.
        if let Some(ref status) = status {
            child.stdin.as_mut().unwrap()
                .write_all(status.as_bytes())
                .map_err(|_| Error::WriteStdIn)?;
        }

        if let Some(timeout) = self.timeout {
            let wait_ret = child.wait_timeout(timeout)
                .map_err(|_| Error::WaitingForCommand)?;
            let exit_code = wait_ret.ok_or(Error::TimedOut)?;
            if exit_code.success() {
                Ok(())
            } else {
                if let Some(ec) = exit_code.code() {
                    Err(Error::CommandFailed(ec))
                } else {
                    Err(Error::CommandKilledBySignal)
                }
            }
        } else {
            let exit_code = child.wait().map_err(|_| Error::WaitingForCommand)?;
            if exit_code.success() {
                Ok(())
            } else {
                if let Some(ec) = exit_code.code() {
                    Err(Error::CommandFailed(ec))
                } else {
                    Err(Error::CommandKilledBySignal)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_hook() {
        let hook = Hook::new(&PathBuf::from("/bin/ls"))
            .args(&["/"]);
        assert_eq!(hook.run(None), Ok(()));
    }

    #[test]
    fn basic_state() {
        let hook = Hook::new(&PathBuf::from("/bin/cat"));
        assert_eq!(hook.run(Some("This would be json formatted\n".to_string())), Ok(()));
    }

    #[test]
    fn basic_env() {
        let hook = Hook::new(&PathBuf::from("/usr/bin/env"))
            .envs(&["SILLYENV1=one".to_string(), "SILLYENV2=two".to_string()]);
        assert_eq!(hook.run(None), Ok(()));
    }
}
