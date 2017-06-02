use std;
use std::collections::HashMap;
use std::io::{self, Write};
use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    SysctlConfigError(String, io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

pub struct Sysctls {
    sysctls: HashMap<String, String>,
}

impl Sysctls {
    pub fn new(s: HashMap<String, String>) -> Self {
        Sysctls { sysctls: s }
    }

    pub fn configure(&self) -> Result<()> {
        for (key, value) in &self.sysctls {
            self.write_sysctl_file(&key, &value)?;
        }
        Ok(())
    }

    fn write_sysctl_file(&self, key: &str, value: &str) -> Result<()> {
        let mut ctl_path = PathBuf::from("/proc/sys");
        ctl_path.push(key.split('.').collect::<Vec<&str>>().join("/"));
        let mut ctl_file = match fs::File::create(ctl_path.as_path()) {
            Ok(f) => f,
            Err(e) => return Err(Error::SysctlConfigError(key.to_string(), e)),
        };
        match ctl_file.write_all(value.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::SysctlConfigError(key.to_string(), e)),
        }
    }
}
