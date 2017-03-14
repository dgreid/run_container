#[cfg(target_arch="x86_64")]
#[path="linux-x86_64/mod.rs"]
pub mod linux;

#[cfg(target_arch="x86")]
#[path="linux-x86/mod.rs"]
pub mod linux;

#[cfg(target_arch="aarch64")]
#[path="linux-aarch64/mod.rs"]
pub mod linux;

pub enum Error {
    UnknownSyscall,
}

pub fn from_name(name: &str) -> Result<linux::LinuxSyscall, Error> {
    linux::from_name(name)
}
