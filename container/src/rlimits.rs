extern crate libc;

use std;
use std::collections::HashMap;
use std::ptr::null_mut;

#[derive(Debug)]
pub enum Error {
    DuplicateLimit,
    PrLimitFailed,
    UnknownLimit,
}
pub type Result<T> = std::result::Result<T, Error>;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum RLimit {
    // Note that these numbers aren't valid for the MIPS architecture.
    RLIMIT_CPU = 0, // CPU time in sec
    RLIMIT_FSIZE = 1, // Maximum filesize
    RLIMIT_DATA = 2, // max data size
    RLIMIT_STACK = 3, // max stack size
    RLIMIT_CORE = 4, // max core file size
    RLIMIT_RSS = 5, // max resident set size
    RLIMIT_NPROC = 6, // max number of processes
    RLIMIT_NOFILE = 7, // max number of open files
    RLIMIT_MEMLOCK = 8, // max locked-in-memory address space
    RLIMIT_AS = 9, // address space limit
    RLIMIT_LOCKS = 10, // maximum file locks held
    RLIMIT_SIGPENDING = 11, // max number of pending signals
    RLIMIT_MSGQUEUE = 12, // maximum bytes in POSIX mqueues
    RLIMIT_NICE = 13, // max nice prio allowed to raise to 0-39 for nice level 19 .. -20
    RLIMIT_RTPRIO = 14, // maximum realtime priority
    RLIMIT_RTTIME = 15, // timeout for RT tasks in us
}

#[derive(Default)]
pub struct RLimits {
    rlimits: HashMap<RLimit, libc::rlimit64>,
}

impl RLimits {
    pub fn new() -> RLimits {
        RLimits { rlimits: HashMap::new() }
    }

    pub fn add_limit(&mut self, name: &str, cur: u64, max: u64) -> Result<()> {
        let rlimit = rlimit_from_name(name)?;
        if self.rlimits.contains_key(&rlimit) {
            return Err(Error::DuplicateLimit);
        }
        self.rlimits
            .insert(rlimit,
                    libc::rlimit64 {
                        rlim_cur: cur,
                        rlim_max: max,
                    });
        Ok(())
    }

    pub fn configure(&self, pid: libc::pid_t) -> Result<()> {
        for (rlim, val) in &self.rlimits {
            let ret = unsafe {
                // Calling prlimit64 is safe here as it doesn't read anything other
                // than memory and setting limits doesn't affect memory safety.
                libc::prlimit64(pid, *rlim as libc::c_int, val as *const _, null_mut())
            };
            if ret != 0 {
                return Err(Error::PrLimitFailed);
            }
        }
        Ok(())
    }
}

fn rlimit_from_name(name: &str) -> Result<RLimit> {
    match name {
        "RLIMIT_CPU" => Ok(RLimit::RLIMIT_CPU),
        "RLIMIT_FSIZE" => Ok(RLimit::RLIMIT_FSIZE),
        "RLIMIT_DATA" => Ok(RLimit::RLIMIT_DATA),
        "RLIMIT_STACK" => Ok(RLimit::RLIMIT_STACK),
        "RLIMIT_CORE" => Ok(RLimit::RLIMIT_CORE),
        "RLIMIT_RSS" => Ok(RLimit::RLIMIT_RSS),
        "RLIMIT_NPROC" => Ok(RLimit::RLIMIT_NPROC),
        "RLIMIT_NOFILE" => Ok(RLimit::RLIMIT_NOFILE),
        "RLIMIT_MEMLOCK" => Ok(RLimit::RLIMIT_MEMLOCK),
        "RLIMIT_AS" => Ok(RLimit::RLIMIT_AS),
        "RLIMIT_LOCKS" => Ok(RLimit::RLIMIT_LOCKS),
        "RLIMIT_SIGPENDING" => Ok(RLimit::RLIMIT_SIGPENDING),
        "RLIMIT_MSGQUEUE" => Ok(RLimit::RLIMIT_MSGQUEUE),
        "RLIMIT_NICE" => Ok(RLimit::RLIMIT_NICE),
        "RLIMIT_RTPRIO" => Ok(RLimit::RLIMIT_RTPRIO),
        "RLIMIT_RTTIME" => Ok(RLimit::RLIMIT_RTTIME),
        _ => Err(Error::UnknownLimit),
    }
}
