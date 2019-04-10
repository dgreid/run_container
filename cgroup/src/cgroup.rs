mod cgroup_directory;

use std::collections::BTreeSet;

use crate::cgroup_directory::CGroupDirectory;

#[derive(Debug)]
pub enum Error {
    ConfigureCgroupCpus(cgroup_directory::Error),
    ConfigureCgroupDevices(cgroup_directory::Error),
    ConfigureCgroupMems(cgroup_directory::Error),
    ConfigureFailed,
    InvalidDevicePermissions,
    InvalidDeviceType,
    CGroupDirError(cgroup_directory::Error),
}

pub trait CGroupConfiguration {
    fn configure(&self, dir: &CGroupDirectory) -> Result<(), Error>;
    fn cgroup_type(&self) -> &str;
}

pub struct CpuCGroupConfiguration {
    shares: Option<u64>,
    period: Option<u64>,
    quota: Option<u64>,
    realtime_runtime: Option<u64>,
    realtime_period: Option<u64>,
}

impl CpuCGroupConfiguration {
    pub fn new() -> Self {
        CpuCGroupConfiguration {
            shares: None,
            period: None,
            quota: None,
            realtime_runtime: None,
            realtime_period: None,
        }
    }

    pub fn shares(&mut self, shares: Option<u64>) {
        self.shares = shares;
    }

    pub fn period(&mut self, period: Option<u64>) {
        self.period = period;
    }

    pub fn quota(&mut self, quota: Option<u64>) {
        self.quota = quota;
    }

    pub fn realtime_runtime(&mut self, realtime_runtime: Option<u64>) {
        self.realtime_runtime = realtime_runtime;
    }

    pub fn realtime_period(&mut self, realtime_period: Option<u64>) {
        self.realtime_period = realtime_period;
    }
}

impl CGroupConfiguration for CpuCGroupConfiguration {
    fn configure(&self, _: &CGroupDirectory) -> Result<(), Error> {
        Ok(())
    }

    fn cgroup_type(&self) -> &str {
        "cpu"
    }
}

pub struct CpuAcctCGroupConfiguration {}

impl CpuAcctCGroupConfiguration {
    pub fn new() -> Self {
        CpuAcctCGroupConfiguration {}
    }
}

impl CGroupConfiguration for CpuAcctCGroupConfiguration {
    fn configure(&self, _: &CGroupDirectory) -> Result<(), Error> {
        Ok(())
    }

    fn cgroup_type(&self) -> &str {
        "cpuacct"
    }
}

pub struct CpuSetCGroupConfiguration {
    cpus: BTreeSet<u32>,
    mems: BTreeSet<u32>,
}

impl CpuSetCGroupConfiguration {
    pub fn new() -> Self {
        CpuSetCGroupConfiguration {
            cpus: BTreeSet::new(),
            mems: BTreeSet::new(),
        }
    }

    pub fn add_cpu(&mut self, cpu_id: u32) {
        self.cpus.insert(cpu_id);
    }

    pub fn num_cpus(&self) -> usize {
        self.cpus.len()
    }

    pub fn has_cpu(&self, cpu_num: u32) -> bool {
        self.cpus.contains(&cpu_num)
    }

    pub fn add_mem(&mut self, mem_id: u32) {
        self.mems.insert(mem_id);
    }

    pub fn num_mems(&self) -> usize {
        self.mems.len()
    }

    pub fn has_mem(&self, mem_num: u32) -> bool {
        self.mems.contains(&mem_num)
    }
}

impl CGroupConfiguration for CpuSetCGroupConfiguration {
    fn configure(&self, dir: &CGroupDirectory) -> Result<(), Error> {
        dir.write_file(
            "cpus",
            &self
                .cpus
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<String>>()
                .join(","),
        )
        .map_err(Error::ConfigureCgroupCpus)?;
        dir.write_file(
            "mems",
            &self
                .mems
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<String>>()
                .join(","),
        )
        .map_err(Error::ConfigureCgroupMems)?;
        Ok(())
    }

    fn cgroup_type(&self) -> &str {
        "cpuset"
    }
}

struct CGroupDeviceConfig {
    major: Option<u32>,
    minor: Option<u32>,
    allow: bool,
    read: bool,
    write: bool,
    modify: bool,
    dev_type: char,
}

impl CGroupDeviceConfig {
    pub fn new(
        major: Option<u32>,
        minor: Option<u32>,
        allow: bool,
        read: bool,
        write: bool,
        modify: bool,
        dev_type: char,
    ) -> Result<CGroupDeviceConfig, Error> {
        match dev_type {
            'a' | 'b' | 'c' => Ok(()),
            _ => Err(Error::InvalidDeviceType),
        }?;

        // Must specify at least one permission.
        if !(read | modify | write) {
            return Err(Error::InvalidDevicePermissions);
        }

        Ok(CGroupDeviceConfig {
            major: major,
            minor: minor,
            allow: allow,
            read: read,
            write: write,
            modify: modify,
            dev_type: dev_type,
        })
    }

    pub fn access_string(&self) -> String {
        let mut perms = String::new();
        if self.read {
            perms.push('r');
        }
        if self.write {
            perms.push('w');
        }
        if self.modify {
            perms.push('m');
        }
        format!(
            "{} {}:{} {}",
            self.dev_type,
            self.major.map_or("*".to_string(), |m| m.to_string()),
            self.minor.map_or("*".to_string(), |m| m.to_string()),
            perms
        )
    }
}

pub struct DevicesCGroupConfiguration {
    devices: Vec<CGroupDeviceConfig>,
    default_allow: bool,
}

impl DevicesCGroupConfiguration {
    pub fn new() -> Self {
        DevicesCGroupConfiguration {
            devices: Vec::new(),
            default_allow: false,
        }
    }

    pub fn default_allow(&mut self, allow: bool) {
        self.default_allow = allow;
    }

    pub fn add_device(
        &mut self,
        major: Option<u32>,
        minor: Option<u32>,
        allow: bool,
        read: bool,
        write: bool,
        modify: bool,
        dev_type: char,
    ) -> Result<(), Error> {
        self.devices.push(CGroupDeviceConfig::new(
            major, minor, allow, read, write, modify, dev_type,
        )?);

        Ok(())
    }
}

impl CGroupConfiguration for DevicesCGroupConfiguration {
    fn configure(&self, dir: &CGroupDirectory) -> Result<(), Error> {
        fn filename_for_access(allow: bool) -> &'static str {
            match allow {
                true => "devices.allow",
                false => "devices.deny",
            }
        }

        match dir.write_file(filename_for_access(self.default_allow), "a") {
            Err(_) => return Ok(()), // Permission denied is OK. TODO - better match
            _ => {}
        };

        for device in &self.devices {
            let filename = filename_for_access(device.allow);
            dir.write_file(filename, &device.access_string())
                .map_err(Error::ConfigureCgroupDevices)?;
        }

        Ok(())
    }

    fn cgroup_type(&self) -> &str {
        "devices"
    }
}

pub struct FreezerCGroupConfiguration {}

impl FreezerCGroupConfiguration {
    pub fn new() -> Self {
        FreezerCGroupConfiguration {}
    }
}

impl CGroupConfiguration for FreezerCGroupConfiguration {
    fn configure(&self, _: &CGroupDirectory) -> Result<(), Error> {
        Ok(())
    }

    fn cgroup_type(&self) -> &str {
        "freezer"
    }
}
