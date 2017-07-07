extern crate nix;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate regex;

extern crate caps;
extern crate container;

mod oci_config;

use caps::{CapConfig, CapType};
use container::container::Container;
use container::cgroup::{self, CGroup};
use container::cgroup::cgroup_configuration::{self, CGroupConfiguration,
                                              CpuAcctCGroupConfiguration, CpuCGroupConfiguration,
                                              CpuSetCGroupConfiguration,
                                              DevicesCGroupConfiguration,
                                              FreezerCGroupConfiguration};
use container::cgroup_namespace::CGroupNamespace;
use container::devices::{self, DeviceConfig, DeviceType};
use container::mount_namespace::{self, MountNamespace};
use container::net_namespace::{EmptyNetNamespace, NetNamespace};
use container::rlimits::{self, RLimits};
use container::seccomp_jail::{self, SeccompConfig, SeccompJail};
use container::sysctls::Sysctls;
use container::user_namespace::UserNamespace;

use self::nix::libc::uid_t;
use self::nix::mount::*;
use self::nix::unistd::{getuid, getgid};

use std::collections::HashMap;
use std::io::{self, BufReader};
use std::fs::File;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use oci_config::*;

#[derive(Debug)]
pub enum Error {
    CreatingCapConfig(caps::Error),
    Io(io::Error),
    MountSetup(mount_namespace::Error),
    ConfigParseError(serde_json::Error),
    NoLinuxNodeFoundError,
    HostnameInvalid(String),
    SeccompError(seccomp_jail::Error),
    ContainerError(container::container::Error),
    CGroupError(cgroup::Error),
    CGroupConfigError(cgroup_configuration::Error),
    DeviceError(devices::Error),
    ParseIntError(std::num::ParseIntError),
    RLimitError(rlimits::Error),
    InvalidDeviceType,
    NoDevicesFound,
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Error {
        Error::ParseIntError(err)
    }
}

impl From<seccomp_jail::Error> for Error {
    fn from(err: seccomp_jail::Error) -> Error {
        Error::SeccompError(err)
    }
}

impl From<container::container::Error> for Error {
    fn from(err: container::container::Error) -> Error {
        Error::ContainerError(err)
    }
}

impl From<cgroup::Error> for Error {
    fn from(err: cgroup::Error) -> Error {
        Error::CGroupError(err)
    }
}

impl From<cgroup_configuration::Error> for Error {
    fn from(err: cgroup_configuration::Error) -> Error {
        Error::CGroupConfigError(err)
    }
}

impl From<devices::Error> for Error {
    fn from(err: devices::Error) -> Error {
        Error::DeviceError(err)
    }
}

pub struct ContainerConfig {
    name: String,
    alt_syscall_table: Option<CString>,
    argv: Vec<CString>,
    caps: Option<CapConfig>,
    cgroup_base_path: PathBuf,
    cgroup_name: String,
    cgroup_parent: String,
    cgroup_configs: Vec<Box<CGroupConfiguration>>,
    cgroup_namespace: Option<CGroupNamespace>,
    device_config: Option<devices::DeviceConfig>,
    mount_namespace: Option<MountNamespace>,
    user_namespace: Option<UserNamespace>,
    net_namespace: Option<Box<NetNamespace>>,
    no_new_privileges: bool,
    rlimits: Option<RLimits>,
    seccomp_jail: Option<SeccompJail>,
    additional_gids: Vec<u32>,
    uid: Option<uid_t>,
    sysctls: Option<Sysctls>,
}

impl ContainerConfig {
    pub fn new(name: String) -> ContainerConfig {
        ContainerConfig {
            name: name,
            alt_syscall_table: None,
            argv: Vec::new(),
            caps: None,
            cgroup_base_path: PathBuf::from("/sys/fs/cgroup"),
            cgroup_name: "container".to_string(),
            cgroup_parent: "".to_string(),
            cgroup_configs: Vec::new(),
            cgroup_namespace: None,
            device_config: None,
            mount_namespace: None,
            user_namespace: None,
            net_namespace: None,
            no_new_privileges: false,
            rlimits: None,
            seccomp_jail: None,
            additional_gids: Vec::new(),
            uid: None,
	    sysctls: None,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_root_uid(&self) -> Option<uid_t> {
        self.user_namespace.as_ref().and_then(|t| t.get_external_uid(0).map(|uid| uid as uid_t))
    }

    pub fn caps(mut self, caps: Option<CapConfig>) -> ContainerConfig {
        self.caps = caps;
        self
    }

    pub fn cgroup_name(mut self, cgroup_name: String) -> ContainerConfig {
        self.cgroup_name = cgroup_name;
        self
    }

    pub fn cgroup_parent(mut self, cgroup_parent: String) -> ContainerConfig {
        self.cgroup_parent = cgroup_parent;
        self
    }

    pub fn cgroup_namespace(mut self,
                            cgroup_namespace: Option<CGroupNamespace>)
                            -> ContainerConfig {
        self.cgroup_namespace = cgroup_namespace;
        self
    }

    pub fn cgroup_configs(mut self,
                          cgroup_configs: Vec<Box<CGroupConfiguration>>)
                          -> ContainerConfig {
        self.cgroup_configs = cgroup_configs;
        self
    }

    pub fn device_config(mut self,
                         device_config: DeviceConfig)
                         -> ContainerConfig {
        self.device_config = Some(device_config);
        self
    }

    pub fn mount_namespace(mut self, mount_namespace: Option<MountNamespace>) -> ContainerConfig {
        self.mount_namespace = mount_namespace;
        self
    }

    pub fn net_namespace(mut self, net_namespace: Option<Box<NetNamespace>>) -> ContainerConfig {
        self.net_namespace = net_namespace;
        self
    }

    pub fn no_new_privileges(mut self, no_new_privileges: bool) -> ContainerConfig {
        self.no_new_privileges = no_new_privileges;
        self
    }

    pub fn user_namespace(mut self, user_namespace: Option<UserNamespace>) -> ContainerConfig {
        self.user_namespace = user_namespace;
        self
    }

    pub fn argv(mut self, argv: Vec<CString>) -> ContainerConfig {
        self.argv = argv;
        self
    }

    pub fn append_args(mut self, args: &[String]) -> ContainerConfig {
        for string_arg in args.iter() {
            self.argv.push(CString::new(string_arg.as_str()).unwrap());
        }
        self
    }

    pub fn alt_syscall_table(mut self, table: Option<&str>) -> ContainerConfig {
        self.alt_syscall_table = table.and_then(|t| CString::new(t).ok());
        self
    }

    pub fn rlimits(mut self, rlimits: Option<RLimits>) -> ContainerConfig {
        self.rlimits = rlimits;
        self
    }

    pub fn seccomp_jail(mut self, seccomp_jail: Option<SeccompJail>) -> ContainerConfig {
        self.seccomp_jail = seccomp_jail;
        self
    }

    pub fn sysctls(mut self, sysctls: Option<HashMap<String, String>>) -> ContainerConfig {
        self.sysctls = sysctls.map(Sysctls::new);
        self
    }

    pub fn uid(mut self, uid: Option<uid_t>) -> ContainerConfig {
        self.uid = uid;
        self
    }

    pub fn additional_gids(mut self, gids: Vec<u32>) -> ContainerConfig {
        self.additional_gids = gids;
        self
    }

    pub fn start(self) -> Result<Container> {
        let mut cgroups = Vec::new();
        let external_uid = self.external_uid();
        for cgconfig in self.cgroup_configs {
            cgroups.push(CGroup::new(&self.cgroup_name,
                                     &self.cgroup_parent,
                                     &self.cgroup_base_path,
                                     cgconfig,
                                     external_uid)?);
        }

        let mut c = Container::new(&self.name,
                                   self.argv,
                                   self.caps,
                                   cgroups,
                                   self.cgroup_namespace,
                                   self.device_config,
                                   self.mount_namespace,
                                   self.net_namespace,
                                   self.user_namespace,
                                   self.additional_gids,
                                   self.no_new_privileges,
                                   self.rlimits,
                                   self.seccomp_jail,
                                   self.sysctls,
                                   true);
        c.start()?;
        Ok(c)
    }

    fn external_uid(&self) -> Option<uid_t> {
        self.uid.and_then(|uid|
                if let Some(ref user_ns) = self.user_namespace {
                    user_ns.get_external_uid(uid as u64).map(|uid| uid as uid_t)
                } else {
                    Some(uid)
                }
            )
    }
}

pub fn container_config_from_oci_config_file(path: &Path,
                                             bind_mounts: Vec<(String, String)>)
                                             -> Result<ContainerConfig> {
    let mut config_path = PathBuf::from(path);
    config_path.push("config.json");
    let config_file = File::open(&config_path)?;
    let reader = BufReader::new(config_file);
    let oci_config: OciConfig = serde_json::from_reader(reader)
        .map_err(Error::ConfigParseError)?;
    container_from_oci(oci_config, bind_mounts, path)
}

fn container_from_oci(config: OciConfig,
                      bind_mounts: Vec<(String, String)>,
                      path: &Path)
                      -> Result<ContainerConfig> {
    let hostname = config.hostname.unwrap_or_else(|| "default".to_string());
    if !hostname_valid(&hostname) {
        return Err(Error::HostnameInvalid(hostname));
    }

    let mut root_path = PathBuf::from(path);
    root_path.push(&config.root.path);

    let linux = config.linux.ok_or(Error::NoLinuxNodeFoundError)?;

    let mnt_ns = if oci_has_namespace(&linux, "mount") {
        Some(mount_ns_from_oci(config.mounts, bind_mounts, root_path)?)
    } else {
        None
    };

    // TODO(dgreid) - Should user namespace really be optional?
    let user_ns = user_ns_from_oci(&linux.uid_mappings,
                                   &linux.gid_mappings,
                                   config.process.user.uid as u64,
                                   config.process.user.gid as u64);

    let device_config = device_config_from_oci(&linux.devices, &user_ns)?;

    let argv = config.process
        .args
        .into_iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    let rlimits = if let Some(ref oci_rlim) = config.process.rlimits {
        Some(rlimits_from_oci(oci_rlim)?)
    } else {
        None
    };

    // TODO(dgreid) - Parse net namespace config.
    let net_ns: Option<Box<NetNamespace>> = if oci_has_namespace(&linux, "network") {
        Some(Box::new(EmptyNetNamespace::new()))
    } else {
        None
    };

    let cgroup_ns = if oci_has_namespace(&linux, "cgroup") {
        Some(CGroupNamespace::new())
    } else {
        None
    };

    let cgroup_configs = cgroups_from_oci(&linux)?;

    let seccomp_jail = match linux.seccomp {
        Some(ref s) => Some(seccomp_jail_from_oci(s)?),
        None => None,
    };

    let additional_gids = config.process.user.additional_gids.map_or(Vec::new(), |g| g);

    let caps = match config.process.capabilities {
        None => None,
        Some(c) => Some(capabilities_from_oci(c)?),
    };

    Ok(ContainerConfig::new(hostname)
        .alt_syscall_table(None)
        .argv(argv)
        .caps(caps)
        .cgroup_namespace(cgroup_ns)
        .cgroup_configs(cgroup_configs)
        .device_config(device_config)
        .mount_namespace(mnt_ns)
        .user_namespace(Some(user_ns))
        .uid(Some(config.process.user.uid as uid_t))
        .net_namespace(net_ns)
        .no_new_privileges(config.process.no_new_privileges.unwrap_or(false))
        .additional_gids(additional_gids)
        .rlimits(rlimits)
        .seccomp_jail(seccomp_jail))
}

fn oci_has_namespace(linux: &OciLinux, namespace_type: &str) -> bool {
    if let Some(ref namespaces) = linux.namespaces {
        for namespace in namespaces {
            if namespace.namespace_type == namespace_type {
                return true;
            }
        }
        false
    } else {
        false
    }
}

fn mount_ns_from_oci(mounts_vec: Option<Vec<OciMount>>,
                     bind_mounts: Vec<(String, String)>,
                     root_path: PathBuf)
                     -> Result<MountNamespace> {
    let mut mnt_ns = MountNamespace::new(root_path);
    if let Some(mounts) = mounts_vec {
        for m in mounts {
            let mut flags = MsFlags::empty();
            let mut options = Vec::new();
            if let Some(mnt_opts) = m.options {
                for opt in mnt_opts {
                    match opt.as_ref() {
                        "bind" => flags.insert(MS_BIND),
                        "noatime" => flags.insert(MS_NOATIME),
                        "nodev" => flags.insert(MS_NODEV),
                        "nodiratime" => flags.insert(MS_NODIRATIME),
                        "noexec" => flags.insert(MS_NOEXEC),
                        "nosuid" => flags.insert(MS_NOSUID),
                        "recursive" => flags.insert(MS_REC),
                        "relatime" => flags.insert(MS_RELATIME),
                        "remount" => flags.insert(MS_REMOUNT),
                        "ro" => flags.insert(MS_RDONLY),
                        "strictatime" => flags.insert(MS_STRICTATIME),
                        _ => options.push(opt.to_string()),
                    }
                }
            }
            mnt_ns.add_mount(Some(PathBuf::from(&m.source)),
                             PathBuf::from(&m.destination.trim_left_matches('/')),
                             Some(m.mount_type),
                             flags,
                             options)
                .map_err(Error::MountSetup)?;
        }
    }
    for m in bind_mounts {
        mnt_ns.add_mount(Some(PathBuf::from(m.0)),
                         PathBuf::from(m.1.trim_matches('/')),
                         None,
                         MS_BIND,
                         Vec::new())
                .map_err(Error::MountSetup)?;
    }
    Ok(mnt_ns)
}

fn device_config_from_oci(dev_list: &Option<Vec<OciLinuxDevice>>,
                          user_ns: &UserNamespace) ->
        Result<devices::DeviceConfig> {
    let mut devices = devices::DeviceConfig::new();
    if let Some(ref dev_list) = *dev_list {
        for d in dev_list {
            let dev_type = match d.dev_type.as_ref() {
                "b" => DeviceType::Block,
                "c" => DeviceType::Character,
                _ => return Err(Error::InvalidDeviceType),
            };
            devices.add_device(dev_type, &PathBuf::from(&d.path), d.major,
                               d.minor, d.file_mode,
                               d.uid.and_then(|u| user_ns.get_external_uid(u as u64)),
                               d.gid.and_then(|g| user_ns.get_external_gid(g as u64)))?;
        }
    }
    Ok(devices)
}

fn user_ns_from_oci(uid_maps: &Option<Vec<OciLinuxNamespaceMapping>>,
                    gid_maps: &Option<Vec<OciLinuxNamespaceMapping>>,
                    ns_uid: u64,
                    ns_gid: u64)
                    -> UserNamespace {
    let mut user_ns = UserNamespace::new();
    if let Some(ref uid_mappings) = *uid_maps {
        for id_map in uid_mappings {
            user_ns.add_uid_mapping(id_map.container_id,
                                    id_map.host_id,
                                    id_map.size);
        }
    } else {
        // Default map the current user to the uid the process will run as.
        user_ns.add_uid_mapping(ns_uid, getuid() as u64, 1);
    }

    if let Some(ref gid_mappings) = *gid_maps {
        for id_map in gid_mappings {
            user_ns.add_gid_mapping(id_map.container_id,
                                    id_map.host_id,
                                    id_map.size);
        }
    } else {
        // Default map the current group to the gid the process will run as.
        user_ns.add_gid_mapping(ns_gid, getgid() as u64, 1);
    }
    user_ns
}

fn hostname_valid(hostname: &str) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    let name_re = regex::Regex::new("^[0-9a-zA-Z]([0-9a-zA-Z-]*[0-9a-zA-Z])?$").unwrap();
    if !name_re.is_match(hostname) {
        return false;
    }

    if hostname.contains("--") {
        return false;
    }

    true
}

fn capabilities_from_oci(oci_caps: OciProcessCapabilities) -> Result<CapConfig> {
    let mut caps = CapConfig::new().map_err(Error::CreatingCapConfig)?;
    if let Some(ref effective) = oci_caps.effective {
        caps.set_caps(CapType::Effective, &effective).map_err(Error::CreatingCapConfig)?;
    }
    if let Some(ref bounding) = oci_caps.bounding {
        caps.set_caps(CapType::Bounding, &bounding).map_err(Error::CreatingCapConfig)?;
    }
    if let Some(ref inheritable) = oci_caps.inheritable {
        caps.set_caps(CapType::Inheritable, &inheritable).map_err(Error::CreatingCapConfig)?;
    }
    if let Some(ref permitted) = oci_caps.permitted {
        caps.set_caps(CapType::Permitted, &permitted).map_err(Error::CreatingCapConfig)?;
    }
    if let Some(ref ambient) = oci_caps.ambient {
        caps.set_caps(CapType::Ambient, &ambient).map_err(Error::CreatingCapConfig)?;
    }
    Ok(caps)
}

fn seccomp_jail_from_oci(oci_seccomp: &OciSeccomp) -> Result<SeccompJail> {
    let mut seccomp_config = SeccompConfig::new(&oci_seccomp.default_action)?;
    for syscall in &oci_seccomp.syscalls {
        if let Some(ref args) = syscall.args {
            for arg in args {
                seccomp_config.add_rule(&syscall.name,
                              &syscall.action,
                              Some(arg.index),
                              Some(arg.value),
                              Some(arg.value2),
                              Some(&arg.op))?;
            }
        } else {
            seccomp_config.add_rule(&syscall.name, &syscall.action, None, None, None, None)?;
        }
    }
    Ok(SeccompJail::new(&seccomp_config)?)
}

fn cgroups_from_oci(linux: &OciLinux) -> Result<Vec<Box<CGroupConfiguration>>> {
    let mut cgroups = Vec::new();
    if let Some(ref resources) = linux.resources {
        if let Some(ref devices) = resources.devices {
            cgroups.push(device_cgroup_config(devices)?);
        }
        if let Some(ref cpu) = resources.cpu {
            cgroups.push(cpu_cgroup_config(cpu)?);
            cgroups.push(cpuset_cgroup_config(cpu)?);
        }
        cgroups.push(Box::new(FreezerCGroupConfiguration::new()));
        cgroups.push(Box::new(CpuAcctCGroupConfiguration::new()));
    }
    Ok(cgroups)
}

fn rlimits_from_oci(oci_rlim: &[OciRlimit]) -> Result<RLimits> {
    let mut rlimits = RLimits::new();
    for lim in oci_rlim {
        rlimits.add_limit(&lim.limit_type, lim.soft as u64, lim.hard as u64)
            .map_err(Error::RLimitError)?;
    }
    Ok(rlimits)
}

fn device_cgroup_config(devices: &[OciLinuxCgroupDevice])
                        -> Result<Box<CGroupConfiguration>> {
    if devices.is_empty() {
        return Err(Error::NoDevicesFound);
    }

    let mut devices_config = Box::new(DevicesCGroupConfiguration::new());
    for device in devices.iter() {
        devices_config.add_device(device.major,
                        device.minor,
                        device.allow,
                        device.access.as_ref().map_or(true, |a| a.contains('r')),
                        device.access.as_ref().map_or(true, |a| a.contains('w')),
                        device.access.as_ref().map_or(true, |a| a.contains('m')),
                        device.dev_type
                            .as_ref()
                            .map_or(Ok('a'),
                                    |t| t.chars().nth(0).ok_or(Error::InvalidDeviceType))?)?;
    }
    Ok(devices_config)
}

fn cpu_cgroup_config(config: &OciLinuxCgroupCpu) -> Result<Box<CGroupConfiguration>> {
    let mut cpu_config = Box::new(CpuCGroupConfiguration::new());
    cpu_config.shares(config.shares);
    cpu_config.quota(config.quota);
    cpu_config.period(config.period);
    cpu_config.realtime_runtime(config.realtime_runtime);
    cpu_config.realtime_period(config.realtime_period);
    Ok(cpu_config)
}

fn cpuset_cgroup_config(config: &OciLinuxCgroupCpu)
                        -> Result<Box<CpuSetCGroupConfiguration>> {
    let mut cpuset_config = Box::new(CpuSetCGroupConfiguration::new());
    if let Some(ref cpus_string) = config.cpus {
        let cpus_vec: Vec<&str> = cpus_string.split(',').collect();
        for cpu in &cpus_vec {
            if cpu.contains('-') {
                // range given
                let range: Vec<&str> = cpu.split('-').collect();
                for i in range[0].parse::<u32>()?..(range[1].parse::<u32>()? + 1) {
                    cpuset_config.add_cpu(i);
                }
            } else {
                cpuset_config.add_cpu(cpu.parse::<u32>()?);
            }
        }
    }

    if let Some(ref mems_string) = config.mems {
        let mems_vec: Vec<&str> = mems_string.split(',').collect();
        for mem in &mems_vec {
            if mem.contains('-') {
                // range given
                let range: Vec<&str> = mem.split('-').collect();
                for i in range[0].parse::<u32>()?..(range[1].parse::<u32>()? + 1) {
                    cpuset_config.add_mem(i);
                }
            } else {
                cpuset_config.add_mem(mem.parse::<u32>()?);
            }
        }
    }

    Ok(cpuset_config)
}

#[cfg(test)]
mod tests {
    use super::cpuset_cgroup_config;
    use super::hostname_valid;

    use oci_config::*;

    #[test]
    fn test_cpuset_parsing() {
        let oci_cpus = OciLinuxCgroupCpu {
            shares: None,
            quota: None,
            period: None,
            realtime_runtime: None,
            realtime_period: None,
            cpus: Some("0,2-5".to_string()),
            mems: None,
        };

        let config = cpuset_cgroup_config(&oci_cpus).unwrap();
        assert!(config.has_cpu(0));
        assert!(config.has_cpu(2));
        assert!(config.has_cpu(3));
        assert!(config.has_cpu(4));
        assert!(config.has_cpu(5));
        assert_eq!(5, config.num_cpus());
        assert_eq!(0, config.num_mems());
    }

    #[test]
    fn test_memset_parsing() {
        let oci_cpus = OciLinuxCgroupCpu {
            shares: None,
            quota: None,
            period: None,
            realtime_runtime: None,
            realtime_period: None,
            cpus: Some("0-5".to_string()),
            mems: Some("5,7,3,0-1".to_string()),
        };

        let config = cpuset_cgroup_config(&oci_cpus).unwrap();
        assert!(config.has_mem(0));
        assert!(config.has_mem(1));
        assert!(config.has_mem(3));
        assert!(config.has_mem(5));
        assert!(config.has_mem(7));
        assert_eq!(5, config.num_mems());
        assert_eq!(6, config.num_cpus());
    }

    #[test]
    fn test_hostname_valid() {
        assert!(hostname_valid("asdf"));
        assert!(hostname_valid("as-df"));
        assert!(hostname_valid("a"));
        assert!(!hostname_valid("-a"));
        assert!(!hostname_valid("../asdf"));
        assert!(!hostname_valid("as/../df"));
    }
}
