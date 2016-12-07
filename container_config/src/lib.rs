#![feature(proc_macro)]

extern crate nix;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate regex;

extern crate container;

mod oci_config;

use container::container::Container;
use container::cgroup_namespace::CGroupNamespace;
use container::mount_namespace::*;
use container::net_namespace::{EmptyNetNamespace, NetNamespace};
use container::seccomp_jail::{self, SeccompConfig, SeccompJail};
use container::user_namespace::UserNamespace;

use self::nix::libc::uid_t;
use self::nix::mount::*;
use self::nix::unistd::{getuid, getgid};

use std::io::{self, BufReader};
use std::fs::File;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use oci_config::*;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    MountError(MountError),
    ConfigParseError,
    NoLinuxNodeFoundError,
    HostnameInvalid(String),
    SeccompError(seccomp_jail::Error),
    ContainerError(container::container::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<MountError> for Error {
    fn from(err: MountError) -> Error {
        Error::MountError(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Error {
        Error::ConfigParseError
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

pub struct ContainerConfig {
    name: String,
    alt_syscall_table: Option<CString>,
    argv: Vec<CString>,
    cgroup_namespace: Option<CGroupNamespace>,
    mount_namespace: Option<MountNamespace>,
    user_namespace: Option<UserNamespace>,
    net_namespace: Option<Box<NetNamespace>>,
    seccomp_jail: Option<SeccompJail>,
}

impl ContainerConfig {
    pub fn new(name: String) -> ContainerConfig {
        ContainerConfig {
            name: name,
            alt_syscall_table: None,
            argv: Vec::new(),
            cgroup_namespace: None,
            mount_namespace: None,
            user_namespace: None,
            net_namespace: None,
            seccomp_jail: None,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_root_uid(&self) -> Option<uid_t> {
        self.user_namespace.as_ref().and_then(|t| t.get_external_uid(0).map(|uid| uid as uid_t))
    }

    pub fn cgroup_namespace(mut self,
                            cgroup_namespace: Option<CGroupNamespace>)
                            -> ContainerConfig {
        self.cgroup_namespace = cgroup_namespace;
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

    pub fn user_namespace(mut self, user_namespace: Option<UserNamespace>) -> ContainerConfig {
        self.user_namespace = user_namespace;
        self
    }

    pub fn argv(mut self, argv: Vec<CString>) -> ContainerConfig {
        self.argv = argv;
        self
    }

    pub fn append_args(mut self, args: &Vec<String>) -> ContainerConfig {
        for ref string_arg in args {
            self.argv.push(CString::new(string_arg.as_str()).unwrap());
        }
        self
    }

    pub fn alt_syscall_table(mut self, table: Option<&str>) -> ContainerConfig {
        self.alt_syscall_table = table.and_then(|t| CString::new(t).ok());
        self
    }

    pub fn seccomp_jail(mut self, seccomp_jail: Option<SeccompJail>) -> ContainerConfig {
        self.seccomp_jail = seccomp_jail;
        self
    }

    pub fn start(self) -> Result<Container, Error> {
        let mut c = Container::new(&self.name,
                                   self.argv,
                                   self.cgroup_namespace,
                                   self.mount_namespace.unwrap(),
                                   self.net_namespace.unwrap(),
                                   self.user_namespace.unwrap(),
                                   self.seccomp_jail);
        c.start()?;
        Ok(c)
    }
}

pub fn container_config_from_oci_config_file(path: &Path,
                                             bind_mounts: Vec<(String, String)>)
                                             -> Result<ContainerConfig, Error> {
    let mut config_path = PathBuf::from(path);
    config_path.push("config.json");
    let config_file = File::open(&config_path)?;
    let reader = BufReader::new(config_file);
    let oci_config: OciConfig = serde_json::from_reader(reader)?;
    container_from_oci(oci_config, bind_mounts, path)
}

fn container_from_oci(config: OciConfig,
                      bind_mounts: Vec<(String, String)>,
                      path: &Path)
                      -> Result<ContainerConfig, Error> {
    let hostname = config.hostname.unwrap_or("default".to_string());
    if !hostname_valid(&hostname) {
        return Err(Error::HostnameInvalid(hostname));
    }

    let mut root_path = PathBuf::from(path);
    root_path.push(&config.root.path);

    let mnt_ns = mount_ns_from_oci(config.mounts, bind_mounts, root_path)?;

    let linux = config.linux.ok_or(Error::NoLinuxNodeFoundError)?;
    let user_ns = user_ns_from_oci(linux.uid_mappings,
                                   linux.gid_mappings,
                                   config.process.user.uid,
                                   config.process.user.gid);

    let argv = config.process
        .args
        .into_iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    // TODO(dgreid) - Parse net namespace config.
    let net_ns = Box::new(EmptyNetNamespace::new());

    let seccomp_jail = match linux.seccomp {
        Some(s) => Some(seccomp_jail_from_oci(s)?),
        None => None,
    };

    Ok(ContainerConfig::new(hostname)
        .alt_syscall_table(None)
        .argv(argv)
        .cgroup_namespace(None)
        .mount_namespace(Some(mnt_ns))
        .user_namespace(Some(user_ns))
        .net_namespace(Some(net_ns))
        .seccomp_jail(seccomp_jail))
}

fn mount_ns_from_oci(mounts_vec: Option<Vec<OciMount>>,
                     bind_mounts: Vec<(String, String)>,
                     root_path: PathBuf)
                     -> Result<MountNamespace, Error> {
    let mut mnt_ns = MountNamespace::new(root_path);
    if let Some(mounts) = mounts_vec {
        for m in mounts.into_iter() {
            let mut flags = MsFlags::empty();
            let mut options = Vec::new();
            if let Some(mnt_opts) = m.options {
                for opt in mnt_opts.into_iter() {
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
            try!(mnt_ns.add_mount(Some(PathBuf::from(&m.source)),
                                  PathBuf::from(&m.destination.trim_left_matches('/')),
                                  Some(m.mount_type),
                                  flags,
                                  options));
        }
    }
    for m in bind_mounts {
        try!(mnt_ns.add_mount(Some(PathBuf::from(m.0)),
                              PathBuf::from(m.1.trim_matches('/')),
                              None,
                              MS_BIND,
                              Vec::new()));
    }
    // Always mount sysfs.
    try!(mnt_ns.add_mount(None,
                          PathBuf::from("sys"),
                          Some("sysfs".to_string()),
                          MsFlags::empty(),
                          Vec::new()));
    Ok(mnt_ns)
}

fn user_ns_from_oci(uid_maps: Option<Vec<OciLinuxNamespaceMapping>>,
                    gid_maps: Option<Vec<OciLinuxNamespaceMapping>>,
                    uid: u32,
                    gid: u32)
                    -> UserNamespace {
    let mut user_ns = UserNamespace::new();
    if let Some(uid_mappings) = uid_maps {
        for id_map in uid_mappings {
            user_ns.add_uid_mapping(id_map.container_id as usize,
                                    id_map.host_id as usize,
                                    id_map.size as usize);
        }
    } else {
        // Default map the current user to the uid the process will run as.
        user_ns.add_uid_mapping(uid as usize, getuid() as usize, 1);
    }

    if let Some(gid_mappings) = gid_maps {
        for id_map in gid_mappings {
            user_ns.add_gid_mapping(id_map.container_id as usize,
                                    id_map.host_id as usize,
                                    id_map.size as usize);
        }
    } else {
        // Default map the current group to the gid the process will run as.
        user_ns.add_gid_mapping(gid as usize, getgid() as usize, 1);
    }
    user_ns
}

fn hostname_valid(hostname: &str) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    let name_re = regex::Regex::new("^([0-9a-zA-Z]|[0-9a-zA-Z][0-9a-zA-Z-]*[0-9a-zA-Z])$").unwrap();
    if !name_re.is_match(hostname) {
        return false;
    }

    let double_dash = regex::Regex::new("--").unwrap();
    if double_dash.is_match(hostname) {
        return false;
    }

    return true;
}

fn seccomp_jail_from_oci(oci_seccomp: OciSeccomp) -> Result<SeccompJail, Error> {
    let mut seccomp_config = SeccompConfig::new(&oci_seccomp.default_action)?;
    for syscall in oci_seccomp.syscalls {
        if let Some(args) = syscall.args {
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

#[cfg(test)]
mod tests {
    use super::hostname_valid;

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
