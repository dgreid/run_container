#![feature(proc_macro)]

extern crate nix;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate container;

mod oci_config;

use container::container::Container;
use container::mount_namespace::*;
use container::net_namespace::EmptyNetNamespace;
use container::user_namespace::UserNamespace;

use self::nix::mount::*;
use self::nix::unistd::getuid;
use self::nix::unistd::getgid;

use std::io;
use std::io::BufReader;
use std::fs::File;
use std::ffi::CString;
use std::path::Path;
use std::path::PathBuf;

use oci_config::*;

#[derive(Debug)]
pub enum ContainerConfigError {
    Io(io::Error),
    MountError(MountError),
    ConfigParseError,
    NoLinuxNodeFoundError,
}

impl From<io::Error> for ContainerConfigError {
    fn from(err: io::Error) -> ContainerConfigError {
        ContainerConfigError::Io(err)
    }
}

impl From<MountError> for ContainerConfigError {
    fn from(err: MountError) -> ContainerConfigError {
        ContainerConfigError::MountError(err)
    }
}

impl From<serde_json::Error> for ContainerConfigError {
    fn from(_: serde_json::Error) -> ContainerConfigError {
        ContainerConfigError::ConfigParseError
    }
}

pub fn container_from_oci_config(path: &Path, bind_mounts: Vec<(String, String)>)
        -> Result<Container, ContainerConfigError> {
    let mut config_path = PathBuf::from(path);
    config_path.push("config.json");
    let config_file = try!(File::open(&config_path));
    let reader = BufReader::new(config_file);
    let oci_config: OciConfig = try!(serde_json::from_reader(reader));
    container_from_oci(oci_config, bind_mounts, path)
}

fn container_from_oci(config: OciConfig, bind_mounts: Vec<(String, String)>,
                      path: &Path)
        -> Result<Container, ContainerConfigError> {
    let mut root_path = PathBuf::from(path);
    root_path.push(&config.root.path);

    let mnt_ns = mount_ns_from_oci(config.mounts, bind_mounts, root_path)?;

    let linux = config.linux.ok_or(ContainerConfigError::NoLinuxNodeFoundError)?;
    let user_ns = user_ns_from_oci(linux.uid_mappings, linux.gid_mappings,
                                   config.process.user.uid,
                                   config.process.user.gid);

    let argv = config.process.args.into_iter()
                    .map(|a| CString::new(a.as_str()).unwrap())
                    .collect();

    //TODO(dgreid) - Parse net namespace config.
    let net_ns = Box::new(EmptyNetNamespace::new());

    Ok(Container::new(config.hostname.unwrap_or("??".to_string()).as_str(),
                      argv, None, mnt_ns, net_ns, user_ns))
}

fn mount_ns_from_oci(mounts_vec: Option<Vec<OciMount>>,
                     bind_mounts: Vec<(String, String)>,
                     root_path: PathBuf)
        -> Result<MountNamespace, ContainerConfigError> {
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
                                  Some(m.mount_type), flags, options));
        }
    }
    for m in bind_mounts {
        try!(mnt_ns.add_mount(Some(PathBuf::from(m.0)),
			      PathBuf::from(m.1.trim_matches('/')), None,
                              MS_BIND, Vec::new()));
    }
    // Always mount sysfs.
    try!(mnt_ns.add_mount(None, PathBuf::from("sys"), Some("sysfs".to_string()),
                          MsFlags::empty(), Vec::new()));
    Ok(mnt_ns)
}

fn user_ns_from_oci(uid_maps: Option<Vec<OciLinuxNamespaceMapping>>,
                    gid_maps: Option<Vec<OciLinuxNamespaceMapping>>,
                    uid: u32, gid: u32) -> UserNamespace {
    let mut user_ns = UserNamespace::new();
    if let Some(uid_mappings) = uid_maps {
        for id_map in uid_mappings {
            user_ns.add_uid_mapping(id_map.container_id as usize,
                                    id_map.host_id as usize,
                                    id_map.size as usize);
        }
    } else {
        // Default map the current user to the uid the process will run as.
        user_ns.add_uid_mapping(uid as usize,
                                getuid() as usize, 1);
    }

    if let Some(gid_mappings) = gid_maps {
        for id_map in gid_mappings {
            user_ns.add_gid_mapping(id_map.container_id as usize,
                                    id_map.host_id as usize,
                                    id_map.size as usize);
        }
    } else {
        // Default map the current group to the gid the process will run as.
        user_ns.add_gid_mapping(gid as usize,
                                getgid() as usize, 1);
    }
    user_ns
}

#[cfg(test)]
mod tests {
}
