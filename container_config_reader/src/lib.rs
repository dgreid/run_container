#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate nix;
extern crate serde_json;

extern crate container;

mod oci_config;

use container::container::Container;
use container::mount_namespace::*;
use container::net_namespace::EmptyNetNamespace;
use container::user_namespace::UserNamespace;

use self::nix::mount::*;
use self::nix::unistd::getuid;

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

pub fn container_from_oci_config(path: &Path) -> Result<Container, ContainerConfigError> {
    let mut config_path = PathBuf::from(path);
    config_path.push("config.json");
    let config_file = try!(File::open(&config_path));
    let reader = BufReader::new(config_file);
    let oci_config: OciConfig = try!(serde_json::from_reader(reader));
    container_from_oci(oci_config, path)
}

fn container_from_oci(config: OciConfig, path: &Path) ->
        Result<Container, ContainerConfigError> {
    let mut root_path = PathBuf::from(path);
    root_path.push(&config.root.path);
    let mut mnt_ns = MountNamespace::new(root_path);
    if let Some(mounts) = config.mounts {
        for m in mounts.into_iter() {
            // TODO - parse options in ocimount
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
                        _ => options.push(opt),
                    }
                }
            }
            try!(mnt_ns.add_mount(Some(PathBuf::from(&m.source)),
                                  PathBuf::from(&m.destination.trim_left_matches('/')),
                                  Some(m.mount_type), flags, options));
        }
    }
    try!(mnt_ns.add_mount(None, PathBuf::from("sys"), Some("sysfs".to_string()), MsFlags::empty(),
                          Vec::new()));
    let mut user_ns = UserNamespace::new();
    if let Some(linux) = config.linux {
        if let Some(uid_mappings) = linux.uid_mappings {
            for id_map in uid_mappings {
                user_ns.add_uid_mapping(id_map.container_id as usize,
                                        id_map.host_id as usize,
                                        id_map.size as usize);
            }
        } else {
            // Default map the current user to the uid the process will run as.
            user_ns.add_uid_mapping(config.process.user.uid as usize,
                                    getuid() as usize, 1);
        }
        if let Some(gid_mappings) = linux.gid_mappings {
            for id_map in gid_mappings {
                user_ns.add_gid_mapping(id_map.container_id as usize,
                                        id_map.host_id as usize,
                                        id_map.size as usize);
            }
        }
    }
    let argv = config.process.args.into_iter()
                    .map(|a| CString::new(a.as_str()).unwrap())
                    .collect();

    //TODO(dgreid) - Parse net namespace config.
    let net_ns = Box::new(EmptyNetNamespace::new());

    Ok(Container::new(config.hostname.unwrap_or("??".to_string()).as_str(),
                      argv, mnt_ns, net_ns, user_ns))
}

#[cfg(test)]
mod tests {
}
