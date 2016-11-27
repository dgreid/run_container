extern crate container;
extern crate container_config_reader;
extern crate getopts;
extern crate nix;

use container::cgroup_namespace::CGroupNamespace;
use container::net_namespace::{NetNamespace, BridgedNetNamespace, EmptyNetNamespace,
                               NatNetNamespace};
use container::user_namespace::UserNamespace;
use container_config_reader::container_from_oci_config;

use nix::unistd::{getgid, getuid};
use std::env;
use std::path::Path;
use std::path::PathBuf;

struct CommandOptions {
    cgroup_ns: Option<CGroupNamespace>,
    container_path: Option<PathBuf>,
    net_ns: Option<Box<NetNamespace>>,
    bind_mounts: Option<Vec<(String, String)>>,
    use_configured_users: bool,
}

// Examples:
//
//  For a NAT'd network:
//  # run_oci -u -n masquerade --masquerade_dev eth0 --masquerade_dev wlan0 --masquerade_ip 10.1.1.1/24 /mnt/stateful_partition/containers/run_container/
//  For a bridged network:
//  # run_oci -n bridge --bridged_ip 10.1.1.2/24 --bridge_device veth1 --bridge_name br0 --masquerade_ip 10.1.1.1 /containers/busybox/

impl CommandOptions {
    pub fn new(argv: &Vec<String>) -> Option<CommandOptions> {
        let mut opts = getopts::Options::new();
        opts.optmulti("b",
                      "bind_mount",
                      "<external dir>:<internal dir> - Add a bind mount from external to internal",
                      "NAME");
        opts.optopt("c", "cgroup_name", "Name to give the cgroup", "NAME");
        opts.optopt("d",
                    "bridge_device",
                    "If network is bridged, the upstream dev to use",
                    "DEV");
        opts.optopt("i",
                    "bridged_ip",
                    "If network is bridged, the IP address for the container",
                    "IP");
        opts.optopt("m",
                    "masquerade_ip",
                    "The IP address of the upstream masquerade device",
                    "IP");
        opts.optopt("n",
                    "net_type",
                    "Network Type (bridge, masquerade, or empty)",
                    "TYPE");
        opts.optopt("p",
                    "cgroup_parent",
                    "parent directory of the container cgroups",
                    "NAME");
        opts.optmulti("q",
                      "masquerade_dev",
                      "Upstream device for NAT, can be specified multiple times",
                      "DEV");
        opts.optopt("r",
                    "bridge_name",
                    "If network is bridged, the bridge to use",
                    "NAME");
        opts.optflag("u", "use_current_user", "Map the current user/group only");

        let matches = match opts.parse(&argv[1..]) {
            Ok(m) => m,
            Err(_) => {
                CommandOptions::print_usage(&argv[0], &opts);
                return None;
            }
        };

        if matches.free.len() != 1 {
            CommandOptions::print_usage(&argv[0], &opts);
            return None;
        }

        let bridge_name = matches.opt_str("r");
        let bridge_device = matches.opt_str("d");
        let bridged_ip = matches.opt_str("i");
        let masquerade_ip = matches.opt_str("m");
        let mut masquerade_devices = Vec::new();
        for dev in matches.opt_strs("q").into_iter() {
            masquerade_devices.push(dev);
        }

        let mut bind_mounts = Vec::new();
        for mount in matches.opt_strs("b").into_iter() {
            let dirs: Vec<&str> = mount.split(":").collect();
            if dirs.len() != 2 {
                println!("Invalid bind mount specified");
                CommandOptions::print_usage(&argv[0], &opts);
                return None;
            }
            bind_mounts.push((dirs[0].to_string(), dirs[1].to_string()));
        }

        let mut net_ns: Option<Box<NetNamespace>> = Some(Box::new(EmptyNetNamespace::new()));
        if let Some(n) = matches.opt_str("n") {
            match n.as_ref() {
                "empty" => {
                    // Default
                }
                "bridge" => {
                    if bridge_name.is_none() || bridge_device.is_none() {
                        CommandOptions::print_usage(&argv[0], &opts);
                        println!("bridge_name and bride_device are required");
                        return None;
                    }
                    if bridged_ip.is_none() || masquerade_ip.is_none() {
                        CommandOptions::print_usage(&argv[0], &opts);
                        println!("bridge_ip, and masquerate_ip are required");
                        return None;
                    }
                    net_ns = Some(Box::new(BridgedNetNamespace::new(bridge_name.unwrap(),
                                                                    bridge_device.unwrap(),
                                                                    masquerade_ip.unwrap(),
                                                                    bridged_ip.unwrap())))
                }
                "masquerade" => {
                    if masquerade_devices.is_empty() || masquerade_ip.is_none() {
                        println!("A device and IP are required for masquerade networking");
                        CommandOptions::print_usage(&argv[0], &opts);
                        return None;
                    }
                    net_ns = Some(Box::new(NatNetNamespace::new(masquerade_devices,
                                                                masquerade_ip.unwrap())))
                }
                _ => {
                    println!("Invalid network type");
                    CommandOptions::print_usage(&argv[0], &opts);
                    return None;
                }
            }
        }

        let cgroup_parent = matches.opt_str("p").unwrap_or("".to_string());
        let cgroup_name = matches.opt_str("c");
        let cgroup_ns = if cgroup_name.is_some() {
            let cgns = CGroupNamespace::new(Path::new("/sys/fs/cgroup"),
                                            Path::new(&cgroup_parent),
                                            Path::new(&cgroup_name.unwrap()));
            if cgns.is_none() {
                println!("cgroup setup error");
                return None;
            }
            cgns
        } else {
            None
        };

        Some(CommandOptions {
            cgroup_ns: cgroup_ns,
            container_path: Some(PathBuf::from(&matches.free[0])),
            net_ns: net_ns,
            bind_mounts: Some(bind_mounts),
            use_configured_users: !matches.opt_present("u"),
        })
    }

    fn print_usage(program: &str, opts: &getopts::Options) {
        let brief = format!("Usage: {} [options] <Container dir>", program);
        print!("{}", opts.usage(&brief));
    }

    pub fn get_cgroup_namespace(&mut self) -> Option<CGroupNamespace> {
        self.cgroup_ns.take()
    }

    pub fn get_net_namespace(&mut self) -> Box<NetNamespace> {
        self.net_ns.take().unwrap()
    }

    pub fn get_container_path(&mut self) -> PathBuf {
        self.container_path.take().unwrap()
    }

    pub fn should_use_user_config(&self) -> bool {
        self.use_configured_users
    }

    pub fn get_bind_mounts(&mut self) -> Vec<(String, String)> {
        self.bind_mounts.take().unwrap()
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut cmd_opts = match CommandOptions::new(&argv) {
        Some(c) => c,
        None => return,
    };

    let mut c = container_from_oci_config(&cmd_opts.get_container_path(),
                                          cmd_opts.get_bind_mounts())
        .expect("Failed to parse config");

    c.set_cgroup_namespace(cmd_opts.get_cgroup_namespace());
    c.set_net_namespace(cmd_opts.get_net_namespace());
    if !cmd_opts.should_use_user_config() {
        let mut user_ns = UserNamespace::new();
        user_ns.add_uid_mapping(0, getuid() as usize, 1);
        user_ns.add_gid_mapping(0, getgid() as usize, 1);
        c.set_user_namespace(user_ns);
    }

    println!("starting {}", c.name());
    c.start().unwrap();
    c.wait().unwrap();
    println!("done");
}
