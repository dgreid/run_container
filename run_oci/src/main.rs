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
    alt_syscall_table: Option<String>,
    cgroup_parent: Option<String>,
    cgroup_name: Option<String>,
    container_path: Option<PathBuf>,
    extra_argv: Vec<String>,
    net_ns: Option<Box<NetNamespace>>,
    no_cgroups: bool,
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
    fn build_opts() -> getopts::Options {
        let mut opts = getopts::Options::new();
        opts.optmulti("b",
                      "bind_mount",
                      "Add a bind mount from external to internal",
                      "<external dir>:<internal dir>");
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
        opts.optopt("s",
                    "alt_syscall",
                    "Use the given alt-syscall table",
                    "TABLE_NAME");
        opts.optflag("u", "use_current_user", "Map the current user/group only");
        opts.optflag("z", "no_cgroup", "Don't put the contaienr in a cgroup");

        opts
    }

    pub fn new(argv: &Vec<String>) -> Result<CommandOptions, ()> {
        let opts = CommandOptions::build_opts();

        let mut matches = opts.parse(&argv[1..])
            .map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        if matches.free.len() == 0 {
            CommandOptions::print_usage(&argv[0], &opts);
            return Err(());
        }

        let bind_mounts = CommandOptions::bind_mounts_from_opts(&matches).map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        let net_ns = CommandOptions::net_ns_from_opts(&matches).map_err(|_| {
                CommandOptions::print_usage(&argv[0], &opts);
                ()
            })?;

        Ok(CommandOptions {
            alt_syscall_table: matches.opt_str("s"),
            cgroup_parent: matches.opt_str("p"),
            cgroup_name: matches.opt_str("c"),
            container_path: Some(PathBuf::from(&matches.free[0])),
            extra_argv: matches.free.split_off(1),
            net_ns: Some(net_ns),
            no_cgroups: matches.opt_present("z"),
            bind_mounts: Some(bind_mounts),
            use_configured_users: !matches.opt_present("u"),
        })
    }

    fn bind_mounts_from_opts(matches: &getopts::Matches) -> Result<Vec<(String, String)>, ()> {
        let mut bind_mounts = Vec::new();
        for mount in matches.opt_strs("b").into_iter() {
            let dirs: Vec<&str> = mount.split(":").collect();
            if dirs.len() != 2 {
                println!("Invalid bind mount specified: {}", mount);
                return Err(());
            }
            bind_mounts.push((dirs[0].to_string(), dirs[1].to_string()));
        }
        Ok(bind_mounts)
    }

    fn net_ns_from_opts(matches: &getopts::Matches) -> Result<Box<NetNamespace>, ()> {
        let bridge_name = matches.opt_str("r");
        let bridge_device = matches.opt_str("d");
        let bridged_ip = matches.opt_str("i");
        let masquerade_ip = matches.opt_str("m");
        let mut masquerade_devices = Vec::new();
        for dev in matches.opt_strs("q").into_iter() {
            masquerade_devices.push(dev);
        }

        matches.opt_str("n").map_or(Ok(Box::new(EmptyNetNamespace::new())), |n| {
            match n.as_ref() {
                "empty" => Ok(Box::new(EmptyNetNamespace::new())),
                "bridge" => {
                    if bridge_name.is_none() || bridge_device.is_none() {
                        println!("bridge_name and bride_device are required");
                        return Err(());
                    }
                    if bridged_ip.is_none() || masquerade_ip.is_none() {
                        println!("bridge_ip, and masquerate_ip are required");
                        return Err(());
                    }
                    Ok(Box::new(BridgedNetNamespace::new(bridge_name.unwrap(),
                                                         bridge_device.unwrap(),
                                                         masquerade_ip.unwrap(),
                                                         bridged_ip.unwrap())))
                }
                "masquerade" => {
                    if masquerade_devices.is_empty() || masquerade_ip.is_none() {
                        println!("A device and IP are required for masquerade networking");
                        return Err(());
                    }
                    Ok(Box::new(NatNetNamespace::new(masquerade_devices, masquerade_ip.unwrap())))
                }
                _ => {
                    println!("Invalid network type");
                    return Err(());
                }
            }
        })
    }

    fn print_usage(program: &str, opts: &getopts::Options) {
        let brief = format!("Usage: {} [options] <Container dir>", program);
        print!("{}", opts.usage(&brief));
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

    pub fn get_extra_args(&self) -> &Vec<String> {
        &self.extra_argv
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut cmd_opts = match CommandOptions::new(&argv) {
        Ok(c) => c,
        Err(()) => return,
    };

    let mut c = container_from_oci_config(&cmd_opts.get_container_path(),
                                          cmd_opts.get_bind_mounts())
        .expect("Failed to parse config");

    if !cmd_opts.no_cgroups {
        let cg = match CGroupNamespace::new(Path::new("/sys/fs/cgroup"),
                                            Path::new(cmd_opts.cgroup_parent
                                                .as_ref()
                                                .unwrap_or(&"".to_string())),
                                            Path::new(cmd_opts.cgroup_name
                                                .as_ref()
                                                .map_or(c.name(), |n| &n)),
                                            c.get_root_uid().unwrap()) {
            Ok(cg) => cg,
            Err(_) => {
                println!("Failed to create cgroup namespace");
                return;
            }
        };
        c.set_cgroup_namespace(Some(cg));
    }

    c.set_net_namespace(cmd_opts.get_net_namespace());
    if !cmd_opts.should_use_user_config() {
        let mut user_ns = UserNamespace::new();
        user_ns.add_uid_mapping(0, getuid() as usize, 1);
        user_ns.add_gid_mapping(0, getgid() as usize, 1);
        c.set_user_namespace(user_ns);
    }
    c.append_args(cmd_opts.get_extra_args());
    cmd_opts.alt_syscall_table.map(|t| c.set_alt_syscall_table(&t));

    c.start().unwrap();
    c.wait().unwrap();
}
